use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use wireprint::{
    BuiltinTransport, EndpointEvidence, H3AddressFamily, H3ProbeConfig, Header,
    HostAggregationConfig, Observation, PlatformKind, ProbeConfig, ProfileSet, RequestProfile,
    RoutingAuditSample, RoutingContextCollector, TlsAddressFamily, TlsProbeConfig,
    TransportProfile, TransportSet, aggregate_observations, assess_endpoint, audit_routing_samples,
    classify_response, detect_path_elements, detect_routing_elements, probe_batch, probe_h3,
    probe_tls,
};

#[derive(Debug, Parser)]
#[command(name = "wireprint", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Send a small benign request batch and emit JSONL observations.
    Probe(ProbeArgs),
    /// Run request profiles × transports × targets as an isolated matrix.
    Matrix(MatrixArgs),
    /// Classify a saved HTTP body using the built-in semantic classifier.
    Classify(ClassifyArgs),
    /// Classify response headers into unordered network-path participation claims.
    Path(PathArgs),
    /// Classify provider-managed CNAMEs into routing/path participation claims.
    Route(RouteArgs),
    /// Fuse one endpoint/vantage evidence document into termination candidates.
    AssessEndpoint(AssessEndpointArgs),
    /// Observe HTTP/3 and raw peer QUIC transport parameters.
    H3(H3Args),
    /// Observe raw TLS 1.3 server handshake morphology.
    Tls(TlsArgs),
    /// Look up non-scoring BGP prefix / origin-AS routing context for IPs.
    RoutingContext(RoutingContextArgs),
    /// Audit ASN/provider specificity and route diversity from observations or normalized samples.
    AuditRoutingContext(AuditRoutingContextArgs),
    /// Aggregate JSONL probe observations into freshness-aware hostname state.
    AggregateHost(AggregateHostArgs),
}

#[derive(Debug, Args)]
struct ProbeArgs {
    #[arg(required = true)]
    urls: Vec<String>,
    /// Convenient built-in transport alias. Defaults to plain when no transport set is supplied.
    #[arg(long, value_enum, conflicts_with = "transport_set")]
    transport: Option<BuiltinTransport>,
    /// Declarative transport-set JSON file.
    #[arg(long, conflicts_with = "transport")]
    transport_set: Option<PathBuf>,
    /// Select one named profile from --transport-set. Required when it has multiple runnable profiles.
    #[arg(long, requires = "transport_set")]
    transport_name: Option<String>,
    /// Platform used by built-ins whose wire image varies by platform.
    #[arg(long, value_enum, default_value_t = PlatformKind::Macos)]
    platform: PlatformKind,
    #[arg(long = "header", value_name = "NAME:VALUE")]
    headers: Vec<String>,
    #[arg(long, default_value = "cli")]
    profile_name: String,
    #[arg(long, default_value_t = 65_536)]
    body_bytes: usize,
    #[arg(long, default_value_t = 250)]
    delay_ms: u64,
    #[arg(long)]
    vantage: Option<String>,
    /// Enrich the selected/peer IP with Team Cymru BGP routing context.
    #[arg(long)]
    routing_context: bool,
}

#[derive(Debug, Args)]
struct MatrixArgs {
    #[arg(long)]
    profiles: PathBuf,
    #[arg(long)]
    targets: PathBuf,
    /// Convenient built-in transport aliases. Defaults to plain when no transport set is supplied.
    #[arg(long = "transport", value_enum, conflicts_with = "transport_set")]
    transports: Vec<BuiltinTransport>,
    /// Declarative transport-set JSON file.
    #[arg(long, conflicts_with = "transports")]
    transport_set: Option<PathBuf>,
    /// Select one or more named profiles from --transport-set. Without this, all runnable profiles run.
    #[arg(long = "transport-name", requires = "transport_set")]
    transport_names: Vec<String>,
    /// Platform used by built-ins whose wire image varies by platform.
    #[arg(long, value_enum, default_value_t = PlatformKind::Macos)]
    platform: PlatformKind,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = 65_536)]
    body_bytes: usize,
    #[arg(long, default_value_t = 250)]
    delay_ms: u64,
    #[arg(long, default_value_t = 500)]
    profile_delay_ms: u64,
    #[arg(long)]
    vantage: Option<String>,
    /// Enrich the selected/peer IP with Team Cymru BGP routing context.
    #[arg(long)]
    routing_context: bool,
}

#[derive(Debug, Args)]
struct H3Args {
    #[arg(required = true)]
    urls: Vec<String>,
    #[arg(long, default_value_t = 1)]
    repeat: usize,
    #[arg(long, default_value_t = 8.0)]
    timeout_secs: f64,
    #[arg(long, value_enum, default_value_t = H3AddressFamily::Auto)]
    family: H3AddressFamily,
    #[arg(long)]
    vantage: Option<String>,
    /// Enrich the selected/peer IP with Team Cymru BGP routing context.
    #[arg(long)]
    routing_context: bool,
}

#[derive(Debug, Args)]
struct TlsArgs {
    #[arg(required = true)]
    urls: Vec<String>,
    #[arg(long, default_value_t = 1)]
    repeat: usize,
    #[arg(long, default_value_t = 5.0)]
    handshake_timeout_secs: f64,
    #[arg(long, default_value_t = 2500)]
    post_handshake_ms: u64,
    #[arg(long, value_enum, default_value_t = TlsAddressFamily::Auto)]
    family: TlsAddressFamily,
    #[arg(long)]
    groups: Option<String>,
    #[arg(long)]
    profile_label: Option<String>,
    #[arg(long)]
    vantage: Option<String>,
    /// Enrich the selected/peer IP with Team Cymru BGP routing context.
    #[arg(long)]
    routing_context: bool,
}

#[derive(Debug, Args)]
struct RoutingContextArgs {
    #[arg(required = true)]
    addresses: Vec<IpAddr>,
}

#[derive(Debug, Args)]
struct AuditRoutingContextArgs {
    input: PathBuf,
    /// Input is normalized `RoutingAuditSample` JSONL rather than `Observation` JSONL.
    #[arg(long)]
    samples: bool,
    /// Minimum distinct labeled hosts before an ASN can be called pure-in-sample.
    #[arg(long, default_value_t = 2)]
    min_labeled_hosts: usize,
}

#[derive(Debug, Args)]
struct ClassifyArgs {
    body: PathBuf,
    #[arg(long)]
    status: u16,
    #[arg(long = "header", value_name = "NAME:VALUE")]
    headers: Vec<String>,
}

#[derive(Debug, Args)]
struct PathArgs {
    #[arg(long = "header", value_name = "NAME:VALUE", required = true)]
    headers: Vec<String>,
}

#[derive(Debug, Args)]
struct RouteArgs {
    #[arg(long = "cname", value_name = "HOSTNAME", required = true)]
    cnames: Vec<String>,
}

#[derive(Debug, Args)]
struct AssessEndpointArgs {
    input: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Probe(args) => run_probe(args).await,
        Command::Matrix(args) => run_matrix(args).await,
        Command::Classify(args) => run_classify(&args),
        Command::Path(args) => run_path(&args),
        Command::Route(args) => run_route(&args),
        Command::AssessEndpoint(args) => run_assess_endpoint(&args),
        Command::H3(args) => run_h3(args).await,
        Command::Tls(args) => run_tls(args).await,
        Command::RoutingContext(args) => run_routing_context(args).await,
        Command::AuditRoutingContext(args) => run_audit_routing_context(&args),
        Command::AggregateHost(args) => run_aggregate_host(&args),
    }
}

async fn run_probe(args: ProbeArgs) -> Result<()> {
    let transport = resolve_probe_transport(&args)?;
    let profile = RequestProfile {
        name: args.profile_name,
        role: None,
        provenance: Some("cli".into()),
        headers: parse_headers(&args.headers)?,
    };
    let config = ProbeConfig {
        body_bytes: args.body_bytes,
        delay: Duration::from_millis(args.delay_ms),
        vantage: args.vantage,
        routing_context_collector: args.routing_context.then(RoutingContextCollector::new),
    };
    for observation in probe_batch(&profile, &transport, &args.urls, &config).await? {
        println!("{}", serde_json::to_string(&observation)?);
    }
    Ok(())
}

async fn run_h3(args: H3Args) -> Result<()> {
    if args.repeat == 0 {
        bail!("--repeat must be at least 1");
    }
    if !args.timeout_secs.is_finite() || args.timeout_secs <= 0.0 {
        bail!("--timeout-secs must be a positive finite number");
    }
    let config = H3ProbeConfig {
        timeout: Duration::from_secs_f64(args.timeout_secs),
        family: args.family,
        vantage: args.vantage,
        routing_context_collector: args.routing_context.then(RoutingContextCollector::new),
    };
    for url in &args.urls {
        for _ in 0..args.repeat {
            match probe_h3(url, &config).await {
                Ok(observation) => println!("{}", serde_json::to_string(&observation)?),
                Err(error) => println!(
                    "{}",
                    serde_json::json!({
                        "target": url,
                        "result": "error",
                        "error": format!("{error:#}"),
                    })
                ),
            }
        }
    }
    Ok(())
}

async fn run_tls(args: TlsArgs) -> Result<()> {
    if args.repeat == 0 {
        bail!("--repeat must be at least 1");
    }
    if !args.handshake_timeout_secs.is_finite() || args.handshake_timeout_secs <= 0.0 {
        bail!("--handshake-timeout-secs must be a positive finite number");
    }
    let config = TlsProbeConfig {
        handshake_timeout: Duration::from_secs_f64(args.handshake_timeout_secs),
        post_handshake_window: Duration::from_millis(args.post_handshake_ms),
        family: args.family,
        vantage: args.vantage,
        groups: args.groups,
        profile_label: args.profile_label,
        routing_context_collector: args.routing_context.then(RoutingContextCollector::new),
    };
    for url in &args.urls {
        for _ in 0..args.repeat {
            match probe_tls(url, &config).await {
                Ok(observation) => println!("{}", serde_json::to_string(&observation)?),
                Err(error) => println!(
                    "{}",
                    serde_json::json!({
                        "target": url,
                        "result": "error",
                        "error": format!("{error:#}"),
                    })
                ),
            }
        }
    }
    Ok(())
}

async fn run_routing_context(args: RoutingContextArgs) -> Result<()> {
    let collector = RoutingContextCollector::new();
    for address in args.addresses {
        println!(
            "{}",
            serde_json::to_string(&collector.collect(address).await)?
        );
    }
    Ok(())
}

fn run_audit_routing_context(args: &AuditRoutingContextArgs) -> Result<()> {
    if args.min_labeled_hosts == 0 {
        bail!("--min-labeled-hosts must be at least 1");
    }
    let samples = if args.samples {
        read_jsonl::<RoutingAuditSample>(&args.input, "routing audit sample")?
    } else {
        let observations = read_observations(&args.input)?;
        wireprint::samples_from_observations(&observations)
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&audit_routing_samples(&samples, args.min_labeled_hosts))?
    );
    Ok(())
}

async fn run_matrix(args: MatrixArgs) -> Result<()> {
    let profile_set: ProfileSet = serde_json::from_reader(BufReader::new(
        File::open(&args.profiles).with_context(|| format!("open {}", args.profiles.display()))?,
    ))
    .with_context(|| format!("parse {}", args.profiles.display()))?;
    if profile_set.profiles.is_empty() {
        bail!("profile set is empty");
    }
    let targets = read_targets(&args.targets)?;
    if targets.is_empty() {
        bail!("target set is empty");
    }
    let transports = resolve_matrix_transports(&args)?;

    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&args.output)
        .with_context(|| format!("open {}", args.output.display()))?;
    let mut writer = BufWriter::new(file);
    let config = ProbeConfig {
        body_bytes: args.body_bytes,
        delay: Duration::from_millis(args.delay_ms),
        vantage: args.vantage.clone(),
        routing_context_collector: args.routing_context.then(RoutingContextCollector::new),
    };

    for (transport_index, transport) in transports.iter().enumerate() {
        for (profile_index, profile) in profile_set.profiles.iter().enumerate() {
            if transport_index > 0 || profile_index > 0 {
                tokio::time::sleep(Duration::from_millis(args.profile_delay_ms)).await;
            }
            for observation in probe_batch(profile, transport, &targets, &config).await? {
                serde_json::to_writer(&mut writer, &observation)?;
                writer.write_all(b"\n")?;
            }
            writer.flush()?;
        }
    }
    Ok(())
}

fn resolve_probe_transport(args: &ProbeArgs) -> Result<TransportProfile> {
    let Some(path) = args.transport_set.as_ref() else {
        return Ok(args
            .transport
            .unwrap_or(BuiltinTransport::Plain)
            .into_profile(args.platform));
    };
    let set = read_transport_set(path)?;
    if let Some(name) = args.transport_name.as_deref() {
        return select_named_transport(&set, name);
    }
    let mut runnable = set
        .transports
        .into_iter()
        .filter(TransportProfile::runnable)
        .collect::<Vec<_>>();
    match runnable.len() {
        0 => bail!("transport set has no runnable profiles"),
        1 => Ok(runnable.remove(0)),
        count => {
            bail!("transport set has {count} runnable profiles; choose one with --transport-name")
        }
    }
}

fn resolve_matrix_transports(args: &MatrixArgs) -> Result<Vec<TransportProfile>> {
    let Some(path) = args.transport_set.as_ref() else {
        let builtins = if args.transports.is_empty() {
            vec![BuiltinTransport::Plain]
        } else {
            args.transports.clone()
        };
        return Ok(builtins
            .into_iter()
            .map(|transport| transport.into_profile(args.platform))
            .collect());
    };

    let set = read_transport_set(path)?;
    if args.transport_names.is_empty() {
        let runnable = set
            .transports
            .into_iter()
            .filter(TransportProfile::runnable)
            .collect::<Vec<_>>();
        if runnable.is_empty() {
            bail!("transport set has no runnable profiles");
        }
        return Ok(runnable);
    }

    args.transport_names
        .iter()
        .map(|name| select_named_transport(&set, name))
        .collect()
}

fn select_named_transport(set: &TransportSet, name: &str) -> Result<TransportProfile> {
    let profile = set
        .transports
        .iter()
        .find(|profile| profile.name == name)
        .with_context(|| format!("transport profile not found: {name}"))?
        .clone();
    if !profile.runnable() {
        bail!(
            "transport profile '{name}' is observational only and has no runnable implementation"
        );
    }
    Ok(profile)
}

fn read_transport_set(path: &Path) -> Result<TransportSet> {
    let set: TransportSet = serde_json::from_reader(BufReader::new(
        File::open(path).with_context(|| format!("open {}", path.display()))?,
    ))
    .with_context(|| format!("parse {}", path.display()))?;
    set.validate()?;
    Ok(set)
}

fn run_classify(args: &ClassifyArgs) -> Result<()> {
    let body =
        std::fs::read(&args.body).with_context(|| format!("read {}", args.body.display()))?;
    let headers = parse_headers(&args.headers)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&classify_response(args.status, &headers, &body))?
    );
    Ok(())
}

fn run_path(args: &PathArgs) -> Result<()> {
    let headers = parse_headers(&args.headers)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&detect_path_elements(&headers))?
    );
    Ok(())
}

fn run_route(args: &RouteArgs) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&detect_routing_elements(&args.cnames))?
    );
    Ok(())
}

fn run_assess_endpoint(args: &AssessEndpointArgs) -> Result<()> {
    let evidence: EndpointEvidence = serde_json::from_reader(BufReader::new(
        File::open(&args.input).with_context(|| format!("open {}", args.input.display()))?,
    ))
    .with_context(|| format!("parse {}", args.input.display()))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&assess_endpoint(&evidence))?
    );
    Ok(())
}

fn parse_headers(values: &[String]) -> Result<Vec<Header>> {
    let mut headers = Vec::new();
    for item in values {
        let Some((name, value)) = item.split_once(':') else {
            bail!("header must be NAME:VALUE: {item}");
        };
        headers.push(Header {
            name: name.trim().to_ascii_lowercase(),
            value: value.trim_start().to_owned(),
        });
    }
    Ok(headers)
}

fn read_targets(path: &Path) -> Result<Vec<String>> {
    let reader =
        BufReader::new(File::open(path).with_context(|| format!("open {}", path.display()))?);
    let mut targets = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let value = line.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        if !(value.starts_with("https://") || value.starts_with("http://")) {
            bail!("target is not an http(s) URL: {value}");
        }
        targets.push(value.to_owned());
    }
    Ok(targets)
}

#[derive(Debug, Args)]
struct AggregateHostArgs {
    input: PathBuf,
    #[arg(long, default_value_t = 6)]
    freshness_hours: u64,
    #[arg(long, default_value_t = 60)]
    support_bucket_minutes: u64,
}

fn run_aggregate_host(args: &AggregateHostArgs) -> Result<()> {
    let observations = read_observations(&args.input)?;
    let config = HostAggregationConfig {
        freshness_window_ms: u128::from(args.freshness_hours) * 60 * 60 * 1000,
        support_bucket_ms: u128::from(args.support_bucket_minutes) * 60 * 1000,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&aggregate_observations(&observations, config))?
    );
    Ok(())
}

fn read_observations(path: &Path) -> Result<Vec<Observation>> {
    read_jsonl(path, "wireprint observation")
}

fn read_jsonl<T>(path: &Path, kind: &str) -> Result<Vec<T>>
where
    T: serde::de::DeserializeOwned,
{
    let reader =
        BufReader::new(File::open(path).with_context(|| format!("open {}", path.display()))?);
    let mut values = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        let value = line.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        values.push(
            serde_json::from_str(value).with_context(|| {
                format!("parse {} line {} as {kind}", path.display(), index + 1)
            })?,
        );
    }
    Ok(values)
}
