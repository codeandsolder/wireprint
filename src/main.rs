use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use wireprint::{
    Header, PlatformKind, ProbeConfig, ProfileSet, RequestProfile, TransportProfile,
    classify_response, probe_batch,
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
}

#[derive(Debug, Args)]
struct ProbeArgs {
    #[arg(required = true)]
    urls: Vec<String>,
    #[arg(long, value_enum, default_value_t = TransportProfile::Plain)]
    transport: TransportProfile,
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
}

#[derive(Debug, Args)]
struct MatrixArgs {
    #[arg(long)]
    profiles: PathBuf,
    #[arg(long)]
    targets: PathBuf,
    #[arg(long = "transport", value_enum, default_values_t = [TransportProfile::Plain])]
    transports: Vec<TransportProfile>,
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
}

#[derive(Debug, Args)]
struct ClassifyArgs {
    body: PathBuf,
    #[arg(long)]
    status: u16,
    #[arg(long = "header", value_name = "NAME:VALUE")]
    headers: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Probe(args) => run_probe(args).await,
        Command::Matrix(args) => run_matrix(args).await,
        Command::Classify(args) => run_classify(args),
    }
}

async fn run_probe(args: ProbeArgs) -> Result<()> {
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
    };
    for observation in
        probe_batch(&profile, args.transport, args.platform, &args.urls, &config).await?
    {
        println!("{}", serde_json::to_string(&observation)?);
    }
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
    };

    for (transport_index, transport) in args.transports.iter().copied().enumerate() {
        for (profile_index, profile) in profile_set.profiles.iter().enumerate() {
            if transport_index > 0 || profile_index > 0 {
                tokio::time::sleep(Duration::from_millis(args.profile_delay_ms)).await;
            }
            for observation in
                probe_batch(profile, transport, args.platform, &targets, &config).await?
            {
                serde_json::to_writer(&mut writer, &observation)?;
                writer.write_all(b"\n")?;
            }
            writer.flush()?;
        }
    }
    Ok(())
}

fn run_classify(args: ClassifyArgs) -> Result<()> {
    let body =
        std::fs::read(&args.body).with_context(|| format!("read {}", args.body.display()))?;
    let headers = parse_headers(&args.headers)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&classify_response(args.status, &headers, &body))?
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
