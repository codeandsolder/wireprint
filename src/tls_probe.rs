use std::collections::HashSet;
use std::io::{ErrorKind, Read};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use boring::ssl::{SslConnector, SslMethod, SslVersion};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use tokio::net::ToSocketAddrs;
use url::Url;

use crate::dns::{DNS_CAPTURE_VERSION, RoutingDnsSnapshotter, routing_names};
use crate::fusion::assess_endpoint;
use crate::model::{DnsProvenance, EndpointEvidence, Observation};
use crate::routing::detect_routing_elements;
use crate::tls::{TlsMessageCapture, TlsServerMorphology, provider_signals};

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsAddressFamily {
    Auto,
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone)]
pub struct TlsProbeConfig {
    pub handshake_timeout: Duration,
    pub post_handshake_window: Duration,
    pub family: TlsAddressFamily,
    pub vantage: Option<String>,
    pub groups: Option<String>,
    pub profile_label: Option<String>,
}

impl Default for TlsProbeConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(5),
            post_handshake_window: Duration::from_millis(2_500),
            family: TlsAddressFamily::Auto,
            vantage: None,
            groups: None,
            profile_label: None,
        }
    }
}

pub async fn probe_tls(target: &str, config: &TlsProbeConfig) -> Result<Observation> {
    let observed_unix_ms = unix_ms();
    let started = Instant::now();
    let url = Url::parse(target).with_context(|| format!("parse TLS target {target}"))?;
    if url.scheme() != "https" {
        bail!("TLS target must use https: {target}");
    }
    let host = url
        .host_str()
        .context("TLS target has no hostname")?
        .to_ascii_lowercase();
    let port = url.port_or_known_default().unwrap_or(443);

    let resolution_unix_ms = unix_ms();
    let candidates = resolve_candidates((&*host, port), config.family).await?;
    let selected_peer = *candidates
        .first()
        .context("no matching TCP address resolved")?;
    let connection_candidates = unique_ips(candidates.iter().map(SocketAddr::ip));

    let routing = RoutingDnsSnapshotter::new().capture(&host).await;
    let dns = DnsProvenance {
        classifier: DNS_CAPTURE_VERSION.into(),
        host: host.clone(),
        connection_candidates,
        connection_resolution_unix_ms: Some(resolution_unix_ms),
        connection_resolution_reused: false,
        cname_chain: routing.cname_chain,
        routing_snapshot_ips: routing.ips,
        routing_snapshot_unix_ms: Some(routing.observed_unix_ms),
        routing_snapshot_error: routing.error,
    };
    let routing_elements = detect_routing_elements(&routing_names(&dns));

    let blocking = BlockingTlsConfig {
        host,
        selected_peer,
        handshake_timeout: config.handshake_timeout,
        post_handshake_window: config.post_handshake_window,
        groups: config.groups.clone(),
        profile: profile_name(config),
    };
    let result = tokio::task::spawn_blocking(move || observe_tls(blocking))
        .await
        .context("join TLS observer")??;

    let provider_signals = provider_signals(&result.morphology);
    let mut observation = Observation {
        target: target.to_owned(),
        observed_unix_ms,
        vantage: config.vantage.clone(),
        request_profile: result.morphology.client_profile.clone(),
        request_role: Some("transport-observer".into()),
        request_provenance: Some("wireprint-tls".into()),
        request_headers: Vec::new(),
        transport_profile: "boringssl-tls13".into(),
        platform: std::env::consts::OS.into(),
        result: "tls_handshake".into(),
        elapsed_ms: started.elapsed().as_millis(),
        status: None,
        http_version: None,
        transport_protocol: Some("TLS/1.3".into()),
        final_uri: Some(target.to_owned()),
        remote: Some(result.actual_peer.ip().to_string()),
        selected_endpoint: Some(selected_peer.ip().to_string()),
        dns: Some(dns),
        response_headers: Vec::new(),
        path_elements: Vec::new(),
        routing_elements,
        provider_signals,
        h2_server_preface: None,
        h3_server_fingerprint: None,
        tls_server_morphology: Some(result.morphology),
        endpoint_assessment: None,
        body_captured_bytes: None,
        body_prefix_sha256: None,
        body_template_sha256: None,
        body_template_normalizer: None,
        body_prefix: None,
        body_truncated: None,
        outcome: None,
        error: None,
    };
    observation.endpoint_assessment = Some(assess_endpoint(&EndpointEvidence::from(&observation)));
    Ok(observation)
}

struct BlockingTlsConfig {
    host: String,
    selected_peer: SocketAddr,
    handshake_timeout: Duration,
    post_handshake_window: Duration,
    groups: Option<String>,
    profile: String,
}

struct BlockingTlsResult {
    actual_peer: SocketAddr,
    morphology: TlsServerMorphology,
}

fn observe_tls(config: BlockingTlsConfig) -> Result<BlockingTlsResult> {
    let tcp = TcpStream::connect_timeout(&config.selected_peer, config.handshake_timeout)
        .with_context(|| format!("connect TCP {}", config.selected_peer))?;
    tcp.set_read_timeout(Some(config.handshake_timeout))?;
    tcp.set_write_timeout(Some(config.handshake_timeout))?;
    let actual_peer = tcp.peer_addr()?;

    let mut connector = SslConnector::builder(SslMethod::tls())?;
    connector.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    connector.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    connector.set_alpn_protos(b"\x02h2")?;
    let connector = connector.build();
    let mut ssl = connector.configure()?.into_ssl(&config.host)?;
    ssl.set_permute_extensions(false);
    if let Some(groups) = &config.groups {
        ssl.set_curves_list(groups)
            .with_context(|| format!("configure TLS groups {groups}"))?;
    }

    let mut capture = TlsMessageCapture::default();
    capture.install(&mut ssl);
    let mut tls = ssl
        .connect(tcp)
        .map_err(|error| anyhow!("TLS handshake failed: {error}"))?;

    // TLS 1.3 NewSessionTicket messages are post-handshake. A read gives
    // BoringSSL a bounded opportunity to consume them; no HTTP request is sent.
    let deadline = Instant::now() + config.post_handshake_window;
    let mut byte = [0u8; 1];
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        tls.get_ref().set_read_timeout(Some(remaining))?;
        match tls.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::UnexpectedEof
                ) =>
            {
                break;
            }
            Err(error) => return Err(error).context("process post-handshake TLS messages"),
        }
    }

    let selected_alpn = tls.ssl().selected_alpn_protocol();
    let mut morphology = capture.morphology(config.profile, selected_alpn)?;
    morphology.post_handshake_window_ms = Some(config.post_handshake_window.as_millis());
    Ok(BlockingTlsResult {
        actual_peer,
        morphology,
    })
}

fn profile_name(config: &TlsProbeConfig) -> String {
    if let Some(label) = &config.profile_label {
        return label.clone();
    }
    match &config.groups {
        Some(groups) => format!("boringssl-h2-tls13-v1:groups={groups}"),
        None => "boringssl-h2-tls13-v1".into(),
    }
}

async fn resolve_candidates(
    target: impl ToSocketAddrs,
    family: TlsAddressFamily,
) -> Result<Vec<SocketAddr>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for address in tokio::net::lookup_host(target).await? {
        let family_match = match family {
            TlsAddressFamily::Auto => true,
            TlsAddressFamily::Ipv4 => address.is_ipv4(),
            TlsAddressFamily::Ipv6 => address.is_ipv6(),
        };
        if family_match && seen.insert(address) {
            out.push(address);
        }
    }
    Ok(out)
}

fn unique_ips(ips: impl IntoIterator<Item = IpAddr>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for ip in ips {
        let text = ip.to_string();
        if seen.insert(text.clone()) {
            out.push(text);
        }
    }
    out
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
