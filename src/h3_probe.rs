use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::slice;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use boring::ssl::{SslContextBuilder, SslMethod};
use clap::ValueEnum;
use foreign_types_shared::ForeignTypeRef;
use quiche::h3::NameValue;
use serde::{Deserialize, Serialize};
use tokio::net::{ToSocketAddrs, UdpSocket};
use url::Url;

use crate::dns::{DNS_CAPTURE_VERSION, RoutingDnsSnapshotter, routing_names};
use crate::fusion::assess_endpoint;
use crate::h3::{H3ServerFingerprint, H3Setting, classify_h3_quic, provider_signals};
use crate::model::{DnsProvenance, EndpointEvidence, Header, Observation};
use crate::path::detect_path_elements;
use crate::routing::detect_routing_elements;
use crate::routing_context::{
    RoutingContextCollector, enrich_observation as enrich_routing_context,
};

const H3_USER_AGENT: &str = "wireprint-h3-observer/1";
const MAX_DATAGRAM_SIZE: usize = 65_535;
const MAX_SEND_DATAGRAM_SIZE: usize = 1_350;

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum H3AddressFamily {
    Auto,
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone)]
pub struct H3ProbeConfig {
    pub timeout: Duration,
    pub family: H3AddressFamily,
    pub vantage: Option<String>,
    pub routing_context_collector: Option<RoutingContextCollector>,
}

impl Default for H3ProbeConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(8),
            family: H3AddressFamily::Auto,
            vantage: None,
            routing_context_collector: None,
        }
    }
}

/// Observe one HTTP/3 endpoint and preserve peer QUIC/H3 wire evidence.
///
/// # Errors
///
/// Returns an error for invalid targets, DNS/connectivity failures, QUIC/H3 protocol errors, or probe timeout.
pub async fn probe_h3(target: &str, config: &H3ProbeConfig) -> Result<Observation> {
    let observed_unix_ms = unix_ms();
    let started = Instant::now();
    let url = Url::parse(target).with_context(|| format!("parse H3 target {target}"))?;
    if url.scheme() != "https" {
        bail!("H3 target must use https: {target}");
    }
    let host = url
        .host_str()
        .context("H3 target has no hostname")?
        .to_ascii_lowercase();
    let port = url.port_or_known_default().unwrap_or(443);
    let authority = if port == 443 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let mut path = if url.path().is_empty() {
        "/".to_owned()
    } else {
        url.path().to_owned()
    };
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }

    let resolution_unix_ms = unix_ms();
    let candidates = resolve_candidates((&*host, port), config.family).await?;
    let peer = *candidates
        .first()
        .context("no matching UDP address resolved")?;
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

    let bind = match peer {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind).await?;
    let local = socket.local_addr()?;

    let raw_peer_transport_parameters = Arc::new(Mutex::new(Vec::new()));
    let mut quic_config = quic_config(Arc::clone(&raw_peer_transport_parameters))?;
    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    boring::rand::rand_bytes(&mut scid_bytes)?;
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    let mut conn = quiche::connect(Some(&host), &scid, local, peer, &mut quic_config)?;
    let h3_config = quiche::h3::Config::new()?;
    let mut h3 = None;
    let mut request_stream_id = None;
    let mut response_headers = None;
    let mut status = None;
    let mut actual_peer = None;
    let mut incoming = vec![0u8; MAX_DATAGRAM_SIZE].into_boxed_slice();
    let mut outgoing = [0u8; MAX_SEND_DATAGRAM_SIZE];

    flush_quic(&socket, &mut conn, &mut outgoing).await?;

    while started.elapsed() < config.timeout {
        if conn.is_closed() {
            let error = conn.local_error().or_else(|| conn.peer_error());
            bail!("QUIC connection closed before final H3 response: {error:?}");
        }

        if conn.is_established() && h3.is_none() {
            h3 = Some(quiche::h3::Connection::with_transport(
                &mut conn, &h3_config,
            )?);
        }

        if let Some(h3_conn) = h3.as_mut() {
            if request_stream_id.is_none() {
                let request = [
                    quiche::h3::Header::new(b":method", b"GET"),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", authority.as_bytes()),
                    quiche::h3::Header::new(b":path", path.as_bytes()),
                    quiche::h3::Header::new(b"user-agent", H3_USER_AGENT.as_bytes()),
                    quiche::h3::Header::new(b"accept", b"*/*"),
                ];
                request_stream_id = Some(h3_conn.send_request(&mut conn, &request, true)?);
                flush_quic(&socket, &mut conn, &mut outgoing).await?;
            }

            loop {
                match h3_conn.poll(&mut conn) {
                    Ok((stream, quiche::h3::Event::Headers { list, .. })) => {
                        if Some(stream) != request_stream_id {
                            continue;
                        }
                        let headers = h3_headers(&list);
                        if let Some(value) = headers
                            .iter()
                            .find(|header| header.name == ":status")
                            .and_then(|header| header.value.parse::<u16>().ok())
                            && value >= 200
                        {
                            status = Some(value);
                            response_headers = Some(headers);
                            break;
                        }
                    }
                    Ok((_stream, quiche::h3::Event::Data)) => {}
                    Ok((_stream, quiche::h3::Event::Finished)) => {}
                    Ok((_stream, quiche::h3::Event::Reset(error))) => {
                        bail!("H3 request reset by peer: {error}");
                    }
                    Ok((_id, quiche::h3::Event::GoAway)) => {}
                    Ok((_id, quiche::h3::Event::PriorityUpdate)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(error) => return Err(error).context("poll HTTP/3 events"),
                }
            }
        }

        if response_headers.is_some() {
            let settings = h3
                .as_ref()
                .and_then(quiche::h3::Connection::peer_settings_raw)
                .context("peer H3 SETTINGS were not observed")?;
            let raw_transport_parameters = raw_peer_transport_parameters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if raw_transport_parameters.is_empty() {
                bail!("peer QUIC transport parameters were not captured");
            }
            let fingerprint = classify_h3_quic(
                quiche::PROTOCOL_VERSION,
                String::from_utf8_lossy(conn.application_proto()).into_owned(),
                settings
                    .iter()
                    .map(|(id, value)| H3Setting {
                        id: *id,
                        value: *value,
                    })
                    .collect(),
                &raw_transport_parameters,
            )?;
            let mut observation = success_observation(H3ObservationParts {
                target,
                observed_unix_ms,
                elapsed: started.elapsed(),
                config,
                selected_peer: peer,
                actual_peer,
                dns,
                routing_elements,
                status,
                response_headers: response_headers.unwrap_or_default(),
                fingerprint,
            });
            if let Some(collector) = config.routing_context_collector.as_ref() {
                enrich_routing_context(&mut observation, collector).await;
            }
            observation.endpoint_assessment =
                Some(assess_endpoint(&EndpointEvidence::from(&observation)));
            return Ok(observation);
        }

        let timeout = conn.timeout().unwrap_or(Duration::from_millis(50));
        match tokio::time::timeout(timeout, socket.recv_from(&mut incoming)).await {
            Ok(Ok((len, from))) => {
                actual_peer = Some(from);
                let recv_info = quiche::RecvInfo { from, to: local };
                match conn.recv(&mut incoming[..len], recv_info) {
                    Ok(_) | Err(quiche::Error::Done) => {}
                    Err(error) => return Err(error).context("process QUIC datagram"),
                }
            }
            Ok(Err(error)) => return Err(error).context("receive QUIC datagram"),
            Err(_) => conn.on_timeout(),
        }
        flush_quic(&socket, &mut conn, &mut outgoing).await?;
    }

    bail!("H3 probe timed out after {} ms", config.timeout.as_millis())
}

struct H3ObservationParts<'a> {
    target: &'a str,
    observed_unix_ms: u128,
    elapsed: Duration,
    config: &'a H3ProbeConfig,
    selected_peer: SocketAddr,
    actual_peer: Option<SocketAddr>,
    dns: DnsProvenance,
    routing_elements: Vec<crate::model::PathElement>,
    status: Option<u16>,
    response_headers: Vec<Header>,
    fingerprint: H3ServerFingerprint,
}

fn success_observation(parts: H3ObservationParts<'_>) -> Observation {
    let provider_signals = provider_signals(&parts.fingerprint);
    let path_elements = detect_path_elements(&parts.response_headers);
    Observation {
        target: parts.target.to_owned(),
        observed_unix_ms: parts.observed_unix_ms,
        vantage: parts.config.vantage.clone(),
        request_profile: "h3-observer".into(),
        request_role: Some("transport-observer".into()),
        request_provenance: Some("wireprint-h3".into()),
        request_profile_headers: vec![
            Header {
                name: "user-agent".into(),
                value: H3_USER_AGENT.into(),
            },
            Header {
                name: "accept".into(),
                value: "*/*".into(),
            },
        ],
        transport_profile: "quiche-h3".into(),
        transport: None,
        platform: Some(std::env::consts::OS.into()),
        result: "response".into(),
        elapsed_ms: parts.elapsed.as_millis(),
        status: parts.status,
        http_version: Some("HTTP/3".into()),
        transport_protocol: Some("HTTP/3".into()),
        final_uri: Some(parts.target.to_owned()),
        remote: parts.actual_peer.map(|peer| peer.ip().to_string()),
        selected_endpoint: Some(parts.selected_peer.ip().to_string()),
        dns: Some(parts.dns),
        response_headers: parts.response_headers,
        path_elements,
        routing_elements: parts.routing_elements,
        provider_signals,
        routing_context_snapshot: None,
        h2_server_preface: None,
        h3_server_fingerprint: Some(parts.fingerprint),
        tls_server_morphology: None,
        endpoint_assessment: None,
        body_captured_bytes: None,
        body_prefix_sha256: None,
        body_template_sha256: None,
        body_template_normalizer: None,
        body_prefix: None,
        body_truncated: None,
        outcome: None,
        error: None,
    }
}

fn quic_config(raw_peer_transport_parameters: Arc<Mutex<Vec<u8>>>) -> Result<quiche::Config> {
    let mut tls = SslContextBuilder::new(SslMethod::tls())?;
    tls.set_default_verify_paths()?;
    tls.set_info_callback(move |ssl, _mode, _value| {
        // SAFETY: BoringSSL owns the returned transport-parameter buffer for the
        // live SSL object. We validate the pointer/length pair and copy it during
        // this synchronous callback before the SSL object can mutate or drop it.
        unsafe {
            let mut ptr = std::ptr::null();
            let mut len = 0usize;
            boring_sys::SSL_get_peer_quic_transport_params(
                ssl.as_ptr(),
                &raw mut ptr,
                &raw mut len,
            );
            if len > 0 && !ptr.is_null() {
                let raw = slice::from_raw_parts(ptr, len).to_vec();
                *raw_peer_transport_parameters
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = raw;
            }
        }
    });

    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls)?;
    config.verify_peer(true);
    config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
    config.set_max_idle_timeout(8_000);
    config.set_max_recv_udp_payload_size(65_527);
    config.set_max_send_udp_payload_size(MAX_SEND_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    Ok(config)
}

async fn flush_quic(
    socket: &UdpSocket,
    conn: &mut quiche::Connection,
    outgoing: &mut [u8],
) -> Result<()> {
    loop {
        match conn.send(outgoing) {
            Ok((written, info)) => {
                let sent = socket.send_to(&outgoing[..written], info.to).await?;
                if sent != written {
                    bail!("short QUIC datagram write: sent {sent} of {written} bytes");
                }
            }
            Err(quiche::Error::Done) => return Ok(()),
            Err(error) => return Err(error).context("generate QUIC datagram"),
        }
    }
}

async fn resolve_candidates(
    target: impl ToSocketAddrs,
    family: H3AddressFamily,
) -> Result<Vec<SocketAddr>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for address in tokio::net::lookup_host(target).await? {
        let family_match = match family {
            H3AddressFamily::Auto => true,
            H3AddressFamily::Ipv4 => address.is_ipv4(),
            H3AddressFamily::Ipv6 => address.is_ipv6(),
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

fn h3_headers(headers: &[quiche::h3::Header]) -> Vec<Header> {
    headers
        .iter()
        .map(|header| Header {
            name: String::from_utf8_lossy(header.name()).into_owned(),
            value: String::from_utf8_lossy(header.value()).into_owned(),
        })
        .collect()
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
