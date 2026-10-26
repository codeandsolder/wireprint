use std::fmt::Write as _;
use std::io;
use std::pin::Pin;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use async_compression::tokio::bufread::{BrotliDecoder, GzipDecoder, ZlibDecoder};
use futures_util::TryStreamExt;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};
use tokio_util::io::StreamReader;

use crate::classify_response;
use crate::dns::{
    RecordingResolver, RoutingDnsSnapshot, RoutingDnsSnapshotter, build_dns_provenance,
    host_from_url, routing_names, selected_endpoint,
};
use crate::fusion::assess_endpoint;
use crate::h2::{H2Setting, classify_h2_preface, provider_signals as h2_provider_signals};
use crate::model::{
    DnsProvenance, EndpointEvidence, Header, Observation, PathElement, RequestProfile,
};
use crate::normalize::{NORMALIZER_VERSION, normalize_response_template};
use crate::path::detect_path_elements;
use crate::routing::detect_routing_elements;
use crate::routing_context::{
    RoutingContextCollector, enrich_observation as enrich_routing_context,
};
use crate::transport::{TransportImplementation, TransportProfile};

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub body_bytes: usize,
    pub delay: Duration,
    pub vantage: Option<String>,
    pub routing_context_collector: Option<RoutingContextCollector>,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            body_bytes: 64 * 1024,
            delay: Duration::from_millis(250),
            vantage: None,
            routing_context_collector: None,
        }
    }
}

/// Probe a batch of targets with one request and transport profile.
///
/// # Errors
///
/// Returns an error when the selected transport cannot be configured or its client cannot be built.
pub async fn probe_batch(
    profile: &RequestProfile,
    transport: &TransportProfile,
    targets: &[String],
    config: &ProbeConfig,
) -> Result<Vec<Observation>> {
    if matches!(
        transport.implementation.as_ref(),
        Some(TransportImplementation::HyperRustls { .. })
    ) {
        return crate::hyper_probe::probe_batch_hyper_rustls(profile, transport, targets, config)
            .await;
    }
    let connection_resolver = RecordingResolver::default();
    let routing_resolver = RoutingDnsSnapshotter::new();
    let builder = wreq::Client::builder()
        .tls_info(true)
        .timeout(Duration::from_secs(20))
        .connect_timeout(Duration::from_secs(8))
        .dns_resolver(connection_resolver.clone());
    let client = transport.configure(builder)?.build()?;
    let context = WreqProbeContext {
        client: &client,
        connection_resolver: &connection_resolver,
        routing_resolver: &routing_resolver,
        profile,
        transport,
        config,
    };
    let mut observations = Vec::with_capacity(targets.len());

    for (index, target) in targets.iter().enumerate() {
        if index > 0 && !config.delay.is_zero() {
            tokio::time::sleep(config.delay).await;
        }
        observations.push(probe_one(&context, target).await);
    }
    Ok(observations)
}

struct WreqProbeContext<'a> {
    client: &'a wreq::Client,
    connection_resolver: &'a RecordingResolver,
    routing_resolver: &'a RoutingDnsSnapshotter,
    profile: &'a RequestProfile,
    transport: &'a TransportProfile,
    config: &'a ProbeConfig,
}

#[expect(
    clippy::too_many_lines,
    reason = "the request/response evidence state machine is easier to audit when its ordering remains contiguous"
)]
async fn probe_one(context: &WreqProbeContext<'_>, target: &str) -> Observation {
    let client = context.client;
    let connection_resolver = context.connection_resolver;
    let routing_resolver = context.routing_resolver;
    let profile = context.profile;
    let transport = context.transport;
    let body_bytes = context.config.body_bytes;
    let vantage = context.config.vantage.clone();
    let routing_context_collector = context.config.routing_context_collector.as_ref();
    let started = Instant::now();
    let observed_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let resolver_cursor = connection_resolver.cursor();
    let target_host = host_from_url(target);

    let routing_future = async {
        match target_host.as_deref() {
            Some(host) => Some(routing_resolver.capture(host).await),
            None => None,
        }
    };

    let request_future = async {
        let mut request = client.get(target);
        for header in &profile.headers {
            request = request.header(header.name.as_str(), header.value.as_str());
        }
        request.send().await
    };

    let (response, target_routing) = tokio::join!(request_future, routing_future);
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            let dns = target_host
                .as_deref()
                .zip(target_routing)
                .map(|(host, routing)| {
                    dns_for_host(connection_resolver, host, resolver_cursor, routing)
                });
            let routing_elements = routing_elements_for_dns(dns.as_ref());
            let observation = Observation {
                target: target.into(),
                observed_unix_ms,
                vantage,
                request_profile: profile.name.clone(),
                request_role: profile.role.clone(),
                request_provenance: profile.provenance.clone(),
                request_profile_headers: profile.headers.clone(),
                transport_profile: transport.name.clone(),
                transport: Some(transport.clone()),
                platform: transport.platform().map(|value| value.name().into()),
                result: "error".into(),
                elapsed_ms: started.elapsed().as_millis(),
                status: None,
                http_version: None,
                transport_protocol: None,
                final_uri: None,
                remote: None,
                selected_endpoint: None,
                dns,
                response_headers: Vec::new(),
                path_elements: Vec::new(),
                routing_elements,
                provider_signals: Vec::new(),
                routing_context_snapshot: None,
                h2_server_preface: None,
                h3_server_fingerprint: None,
                tls_server_morphology: None,
                endpoint_assessment: None,
                body_captured_bytes: None,
                body_prefix_sha256: None,
                body_template_sha256: None,
                body_template_normalizer: None,
                body_prefix: None,
                body_truncated: None,
                outcome: None,
                error: Some(error.to_string()),
            };
            return finalize_observation(observation);
        }
    };

    let status = response.status().as_u16();
    let http_version = format!("{:?}", response.version());
    let final_uri = response.uri().to_string();
    let final_host = host_from_url(&final_uri).or_else(|| target_host.clone());
    let remote_addr = response.remote_addr();
    let remote = remote_addr.map(|value| value.to_string());
    let content_length = response.content_length();
    let h2_server_preface = response
        .extensions()
        .get::<wreq::http2::Http2Info>()
        .map(|info| {
            classify_h2_preface(
                info.peer_initial_settings_received(),
                info.peer_initial_settings()
                    .iter()
                    .map(|setting| H2Setting {
                        id: setting.id(),
                        value: setting.value(),
                    })
                    .collect(),
                info.peer_first_connection_window_update(),
                info.peer_first_connection_window_update_before_settings_ack(),
                info.peer_acknowledged_local_initial_settings(),
            )
        });
    let provider_signals = h2_server_preface
        .as_ref()
        .map(h2_provider_signals)
        .unwrap_or_default();
    let mut headers = response
        .headers()
        .iter()
        .map(|(key, value)| Header {
            name: key.as_str().to_ascii_lowercase(),
            value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
        })
        .collect::<Vec<_>>();
    let encoding = headers
        .iter()
        .find(|field| field.name.eq_ignore_ascii_case("content-encoding"))
        .map(|field| field.value.to_ascii_lowercase());

    let routing = match (&target_host, &final_host, target_routing) {
        (Some(target_host), Some(final_host), Some(snapshot)) if target_host == final_host => {
            Some(snapshot)
        }
        (_, Some(final_host), _) => Some(routing_resolver.capture(final_host).await),
        _ => None,
    };
    let dns = final_host
        .as_deref()
        .zip(routing)
        .map(|(host, routing)| dns_for_host(connection_resolver, host, resolver_cursor, routing));
    let selected_endpoint = selected_endpoint(remote_addr, dns.as_ref());
    let routing_elements = routing_elements_for_dns(dns.as_ref());

    let stream = response
        .bytes_stream()
        .map_err(|error| io::Error::other(error.to_string()));
    let reader = BufReader::new(StreamReader::new(stream));
    let mut reader: Pin<Box<dyn AsyncRead + Send>> = match encoding.as_deref() {
        Some("gzip") => Box::pin(GzipDecoder::new(reader)),
        Some("br") => Box::pin(BrotliDecoder::new(reader)),
        Some("deflate") => Box::pin(ZlibDecoder::new(reader)),
        _ => Box::pin(reader),
    };
    let decoded = matches!(encoding.as_deref(), Some("gzip" | "br" | "deflate"));
    if decoded {
        headers.retain(|field| field.name != "content-encoding" && field.name != "content-length");
    }

    let mut body = Vec::with_capacity(body_bytes.min(64 * 1024));
    let mut body_error = None;
    let mut truncated = !decoded && content_length.is_some_and(|length| length > body_bytes as u64);
    let mut chunk = [0_u8; 8192];
    while body.len() <= body_bytes {
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(read) => {
                let remaining = body_bytes.saturating_sub(body.len());
                if read > remaining {
                    body.extend_from_slice(&chunk[..remaining]);
                    truncated = true;
                    break;
                }
                body.extend_from_slice(&chunk[..read]);
            }
            Err(error) => {
                body_error = Some(error.to_string());
                break;
            }
        }
    }

    let outcome = classify_response(status, &headers, &body);
    let path_elements = detect_path_elements(&headers);
    let digest = hex_digest(Sha256::digest(&body));
    let textual = is_textual_response(&headers, &body);
    let (template_digest, template_normalizer, body_prefix) = if textual {
        let normalized = normalize_response_template(&body);
        (
            Some(hex_digest(Sha256::digest(normalized.as_bytes()))),
            Some(NORMALIZER_VERSION.into()),
            Some(String::from_utf8_lossy(&body).into_owned()),
        )
    } else {
        (None, None, None)
    };

    let mut observation = Observation {
        target: target.into(),
        observed_unix_ms,
        vantage,
        request_profile: profile.name.clone(),
        request_role: profile.role.clone(),
        request_provenance: profile.provenance.clone(),
        request_profile_headers: profile.headers.clone(),
        transport_profile: transport.name.clone(),
        transport: Some(transport.clone()),
        platform: transport.platform().map(|value| value.name().into()),
        result: if body_error.is_some() {
            "partial_response"
        } else {
            "response"
        }
        .into(),
        elapsed_ms: started.elapsed().as_millis(),
        status: Some(status),
        http_version: Some(http_version),
        transport_protocol: None,
        final_uri: Some(final_uri),
        remote,
        selected_endpoint,
        dns,
        response_headers: headers,
        path_elements,
        routing_elements,
        provider_signals,
        routing_context_snapshot: None,
        h2_server_preface,
        h3_server_fingerprint: None,
        tls_server_morphology: None,
        endpoint_assessment: None,
        body_captured_bytes: Some(body.len()),
        body_prefix_sha256: Some(digest),
        body_template_sha256: template_digest,
        body_template_normalizer: template_normalizer,
        body_prefix,
        body_truncated: Some(truncated),
        outcome: Some(outcome),
        error: body_error,
    };
    if let Some(collector) = routing_context_collector {
        enrich_routing_context(&mut observation, collector).await;
    }
    finalize_observation(observation)
}

fn dns_for_host(
    connection_resolver: &RecordingResolver,
    host: &str,
    cursor: u64,
    routing: RoutingDnsSnapshot,
) -> DnsProvenance {
    let connection = connection_resolver.latest(host);
    build_dns_provenance(host, cursor, connection.as_ref(), routing)
}

fn routing_elements_for_dns(dns: Option<&DnsProvenance>) -> Vec<PathElement> {
    dns.map(routing_names)
        .map(|names| detect_routing_elements(&names))
        .unwrap_or_default()
}

fn finalize_observation(mut observation: Observation) -> Observation {
    let evidence = EndpointEvidence::from(&observation);
    observation.endpoint_assessment = Some(assess_endpoint(&evidence));
    observation
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn is_textual_response(headers: &[Header], body: &[u8]) -> bool {
    let content_type = headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-type"))
        .map(|header| header.value.to_ascii_lowercase());
    content_type.map_or_else(
        || std::str::from_utf8(body).is_ok(),
        |value| {
            value.starts_with("text/")
                || value.contains("json")
                || value.contains("javascript")
                || value.contains("xml")
                || value.contains("x-www-form-urlencoded")
        },
    )
}
