use std::fmt::Write as _;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};

use crate::classify_response;
use crate::dns::{
    RecordingResolver, RoutingDnsSnapshot, RoutingDnsSnapshotter, build_dns_provenance,
    host_from_url, routing_names, selected_endpoint,
};
use crate::fusion::assess_endpoint;
use crate::model::{
    DnsProvenance, EndpointEvidence, Header, Observation, PathElement, RequestProfile,
};
use crate::normalize::{NORMALIZER_VERSION, normalize_response_template};
use crate::path::detect_path_elements;
use crate::routing::detect_routing_elements;
use crate::transport::{PlatformKind, TransportProfile};

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub body_bytes: usize,
    pub delay: Duration,
    pub vantage: Option<String>,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            body_bytes: 64 * 1024,
            delay: Duration::from_millis(250),
            vantage: None,
        }
    }
}

pub async fn probe_batch(
    profile: &RequestProfile,
    transport: TransportProfile,
    platform: PlatformKind,
    targets: &[String],
    config: &ProbeConfig,
) -> Result<Vec<Observation>> {
    let connection_resolver = RecordingResolver::default();
    let routing_resolver = RoutingDnsSnapshotter::new();
    let builder = wreq::Client::builder()
        .tls_info(true)
        .timeout(Duration::from_secs(20))
        .connect_timeout(Duration::from_secs(8))
        .dns_resolver(connection_resolver.clone());
    let client = transport.configure(builder, platform).build()?;
    let mut observations = Vec::with_capacity(targets.len());

    for (index, target) in targets.iter().enumerate() {
        if index > 0 && !config.delay.is_zero() {
            tokio::time::sleep(config.delay).await;
        }
        observations.push(
            probe_one(
                &client,
                &connection_resolver,
                &routing_resolver,
                profile,
                transport,
                platform,
                target,
                config.body_bytes,
                config.vantage.clone(),
            )
            .await,
        );
    }
    Ok(observations)
}

#[allow(clippy::too_many_arguments)]
async fn probe_one(
    client: &wreq::Client,
    connection_resolver: &RecordingResolver,
    routing_resolver: &RoutingDnsSnapshotter,
    profile: &RequestProfile,
    transport: TransportProfile,
    platform: PlatformKind,
    target: &str,
    body_bytes: usize,
    vantage: Option<String>,
) -> Observation {
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
                request_headers: profile.headers.clone(),
                transport_profile: transport.name().into(),
                platform: platform.name().into(),
                result: "error".into(),
                elapsed_ms: started.elapsed().as_millis(),
                status: None,
                http_version: None,
                final_uri: None,
                remote: None,
                selected_endpoint: None,
                dns,
                response_headers: Vec::new(),
                path_elements: Vec::new(),
                routing_elements,
                provider_signals: Vec::new(),
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
    let final_host = host_from_url(&final_uri).or(target_host.clone());
    let remote_addr = response.remote_addr();
    let remote = remote_addr.map(|value| value.to_string());
    let content_length = response.content_length();
    let headers = response
        .headers()
        .iter()
        .map(|(key, value)| Header {
            name: key.as_str().to_ascii_lowercase(),
            value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
        })
        .collect::<Vec<_>>();

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

    let mut body = Vec::with_capacity(body_bytes.min(64 * 1024));
    let mut truncated = content_length.is_some_and(|length| length > body_bytes as u64);
    let mut stream = response.bytes_stream();
    let mut body_error = None;
    while let Some(item) = stream.next().await {
        match item {
            Ok(chunk) => {
                let remaining = body_bytes.saturating_sub(body.len());
                if remaining == 0 {
                    truncated = true;
                    break;
                }
                if chunk.len() > remaining {
                    body.extend_from_slice(&chunk[..remaining]);
                    truncated = true;
                    break;
                }
                body.extend_from_slice(&chunk);
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

    let observation = Observation {
        target: target.into(),
        observed_unix_ms,
        vantage,
        request_profile: profile.name.clone(),
        request_role: profile.role.clone(),
        request_provenance: profile.provenance.clone(),
        request_headers: profile.headers.clone(),
        transport_profile: transport.name().into(),
        platform: platform.name().into(),
        result: if body_error.is_some() {
            "partial_response"
        } else {
            "response"
        }
        .into(),
        elapsed_ms: started.elapsed().as_millis(),
        status: Some(status),
        http_version: Some(http_version),
        final_uri: Some(final_uri),
        remote,
        selected_endpoint,
        dns,
        response_headers: headers,
        path_elements,
        routing_elements,
        // Current wreq observations do not expose the server H2/H3/TLS family
        // features used by the research classifiers. Do not manufacture provider
        // signals from client transport profile or negotiated HTTP version.
        provider_signals: Vec::new(),
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
    finalize_observation(observation)
}

fn dns_for_host(
    connection_resolver: &RecordingResolver,
    host: &str,
    cursor: u64,
    routing: RoutingDnsSnapshot,
) -> DnsProvenance {
    build_dns_provenance(host, cursor, connection_resolver.latest(host), routing)
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
    match content_type {
        Some(value) => {
            value.starts_with("text/")
                || value.contains("json")
                || value.contains("javascript")
                || value.contains("xml")
                || value.contains("x-www-form-urlencoded")
        }
        None => std::str::from_utf8(body).is_ok(),
    }
}
