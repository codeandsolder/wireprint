use std::fmt::Write as _;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};

use crate::classify_response;
use crate::model::{Header, Observation, RequestProfile};
use crate::normalize::{NORMALIZER_VERSION, normalize_response_template};
use crate::path::detect_path_elements;
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
    let builder = wreq::Client::builder()
        .tls_info(true)
        .timeout(Duration::from_secs(20))
        .connect_timeout(Duration::from_secs(8));
    let client = transport.configure(builder, platform).build()?;
    let mut observations = Vec::with_capacity(targets.len());

    for (index, target) in targets.iter().enumerate() {
        if index > 0 && !config.delay.is_zero() {
            tokio::time::sleep(config.delay).await;
        }
        observations.push(
            probe_one(
                &client,
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

async fn probe_one(
    client: &wreq::Client,
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
    let mut request = client.get(target);
    for header in &profile.headers {
        request = request.header(header.name.as_str(), header.value.as_str());
    }

    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => {
            return Observation {
                target: target.into(),
                observed_unix_ms,
                vantage: vantage.clone(),
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
                response_headers: Vec::new(),
                path_elements: Vec::new(),
                body_captured_bytes: None,
                body_prefix_sha256: None,
                body_template_sha256: None,
                body_template_normalizer: None,
                body_prefix: None,
                body_truncated: None,
                outcome: None,
                error: Some(error.to_string()),
            };
        }
    };

    let status = response.status().as_u16();
    let http_version = format!("{:?}", response.version());
    let final_uri = response.uri().to_string();
    let remote = response.remote_addr().map(|value| value.to_string());
    let content_length = response.content_length();
    let headers = response
        .headers()
        .iter()
        .map(|(key, value)| Header {
            name: key.as_str().to_ascii_lowercase(),
            value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
        })
        .collect::<Vec<_>>();

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
    Observation {
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
        response_headers: headers,
        path_elements,
        body_captured_bytes: Some(body.len()),
        body_prefix_sha256: Some(digest),
        body_template_sha256: template_digest,
        body_template_normalizer: template_normalizer,
        body_prefix,
        body_truncated: Some(truncated),
        outcome: Some(outcome),
        error: body_error,
    }
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
