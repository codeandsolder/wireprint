use std::fmt::Write as _;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use async_compression::tokio::bufread::{BrotliDecoder, GzipDecoder, ZlibDecoder};
use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::{BodyExt, Empty};
use hyper::{Request, StatusCode, header};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{
        Client,
        connect::{HttpConnector, HttpInfo},
    },
    rt::TokioExecutor,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};
use tokio_util::io::StreamReader;
use url::Url;

use crate::classify_response;
use crate::fusion::assess_endpoint;
use crate::model::{EndpointEvidence, Header, Observation, RequestProfile};
use crate::normalize::{NORMALIZER_VERSION, normalize_response_template};
use crate::path::detect_path_elements;
use crate::probe::ProbeConfig;
use crate::routing_context::enrich_observation as enrich_routing_context;
use crate::transport::{HyperRustlsProfileKind, TransportImplementation, TransportProfile};

type NativeClient = Client<HttpsConnector<HttpConnector>, Empty<Bytes>>;
const MAX_REDIRECTS: usize = 10;

pub async fn probe_batch_hyper_rustls(
    profile: &RequestProfile,
    transport: &TransportProfile,
    targets: &[String],
    config: &ProbeConfig,
) -> Result<Vec<Observation>> {
    match transport.implementation.as_ref() {
        Some(TransportImplementation::HyperRustls {
            profile: HyperRustlsProfileKind::Reqwest01228CompatibleRustls02342,
        }) => {}
        Some(_) => bail!(
            "transport profile '{}' is not a hyper/rustls transport",
            transport.name
        ),
        None => bail!(
            "transport profile '{}' is observational only and has no runnable implementation",
            transport.name
        ),
    }

    let https = HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(Arc::new(rustls::crypto::ring::default_provider()))?
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    let client: NativeClient = Client::builder(TokioExecutor::new()).build(https);
    let context = NativeProbeContext {
        client: &client,
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

struct NativeProbeContext<'a> {
    client: &'a NativeClient,
    profile: &'a RequestProfile,
    transport: &'a TransportProfile,
    config: &'a ProbeConfig,
}

#[expect(
    clippy::too_many_lines,
    reason = "redirect handling and request failure provenance form one small native-client state machine"
)]
async fn probe_one(context: &NativeProbeContext<'_>, target: &str) -> Observation {
    let client = context.client;
    let profile = context.profile;
    let transport = context.transport;
    let vantage = context.config.vantage.clone();
    let started = Instant::now();
    let observed_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let mut current = match Url::parse(target) {
        Ok(url) => url,
        Err(error) => {
            return error_observation(
                profile,
                transport,
                target,
                observed_unix_ms,
                started,
                vantage,
                error.to_string(),
            );
        }
    };

    let mut redirects = 0usize;
    let mut allow_sensitive_headers = true;
    let response = loop {
        let mut request = Request::builder().method("GET").uri(current.as_str());
        for field in &profile.headers {
            if allow_sensitive_headers || !is_sensitive_redirect_header(&field.name) {
                request = request.header(field.name.as_str(), field.value.as_str());
            }
        }
        let request = match request.body(Empty::<Bytes>::new()) {
            Ok(request) => request,
            Err(error) => {
                return error_observation(
                    profile,
                    transport,
                    target,
                    observed_unix_ms,
                    started,
                    vantage,
                    error.to_string(),
                );
            }
        };

        let response =
            match tokio::time::timeout(Duration::from_secs(20), client.request(request)).await {
                Ok(Ok(response)) => response,
                Ok(Err(error)) => {
                    return error_observation(
                        profile,
                        transport,
                        target,
                        observed_unix_ms,
                        started,
                        vantage,
                        error.to_string(),
                    );
                }
                Err(_) => {
                    return error_observation(
                        profile,
                        transport,
                        target,
                        observed_unix_ms,
                        started,
                        vantage,
                        "request timed out after 20 seconds".into(),
                    );
                }
            };

        if !is_redirect(response.status()) || redirects >= MAX_REDIRECTS {
            break response;
        }
        let Some(location) = response.headers().get(header::LOCATION) else {
            break response;
        };
        let Ok(location) = location.to_str() else {
            break response;
        };
        let Ok(next) = current.join(location) else {
            break response;
        };
        if !same_origin(&current, &next) {
            allow_sensitive_headers = false;
        }
        current = next;
        redirects += 1;
    };

    finalize_response(
        response,
        context,
        target,
        current,
        observed_unix_ms,
        started,
    )
    .await
}

fn is_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

const fn is_sensitive_redirect_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("cookie")
        || name.eq_ignore_ascii_case("proxy-authorization")
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

#[expect(
    clippy::too_many_lines,
    reason = "response capture, decoding, classification, and evidence fusion are intentionally emitted as one observation transaction"
)]
async fn finalize_response(
    response: hyper::Response<hyper::body::Incoming>,
    context: &NativeProbeContext<'_>,
    target: &str,
    final_url: Url,
    observed_unix_ms: u128,
    started: Instant,
) -> Observation {
    let profile = context.profile;
    let transport = context.transport;
    let body_bytes = context.config.body_bytes;
    let vantage = context.config.vantage.clone();
    let routing_context_collector = context.config.routing_context_collector.as_ref();
    let status = response.status().as_u16();
    let http_version = format!("{:?}", response.version());
    let remote_addr = response
        .extensions()
        .get::<HttpInfo>()
        .map(HttpInfo::remote_addr);
    let remote = remote_addr.map(|value| value.to_string());
    let selected_endpoint = remote_addr.map(|value| value.ip().to_string());
    let encoding = response
        .headers()
        .get(header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(str::to_ascii_lowercase);
    let mut headers = response
        .headers()
        .iter()
        .map(|(key, value)| Header {
            name: key.as_str().to_ascii_lowercase(),
            value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
        })
        .collect::<Vec<_>>();

    let stream = response
        .into_body()
        .into_data_stream()
        .map_err(|error| io::Error::other(error.to_string()));
    let reader = BufReader::new(StreamReader::new(stream));
    let mut reader: Pin<Box<dyn AsyncRead + Send>> = match encoding.as_deref() {
        Some("gzip") => Box::pin(GzipDecoder::new(reader)),
        Some("br") => Box::pin(BrotliDecoder::new(reader)),
        Some("deflate") => Box::pin(ZlibDecoder::new(reader)),
        _ => Box::pin(reader),
    };
    if matches!(encoding.as_deref(), Some("gzip" | "br" | "deflate")) {
        headers.retain(|field| field.name != "content-encoding" && field.name != "content-length");
    }

    let mut body = Vec::with_capacity(body_bytes.min(64 * 1024));
    let mut body_error = None;
    let mut truncated = false;
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
        platform: None,
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
        final_uri: Some(final_url.to_string()),
        remote,
        selected_endpoint,
        dns: None,
        response_headers: headers,
        path_elements,
        routing_elements: Vec::new(),
        provider_signals: Vec::new(),
        routing_context_snapshot: None,
        h2_server_preface: None,
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
    observation.endpoint_assessment = Some(assess_endpoint(&EndpointEvidence::from(&observation)));
    observation
}

fn error_observation(
    profile: &RequestProfile,
    transport: &TransportProfile,
    target: &str,
    observed_unix_ms: u128,
    started: Instant,
    vantage: Option<String>,
    error: String,
) -> Observation {
    Observation {
        target: target.into(),
        observed_unix_ms,
        vantage,
        request_profile: profile.name.clone(),
        request_role: profile.role.clone(),
        request_provenance: profile.provenance.clone(),
        request_profile_headers: profile.headers.clone(),
        transport_profile: transport.name.clone(),
        transport: Some(transport.clone()),
        platform: None,
        result: "error".into(),
        elapsed_ms: started.elapsed().as_millis(),
        status: None,
        http_version: None,
        transport_protocol: None,
        final_uri: None,
        remote: None,
        selected_endpoint: None,
        dns: None,
        response_headers: Vec::new(),
        path_elements: Vec::new(),
        routing_elements: Vec::new(),
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
        error: Some(error),
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
        .find(|field| field.name.eq_ignore_ascii_case("content-type"))
        .map(|field| field.value.to_ascii_lowercase());
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

#[cfg(test)]
mod tests {
    use super::{is_sensitive_redirect_header, same_origin};
    use url::Url;

    #[test]
    fn sensitive_headers_are_not_forwarded_cross_origin() {
        assert!(is_sensitive_redirect_header("Authorization"));
        assert!(is_sensitive_redirect_header("cookie"));
        assert!(is_sensitive_redirect_header("PROXY-AUTHORIZATION"));
        assert!(!is_sensitive_redirect_header("user-agent"));
    }

    #[test]
    fn redirect_origin_comparison_includes_scheme_host_and_effective_port() {
        let base = Url::parse("https://example.test/a").unwrap();
        assert!(same_origin(
            &base,
            &Url::parse("https://example.test/b").unwrap()
        ));
        assert!(same_origin(
            &base,
            &Url::parse("https://example.test:443/b").unwrap()
        ));
        assert!(!same_origin(
            &base,
            &Url::parse("http://example.test/b").unwrap()
        ));
        assert!(!same_origin(
            &base,
            &Url::parse("https://other.test/b").unwrap()
        ));
        assert!(!same_origin(
            &base,
            &Url::parse("https://example.test:8443/b").unwrap()
        ));
    }
}
