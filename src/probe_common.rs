//! Shared HTTP response capture and address-resolution primitives.
//!
//! Transport implementations retain their own request, wire and peer evidence.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use async_compression::tokio::bufread::{BrotliDecoder, GzipDecoder, ZlibDecoder};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncReadExt};
use tokio::net::ToSocketAddrs;

use crate::address_family::AddressFamily;
use crate::cf_ray::detect_cf_ray_provenance;
use crate::classify_response;
use crate::model::{CfRayProvenance, Header, Outcome, PathElement};
pub use crate::passive::finalize_observation;
use crate::passive::{BodyEvidence, body_evidence};
use crate::path::detect_path_elements_with_body;

pub fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

pub fn unique_ips(ips: impl IntoIterator<Item = IpAddr>) -> Vec<String> {
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

/// Resolve and filter before selecting a peer, with no cross-family fallback.
pub async fn resolve_candidates(
    target: impl ToSocketAddrs,
    family: AddressFamily,
) -> Result<Vec<SocketAddr>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for address in tokio::net::lookup_host(target).await? {
        if family.accepts(address) && seen.insert(address) {
            out.push(address);
        }
    }
    Ok(out)
}

pub struct CapturedBody {
    pub body: Vec<u8>,
    pub error: Option<String>,
    pub truncated: bool,
}

/// Decode known content codings, remove invalidated representation headers,
/// and read at most `limit` bytes plus one lookahead for truncation.
pub async fn capture_body<R: AsyncBufRead + Send + 'static>(
    reader: R,
    headers: &mut Vec<Header>,
    limit: usize,
    content_length: Option<u64>,
) -> CapturedBody {
    let encoding = headers
        .iter()
        .find(|field| field.name.eq_ignore_ascii_case("content-encoding"))
        .map(|field| field.value.to_ascii_lowercase());
    let mut reader: Pin<Box<dyn AsyncRead + Send>> = match encoding.as_deref() {
        Some("gzip") => Box::pin(GzipDecoder::new(reader)),
        Some("br") => Box::pin(BrotliDecoder::new(reader)),
        Some("deflate") => Box::pin(ZlibDecoder::new(reader)),
        _ => Box::pin(reader),
    };
    let decoded = matches!(encoding.as_deref(), Some("gzip" | "br" | "deflate"));
    if decoded {
        headers.retain(|field| {
            !field.name.eq_ignore_ascii_case("content-encoding")
                && !field.name.eq_ignore_ascii_case("content-length")
        });
    }

    let mut body = Vec::with_capacity(limit.min(64 * 1024));
    let mut error = None;
    let mut truncated = !decoded && content_length.is_some_and(|length| length > limit as u64);
    let mut chunk = [0_u8; 8192];
    while body.len() <= limit {
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(read) => {
                let remaining = limit.saturating_sub(body.len());
                if read > remaining {
                    body.extend_from_slice(&chunk[..remaining]);
                    truncated = true;
                    break;
                }
                body.extend_from_slice(&chunk[..read]);
            }
            Err(read_error) => {
                error = Some(read_error.to_string());
                break;
            }
        }
    }
    CapturedBody {
        body,
        error,
        truncated,
    }
}

pub struct ClassifiedResponse {
    pub headers: Vec<Header>,
    pub captured_bytes: usize,
    pub error: Option<String>,
    pub truncated: bool,
    pub outcome: Outcome,
    pub path_elements: Vec<PathElement>,
    pub cf_ray_provenance: Option<CfRayProvenance>,
    pub evidence: BodyEvidence,
}

/// Decode and classify the exact bounded body both HTTP transports observed.
pub async fn capture_classified_response<R: AsyncBufRead + Send + 'static>(
    reader: R,
    mut headers: Vec<Header>,
    limit: usize,
    content_length: Option<u64>,
    status: u16,
) -> ClassifiedResponse {
    let captured = capture_body(reader, &mut headers, limit, content_length).await;
    ClassifiedResponse {
        outcome: classify_response(status, &headers, &captured.body),
        path_elements: detect_path_elements_with_body(&headers, &captured.body),
        cf_ray_provenance: detect_cf_ray_provenance(&headers),
        evidence: body_evidence(&headers, &captured.body),
        captured_bytes: captured.body.len(),
        error: captured.error,
        truncated: captured.truncated,
        headers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    fn header(name: &str, value: &str) -> Header {
        Header {
            name: name.into(),
            value: value.into(),
        }
    }

    #[tokio::test]
    async fn bounded_body_read_distinguishes_exact_from_truncated_and_zero_limit() {
        for (limit, expected, truncated) in [
            (4, b"abcd".as_slice(), false),
            (3, b"abc".as_slice(), true),
            (0, b"".as_slice(), true),
        ] {
            let mut headers = vec![];
            let captured = capture_body(
                BufReader::new(std::io::Cursor::new(b"abcd".to_vec())),
                &mut headers,
                limit,
                None,
            )
            .await;
            assert_eq!(captured.body, expected);
            assert_eq!(captured.truncated, truncated);
            assert!(captured.error.is_none());
        }
    }

    #[tokio::test]
    async fn decoded_body_strips_invalid_representation_headers() {
        // gzip("hello") with fixed mtime=0
        let gzip: [u8; 25] = [
            31, 139, 8, 0, 0, 0, 0, 0, 2, 3, 203, 72, 205, 201, 201, 7, 0, 134, 166, 16, 54, 5, 0,
            0, 0,
        ];
        let mut headers = vec![
            header("Content-Encoding", "gzip"),
            header("Content-Length", "25"),
            header("Content-Type", "text/plain"),
        ];
        let captured = capture_body(
            BufReader::new(std::io::Cursor::new(gzip)),
            &mut headers,
            16,
            Some(25),
        )
        .await;
        assert_eq!(captured.body, b"hello");
        assert_eq!(captured.error, None);
        assert!(!captured.truncated);
        assert_eq!(headers, vec![header("Content-Type", "text/plain")]);
    }

    #[test]
    fn unique_ips_preserves_first_seen_order() {
        let ip = "127.0.0.1".parse().unwrap();
        let other = "::1".parse().unwrap();
        assert_eq!(unique_ips([ip, other, ip]), vec!["127.0.0.1", "::1"]);
    }
}
