//! Classification of traffic already observed by the application.
//!
//! No functions here open connections, issue requests, resolve DNS or alter
//! request/response bodies. The caller supplies actual peer and DNS evidence;
//! absent observations stay absent.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

use crate::{
    cf_ray::detect_cf_ray_provenance,
    classify_response,
    fusion::assess_endpoint,
    h2::{H2ServerPreface, H2Setting, classify_h2_preface},
    model::{EndpointEvidence, Header, Observation, ProviderEvidenceChannel},
    normalize::{NORMALIZER_VERSION, normalize_response_template},
    path::detect_path_elements_with_body,
    routing::detect_routing_snapshot_elements,
};

/// Extract the peer's actual HTTP/2 preface from Wreq connection metadata.
#[must_use = "the returned fingerprint identifies observed peer settings"]
pub fn h2_from_wreq_response(response: &wreq::Response) -> Option<H2ServerPreface> {
    response
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
        })
}

/// Classify an existing observation using its actual headers, bounded decoded
/// body prefix, DNS and transport evidence.
///
/// The caller owns body capture and
/// decides whether to persist raw body bytes separately. This function clears
/// any previously stored raw body prefix. Repeated calls replace derived
/// evidence rather than append duplicate provider signals.
pub fn classify_observation(observation: &mut Observation, body_prefix: Option<&[u8]>) {
    let body = body_prefix.unwrap_or_default();
    observation.outcome = observation
        .status
        .map(|status| classify_response(status, &observation.response_headers, body));
    observation.path_elements = detect_path_elements_with_body(&observation.response_headers, body);
    observation.cf_ray_provenance = detect_cf_ray_provenance(&observation.response_headers);
    observation.routing_elements = observation
        .dns
        .as_ref()
        .map_or_default(detect_routing_snapshot_elements);
    observation.provider_signals.retain(|signal| {
        matches!(
            signal.channel,
            ProviderEvidenceChannel::ResponseMetadata | ProviderEvidenceChannel::RoutingDns
        )
    });
    if let Some(preface) = &observation.h2_server_preface {
        observation
            .provider_signals
            .extend(crate::h2::provider_signals(preface));
    }
    if let Some(fingerprint) = &observation.h3_server_fingerprint {
        observation
            .provider_signals
            .extend(crate::h3::provider_signals(fingerprint));
    }
    if let Some(morphology) = &observation.tls_server_morphology {
        observation
            .provider_signals
            .extend(crate::tls::provider_signals(morphology));
    }
    observation.body_prefix = None;
    observation.body_captured_bytes = None;
    observation.body_prefix_sha256 = None;
    observation.body_template_sha256 = None;
    observation.body_template_normalizer = None;
    if let Some(body) = body_prefix {
        let evidence = body_evidence(&observation.response_headers, body);
        observation.body_captured_bytes = Some(body.len());
        observation.body_prefix_sha256 = Some(evidence.sha256);
        observation.body_template_sha256 = evidence.template_sha256;
        observation.body_template_normalizer = evidence.template_normalizer;
        // Do not implicitly persist potentially sensitive response text.
    }
    observation.endpoint_assessment = Some(assess_endpoint(&EndpointEvidence::from(&*observation)));
}

#[derive(Debug)]
pub struct BodyEvidence {
    pub sha256: String,
    pub template_sha256: Option<String>,
    pub template_normalizer: Option<String>,
    pub prefix: Option<String>,
}

/// Hash and normalize the already observed body prefix.
#[must_use = "the returned evidence describes the captured bytes"]
pub fn body_evidence(headers: &[Header], body: &[u8]) -> BodyEvidence {
    let sha256 = hex_digest(Sha256::digest(body));
    if !is_textual_response(headers, body) {
        return BodyEvidence {
            sha256,
            template_sha256: None,
            template_normalizer: None,
            prefix: None,
        };
    }
    let normalized = normalize_response_template(body);
    BodyEvidence {
        sha256,
        template_sha256: Some(hex_digest(Sha256::digest(normalized.as_bytes()))),
        template_normalizer: Some(NORMALIZER_VERSION.into()),
        prefix: Some(String::from_utf8_lossy(body).into_owned()),
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

/// Fuse the supplied endpoint evidence without additional network requests.
#[must_use = "the returned observation contains the endpoint assessment"]
pub fn finalize_observation(mut observation: Observation) -> Observation {
    observation.endpoint_assessment = Some(assess_endpoint(&EndpointEvidence::from(&observation)));
    observation
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, value: &str) -> Header {
        Header {
            name: name.into(),
            value: value.into(),
        }
    }

    #[test]
    fn textual_response_uses_content_type_or_utf8_fallback() {
        assert!(is_textual_response(&[], b"plain text"));
        assert!(!is_textual_response(&[], &[0xff]));
        assert!(is_textual_response(
            &[header("Content-Type", "application/json")],
            b"{}"
        ));
        assert!(!is_textual_response(
            &[header("Content-Type", "image/png")],
            b"printable"
        ));
    }
}
