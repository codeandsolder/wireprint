use serde::{Deserialize, Serialize};

use crate::model::{ProviderEvidenceChannel, ProviderSignal};

pub const H2_PREFACE_CLASSIFIER_VERSION: &str = "builtin-h2-preface-v1";
const H2_INITIAL_CONNECTION_WINDOW: u64 = 65_535;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct H2Setting {
    pub id: u16,
    pub value: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum H2ControlFrame {
    Settings,
    WindowUpdate,
    SettingsAck,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum H2FingerprintMatchKind {
    Exact,
    FamilyRule,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct H2FingerprintMatch {
    pub name: String,
    pub kind: H2FingerprintMatchKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_family: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implementation_family: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct H2ServerPreface {
    pub classifier: String,
    pub peer_initial_settings_received: bool,
    pub settings: Vec<H2Setting>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_connection_window_update: Option<u32>,
    pub effective_connection_window: u64,
    pub peer_acknowledged_local_initial_settings: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_connection_window_update_before_settings_ack: Option<bool>,
    pub control_order: Vec<H2ControlFrame>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exact_match: Option<H2FingerprintMatch>,
    #[serde(default)]
    pub family_matches: Vec<H2FingerprintMatch>,
}

#[derive(Clone, Copy)]
struct ExactFingerprint {
    name: &'static str,
    settings: &'static [(u16, u32)],
    connection_window: u64,
    control_order: &'static [H2ControlFrame],
    provider_family: Option<&'static str>,
    implementation_family: Option<&'static str>,
}

#[derive(Clone, Copy)]
struct FamilyRule {
    name: &'static str,
    settings_order: &'static [u16],
    settings_values: &'static [(u16, u32)],
    connection_window: u64,
    control_order: &'static [H2ControlFrame],
    implementation_family: &'static str,
}

const SETTINGS_WU_ACK: &[H2ControlFrame] = &[
    H2ControlFrame::Settings,
    H2ControlFrame::WindowUpdate,
    H2ControlFrame::SettingsAck,
];
const SETTINGS_ACK: &[H2ControlFrame] = &[H2ControlFrame::Settings, H2ControlFrame::SettingsAck];
const SETTINGS_ACK_WU: &[H2ControlFrame] = &[
    H2ControlFrame::Settings,
    H2ControlFrame::SettingsAck,
    H2ControlFrame::WindowUpdate,
];

const EXACT_FINGERPRINTS: &[ExactFingerprint] = &[
    ExactFingerprint {
        name: "cloudflare-current-corpus",
        settings: &[(3, 100), (4, 65_536), (5, 16_777_215)],
        connection_window: 2_147_483_647,
        control_order: SETTINGS_WU_ACK,
        provider_family: Some("cloudflare"),
        implementation_family: None,
    },
    ExactFingerprint {
        name: "nginx-classic-default-preface",
        settings: &[(3, 128), (4, 65_536), (5, 16_777_215)],
        connection_window: 2_147_483_647,
        control_order: SETTINGS_WU_ACK,
        provider_family: None,
        implementation_family: Some("nginx / nginx-derived classic HTTP/2 server defaults"),
    },
    ExactFingerprint {
        name: "fastly-h2o-edge-current-config",
        settings: &[(1, 8192), (3, 100), (18_550, 0)],
        connection_window: 16_777_216,
        control_order: SETTINGS_WU_ACK,
        provider_family: Some("fastly"),
        implementation_family: Some("Fastly edge proxy / H2O-derived HTTP/2 stack"),
    },
    ExactFingerprint {
        name: "akamai-current-corpus",
        settings: &[(1, 4096), (3, 100), (4, 65_535), (5, 16_384), (6, 32_768)],
        connection_window: 65_535,
        control_order: SETTINGS_ACK,
        provider_family: Some("akamai"),
        implementation_family: None,
    },
    ExactFingerprint {
        name: "f5-volt-envoy-current-config",
        settings: &[(1, 4096), (8, 0), (3, 100), (4, 524_288)],
        connection_window: 4_194_304,
        control_order: SETTINGS_ACK_WU,
        provider_family: Some("f5-volt"),
        implementation_family: Some("F5 Distributed Cloud Volt ADC / Envoy-based HTTP proxy"),
    },
    ExactFingerprint {
        name: "imperva-cloud-current-config",
        settings: &[(4, 20_000_000), (3, 128)],
        connection_window: 20_000_000,
        control_order: SETTINGS_WU_ACK,
        provider_family: Some("imperva"),
        implementation_family: Some("Imperva Cloud edge termination"),
    },
    ExactFingerprint {
        name: "google-edge-current-corpus",
        settings: &[(3, 100), (4, 1_048_576), (6, 65_536)],
        connection_window: 1_048_576,
        control_order: SETTINGS_WU_ACK,
        provider_family: Some("google-gfe"),
        implementation_family: Some("Google Front End (GFE) / Google edge termination family"),
    },
    ExactFingerprint {
        name: "go-x-net-http2-vercel-config",
        settings: &[
            (5, 1_048_576),
            (3, 160),
            (6, 2_097_472),
            (1, 4096),
            (4, 1_048_576),
        ],
        connection_window: 1_048_576,
        control_order: SETTINGS_WU_ACK,
        provider_family: None,
        implementation_family: Some("Go golang.org/x/net/http2 server wire family"),
    },
    ExactFingerprint {
        name: "go-x-net-http2-netlify-config",
        settings: &[
            (5, 1_048_576),
            (3, 100),
            (6, 1_048_896),
            (1, 4096),
            (4, 1_048_576),
        ],
        connection_window: 1_048_576,
        control_order: SETTINGS_WU_ACK,
        provider_family: Some("netlify"),
        implementation_family: Some("Go golang.org/x/net/http2 server wire family"),
    },
    ExactFingerprint {
        name: "envoy-quiche-256m-current-config",
        settings: &[(1, 4096), (3, 2_147_483_647), (4, 268_435_456), (8, 0)],
        connection_window: 268_435_456,
        control_order: SETTINGS_WU_ACK,
        provider_family: None,
        implementation_family: Some("Envoy HTTP/2 server via QUICHE HTTP/2 adapter"),
    },
    ExactFingerprint {
        name: "go-x-net-http2-default-preface",
        settings: &[
            (5, 1_048_576),
            (3, 250),
            (6, 1_048_896),
            (1, 4096),
            (4, 1_048_576),
        ],
        connection_window: 1_048_576,
        control_order: SETTINGS_WU_ACK,
        provider_family: None,
        implementation_family: Some("Go golang.org/x/net/http2 server defaults"),
    },
    ExactFingerprint {
        name: "haproxy-www-current-config",
        settings: &[(8, 1), (4, 1_048_576), (3, 100), (5, 32_768)],
        connection_window: 65_535,
        control_order: SETTINGS_ACK,
        provider_family: None,
        implementation_family: Some("HAProxy HTTP/2 frontend"),
    },
    ExactFingerprint {
        name: "haproxy-org-current-config",
        settings: &[(8, 1), (4, 32_720), (3, 30), (5, 32_768)],
        connection_window: 65_535,
        control_order: SETTINGS_ACK,
        provider_family: None,
        implementation_family: Some("HAProxy HTTP/2 frontend"),
    },
    ExactFingerprint {
        name: "haproxy-allegro-www-config",
        settings: &[(8, 1), (4, 20_424), (3, 100), (5, 20_480)],
        connection_window: 65_535,
        control_order: SETTINGS_ACK,
        provider_family: None,
        implementation_family: Some("HAProxy HTTP/2 frontend wire family"),
    },
    ExactFingerprint {
        name: "haproxy-allegro-bare-config",
        settings: &[(8, 1), (4, 16_384), (3, 100)],
        connection_window: 65_535,
        control_order: SETTINGS_ACK,
        provider_family: None,
        implementation_family: Some("HAProxy HTTP/2 frontend wire family"),
    },
    ExactFingerprint {
        name: "haproxy-github-current-layout-config",
        settings: &[(8, 1), (4, 68_560), (3, 100), (5, 68_608)],
        connection_window: 65_535,
        control_order: SETTINGS_ACK,
        provider_family: None,
        implementation_family: Some("HAProxy HTTP/2 frontend"),
    },
];

const FAMILY_RULES: &[FamilyRule] = &[
    FamilyRule {
        name: "nginx-h2-classic-preface-shape",
        settings_order: &[3, 4, 5],
        settings_values: &[(5, 16_777_215)],
        connection_window: 2_147_483_647,
        control_order: SETTINGS_WU_ACK,
        implementation_family: "nginx / nginx-derived classic HTTP/2 preface",
    },
    FamilyRule {
        name: "nginx-h2-rfc9218-preface-shape",
        settings_order: &[3, 4, 5, 9],
        settings_values: &[(5, 16_777_215), (9, 1)],
        connection_window: 2_147_483_647,
        control_order: SETTINGS_WU_ACK,
        implementation_family: "nginx / nginx-derived RFC 9218 HTTP/2 preface",
    },
    FamilyRule {
        name: "go-x-net-http2-common-preface-shape",
        settings_order: &[5, 3, 6, 1, 4],
        settings_values: &[(5, 1_048_576), (1, 4096), (4, 1_048_576)],
        connection_window: 1_048_576,
        control_order: SETTINGS_WU_ACK,
        implementation_family: "Go golang.org/x/net/http2 server common/default configuration family",
    },
    FamilyRule {
        name: "haproxy-h2-frontend-preface-with-max-frame",
        settings_order: &[8, 4, 3, 5],
        settings_values: &[(8, 1)],
        connection_window: 65_535,
        control_order: SETTINGS_ACK,
        implementation_family: "HAProxy HTTP/2 frontend",
    },
    FamilyRule {
        name: "haproxy-h2-frontend-preface-default-max-frame",
        settings_order: &[8, 4, 3],
        settings_values: &[(8, 1)],
        connection_window: 65_535,
        control_order: SETTINGS_ACK,
        implementation_family: "HAProxy HTTP/2 frontend",
    },
];

pub fn classify_h2_preface(
    peer_initial_settings_received: bool,
    settings: Vec<H2Setting>,
    first_connection_window_update: Option<u32>,
    first_connection_window_update_before_settings_ack: Option<bool>,
    peer_acknowledged_local_initial_settings: bool,
) -> H2ServerPreface {
    let effective_connection_window =
        H2_INITIAL_CONNECTION_WINDOW + u64::from(first_connection_window_update.unwrap_or(0));
    let control_order = derive_control_order(
        peer_initial_settings_received,
        first_connection_window_update,
        first_connection_window_update_before_settings_ack,
        peer_acknowledged_local_initial_settings,
    );

    let exact = EXACT_FINGERPRINTS
        .iter()
        .find(|fingerprint| {
            settings_match(&settings, fingerprint.settings)
                && effective_connection_window == fingerprint.connection_window
                && control_order == fingerprint.control_order
        })
        .map(exact_match);

    let family_matches = if exact.is_some() {
        Vec::new()
    } else {
        FAMILY_RULES
            .iter()
            .filter(|rule| {
                family_rule_matches(&settings, effective_connection_window, &control_order, rule)
            })
            .map(family_match)
            .collect()
    };

    H2ServerPreface {
        classifier: H2_PREFACE_CLASSIFIER_VERSION.into(),
        peer_initial_settings_received,
        settings,
        first_connection_window_update,
        effective_connection_window,
        peer_acknowledged_local_initial_settings,
        first_connection_window_update_before_settings_ack,
        control_order,
        exact_match: exact,
        family_matches,
    }
}

#[must_use]
pub fn provider_signals(preface: &H2ServerPreface) -> Vec<ProviderSignal> {
    let Some(exact) = preface.exact_match.as_ref() else {
        return Vec::new();
    };
    let Some(provider) = exact.provider_family.as_ref() else {
        return Vec::new();
    };

    vec![ProviderSignal {
        provider: provider.clone(),
        channel: ProviderEvidenceChannel::H2Transport,
        classifier: H2_PREFACE_CLASSIFIER_VERSION.into(),
        evidence: vec![
            format!("h2-preface:{}", exact.name),
            format!("settings:{}", settings_signature(&preface.settings)),
            format!("connection-window:{}", preface.effective_connection_window),
            format!(
                "control-order:{}",
                control_order_signature(&preface.control_order)
            ),
        ],
    }]
}

fn derive_control_order(
    settings_received: bool,
    first_window_update: Option<u32>,
    window_before_ack: Option<bool>,
    ack_received: bool,
) -> Vec<H2ControlFrame> {
    if !settings_received {
        return Vec::new();
    }

    let mut order = vec![H2ControlFrame::Settings];
    match (first_window_update, window_before_ack) {
        (Some(_), Some(true)) => {
            order.push(H2ControlFrame::WindowUpdate);
            if ack_received {
                order.push(H2ControlFrame::SettingsAck);
            }
        }
        (Some(_), Some(false)) => {
            order.push(H2ControlFrame::SettingsAck);
            order.push(H2ControlFrame::WindowUpdate);
        }
        (Some(_), None) => order.push(H2ControlFrame::WindowUpdate),
        (None, _) if ack_received => order.push(H2ControlFrame::SettingsAck),
        (None, _) => {}
    }
    order
}

fn settings_match(observed: &[H2Setting], expected: &[(u16, u32)]) -> bool {
    observed.len() == expected.len()
        && observed
            .iter()
            .zip(expected)
            .all(|(observed, expected)| (observed.id, observed.value) == *expected)
}

fn family_rule_matches(
    settings: &[H2Setting],
    connection_window: u64,
    control_order: &[H2ControlFrame],
    rule: &FamilyRule,
) -> bool {
    if connection_window != rule.connection_window || control_order != rule.control_order {
        return false;
    }
    if settings
        .iter()
        .map(|setting| setting.id)
        .ne(rule.settings_order.iter().copied())
    {
        return false;
    }
    rule.settings_values.iter().all(|(id, expected)| {
        settings
            .iter()
            .find(|setting| setting.id == *id)
            .is_some_and(|setting| setting.value == *expected)
    })
}

fn exact_match(fingerprint: &ExactFingerprint) -> H2FingerprintMatch {
    H2FingerprintMatch {
        name: fingerprint.name.into(),
        kind: H2FingerprintMatchKind::Exact,
        provider_family: fingerprint.provider_family.map(str::to_owned),
        implementation_family: fingerprint.implementation_family.map(str::to_owned),
    }
}

fn family_match(rule: &FamilyRule) -> H2FingerprintMatch {
    H2FingerprintMatch {
        name: rule.name.into(),
        kind: H2FingerprintMatchKind::FamilyRule,
        provider_family: None,
        implementation_family: Some(rule.implementation_family.into()),
    }
}

fn settings_signature(settings: &[H2Setting]) -> String {
    settings
        .iter()
        .map(|setting| format!("{}={}", setting.id, setting.value))
        .collect::<Vec<_>>()
        .join(";")
}

fn control_order_signature(order: &[H2ControlFrame]) -> String {
    order
        .iter()
        .map(|frame| match frame {
            H2ControlFrame::Settings => "SETTINGS",
            H2ControlFrame::WindowUpdate => "WINDOW_UPDATE",
            H2ControlFrame::SettingsAck => "SETTINGS_ACK",
        })
        .collect::<Vec<_>>()
        .join(">")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(values: &[(u16, u32)]) -> Vec<H2Setting> {
        values
            .iter()
            .map(|(id, value)| H2Setting {
                id: *id,
                value: *value,
            })
            .collect()
    }

    #[test]
    fn cloudflare_exact_preface_originates_provider_signal() {
        let preface = classify_h2_preface(
            true,
            settings(&[(3, 100), (4, 65_536), (5, 16_777_215)]),
            Some(2_147_418_112),
            Some(true),
            true,
        );
        assert_eq!(preface.effective_connection_window, 2_147_483_647);
        assert_eq!(
            preface.exact_match.as_ref().unwrap().name,
            "cloudflare-current-corpus"
        );
        assert_eq!(provider_signals(&preface)[0].provider, "cloudflare");
    }

    #[test]
    fn nginx_classic_exact_match_is_implementation_only() {
        let preface = classify_h2_preface(
            true,
            settings(&[(3, 128), (4, 65_536), (5, 16_777_215)]),
            Some(2_147_418_112),
            Some(true),
            true,
        );
        assert_eq!(
            preface.exact_match.as_ref().unwrap().name,
            "nginx-classic-default-preface"
        );
        assert!(provider_signals(&preface).is_empty());
    }

    #[test]
    fn f5_order_preserves_ack_before_window_update() {
        let preface = classify_h2_preface(
            true,
            settings(&[(1, 4096), (8, 0), (3, 100), (4, 524_288)]),
            Some(4_128_769),
            Some(false),
            true,
        );
        assert_eq!(preface.control_order, SETTINGS_ACK_WU);
        assert_eq!(
            preface
                .exact_match
                .as_ref()
                .unwrap()
                .provider_family
                .as_deref(),
            Some("f5-volt")
        );
    }

    #[test]
    fn family_rule_does_not_originate_provider() {
        let preface = classify_h2_preface(
            true,
            settings(&[(3, 77), (4, 123_456), (5, 16_777_215)]),
            Some(2_147_418_112),
            Some(true),
            true,
        );
        assert!(preface.exact_match.is_none());
        assert_eq!(
            preface.family_matches[0].name,
            "nginx-h2-classic-preface-shape"
        );
        assert!(provider_signals(&preface).is_empty());
    }

    #[test]
    fn incomplete_control_sequence_does_not_fake_exact_match() {
        let preface = classify_h2_preface(
            true,
            settings(&[(3, 100), (4, 65_536), (5, 16_777_215)]),
            Some(2_147_418_112),
            Some(true),
            false,
        );
        assert_eq!(
            preface.control_order,
            [H2ControlFrame::Settings, H2ControlFrame::WindowUpdate]
        );
        assert!(preface.exact_match.is_none());
        assert!(provider_signals(&preface).is_empty());
    }

    #[test]
    fn no_peer_settings_means_no_invented_control_order() {
        let preface = classify_h2_preface(false, Vec::new(), None, None, false);
        assert!(preface.control_order.is_empty());
        assert!(preface.exact_match.is_none());
    }
}
