use std::collections::BTreeSet;
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::{ProviderEvidenceChannel, ProviderSignal};

pub const H3_QUIC_CLASSIFIER_VERSION: &str = "builtin-h3-quic-v1";
const QUIC_MIN_ACK_DELAY_PARAMETER_ID: u64 = 0xff04_de1b;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct H3Setting {
    pub id: u64,
    pub value: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuicTransportParameterWire {
    pub id: u64,
    pub length: u64,
    pub raw_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct QuicStableTransportParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_idle_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_udp_payload_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_max_data: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_max_stream_data_bidi_local: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_max_stream_data_bidi_remote: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_max_stream_data_uni: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_max_streams_bidi: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_max_streams_uni: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ack_delay_exponent: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_ack_delay: Option<u64>,
    pub disable_active_migration: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_connection_id_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_datagram_frame_size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuicVersionInformation {
    pub chosen_version: u32,
    pub available_versions: Vec<u32>,
    pub reserved_version_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuicTransportStructure {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_source_connection_id_length: Option<u64>,
    pub stateless_reset_token_present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_information: Option<QuicVersionInformation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_ack_delay: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum H3FingerprintMatchKind {
    Exact,
    MiddleTier,
    FamilyRule,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct H3FingerprintMatch {
    pub name: String,
    pub kind: H3FingerprintMatchKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_family: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implementation_family: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct H3ServerFingerprint {
    pub classifier: String,
    pub quic_version: u32,
    pub alpn: String,
    pub settings: Vec<H3Setting>,
    pub transport_parameters: QuicStableTransportParameters,
    pub transport_parameter_wire: Vec<QuicTransportParameterWire>,
    pub transport_parameter_order: Vec<String>,
    pub transport_structure: QuicTransportStructure,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exact_match: Option<H3FingerprintMatch>,
    #[serde(default)]
    pub middle_tier_matches: Vec<H3FingerprintMatch>,
    #[serde(default)]
    pub family_matches: Vec<H3FingerprintMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NormalizedSetting {
    Grease,
    Setting(u64, u64),
}

#[derive(Debug, Deserialize)]
struct Catalog {
    #[serde(default)]
    fingerprints: Vec<CatalogFingerprint>,
    #[serde(default)]
    family_rules: Vec<CatalogFamilyRule>,
}

#[derive(Debug, Deserialize)]
struct CatalogFingerprint {
    name: String,
    #[serde(default)]
    implementation_family: Option<String>,
    quic_version: u32,
    alpn: String,
    settings: Vec<Vec<Value>>,
    #[serde(default)]
    transport_parameters: Value,
    #[serde(default)]
    transport_structure: Value,
}

#[derive(Debug, Deserialize)]
struct CatalogFamilyRule {
    name: String,
    #[serde(default)]
    implementation_family: Option<String>,
    #[serde(default)]
    derived_rule: Option<String>,
    #[serde(default)]
    settings: Vec<Vec<Value>>,
    #[serde(default)]
    transport_constraints: Value,
}

fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        serde_json::from_str(include_str!("../data/h3-quic-catalog-v1.json"))
            .expect("embedded H3/QUIC catalog must parse")
    })
}

pub fn parse_quic_transport_parameter_wire(data: &[u8]) -> Result<Vec<QuicTransportParameterWire>> {
    let mut offset = 0usize;
    let mut parameters = Vec::new();
    while offset < data.len() {
        let id = pull_varint(data, &mut offset).context("transport parameter id")?;
        let length = pull_varint(data, &mut offset).context("transport parameter length")?;
        let length_usize =
            usize::try_from(length).context("transport parameter length overflow")?;
        let end = offset
            .checked_add(length_usize)
            .context("transport parameter length overflow")?;
        if end > data.len() {
            bail!("transport parameter {id} body is truncated");
        }
        parameters.push(QuicTransportParameterWire {
            id,
            length,
            raw_hex: hex(&data[offset..end]),
        });
        offset = end;
    }
    Ok(parameters)
}

pub fn classify_h3_quic(
    quic_version: u32,
    alpn: impl Into<String>,
    settings: Vec<H3Setting>,
    raw_transport_parameters: &[u8],
) -> Result<H3ServerFingerprint> {
    let alpn = alpn.into();
    let wire = parse_quic_transport_parameter_wire(raw_transport_parameters)?;
    let stable = stable_transport_parameters(&wire)?;
    let structure = transport_structure(&wire)?;
    let normalized_settings = normalize_settings(&settings);

    let exact_match = catalog()
        .fingerprints
        .iter()
        .find(|entry| {
            entry.quic_version == quic_version
                && entry.alpn == alpn
                && catalog_settings(&entry.settings)
                    .is_some_and(|value| value == normalized_settings)
                && catalog_stable_parameters(&entry.transport_parameters)
                    .is_some_and(|expected| expected == stable)
        })
        .map(|entry| H3FingerprintMatch {
            name: entry.name.clone(),
            kind: H3FingerprintMatchKind::Exact,
            provider_family: provider_for_exact(&entry.name).map(str::to_owned),
            implementation_family: entry.implementation_family.clone(),
        });

    let middle_tier_matches = catalog()
        .fingerprints
        .iter()
        .filter(|entry| {
            entry.quic_version == quic_version
                && entry.alpn == alpn
                && catalog_settings(&entry.settings)
                    .is_some_and(|value| value == normalized_settings)
                && catalog_transport_structure(&entry.transport_structure)
                    .is_some_and(|expected| expected == structure)
        })
        .map(|entry| H3FingerprintMatch {
            name: entry.name.clone(),
            kind: H3FingerprintMatchKind::MiddleTier,
            provider_family: None,
            implementation_family: entry.implementation_family.clone(),
        })
        .collect();

    let family_matches = catalog()
        .family_rules
        .iter()
        .filter(|rule| family_rule_matches(rule, &normalized_settings, &stable))
        .map(|rule| H3FingerprintMatch {
            name: rule.name.clone(),
            kind: H3FingerprintMatchKind::FamilyRule,
            provider_family: None,
            implementation_family: rule.implementation_family.clone(),
        })
        .collect();

    Ok(H3ServerFingerprint {
        classifier: H3_QUIC_CLASSIFIER_VERSION.into(),
        quic_version,
        alpn,
        settings,
        transport_parameters: stable,
        transport_parameter_order: wire
            .iter()
            .map(|parameter| {
                if is_quic_transport_parameter_grease(parameter.id) {
                    "GREASE".into()
                } else {
                    parameter.id.to_string()
                }
            })
            .collect(),
        transport_parameter_wire: wire,
        transport_structure: structure,
        exact_match,
        middle_tier_matches,
        family_matches,
    })
}

pub fn provider_signals(fingerprint: &H3ServerFingerprint) -> Vec<ProviderSignal> {
    let Some(exact) = fingerprint.exact_match.as_ref() else {
        return Vec::new();
    };
    let Some(provider) = exact.provider_family.as_ref() else {
        return Vec::new();
    };
    vec![ProviderSignal {
        provider: provider.clone(),
        channel: ProviderEvidenceChannel::H3Transport,
        classifier: H3_QUIC_CLASSIFIER_VERSION.into(),
        evidence: vec![
            format!("h3-quic:{}", exact.name),
            format!("settings:{}", settings_signature(&fingerprint.settings)),
            format!(
                "tp-order:{}",
                fingerprint.transport_parameter_order.join(",")
            ),
        ],
    }]
}

pub fn is_h3_grease_setting(id: u64) -> bool {
    id >= 0x21 && (id - 0x21).is_multiple_of(0x1f)
}

pub fn is_quic_transport_parameter_grease(id: u64) -> bool {
    id >= 27 && (id - 27).is_multiple_of(31)
}

fn normalize_settings(settings: &[H3Setting]) -> Vec<NormalizedSetting> {
    settings
        .iter()
        .map(|setting| {
            if is_h3_grease_setting(setting.id) {
                NormalizedSetting::Grease
            } else {
                NormalizedSetting::Setting(setting.id, setting.value)
            }
        })
        .collect()
}

fn catalog_settings(settings: &[Vec<Value>]) -> Option<Vec<NormalizedSetting>> {
    settings
        .iter()
        .map(|pair| {
            if pair.len() != 2 {
                return None;
            }
            if pair[0].as_str() == Some("GREASE") {
                return Some(NormalizedSetting::Grease);
            }
            Some(NormalizedSetting::Setting(
                pair[0].as_u64()?,
                pair[1].as_u64()?,
            ))
        })
        .collect()
}

fn stable_transport_parameters(
    wire: &[QuicTransportParameterWire],
) -> Result<QuicStableTransportParameters> {
    let mut out = QuicStableTransportParameters::default();
    for parameter in wire {
        let value = match parameter.id {
            1 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 14 | 32 => Some(
                decode_varint_hex(&parameter.raw_hex)
                    .with_context(|| format!("decode QUIC transport parameter {}", parameter.id))?,
            ),
            _ => None,
        };
        match parameter.id {
            1 => out.max_idle_timeout = value,
            3 => out.max_udp_payload_size = value,
            4 => out.initial_max_data = value,
            5 => out.initial_max_stream_data_bidi_local = value,
            6 => out.initial_max_stream_data_bidi_remote = value,
            7 => out.initial_max_stream_data_uni = value,
            8 => out.initial_max_streams_bidi = value,
            9 => out.initial_max_streams_uni = value,
            10 => out.ack_delay_exponent = value,
            11 => out.max_ack_delay = value,
            12 => {
                if parameter.length != 0 {
                    bail!("disable_active_migration must be empty");
                }
                out.disable_active_migration = true;
            }
            14 => out.active_connection_id_limit = value,
            32 => out.max_datagram_frame_size = value,
            _ => {}
        }
    }
    Ok(out)
}

fn transport_structure(wire: &[QuicTransportParameterWire]) -> Result<QuicTransportStructure> {
    let mut initial_source_connection_id_length = None;
    let mut stateless_reset_token_present = false;
    let mut version_information = None;
    let mut min_ack_delay = None;
    for parameter in wire {
        match parameter.id {
            2 => stateless_reset_token_present = true,
            15 => initial_source_connection_id_length = Some(parameter.length),
            17 => version_information = parse_version_information(&parameter.raw_hex)?,
            QUIC_MIN_ACK_DELAY_PARAMETER_ID => {
                min_ack_delay = Some(decode_varint_hex(&parameter.raw_hex)?);
            }
            _ => {}
        }
    }
    Ok(QuicTransportStructure {
        initial_source_connection_id_length,
        stateless_reset_token_present,
        version_information,
        min_ack_delay,
    })
}

fn parse_version_information(raw_hex: &str) -> Result<Option<QuicVersionInformation>> {
    let bytes = decode_hex(raw_hex)?;
    if bytes.len() < 4 || bytes.len() % 4 != 0 {
        return Ok(None);
    }
    let versions = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|chunk| u32::from_be_bytes(*chunk))
        .collect::<Vec<_>>();
    let chosen_version = versions[0];
    let mut available_versions = BTreeSet::new();
    let mut reserved_version_count = 0usize;
    for version in versions.into_iter().skip(1) {
        if is_reserved_quic_version(version) {
            reserved_version_count += 1;
        } else {
            available_versions.insert(version);
        }
    }
    Ok(Some(QuicVersionInformation {
        chosen_version,
        available_versions: available_versions.into_iter().collect(),
        reserved_version_count,
    }))
}

fn is_reserved_quic_version(version: u32) -> bool {
    version & 0x0f0f_0f0f == 0x0a0a_0a0a
}

fn decode_varint_hex(raw_hex: &str) -> Result<u64> {
    let bytes = decode_hex(raw_hex)?;
    let mut offset = 0usize;
    let value = pull_varint(&bytes, &mut offset)?;
    if offset != bytes.len() {
        bail!("trailing bytes after QUIC varint");
    }
    Ok(value)
}

fn pull_varint(data: &[u8], offset: &mut usize) -> Result<u64> {
    if *offset >= data.len() {
        bail!("truncated QUIC varint");
    }
    let length = 1usize << (data[*offset] >> 6);
    let end = offset
        .checked_add(length)
        .context("QUIC varint length overflow")?;
    if end > data.len() {
        bail!("truncated QUIC varint body");
    }
    let mut value = u64::from(data[*offset] & 0x3f);
    for byte in &data[*offset + 1..end] {
        value = (value << 8) | u64::from(*byte);
    }
    *offset = end;
    Ok(value)
}

fn family_rule_matches(
    rule: &CatalogFamilyRule,
    settings: &[NormalizedSetting],
    stable: &QuicStableTransportParameters,
) -> bool {
    if rule.derived_rule.as_deref() == Some("nginx-h3-source-relationship") {
        return nginx_h3_structural_match(settings, stable);
    }
    if catalog_settings(&rule.settings).is_none_or(|expected| expected != settings) {
        return false;
    }
    transport_constraints_match(&rule.transport_constraints, stable)
}

fn nginx_h3_structural_match(
    settings: &[NormalizedSetting],
    stable: &QuicStableTransportParameters,
) -> bool {
    let [
        NormalizedSetting::Setting(1, 4096),
        NormalizedSetting::Setting(7, blocked),
    ] = settings
    else {
        return false;
    };
    if *blocked == 0 {
        return false;
    }
    let Some(stream_buf) = stable.initial_max_stream_data_bidi_local else {
        return false;
    };
    stream_buf > 0
        && stable.initial_max_stream_data_bidi_remote == Some(stream_buf)
        && stable.initial_max_stream_data_uni == Some(stream_buf)
        && stable.initial_max_streams_bidi == Some(*blocked)
        && stable.initial_max_streams_uni == Some(3)
        && stable.initial_max_data == Some((*blocked + 3).saturating_mul(stream_buf))
}

fn transport_constraints_match(raw: &Value, stable: &QuicStableTransportParameters) -> bool {
    let Some(object) = raw.as_object() else {
        return raw.is_null();
    };
    object.iter().all(|(key, expected)| match key.as_str() {
        "max_idle_timeout" => numeric_matches(stable.max_idle_timeout, expected),
        "max_udp_payload_size" => numeric_matches(stable.max_udp_payload_size, expected),
        "initial_max_data" => numeric_matches(stable.initial_max_data, expected),
        "initial_max_stream_data_bidi_local" => {
            numeric_matches(stable.initial_max_stream_data_bidi_local, expected)
        }
        "initial_max_stream_data_bidi_remote" => {
            numeric_matches(stable.initial_max_stream_data_bidi_remote, expected)
        }
        "initial_max_stream_data_uni" => {
            numeric_matches(stable.initial_max_stream_data_uni, expected)
        }
        "initial_max_streams_bidi" => numeric_matches(stable.initial_max_streams_bidi, expected),
        "initial_max_streams_uni" => numeric_matches(stable.initial_max_streams_uni, expected),
        "ack_delay_exponent" => numeric_matches(stable.ack_delay_exponent, expected),
        "max_ack_delay" => numeric_matches(stable.max_ack_delay, expected),
        "active_connection_id_limit" => {
            numeric_matches(stable.active_connection_id_limit, expected)
        }
        "max_datagram_frame_size" => numeric_matches(stable.max_datagram_frame_size, expected),
        "disable_active_migration" => expected.as_bool() == Some(stable.disable_active_migration),
        _ => false,
    })
}

fn catalog_stable_parameters(raw: &Value) -> Option<QuicStableTransportParameters> {
    let object = raw.as_object()?;
    let mut out = QuicStableTransportParameters {
        disable_active_migration: object
            .get("disable_active_migration")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        ..Default::default()
    };
    macro_rules! assign {
        ($field:ident, $key:literal) => {
            out.$field = object.get($key).and_then(Value::as_u64);
        };
    }
    assign!(max_idle_timeout, "max_idle_timeout");
    assign!(max_udp_payload_size, "max_udp_payload_size");
    assign!(initial_max_data, "initial_max_data");
    assign!(
        initial_max_stream_data_bidi_local,
        "initial_max_stream_data_bidi_local"
    );
    assign!(
        initial_max_stream_data_bidi_remote,
        "initial_max_stream_data_bidi_remote"
    );
    assign!(initial_max_stream_data_uni, "initial_max_stream_data_uni");
    assign!(initial_max_streams_bidi, "initial_max_streams_bidi");
    assign!(initial_max_streams_uni, "initial_max_streams_uni");
    assign!(ack_delay_exponent, "ack_delay_exponent");
    assign!(max_ack_delay, "max_ack_delay");
    assign!(active_connection_id_limit, "active_connection_id_limit");
    assign!(max_datagram_frame_size, "max_datagram_frame_size");
    Some(out)
}

fn catalog_transport_structure(raw: &Value) -> Option<QuicTransportStructure> {
    let object = raw.as_object()?;
    let version_information = match object.get("version_information") {
        Some(Value::Object(value)) => Some(QuicVersionInformation {
            chosen_version: u32::try_from(value.get("chosen_version")?.as_u64()?).ok()?,
            available_versions: value
                .get("available_versions")?
                .as_array()?
                .iter()
                .map(|item| u32::try_from(item.as_u64()?).ok())
                .collect::<Option<Vec<_>>>()?,
            reserved_version_count: usize::try_from(value.get("reserved_version_count")?.as_u64()?)
                .ok()?,
        }),
        Some(Value::Null) | None => None,
        _ => return None,
    };
    Some(QuicTransportStructure {
        initial_source_connection_id_length: object
            .get("initial_source_connection_id_length")
            .and_then(Value::as_u64),
        stateless_reset_token_present: object
            .get("stateless_reset_token_present")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        version_information,
        min_ack_delay: object.get("min_ack_delay").and_then(Value::as_u64),
    })
}

fn numeric_matches(actual: Option<u64>, expected: &Value) -> bool {
    actual == expected.as_u64()
}

fn provider_for_exact(name: &str) -> Option<&'static str> {
    match name {
        "google-gfe-h3-current" => Some("google-gfe"),
        "fastly-h3-current" => Some("fastly"),
        "aws-cloudfront-h3-current" => Some("aws-cloudfront"),
        "akamai-h3-current" => Some("akamai"),
        "cloudflare-h3-marketing-config" | "cloudflare-h3-wayfair-config" => Some("cloudflare"),
        // This exact transport signature passed the historical independent-label promotion gate.
        "openresty-h3-current" => Some("openresty-edge"),
        _ => None,
    }
}

fn settings_signature(settings: &[H3Setting]) -> String {
    settings
        .iter()
        .map(|setting| {
            if is_h3_grease_setting(setting.id) {
                "GREASE".into()
            } else {
                format!("{}={}", setting.id, setting.value)
            }
        })
        .collect::<Vec<_>>()
        .join(";")
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        bail!("odd-length hex string");
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("ASCII hex pair");
            u8::from_str_radix(text, 16).with_context(|| format!("invalid hex byte {text}"))
        })
        .collect()
}
