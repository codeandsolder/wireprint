use std::sync::LazyLock;

use regex::Regex;

pub const NORMALIZER_VERSION: &str = "template-v1";

static UUID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
        .expect("valid uuid regex")
});
static LONG_HEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[0-9a-f]{16,}\b").expect("valid long-hex regex"));
static NONCE_DOUBLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)nonce="[^"]+""#).expect("valid double-quoted nonce regex"));
static NONCE_SINGLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)nonce='[^']+'").expect("valid single-quoted nonce regex"));
static DATADOME_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(['"](?:cid|cookie)['"]\s*:\s*['"])[^'"]+"#)
        .expect("valid DataDome token regex")
});

/// Produce a conservative grouping representation for response-template comparison.
///
/// The raw captured bytes and raw SHA-256 remain authoritative. This normalizer only removes
/// a small set of high-churn values observed in challenge/interstitial templates: UUIDs, long
/// hex tokens, HTML nonces, and DataDome `cid`/`cookie` object values.
pub fn normalize_response_template(body: &[u8]) -> String {
    let mut value = String::from_utf8_lossy(body).into_owned();
    value = UUID.replace_all(&value, "<uuid>").into_owned();
    value = NONCE_DOUBLE.replace_all(&value, "nonce=\"<nonce>\"").into_owned();
    value = NONCE_SINGLE.replace_all(&value, "nonce='<nonce>'").into_owned();
    value = DATADOME_TOKEN.replace_all(&value, "$1<token>").into_owned();
    LONG_HEX.replace_all(&value, "<hex>").into_owned()
}
