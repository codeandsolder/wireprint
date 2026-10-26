use std::sync::LazyLock;

use regex::Regex;

pub const NORMALIZER_VERSION: &str = "template-v1";

static UUID: LazyLock<Result<Regex, regex::Error>> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
});
static LONG_HEX: LazyLock<Result<Regex, regex::Error>> =
    LazyLock::new(|| Regex::new(r"(?i)\b[0-9a-f]{16,}\b"));
static NONCE_DOUBLE: LazyLock<Result<Regex, regex::Error>> =
    LazyLock::new(|| Regex::new(r#"(?i)nonce="[^"]+""#));
static NONCE_SINGLE: LazyLock<Result<Regex, regex::Error>> =
    LazyLock::new(|| Regex::new(r"(?i)nonce='[^']+'"));
static DATADOME_TOKEN: LazyLock<Result<Regex, regex::Error>> =
    LazyLock::new(|| Regex::new(r#"(?i)(['"](?:cid|cookie)['"]\s*:\s*['"])[^'"]+"#));

fn replace_if_compiled(
    value: String,
    regex: &Result<Regex, regex::Error>,
    replacement: &str,
) -> String {
    match regex {
        Ok(regex) => regex.replace_all(&value, replacement).into_owned(),
        Err(_) => value,
    }
}

/// Produce a conservative grouping representation for response-template comparison.
///
/// The raw captured bytes and raw SHA-256 remain authoritative. This normalizer only removes
/// a small set of high-churn values observed in challenge/interstitial templates: UUIDs, long
/// hex tokens, HTML nonces, and `DataDome` `cid`/`cookie` object values.
#[must_use]
pub fn normalize_response_template(body: &[u8]) -> String {
    let mut value = String::from_utf8_lossy(body).into_owned();
    value = replace_if_compiled(value, &UUID, "<uuid>");
    value = replace_if_compiled(value, &NONCE_DOUBLE, "nonce=\"<nonce>\"");
    value = replace_if_compiled(value, &NONCE_SINGLE, "nonce='<nonce>'");
    value = replace_if_compiled(value, &DATADOME_TOKEN, "$1<token>");
    replace_if_compiled(value, &LONG_HEX, "<hex>")
}
