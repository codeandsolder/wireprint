use crate::model::{Header, Outcome, OutcomeKind};
use crate::path::has_anubis_challenge_scripts;
use regex::Regex;
use std::sync::LazyLock;

fn header_values<'a>(headers: &'a [Header], name: &str) -> impl Iterator<Item = &'a str> {
    headers
        .iter()
        .filter(move |header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

// Prefer first-party action markers over generic HTTP status heuristics.
fn explicit_vendor_challenge(headers: &[Header], body: &[u8], lower: &str) -> Option<Outcome> {
    let mut evidence = Vec::new();
    // These response-side action signals are first-party contracts rather
    // than generic vendor-presence or CDN markers. Evaluate them before
    // status-only 401/403/405/429 handling.
    if header_values(headers, "x-amzn-waf-action")
        .any(|value| value.trim().eq_ignore_ascii_case("captcha"))
    {
        return Some(outcome(
            OutcomeKind::Captcha,
            vec!["header:x-amzn-waf-action=captcha".into()],
        ));
    }
    if header_values(headers, "x-amzn-waf-action")
        .any(|value| value.trim().eq_ignore_ascii_case("challenge"))
    {
        return Some(outcome(
            OutcomeKind::Challenge,
            vec!["header:x-amzn-waf-action=challenge".into()],
        ));
    }
    let cloudflare_challenge_header = header_values(headers, "cf-mitigated")
        .any(|value| value.trim().eq_ignore_ascii_case("challenge"));
    // On pages without the CF-Mitigated header, pair the challenge bootstrap
    // object with its reserved challenge-platform path; neither alone is
    // sufficient to reclassify an ordinary Cloudflare-delivered document.
    let cloudflare_challenge_body =
        lower.contains("_cf_chl_opt") && lower.contains("/cdn-cgi/challenge-platform/");
    if cloudflare_challenge_header || cloudflare_challenge_body {
        if cloudflare_challenge_header {
            evidence.push("header:cf-mitigated=challenge".into());
        }
        if cloudflare_challenge_body {
            evidence.push("body:cf-challenge-bootstrap+platform".into());
        }
        return Some(outcome(OutcomeKind::Challenge, evidence));
    }
    if has_anubis_challenge_scripts(body) {
        return Some(outcome(
            OutcomeKind::Challenge,
            vec!["body:anubis-version+challenge-scripts".into()],
        ));
    }

    None
}

/// Match visible template phrases across harmless line wrapping without
/// requiring one exact whitespace layout. Only invoked for rare gate candidates.
fn has_normalized_phrase(body: &str, phrase: &str) -> bool {
    body.contains(phrase)
        || body
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .contains(phrase)
}

// Additional browser verification interstitials from preserved main-frame HTML.
// These are action classifications, not claims about the TLS peer or a vendor.
fn archived_browser_gate(lower: &str) -> Option<Outcome> {
    // Hostinger CDN can issue this script challenge under its reserved path.
    // The ordinary CDN header, a documentation article or the script URL
    // alone must never be treated as a completed response-side challenge.
    if lower.contains("/hcdn-cgi/jschallenge")
        && has_normalized_phrase(lower, "checking your browser before accessing")
    {
        return Some(outcome(
            OutcomeKind::Challenge,
            vec!["body:hcdn-jschallenge+browser-check".into()],
        ));
    }

    // An observed HTTP 405 first-party page also requires browser-side JS
    // verification without a vendor-authenticated X-Amzn-Waf-Action header.
    // Do not attribute it to AWS WAF or claim that a CAPTCHA puzzle occurred.
    if lower.contains("security verification")
        && (has_normalized_phrase(lower, "verify that you are not a robot")
            || has_normalized_phrase(lower, "verify that you're not a robot"))
        && has_normalized_phrase(lower, "this requires javascript")
        && has_normalized_phrase(lower, "enable javascript and then reload the page")
    {
        return Some(outcome(
            OutcomeKind::Challenge,
            vec!["body:security-verification+javascript-robot-check".into()],
        ));
    }

    // Google reCAPTCHA has a dedicated browser-verification document. Two
    // real NCBI root-frame responses contain its title, reserved document
    // base and RecaptchaChallengePageUi bootstrap. An embedded reCAPTCHA
    // widget on an ordinary site has none of this complete shell.
    // Requiring the three independent markers prevents false classification
    // of normal forms and articles. The regexes are evaluated only after
    // the rare product bootstrap marker is observed.
    if lower.contains("recaptchachallengepageui")
        && Regex::new(
            r"(?s)<title(?:\s[^>]*)?>\s*checking\s+your\s+browser\s*-\s*recaptcha\s*</title>",
        )
        .is_ok_and(|title| title.is_match(lower))
        && Regex::new(
            r#"<base\s+[^>]*\bhref\s*=\s*["']https://www\.google\.com/recaptcha/challengepage/["']"#,
        )
        .is_ok_and(|base| base.is_match(lower))
    {
        return Some(outcome(
            OutcomeKind::Challenge,
            vec!["body:recaptcha-challengepage+browser-check".into()],
        ));
    }

    None
}

// JS object literals use either quote style, often unquoted keys. Only
// parse a small bounded inline descriptor, never minified vendor scripts.
static DD_DESCRIPTOR: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?s)\b(?:var|let|const)\s+dd\s*=\s*\{([^}]{0,4096})\}").ok());
static DD_HOST: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"(?m)(?:^|,)\s*['"]?host['"]?\s*:\s*['"](?:[a-z0-9-]+\.)*captcha-delivery\.com['"]"#,
    )
    .ok()
});
static DD_RUNTIME: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"(?m)(?:^|,)\s*['"]?rt['"]?\s*:\s*['"]([a-z])['"]"#).ok());

// DataDome challenge-service documents carry a dedicated body role. Their
// observed HTTP 200 or /captcha/ route must not be interpreted as content or
// an interactive CAPTCHA without evidence from the response HTML.
static DD_SERVICE_BODY_CLASS: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"(?is)<body\b[^>]{0,2048}\sclass\s*=\s*['"]([^'"]{0,512})['"]"#).ok()
});

fn datadome_service_document_action(lower: &str) -> Option<Outcome> {
    if !lower.contains("dd-response-page--") {
        return None;
    }
    let classes = DD_SERVICE_BODY_CLASS
        .as_ref()?
        .captures(lower)?
        .get(1)?
        .as_str();
    let mut roles = classes.split_whitespace().filter_map(|class| match class {
        "dd-response-page--device-check" => Some(OutcomeKind::Challenge),
        "dd-response-page--hard-block" => Some(OutcomeKind::ExplicitBlock),
        "dd-response-page--captcha" => Some(OutcomeKind::Captcha),
        _ => None,
    });
    let kind = roles.next()?;
    if roles.any(|other| other != kind) {
        return None;
    }
    let evidence = match kind {
        OutcomeKind::Challenge => "body:datadome-service-device-check",
        OutcomeKind::ExplicitBlock => "body:datadome-service-hard-block",
        OutcomeKind::Captcha => "body:datadome-service-captcha",
        _ => return None,
    };
    Some(outcome(kind, vec![evidence.into()]))
}

// DataDome's 'protected' response header identifies protection participation,
// not an applied CAPTCHA action. Its original first-party response documents
// carry an inline dd runtime descriptor: 'i' means noninteractive device check
// and 'c' means CAPTCHA. Require the script/object, challenge host and visible
// browser-check shell together; an ordinary page may include DataDome headers
// or SDK references without challenging the client.
fn datadome_document_action(lower: &str) -> Option<Outcome> {
    if !lower.contains("captcha-delivery.com")
        || !lower.contains("<script")
        || !has_normalized_phrase(lower, "please enable js and disable any ad blocker")
    {
        return None;
    }

    let fields = DD_DESCRIPTOR.as_ref()?.captures(lower)?.get(1)?.as_str();
    if !DD_HOST.as_ref()?.is_match(fields) {
        return None;
    }
    match DD_RUNTIME.as_ref()?.captures(fields)?.get(1)?.as_str() {
        "i" => Some(outcome(
            OutcomeKind::Challenge,
            vec!["body:datadome-device-check".into()],
        )),
        "c" => Some(outcome(
            OutcomeKind::Captcha,
            vec!["body:datadome-captcha".into()],
        )),
        _ => None,
    }
}

// Source-backed, first-party document-gate shapes from captured HTML pages.
// Ordinary CAPTCHA integrations, vendor SDK scripts and security articles do
// not by themselves indicate a gate. These pairs are deliberately contextual.
fn corpus_document_gate(status: u16, lower: &str) -> Option<Outcome> {
    // Tencent Cloud EdgeOne CAPTCHA page: branded interstitial and dedicated
    // Tencent widget together, not the widget alone on an application form.
    if lower.contains("teocaptchawidgetv1-global.js")
        && has_normalized_phrase(lower, "protected by tencent cloud edgeone")
        && lower.contains("security verification")
    {
        return Some(outcome(
            OutcomeKind::Captcha,
            vec!["body:edgeone-security-verification+captcha-widget".into()],
        ));
    }

    // Several saved first-party documents return HTTP 200 with a full-page
    // "Client Challenge" requiring JavaScript before any site content.
    // An application requiring JavaScript is not enough: the three-part
    // challenge shell is required.
    if lower.contains("client challenge")
        && has_normalized_phrase(lower, "javascript is disabled in your browser")
        && has_normalized_phrase(lower, "please enable javascript to proceed")
    {
        return Some(outcome(
            OutcomeKind::Challenge,
            vec!["body:client-challenge+javascript-gate".into()],
        ));
    }

    // Imperva-style browser check appears with HTTP 200 in the saved corpus.
    // The title alone is not enough: the page must state that the browser is
    // being checked for bot-like behavior.
    if lower.contains("pardon our interruption")
        && has_normalized_phrase(
            lower,
            "something about your browser made us think you were a bot",
        )
    {
        return Some(outcome(
            OutcomeKind::Challenge,
            vec!["body:pardon-interruption+bot-browser-check".into()],
        ));
    }

    // HUMAN/PerimeterX CAPTCHA template, versus regular JS integrations.
    if (status == 403 || status == 429)
        && lower.contains("px-captcha")
        && (lower.contains("press and hold") || lower.contains("press & hold"))
    {
        return Some(outcome(
            OutcomeKind::Captcha,
            vec!["body:px-captcha+press-hold".into()],
        ));
    }

    // A first-party denied document can itself be a Turnstile verification
    // gate. The script alone, or a generic 200 application form, is not.
    if status == 403
        && has_normalized_phrase(lower, "verify you are human")
        && lower.contains("challenges.cloudflare.com/turnstile/v0/api.js")
    {
        return Some(outcome(
            OutcomeKind::Challenge,
            vec!["body:turnstile+verify-human-gate".into()],
        ));
    }

    // A provider-agnostic browser-verification interstitial encountered on
    // a first-party document route; requires all three independent phrases.
    if has_normalized_phrase(lower, "security verification in progress")
        && has_normalized_phrase(
            lower,
            "verify your browser to protect against automated access",
        )
        && has_normalized_phrase(lower, "verifying connection")
    {
        return Some(outcome(
            OutcomeKind::Challenge,
            vec!["body:security-verification+browser-connection".into()],
        ));
    }

    None
}

#[must_use = "the response classification is returned rather than stored"]
pub fn classify_response(status: u16, headers: &[Header], body: &[u8]) -> Outcome {
    let body = String::from_utf8_lossy(body);
    let lower = body.to_ascii_lowercase();
    let mut evidence = Vec::new();

    if let Some(action) = explicit_vendor_challenge(headers, body.as_bytes(), &lower) {
        return action;
    }
    if let Some(action) = archived_browser_gate(&lower) {
        return action;
    }
    if let Some(action) = corpus_document_gate(status, &lower) {
        return action;
    }

    if let Some(action) = datadome_service_document_action(&lower) {
        return action;
    }
    if let Some(action) = datadome_document_action(&lower) {
        return action;
    }

    let reddit_js_gate = lower.contains("js_challenge") && lower.contains("jsc_token");
    let aws_waf_challenge = header_values(headers, "x-amzn-waf-action")
        .any(|value| value.eq_ignore_ascii_case("challenge"))
        || (lower.contains("awswaf") && lower.contains("challenge"));
    if reddit_js_gate || aws_waf_challenge {
        if reddit_js_gate {
            evidence.push("body:reddit-js-challenge-form".into());
        }
        if aws_waf_challenge {
            evidence.push("marker:aws-waf-challenge".into());
        }
        return outcome(OutcomeKind::Challenge, evidence);
    }

    if status == 429 {
        evidence.push("status:429".into());
        if lower.contains("captcha") || lower.contains("verify you are human") {
            evidence.push("body:captcha-marker".into());
            return outcome(OutcomeKind::Captcha, evidence);
        }
        return outcome(OutcomeKind::RateLimited, evidence);
    }

    if status == 401 || status == 403 {
        evidence.push(format!("status:{status}"));
        if lower.contains("sucuri website firewall") && lower.contains("access denied") {
            evidence.push("body:sucuri-website-firewall".into());
        }
        for (needle, marker) in [
            (
                "blocked due to a network policy",
                "body:network-policy-block",
            ),
            ("access denied", "body:access-denied"),
            ("403 forbidden", "body:forbidden"),
            ("whoa there, pardner", "body:reddit-pardner-block"),
        ] {
            if lower.contains(needle) {
                evidence.push(marker.into());
            }
        }
        return outcome(OutcomeKind::ExplicitBlock, evidence);
    }

    if (300..400).contains(&status) {
        evidence.push(format!("status:{status}"));
        return outcome(OutcomeKind::Redirect, evidence);
    }

    if status >= 500 {
        evidence.push(format!("status:{status}"));
        return outcome(OutcomeKind::ApplicationError, evidence);
    }

    if (200..300).contains(&status) {
        evidence.push(format!("status:{status}"));
        return outcome(OutcomeKind::ContentLike, evidence);
    }

    evidence.push(format!("status:{status}"));
    outcome(OutcomeKind::Unknown, evidence)
}

fn outcome(kind: OutcomeKind, evidence: Vec<String>) -> Outcome {
    Outcome {
        kind,
        classifier: "builtin-v7".into(),
        evidence,
    }
}
