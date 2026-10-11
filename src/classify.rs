use crate::model::{Header, Outcome, OutcomeKind};

fn header_values<'a>(headers: &'a [Header], name: &str) -> impl Iterator<Item = &'a str> {
    headers
        .iter()
        .filter(move |header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

pub fn classify_response(status: u16, headers: &[Header], body: &[u8]) -> Outcome {
    let body = String::from_utf8_lossy(body);
    let lower = body.to_ascii_lowercase();
    let mut evidence = Vec::new();

    let datadome_header =
        header_values(headers, "x-datadome").any(|value| value.eq_ignore_ascii_case("protected"));
    let datadome_body = lower.contains("captcha-delivery.com")
        || lower.contains("please enable js and disable any ad blocker");
    if datadome_header || datadome_body {
        if datadome_header {
            evidence.push("header:x-datadome=protected".into());
        }
        if lower.contains("captcha-delivery.com") {
            evidence.push("body:captcha-delivery.com".into());
        }
        if lower.contains("please enable js and disable any ad blocker") {
            evidence.push("body:enable-js-disable-adblock".into());
        }
        return outcome(OutcomeKind::Captcha, evidence);
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
        for (needle, marker) in [
            ("blocked due to a network policy", "body:network-policy-block"),
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
        classifier: "builtin-v1".into(),
        evidence,
    }
}
