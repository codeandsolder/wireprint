use pretty_assertions::assert_eq;
use wireprint::{Header, OutcomeKind, classify_response};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("tests/fixtures/{name}")).unwrap()
}

#[test]
fn reddit_200_is_challenge_not_content() {
    let out = classify_response(200, &[], &fixture("reddit-js-challenge.html"));
    assert_eq!(out.kind, OutcomeKind::Challenge);
    assert!(out.evidence.iter().any(|value| value.contains("reddit-js-challenge")));
}

#[test]
fn reddit_network_policy_is_explicit_block() {
    let out = classify_response(403, &[], &fixture("reddit-hard-block.html"));
    assert_eq!(out.kind, OutcomeKind::ExplicitBlock);
    assert!(out.evidence.iter().any(|value| value.contains("network-policy")));
}

#[test]
fn datadome_header_and_body_are_captcha() {
    let headers = vec![Header { name: "x-datadome".into(), value: "protected".into() }];
    let out = classify_response(403, &headers, &fixture("datadome-captcha.html"));
    assert_eq!(out.kind, OutcomeKind::Captcha);
    assert!(out.evidence.iter().any(|value| value.contains("x-datadome")));
}

#[test]
fn akamai_access_denied_is_explicit_block() {
    let out = classify_response(403, &[], &fixture("akamai-access-denied.html"));
    assert_eq!(out.kind, OutcomeKind::ExplicitBlock);
    assert!(out.evidence.iter().any(|value| value.contains("access-denied")));
}

#[test]
fn ordinary_200_is_only_content_like() {
    let out = classify_response(200, &[], b"<html><body>Hello</body></html>");
    assert_eq!(out.kind, OutcomeKind::ContentLike);
}

#[test]
fn aws_waf_202_challenge_beats_status() {
    let headers = vec![Header { name: "x-amzn-waf-action".into(), value: "challenge".into() }];
    let out = classify_response(202, &headers, b"");
    assert_eq!(out.kind, OutcomeKind::Challenge);
}

#[test]
fn profile_headers_preserve_order_and_duplicates() {
    let raw = r#"{
        "profiles": [{
            "name": "ordered",
            "headers": [
                {"name": "x-b", "value": "1"},
                {"name": "x-a", "value": "2"},
                {"name": "x-b", "value": "3"}
            ]
        }]
    }"#;
    let set: wireprint::ProfileSet = serde_json::from_str(raw).unwrap();
    let headers = &set.profiles[0].headers;
    assert_eq!(headers.iter().map(|h| h.name.as_str()).collect::<Vec<_>>(), vec!["x-b", "x-a", "x-b"]);
    assert_eq!(headers[2].value, "3");
}

#[test]
fn normalization_collapses_reddit_challenge_tokens() {
    let a = br#"<script nonce="c36cc8fa-0828-4fb8-9361-ecdb7850c2b3">x("6c7c95e231562510")</script><input name="jsc_token" value="2824be10929bdc604753c70a67a1c3312941ceb9555c4e05598345d41ec3795c">"#;
    let b = br#"<script nonce="37f808d2-4d2c-4794-a26c-6a07c5882e1a">x("e9313851d6df2227")</script><input name="jsc_token" value="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">"#;
    assert_eq!(wireprint::normalize_response_template(a), wireprint::normalize_response_template(b));
}

#[test]
fn normalization_collapses_datadome_ephemeral_tokens() {
    let a = br#"var dd={'cid':'AHrlqAAAAAMA-one','cookie':'abc~123','e':'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}"#;
    let b = br#"var dd={'cid':'AHrlqAAAAAMA-two','cookie':'xyz~789','e':'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'}"#;
    assert_eq!(wireprint::normalize_response_template(a), wireprint::normalize_response_template(b));
}
