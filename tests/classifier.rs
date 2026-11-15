use pretty_assertions::assert_eq;
use wireprint::{Header, OutcomeKind, classify_response};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("tests/fixtures/{name}")).unwrap()
}

#[test]
fn reddit_200_is_challenge_not_content() {
    let out = classify_response(200, &[], &fixture("reddit-js-challenge.html"));
    assert_eq!(out.kind, OutcomeKind::Challenge);
    assert!(
        out.evidence
            .iter()
            .any(|value| value.contains("reddit-js-challenge"))
    );
}

#[test]
fn reddit_network_policy_is_explicit_block() {
    let out = classify_response(403, &[], &fixture("reddit-hard-block.html"));
    assert_eq!(out.kind, OutcomeKind::ExplicitBlock);
    assert!(
        out.evidence
            .iter()
            .any(|value| value.contains("network-policy"))
    );
}

#[test]
fn datadome_header_and_body_are_captcha() {
    let headers = vec![Header {
        name: "x-datadome".into(),
        value: "protected".into(),
    }];
    let out = classify_response(403, &headers, &fixture("datadome-captcha.html"));
    assert_eq!(out.kind, OutcomeKind::Captcha);
    assert!(
        out.evidence
            .iter()
            .any(|value| value.contains("x-datadome"))
    );
}

#[test]
fn akamai_access_denied_is_explicit_block() {
    let out = classify_response(403, &[], &fixture("akamai-access-denied.html"));
    assert_eq!(out.kind, OutcomeKind::ExplicitBlock);
    assert!(
        out.evidence
            .iter()
            .any(|value| value.contains("access-denied"))
    );
}

#[test]
fn ordinary_200_is_only_content_like() {
    let out = classify_response(200, &[], b"<html><body>Hello</body></html>");
    assert_eq!(out.kind, OutcomeKind::ContentLike);
}

#[test]
fn aws_waf_202_challenge_beats_status() {
    let headers = vec![Header {
        name: "x-amzn-waf-action".into(),
        value: "challenge".into(),
    }];
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
    assert_eq!(
        headers.iter().map(|h| h.name.as_str()).collect::<Vec<_>>(),
        vec!["x-b", "x-a", "x-b"]
    );
    assert_eq!(headers[2].value, "3");
}

#[test]
fn normalization_collapses_reddit_challenge_tokens() {
    let a = br#"<script nonce="c36cc8fa-0828-4fb8-9361-ecdb7850c2b3">x("6c7c95e231562510")</script><input name="jsc_token" value="2824be10929bdc604753c70a67a1c3312941ceb9555c4e05598345d41ec3795c">"#;
    let b = br#"<script nonce="37f808d2-4d2c-4794-a26c-6a07c5882e1a">x("e9313851d6df2227")</script><input name="jsc_token" value="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">"#;
    assert_eq!(
        wireprint::normalize_response_template(a),
        wireprint::normalize_response_template(b)
    );
}

#[test]
fn normalization_collapses_datadome_ephemeral_tokens() {
    let a = br#"var dd={'cid':'AHrlqAAAAAMA-one','cookie':'abc~123','e':'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}"#;
    let b = br#"var dd={'cid':'AHrlqAAAAAMA-two','cookie':'xyz~789','e':'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'}"#;
    assert_eq!(
        wireprint::normalize_response_template(a),
        wireprint::normalize_response_template(b)
    );
}

#[test]
fn aws_waf_captcha_header_is_a_captcha_even_with_uninformative_body() {
    let headers = [Header {
        name: "X-Amzn-Waf-Action".into(),
        value: " CAPTCHA ".into(),
    }];
    let out = classify_response(405, &headers, b"");
    assert_eq!(out.kind, OutcomeKind::Captcha);
    assert_eq!(out.classifier, "builtin-v2");
    assert_eq!(out.evidence, ["header:x-amzn-waf-action=captcha"]);
}

#[test]
fn cloudflare_mitigated_challenge_header_beats_403_and_429() {
    for status in [200, 403, 429] {
        let headers = [
            Header {
                name: "CF-MitIgated".into(),
                value: " challenge ".into(),
            },
            Header {
                name: "cf-ray".into(),
                value: "a123456-WAW".into(),
            },
        ];
        let out = classify_response(status, &headers, b"");
        assert_eq!(out.kind, OutcomeKind::Challenge, "{status}");
        assert_eq!(out.evidence, ["header:cf-mitigated=challenge"]);
    }
}

#[test]
fn cloudflare_200_body_only_challenge_needs_both_bootstrap_and_platform_path() {
    let body = br#"<html><head><title>Just a moment...</title>
        <script>window._cf_chl_opt={cType:"managed",cRay:"abc"};</script>
        <script src="/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1"></script>
        </head></html>"#;
    let out = classify_response(200, &[], body);
    assert_eq!(out.kind, OutcomeKind::Challenge);
    assert_eq!(out.evidence, ["body:cf-challenge-bootstrap+platform"]);
}

#[test]
fn cloudflare_stray_script_or_turnstile_widget_is_not_challenge() {
    for body in [
        "<script>window._cf_chl_opt={};</script>",
        "<script src='/cdn-cgi/challenge-platform/any.js'></script>",
        "<div class='cf-turnstile' data-sitekey='opaque'></div>",
        "<script src='https://challenges.cloudflare.com/turnstile/v0/api.js'></script>",
        "<p>this article explains _cf_chl_opt and Cloudflare challenges</p>",
    ] {
        let out = classify_response(200, &[], body.as_bytes());
        assert_eq!(out.kind, OutcomeKind::ContentLike, "bad body: {body}");
    }
    let out = classify_response(
        200,
        &[
            Header {
                name: "cf-ray".into(),
                value: "abc123-WAW".into(),
            },
            Header {
                name: "cf-mitigated".into(),
                value: "none".into(),
            },
        ],
        b"normal content",
    );
    assert_eq!(out.kind, OutcomeKind::ContentLike);
}

#[test]
fn anubis_actual_script_pair_beats_success_status_and_plain_block() {
    let body = br#"<html><head>
      <script id="anubis_version" type="application/json">"1.2"</script>
      <script type="application/json" id="anubis_challenge">{"difficulty":5}</script>
      </head></html>"#;
    for status in [200, 403] {
        let out = classify_response(status, &[], body);
        assert_eq!(out.kind, OutcomeKind::Challenge);
        assert_eq!(out.evidence, ["body:anubis-version+challenge-scripts"]);
    }
}

#[test]
fn anubis_link_or_single_script_does_not_establish_challenge_outcome() {
    for body in [
        "<a href='https://github.com/TecharoHQ/anubis'>source</a>",
        "<script id='anubis_challenge'></script>",
        "<script id='anubis_version'></script>",
        "<div>anubis_version anubis_challenge</div>",
    ] {
        assert_eq!(
            classify_response(200, &[], body.as_bytes()).kind,
            OutcomeKind::ContentLike,
            "{body}"
        );
    }
}

#[test]
fn ordinary_waf_presence_is_not_an_enforcement_event() {
    for headers in [
        vec![Header {
            name: "cf-ray".into(),
            value: "abcdef12-WAW".into(),
        }],
        vec![Header {
            name: "set-cookie".into(),
            value: "__cf_bm=opaque; Path=/".into(),
        }],
        vec![Header {
            name: "set-cookie".into(),
            value: "aws-waf-token=opaque; Path=/".into(),
        }],
        vec![Header {
            name: "set-cookie".into(),
            value: "techaro.lol-anubis-auth=opaque; Path=/".into(),
        }],
        vec![Header {
            name: "x-amzn-waf-action".into(),
            value: "count".into(),
        }],
    ] {
        assert_eq!(
            classify_response(200, &headers, b"<h1>Hello</h1>").kind,
            OutcomeKind::ContentLike,
            "{headers:?}"
        );
    }
}
