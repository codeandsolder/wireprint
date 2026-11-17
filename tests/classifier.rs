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
    assert_eq!(out.classifier, "builtin-v6");
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

#[test]
fn edgeone_captcha_interstitial_is_detected_even_as_http_200() {
    let body = br#"<html><head><title>Security Verification</title>
<script src="https://gcaptcha.eo.gtimg.com/TEOCaptchaWidgetV1-global.js"></script>
</head><body><div id="captcha"></div><footer>Protected by Tencent Cloud EdgeOne</footer></body></html>"#;
    let result = classify_response(200, &[], body);
    assert_eq!(result.classifier, "builtin-v6");
    assert_eq!(result.kind, OutcomeKind::Captcha);
    assert_eq!(
        result.evidence,
        ["body:edgeone-security-verification+captcha-widget"]
    );
}

#[test]
fn edgeone_integration_or_branding_alone_is_not_an_active_captcha() {
    for body in [
        "<title>Security Verification</title>",
        "<script src='https://gcaptcha.eo.gtimg.com/TEOCaptchaWidgetV1-global.js'></script>",
        "<p>Protected by Tencent Cloud EdgeOne</p>",
        "<p>Protected by Tencent Cloud EdgeOne</p><h1>Security Verification</h1>",
        "<script src='/TEOCaptchaWidgetV1-global.js'></script><h1>Security Verification</h1>",
    ] {
        assert_eq!(
            classify_response(200, &[], body.as_bytes()).kind,
            OutcomeKind::ContentLike,
            "{body}"
        );
    }
}

#[test]
fn imperva_browser_interruption_page_is_a_challenge_not_content() {
    let body = br#"<title>Pardon Our Interruption</title><h1>Pardon Our Interruption</h1>
<h3>Please stand by</h3><p>As you were browsing something about your browser made
us think you were a bot. There are a few reasons this might happen:</p>"#;
    let out = classify_response(200, &[], body);
    assert_eq!(out.kind, OutcomeKind::Challenge);
    assert_eq!(out.evidence, ["body:pardon-interruption+bot-browser-check"]);
}

#[test]
fn ordinary_imperva_sdk_and_mentions_do_not_create_browser_challenge() {
    for body in [
        "<title>Pardon Our Interruption</title><p>Read our article on this error.</p>",
        "<script src='/_Incapsula_Resource?SWJIYLWA=anything'></script>",
        "<p>something about your browser made us think you were a bot</p>",
        "<h1>Pardon Our Interruption</h1><p>A website can challenge visitors.</p>",
    ] {
        assert_eq!(
            classify_response(200, &[], body.as_bytes()).kind,
            OutcomeKind::ContentLike
        );
    }
}

#[test]
fn perimeterx_active_press_hold_captcha_requires_denied_document_and_pair() {
    let body = br#"<title>Loading ...</title>
        <div class="px-captcha"></div>
        <span>Press and Hold to verify you're human</span>
        <script src="/px-files/dt.js"></script>"#;
    let out = classify_response(403, &[], body);
    assert_eq!(out.kind, OutcomeKind::Captcha);
    assert_eq!(out.evidence, ["body:px-captcha+press-hold"]);
    let accepted = classify_response(200, &[], body);
    assert_eq!(accepted.kind, OutcomeKind::ContentLike);
    assert_eq!(
        classify_response(403, &[], b"<p>Press and hold</p>").kind,
        OutcomeKind::ExplicitBlock
    );
    assert_eq!(
        classify_response(403, &[], b"<p>px-captcha</p>").kind,
        OutcomeKind::ExplicitBlock
    );
}

#[test]
fn turnstile_in_denied_verify_human_gate_is_challenge_not_generic_block() {
    let body = br#"<h1>Verify you are human</h1>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"></script>"#;
    let out = classify_response(403, &[], body);
    assert_eq!(out.kind, OutcomeKind::Challenge);
    assert_eq!(out.evidence, ["body:turnstile+verify-human-gate"]);
    assert_eq!(
        classify_response(200, &[], body).kind,
        OutcomeKind::ContentLike
    );
    assert_eq!(
        classify_response(403, &[], b"<h1>Verify you are human</h1>").kind,
        OutcomeKind::ExplicitBlock
    );
}

#[test]
fn browser_security_verification_interstitial_is_not_content() {
    let body = br#"<title>Security Verification</title>
<h1>Security verification in progress. Please wait while we verify your
browser to protect against automated access.</h1>
<h2>Verifying connection...</h2>"#;
    let out = classify_response(200, &[], body);
    assert_eq!(out.kind, OutcomeKind::Challenge);
    assert_eq!(
        out.evidence,
        ["body:security-verification+browser-connection"]
    );
}

#[test]
fn generic_security_article_or_title_is_not_browser_interstitial() {
    for body in [
        "<title>Security Verification</title>",
        "<h2>Verifying connection...</h2>",
        "<h1>Security verification in progress</h1>",
        "<p>verify your browser to protect against automated access</p>",
        "<h1>Security verification in progress</h1><p>learn more about bot defenses</p>",
    ] {
        assert_eq!(
            classify_response(200, &[], body.as_bytes()).kind,
            OutcomeKind::ContentLike
        );
    }
}

#[test]
fn sucuri_firewall_block_enriches_existing_explicit_block() {
    let body = b"<title>Sucuri WebSite Firewall - Access Denied</title><h1>Access Denied - Sucuri Website Firewall</h1>";
    let out = classify_response(403, &[], body);
    assert_eq!(out.kind, OutcomeKind::ExplicitBlock);
    assert_eq!(
        out.evidence,
        [
            "status:403",
            "body:sucuri-website-firewall",
            "body:access-denied"
        ]
    );
    assert_eq!(
        classify_response(200, &[], body).kind,
        OutcomeKind::ContentLike
    );
}

#[test]
fn documented_header_action_remains_more_specific_than_corpus_body_gate() {
    let headers = [Header {
        name: "CF-Mitigated".into(),
        value: "challenge".into(),
    }];
    let html = b"<title>Pardon Our Interruption</title><p>something about your browser made us think you were a bot</p>";
    let out = classify_response(403, &headers, html);
    assert_eq!(out.kind, OutcomeKind::Challenge);
    assert_eq!(out.evidence, ["header:cf-mitigated=challenge"]);
}

#[test]
fn client_challenge_javascript_gate_requires_context() {
    let body = br#"<html><head><title>Client Challenge</title></head><body><noscript>
    <p>JavaScript is disabled in your browser.</p>
    <p>Please enable JavaScript to proceed.</p>
    </noscript></body></html>"#;
    let out = classify_response(200, &[], body);
    assert_eq!(out.kind, OutcomeKind::Challenge);
    assert_eq!(out.evidence, ["body:client-challenge+javascript-gate"]);
    for text in [
        "<title>Client Challenge</title>",
        "<p>JavaScript is disabled in your browser. Please enable JavaScript to proceed.</p>",
        "<title>Client Challenge</title><p>This page needs JavaScript.</p>",
    ] {
        assert_eq!(
            classify_response(200, &[], text.as_bytes()).kind,
            OutcomeKind::ContentLike,
            "{text}"
        );
    }
}

#[test]
fn hcdn_reserved_js_challenge_and_browser_check_are_joint_evidence() {
    let body = br#"<html><head><title>Checking your browser before accessing. Just a moment...</title></head>
<body><h1>Checking your browser before accessing</h1><p>Please wait for up to 5 seconds...</p>
<script src="/hcdn-cgi/jschallenge"></script></body></html>"#;
    for status in [200, 403] {
        let out = classify_response(status, &[], body);
        assert_eq!(out.kind, OutcomeKind::Challenge, "{status}");
        assert_eq!(out.classifier, "builtin-v6");
        assert_eq!(out.evidence, ["body:hcdn-jschallenge+browser-check"]);
    }
}

#[test]
fn hcdn_brand_script_and_browser_wording_alone_are_not_gate_evidence() {
    for body in [
        "<script src='/hcdn-cgi/jschallenge'></script>",
        "<h1>Checking your browser before accessing</h1>",
        "<h1>Why is the hcdn-cgi JS Challenge shown to browsers?</h1>",
        "<p>This page documents a browser protection mechanism.</p>",
    ] {
        assert_eq!(
            classify_response(200, &[], body.as_bytes()).kind,
            OutcomeKind::ContentLike,
            "{body}"
        );
    }
    let headers = [Header {
        name: "Server".into(),
        value: "hcdn".into(),
    }];
    assert_eq!(
        classify_response(200, &headers, b"ordinary content").kind,
        OutcomeKind::ContentLike
    );
}

#[test]
fn custom_security_verification_javascript_robot_check_is_challenge() {
    let body = br#"<html><title>Security Verification</title>
<h1>JavaScript is disabled</h1>
<p>In order to continue, we need to verify that you are not a robot.</p>
<p>This requires JavaScript. Enable JavaScript and then reload the page.</p></html>"#;
    let out = classify_response(405, &[], body);
    assert_eq!(out.kind, OutcomeKind::Challenge);
    assert_eq!(out.classifier, "builtin-v6");
    assert_eq!(
        out.evidence,
        ["body:security-verification+javascript-robot-check"]
    );
    let headers = [Header {
        name: "X-Amzn-Waf-Action".into(),
        value: "captcha".into(),
    }];
    let overridden = classify_response(405, &headers, body);
    assert_eq!(overridden.kind, OutcomeKind::Captcha);
    assert_eq!(overridden.evidence, ["header:x-amzn-waf-action=captcha"]);
}

#[test]
fn generic_security_verification_and_javascript_requirements_are_not_challenge() {
    for body in [
        "<title>Security Verification</title><p>Complete our form.</p>",
        "<p>Verify that you are not a robot.</p>",
        "<p>This requires JavaScript. Enable JavaScript and then reload the page.</p>",
        "<title>Security Verification</title><p>This requires JavaScript.</p>",
        "<title>Security Verification</title><p>Verify that you are not a robot.</p>",
        "<title>Security Verification</title><p>Verify that you are not a robot.</p><p>Enable JavaScript to continue.</p>",
    ] {
        assert_eq!(
            classify_response(200, &[], body.as_bytes()).kind,
            OutcomeKind::ContentLike,
            "{body}"
        );
    }
}

#[test]
fn recaptcha_browser_verification_document_is_challenge_not_captcha() {
    // Reproduces the three independent markers in archived NIH PubMed/PMC
    // first-party root-frame HTTP 200 documents, not an embedded widget.
    let html = br#"<html><head>
        <base href='https://www.google.com/recaptcha/challengepage/'>
        <title> Checking your
            browser - reCAPTCHA </title>
        <script>window['ppConfig'] = {productName: 'RecaptchaChallengePageUi'};</script>
        </head><body>
        Checking your browser before accessing pubmed.ncbi.nlm.nih.gov ...
        <script src="https://www.google.com/recaptcha/enterprise.js"></script>
        </body></html>"#;
    for status in [200, 403] {
        let outcome = classify_response(status, &[], html);
        assert_eq!(outcome.kind, OutcomeKind::Challenge);
        assert_eq!(outcome.classifier, "builtin-v6");
        assert_eq!(
            outcome.evidence,
            ["body:recaptcha-challengepage+browser-check"]
        );
    }
}

#[test]
fn recaptcha_widget_docs_or_partial_browser_document_are_not_gate() {
    let normal_widget = r#"<form><div class="g-recaptcha"></div>
        <script src="https://www.google.com/recaptcha/enterprise.js"></script></form>"#;
    let samples = [
        normal_widget,
        "<title>Checking your browser - reCAPTCHA</title>",
        "<base href='https://www.google.com/recaptcha/challengepage/'>",
        "<script>RecaptchaChallengePageUi</script>",
        "<title>Checking your browser - reCAPTCHA</title><script>RecaptchaChallengePageUi</script>",
        "<base href='https://www.google.com/recaptcha/challengepage/'><script>RecaptchaChallengePageUi</script>",
        "<title>Checking your browser - reCAPTCHA</title><base href='https://www.google.com/recaptcha/challengepage/'>",
        "<article>Checking your browser - reCAPTCHA and RecaptchaChallengePageUi are documented at https://www.google.com/recaptcha/challengepage/</article>",
    ];
    for sample in samples {
        assert_eq!(
            classify_response(200, &[], sample.as_bytes()).kind,
            OutcomeKind::ContentLike,
            "{sample}"
        );
    }
}

#[test]
fn first_party_action_header_precedes_recaptcha_body_interpretation() {
    let headers = [Header {
        name: "X-Amzn-Waf-Action".into(),
        value: "captcha".into(),
    }];
    let body = br#"<title>Checking your browser - reCAPTCHA</title><base href="https://www.google.com/recaptcha/challengepage/"><script>RecaptchaChallengePageUi</script>"#;
    let out = classify_response(200, &headers, body);
    assert_eq!(out.kind, OutcomeKind::Captcha);
    assert_eq!(out.evidence, ["header:x-amzn-waf-action=captcha"]);
}

#[test]
fn datadome_presence_header_does_not_determine_enforcement_outcome() {
    let headers = [Header {
        name: "X-DataDome".into(),
        value: "protected".into(),
    }];
    for status in [200, 201, 204] {
        let out = classify_response(status, &headers, b"<html>Ordinary page</html>");
        assert_eq!(out.kind, OutcomeKind::ContentLike);
        assert_eq!(out.evidence, [format!("status:{status}")]);
        assert_eq!(out.classifier, "builtin-v6");
    }
    for status in [401, 403] {
        let out = classify_response(status, &headers, b"<html>Access denied</html>");
        assert_eq!(out.kind, OutcomeKind::ExplicitBlock);
        assert_eq!(
            out.evidence,
            [format!("status:{status}"), "body:access-denied".into()]
        );
    }
}

#[test]
fn datadome_device_check_and_captcha_are_different_actions() {
    let header = [Header {
        name: "X-DataDome".into(),
        value: "protected".into(),
    }];
    for (runtime, expected, marker) in [
        ("i", OutcomeKind::Challenge, "body:datadome-device-check"),
        ("c", OutcomeKind::Captcha, "body:datadome-captcha"),
    ] {
        let body = format!(
            r#"<html><p id="cmsg">Please enable JS and disable any ad blocker</p>
<script>var dd={{'cid':'c','host':'geo.captcha-delivery.com',
'rt':'{runtime}','hsh':'abc'}};</script></html>"#
        );
        for status in [200, 401, 403] {
            let out = classify_response(status, &header, body.as_bytes());
            assert_eq!(out.kind, expected, "{runtime} {status}");
            assert_eq!(out.evidence, [marker], "{runtime} {status}");
            assert_eq!(out.classifier, "builtin-v6");
        }
    }
    let variants = [
        r#"<p>Please enable JS and disable any ad blocker</p><script>const dd = { "host" : "geo.captcha-delivery.com", "rt" : "i" };</script>"#,
        r#"<p>Please enable JS and disable any ad blocker</p><script>let dd = {rt:"i",host:"geo.captcha-delivery.com"};</script>"#,
    ];
    for body in variants {
        assert_eq!(
            classify_response(403, &[], body.as_bytes()).kind,
            OutcomeKind::Challenge
        );
    }
}

#[test]
fn datadome_sdk_article_and_incomplete_shells_are_not_active_challenges() {
    let bodies = [
        r#"<article>Why does captcha-delivery.com appear in a network log?</article>"#,
        r#"<script src="https://ct.captcha-delivery.com/tags.js"></script>"#,
        r#"<p>Please enable JS and disable any ad blocker</p>"#,
        r#"<script>var dd={'rt':'i','host':'geo.captcha-delivery.com'};</script>"#,
        r#"<script>var dd={'rt':'i','host':'other.example'};</script><p>Please enable JS and disable any ad blocker</p>"#,
        r#"<script>var dd={'rt':'x','host':'geo.captcha-delivery.com'};</script><p>Please enable JS and disable any ad blocker</p>"#,
        r#"<script>var dd={'rt':'i','host':'evilcaptcha-delivery.com'};</script><p>Please enable JS and disable any ad blocker</p>"#,
        r#"<script>const ddd={'rt':'i','host':'geo.captcha-delivery.com'};</script><p>Please enable JS and disable any ad blocker</p>"#,
    ];
    for body in bodies {
        let result = classify_response(200, &[], body.as_bytes());
        assert_eq!(result.kind, OutcomeKind::ContentLike, "{body}");
        assert_eq!(result.evidence, ["status:200"], "{body}");
    }
}

#[test]
fn authenticated_vendor_action_precedes_datadome_document_gate() {
    let headers = [Header {
        name: "X-Amzn-Waf-Action".into(),
        value: "captcha".into(),
    }];
    let body = br#"<p>Please enable JS and disable any ad blocker</p><script>var dd={'rt':'i','host':'geo.captcha-delivery.com'};</script>"#;
    let result = classify_response(405, &headers, body);
    assert_eq!(result.kind, OutcomeKind::Captcha);
    assert_eq!(result.evidence, ["header:x-amzn-waf-action=captcha"]);
}
