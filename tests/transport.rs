use wireprint::{BuiltinTransport, PlatformKind, TransportObservationCompleteness, TransportSet};

#[test]
fn observational_transport_can_preserve_partial_fingerprint_without_becoming_runnable() {
    let raw = r#"{
        "schema_version": 1,
        "transports": [{
            "name": "passive-only",
            "provenance": "example passive source",
            "observations": [{
                "scheme": "ja4",
                "value": "t13d1011h2_example_",
                "completeness": "prefix",
                "provenance": "only a prefix was retained"
            }]
        }]
    }"#;

    let set: TransportSet = serde_json::from_str(raw).unwrap();
    let profile = &set.transports[0];
    assert!(!profile.runnable());
    assert!(profile.implementation.is_none());
    assert_eq!(profile.observations[0].scheme, "ja4");
    assert_eq!(
        profile.observations[0].completeness,
        TransportObservationCompleteness::Prefix
    );

    let encoded = serde_json::to_string(profile).unwrap();
    assert!(encoded.contains("\"completeness\":\"prefix\""));
    assert!(!encoded.contains("implementation"));
}

#[test]
fn observational_transport_cannot_be_executed() {
    let raw = r#"{
        "schema_version": 1,
        "transports": [{
            "name": "hash-is-not-a-recipe",
            "observations": [{"scheme": "ja4", "value": "partial", "completeness": "partial"}]
        }]
    }"#;
    let set: TransportSet = serde_json::from_str(raw).unwrap();
    let error = set.transports[0]
        .configure(wreq::Client::builder())
        .err()
        .expect("observational-only transport should be rejected");
    assert!(error.to_string().contains("observational only"));
}

#[test]
fn builtin_browser_transport_keeps_platform_in_transport_axis() {
    let profile = BuiltinTransport::Chrome149.into_profile(PlatformKind::Windows);
    assert!(profile.runnable());
    assert_eq!(profile.name, "chrome149");
    assert_eq!(profile.platform(), Some(PlatformKind::Windows));
}

#[test]
fn plain_transport_has_no_fake_platform_identity() {
    let profile = BuiltinTransport::Plain.into_profile(PlatformKind::Macos);
    assert!(profile.runnable());
    assert_eq!(profile.name, "plain");
    assert_eq!(profile.platform(), None);
}

#[test]
fn fixed_mobile_builtin_platforms_are_recorded_from_the_transport() {
    assert_eq!(
        BuiltinTransport::SafariIos18
            .into_profile(PlatformKind::Macos)
            .platform(),
        Some(PlatformKind::Ios)
    );
    assert_eq!(
        BuiltinTransport::FirefoxAndroid135
            .into_profile(PlatformKind::Macos)
            .platform(),
        Some(PlatformKind::Android)
    );
}

#[test]
fn bundled_transport_set_is_valid() {
    let set: TransportSet =
        serde_json::from_str(include_str!("../transports/builtins.json")).unwrap();
    set.validate().unwrap();
    assert_eq!(set.transports.len(), 12);
    assert!(set.transports.iter().all(|profile| profile.runnable()));
}

#[test]
fn duplicate_transport_names_are_rejected() {
    let raw = r#"{
        "schema_version": 1,
        "transports": [
            {"name": "same", "implementation": {"kind": "builtin", "profile": "plain"}},
            {"name": "same", "implementation": {"kind": "builtin", "profile": "plain"}}
        ]
    }"#;
    let set: TransportSet = serde_json::from_str(raw).unwrap();
    let error = set.validate().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("duplicate transport profile name")
    );
}

#[test]
fn unsupported_transport_schema_version_is_rejected() {
    let raw = r#"{
        "schema_version": 2,
        "transports": [
            {"name": "plain", "implementation": {"kind": "builtin", "profile": "plain"}}
        ]
    }"#;
    let set: TransportSet = serde_json::from_str(raw).unwrap();
    let error = set.validate().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unsupported transport schema version")
    );
}

#[test]
fn bundled_gptbot_capture_is_exact_and_observational_only() {
    let set: TransportSet =
        serde_json::from_str(include_str!("../transports/openai-gptbot-observed.json")).unwrap();
    set.validate().unwrap();
    assert_eq!(set.transports.len(), 1);
    let profile = &set.transports[0];
    assert!(!profile.runnable());
    assert_eq!(profile.observations.len(), 3);
    assert!(profile.observations.iter().any(|observation| {
        observation.scheme == "ja4"
            && observation.value == "t13d1011h2_61a7ad8aa9b6_3fcd1a44f3e3"
            && observation.completeness == TransportObservationCompleteness::Exact
    }));
    assert!(profile.observations.iter().any(|observation| {
        observation.scheme == "akamai_http2_client_fingerprint"
            && observation.value == "2:0;4:2097152;5:16384;6:16384|5177345|0|m,s,a,p"
    }));
}

#[test]
fn bundled_chatgpt_user_capture_is_distinct_and_observational_only() {
    let set: TransportSet = serde_json::from_str(include_str!(
        "../transports/openai-chatgpt-user-observed.json"
    ))
    .unwrap();
    set.validate().unwrap();
    assert_eq!(set.transports.len(), 1);
    let profile = &set.transports[0];
    assert!(!profile.runnable());
    assert_eq!(profile.observations.len(), 4);
    assert!(profile.observations.iter().any(|observation| {
        observation.scheme == "ja4_peet_legacy"
            && observation.value == "t13d1712h2_5b57614c22b0_78e6aca7449b"
            && observation.completeness == TransportObservationCompleteness::Exact
    }));
    assert!(profile.observations.iter().any(|observation| {
        observation.scheme == "ja3" && observation.value == "f5bd742fa88333052a1deec09f821012"
    }));
    assert!(profile.observations.iter().any(|observation| {
        observation.scheme == "akamai_http2_client_fingerprint"
            && observation.value == "2:0;1:4096;8:0;3:1024;4:1048576|25100289|0|a,p,m,s"
    }));
    assert_ne!(
        profile
            .observations
            .iter()
            .find(|o| o.scheme == "ja4_peet_legacy")
            .unwrap()
            .value,
        "t13d1011h2_61a7ad8aa9b6_3fcd1a44f3e3"
    );
}

#[test]
fn reconstructed_gptbot_transport_is_runnable_and_pins_measured_fingerprints() {
    let set: TransportSet = serde_json::from_str(include_str!(
        "../transports/openai-gptbot-reconstructed.json"
    ))
    .unwrap();
    set.validate().unwrap();
    assert_eq!(set.transports.len(), 1);
    let profile = &set.transports[0];
    assert!(profile.runnable());
    assert_eq!(profile.platform(), None);
    assert!(matches!(
        profile.implementation,
        Some(wireprint::TransportImplementation::HyperRustls {
            profile: wireprint::HyperRustlsProfileKind::Reqwest01228CompatibleRustls02342,
        })
    ));
    assert!(profile.observations.iter().any(|observation| {
        observation.scheme == "ja4"
            && observation.value == "t13d1011h2_61a7ad8aa9b6_3fcd1a44f3e3"
            && observation.completeness == TransportObservationCompleteness::Exact
    }));
    assert!(profile.observations.iter().any(|observation| {
        observation.scheme == "ja4_r"
            && observation
                .value
                .starts_with("t13d1011h2_00ff,1301,1302,1303")
            && observation.completeness == TransportObservationCompleteness::Exact
    }));
    assert!(profile.observations.iter().any(|observation| {
        observation.scheme == "akamai_http2_client_fingerprint"
            && observation.value == "2:0;4:2097152;5:16384;6:16384|5177345|0|m,s,a,p"
            && observation.completeness == TransportObservationCompleteness::Exact
    }));
}

#[test]
fn reconstructed_chatgpt_user_transport_is_runnable_and_pins_envoy_compatible_wire_image() {
    let set: TransportSet = serde_json::from_str(include_str!(
        "../transports/openai-chatgpt-user-reconstructed.json"
    ))
    .unwrap();
    set.validate().unwrap();
    assert_eq!(set.transports.len(), 1);
    let profile = &set.transports[0];
    assert!(profile.runnable());
    assert_eq!(profile.platform(), None);
    assert!(matches!(
        profile.implementation,
        Some(wireprint::TransportImplementation::WreqMeasured {
            profile: wireprint::WreqMeasuredProfileKind::EnvoyChatgptUserCompatible2026,
        })
    ));
    assert!(profile.observations.iter().any(|observation| {
        observation.scheme == "ja4"
            && observation.value == "t13d1712h2_5b57614c22b0_ef7df7f74e48"
            && observation.completeness == TransportObservationCompleteness::Exact
    }));
    assert!(profile.observations.iter().any(|observation| {
        observation.scheme == "ja3"
            && observation.value == "f5bd742fa88333052a1deec09f821012"
            && observation.completeness == TransportObservationCompleteness::Exact
    }));
    assert!(profile.observations.iter().any(|observation| {
        observation.scheme == "akamai_http2_client_fingerprint"
            && observation.value == "2:0;1:4096;8:0;3:1024;4:1048576|25100289|0|a,p,m,s"
            && observation.completeness == TransportObservationCompleteness::Exact
    }));
}

#[test]
fn observed_chatgpt_user_request_profile_keeps_measured_static_header_order() {
    let set: wireprint::ProfileSet =
        serde_json::from_str(include_str!("../profiles/ai-retrievers-observed.json")).unwrap();
    let profile = set
        .profiles
        .iter()
        .find(|profile| profile.name == "openai-chatgpt-user")
        .unwrap();
    let names = profile
        .headers
        .iter()
        .map(|header| header.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "user-agent",
            "accept-language",
            "accept-encoding",
            "accept",
            "x-envoy-expected-rq-timeout-ms",
        ]
    );
}

#[test]
fn verified_claudebot_capture_is_observational_only_and_pins_only_stable_ja4() {
    let set: TransportSet = serde_json::from_str(include_str!(
        "../transports/anthropic-claudebot-observed.json"
    ))
    .unwrap();
    set.validate().unwrap();
    assert_eq!(set.transports.len(), 1);
    let profile = &set.transports[0];
    assert!(!profile.runnable());
    assert_eq!(profile.observations.len(), 1);
    assert_eq!(profile.observations[0].scheme, "ja4");
    assert_eq!(
        profile.observations[0].value,
        "t13d1011h2_61a7ad8aa9b6_3fcd1a44f3e3"
    );
    assert_eq!(
        profile.observations[0].completeness,
        TransportObservationCompleteness::Exact
    );
    assert!(
        !profile
            .observations
            .iter()
            .any(|observation| observation.scheme == "akamai_http2_client_fingerprint")
    );
}
