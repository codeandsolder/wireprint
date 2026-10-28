use wireprint::{
    EndpointEvidence, PATH_CLASSIFIER_VERSION, PathElement, PathElementRole,
    ProviderEvidenceChannel, ProviderSignal, ProviderSupport, RoutingContext, TerminationState,
    assess_endpoint, detect_path_elements, detect_routing_elements,
};

fn signal(provider: &str, channel: ProviderEvidenceChannel) -> ProviderSignal {
    ProviderSignal {
        provider: provider.into(),
        channel,
        classifier: "test".into(),
        evidence: vec![format!("test:{provider}:{channel:?}")],
    }
}

fn provider_element(product: &str) -> PathElement {
    PathElement {
        role: PathElementRole::EdgeProvider,
        product: product.into(),
        classifier: "test".into(),
        evidence: vec![format!("test:{product}")],
    }
}

#[test]
fn routing_and_response_metadata_corroborate_without_request_count_weights() {
    let response = detect_path_elements(&[wireprint::Header {
        name: "cf-ray".into(),
        value: "abc-FRA".into(),
    }]);
    let routing = detect_routing_elements(&["site.cdn.cloudflare.net".into()]);
    let assessment = assess_endpoint(&EndpointEvidence {
        response_elements: response,
        routing_elements: routing,
        ..EndpointEvidence::default()
    });

    assert_eq!(assessment.state, TerminationState::SingleCandidate);
    assert_eq!(assessment.candidates.len(), 1);
    let candidate = &assessment.candidates[0];
    assert_eq!(candidate.provider, "cloudflare");
    assert_eq!(candidate.support, ProviderSupport::CrossChannelCorroborated);
    assert_eq!(
        candidate.originating_channels,
        vec![
            ProviderEvidenceChannel::ResponseMetadata,
            ProviderEvidenceChannel::RoutingCname,
        ]
    );
    let cloudflare_claims = assessment
        .path_elements
        .iter()
        .filter(|element| {
            element.role == PathElementRole::EdgeProvider && element.product == "cloudflare"
        })
        .collect::<Vec<_>>();
    assert_eq!(cloudflare_claims.len(), 2);
    assert!(
        cloudflare_claims
            .iter()
            .any(|element| element.classifier == PATH_CLASSIFIER_VERSION)
    );
    assert!(
        cloudflare_claims
            .iter()
            .any(|element| element.classifier == "builtin-routing-v1")
    );
}

#[test]
fn duplicate_signals_do_not_inflate_independent_channel_support() {
    let assessment = assess_endpoint(&EndpointEvidence {
        provider_signals: vec![
            signal("fastly", ProviderEvidenceChannel::H3Transport),
            signal("fastly", ProviderEvidenceChannel::H3Transport),
        ],
        ..EndpointEvidence::default()
    });

    let candidate = &assessment.candidates[0];
    assert_eq!(candidate.support, ProviderSupport::OriginatingEvidence);
    assert_eq!(
        candidate.originating_channels,
        vec![ProviderEvidenceChannel::H3Transport]
    );
}

#[test]
fn tls_morphology_cannot_originate_a_provider() {
    let tls = signal("imperva", ProviderEvidenceChannel::TlsMorphology);
    let assessment = assess_endpoint(&EndpointEvidence {
        provider_signals: vec![tls.clone()],
        ..EndpointEvidence::default()
    });

    assert_eq!(assessment.state, TerminationState::Unresolved);
    assert!(assessment.candidates.is_empty());
    assert_eq!(assessment.unanchored_corroborating_signals, vec![tls]);
}

#[test]
fn tls_morphology_can_confirm_an_existing_provider_candidate() {
    let assessment = assess_endpoint(&EndpointEvidence {
        routing_elements: vec![provider_element("imperva")],
        provider_signals: vec![signal("imperva", ProviderEvidenceChannel::TlsMorphology)],
        ..EndpointEvidence::default()
    });

    let candidate = &assessment.candidates[0];
    assert_eq!(candidate.support, ProviderSupport::CrossChannelCorroborated);
    assert_eq!(
        candidate.corroborating_channels,
        vec![ProviderEvidenceChannel::TlsMorphology]
    );
}

#[test]
fn downstream_platform_participation_does_not_become_outer_termination() {
    let assessment = assess_endpoint(&EndpointEvidence {
        routing_elements: detect_routing_elements(&["d1d4fc829fe7bc7c.vercel-dns-017.com".into()]),
        ..EndpointEvidence::default()
    });

    assert_eq!(assessment.state, TerminationState::Unresolved);
    assert!(assessment.candidates.is_empty());
    assert!(assessment.path_elements.iter().any(|element| {
        element.role == PathElementRole::ApplicationPlatform && element.product == "vercel"
    }));
}

#[test]
fn conflicting_originating_channels_are_preserved_as_multiple_candidates() {
    let assessment = assess_endpoint(&EndpointEvidence {
        response_elements: vec![provider_element("fastly")],
        routing_elements: vec![provider_element("azure-front-door")],
        ..EndpointEvidence::default()
    });

    assert_eq!(assessment.state, TerminationState::MultipleCandidates);
    assert_eq!(
        assessment
            .candidates
            .iter()
            .map(|candidate| candidate.provider.as_str())
            .collect::<Vec<_>>(),
        vec!["azure-front-door", "fastly"]
    );
}

#[test]
fn h2_h3_and_tls_are_kept_as_independent_channel_classes() {
    let assessment = assess_endpoint(&EndpointEvidence {
        provider_signals: vec![
            signal("akamai", ProviderEvidenceChannel::H2Transport),
            signal("akamai", ProviderEvidenceChannel::H3Transport),
            signal("akamai", ProviderEvidenceChannel::TlsMorphology),
        ],
        ..EndpointEvidence::default()
    });

    let candidate = &assessment.candidates[0];
    assert_eq!(candidate.support, ProviderSupport::CrossChannelCorroborated);
    assert_eq!(
        candidate.originating_channels,
        vec![
            ProviderEvidenceChannel::H2Transport,
            ProviderEvidenceChannel::H3Transport,
        ]
    );
    assert_eq!(
        candidate.corroborating_channels,
        vec![ProviderEvidenceChannel::TlsMorphology]
    );
}

#[test]
fn routing_context_is_preserved_but_cannot_originate_a_provider() {
    let context = RoutingContext {
        prefix: Some("104.16.112.0/20".into()),
        asn: Some(13_335),
        as_name: Some("CLOUDFLARENET - Cloudflare, Inc.".into()),
        evidence: vec!["team-cymru-origin-asn:AS13335".into()],
    };
    let assessment = assess_endpoint(&EndpointEvidence {
        routing_context: vec![context.clone()],
        ..EndpointEvidence::default()
    });

    assert_eq!(assessment.state, TerminationState::Unresolved);
    assert!(assessment.candidates.is_empty());
    assert_eq!(assessment.routing_context, vec![context]);
}

#[test]
fn routing_context_does_not_inflate_existing_provider_support() {
    let assessment = assess_endpoint(&EndpointEvidence {
        provider_signals: vec![signal("cloudflare", ProviderEvidenceChannel::H2Transport)],
        routing_context: vec![RoutingContext {
            prefix: Some("104.16.112.0/20".into()),
            asn: Some(13_335),
            as_name: Some("CLOUDFLARENET - Cloudflare, Inc.".into()),
            evidence: vec!["team-cymru-origin-asn:AS13335".into()],
        }],
        ..EndpointEvidence::default()
    });

    assert_eq!(assessment.state, TerminationState::SingleCandidate);
    assert_eq!(assessment.candidates.len(), 1);
    assert_eq!(
        assessment.candidates[0].support,
        ProviderSupport::OriginatingEvidence
    );
    assert!(assessment.candidates[0].corroborating_channels.is_empty());
}
