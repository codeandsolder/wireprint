use wireprint::{
    EndpointAssessment, HostAggregationConfig, HostFreshnessBasis, HostProviderState,
    HostProviderSupport, ProviderCandidate, ProviderEvidenceChannel, ProviderSignal,
    ProviderSupport, TerminationState, aggregate_host,
};

const HOUR: u128 = 60 * 60 * 1000;

fn candidate(
    provider: &str,
    originating: &[ProviderEvidenceChannel],
    corroborating: &[ProviderEvidenceChannel],
) -> ProviderCandidate {
    ProviderCandidate {
        provider: provider.into(),
        support: if originating.len() + corroborating.len() >= 2 {
            ProviderSupport::CrossChannelCorroborated
        } else {
            ProviderSupport::OriginatingEvidence
        },
        originating_channels: originating.to_vec(),
        corroborating_channels: corroborating.to_vec(),
        evidence: vec![format!("test:{provider}")],
    }
}

fn assessment(
    at: Option<u128>,
    vantage: Option<&str>,
    endpoint: Option<&str>,
    candidates: Vec<ProviderCandidate>,
) -> EndpointAssessment {
    EndpointAssessment {
        classifier: "test-endpoint".into(),
        target: Some("https://example.test/".into()),
        observed_unix_ms: at,
        vantage: vantage.map(str::to_owned),
        protocol: Some("HTTP/2.0".into()),
        selected_endpoint: endpoint.map(str::to_owned),
        actual_peer: endpoint.map(str::to_owned),
        state: match candidates.len() {
            0 => TerminationState::Unresolved,
            1 => TerminationState::SingleCandidate,
            _ => TerminationState::MultipleCandidates,
        },
        candidates,
        path_elements: Vec::new(),
        unanchored_corroborating_signals: Vec::new(),
        routing_context: Vec::new(),
    }
}

fn tls_only_assessment(at: Option<u128>, provider: &str) -> EndpointAssessment {
    let mut row = assessment(at, Some("tls"), Some("203.0.113.99"), Vec::new());
    row.protocol = Some("TLS/1.3".into());
    row.unanchored_corroborating_signals = vec![ProviderSignal {
        provider: provider.into(),
        channel: ProviderEvidenceChannel::TlsMorphology,
        classifier: "test-tls".into(),
        evidence: vec![format!("tls:{provider}")],
    }];
    row
}

#[test]
fn stale_provider_stays_historical_without_resurrecting_current_membership() {
    let rows = vec![
        assessment(
            Some(HOUR),
            Some("home"),
            Some("203.0.113.10"),
            vec![candidate(
                "fastly",
                &[ProviderEvidenceChannel::RoutingCname],
                &[],
            )],
        ),
        assessment(
            Some(12 * HOUR),
            Some("home"),
            Some("203.0.113.20"),
            vec![candidate(
                "cloudflare",
                &[ProviderEvidenceChannel::ResponseMetadata],
                &[],
            )],
        ),
    ];

    let host = aggregate_host("example.test", &rows, HostAggregationConfig::default());
    assert_eq!(host.current_basis, HostFreshnessBasis::TrailingWindow);
    assert_eq!(host.current_provider_set, vec!["cloudflare"]);
    assert_eq!(host.historical_provider_set, vec!["cloudflare", "fastly"]);
    assert_eq!(host.state, HostProviderState::SingleCurrentProvider);
}

#[test]
fn simultaneous_current_routes_preserve_multiple_provider_state() {
    let rows = vec![
        assessment(
            Some(10 * HOUR),
            Some("eu"),
            Some("192.0.2.10"),
            vec![candidate(
                "fastly",
                &[ProviderEvidenceChannel::RoutingCname],
                &[],
            )],
        ),
        assessment(
            Some(11 * HOUR),
            Some("us"),
            Some("192.0.2.20"),
            vec![candidate(
                "aws-cloudfront",
                &[ProviderEvidenceChannel::H2Transport],
                &[],
            )],
        ),
    ];

    let host = aggregate_host("example.test", &rows, HostAggregationConfig::default());
    assert_eq!(
        host.state,
        HostProviderState::MultipleCurrentProvidersOrPathSplit
    );
    assert_eq!(host.current_provider_set, vec!["aws-cloudfront", "fastly"]);
    assert_eq!(host.current_route_groups.len(), 2);
    assert!(host.current_route_groups.iter().any(|route| {
        route.endpoint.as_deref() == Some("192.0.2.10") && route.providers == vec!["fastly"]
    }));
    assert!(host.current_route_groups.iter().any(|route| {
        route.endpoint.as_deref() == Some("192.0.2.20") && route.providers == vec!["aws-cloudfront"]
    }));
}

#[test]
fn retries_in_one_route_bucket_do_not_become_independent_support() {
    let row = || {
        assessment(
            Some(20 * HOUR + 1000),
            Some("home"),
            Some("198.51.100.8"),
            vec![candidate(
                "cloudflare",
                &[ProviderEvidenceChannel::ResponseMetadata],
                &[],
            )],
        )
    };
    let rows = vec![row(), row(), row()];

    let host = aggregate_host("example.test", &rows, HostAggregationConfig::default());
    let membership = &host.current_memberships[0];
    assert_eq!(membership.current_independent_group_count, 1);
    assert_eq!(host.current_support_groups.len(), 1);
    assert_eq!(host.current_support_groups[0].raw_observations, 3);
    assert_eq!(host.current_route_groups.len(), 1);
    assert_eq!(host.current_route_groups[0].raw_observations, 3);
}

#[test]
fn historical_channel_can_corroborate_current_family_without_becoming_fresh() {
    let rows = vec![
        assessment(
            Some(HOUR),
            Some("home"),
            Some("203.0.113.1"),
            vec![candidate(
                "cloudflare",
                &[ProviderEvidenceChannel::H2Transport],
                &[],
            )],
        ),
        assessment(
            Some(20 * HOUR),
            Some("home"),
            Some("203.0.113.1"),
            vec![candidate(
                "cloudflare",
                &[ProviderEvidenceChannel::ResponseMetadata],
                &[],
            )],
        ),
    ];

    let host = aggregate_host("example.test", &rows, HostAggregationConfig::default());
    let membership = &host.current_memberships[0];
    assert_eq!(
        membership.support,
        HostProviderSupport::WithHistoricalCrossChannelCorroboration
    );
    assert_eq!(
        membership.current_originating_channels,
        vec![ProviderEvidenceChannel::ResponseMetadata]
    );
    assert_eq!(
        membership.historical_originating_channels,
        vec![
            ProviderEvidenceChannel::ResponseMetadata,
            ProviderEvidenceChannel::H2Transport,
        ]
    );
}

#[test]
fn fresh_cross_channel_evidence_is_reported_separately() {
    let rows = vec![assessment(
        Some(30 * HOUR),
        Some("home"),
        Some("203.0.113.1"),
        vec![candidate(
            "fastly",
            &[
                ProviderEvidenceChannel::RoutingCname,
                ProviderEvidenceChannel::H2Transport,
            ],
            &[],
        )],
    )];

    let host = aggregate_host("example.test", &rows, HostAggregationConfig::default());
    assert_eq!(
        host.current_memberships[0].support,
        HostProviderSupport::CrossChannelCorroborated
    );
}

#[test]
fn untimed_provider_evidence_is_current_only_when_no_timed_provider_evidence_exists() {
    let rows = vec![
        assessment(
            None,
            Some("archive"),
            Some("192.0.2.1"),
            vec![candidate(
                "fastly",
                &[ProviderEvidenceChannel::RoutingCname],
                &[],
            )],
        ),
        assessment(
            None,
            Some("archive"),
            Some("192.0.2.2"),
            vec![candidate(
                "cloudflare",
                &[ProviderEvidenceChannel::ResponseMetadata],
                &[],
            )],
        ),
    ];

    let host = aggregate_host("example.test", &rows, HostAggregationConfig::default());
    assert_eq!(host.current_basis, HostFreshnessBasis::UntimedEvidence);
    assert_eq!(host.current_provider_set, vec!["cloudflare", "fastly"]);
}

#[test]
fn untimed_evidence_cannot_override_timed_freshness() {
    let rows = vec![
        assessment(
            None,
            Some("archive"),
            Some("192.0.2.1"),
            vec![candidate(
                "fastly",
                &[ProviderEvidenceChannel::RoutingCname],
                &[],
            )],
        ),
        assessment(
            Some(50 * HOUR),
            Some("live"),
            Some("192.0.2.2"),
            vec![candidate(
                "cloudflare",
                &[ProviderEvidenceChannel::ResponseMetadata],
                &[],
            )],
        ),
    ];

    let host = aggregate_host("example.test", &rows, HostAggregationConfig::default());
    assert_eq!(host.current_basis, HostFreshnessBasis::TrailingWindow);
    assert_eq!(host.current_provider_set, vec!["cloudflare"]);
    assert_eq!(host.historical_provider_set, vec!["cloudflare", "fastly"]);
}

#[test]
fn no_provider_candidates_is_unresolved() {
    let rows = vec![assessment(Some(10 * HOUR), Some("home"), None, Vec::new())];
    let host = aggregate_host("example.test", &rows, HostAggregationConfig::default());
    assert_eq!(host.current_basis, HostFreshnessBasis::NoProviderEvidence);
    assert_eq!(host.state, HostProviderState::Unresolved);
    assert!(host.current_provider_set.is_empty());
    assert!(host.historical_provider_set.is_empty());
}

#[test]
fn protocol_is_part_of_independent_support_identity() {
    let mut h1 = assessment(
        Some(60 * HOUR + 1000),
        Some("home"),
        Some("198.51.100.9"),
        vec![candidate(
            "cloudflare",
            &[ProviderEvidenceChannel::ResponseMetadata],
            &[],
        )],
    );
    h1.protocol = Some("HTTP/1.1".into());
    let mut h2 = h1.clone();
    h2.protocol = Some("HTTP/2.0".into());

    let host = aggregate_host("example.test", &[h1, h2], HostAggregationConfig::default());
    assert_eq!(
        host.current_memberships[0].current_independent_group_count,
        2
    );
    assert_eq!(host.current_support_groups.len(), 2);
    assert_eq!(
        host.current_memberships[0].current_protocols,
        vec!["HTTP/1.1", "HTTP/2.0"]
    );
}

#[test]
fn tls_only_signal_cannot_originate_hostname_membership() {
    let rows = vec![tls_only_assessment(Some(10 * HOUR), "cloudflare")];
    let host = aggregate_host("example.test", &rows, HostAggregationConfig::default());
    assert_eq!(host.state, HostProviderState::Unresolved);
    assert!(host.current_provider_set.is_empty());
    assert!(host.historical_provider_set.is_empty());
    assert!(host.current_support_groups.is_empty());
    assert!(host.historical_support_groups.is_empty());
}

#[test]
fn separate_fresh_tls_observation_can_corroborate_current_provider() {
    let rows = vec![
        assessment(
            Some(10 * HOUR),
            Some("http"),
            Some("203.0.113.10"),
            vec![candidate(
                "cloudflare",
                &[ProviderEvidenceChannel::ResponseMetadata],
                &[],
            )],
        ),
        tls_only_assessment(Some(10 * HOUR + 1_000), "cloudflare"),
    ];
    let host = aggregate_host("example.test", &rows, HostAggregationConfig::default());
    let membership = &host.current_memberships[0];
    assert_eq!(
        membership.support,
        HostProviderSupport::CrossChannelCorroborated
    );
    assert_eq!(
        membership.current_corroborating_channels,
        vec![ProviderEvidenceChannel::TlsMorphology]
    );
    assert_eq!(membership.current_independent_group_count, 2);
}

#[test]
fn stale_tls_observation_is_historical_corroboration_only() {
    let rows = vec![
        tls_only_assessment(Some(HOUR), "cloudflare"),
        assessment(
            Some(20 * HOUR),
            Some("http"),
            Some("203.0.113.10"),
            vec![candidate(
                "cloudflare",
                &[ProviderEvidenceChannel::ResponseMetadata],
                &[],
            )],
        ),
    ];
    let host = aggregate_host("example.test", &rows, HostAggregationConfig::default());
    let membership = &host.current_memberships[0];
    assert_eq!(
        membership.support,
        HostProviderSupport::WithHistoricalCrossChannelCorroboration
    );
    assert!(membership.current_corroborating_channels.is_empty());
    assert_eq!(
        membership.historical_corroborating_channels,
        vec![ProviderEvidenceChannel::TlsMorphology]
    );
}

#[test]
fn tls_shape_for_other_provider_cannot_create_conflict() {
    let rows = vec![
        assessment(
            Some(10 * HOUR),
            Some("http"),
            Some("203.0.113.10"),
            vec![candidate(
                "cloudflare",
                &[ProviderEvidenceChannel::ResponseMetadata],
                &[],
            )],
        ),
        tls_only_assessment(Some(10 * HOUR + 1_000), "akamai"),
    ];
    let host = aggregate_host("example.test", &rows, HostAggregationConfig::default());
    assert_eq!(host.current_provider_set, vec!["cloudflare"]);
    assert_eq!(host.historical_provider_set, vec!["cloudflare"]);
    assert!(
        host.current_memberships[0]
            .current_corroborating_channels
            .is_empty()
    );
}
