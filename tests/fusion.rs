use wireprint::{
    AddressFamily, DnsCnameLink, DnsProvenance, DnsRouteAnswer, EndpointEvidence,
    PATH_CLASSIFIER_VERSION, PathElement, PathElementRole, ProviderEvidenceChannel, ProviderSignal,
    ProviderSupport, ROUTING_CLASSIFIER_VERSION, RoutingContext, RoutingSnapshotBinding,
    TerminationState, assess_endpoint as assess_endpoint_core, detect_path_elements,
    detect_routing_elements as detect_routing_with_source,
};

// Existing synthetic fixtures explicitly posit a matched/verified DNS route.
// Live observations instead derive exact bound evidence from recorded A/AAAA RRs.
fn assess_endpoint(evidence: &EndpointEvidence) -> wireprint::EndpointAssessment {
    let mut verified = evidence.clone();
    if verified.routing_snapshot_binding == RoutingSnapshotBinding::Matched
        && verified.routing_bound_evidence.is_empty()
    {
        verified.routing_bound_evidence = verified
            .routing_elements
            .iter()
            .flat_map(|element| element.evidence.iter().cloned())
            .chain(
                verified
                    .provider_signals
                    .iter()
                    .filter(|signal| signal.channel == ProviderEvidenceChannel::RoutingDns)
                    .flat_map(|signal| signal.evidence.iter().cloned()),
            )
            .collect();
    }
    assess_endpoint_core(&verified)
}

// Synthetic CNAME-target fixture; production callers supply both sources.
fn detect_routing_elements(cname_targets: &[String]) -> Vec<PathElement> {
    detect_routing_with_source("customer.example.invalid", cname_targets)
}

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
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
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
            ProviderEvidenceChannel::RoutingDns,
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
            .any(|element| element.classifier == ROUTING_CLASSIFIER_VERSION)
    );
}

#[test]
fn railway_and_fly_routing_match_existing_response_provider_labels() {
    for (hostname, header_name, header_value, provider) in [
        (
            "utilities-us-east.up.railway.app",
            "x-railway-edge",
            "waw1",
            "railway",
        ),
        ("debug.fly.dev", "fly-request-id", "01M64WSK-fra", "fly-io"),
    ] {
        let response = detect_path_elements(&[wireprint::Header {
            name: header_name.into(),
            value: header_value.into(),
        }]);
        let routing = detect_routing_elements(&[hostname.into()]);
        let assessment = assess_endpoint(&EndpointEvidence {
            response_elements: response,
            routing_snapshot_binding: RoutingSnapshotBinding::Matched,
            routing_elements: routing,
            ..EndpointEvidence::default()
        });

        assert_eq!(assessment.state, TerminationState::SingleCandidate);
        assert_eq!(assessment.candidates.len(), 1);
        let candidate = &assessment.candidates[0];
        assert_eq!(candidate.provider, provider);
        assert_eq!(candidate.support, ProviderSupport::CrossChannelCorroborated);
        assert_eq!(
            candidate.originating_channels,
            vec![
                ProviderEvidenceChannel::ResponseMetadata,
                ProviderEvidenceChannel::RoutingDns,
            ]
        );
        assert!(assessment.path_elements.iter().any(|element| {
            element.role == PathElementRole::ApplicationPlatform && element.product == provider
        }));
    }
}

#[test]
fn managed_platform_routing_stays_non_originating() {
    for (hostname, product) in [
        ("example.onrender.com", "render"),
        ("whispering-willow-5678.herokudns.com", "heroku"),
        ("live-example.pantheonsite.io", "pantheon"),
        ("137828.hs-sites.com", "hubspot"),
        ("19490924.group24.sites.hubspot.net", "hubspot"),
        ("mysite.prod.acquia-sites.com", "acquia-cloud-platform"),
    ] {
        let assessment = assess_endpoint(&EndpointEvidence {
            routing_snapshot_binding: RoutingSnapshotBinding::Matched,
            routing_elements: detect_routing_elements(&[hostname.into()]),
            ..EndpointEvidence::default()
        });

        assert_eq!(assessment.state, TerminationState::Unresolved);
        assert!(assessment.candidates.is_empty());
        assert!(assessment.path_elements.iter().any(|element| {
            element.role == PathElementRole::ApplicationPlatform && element.product == product
        }));
    }

    let acquia = assess_endpoint(&EndpointEvidence {
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
        routing_elements: detect_routing_elements(&["mysite.prod.acquia-sites.com".into()]),
        ..EndpointEvidence::default()
    });
    assert!(acquia.path_elements.iter().any(|element| {
        element.role == PathElementRole::OriginService && element.product == "acquia-cloud-platform"
    }));
}

#[test]
fn routing_object_storage_origins_do_not_originate_termination_candidates() {
    for (hostname, product) in [
        ("c.storage.googleapis.com", "google-cloud-storage"),
        (
            "mystorageaccount.blob.core.windows.net",
            "azure-blob-storage",
        ),
        ("s3.us-west-004.backblazeb2.com", "backblaze-b2"),
        ("bucket.s3.us-west-2.amazonaws.com", "aws-s3"),
        ("baseball-nsu.akamaihd.net", "akamai-netstorage"),
        ("fra1.digitaloceanspaces.com", "digitalocean-spaces"),
        ("payload.fra1.digitaloceanspaces.com", "digitalocean-spaces"),
    ] {
        let assessment = assess_endpoint(&EndpointEvidence {
            routing_snapshot_binding: RoutingSnapshotBinding::Matched,
            routing_elements: detect_routing_elements(&[hostname.into()]),
            ..EndpointEvidence::default()
        });

        assert_eq!(assessment.state, TerminationState::Unresolved);
        assert!(assessment.candidates.is_empty());
        assert!(assessment.path_elements.iter().any(|element| {
            element.role == PathElementRole::OriginService && element.product == product
        }));
    }
}

#[test]
fn imgix_and_fastly_routing_preserve_layered_serving_candidates() {
    let routing = detect_routing_elements(&[
        "unsplash.imgix.net".into(),
        "dualstack.com.imgix.map.fastly.net".into(),
    ]);
    let assessment = assess_endpoint(&EndpointEvidence {
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
        routing_elements: routing,
        ..EndpointEvidence::default()
    });

    assert_eq!(assessment.state, TerminationState::MultipleCandidates);
    assert_eq!(
        assessment
            .candidates
            .iter()
            .map(|candidate| candidate.provider.as_str())
            .collect::<Vec<_>>(),
        vec!["fastly", "imgix"]
    );
}

#[test]
fn imgix_routing_can_originate_its_managed_edge() {
    let assessment = assess_endpoint(&EndpointEvidence {
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
        routing_elements: detect_routing_elements(&["axeptio.imgix.net".into()]),
        ..EndpointEvidence::default()
    });

    assert_eq!(assessment.state, TerminationState::SingleCandidate);
    assert_eq!(assessment.candidates.len(), 1);
    assert_eq!(assessment.candidates[0].provider, "imgix");
}

#[test]
fn cloudflare_edge_and_hubspot_platform_preserve_layered_roles() {
    let response = detect_path_elements(&[
        wireprint::Header {
            name: "server".into(),
            value: "cloudflare".into(),
        },
        wireprint::Header {
            name: "cf-ray".into(),
            value: "a545ed47b926b617-WAW".into(),
        },
    ]);
    let routing = detect_routing_elements(&["19490924.group24.sites.hubspot.net".into()]);
    let assessment = assess_endpoint(&EndpointEvidence {
        response_elements: response,
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
        routing_elements: routing,
        ..EndpointEvidence::default()
    });

    assert_eq!(assessment.state, TerminationState::SingleCandidate);
    assert_eq!(assessment.candidates.len(), 1);
    assert_eq!(assessment.candidates[0].provider, "cloudflare");
    assert!(assessment.path_elements.iter().any(|element| {
        element.role == PathElementRole::ApplicationPlatform && element.product == "hubspot"
    }));
}

#[test]
fn digitalocean_spaces_cdn_and_cloudflare_preserve_layered_serving_candidates() {
    let response = detect_path_elements(&[
        wireprint::Header {
            name: "server".into(),
            value: "cloudflare".into(),
        },
        wireprint::Header {
            name: "cf-ray".into(),
            value: "a545ed47b926b617-WAW".into(),
        },
    ]);
    let routing = detect_routing_elements(&["hopperhq.ams3.cdn.digitaloceanspaces.com".into()]);
    let assessment = assess_endpoint(&EndpointEvidence {
        response_elements: response,
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
        routing_elements: routing,
        ..EndpointEvidence::default()
    });

    assert_eq!(assessment.state, TerminationState::MultipleCandidates);
    assert_eq!(
        assessment
            .candidates
            .iter()
            .map(|candidate| candidate.provider.as_str())
            .collect::<Vec<_>>(),
        vec!["cloudflare", "digitalocean-spaces-cdn"]
    );
    assert!(assessment.path_elements.iter().any(|element| {
        element.role == PathElementRole::OriginService && element.product == "digitalocean-spaces"
    }));
}

#[test]
fn digitalocean_spaces_cdn_routing_can_originate_its_managed_edge() {
    let assessment = assess_endpoint(&EndpointEvidence {
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
        routing_elements: detect_routing_elements(&[
            "hopperhq.ams3.cdn.digitaloceanspaces.com".into()
        ]),
        ..EndpointEvidence::default()
    });

    assert_eq!(assessment.state, TerminationState::SingleCandidate);
    assert_eq!(assessment.candidates.len(), 1);
    assert_eq!(assessment.candidates[0].provider, "digitalocean-spaces-cdn");
    assert!(assessment.path_elements.iter().any(|element| {
        element.role == PathElementRole::OriginService && element.product == "digitalocean-spaces"
    }));
}

#[test]
fn akamai_edge_and_netstorage_origin_coexist_without_provider_conflict() {
    let assessment = assess_endpoint(&EndpointEvidence {
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
        routing_elements: detect_routing_elements(&[
            "media-example-a.akamaihd.net".into(),
            "baseball-nsu.akamaihd.net".into(),
        ]),
        ..EndpointEvidence::default()
    });

    assert_eq!(assessment.state, TerminationState::SingleCandidate);
    assert_eq!(assessment.candidates.len(), 1);
    assert_eq!(assessment.candidates[0].provider, "akamai");
    assert!(assessment.path_elements.iter().any(|element| {
        element.role == PathElementRole::OriginService && element.product == "akamai-netstorage"
    }));
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
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
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
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
        routing_elements: detect_routing_elements(&["teacher-glances-63085.netlify.com".into()]),
        ..EndpointEvidence::default()
    });

    assert_eq!(assessment.state, TerminationState::Unresolved);
    assert!(assessment.candidates.is_empty());
    assert!(assessment.path_elements.iter().any(|element| {
        element.role == PathElementRole::ApplicationPlatform && element.product == "netlify"
    }));
}

#[test]
fn vercel_and_netlify_ingress_routing_corroborates_response_metadata() {
    for (hostname, server, provider) in [
        ("d1d4fc829fe7bc7c.vercel-dns-017.com", "Vercel", "vercel"),
        ("my-project.netlify.app", "Netlify", "netlify"),
    ] {
        let response = detect_path_elements(&[wireprint::Header {
            name: "server".into(),
            value: server.into(),
        }]);
        let routing = detect_routing_elements(&[hostname.into()]);
        let assessment = assess_endpoint(&EndpointEvidence {
            response_elements: response,
            routing_snapshot_binding: RoutingSnapshotBinding::Matched,
            routing_elements: routing,
            ..EndpointEvidence::default()
        });

        assert_eq!(assessment.state, TerminationState::SingleCandidate);
        assert_eq!(assessment.candidates.len(), 1);
        let candidate = &assessment.candidates[0];
        assert_eq!(candidate.provider, provider);
        assert_eq!(candidate.support, ProviderSupport::CrossChannelCorroborated);
        assert_eq!(
            candidate.originating_channels,
            vec![
                ProviderEvidenceChannel::ResponseMetadata,
                ProviderEvidenceChannel::RoutingDns,
            ]
        );
    }
}

#[test]
fn azure_cdn_namespace_anchors_broad_edge_while_azure_ref_stays_participation_only() {
    let response = detect_path_elements(&[wireprint::Header {
        name: "x-azure-ref".into(),
        value: "20261029T230602Z-example".into(),
    }]);
    let routing = detect_routing_elements(&[
        "catalogartifact.azureedge.net".into(),
        "catalogartifact.afd.azureedge.net".into(),
        "azurefd-critical-t-prod.trafficmanager.net".into(),
        "shed.dual-low.part-0017.t-0009.t-msedge.net".into(),
        "part-0017.t-0009.t-msedge.net".into(),
    ]);
    let assessment = assess_endpoint(&EndpointEvidence {
        response_elements: response,
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
        routing_elements: routing,
        ..EndpointEvidence::default()
    });

    assert_eq!(assessment.state, TerminationState::SingleCandidate);
    assert_eq!(assessment.candidates.len(), 1);
    let candidate = &assessment.candidates[0];
    assert_eq!(candidate.provider, "azure-cloud-edge");
    assert_eq!(candidate.support, ProviderSupport::OriginatingEvidence);
    assert_eq!(
        candidate.originating_channels,
        vec![ProviderEvidenceChannel::RoutingDns]
    );
    assert!(assessment.path_elements.iter().any(|element| {
        element.role == PathElementRole::ApplicationPlatform
            && element.product == "azure-front-door"
    }));
}

#[test]
fn conflicting_originating_channels_are_preserved_as_multiple_candidates() {
    let assessment = assess_endpoint(&EndpointEvidence {
        response_elements: vec![provider_element("fastly")],
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
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

#[test]
fn cloudflare_edge_and_webflow_platform_preserve_layered_roles() {
    let response = detect_path_elements(&[
        wireprint::Header {
            name: "server".into(),
            value: "cloudflare".into(),
        },
        wireprint::Header {
            name: "cf-ray".into(),
            value: "a4f140517c85bfdf-WAW".into(),
        },
    ]);
    let routing = detect_routing_elements(&["cdn.webflow.com".into()]);
    let assessment = assess_endpoint(&EndpointEvidence {
        response_elements: response,
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
        routing_elements: routing,
        ..EndpointEvidence::default()
    });

    assert_eq!(assessment.state, TerminationState::SingleCandidate);
    assert_eq!(assessment.candidates.len(), 1);
    assert_eq!(assessment.candidates[0].provider, "cloudflare");
    assert!(assessment.path_elements.iter().any(|element| {
        element.role == PathElementRole::ApplicationPlatform && element.product == "webflow"
    }));
}

#[test]
fn webflow_routing_stays_non_originating() {
    let assessment = assess_endpoint(&EndpointEvidence {
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
        routing_elements: detect_routing_elements(&["my-project.webflow.io".into()]),
        ..EndpointEvidence::default()
    });

    assert_eq!(assessment.state, TerminationState::Unresolved);
    assert!(assessment.candidates.is_empty());
    assert!(assessment.path_elements.iter().any(|element| {
        element.role == PathElementRole::ApplicationPlatform && element.product == "webflow"
    }));
}

#[test]
fn cloudfront_edge_and_intercom_help_center_preserve_layered_roles() {
    let assessment = assess_endpoint(&EndpointEvidence {
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
        routing_elements: detect_routing_elements(&[
            "d21fzxmyf1hje3.cloudfront.net".into(),
            "custom.intercom.help".into(),
        ]),
        ..EndpointEvidence::default()
    });

    assert_eq!(assessment.state, TerminationState::SingleCandidate);
    assert_eq!(assessment.candidates.len(), 1);
    assert_eq!(assessment.candidates[0].provider, "aws-cloudfront");
    assert!(assessment.path_elements.iter().any(|element| {
        element.role == PathElementRole::ApplicationPlatform && element.product == "intercom"
    }));
}

#[test]
fn cloudflare_edge_and_shopify_platform_preserve_layered_roles() {
    let response = detect_path_elements(&[
        wireprint::Header {
            name: "server".into(),
            value: "cloudflare".into(),
        },
        wireprint::Header {
            name: "cf-ray".into(),
            value: "a4f140517c85bfdf-WAW".into(),
        },
    ]);
    let routing = detect_routing_elements(&["shops.myshopify.com".into()]);
    let assessment = assess_endpoint(&EndpointEvidence {
        response_elements: response,
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
        routing_elements: routing,
        ..EndpointEvidence::default()
    });

    assert_eq!(assessment.state, TerminationState::SingleCandidate);
    assert_eq!(assessment.candidates.len(), 1);
    assert_eq!(assessment.candidates[0].provider, "cloudflare");
    assert!(assessment.path_elements.iter().any(|element| {
        element.role == PathElementRole::ApplicationPlatform && element.product == "shopify"
    }));
}

#[test]
fn shopify_routing_stays_non_originating() {
    let assessment = assess_endpoint(&EndpointEvidence {
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
        routing_elements: detect_routing_elements(&["example-store.myshopify.com".into()]),
        ..EndpointEvidence::default()
    });

    assert_eq!(assessment.state, TerminationState::Unresolved);
    assert!(assessment.candidates.is_empty());
    assert!(assessment.path_elements.iter().any(|element| {
        element.role == PathElementRole::ApplicationPlatform && element.product == "shopify"
    }));
}

#[test]
fn intercom_help_center_routing_stays_non_originating() {
    let assessment = assess_endpoint(&EndpointEvidence {
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
        routing_elements: detect_routing_elements(&["custom.intercom.help".into()]),
        ..EndpointEvidence::default()
    });

    assert_eq!(assessment.state, TerminationState::Unresolved);
    assert!(assessment.candidates.is_empty());
    assert!(assessment.path_elements.iter().any(|element| {
        element.role == PathElementRole::ApplicationPlatform && element.product == "intercom"
    }));
}

#[test]
fn direct_host_and_cname_provenance_survive_fusion_without_false_extra_channels() {
    let elements = detect_routing_with_source(
        "site.cdn.cloudflare.net",
        &["site.cdn.cloudflare.net".into()],
    );
    let assessment = assess_endpoint(&EndpointEvidence {
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
        routing_elements: elements,
        ..EndpointEvidence::default()
    });
    assert_eq!(assessment.state, TerminationState::SingleCandidate);
    assert_eq!(assessment.candidates.len(), 1);
    assert_eq!(
        assessment.candidates[0].originating_channels,
        [ProviderEvidenceChannel::RoutingDns]
    );
    assert_eq!(
        assessment.candidates[0].support,
        ProviderSupport::OriginatingEvidence
    );
    assert_eq!(
        assessment.candidates[0].evidence,
        [
            "cname:site.cdn.cloudflare.net",
            "host:site.cdn.cloudflare.net"
        ]
    );
}

#[test]
fn routing_dns_channel_serializes_without_mislabeling_direct_host_as_cname() {
    assert_eq!(
        serde_json::to_value(ProviderEvidenceChannel::RoutingDns).ok(),
        Some(serde_json::json!("routing_dns"))
    );
}

#[test]
fn zendesk_cname_and_cloudflare_response_preserve_downstream_role() {
    let response = detect_path_elements(&[wireprint::Header {
        name: "cf-ray".into(),
        value: "a557c23d690645c1-WAW".into(),
    }]);
    let assessment = assess_endpoint(&EndpointEvidence {
        response_elements: response,
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
        routing_elements: detect_routing_with_source(
            "help.coda.io",
            &["coda-docs.zendesk.com".into()],
        ),
        ..EndpointEvidence::default()
    });
    assert_eq!(assessment.state, TerminationState::SingleCandidate);
    assert_eq!(assessment.candidates.len(), 1);
    assert_eq!(assessment.candidates[0].provider, "cloudflare");
    assert!(assessment.path_elements.iter().any(|element| {
        element.role == PathElementRole::ApplicationPlatform
            && element.product == "zendesk"
            && element.evidence == ["cname:coda-docs.zendesk.com"]
    }));
}

#[test]
fn freshdesk_cname_and_cloudflare_response_do_not_merge_layers() {
    let response = detect_path_elements(&[wireprint::Header {
        name: "cf-ray".into(),
        value: "a557e28fba359d13-WAW".into(),
    }]);
    let assessment = assess_endpoint(&EndpointEvidence {
        response_elements: response,
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
        routing_elements: detect_routing_with_source(
            "helpline.cdlib.org",
            &["584fd6f03d18689f8f63743ad3a71133.freshdesk.com".into()],
        ),
        ..EndpointEvidence::default()
    });
    assert_eq!(assessment.state, TerminationState::SingleCandidate);
    assert_eq!(assessment.candidates.len(), 1);
    assert_eq!(assessment.candidates[0].provider, "cloudflare");
    assert!(assessment.path_elements.iter().any(|element| {
        element.role == PathElementRole::ApplicationPlatform
            && element.product == "freshdesk"
            && element.evidence == ["cname:584fd6f03d18689f8f63743ad3a71133.freshdesk.com"]
    }));
}

fn routing_snapshot(addresses: &[&str], error: Option<&str>) -> DnsProvenance {
    let chain = vec![
        "www.pinterest.com".to_owned(),
        "www-pinterest-com.gslb.pinterest.com".to_owned(),
        "www.gslb2.pinterest.net".to_owned(),
        "prod.pinterest.global.map.fastly.net".to_owned(),
    ];
    let mut owner = "ct.pinterest.com".to_owned();
    let links = chain
        .iter()
        .map(|target| {
            let link = DnsCnameLink {
                owner: owner.clone(),
                target: target.clone(),
            };
            owner = target.clone();
            link
        })
        .collect::<Vec<_>>();
    let ips = addresses
        .iter()
        .map(|ip| (*ip).to_owned())
        .collect::<Vec<_>>();
    let family = if addresses.first().is_some_and(|ip| ip.contains(':')) {
        AddressFamily::Ipv6
    } else {
        AddressFamily::Ipv4
    };
    DnsProvenance {
        classifier: "builtin-dns-v2".into(),
        host: "ct.pinterest.com".into(),
        connection_candidates: vec!["23.197.161.35".into()],
        connection_resolution_unix_ms: Some(1793881734257),
        connection_resolution_reused: false,
        routing_answers: vec![DnsRouteAnswer {
            family,
            linked_ips: if error.is_none() {
                ips.clone()
            } else {
                Vec::new()
            },
            ips,
            cname_chain: chain,
            cname_links: links,
            error: error.map(str::to_owned),
        }],
        routing_snapshot_unix_ms: Some(1793881734130),
        routing_snapshot_error: error.map(str::to_owned),
    }
}

#[test]
fn parallel_dns_snapshot_divergence_is_not_a_second_termination_candidate() {
    // Exact endpoint/CNAME mismatch observed on Asus on 2026-11-05.
    let dns = routing_snapshot(
        &[
            "151.101.0.84",
            "151.101.64.84",
            "151.101.128.84",
            "151.101.192.84",
        ],
        None,
    );
    let binding = dns.routing_snapshot_binding(Some("23.197.161.35"));
    assert_eq!(binding, RoutingSnapshotBinding::Divergent);
    let assessment = assess_endpoint(&EndpointEvidence {
        selected_endpoint: Some("23.197.161.35".into()),
        actual_peer: Some("23.197.161.35:443".into()),
        routing_snapshot_binding: binding,
        response_elements: vec![provider_element("akamai")],
        routing_elements: wireprint::detect_routing_snapshot_elements(&dns),
        provider_signals: vec![signal("akamai", ProviderEvidenceChannel::H2Transport)],
        ..EndpointEvidence::default()
    });
    assert_eq!(assessment.state, TerminationState::SingleCandidate);
    assert_eq!(assessment.candidates.len(), 1);
    assert_eq!(assessment.candidates[0].provider, "akamai");
    assert_eq!(
        assessment.candidates[0].support,
        ProviderSupport::CrossChannelCorroborated
    );
    assert_eq!(
        assessment.candidates[0].originating_channels,
        [
            ProviderEvidenceChannel::ResponseMetadata,
            ProviderEvidenceChannel::H2Transport
        ]
    );
    assert_eq!(
        assessment.routing_snapshot_binding,
        RoutingSnapshotBinding::Divergent
    );
    assert!(assessment.path_elements.iter().any(|e| {
        e.role == PathElementRole::EdgeProvider
            && e.product == "fastly"
            && e.evidence
                .contains(&"cname:prod.pinterest.global.map.fastly.net".into())
    }));
    assert_eq!(
        serde_json::to_value(&assessment).expect("serialize assessment")["routing_snapshot_binding"],
        "divergent"
    );
}

#[test]
fn matching_dns_snapshot_can_corrobate_serving_route() {
    let dns = routing_snapshot(&["151.101.128.84", "151.101.0.84"], None);
    let binding = dns.routing_snapshot_binding(Some("151.101.128.84"));
    assert_eq!(binding, RoutingSnapshotBinding::Matched);
    let assessment = assess_endpoint(&EndpointEvidence {
        selected_endpoint: Some("151.101.128.84".into()),
        routing_snapshot_binding: binding,
        routing_elements: wireprint::detect_routing_snapshot_elements(&dns),
        provider_signals: vec![signal("fastly", ProviderEvidenceChannel::H2Transport)],
        ..EndpointEvidence::default()
    });
    assert_eq!(assessment.state, TerminationState::SingleCandidate);
    assert_eq!(assessment.candidates[0].provider, "fastly");
    assert_eq!(
        assessment.candidates[0].support,
        ProviderSupport::CrossChannelCorroborated
    );
    assert_eq!(
        assessment.candidates[0].originating_channels,
        [
            ProviderEvidenceChannel::RoutingDns,
            ProviderEvidenceChannel::H2Transport
        ]
    );
}

#[test]
fn dns_snapshot_binding_is_safe_across_missing_peer_error_and_address_families() {
    let dns = routing_snapshot(&["151.101.0.84"], None);
    assert_eq!(
        dns.routing_snapshot_binding(None),
        RoutingSnapshotBinding::Unverified
    );
    assert_eq!(
        dns.routing_snapshot_binding(Some("not an IP")),
        RoutingSnapshotBinding::Unverified
    );
    assert_eq!(
        dns.routing_snapshot_binding(Some("151.101.0.84")),
        RoutingSnapshotBinding::Matched
    );
    assert_eq!(
        dns.routing_snapshot_binding(Some("23.197.161.35")),
        RoutingSnapshotBinding::Divergent
    );
    assert_eq!(
        routing_snapshot(&[], None).routing_snapshot_binding(Some("23.197.161.35")),
        RoutingSnapshotBinding::Unverified
    );
    assert_eq!(
        routing_snapshot(&["23.197.161.35"], Some("resolver failed"))
            .routing_snapshot_binding(Some("23.197.161.35")),
        RoutingSnapshotBinding::Unverified
    );
    assert_eq!(
        routing_snapshot(&["not-an-ip"], None).routing_snapshot_binding(Some("23.197.161.35")),
        RoutingSnapshotBinding::Unverified
    );
    let v6 = routing_snapshot(&["2a06:98c1:3108::ac40:99cd"], None);
    assert_eq!(
        v6.routing_snapshot_binding(Some("2a06:98c1:3108::ac40:99cd")),
        RoutingSnapshotBinding::Matched
    );
    assert_eq!(
        v6.routing_snapshot_binding(Some("2600:9000:290c:fa00:19:7d10:bd80:93a1")),
        RoutingSnapshotBinding::Divergent
    );
}

#[test]
fn unknown_dns_binding_keeps_route_evidence_but_never_votes_termination() {
    let routing = detect_routing_with_source(
        "d123.cloudfront.net",
        &["prod.pinterest.global.map.fastly.net".into()],
    );
    for binding in [
        RoutingSnapshotBinding::Divergent,
        RoutingSnapshotBinding::Unverified,
    ] {
        let assessment = assess_endpoint(&EndpointEvidence {
            routing_snapshot_binding: binding,
            routing_elements: routing.clone(),
            provider_signals: vec![signal("fastly", ProviderEvidenceChannel::RoutingDns)],
            ..EndpointEvidence::default()
        });
        assert_eq!(assessment.state, TerminationState::Unresolved);
        assert!(assessment.candidates.is_empty());
        assert!(assessment.path_elements.iter().any(|e| {
            e.product == "aws-cloudfront" && e.evidence == ["host:d123.cloudfront.net"]
        }));
        assert!(assessment.path_elements.iter().any(|e| {
            e.product == "fastly" && e.evidence == ["cname:prod.pinterest.global.map.fastly.net"]
        }));
    }
    let assessment = assess_endpoint(&EndpointEvidence {
        routing_snapshot_binding: RoutingSnapshotBinding::Matched,
        routing_elements: routing,
        ..EndpointEvidence::default()
    });
    assert_eq!(assessment.state, TerminationState::MultipleCandidates);
}

#[test]
fn real_asus_pinterest_observations_replay_endpoint_binding_end_to_end() {
    for (raw, binding, provider) in [
        (
            include_str!("fixtures/pinterest-snapshot-divergent.json"),
            RoutingSnapshotBinding::Divergent,
            "akamai",
        ),
        (
            include_str!("fixtures/pinterest-snapshot-matched.json"),
            RoutingSnapshotBinding::Matched,
            "fastly",
        ),
    ] {
        let observation: wireprint::Observation =
            serde_json::from_str(raw).expect("valid captured observation");
        let evidence = EndpointEvidence::from(&observation);
        assert_eq!(evidence.routing_snapshot_binding, binding);
        let assessment = assess_endpoint_core(&evidence);
        assert_eq!(assessment.state, TerminationState::SingleCandidate);
        assert_eq!(assessment.candidates.len(), 1);
        assert_eq!(assessment.candidates[0].provider, provider);
        assert_eq!(assessment.routing_snapshot_binding, binding);
        assert_eq!(assessment.classifier, wireprint::ENDPOINT_FUSION_VERSION);
    }
}

#[test]
fn captured_stripe_mixed_union_legacy_snapshot_cannot_vote_for_cloudfront() {
    // Real Acer IPv4 Wreq capture on 2026-11-07: Fastly peer and H2
    // response, but old Hickory combined an unrelated CloudFront AAAA alias.
    // The old *ungrouped* format cannot prove any DNS CNAME-to-peer binding.
    let observation: wireprint::Observation =
        serde_json::from_str(include_str!("fixtures/stripe-mixed-union-legacy.json"))
            .expect("real legacy Stripe observation");
    assert!(
        observation
            .dns
            .as_ref()
            .expect("DNS")
            .routing_answers
            .is_empty()
    );
    let evidence = EndpointEvidence::from(&observation);
    assert_eq!(
        evidence.routing_snapshot_binding,
        RoutingSnapshotBinding::Unverified
    );
    assert!(evidence.routing_bound_evidence.is_empty());
    let assessment = assess_endpoint_core(&evidence);
    assert_eq!(assessment.state, TerminationState::SingleCandidate);
    assert_eq!(assessment.candidates.len(), 1);
    assert_eq!(assessment.candidates[0].provider, "fastly");
    assert_eq!(
        assessment.candidates[0].support,
        ProviderSupport::CrossChannelCorroborated
    );
    assert!(
        assessment
            .path_elements
            .iter()
            .any(|element| element.product == "aws-cloudfront"
                && element.evidence == ["cname:d1tcqh4bio8cty.cloudfront.net"])
    );
}
