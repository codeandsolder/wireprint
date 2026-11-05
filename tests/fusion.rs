use wireprint::{
    EndpointEvidence, PATH_CLASSIFIER_VERSION, PathElement, PathElementRole,
    ProviderEvidenceChannel, ProviderSignal, ProviderSupport, ROUTING_CLASSIFIER_VERSION,
    RoutingContext, TerminationState, assess_endpoint, detect_path_elements,
    detect_routing_elements as detect_routing_with_source,
};

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
