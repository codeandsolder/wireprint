use wireprint::{Header, PathElement, PathElementRole, detect_path_elements};

fn header(name: &str, value: &str) -> Header {
    Header {
        name: name.into(),
        value: value.into(),
    }
}

fn has(elements: &[PathElement], role: PathElementRole, product: &str) -> bool {
    elements
        .iter()
        .any(|element| element.role == role && element.product == product)
}

#[test]
fn downstream_platform_headers_do_not_become_outer_provider_claims() {
    let elements = detect_path_elements(&[
        header("x-vercel-id", "fra1::abc"),
        header("x-azure-ref", "20261021T000000Z-abc"),
    ]);

    assert!(has(
        &elements,
        PathElementRole::ApplicationPlatform,
        "vercel"
    ));
    assert!(has(
        &elements,
        PathElementRole::ApplicationPlatform,
        "azure-front-door"
    ));
    assert!(
        !elements
            .iter()
            .any(|element| element.role == PathElementRole::EdgeProvider)
    );
}

#[test]
fn barracuda_capture_keeps_azure_front_door_as_platform_only() {
    let elements = detect_path_elements(&[
        header("x-served-by", "cache-lcy-eglc8600044-LCY"),
        header("x-cache", "TCP_REMOTE_HIT"),
        header(
            "x-azure-ref",
            "20261009T171503Z-r1d9499f5f895ks5hC1WAWmgs40000001heg00000000tfsr",
        ),
    ]);

    assert!(has(
        &elements,
        PathElementRole::ApplicationPlatform,
        "azure-front-door"
    ));
    assert!(!elements.iter().any(|element| element.product == "fastly"));
    assert!(
        !elements
            .iter()
            .any(|element| element.role == PathElementRole::EdgeProvider)
    );
}

#[test]
fn generic_cache_vocabulary_does_not_imply_fastly() {
    let elements = detect_path_elements(&[
        header("x-served-by", "cache-fra-eddf8230134-FRA"),
        header("x-cache", "HIT"),
    ]);

    assert!(!elements.iter().any(|element| element.product == "fastly"));
}

#[test]
fn multi_layer_datadome_varnish_fastly_response_is_preserved() {
    let elements = detect_path_elements(&[
        header("server", "DataDome"),
        header("via", "1.1 varnish"),
        header("x-fastly-backend-reqs", "10"),
        header(
            "set-cookie",
            "datadome=opaque; Max-Age=31536000; Domain=.example.com; Path=/; Secure",
        ),
    ]);

    assert!(has(&elements, PathElementRole::BotManagement, "datadome"));
    assert!(has(&elements, PathElementRole::Cache, "varnish"));
    assert!(has(&elements, PathElementRole::Cache, "fastly"));
    assert!(!has(&elements, PathElementRole::EdgeProvider, "fastly"));
}

#[test]
fn aws_api_gateway_and_application_load_balancer_are_separate_elements() {
    let elements = detect_path_elements(&[
        header("x-amz-apigw-id", "abc123="),
        header("set-cookie", "AWSALB=opaque; Path=/; SameSite=None; Secure"),
    ]);

    assert!(has(
        &elements,
        PathElementRole::ApiGateway,
        "aws-api-gateway"
    ));
    assert!(has(
        &elements,
        PathElementRole::LoadBalancer,
        "aws-application-load-balancer"
    ));
}

#[test]
fn f5_ltm_and_asm_cookie_markers_are_distinct() {
    let elements = detect_path_elements(&[
        header("set-cookie", "BIGipServerpayments=opaque; Path=/"),
        header("set-cookie", "TS01e598a2=opaque; Path=/; Secure"),
    ]);

    assert!(has(
        &elements,
        PathElementRole::LoadBalancer,
        "f5-big-ip-ltm"
    ));
    assert!(has(&elements, PathElementRole::Waf, "f5-big-ip-asm"));
}

#[test]
fn cloudflare_can_contribute_four_distinct_path_roles() {
    let elements = detect_path_elements(&[
        header("server", "cloudflare"),
        header("cf-ray", "abc-FRA"),
        header("set-cookie", "__cf_bm=opaque; Path=/; Secure"),
        header("set-cookie", "__cflb=opaque; Path=/; Secure"),
        header("set-cookie", "cf_clearance=opaque; Path=/; Secure"),
    ]);

    assert!(has(&elements, PathElementRole::EdgeProvider, "cloudflare"));
    assert!(has(
        &elements,
        PathElementRole::BotManagement,
        "cloudflare-bot-management"
    ));
    assert!(has(
        &elements,
        PathElementRole::LoadBalancer,
        "cloudflare-load-balancer"
    ));
    assert!(has(
        &elements,
        PathElementRole::SecurityMiddleware,
        "cloudflare-security"
    ));
}

#[test]
fn kong_and_envoy_can_coexist() {
    let elements = detect_path_elements(&[
        header("via", "kong/3.8.0"),
        header("x-kong-proxy-latency", "2"),
        header("x-envoy-upstream-service-time", "4"),
    ]);

    assert!(has(&elements, PathElementRole::ApiGateway, "kong"));
    assert!(has(&elements, PathElementRole::ReverseProxy, "envoy"));
}

#[test]
fn azure_application_gateway_affinity_cookie_is_load_balancer_evidence() {
    let elements = detect_path_elements(&[header(
        "set-cookie",
        "ApplicationGatewayAffinity=opaque; Path=/",
    )]);

    assert!(has(
        &elements,
        PathElementRole::LoadBalancer,
        "azure-application-gateway"
    ));
}

#[test]
fn generic_aws_request_id_does_not_imply_api_gateway() {
    let elements = detect_path_elements(&[header("x-amzn-requestid", "abc")]);
    assert!(!has(
        &elements,
        PathElementRole::ApiGateway,
        "aws-api-gateway"
    ));
}

#[test]
fn google_via_is_application_load_balancer_participation() {
    let elements = detect_path_elements(&[header("via", "1.1 google, 1.1 varnish")]);
    assert!(has(
        &elements,
        PathElementRole::LoadBalancer,
        "google-cloud-application-load-balancer"
    ));
    assert!(has(&elements, PathElementRole::Cache, "varnish"));
}

#[test]
fn netscaler_persistence_cookie_is_load_balancer_evidence() {
    let elements = detect_path_elements(&[header(
        "set-cookie",
        "NSC_abcd=ffffffff09a0aa0a45525d5f4f58455e445a4a423660; path=/; HttpOnly",
    )]);
    assert!(has(
        &elements,
        PathElementRole::LoadBalancer,
        "netscaler-adc"
    ));
}

#[test]
fn squid_via_and_error_headers_identify_cache_participation() {
    let elements = detect_path_elements(&[
        header("via", "1.1 proxy.example (squid/6.10)"),
        header("x-squid-error", "ERR_ACCESS_DENIED 0"),
    ]);
    assert!(has(&elements, PathElementRole::Cache, "squid"));
}

#[test]
fn fortiweb_session_cookie_is_waf_evidence() {
    let elements = detect_path_elements(&[header(
        "set-cookie",
        "cookiesession1=K8BXT3TNYUM710UEGWC8IQBTPX9PRWHB; path=/; HttpOnly",
    )]);
    assert!(has(&elements, PathElementRole::Waf, "fortiweb"));
}

#[test]
fn fastly_artisanal_bits_is_edge_but_akamai_netstorage_is_origin() {
    let fastly = detect_path_elements(&[header("server", "Artisanal bits")]);
    assert!(has(&fastly, PathElementRole::EdgeProvider, "fastly"));

    let akamai = detect_path_elements(&[header("server", "AkamaiNetStorage")]);
    assert!(has(
        &akamai,
        PathElementRole::OriginService,
        "akamai-netstorage"
    ));
    assert!(!has(&akamai, PathElementRole::EdgeProvider, "akamai"));
}

#[test]
fn common_server_implementations_are_not_promoted_to_edge_providers() {
    for (server, product) in [
        ("Apache/2.4.65", "apache-http-server"),
        ("Microsoft-IIS/10.0", "microsoft-iis"),
        ("LiteSpeed", "litespeed"),
        ("sffe", "sffe"),
        ("GSE", "gse"),
    ] {
        let elements = detect_path_elements(&[header("server", server)]);
        assert!(has(
            &elements,
            PathElementRole::ServerImplementation,
            product
        ));
        assert!(
            !elements
                .iter()
                .any(|element| element.role == PathElementRole::EdgeProvider)
        );
    }
}

#[test]
fn kong_request_id_alone_is_gateway_evidence() {
    let elements = detect_path_elements(&[header("x-kong-request-id", "8d4d0e93")]);
    assert!(has(&elements, PathElementRole::ApiGateway, "kong"));
}

#[test]
fn platform_request_ids_do_not_become_origin_server_claims() {
    let elements = detect_path_elements(&[
        header("rndr-id", "abc123"),
        header("x-railway-upstream-zone", "railway/europe-west4-drams3a"),
    ]);
    assert!(has(
        &elements,
        PathElementRole::ApplicationPlatform,
        "render"
    ));
    assert!(has(
        &elements,
        PathElementRole::ApplicationPlatform,
        "railway"
    ));
    assert!(
        !elements
            .iter()
            .any(|element| element.role == PathElementRole::ServerImplementation)
    );
}

#[test]
fn fly_response_markers_are_edge_participation_evidence() {
    let elements = detect_path_elements(&[
        header("server", "Fly/1782112b (2025-01-09)"),
        header("via", "2 fly.io"),
        header("fly-request-id", "01JHNX6S1BW8JVCCYG28CGQBWN-chi"),
    ]);
    assert!(has(&elements, PathElementRole::EdgeProvider, "fly-io"));
}

#[test]
fn fastly_specific_cache_headers_do_not_claim_outer_edge() {
    for name in ["fastly-debug-path", "fastly-debug-ttl", "fastly-restarts"] {
        let elements = detect_path_elements(&[header(name, "1")]);
        assert!(has(&elements, PathElementRole::Cache, "fastly"));
        assert!(!has(&elements, PathElementRole::EdgeProvider, "fastly"));
    }
}

#[test]
fn generic_x_cache_hits_does_not_imply_fastly() {
    let elements = detect_path_elements(&[header("x-cache-hits", "17")]);
    assert!(!elements.iter().any(|element| element.product == "fastly"));
}

#[test]
fn bunny_cache_metadata_can_survive_without_bunny_server_banner() {
    let elements = detect_path_elements(&[
        header("cdn-pullzone", "876725"),
        header("cdn-requestid", "6270904e7bf6eea7f431a0d81482c168"),
    ]);
    assert!(has(&elements, PathElementRole::Cache, "bunnycdn"));
    assert!(!has(&elements, PathElementRole::EdgeProvider, "bunnycdn"));
}

#[test]
fn google_frontend_banner_is_google_edge_evidence() {
    let elements = detect_path_elements(&[header("server", "Google Frontend")]);
    assert!(has(&elements, PathElementRole::EdgeProvider, "google-gfe"));
}

#[test]
fn railway_separates_entry_edge_from_upstream_zone() {
    let elements = detect_path_elements(&[
        header("x-railway-edge", "fra1"),
        header("x-railway-upstream-zone", "railway/europe-west4-drams3a"),
    ]);
    assert!(has(&elements, PathElementRole::EdgeProvider, "railway"));
    assert!(has(
        &elements,
        PathElementRole::ApplicationPlatform,
        "railway"
    ));
}

#[test]
fn gateway_products_use_product_specific_response_markers() {
    for (headers, product) in [
        (vec![header("server", "APISIX/3.16.0")], "apache-apisix"),
        (vec![header("x-krakend-completed", "true")], "krakend"),
        (vec![header("x-tyk-cached-response", "1")], "tyk"),
    ] {
        let elements = detect_path_elements(&headers);
        assert!(has(&elements, PathElementRole::ApiGateway, product));
    }
}

#[test]
fn linkerd_proxy_error_is_mesh_participation() {
    let elements = detect_path_elements(&[header(
        "l5d-proxy-error",
        "logical service example:80: service in fail-fast",
    )]);
    assert!(has(&elements, PathElementRole::ServiceMesh, "linkerd"));
}

#[test]
fn akamai_bm_sv_is_bot_manager_evidence() {
    let elements = detect_path_elements(&[header("set-cookie", "bm_sv=opaque; path=/; secure")]);
    assert!(has(
        &elements,
        PathElementRole::BotManagement,
        "akamai-bot-manager"
    ));
}

#[test]
fn s3_compatible_origin_can_be_preserved_behind_fastly_without_claiming_aws() {
    let elements = detect_path_elements(&[
        header("server", "Fastly"),
        header("x-amz-bucket-region", "us-east-1"),
    ]);
    assert!(has(
        &elements,
        PathElementRole::OriginService,
        "s3-compatible-object-storage"
    ));
    assert!(!has(&elements, PathElementRole::OriginService, "aws-s3"));
    assert!(has(&elements, PathElementRole::EdgeProvider, "fastly"));
}

#[test]
fn amazon_s3_requires_an_aws_specific_server_marker() {
    let elements = detect_path_elements(&[header("server", "AmazonS3")]);
    assert!(has(&elements, PathElementRole::OriginService, "aws-s3"));
}

#[test]
fn uploadserver_is_implementation_not_gfe_or_gcs_by_itself() {
    let elements = detect_path_elements(&[header("server", "UploadServer")]);
    assert!(has(
        &elements,
        PathElementRole::ServerImplementation,
        "google-uploadserver"
    ));
    assert!(!has(&elements, PathElementRole::EdgeProvider, "google-gfe"));
    assert!(!has(
        &elements,
        PathElementRole::OriginService,
        "google-cloud-storage"
    ));
}

#[test]
fn storage_origins_use_service_specific_response_metadata() {
    for (headers, product) in [
        (
            vec![header("x-goog-storage-class", "STANDARD")],
            "google-cloud-storage",
        ),
        (
            vec![header("x-ms-blob-type", "BlockBlob")],
            "azure-blob-storage",
        ),
        (vec![header("x-bz-file-id", "4_zopaque")], "backblaze-b2"),
    ] {
        let elements = detect_path_elements(&headers);
        assert!(has(&elements, PathElementRole::OriginService, product));
    }
}

#[test]
fn documented_platform_markers_can_coexist_with_outer_edges() {
    let elements = detect_path_elements(&[
        header("server", "cloudflare"),
        header("x-pantheon-styx-hostname", "styx-fe1-a"),
        header("x-ah-environment", "prod"),
        header("via", "1.1 vegur, 1.1 opaque.cloudfront.net (CloudFront)"),
    ]);
    assert!(has(&elements, PathElementRole::EdgeProvider, "cloudflare"));
    assert!(has(
        &elements,
        PathElementRole::EdgeProvider,
        "aws-cloudfront"
    ));
    assert!(has(
        &elements,
        PathElementRole::ApplicationPlatform,
        "pantheon"
    ));
    assert!(has(
        &elements,
        PathElementRole::ApplicationPlatform,
        "acquia-cloud-platform"
    ));
    assert!(has(
        &elements,
        PathElementRole::ApplicationPlatform,
        "heroku"
    ));
}

#[test]
fn gravitee_and_tyk_use_documented_gateway_markers() {
    let gravitee = detect_path_elements(&[header("x-gravitee-request-id", "opaque")]);
    assert!(has(&gravitee, PathElementRole::ApiGateway, "gravitee"));

    let tyk = detect_path_elements(&[header("x-generator", "tyk.io")]);
    assert!(has(&tyk, PathElementRole::ApiGateway, "tyk"));
}

#[test]
fn aws_waf_token_cookie_is_waf_participation() {
    let elements =
        detect_path_elements(&[header("set-cookie", "aws-waf-token=opaque; Path=/; Secure")]);
    assert!(has(&elements, PathElementRole::Waf, "aws-waf"));
}

#[test]
fn explicit_cdn_cache_markers_stay_separate_from_edge_identity() {
    for (headers, product) in [
        (vec![header("cf-cache-status", "HIT")], "cloudflare"),
        (vec![header("x-qc-cache", "hit")], "quic-cloud"),
        (vec![header("x-sucuri-cache", "HIT")], "sucuri"),
        (vec![header("x-vercel-cache", "HIT")], "vercel"),
    ] {
        let elements = detect_path_elements(&headers);
        assert!(has(&elements, PathElementRole::Cache, product));
    }

    let cloudflare = detect_path_elements(&[header("cf-cache-status", "HIT")]);
    assert!(!has(
        &cloudflare,
        PathElementRole::EdgeProvider,
        "cloudflare"
    ));
    let quic = detect_path_elements(&[header("x-qc-cache", "hit")]);
    assert!(!has(&quic, PathElementRole::EdgeProvider, "quic-cloud"));
}

#[test]
fn keycdn_and_quic_cloud_use_product_specific_edge_markers() {
    let keycdn = detect_path_elements(&[
        header("server", "keycdn-engine"),
        header("x-cache", "HIT"),
        header("x-edge-location", "defr"),
    ]);
    assert!(has(&keycdn, PathElementRole::EdgeProvider, "keycdn"));
    assert!(has(&keycdn, PathElementRole::Cache, "keycdn"));

    let quic = detect_path_elements(&[header("x-qc-pop", "USDFW1"), header("x-qc-cache", "hit")]);
    assert!(has(&quic, PathElementRole::EdgeProvider, "quic-cloud"));
    assert!(has(&quic, PathElementRole::Cache, "quic-cloud"));
}

#[test]
fn google_load_balancer_generated_affinity_cookies_are_explicit() {
    for cookie in ["GCLB=opaque; Path=/", "GCILB=opaque; Path=/"] {
        let elements = detect_path_elements(&[header("set-cookie", cookie)]);
        assert!(has(
            &elements,
            PathElementRole::LoadBalancer,
            "google-cloud-application-load-balancer"
        ));
    }
}

#[test]
fn azure_arr_affinity_is_load_balancing_family_evidence() {
    for cookie in [
        "ARRAffinity=opaque; Path=/; HttpOnly",
        "ARRAffinitySameSite=opaque; Path=/; SameSite=None; Secure",
    ] {
        let elements = detect_path_elements(&[header("set-cookie", cookie)]);
        assert!(has(
            &elements,
            PathElementRole::LoadBalancer,
            "azure-arr-affinity"
        ));
        assert!(!has(
            &elements,
            PathElementRole::ApplicationPlatform,
            "azure-app-service"
        ));
    }
}

#[test]
fn awselb_server_banner_is_alb_participation() {
    let elements = detect_path_elements(&[header("server", "awselb/2.0")]);
    assert!(has(
        &elements,
        PathElementRole::LoadBalancer,
        "aws-application-load-balancer"
    ));
}

#[test]
fn cloudflare_rate_limit_cookies_are_security_middleware() {
    for cookie in [
        "__cfruid=opaque; Path=/; Secure; HttpOnly",
        "_cfuvid=opaque; Path=/; Secure; HttpOnly",
    ] {
        let elements = detect_path_elements(&[header("set-cookie", cookie)]);
        assert!(has(
            &elements,
            PathElementRole::SecurityMiddleware,
            "cloudflare-rate-limiting"
        ));
    }
}

#[test]
fn identity_aware_proxy_markers_are_first_class_path_elements() {
    let iap = detect_path_elements(&[header("x-goog-iap-generated-response", "true")]);
    assert!(has(
        &iap,
        PathElementRole::IdentityProxy,
        "google-cloud-iap"
    ));

    let access = detect_path_elements(&[header(
        "set-cookie",
        "CF_Authorization=opaque; Path=/; Secure; HttpOnly",
    )]);
    assert!(has(
        &access,
        PathElementRole::IdentityProxy,
        "cloudflare-access"
    ));
}

#[test]
fn waiting_rooms_are_traffic_management_not_generic_security() {
    let cloudflare = detect_path_elements(&[header(
        "set-cookie",
        "__cfwaitingroom_shop=opaque; Path=/; Secure",
    )]);
    assert!(has(
        &cloudflare,
        PathElementRole::TrafficManagement,
        "cloudflare-waiting-room"
    ));

    for cookie in [
        "QueueITAccepted-SDFrts345E-V3_event42=opaque; Path=/; Secure",
        "Queue-it-visitorsession=opaque; Path=/; Secure",
    ] {
        let queueit = detect_path_elements(&[header("set-cookie", cookie)]);
        assert!(has(
            &queueit,
            PathElementRole::TrafficManagement,
            "queue-it"
        ));
    }
}

#[test]
fn alb_auth_cookie_identifies_both_alb_and_auth_middleware() {
    let elements = detect_path_elements(&[header(
        "set-cookie",
        "AWSELBAuthSessionCookie-0=opaque; Path=/; Secure; HttpOnly",
    )]);
    assert!(has(
        &elements,
        PathElementRole::LoadBalancer,
        "aws-application-load-balancer"
    ));
    assert!(has(
        &elements,
        PathElementRole::SecurityMiddleware,
        "aws-alb-authentication"
    ));
}

#[test]
fn minio_marker_distinguishes_minio_from_generic_s3_compatibility() {
    let elements = detect_path_elements(&[
        header(
            "x-minio-deployment-id",
            "00000000-0000-0000-0000-000000000000",
        ),
        header("x-amz-bucket-region", "us-east-1"),
    ]);
    assert!(has(&elements, PathElementRole::OriginService, "minio"));
    assert!(has(
        &elements,
        PathElementRole::OriginService,
        "s3-compatible-object-storage"
    ));
    assert!(!has(&elements, PathElementRole::OriginService, "aws-s3"));
}

#[test]
fn cdn77_separates_edge_and_cache_participation() {
    let elements = detect_path_elements(&[
        header("x-77-pop", "pragueCZ"),
        header("x-77-cache", "HIT"),
        header("x-77-age", "10"),
    ]);
    assert!(has(&elements, PathElementRole::EdgeProvider, "cdn77"));
    assert!(has(&elements, PathElementRole::Cache, "cdn77"));

    let cache_only = detect_path_elements(&[header("x-77-cache", "MISS")]);
    assert!(has(&cache_only, PathElementRole::Cache, "cdn77"));
    assert!(!has(&cache_only, PathElementRole::EdgeProvider, "cdn77"));
}

#[test]
fn oracle_lb_default_cookie_is_load_balancer_evidence() {
    let elements = detect_path_elements(&[header(
        "set-cookie",
        "X-Oracle-BMC-LBS-Route=opaque; Path=/; HttpOnly",
    )]);
    assert!(has(
        &elements,
        PathElementRole::LoadBalancer,
        "oracle-cloud-load-balancer"
    ));
}

#[test]
fn identity_proxy_defaults_are_product_specific_positive_markers() {
    for (headers, product) in [
        (
            vec![header("set-cookie", "_oauth2_proxy=opaque; Path=/; Secure")],
            "oauth2-proxy",
        ),
        (
            vec![header(
                "set-cookie",
                "_oauth2_proxy_1=opaque; Path=/; Secure",
            )],
            "oauth2-proxy",
        ),
        (
            vec![header(
                "set-cookie",
                "authelia_session=opaque; Path=/; Secure",
            )],
            "authelia",
        ),
        (
            vec![header(
                "location",
                "/outpost.goauthentik.io/start?rd=https%3A%2F%2Fapp.example%2F",
            )],
            "authentik",
        ),
    ] {
        let elements = detect_path_elements(&headers);
        assert!(has(&elements, PathElementRole::IdentityProxy, product));
    }
}
