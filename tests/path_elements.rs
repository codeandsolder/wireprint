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
fn fastly_artisanal_bits_and_akamai_netstorage_are_edge_evidence() {
    let fastly = detect_path_elements(&[header("server", "Artisanal bits")]);
    assert!(has(&fastly, PathElementRole::EdgeProvider, "fastly"));

    let akamai = detect_path_elements(&[header("server", "AkamaiNetStorage")]);
    assert!(has(&akamai, PathElementRole::EdgeProvider, "akamai"));
}

#[test]
fn common_server_implementations_are_not_promoted_to_edge_providers() {
    for (server, product) in [
        ("Apache/2.4.65", "apache-http-server"),
        ("Microsoft-IIS/10.0", "microsoft-iis"),
        ("LiteSpeed", "litespeed"),
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
