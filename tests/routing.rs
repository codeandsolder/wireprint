use wireprint::{PathElement, PathElementRole, detect_routing_elements};

fn has(elements: &[PathElement], role: PathElementRole, product: &str) -> bool {
    elements
        .iter()
        .any(|element| element.role == role && element.product == product)
}

#[test]
fn established_provider_managed_aliases_emit_edge_provider_claims() {
    for (cname, provider) in [
        ("a.example.edgekey.net", "akamai"),
        ("d111111abcdef8.cloudfront.net", "aws-cloudfront"),
        ("global.prod.fastly.net", "fastly"),
        ("site.azurefd.net", "azure-front-door"),
        ("foo.impervadns.net", "imperva"),
        ("site.cdn.cloudflare.net", "cloudflare"),
        ("tenant.ac.vh.ves.io", "f5-volt"),
        ("site.v1.radwarecloud.net", "radware-cloud"),
    ] {
        let elements = detect_routing_elements(&[cname.into()]);
        assert!(has(&elements, PathElementRole::EdgeProvider, provider));
    }
}

#[test]
fn new_cdn_aliases_emit_edge_provider_claims() {
    for (cname, provider) in [
        ("example-abcdef.kxcdn.com", "keycdn"),
        ("myzone.b-cdn.net.", "bunnycdn"),
        ("1234567890.rsc.cdn77.org", "cdn77"),
    ] {
        let elements = detect_routing_elements(&[cname.into()]);
        assert!(has(&elements, PathElementRole::EdgeProvider, provider));
    }
}

#[test]
fn tencent_edgeone_and_alibaba_cloud_cnames_emit_edge_family_claims() {
    for cname in [
        "www.example.com.acc.edgeonedy1.com",
        "www.example.com.acc.tyxcdn.com",
    ] {
        let elements = detect_routing_elements(&[cname.into()]);
        assert!(has(
            &elements,
            PathElementRole::EdgeProvider,
            "tencent-edgeone"
        ));
        assert!(!has(
            &elements,
            PathElementRole::TrafficManagement,
            "tencent-edgeone"
        ));
    }

    for cname in [
        "www.example.com.eo.dnse1.com",
        "www.example.com.eo.dnse2.com",
        "www.example.com.eo.dnse5.com.",
    ] {
        let elements = detect_routing_elements(&[cname.into()]);
        assert!(has(
            &elements,
            PathElementRole::TrafficManagement,
            "tencent-edgeone"
        ));
        assert!(!has(
            &elements,
            PathElementRole::EdgeProvider,
            "tencent-edgeone"
        ));
    }

    let chain = detect_routing_elements(&[
        "www.example.com.eo.dnse2.com".into(),
        "www.example.com.acc.edgeonedy1.com".into(),
    ]);
    assert!(has(
        &chain,
        PathElementRole::TrafficManagement,
        "tencent-edgeone"
    ));
    assert!(has(
        &chain,
        PathElementRole::EdgeProvider,
        "tencent-edgeone"
    ));

    let alibaba = detect_routing_elements(&["cdn.example.com.w.alikunlun.com".into()]);
    assert!(has(
        &alibaba,
        PathElementRole::EdgeProvider,
        "alibaba-cloud-edge"
    ));
}

#[test]
fn alibaba_cloud_cnames_emit_edge_family_claims() {
    for cname in [
        "friends.duolingo.cn.w.kunluncan.com",
        "fast.example.com.w.kunlunle.com",
        "cdn.example.com.w.alikunlun.com",
    ] {
        let elements = detect_routing_elements(&[cname.into()]);
        assert!(has(
            &elements,
            PathElementRole::EdgeProvider,
            "alibaba-cloud-edge"
        ));
    }
}

#[test]
fn similar_but_non_provider_cnames_are_not_force_labeled() {
    for cname in [
        "www.example.com.eo.dnse.example",
        "www.example.com.eo.dnsefoo.com",
        "www.example.com.acc.edgeonedy1.example",
        "www.example.com.w.kunlun.invalid",
        "www.example.com.w.notkunlun.com",
    ] {
        let elements = detect_routing_elements(&[cname.into()]);
        assert!(!elements.iter().any(|element| {
            matches!(
                element.product.as_str(),
                "tencent-edgeone" | "alibaba-cloud-edge"
            )
        }));
    }
}

#[test]
fn netlify_and_vercel_aliases_remain_platform_only() {
    let elements = detect_routing_elements(&[
        "my-project.netlify.app".into(),
        "apex-loadbalancer.netlify.com".into(),
        "d1d4fc829fe7bc7c.vercel-dns-017.com".into(),
        "cname.vercel-dns-0.com".into(),
    ]);

    assert!(has(
        &elements,
        PathElementRole::ApplicationPlatform,
        "netlify"
    ));
    assert!(has(
        &elements,
        PathElementRole::ApplicationPlatform,
        "vercel"
    ));
    assert!(
        !elements
            .iter()
            .any(|element| element.role == PathElementRole::EdgeProvider)
    );
}

#[test]
fn unrelated_cname_is_not_force_labeled() {
    assert!(detect_routing_elements(&["edge.example.invalid".into()]).is_empty());
}

#[test]
fn additional_cdn_aliases_emit_edge_provider_claims() {
    for (cname, provider) in [
        ("myservice.cachefly.net", "cachefly"),
        ("resource.gcdn.co", "gcore"),
    ] {
        let elements = detect_routing_elements(&[cname.into()]);
        assert!(has(&elements, PathElementRole::EdgeProvider, provider));
    }
}

#[test]
fn cloud_load_balancer_and_api_gateway_aliases_keep_specific_roles() {
    let elements = detect_routing_elements(&[
        "my-load-balancer-1234567890abcdef.elb.us-east-2.amazonaws.com".into(),
        "dualstack.my-load-balancer-1234567890.us-west-2.elb.amazonaws.com".into(),
        "d-numh1z56v6.execute-api.us-west-2.amazonaws.com".into(),
        "my-apim.azure-api.net".into(),
    ]);

    assert!(has(
        &elements,
        PathElementRole::LoadBalancer,
        "aws-elastic-load-balancing"
    ));
    assert!(has(
        &elements,
        PathElementRole::ApiGateway,
        "aws-api-gateway"
    ));
    assert!(has(
        &elements,
        PathElementRole::ApiGateway,
        "azure-api-management"
    ));
    assert!(
        !elements
            .iter()
            .any(|element| element.role == PathElementRole::EdgeProvider)
    );
}

#[test]
fn dns_traffic_steering_does_not_become_edge_termination() {
    let elements = detect_routing_elements(&[
        "contoso.trafficmanager.net".into(),
        "a1234567890abcdef.dualstack.awsglobalaccelerator.com".into(),
    ]);

    assert!(has(
        &elements,
        PathElementRole::TrafficManagement,
        "azure-traffic-manager"
    ));
    assert!(has(
        &elements,
        PathElementRole::TrafficManagement,
        "aws-global-accelerator"
    ));
    assert!(
        !elements
            .iter()
            .any(|element| element.role == PathElementRole::EdgeProvider)
    );
}

#[test]
fn paas_aliases_remain_application_platform_evidence() {
    let elements = detect_routing_elements(&[
        "teacher-glances-63085.netlify.com".into(),
        "myapp-00000.westus.azurewebsites.net".into(),
        "example.us-east-1.elasticbeanstalk.com".into(),
        "legacy.azureedge.net".into(),
    ]);

    for product in [
        "netlify",
        "azure-app-service",
        "aws-elastic-beanstalk",
        "azure-cdn",
    ] {
        assert!(has(
            &elements,
            PathElementRole::ApplicationPlatform,
            product
        ));
    }
    assert!(
        !elements
            .iter()
            .any(|element| element.role == PathElementRole::EdgeProvider)
    );
}

#[test]
fn azure_api_management_non_gateway_hosts_are_not_mislabeled_as_gateway() {
    let elements = detect_routing_elements(&[
        "service.developer.azure-api.net".into(),
        "service.management.azure-api.net".into(),
    ]);
    assert!(!has(
        &elements,
        PathElementRole::ApiGateway,
        "azure-api-management"
    ));
}
