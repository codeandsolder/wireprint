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
fn azure_front_door_managed_name_emits_edge_and_platform_claims() {
    let elements = detect_routing_elements(&["site.azurefd.net".into()]);
    assert!(has(
        &elements,
        PathElementRole::EdgeProvider,
        "azure-front-door"
    ));
    assert!(has(
        &elements,
        PathElementRole::ApplicationPlatform,
        "azure-front-door"
    ));
}

#[test]
fn akamai_documented_edge_hostname_families_emit_provider_claims() {
    for cname in [
        "www.example.com.edgekey.net",
        "www.example.com.edgekey-staging.net",
        "www.example.com.edgesuite.net",
        "www.example.com.edgesuite-staging.net",
        "media-example.akamaized.net",
        "media-example-a.akamaihd.net",
    ] {
        let elements = detect_routing_elements(&[cname.into()]);
        assert!(has(&elements, PathElementRole::EdgeProvider, "akamai"));
    }
}

#[test]
fn quic_cloud_assigned_cname_is_edge_but_dns_nameserver_is_not() {
    for cname in [
        "c12345.tier1.quicns.com",
        "c30027.tier1.quicns.com.",
        "c2351297.tier1.quicns.com",
    ] {
        let elements = detect_routing_elements(&[cname.into()]);
        assert!(has(&elements, PathElementRole::EdgeProvider, "quic-cloud"));
    }

    for cname in [
        "kevin.quicns.com",
        "c12345.quicns.com",
        "c12345.tierx.quicns.com",
        "c12345.tier2.quicns.com",
        "client.tier1.quicns.com",
        "c12345.tier1.quicns.example",
    ] {
        let elements = detect_routing_elements(&[cname.into()]);
        assert!(!has(&elements, PathElementRole::EdgeProvider, "quic-cloud"));
    }
}

#[test]
fn railway_and_fly_managed_public_hostnames_emit_edge_and_platform_claims() {
    for (hostname, provider) in [
        ("utilities-us-east.up.railway.app", "railway"),
        ("g05ns7.up.railway.app.", "railway"),
        ("debug.fly.dev", "fly-io"),
        ("flyio-landing.fly.dev.", "fly-io"),
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(has(&elements, PathElementRole::EdgeProvider, provider));
        assert!(has(
            &elements,
            PathElementRole::ApplicationPlatform,
            provider
        ));
    }
}

#[test]
fn railway_tcp_proxy_and_managed_hostname_lookalikes_are_not_http_edge_claims() {
    for hostname in [
        "up.railway.app",
        "nested.example.up.railway.app",
        "shuttle.proxy.rlwy.net",
        "proxy.rlwy.net",
        "fly.dev",
        "nested.example.fly.dev",
        "fly.io",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(!elements.iter().any(|element| {
            matches!(
                element.role,
                PathElementRole::EdgeProvider | PathElementRole::ApplicationPlatform
            ) && matches!(element.product.as_str(), "railway" | "fly-io")
        }));
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
fn netlify_and_vercel_ingress_names_emit_edge_and_platform_claims() {
    for (hostname, provider) in [
        ("my-project.netlify.app", "netlify"),
        ("branch--my-project.netlify.app.", "netlify"),
        ("apex-loadbalancer.netlify.com", "netlify"),
        ("d1d4fc829fe7bc7c.vercel-dns-017.com", "vercel"),
        ("cname.vercel-dns-0.com", "vercel"),
        ("cname.vercel-dns.com", "vercel"),
        ("my-project.vercel.app.", "vercel"),
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(has(&elements, PathElementRole::EdgeProvider, provider));
        assert!(has(
            &elements,
            PathElementRole::ApplicationPlatform,
            provider
        ));
    }
}

#[test]
fn vercel_nameservers_and_broad_lookalikes_do_not_become_edge_claims() {
    for hostname in [
        "ns1.vercel-dns.com",
        "ns2.vercel-dns.com",
        "client.vercel-dns.com",
        "nested.client.vercel-dns-017.com",
        "vercel-dns-017.com",
        "netlify.app",
        "nested.my-project.netlify.app",
        "teacher-glances-63085.netlify.com",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(!elements.iter().any(|element| {
            element.role == PathElementRole::EdgeProvider
                && matches!(element.product.as_str(), "vercel" | "netlify")
        }));
    }

    let legacy = detect_routing_elements(&["teacher-glances-63085.netlify.com".into()]);
    assert!(has(
        &legacy,
        PathElementRole::ApplicationPlatform,
        "netlify"
    ));
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
fn azure_cdn_managed_names_emit_broad_edge_family_claims() {
    for hostname in [
        "catalogartifact.azureedge.net",
        "contoso.azureedge.net.",
        "az416426.vo.msecnd.net",
        "assets.vo.msecnd.net.",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(has(
            &elements,
            PathElementRole::EdgeProvider,
            "azure-cloud-edge"
        ));
        assert!(!has(
            &elements,
            PathElementRole::ApplicationPlatform,
            "azure-cdn"
        ));
    }
}

#[test]
fn azure_cloud_edge_refines_to_front_door_when_dns_chain_exposes_both() {
    let elements = detect_routing_elements(&[
        "az416426.vo.msecnd.net".into(),
        "aijscdn1-g4ccc2ajgnahcpct.b02.azurefd.net".into(),
        "mr-b02.tm-azurefd.net".into(),
    ]);

    assert!(has(
        &elements,
        PathElementRole::EdgeProvider,
        "azure-front-door"
    ));
    assert!(!has(
        &elements,
        PathElementRole::EdgeProvider,
        "azure-cloud-edge"
    ));
    let front_door = elements.iter().find(|element| {
        element.role == PathElementRole::EdgeProvider && element.product == "azure-front-door"
    });
    assert!(front_door.is_some());
    if let Some(front_door) = front_door {
        assert!(
            front_door
                .evidence
                .contains(&"cname:az416426.vo.msecnd.net".into())
        );
        assert!(
            front_door
                .evidence
                .iter()
                .any(|evidence| evidence.contains("azurefd.net"))
        );
    }
}

#[test]
fn azure_cdn_parent_and_deeper_lookalikes_are_not_edge_claims() {
    for hostname in [
        "azureedge.net",
        "nested.example.azureedge.net",
        "vo.msecnd.net",
        "nested.example.vo.msecnd.net",
        "example.azureedge.invalid",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(!has(
            &elements,
            PathElementRole::EdgeProvider,
            "azure-cloud-edge"
        ));
    }
}

#[test]
fn managed_application_platform_hostnames_emit_bounded_provenance() {
    for (hostname, product) in [
        ("example.onrender.com", "render"),
        ("whispering-willow-5678.herokudns.com", "heroku"),
        ("example-12345.ssl.herokudns.com", "heroku"),
        ("my-app-12345.herokuapp.com", "heroku"),
        ("my-app-12345.us.herokuapp.com", "heroku"),
        ("haiku-name.space-name.herokuspace.com", "heroku"),
        ("live-example.pantheonsite.io", "pantheon"),
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(has(
            &elements,
            PathElementRole::ApplicationPlatform,
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
fn acquia_default_environment_hostname_emits_platform_and_origin() {
    for hostname in [
        "mysite.prod.acquia-sites.com",
        "examplesite.devcloud.acquia-sites.com.",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(has(
            &elements,
            PathElementRole::ApplicationPlatform,
            "acquia-cloud-platform"
        ));
        assert!(has(
            &elements,
            PathElementRole::OriginService,
            "acquia-cloud-platform"
        ));
        assert!(
            !elements
                .iter()
                .any(|element| element.role == PathElementRole::EdgeProvider)
        );
    }
}

#[test]
fn platform_validation_management_and_deeper_names_are_not_path_claims() {
    for hostname in [
        "onrender.com",
        "nested.example.onrender.com",
        "example.verify.renderdns.com",
        "example.hostname.renderdns.com",
        "herokuapp.com",
        "nested.too.deep.herokuapp.com",
        "app..herokuapp.com",
        "herokudns.com",
        "nested.too.deep.herokudns.com",
        "target..herokudns.com",
        "herokuspace.com",
        "onlyone.herokuspace.com",
        "too.many.labels.herokuspace.com",
        "pantheonsite.io",
        "nested.example.pantheonsite.io",
        "acquia-sites.com",
        "mysite.acquia-sites.com",
        "mysite.ssh.prod.acquia-sites.com",
        "nested.mysite.prod.acquia-sites.com",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(!elements.iter().any(|element| {
            matches!(
                element.product.as_str(),
                "render" | "heroku" | "pantheon" | "acquia-cloud-platform"
            )
        }));
    }
}

#[test]
fn paas_aliases_remain_application_platform_evidence() {
    let elements = detect_routing_elements(&[
        "teacher-glances-63085.netlify.com".into(),
        "myapp-00000.westus.azurewebsites.net".into(),
        "example.us-east-1.elasticbeanstalk.com".into(),
    ]);

    for product in ["netlify", "azure-app-service", "aws-elastic-beanstalk"] {
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
