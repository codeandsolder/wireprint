use wireprint::{
    PathElement, PathElementRole, detect_routing_elements as detect_routing_with_source,
};

// Synthetic CNAME-target fixture; production callers supply both sources.
fn detect_routing_elements(cname_targets: &[String]) -> Vec<PathElement> {
    detect_routing_with_source("customer.example.invalid", cname_targets)
}

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
fn akamai_netstorage_http_hostname_overrides_broad_akamai_edge_suffix() {
    let elements = detect_routing_elements(&["baseball-nsu.akamaihd.net".into()]);
    assert!(has(
        &elements,
        PathElementRole::OriginService,
        "akamai-netstorage"
    ));
    assert!(!has(&elements, PathElementRole::EdgeProvider, "akamai"));

    let edge = detect_routing_elements(&["media-example-a.akamaihd.net".into()]);
    assert!(has(&edge, PathElementRole::EdgeProvider, "akamai"));
    assert!(!has(
        &edge,
        PathElementRole::OriginService,
        "akamai-netstorage"
    ));
}

#[test]
fn managed_object_storage_hostnames_emit_origin_provenance() {
    for (hostname, product) in [
        ("c.storage.googleapis.com", "google-cloud-storage"),
        (
            "mystorageaccount.blob.core.windows.net",
            "azure-blob-storage",
        ),
        ("s3.us-west-004.backblazeb2.com", "backblaze-b2"),
        (
            "example-bucket.s3.us-west-004.backblazeb2.com",
            "backblaze-b2",
        ),
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(has(&elements, PathElementRole::OriginService, product));
        assert!(
            !elements
                .iter()
                .any(|element| element.role == PathElementRole::EdgeProvider)
        );
    }
}

#[test]
fn imgix_source_hostnames_emit_managed_edge_provenance() {
    for hostname in [
        "axeptio.imgix.net",
        "fractal-media.imgix.net",
        "unsplash.imgix.net.",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(has(&elements, PathElementRole::EdgeProvider, "imgix"));
    }

    let layered = detect_routing_elements(&[
        "unsplash.imgix.net".into(),
        "dualstack.com.imgix.map.fastly.net".into(),
    ]);
    assert!(has(&layered, PathElementRole::EdgeProvider, "imgix"));
    assert!(has(&layered, PathElementRole::EdgeProvider, "fastly"));
}

#[test]
fn imgix_parent_deeper_and_malformed_names_are_not_edge_claims() {
    for hostname in [
        "imgix.net",
        "foo.bar.imgix.net",
        "-bad.imgix.net",
        "bad-.imgix.net",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.imgix.net",
        "imgix.net.example",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(!has(&elements, PathElementRole::EdgeProvider, "imgix"));
    }
}

#[test]
fn digitalocean_spaces_endpoints_separate_cdn_edge_from_storage_origin() {
    for hostname in [
        "hopperhq.ams3.cdn.digitaloceanspaces.com",
        "assets.example.fra1.cdn.digitaloceanspaces.com",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(has(
            &elements,
            PathElementRole::EdgeProvider,
            "digitalocean-spaces-cdn"
        ));
        assert!(has(
            &elements,
            PathElementRole::OriginService,
            "digitalocean-spaces"
        ));
    }

    for hostname in [
        "fra1.digitaloceanspaces.com",
        "payload.fra1.digitaloceanspaces.com",
        "assets.example.fra1.digitaloceanspaces.com",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(has(
            &elements,
            PathElementRole::OriginService,
            "digitalocean-spaces"
        ));
        assert!(!has(
            &elements,
            PathElementRole::EdgeProvider,
            "digitalocean-spaces-cdn"
        ));
    }
}

#[test]
fn digitalocean_spaces_current_regions_are_explicitly_covered() {
    for region in [
        "nyc3", "ams3", "sfo2", "sfo3", "sgp1", "lon1", "fra1", "tor1", "blr1", "syd1", "atl1",
        "ric1", "mkc1",
    ] {
        let origin = detect_routing_elements(&[format!("bucket.{region}.digitaloceanspaces.com")]);
        assert!(has(
            &origin,
            PathElementRole::OriginService,
            "digitalocean-spaces"
        ));
        assert!(!has(
            &origin,
            PathElementRole::EdgeProvider,
            "digitalocean-spaces-cdn"
        ));

        let cdn = detect_routing_elements(&[format!("bucket.{region}.cdn.digitaloceanspaces.com")]);
        assert!(has(
            &cdn,
            PathElementRole::EdgeProvider,
            "digitalocean-spaces-cdn"
        ));
        assert!(has(
            &cdn,
            PathElementRole::OriginService,
            "digitalocean-spaces"
        ));
    }
}

#[test]
fn digitalocean_spaces_lookalikes_do_not_become_path_claims() {
    for hostname in [
        "digitaloceanspaces.com",
        "cdn.digitaloceanspaces.com",
        "fra1.cdn.digitaloceanspaces.com",
        "payload.unknown1.digitaloceanspaces.com",
        "payload.unknown1.cdn.digitaloceanspaces.com",
        "payload.mem1.digitaloceanspaces.com",
        "payload.mem1.cdn.digitaloceanspaces.com",
        "payload.fra1.cdn.digitaloceanspaces.example",
        "ab.fra1.digitaloceanspaces.com",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.fra1.digitaloceanspaces.com",
        "-bad.fra1.digitaloceanspaces.com",
        "bad-.fra1.cdn.digitaloceanspaces.com",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(!elements.iter().any(|element| {
            matches!(
                element.product.as_str(),
                "digitalocean-spaces" | "digitalocean-spaces-cdn"
            )
        }));
    }
}

#[test]
fn aws_s3_documented_public_data_hostnames_emit_origin_provenance() {
    for hostname in [
        "s3.amazonaws.com",
        "s3.us-west-2.amazonaws.com",
        "s3-us-west-2.amazonaws.com",
        "s3.dualstack.us-west-2.amazonaws.com",
        "amzn-s3-demo-bucket1.s3.us-west-2.amazonaws.com",
        "images.example.com.s3.us-east-1.amazonaws.com",
        "bucket.s3.dualstack.eu-central-1.amazonaws.com",
        "bucket.s3-us-west-2.amazonaws.com",
        "bucket.s3.amazonaws.com",
        "bucket.s3-accelerate.amazonaws.com",
        "bucket.s3-accelerate.dualstack.amazonaws.com",
        "finance-docs-123456789012.s3-accesspoint.us-west-2.amazonaws.com",
        "mfzwi23gnjvgw.mrap.accesspoint.s3-global.amazonaws.com",
        "s3.amazonaws.com.cn",
        "s3.cn-north-1.amazonaws.com.cn",
        "s3-cn-north-1.amazonaws.com.cn",
        "s3.dualstack.cn-northwest-1.amazonaws.com.cn",
        "china-bucket.s3.cn-north-1.amazonaws.com.cn",
        "china-bucket.s3.dualstack.cn-northwest-1.amazonaws.com.cn",
        "china-bucket.s3-cn-north-1.amazonaws.com.cn",
        "china-bucket.s3.amazonaws.com.cn",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(has(&elements, PathElementRole::OriginService, "aws-s3"));
        assert!(
            !elements
                .iter()
                .any(|element| element.role == PathElementRole::EdgeProvider)
        );
    }
}

#[test]
fn aws_s3_adjacent_endpoint_families_are_not_origin_claims() {
    for hostname in [
        "bucket.s3.dualstack.amazonaws.com",
        "bucket.s3.accelerate.amazonaws.com",
        "bucket.s3-website-us-east-1.amazonaws.com",
        "example-123456789012.s3-object-lambda.us-east-1.amazonaws.com",
        "ap-123456789012.s3-outposts.us-east-1.amazonaws.com",
        "finance-docs-12345.s3-accesspoint.us-west-2.amazonaws.com",
        "finance-docs-123456789012.s3-accesspoint.not-a-region.amazonaws.com",
        "mfzwi23gnjvgw.mrap.accesspoint.s3-global.amazonaws.example",
        "china-bucket.s3-website.cn-north-1.amazonaws.com.cn",
        "china-bucket.s3-accelerate.amazonaws.com.cn",
        "finance-docs-123456789012.s3-accesspoint.cn-north-1.amazonaws.com.cn",
        "mfzwi23gnjvgw.mrap.accesspoint.s3-global.amazonaws.com.cn",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(!has(&elements, PathElementRole::OriginService, "aws-s3"));
    }
}

#[test]
fn managed_object_storage_validation_and_lookalike_names_are_not_origin_claims() {
    for hostname in [
        "-nsu.akamaihd.net",
        "nested.baseball-nsu.akamaihd.net",
        "baseball-nsu.akamaihd.example",
        "storage.googleapis.com",
        "x.c.storage.googleapis.com",
        "c.storage.googleapis.example",
        "blob.core.windows.net",
        "asverify.mystorageaccount.blob.core.windows.net",
        "nested.mystorageaccount.blob.core.windows.net",
        "mystorageaccount.z5.web.core.windows.net",
        "backblazeb2.com",
        "s3.backblazeb2.com",
        "nested.example.s3.us-west-004.backblazeb2.com",
        "s3.us-west-004.backblazeb2.example",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(!elements.iter().any(|element| {
            element.role == PathElementRole::OriginService
                && matches!(
                    element.product.as_str(),
                    "akamai-netstorage"
                        | "google-cloud-storage"
                        | "azure-blob-storage"
                        | "backblaze-b2"
                        | "aws-s3"
                )
        }));
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
fn hubspot_hosted_site_names_emit_platform_provenance() {
    for hostname in [
        "137828.hs-sites.com",
        "ezblockchain-4353115.hs-sites.com",
        "12345.hs-sites.eu",
        "143796548.hs-sites-eu1.com",
        "portal-12345.hs-sites.net",
        "12345.hs-sites-na2.com",
        "portal-12345.hs-sites.ca",
        "12345.hs-sites-na3.com",
        "portal-12345.hs-sites.au",
        "12345.hs-sites-ap1.com",
        "12345.hubspotpagebuilder.com",
        "12345.hubspotpagebuilder.eu",
        "12345.hubspotpagebuilder.net",
        "12345.hubspotpagebuilder.ca",
        "12345.hubspotpagebuilder.au",
        "19490924.group24.sites.hubspot.net",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(has(
            &elements,
            PathElementRole::ApplicationPlatform,
            "hubspot"
        ));
        assert!(
            !elements
                .iter()
                .any(|element| element.role == PathElementRole::EdgeProvider)
        );
    }
}

#[test]
fn hubspot_non_hosting_and_lookalike_names_are_not_platform_provenance() {
    for hostname in [
        "hs-sites.com",
        "bareportal.hs-sites.com",
        "portal-name.hs-sites.net",
        "portal-abc.hs-sites-eu1.com",
        "portal-12345.hs-sites.eu",
        "12345.hs-sites.net",
        "12345.hs-sites.ca",
        "12345.hs-sites.au",
        "nested.137828.hs-sites.com",
        "-invalid.hs-sites.com",
        "invalid-.hs-sites.com",
        "hubspotpagebuilder.com",
        "legacy-name.hubspotpagebuilder.com",
        "nested.12345.hubspotpagebuilder.com",
        "sites.hubspot.net",
        "group24.sites.hubspot.net",
        "abc.group24.sites.hubspot.net",
        "19490924.groupx.sites.hubspot.net",
        "19490924.group.sites.hubspot.net",
        "nested.19490924.group24.sites.hubspot.net",
        "1111111111111111111111111111111111111111111111111111111111111111.group24.sites.hubspot.net",
        "19490924.group22222222222222222222222222222222222222222222222222222222222.sites.hubspot.net",
        "513577g27.secure004.hubspot.net",
        "cdn2.hubspot.net",
        "js.hs-scripts.com",
        "forms.hsforms.com",
        "example.hs1a.dkim.hubspotemail.net",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(!has(
            &elements,
            PathElementRole::ApplicationPlatform,
            "hubspot"
        ));
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

#[test]
fn webflow_hosted_site_names_emit_platform_provenance() {
    for hostname in [
        "cdn.webflow.com",
        "proxy-ssl.webflow.com",
        "my-project.webflow.io",
        "branch-preview.webflow.io",
        "MY-PROJECT.WEBFLOW.IO.",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(has(
            &elements,
            PathElementRole::ApplicationPlatform,
            "webflow"
        ));
        assert!(
            !elements
                .iter()
                .any(|element| element.role == PathElementRole::EdgeProvider)
        );
    }
}

#[test]
fn webflow_non_hosting_and_lookalike_names_are_not_platform_provenance() {
    for hostname in [
        "webflow.io",
        "nested.site.webflow.io",
        "-invalid.webflow.io",
        "invalid-.webflow.io",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.webflow.io",
        "webflow.com",
        "api.webflow.com",
        "nested.cdn.webflow.com",
        "cdn.webflow.com.example",
        "prod.website-files.com",
        "cdn.prod.website-files.com",
        "nested.proxy-ssl.webflow.com",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(!has(
            &elements,
            PathElementRole::ApplicationPlatform,
            "webflow"
        ));
    }
}

#[test]
fn intercom_help_center_names_emit_platform_provenance() {
    for hostname in [
        "intercom.help",
        "custom.intercom.help",
        "custom.eu.intercom.help",
        "custom.au.intercom.help",
        "custom.intercom-help.eu",
        "us.intercomhelpcenter.com",
        "eu.intercomhelpcenter.com",
        "au.intercomhelpcenter.com",
        "CUSTOM.INTERCOM.HELP.",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(has(
            &elements,
            PathElementRole::ApplicationPlatform,
            "intercom"
        ));
        assert!(
            !elements
                .iter()
                .any(|element| element.role == PathElementRole::EdgeProvider)
        );
    }
}

#[test]
fn shopify_storefront_names_emit_platform_provenance() {
    for hostname in [
        "cdn.shopify.com",
        "shops.myshopify.com",
        "example-store.myshopify.com",
        "EXAMPLE-STORE.MYSHOPIFY.COM.",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(has(
            &elements,
            PathElementRole::ApplicationPlatform,
            "shopify"
        ));
        assert!(
            !elements
                .iter()
                .any(|element| element.role == PathElementRole::EdgeProvider)
        );
    }
}

#[test]
fn shopify_non_storefront_and_lookalike_names_are_not_platform_provenance() {
    for hostname in [
        "myshopify.com",
        "nested.store.myshopify.com",
        "-invalid.myshopify.com",
        "invalid-.myshopify.com",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.myshopify.com",
        "shopify.com",
        "www.shopify.com",
        "shop.app",
        "monorail-edge.shopifysvc.com",
        "apps.cloudflare-edge.shopifycloud.com",
        "nested.cdn.shopify.com",
        "cdn.shopify.com.example",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(!has(
            &elements,
            PathElementRole::ApplicationPlatform,
            "shopify"
        ));
    }
}

#[test]
fn intercom_non_help_center_and_lookalike_names_are_not_platform_provenance() {
    for hostname in [
        "intercom.com",
        "api.intercom.com",
        "api-iam.intercom.io",
        "downloads.intercomcdn.com",
        "fin.ai",
        "intercomhelpcenter.com",
        "intercom-help.eu",
        "eu.intercom.help",
        "nested.intercom.help",
        "nested.custom.intercom.help",
        "nested.us.intercomhelpcenter.com",
        "custom.intercom.help.example",
        "us.intercomhelpcenter.com.example",
    ] {
        let elements = detect_routing_elements(&[hostname.into()]);
        assert!(!has(
            &elements,
            PathElementRole::ApplicationPlatform,
            "intercom"
        ));
    }
}

#[test]
fn routing_provenance_keeps_direct_host_separate_from_cname_targets() {
    let direct = detect_routing_with_source("SITE.CDN.CLOUDFLARE.NET.", &[]);
    let direct_claim = direct
        .iter()
        .find(|element| element.product == "cloudflare")
        .expect("direct provider-managed hostname");
    assert_eq!(direct_claim.evidence, ["host:site.cdn.cloudflare.net"]);

    let alias =
        detect_routing_with_source("customer.example.org", &["SITE.CDN.CLOUDFLARE.NET.".into()]);
    let alias_claim = alias
        .iter()
        .find(|element| element.product == "cloudflare")
        .expect("provider-managed CNAME target");
    assert_eq!(alias_claim.evidence, ["cname:site.cdn.cloudflare.net"]);

    let both = detect_routing_with_source(
        "site.cdn.cloudflare.net",
        &[
            "SITE.CDN.CLOUDFLARE.NET.".into(),
            "site.cdn.cloudflare.net".into(),
        ],
    );
    let claim = both
        .iter()
        .find(|element| element.product == "cloudflare")
        .expect("same name seen from both sources");
    assert_eq!(
        claim.evidence,
        [
            "host:site.cdn.cloudflare.net",
            "cname:site.cdn.cloudflare.net"
        ]
    );

    let unknown = detect_routing_with_source("customer.example.org", &[]);
    assert!(unknown.is_empty());
}

#[test]
fn zendesk_host_mapped_account_cname_is_platform_participation_only() {
    for (requested, target) in [
        ("help.coda.io", "coda-docs.zendesk.com"),
        ("support.jvid.com", "jvid.zendesk.com"),
        ("help.redletterdays.co.uk", "redletterdays.zendesk.com"),
        ("support.beenverified.com", "BEENVERIFIED.ZENDESK.COM."),
        ("support.example.invalid", "a-b-c.zendesk.com"),
    ] {
        let elements = detect_routing_with_source(requested, &[target.into()]);
        let zendesk = elements
            .iter()
            .find(|e| e.product == "zendesk" && e.role == PathElementRole::ApplicationPlatform)
            .expect("Zendesk CNAME target");
        assert_eq!(
            zendesk.evidence,
            [format!(
                "cname:{}",
                target.trim_end_matches('.').to_ascii_lowercase()
            )]
        );
        assert!(!has(&elements, PathElementRole::EdgeProvider, "zendesk"));
    }
}

#[test]
fn zendesk_direct_names_and_unrelated_dns_aliases_are_not_host_mapping_evidence() {
    for requested in [
        "cheathappens.zendesk.com",
        "whistichelp.zendesk.com",
        "www.zendesk.com",
        "web-assets.zendesk.com",
        "mail1.zendesk.com",
    ] {
        let elements = detect_routing_with_source(requested, &[]);
        assert!(!has(
            &elements,
            PathElementRole::ApplicationPlatform,
            "zendesk"
        ));
    }

    for target in [
        "zendesk.com",
        "nested.coda-docs.zendesk.com",
        "coda-docs.zendesk.com.evil.example",
        "zendesks.com",
        "ab.zendesk.com",
        "-invalid.zendesk.com",
        "invalid-.zendesk.com",
        "inv_alid.zendesk.com",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.zendesk.com",
        "zendesk1._domainkey.zendesk.com",
        "mail.zendesk.com.example",
    ] {
        let elements = detect_routing_with_source("support.customer.example", &[target.into()]);
        assert!(!has(
            &elements,
            PathElementRole::ApplicationPlatform,
            "zendesk"
        ));
    }
}

#[test]
fn zendesk_cname_layered_with_cloudflare_keeps_one_outer_provider() {
    let elements = detect_routing_with_source(
        "help.coda.io",
        &[
            "coda-docs.zendesk.com".into(),
            "site.cdn.cloudflare.net".into(),
        ],
    );
    assert!(has(
        &elements,
        PathElementRole::ApplicationPlatform,
        "zendesk"
    ));
    assert!(has(&elements, PathElementRole::EdgeProvider, "cloudflare"));
    assert!(!has(&elements, PathElementRole::EdgeProvider, "zendesk"));
}
