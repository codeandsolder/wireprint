use crate::model::{PathElement, PathElementRole};

pub const ROUTING_CLASSIFIER_VERSION: &str = "builtin-routing-v12";

fn normalize_name(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn matches_suffix(host: &str, suffix: &str) -> bool {
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

fn labels(host: &str) -> Vec<&str> {
    host.split('.').collect()
}

fn looks_like_vercel_ingress(host: &str) -> bool {
    if host == "cname.vercel-dns.com" {
        return true;
    }

    let parts = labels(host);
    if parts.len() == 3 && parts[1..] == ["vercel", "app"] {
        return !parts[0].is_empty();
    }
    if parts.len() != 3 || parts[2] != "com" || parts[0].is_empty() {
        return false;
    }

    parts[1].strip_prefix("vercel-dns-").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn looks_like_netlify_ingress(host: &str) -> bool {
    if host == "apex-loadbalancer.netlify.com" {
        return true;
    }

    let parts = labels(host);
    parts.len() == 3 && parts[1..] == ["netlify", "app"] && !parts[0].is_empty()
}

fn looks_like_aws_elb(host: &str) -> bool {
    let parts = labels(host);
    parts.len() >= 5
        && parts[parts.len() - 2..] == ["amazonaws", "com"]
        && (parts.get(parts.len() - 3) == Some(&"elb")
            || parts.get(parts.len() - 4) == Some(&"elb"))
}

fn looks_like_aws_api_gateway(host: &str) -> bool {
    let parts = labels(host);
    parts.len() >= 5
        && parts[parts.len() - 2..] == ["amazonaws", "com"]
        && parts.get(parts.len() - 4) == Some(&"execute-api")
}

fn looks_like_azure_api_management_gateway(host: &str) -> bool {
    let parts = labels(host);
    parts.len() == 3 && parts[1..] == ["azure-api", "net"]
}

fn looks_like_tencent_edgeone_edge_cname(host: &str) -> bool {
    matches_suffix(host, "acc.edgeonedy1.com") || matches_suffix(host, "acc.tyxcdn.com")
}

fn looks_like_tencent_edgeone_traffic_cname(host: &str) -> bool {
    let parts = labels(host);
    if parts.len() < 4 || parts[parts.len() - 1] != "com" || parts[parts.len() - 3] != "eo" {
        return false;
    }

    parts[parts.len() - 2]
        .strip_prefix("dnse")
        .is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn looks_like_alibaba_cloud_edge_cname(host: &str) -> bool {
    let parts = labels(host);
    if parts.len() < 3 || parts[parts.len() - 1] != "com" {
        return false;
    }

    let provider_root = parts[parts.len() - 2];
    provider_root == "alikunlun" || provider_root.starts_with("kunlun")
}

fn looks_like_quic_cloud_cdn_cname(host: &str) -> bool {
    let parts = labels(host);
    if parts.len() != 4 || parts[1..] != ["tier1", "quicns", "com"] {
        return false;
    }

    parts[0].strip_prefix('c').is_some_and(|site_id| {
        !site_id.is_empty() && site_id.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn looks_like_railway_public_hostname(host: &str) -> bool {
    let parts = labels(host);
    parts.len() == 4 && parts[1..] == ["up", "railway", "app"]
}

fn looks_like_fly_app_hostname(host: &str) -> bool {
    let parts = labels(host);
    parts.len() == 3 && parts[1..] == ["fly", "dev"]
}

fn looks_like_render_public_hostname(host: &str) -> bool {
    let parts = labels(host);
    parts.len() == 3 && parts[1..] == ["onrender", "com"] && !parts[0].is_empty()
}

fn looks_like_heroku_platform_hostname(host: &str) -> bool {
    let parts = labels(host);
    match parts.as_slice() {
        [app, "herokuapp", "com"] => !app.is_empty(),
        [app, zone, "herokuapp", "com"] => !app.is_empty() && !zone.is_empty(),
        [target, "herokudns", "com"] => !target.is_empty(),
        [target, zone, "herokudns", "com"] => !target.is_empty() && !zone.is_empty(),
        [app, space, "herokuspace", "com"] => !app.is_empty() && !space.is_empty(),
        _ => false,
    }
}

fn looks_like_pantheon_platform_hostname(host: &str) -> bool {
    let parts = labels(host);
    parts.len() == 3 && parts[1..] == ["pantheonsite", "io"] && !parts[0].is_empty()
}

fn looks_like_acquia_default_hostname(host: &str) -> bool {
    let parts = labels(host);
    parts.len() == 4
        && parts[2..] == ["acquia-sites", "com"]
        && !parts[0].is_empty()
        && !parts[1].is_empty()
}

fn looks_like_akamai_netstorage_http_hostname(host: &str) -> bool {
    let parts = labels(host);
    parts.len() == 3
        && parts[1..] == ["akamaihd", "net"]
        && parts[0]
            .strip_suffix("-nsu")
            .is_some_and(|prefix| !prefix.is_empty())
}

fn looks_like_google_cloud_storage_custom_domain_target(host: &str) -> bool {
    host == "c.storage.googleapis.com"
}

fn looks_like_azure_blob_storage_hostname(host: &str) -> bool {
    let parts = labels(host);
    parts.len() == 5 && parts[1..] == ["blob", "core", "windows", "net"] && !parts[0].is_empty()
}

fn looks_like_backblaze_b2_s3_hostname(host: &str) -> bool {
    let parts = labels(host);
    match parts.as_slice() {
        ["s3", region, "backblazeb2", "com"] => !region.is_empty(),
        [bucket, "s3", region, "backblazeb2", "com"] => !bucket.is_empty() && !region.is_empty(),
        _ => false,
    }
}

fn looks_like_digitalocean_spaces_region(label: &str) -> bool {
    matches!(
        label,
        "nyc3"
            | "ams3"
            | "sfo2"
            | "sfo3"
            | "sgp1"
            | "lon1"
            | "fra1"
            | "tor1"
            | "blr1"
            | "syd1"
            | "atl1"
            | "ric1"
            | "mkc1"
    )
}

fn looks_like_dns_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn digitalocean_spaces_body(host: &str) -> Option<&str> {
    host.strip_suffix(".digitaloceanspaces.com")
        .filter(|body| !body.is_empty())
}

fn looks_like_digitalocean_spaces_bucket(bucket: &str) -> bool {
    (3..=63).contains(&bucket.len()) && bucket.split('.').all(looks_like_dns_label)
}

fn looks_like_digitalocean_spaces_cdn_hostname(host: &str) -> bool {
    let Some(body) = digitalocean_spaces_body(host) else {
        return false;
    };
    let Some(endpoint) = body.strip_suffix(".cdn") else {
        return false;
    };
    let Some((bucket, region)) = endpoint.rsplit_once('.') else {
        return false;
    };

    looks_like_digitalocean_spaces_region(region) && looks_like_digitalocean_spaces_bucket(bucket)
}

fn looks_like_digitalocean_spaces_origin_hostname(host: &str) -> bool {
    let Some(body) = digitalocean_spaces_body(host) else {
        return false;
    };
    if let Some((bucket, region)) = body.rsplit_once('.') {
        return looks_like_digitalocean_spaces_region(region)
            && looks_like_digitalocean_spaces_bucket(bucket);
    }

    looks_like_digitalocean_spaces_region(body)
}

fn one_valid_label_under<'a>(host: &'a str, suffix: &str) -> Option<&'a str> {
    let label = host.strip_suffix(suffix)?.strip_suffix('.')?;
    (!label.contains('.') && looks_like_dns_label(label)).then_some(label)
}

fn looks_like_numeric_label(label: &str) -> bool {
    looks_like_dns_label(label) && label.bytes().all(|byte| byte.is_ascii_digit())
}

fn looks_like_hubspot_named_system_label(label: &str) -> bool {
    label
        .rsplit_once('-')
        .is_some_and(|(name, hub_id)| !name.is_empty() && looks_like_numeric_label(hub_id))
}

fn looks_like_hubspot_system_hostname(host: &str) -> bool {
    const NUMERIC_ONLY_ROOTS: [&str; 1] = ["hs-sites.eu"];
    const NUMERIC_OR_NAMED_ROOTS: [&str; 5] = [
        "hs-sites.com",
        "hs-sites-eu1.com",
        "hs-sites-na2.com",
        "hs-sites-na3.com",
        "hs-sites-ap1.com",
    ];
    const NAMED_ONLY_ROOTS: [&str; 3] = ["hs-sites.net", "hs-sites.ca", "hs-sites.au"];
    const LEGACY_PAGE_BUILDER_ROOTS: [&str; 5] = [
        "hubspotpagebuilder.com",
        "hubspotpagebuilder.eu",
        "hubspotpagebuilder.net",
        "hubspotpagebuilder.ca",
        "hubspotpagebuilder.au",
    ];

    NUMERIC_ONLY_ROOTS
        .into_iter()
        .any(|suffix| one_valid_label_under(host, suffix).is_some_and(looks_like_numeric_label))
        || NUMERIC_OR_NAMED_ROOTS.into_iter().any(|suffix| {
            one_valid_label_under(host, suffix).is_some_and(|label| {
                looks_like_numeric_label(label) || looks_like_hubspot_named_system_label(label)
            })
        })
        || NAMED_ONLY_ROOTS.into_iter().any(|suffix| {
            one_valid_label_under(host, suffix).is_some_and(looks_like_hubspot_named_system_label)
        })
        || LEGACY_PAGE_BUILDER_ROOTS
            .into_iter()
            .any(|suffix| one_valid_label_under(host, suffix).is_some_and(looks_like_numeric_label))
}

fn looks_like_hubspot_site_cname(host: &str) -> bool {
    let parts = labels(host);
    parts.len() == 5
        && parts[2..] == ["sites", "hubspot", "net"]
        && looks_like_numeric_label(parts[0])
        && looks_like_dns_label(parts[1])
        && parts[1]
            .strip_prefix("group")
            .is_some_and(looks_like_numeric_label)
}

fn looks_like_webflow_platform_hostname(host: &str) -> bool {
    host == "cdn.webflow.com"
        || host == "proxy-ssl.webflow.com"
        || one_valid_label_under(host, "webflow.io").is_some()
}

fn looks_like_aws_region_label(label: &str) -> bool {
    [
        "us-", "af-", "ap-", "ca-", "cn-", "eu-", "il-", "me-", "mx-", "sa-", "eusc-",
    ]
    .iter()
    .any(|prefix| label.starts_with(prefix))
        && label.as_bytes().last().is_some_and(u8::is_ascii_digit)
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn aws_endpoint_root_len(parts: &[&str]) -> Option<usize> {
    if parts.ends_with(&["amazonaws", "com", "cn"]) {
        Some(3)
    } else if parts.ends_with(&["amazonaws", "com"]) {
        Some(2)
    } else {
        None
    }
}

fn looks_like_aws_s3_access_point_label(label: &str) -> bool {
    label.rsplit_once('-').is_some_and(|(name, account_id)| {
        !name.is_empty()
            && account_id.len() == 12
            && account_id.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn looks_like_aws_s3_data_hostname(host: &str) -> bool {
    let parts = labels(host);
    if parts.iter().any(|part| part.is_empty()) {
        return false;
    }
    let Some(root_len) = aws_endpoint_root_len(&parts) else {
        return false;
    };
    let body = &parts[..parts.len() - root_len];
    let is_china_partition = root_len == 3;

    if !is_china_partition && body.len() == 4 && body[1..] == ["mrap", "accesspoint", "s3-global"] {
        return true;
    }

    if !is_china_partition
        && body.len() == 3
        && body[1] == "s3-accesspoint"
        && looks_like_aws_s3_access_point_label(body[0])
        && looks_like_aws_region_label(body[2])
    {
        return true;
    }

    if !is_china_partition && body.len() == 2 && body[1] == "s3-accelerate" {
        return true;
    }
    if !is_china_partition && body.len() == 3 && body[1..] == ["s3-accelerate", "dualstack"] {
        return true;
    }

    if body == ["s3"] {
        return true;
    }
    if body.len() == 1
        && body[0]
            .strip_prefix("s3-")
            .is_some_and(looks_like_aws_region_label)
    {
        return true;
    }
    if body.len() == 2 && body[0] == "s3" && looks_like_aws_region_label(body[1]) {
        return true;
    }
    if body.len() == 3 && body[0..2] == ["s3", "dualstack"] && looks_like_aws_region_label(body[2])
    {
        return true;
    }

    if body.len() >= 4 {
        let n = body.len();
        if body[n - 3] == "s3"
            && body[n - 2] == "dualstack"
            && looks_like_aws_region_label(body[n - 1])
        {
            return true;
        }
    }

    if body.len() >= 3 {
        let n = body.len();
        if body[n - 2] == "s3" && looks_like_aws_region_label(body[n - 1]) {
            return true;
        }
    }

    if body.len() >= 2 {
        let service = body[body.len() - 1];
        if service == "s3" {
            return true;
        }
        if service
            .strip_prefix("s3-")
            .is_some_and(looks_like_aws_region_label)
        {
            return true;
        }
    }

    false
}

fn looks_like_azure_cloud_edge_hostname(host: &str) -> bool {
    let parts = labels(host);
    (parts.len() == 3 && parts[1..] == ["azureedge", "net"] && !parts[0].is_empty())
        || (parts.len() == 4 && parts[1..] == ["vo", "msecnd", "net"] && !parts[0].is_empty())
}

fn refine_edge_provider_family(elements: &mut Vec<PathElement>, family: &str, specific: &str) {
    let specific_index = elements.iter().position(|element| {
        element.role == PathElementRole::EdgeProvider && element.product == specific
    });
    let family_index = elements.iter().position(|element| {
        element.role == PathElementRole::EdgeProvider && element.product == family
    });
    let (Some(specific_index), Some(family_index)) = (specific_index, family_index) else {
        return;
    };

    let family_evidence = elements[family_index].evidence.clone();
    for evidence in family_evidence {
        if !elements[specific_index].evidence.contains(&evidence) {
            elements[specific_index].evidence.push(evidence);
        }
    }
    let _ = elements.remove(family_index);
}

fn add(elements: &mut Vec<PathElement>, role: PathElementRole, product: &str, evidence: String) {
    if let Some(existing) = elements
        .iter_mut()
        .find(|element| element.role == role && element.product == product)
    {
        if !existing.evidence.contains(&evidence) {
            existing.evidence.push(evidence);
        }
        return;
    }

    elements.push(PathElement {
        role,
        product: product.into(),
        classifier: ROUTING_CLASSIFIER_VERSION.into(),
        evidence: vec![evidence],
    });
}

/// Recognize provider-managed DNS aliases as routing/path participation.
///
/// `EdgeProvider` results are strong enough to originate a termination-provider
/// candidate in endpoint fusion. Other roles intentionally are not: DNS can
/// prove that a load balancer, API gateway, application platform, or traffic
/// steering service participates without proving it terminates the observed TLS
/// connection. Absence of one of these aliases is not negative evidence because
/// flattened/alias records can hide the provider-managed name from the client.
#[expect(
    clippy::too_many_lines,
    reason = "routing namespace recognition is an ordered audit table kept contiguous for reviewability"
)]
#[must_use]
pub fn detect_routing_elements(cname_chain: &[String]) -> Vec<PathElement> {
    let mut elements = Vec::new();

    for raw in cname_chain {
        let host = normalize_name(raw);
        if host.is_empty() {
            continue;
        }
        let evidence = format!("cname:{host}");

        if looks_like_akamai_netstorage_http_hostname(&host) {
            add(
                &mut elements,
                PathElementRole::OriginService,
                "akamai-netstorage",
                evidence,
            );
            continue;
        }

        if looks_like_google_cloud_storage_custom_domain_target(&host) {
            add(
                &mut elements,
                PathElementRole::OriginService,
                "google-cloud-storage",
                evidence,
            );
            continue;
        }

        if looks_like_azure_blob_storage_hostname(&host) {
            add(
                &mut elements,
                PathElementRole::OriginService,
                "azure-blob-storage",
                evidence,
            );
            continue;
        }

        if looks_like_backblaze_b2_s3_hostname(&host) {
            add(
                &mut elements,
                PathElementRole::OriginService,
                "backblaze-b2",
                evidence,
            );
            continue;
        }

        if looks_like_digitalocean_spaces_cdn_hostname(&host) {
            add(
                &mut elements,
                PathElementRole::EdgeProvider,
                "digitalocean-spaces-cdn",
                evidence.clone(),
            );
            add(
                &mut elements,
                PathElementRole::OriginService,
                "digitalocean-spaces",
                evidence,
            );
            continue;
        }

        if looks_like_digitalocean_spaces_origin_hostname(&host) {
            add(
                &mut elements,
                PathElementRole::OriginService,
                "digitalocean-spaces",
                evidence,
            );
            continue;
        }

        if looks_like_aws_s3_data_hostname(&host) {
            add(
                &mut elements,
                PathElementRole::OriginService,
                "aws-s3",
                evidence,
            );
            continue;
        }

        if one_valid_label_under(&host, "imgix.net").is_some() {
            add(
                &mut elements,
                PathElementRole::EdgeProvider,
                "imgix",
                evidence,
            );
            continue;
        }

        let edge_provider = [
            (
                "akamai",
                [
                    "edgekey.net",
                    "edgekey-staging.net",
                    "edgesuite.net",
                    "edgesuite-staging.net",
                    "akamaiedge.net",
                    "akamaihd.net",
                    "akamaized.net",
                ]
                .as_slice(),
            ),
            ("imperva", ["impervadns.net", "incapdns.net"].as_slice()),
            ("aws-cloudfront", ["cloudfront.net"].as_slice()),
            ("azure-front-door", ["azurefd.net"].as_slice()),
            ("fastly", ["fastly.net", "fastlylb.net"].as_slice()),
            ("cloudflare", ["cdn.cloudflare.net"].as_slice()),
            ("f5-volt", ["ac.vh.ves.io"].as_slice()),
            ("radware-cloud", ["radwarecloud.net"].as_slice()),
            ("keycdn", ["kxcdn.com"].as_slice()),
            ("bunnycdn", ["b-cdn.net"].as_slice()),
            ("cdn77", ["rsc.cdn77.org"].as_slice()),
            ("cachefly", ["cachefly.net"].as_slice()),
            ("gcore", ["gcdn.co"].as_slice()),
        ]
        .into_iter()
        .find_map(|(provider, suffixes)| {
            suffixes
                .iter()
                .any(|suffix| matches_suffix(&host, suffix))
                .then_some(provider)
        });

        if let Some(provider) = edge_provider {
            if provider == "azure-front-door" {
                add(
                    &mut elements,
                    PathElementRole::EdgeProvider,
                    provider,
                    evidence.clone(),
                );
                add(
                    &mut elements,
                    PathElementRole::ApplicationPlatform,
                    provider,
                    evidence,
                );
            } else {
                add(
                    &mut elements,
                    PathElementRole::EdgeProvider,
                    provider,
                    evidence,
                );
            }
            continue;
        }

        if looks_like_tencent_edgeone_edge_cname(&host) {
            add(
                &mut elements,
                PathElementRole::EdgeProvider,
                "tencent-edgeone",
                evidence,
            );
            continue;
        }

        if looks_like_tencent_edgeone_traffic_cname(&host) {
            add(
                &mut elements,
                PathElementRole::TrafficManagement,
                "tencent-edgeone",
                evidence,
            );
            continue;
        }

        if looks_like_alibaba_cloud_edge_cname(&host) {
            add(
                &mut elements,
                PathElementRole::EdgeProvider,
                "alibaba-cloud-edge",
                evidence,
            );
            continue;
        }

        if looks_like_quic_cloud_cdn_cname(&host) {
            add(
                &mut elements,
                PathElementRole::EdgeProvider,
                "quic-cloud",
                evidence,
            );
            continue;
        }

        if looks_like_railway_public_hostname(&host) {
            add(
                &mut elements,
                PathElementRole::EdgeProvider,
                "railway",
                evidence.clone(),
            );
            add(
                &mut elements,
                PathElementRole::ApplicationPlatform,
                "railway",
                evidence,
            );
            continue;
        }

        if looks_like_fly_app_hostname(&host) {
            add(
                &mut elements,
                PathElementRole::EdgeProvider,
                "fly-io",
                evidence.clone(),
            );
            add(
                &mut elements,
                PathElementRole::ApplicationPlatform,
                "fly-io",
                evidence,
            );
            continue;
        }

        if looks_like_aws_elb(&host) {
            add(
                &mut elements,
                PathElementRole::LoadBalancer,
                "aws-elastic-load-balancing",
                evidence,
            );
            continue;
        }

        if looks_like_aws_api_gateway(&host) {
            add(
                &mut elements,
                PathElementRole::ApiGateway,
                "aws-api-gateway",
                evidence,
            );
            continue;
        }

        if looks_like_azure_api_management_gateway(&host) {
            add(
                &mut elements,
                PathElementRole::ApiGateway,
                "azure-api-management",
                evidence,
            );
            continue;
        }

        if matches_suffix(&host, "trafficmanager.net") {
            add(
                &mut elements,
                PathElementRole::TrafficManagement,
                "azure-traffic-manager",
                evidence,
            );
            continue;
        }

        if matches_suffix(&host, "awsglobalaccelerator.com") {
            add(
                &mut elements,
                PathElementRole::TrafficManagement,
                "aws-global-accelerator",
                evidence,
            );
            continue;
        }

        if looks_like_netlify_ingress(&host) {
            add(
                &mut elements,
                PathElementRole::EdgeProvider,
                "netlify",
                evidence.clone(),
            );
            add(
                &mut elements,
                PathElementRole::ApplicationPlatform,
                "netlify",
                evidence,
            );
            continue;
        }

        if matches_suffix(&host, "netlify.com") {
            add(
                &mut elements,
                PathElementRole::ApplicationPlatform,
                "netlify",
                evidence,
            );
            continue;
        }

        if looks_like_vercel_ingress(&host) {
            add(
                &mut elements,
                PathElementRole::EdgeProvider,
                "vercel",
                evidence.clone(),
            );
            add(
                &mut elements,
                PathElementRole::ApplicationPlatform,
                "vercel",
                evidence,
            );
            continue;
        }

        if looks_like_render_public_hostname(&host) {
            add(
                &mut elements,
                PathElementRole::ApplicationPlatform,
                "render",
                evidence,
            );
            continue;
        }

        if looks_like_heroku_platform_hostname(&host) {
            add(
                &mut elements,
                PathElementRole::ApplicationPlatform,
                "heroku",
                evidence,
            );
            continue;
        }

        if looks_like_pantheon_platform_hostname(&host) {
            add(
                &mut elements,
                PathElementRole::ApplicationPlatform,
                "pantheon",
                evidence,
            );
            continue;
        }

        if looks_like_hubspot_system_hostname(&host) || looks_like_hubspot_site_cname(&host) {
            add(
                &mut elements,
                PathElementRole::ApplicationPlatform,
                "hubspot",
                evidence,
            );
            continue;
        }

        if looks_like_webflow_platform_hostname(&host) {
            add(
                &mut elements,
                PathElementRole::ApplicationPlatform,
                "webflow",
                evidence,
            );
            continue;
        }

        if looks_like_acquia_default_hostname(&host) {
            add(
                &mut elements,
                PathElementRole::ApplicationPlatform,
                "acquia-cloud-platform",
                evidence.clone(),
            );
            add(
                &mut elements,
                PathElementRole::OriginService,
                "acquia-cloud-platform",
                evidence,
            );
            continue;
        }

        if matches_suffix(&host, "azurewebsites.net") {
            add(
                &mut elements,
                PathElementRole::ApplicationPlatform,
                "azure-app-service",
                evidence,
            );
            continue;
        }

        if matches_suffix(&host, "elasticbeanstalk.com") {
            add(
                &mut elements,
                PathElementRole::ApplicationPlatform,
                "aws-elastic-beanstalk",
                evidence,
            );
            continue;
        }

        if looks_like_azure_cloud_edge_hostname(&host) {
            add(
                &mut elements,
                PathElementRole::EdgeProvider,
                "azure-cloud-edge",
                evidence,
            );
        }
    }

    refine_edge_provider_family(&mut elements, "azure-cloud-edge", "azure-front-door");
    elements
}
