use crate::model::{PathElement, PathElementRole};

pub const ROUTING_CLASSIFIER_VERSION: &str = "builtin-routing-v2";

fn normalize_name(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn matches_suffix(host: &str, suffix: &str) -> bool {
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

fn labels(host: &str) -> Vec<&str> {
    host.split('.').collect()
}

fn looks_like_vercel_dns(host: &str) -> bool {
    if matches_suffix(host, "vercel-dns.com") {
        return true;
    }
    let mut labels = host.rsplit('.');
    let Some(tld) = labels.next() else {
        return false;
    };
    let Some(base) = labels.next() else {
        return false;
    };
    tld == "com"
        && base.strip_prefix("vercel-dns-").is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
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

        let edge_provider = [
            (
                "akamai",
                ["edgekey.net", "edgesuite.net", "akamaiedge.net"].as_slice(),
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
            add(
                &mut elements,
                PathElementRole::EdgeProvider,
                provider,
                evidence,
            );
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

        if matches_suffix(&host, "netlify.app")
            || matches_suffix(&host, "netlify.com")
            || host == "apex-loadbalancer.netlify.com"
        {
            add(
                &mut elements,
                PathElementRole::ApplicationPlatform,
                "netlify",
                evidence,
            );
            continue;
        }

        if looks_like_vercel_dns(&host) {
            add(
                &mut elements,
                PathElementRole::ApplicationPlatform,
                "vercel",
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

        if matches_suffix(&host, "azureedge.net") {
            add(
                &mut elements,
                PathElementRole::ApplicationPlatform,
                "azure-cdn",
                evidence,
            );
        }
    }

    elements
}
