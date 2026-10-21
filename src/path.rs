use crate::model::{Header, PathElement, PathElementRole};

pub const PATH_CLASSIFIER_VERSION: &str = "builtin-path-v1";

fn header_values<'a>(headers: &'a [Header], name: &str) -> impl Iterator<Item = &'a str> {
    headers
        .iter()
        .filter(move |header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

fn has_header(headers: &[Header], name: &str) -> bool {
    header_values(headers, name).next().is_some()
}

fn has_header_prefix(headers: &[Header], prefix: &str) -> bool {
    headers
        .iter()
        .any(|header| header.name.to_ascii_lowercase().starts_with(prefix))
}

fn joined_header_values(headers: &[Header], name: &str) -> String {
    header_values(headers, name)
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn has_header_value(headers: &[Header], name: &str, value: &str) -> bool {
    header_values(headers, name).any(|candidate| candidate.eq_ignore_ascii_case(value))
}

fn cookie_names(headers: &[Header]) -> Vec<String> {
    header_values(headers, "set-cookie")
        .filter_map(|value| value.split(';').next())
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, _)| name.trim().to_ascii_lowercase())
        .collect()
}

fn add(
    elements: &mut Vec<PathElement>,
    role: PathElementRole,
    product: &str,
    evidence: impl Into<String>,
) {
    let evidence = evidence.into();
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
        classifier: PATH_CLASSIFIER_VERSION.into(),
        evidence: vec![evidence],
    });
}

fn has_cookie(cookies: &[String], name: &str) -> bool {
    cookies
        .iter()
        .any(|cookie| cookie.eq_ignore_ascii_case(name))
}

fn has_cookie_prefix(cookies: &[String], prefix: &str) -> bool {
    let prefix = prefix.to_ascii_lowercase();
    cookies.iter().any(|cookie| cookie.starts_with(&prefix))
}

fn looks_like_f5_asm_ts_cookie(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix("ts") else {
        return false;
    };
    suffix.len() >= 8 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Recognize network-path participation from ordinary response metadata.
///
/// The result is deliberately an unordered set of participation claims. A
/// downstream marker (for example `x-vercel-id` or `x-azure-ref`) does not
/// establish that product as the outer TLS termination provider.
pub fn detect_path_elements(headers: &[Header]) -> Vec<PathElement> {
    let mut elements = Vec::new();
    let cookies = cookie_names(headers);
    let server = joined_header_values(headers, "server");
    let via = joined_header_values(headers, "via");

    // Serving / termination providers. Keep these markers explicit enough to
    // survive known cross-provider cache-header collisions.
    if has_header(headers, "cf-ray") || server.contains("cloudflare") {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "cloudflare",
            if has_header(headers, "cf-ray") {
                "header:cf-ray"
            } else {
                "server:cloudflare"
            },
        );
    }
    if has_header(headers, "x-amz-cf-id")
        || has_header(headers, "x-amz-cf-pop")
        || server.contains("cloudfront")
        || via.contains("cloudfront")
    {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "aws-cloudfront",
            "marker:cloudfront",
        );
    }
    if server.contains("akamaighost")
        || server.contains("akamainetstorage")
        || has_header(headers, "akamai-grn")
        || has_header(headers, "akamai-request-bc")
        || headers
            .iter()
            .any(|header| header.name.to_ascii_lowercase().starts_with("x-akamai"))
    {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "akamai",
            "marker:akamai-edge",
        );
    }
    if server.contains("fastly") || has_header_value(headers, "server", "Artisanal bits") {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "fastly",
            if has_header_value(headers, "server", "Artisanal bits") {
                "server:artisanal-bits"
            } else {
                "server:fastly"
            },
        );
    }
    if via.contains("fastly")
        || has_header(headers, "fastly-restarts")
        || has_header(headers, "x-fastly-backend-reqs")
        || has_header_prefix(headers, "fastly-debug-")
    {
        add(
            &mut elements,
            PathElementRole::Cache,
            "fastly",
            "marker:fastly-cache-participation",
        );
    }
    if server.contains("volt-adc") || has_header(headers, "x-volterra-location") {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "f5-volt",
            "marker:f5-volt",
        );
    }
    if header_values(headers, "x-cdn").any(|value| value.eq_ignore_ascii_case("imperva")) {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "imperva",
            "header:x-cdn=imperva",
        );
    }
    if has_header(headers, "x-sucuri-id")
        || has_header(headers, "x-sucuri-cache")
        || server.contains("sucuri")
    {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "sucuri",
            "marker:sucuri",
        );
    }
    if server.contains("bunnycdn") {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "bunnycdn",
            "server:bunnycdn",
        );
    }
    if ["gws", "esf", "uploadserver"]
        .iter()
        .any(|value| has_header_value(headers, "server", value))
    {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "google-gfe",
            format!("server:{server}"),
        );
    }
    if server.contains("openresty edge") {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "openresty-edge",
            "server:openresty-edge",
        );
    }
    if server.contains("vercel") {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "vercel",
            "server:vercel",
        );
    }
    if server.contains("netlify") {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "netlify",
            "server:netlify",
        );
    }

    if server.starts_with("fly/") || via.contains("fly.io") || has_header(headers, "fly-request-id")
    {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "fly-io",
            "marker:fly-io",
        );
    }

    // Delivery/application platforms: participation evidence, not necessarily the outer edge.
    if has_header(headers, "x-vercel-id") {
        add(
            &mut elements,
            PathElementRole::ApplicationPlatform,
            "vercel",
            "header:x-vercel-id",
        );
    }
    if has_header(headers, "x-nf-request-id") {
        add(
            &mut elements,
            PathElementRole::ApplicationPlatform,
            "netlify",
            "header:x-nf-request-id",
        );
    }
    if has_header(headers, "x-azure-ref") {
        add(
            &mut elements,
            PathElementRole::ApplicationPlatform,
            "azure-front-door",
            "header:x-azure-ref",
        );
    }

    if has_header(headers, "rndr-id") {
        add(
            &mut elements,
            PathElementRole::ApplicationPlatform,
            "render",
            "header:rndr-id",
        );
    }
    if has_header(headers, "x-railway-edge") || has_header(headers, "x-railway-upstream-zone") {
        add(
            &mut elements,
            PathElementRole::ApplicationPlatform,
            "railway",
            if has_header(headers, "x-railway-edge") {
                "header:x-railway-edge"
            } else {
                "header:x-railway-upstream-zone"
            },
        );
    }

    // API gateways.
    if has_header(headers, "x-amz-apigw-id") || has_header(headers, "apigw-requestid") {
        add(
            &mut elements,
            PathElementRole::ApiGateway,
            "aws-api-gateway",
            if has_header(headers, "x-amz-apigw-id") {
                "header:x-amz-apigw-id"
            } else {
                "header:apigw-requestid"
            },
        );
    }
    if server.starts_with("kong/")
        || via.contains("kong/")
        || has_header(headers, "x-kong-request-id")
        || has_header(headers, "x-kong-proxy-latency")
        || has_header(headers, "x-kong-upstream-latency")
        || has_header(headers, "x-kong-response-latency")
        || has_header(headers, "x-kong-total-latency")
        || has_header(headers, "x-kong-third-party-latency")
        || has_header(headers, "x-kong-client-latency")
    {
        add(
            &mut elements,
            PathElementRole::ApiGateway,
            "kong",
            "marker:kong-gateway",
        );
    }

    // Load balancers. Cookie markers only establish participation somewhere on the path.
    for cookie in &cookies {
        if matches!(
            cookie.as_str(),
            "awsalb" | "awsalbcors" | "awsalbtg" | "awsalbtgcors"
        ) || cookie.starts_with("awsalbapp-")
        {
            add(
                &mut elements,
                PathElementRole::LoadBalancer,
                "aws-application-load-balancer",
                format!("cookie:{cookie}"),
            );
        }
        if matches!(cookie.as_str(), "awselb" | "awselbcors") {
            add(
                &mut elements,
                PathElementRole::LoadBalancer,
                "aws-classic-load-balancer",
                format!("cookie:{cookie}"),
            );
        }
        if cookie.starts_with("bigipserver") {
            add(
                &mut elements,
                PathElementRole::LoadBalancer,
                "f5-big-ip-ltm",
                format!("cookie:{cookie}"),
            );
        }
        if cookie.starts_with("nsc_") {
            add(
                &mut elements,
                PathElementRole::LoadBalancer,
                "netscaler-adc",
                format!("cookie:{cookie}"),
            );
        }
        if matches!(
            cookie.as_str(),
            "applicationgatewayaffinity" | "applicationgatewayaffinitycors"
        ) {
            add(
                &mut elements,
                PathElementRole::LoadBalancer,
                "azure-application-gateway",
                format!("cookie:{cookie}"),
            );
        }
    }
    if has_cookie(&cookies, "__cflb") {
        add(
            &mut elements,
            PathElementRole::LoadBalancer,
            "cloudflare-load-balancer",
            "cookie:__cflb",
        );
    }

    if via.contains("1.1 google") {
        add(
            &mut elements,
            PathElementRole::LoadBalancer,
            "google-cloud-application-load-balancer",
            "via:1.1-google",
        );
    }

    // Reverse proxies, caches and server implementations. These never elevate themselves into managed-provider identity.
    if has_header_value(headers, "server", "envoy")
        || server.contains("istio-envoy")
        || has_header(headers, "x-envoy-upstream-service-time")
        || has_header(headers, "x-envoy-overloaded")
    {
        add(
            &mut elements,
            PathElementRole::ReverseProxy,
            "envoy",
            "marker:envoy",
        );
    }
    if server.contains("istio-envoy") {
        add(
            &mut elements,
            PathElementRole::ServiceMesh,
            "istio",
            "server:istio-envoy",
        );
    }
    if server.starts_with("nginx") {
        add(
            &mut elements,
            PathElementRole::ServerImplementation,
            "nginx",
            "server:nginx",
        );
    }
    if server.contains("openresty") && !server.contains("openresty edge") {
        add(
            &mut elements,
            PathElementRole::ServerImplementation,
            "openresty",
            "server:openresty",
        );
    }
    if server.contains("caddy") {
        add(
            &mut elements,
            PathElementRole::ServerImplementation,
            "caddy",
            "server:caddy",
        );
    }
    if server.contains("nghttpx") || via.contains("nghttpx") {
        add(
            &mut elements,
            PathElementRole::ReverseProxy,
            "nghttpx",
            "marker:nghttpx",
        );
    }
    if server.contains("haproxy")
        || via.contains("haproxy")
        || has_header(headers, "x-haproxy-recruits")
    {
        add(
            &mut elements,
            PathElementRole::ReverseProxy,
            "haproxy",
            "marker:haproxy",
        );
    }
    if server.starts_with("traefik") {
        add(
            &mut elements,
            PathElementRole::ReverseProxy,
            "traefik",
            "server:traefik",
        );
    }
    if server.starts_with("squid") || via.contains("squid") || has_header(headers, "x-squid-error")
    {
        add(
            &mut elements,
            PathElementRole::Cache,
            "squid",
            "marker:squid",
        );
    }
    if server.starts_with("apache") {
        add(
            &mut elements,
            PathElementRole::ServerImplementation,
            "apache-http-server",
            "server:apache",
        );
    }
    if server.starts_with("microsoft-iis") {
        add(
            &mut elements,
            PathElementRole::ServerImplementation,
            "microsoft-iis",
            "server:microsoft-iis",
        );
    }
    if server.contains("litespeed") {
        add(
            &mut elements,
            PathElementRole::ServerImplementation,
            "litespeed",
            "server:litespeed",
        );
    }
    if has_header(headers, "x-varnish") || via.contains("varnish") {
        add(
            &mut elements,
            PathElementRole::Cache,
            "varnish",
            if has_header(headers, "x-varnish") {
                "header:x-varnish"
            } else {
                "via:varnish"
            },
        );
    }
    if server.contains("apachetrafficserver")
        || server.contains("traffic server")
        || via.contains("apachetrafficserver")
        || via.contains("traffic-server")
    {
        add(
            &mut elements,
            PathElementRole::Cache,
            "apache-traffic-server",
            "marker:apache-traffic-server",
        );
    }

    // Security and bot-management middleware.
    if has_header(headers, "x-amzn-waf-action") {
        add(
            &mut elements,
            PathElementRole::Waf,
            "aws-waf",
            "header:x-amzn-waf-action",
        );
    }
    if has_header(headers, "cf-mitigated") || has_cookie(&cookies, "cf_clearance") {
        add(
            &mut elements,
            PathElementRole::SecurityMiddleware,
            "cloudflare-security",
            if has_header(headers, "cf-mitigated") {
                "header:cf-mitigated"
            } else {
                "cookie:cf_clearance"
            },
        );
    }
    if has_cookie(&cookies, "__cf_bm") {
        add(
            &mut elements,
            PathElementRole::BotManagement,
            "cloudflare-bot-management",
            "cookie:__cf_bm",
        );
    }
    if has_cookie(&cookies, "ak_bmsc")
        || has_cookie(&cookies, "bm_sz")
        || has_cookie(&cookies, "_abck")
    {
        add(
            &mut elements,
            PathElementRole::BotManagement,
            "akamai-bot-manager",
            "cookie:akamai-bot",
        );
    }
    if has_header_value(headers, "server", "DataDome")
        || has_header(headers, "x-datadome")
        || has_cookie(&cookies, "datadome")
    {
        add(
            &mut elements,
            PathElementRole::BotManagement,
            "datadome",
            "marker:datadome",
        );
    }
    if headers
        .iter()
        .any(|header| header.name.to_ascii_lowercase().starts_with("x-px"))
        || has_cookie(&cookies, "_px3")
        || has_cookie(&cookies, "_pxvid")
        || has_cookie(&cookies, "_pxhd")
    {
        add(
            &mut elements,
            PathElementRole::BotManagement,
            "human-perimeterx",
            "marker:perimeterx",
        );
    }
    if has_cookie(&cookies, "cookiesession1") {
        add(
            &mut elements,
            PathElementRole::Waf,
            "fortiweb",
            "cookie:cookiesession1",
        );
    }
    if has_header(headers, "x-iinfo")
        || has_cookie_prefix(&cookies, "visid_incap_")
        || has_cookie_prefix(&cookies, "incap_ses_")
        || has_cookie_prefix(&cookies, "nlbi_")
    {
        add(
            &mut elements,
            PathElementRole::Waf,
            "imperva-waf",
            "marker:imperva-waf",
        );
    }
    if cookies.iter().any(|name| looks_like_f5_asm_ts_cookie(name)) {
        add(
            &mut elements,
            PathElementRole::Waf,
            "f5-big-ip-asm",
            "cookie:f5-asm-ts",
        );
    }

    elements
}
