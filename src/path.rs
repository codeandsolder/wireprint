use crate::model::{Header, PathElement, PathElementRole};

pub const PATH_CLASSIFIER_VERSION: &str = "builtin-path-v6";

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

fn looks_like_akamai_grn(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(prefix) = parts.next() else {
        return false;
    };
    let Some(edge_id) = parts.next() else {
        return false;
    };
    let Some(timestamp) = parts.next() else {
        return false;
    };
    let Some(request_id) = parts.next() else {
        return false;
    };
    if parts.next().is_some()
        || prefix != "0"
        || edge_id.is_empty()
        || timestamp.is_empty()
        || request_id.is_empty()
    {
        return false;
    }

    edge_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        && timestamp.bytes().all(|byte| byte.is_ascii_digit())
        && request_id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn looks_like_fastly_x_timer(value: &str) -> bool {
    let mut parts = value.split(',');
    let Some(start) = parts.next().and_then(|part| part.strip_prefix('S')) else {
        return false;
    };
    let Some(varnish_start) = parts.next() else {
        return false;
    };
    let Some(varnish_end) = parts.next().and_then(|part| part.strip_prefix("VE")) else {
        return false;
    };
    if parts.next().is_some() || varnish_start != "VS0" || varnish_end.is_empty() {
        return false;
    }

    let Some((seconds, fraction)) = start.split_once('.') else {
        return false;
    };
    if seconds.is_empty()
        || fraction.is_empty()
        || !seconds.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }

    varnish_end.bytes().all(|byte| byte.is_ascii_digit())
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
#[expect(
    clippy::too_many_lines,
    reason = "response marker recognition is an ordered audit table; splitting it would obscure precedence and deduplication"
)]
#[must_use]
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
    if has_header(headers, "cf-cache-status") {
        add(
            &mut elements,
            PathElementRole::Cache,
            "cloudflare",
            "header:cf-cache-status",
        );
    }
    if server.contains("keycdn-engine") {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "keycdn",
            "server:keycdn-engine",
        );
        if has_header(headers, "x-cache") {
            add(
                &mut elements,
                PathElementRole::Cache,
                "keycdn",
                "header:x-cache+server:keycdn-engine",
            );
        }
    }
    if has_header(headers, "x-qc-pop") {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "quic-cloud",
            "header:x-qc-pop",
        );
    }
    if has_header(headers, "x-qc-cache") {
        add(
            &mut elements,
            PathElementRole::Cache,
            "quic-cloud",
            "header:x-qc-cache",
        );
    }
    if has_header(headers, "x-77-pop") {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "cdn77",
            "header:x-77-pop",
        );
    }
    if has_header(headers, "x-77-cache") || has_header(headers, "x-77-age") {
        add(
            &mut elements,
            PathElementRole::Cache,
            "cdn77",
            if has_header(headers, "x-77-cache") {
                "header:x-77-cache"
            } else {
                "header:x-77-age"
            },
        );
    }
    if has_header(headers, "eo-log-uuid") || has_header_value(headers, "server", "TencentEdgeOne") {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "tencent-edgeone",
            if has_header(headers, "eo-log-uuid") {
                "header:eo-log-uuid"
            } else {
                "server:tencentedgeone"
            },
        );
    }
    if has_header(headers, "eo-cache-status") {
        add(
            &mut elements,
            PathElementRole::Cache,
            "tencent-edgeone",
            "header:eo-cache-status",
        );
    }
    if has_header(headers, "eagleid") {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "alibaba-cloud-edge",
            "header:eagleid",
        );
    }
    if has_header(headers, "x-swift-savetime")
        || has_header(headers, "x-swift-cachetime")
        || has_header(headers, "ali-swift-global-savetime")
    {
        let evidence = if has_header(headers, "x-swift-savetime") {
            "header:x-swift-savetime"
        } else if has_header(headers, "x-swift-cachetime") {
            "header:x-swift-cachetime"
        } else {
            "header:ali-swift-global-savetime"
        };
        add(
            &mut elements,
            PathElementRole::Cache,
            "alibaba-cloud-cdn",
            evidence,
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
    if header_values(headers, "x-cdn-traceid").any(looks_like_akamai_grn) {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "akamai",
            "header:x-cdn-traceid-akamai-grn-shape",
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
    if header_values(headers, "x-timer").any(looks_like_fastly_x_timer) {
        add(
            &mut elements,
            PathElementRole::Cache,
            "fastly",
            "header:x-timer-fastly-shape",
        );
    }
    if via.contains("fastly")
        || has_header(headers, "fastly-restarts")
        || has_header(headers, "x-fastly-backend-reqs")
        || has_header_prefix(headers, "fastly-debug-")
    {
        let evidence = if has_header_prefix(headers, "fastly-debug-") {
            "header:fastly-debug-*"
        } else {
            "marker:fastly-cache-participation"
        };
        add(&mut elements, PathElementRole::Cache, "fastly", evidence);
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
    if has_header(headers, "x-sucuri-cache") {
        add(
            &mut elements,
            PathElementRole::Cache,
            "sucuri",
            "header:x-sucuri-cache",
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
    if has_header(headers, "cdn-pullzone")
        || has_header(headers, "cdn-requestid")
        || has_header(headers, "cdn-edgestorageid")
    {
        let evidence = if has_header(headers, "cdn-pullzone") {
            "header:cdn-pullzone"
        } else if has_header(headers, "cdn-requestid") {
            "header:cdn-requestid"
        } else {
            "header:cdn-edgestorageid"
        };
        add(&mut elements, PathElementRole::Cache, "bunnycdn", evidence);
    }
    if ["gws", "esf", "google frontend"]
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
    if has_header(headers, "x-vercel-cache") {
        add(
            &mut elements,
            PathElementRole::Cache,
            "vercel",
            "header:x-vercel-cache",
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
    if has_header(headers, "x-railway-edge") {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "railway",
            "header:x-railway-edge",
        );
    }
    if has_header(headers, "x-railway-edge") || has_header(headers, "x-railway-upstream-zone") {
        add(
            &mut elements,
            PathElementRole::ApplicationPlatform,
            "railway",
            if has_header(headers, "x-railway-upstream-zone") {
                "header:x-railway-upstream-zone"
            } else {
                "header:x-railway-edge"
            },
        );
    }
    if has_header(headers, "x-pantheon-styx-hostname") || has_header(headers, "x-styx-req-id") {
        add(
            &mut elements,
            PathElementRole::ApplicationPlatform,
            "pantheon",
            if has_header(headers, "x-pantheon-styx-hostname") {
                "header:x-pantheon-styx-hostname"
            } else {
                "header:x-styx-req-id"
            },
        );
    }
    if has_header(headers, "x-ah-environment") || has_header(headers, "x-ah-app-trace") {
        add(
            &mut elements,
            PathElementRole::ApplicationPlatform,
            "acquia-cloud-platform",
            if has_header(headers, "x-ah-environment") {
                "header:x-ah-environment"
            } else {
                "header:x-ah-app-trace"
            },
        );
    }
    if via.contains("vegur") {
        add(
            &mut elements,
            PathElementRole::ApplicationPlatform,
            "heroku",
            "via:vegur",
        );
    }
    if has_cookie(&cookies, "arraffinity") || has_cookie(&cookies, "arraffinitysamesite") {
        add(
            &mut elements,
            PathElementRole::LoadBalancer,
            "azure-arr-affinity",
            if has_cookie(&cookies, "arraffinitysamesite") {
                "cookie:ARRAffinitySameSite"
            } else {
                "cookie:ARRAffinity"
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

    if server.starts_with("apisix/")
        || has_header(headers, "x-apisix-upstream-status")
        || has_header(headers, "apisix-plugins")
    {
        let evidence = if server.starts_with("apisix/") {
            "server:apisix"
        } else if has_header(headers, "x-apisix-upstream-status") {
            "header:x-apisix-upstream-status"
        } else {
            "header:apisix-plugins"
        };
        add(
            &mut elements,
            PathElementRole::ApiGateway,
            "apache-apisix",
            evidence,
        );
    }
    if has_header_prefix(headers, "x-krakend-") {
        add(
            &mut elements,
            PathElementRole::ApiGateway,
            "krakend",
            "header:x-krakend-*",
        );
    }
    if has_header(headers, "x-tyk-cached-response")
        || header_values(headers, "x-generator").any(|value| value.eq_ignore_ascii_case("tyk.io"))
    {
        add(
            &mut elements,
            PathElementRole::ApiGateway,
            "tyk",
            if has_header(headers, "x-tyk-cached-response") {
                "header:x-tyk-cached-response"
            } else {
                "header:x-generator=tyk.io"
            },
        );
    }
    if has_header(headers, "x-gravitee-request-id")
        || has_header(headers, "x-gravitee-transaction-id")
    {
        add(
            &mut elements,
            PathElementRole::ApiGateway,
            "gravitee",
            if has_header(headers, "x-gravitee-request-id") {
                "header:x-gravitee-request-id"
            } else {
                "header:x-gravitee-transaction-id"
            },
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
        if cookie.starts_with("awselbauthsessioncookie") {
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
        if matches!(cookie.as_str(), "gclb" | "gcilb") {
            add(
                &mut elements,
                PathElementRole::LoadBalancer,
                "google-cloud-application-load-balancer",
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
    if has_cookie(&cookies, "x-oracle-bmc-lbs-route") {
        add(
            &mut elements,
            PathElementRole::LoadBalancer,
            "oracle-cloud-load-balancer",
            "cookie:X-Oracle-BMC-LBS-Route",
        );
    }

    if has_header_value(headers, "server", "awselb/2.0") {
        add(
            &mut elements,
            PathElementRole::LoadBalancer,
            "aws-application-load-balancer",
            "server:awselb/2.0",
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
    if has_header(headers, "l5d-proxy-error")
        || has_header(headers, "l5d-proxy-connection")
        || has_header(headers, "l5d-client-id")
    {
        let evidence = if has_header(headers, "l5d-proxy-error") {
            "header:l5d-proxy-error"
        } else if has_header(headers, "l5d-client-id") {
            "header:l5d-client-id"
        } else {
            "header:l5d-proxy-connection"
        };
        add(
            &mut elements,
            PathElementRole::ServiceMesh,
            "linkerd",
            evidence,
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
    if has_header_value(headers, "server", "UploadServer") {
        add(
            &mut elements,
            PathElementRole::ServerImplementation,
            "google-uploadserver",
            "server:uploadserver",
        );
    }
    if has_header_value(headers, "server", "sffe") {
        add(
            &mut elements,
            PathElementRole::ServerImplementation,
            "sffe",
            "server:sffe",
        );
    }
    if has_header_value(headers, "server", "GSE") {
        add(
            &mut elements,
            PathElementRole::ServerImplementation,
            "gse",
            "server:gse",
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

    // Explicit backend/origin services. These can coexist with any outer
    // edge/cache/gateway marker preserved in the same response.
    if has_header_value(headers, "server", "AmazonS3") {
        add(
            &mut elements,
            PathElementRole::OriginService,
            "aws-s3",
            "server:amazons3",
        );
    } else if has_header(headers, "x-amz-bucket-region") {
        add(
            &mut elements,
            PathElementRole::OriginService,
            "s3-compatible-object-storage",
            "header:x-amz-bucket-region",
        );
    }
    if server.starts_with("minio") || has_header(headers, "x-minio-deployment-id") {
        add(
            &mut elements,
            PathElementRole::OriginService,
            "minio",
            if has_header(headers, "x-minio-deployment-id") {
                "header:x-minio-deployment-id"
            } else {
                "server:minio"
            },
        );
    }
    if server.contains("akamainetstorage") {
        add(
            &mut elements,
            PathElementRole::OriginService,
            "akamai-netstorage",
            "server:akamainetstorage",
        );
    }
    if has_header(headers, "x-goog-storage-class")
        || (has_header(headers, "x-goog-generation")
            && has_header(headers, "x-goog-metageneration"))
    {
        add(
            &mut elements,
            PathElementRole::OriginService,
            "google-cloud-storage",
            if has_header(headers, "x-goog-storage-class") {
                "header:x-goog-storage-class"
            } else {
                "headers:x-goog-generation+x-goog-metageneration"
            },
        );
    }
    if has_header(headers, "x-ms-blob-type") || server.contains("windows-azure-blob") {
        add(
            &mut elements,
            PathElementRole::OriginService,
            "azure-blob-storage",
            if has_header(headers, "x-ms-blob-type") {
                "header:x-ms-blob-type"
            } else {
                "server:windows-azure-blob"
            },
        );
    }
    if has_header(headers, "x-bz-file-id") || has_header(headers, "x-bz-file-name") {
        add(
            &mut elements,
            PathElementRole::OriginService,
            "backblaze-b2",
            if has_header(headers, "x-bz-file-id") {
                "header:x-bz-file-id"
            } else {
                "header:x-bz-file-name"
            },
        );
    }

    // Identity-aware proxies and traffic-management layers.
    if has_header(headers, "x-goog-iap-generated-response") {
        add(
            &mut elements,
            PathElementRole::IdentityProxy,
            "google-cloud-iap",
            "header:x-goog-iap-generated-response",
        );
    }
    if has_cookie(&cookies, "cf_authorization") {
        add(
            &mut elements,
            PathElementRole::IdentityProxy,
            "cloudflare-access",
            "cookie:CF_Authorization",
        );
    }
    if has_cookie(&cookies, "_oauth2_proxy") || has_cookie_prefix(&cookies, "_oauth2_proxy_") {
        add(
            &mut elements,
            PathElementRole::IdentityProxy,
            "oauth2-proxy",
            if has_cookie(&cookies, "_oauth2_proxy") {
                "cookie:_oauth2_proxy"
            } else {
                "cookie:_oauth2_proxy_*"
            },
        );
    }
    if has_cookie(&cookies, "authelia_session") {
        add(
            &mut elements,
            PathElementRole::IdentityProxy,
            "authelia",
            "cookie:authelia_session",
        );
    }
    if header_values(headers, "location").any(|value| value.contains("/outpost.goauthentik.io/")) {
        add(
            &mut elements,
            PathElementRole::IdentityProxy,
            "authentik",
            "location:/outpost.goauthentik.io/",
        );
    }
    if has_cookie_prefix(&cookies, "__cfwaitingroom") {
        add(
            &mut elements,
            PathElementRole::TrafficManagement,
            "cloudflare-waiting-room",
            "cookie:__cfwaitingroom*",
        );
    }
    if has_cookie_prefix(&cookies, "queueitaccepted-sdfrts345e-v3_")
        || has_cookie(&cookies, "queue-it-visitorsession")
    {
        add(
            &mut elements,
            PathElementRole::TrafficManagement,
            "queue-it",
            if has_cookie_prefix(&cookies, "queueitaccepted-sdfrts345e-v3_") {
                "cookie:QueueITAccepted-SDFrts345E-V3_*"
            } else {
                "cookie:Queue-it-visitorsession"
            },
        );
    }

    // Security and bot-management middleware.
    if has_cookie_prefix(&cookies, "awselbauthsessioncookie") {
        add(
            &mut elements,
            PathElementRole::SecurityMiddleware,
            "aws-alb-authentication",
            "cookie:AWSELBAuthSessionCookie*",
        );
    }
    if has_header(headers, "x-amzn-waf-action") || has_cookie(&cookies, "aws-waf-token") {
        add(
            &mut elements,
            PathElementRole::Waf,
            "aws-waf",
            if has_header(headers, "x-amzn-waf-action") {
                "header:x-amzn-waf-action"
            } else {
                "cookie:aws-waf-token"
            },
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
    if has_cookie(&cookies, "__cfruid") || has_cookie(&cookies, "_cfuvid") {
        add(
            &mut elements,
            PathElementRole::SecurityMiddleware,
            "cloudflare-rate-limiting",
            if has_cookie(&cookies, "__cfruid") {
                "cookie:__cfruid"
            } else {
                "cookie:_cfuvid"
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
        || has_cookie(&cookies, "bm_sv")
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
