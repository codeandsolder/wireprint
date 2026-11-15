use crate::model::{Header, PathElement, PathElementRole};

pub const PATH_CLASSIFIER_VERSION: &str = "builtin-path-v14";

fn header_values<'a>(headers: &'a [Header], name: &str) -> impl Iterator<Item = &'a str> {
    headers
        .iter()
        .filter(move |header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

fn has_header(headers: &[Header], name: &str) -> bool {
    header_values(headers, name).next().is_some()
}

fn has_nonempty_header(headers: &[Header], name: &str) -> bool {
    header_values(headers, name).any(|value| !value.trim().is_empty())
}

// X-Tt-Trace-Tag is a reserved ByteDance CDN header, but trace-only tags
// (such as id=5) do not prove cache participation. Require the named
// cdn-cache field, without assuming a closed set of cache result values.
fn bytedance_cdn_cache_tag(value: &str) -> bool {
    value.split(';').any(|field| {
        field.trim().split_once('=').is_some_and(|(key, status)| {
            key.trim().eq_ignore_ascii_case("cdn-cache") && !status.trim().is_empty()
        })
    })
}

// Parse Server-Timing metric boundaries without mistaking commas in quoted
// descriptions for new metric names.
fn server_timing_has_metric(value: &str, sought: &str) -> bool {
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in value.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if quoted => escaped = true,
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                if value[start..index]
                    .split(';')
                    .next()
                    .is_some_and(|metric| metric.trim().eq_ignore_ascii_case(sought))
                {
                    return true;
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    !quoted
        && value[start..]
            .split(';')
            .next()
            .is_some_and(|metric| metric.trim().eq_ignore_ascii_case(sought))
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

fn looks_like_aws_s3_request_id(value: &str) -> bool {
    value.len() == 16
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
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

// A normalized archive may have joined several Set-Cookie header fields with
// newlines. Do not split on commas: Expires dates contain them.
fn cookie_names(headers: &[Header]) -> Vec<String> {
    header_values(headers, "set-cookie")
        .flat_map(|value| value.split(['\r', '\n']))
        .filter_map(|line| line.split(';').next())
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, _)| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect()
}

// Parse product tokens in a Server-shaped header, with optional versions
// and Jetty-style comments. Ignore product names inside RFC comments.
// Multiple products and comma-combined values are supported.
fn header_has_product(headers: &[Header], header_name: &str, product: &str) -> bool {
    header_values(headers, header_name).any(|value| {
        let mut comment_depth = 0u32;
        let mut escaped = false;
        let mut token_start = None;
        for (idx, byte) in value.bytes().chain(std::iter::once(b' ')).enumerate() {
            if comment_depth > 0 {
                if escaped {
                    escaped = false;
                } else {
                    match byte {
                        b'\\' => escaped = true,
                        b'(' => comment_depth += 1,
                        b')' => comment_depth -= 1,
                        _ => {}
                    }
                }
                continue;
            }
            if matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b',' | b'(') {
                if let Some(start) = token_start.take() {
                    let token = &value[start..idx];
                    let (name, version) = token
                        .split_once('/')
                        .map_or((token, None), |(name, version)| (name, Some(version)));
                    if name.eq_ignore_ascii_case(product)
                        && version
                            .is_none_or(|version| !version.is_empty() && !version.contains('/'))
                    {
                        return true;
                    }
                }
                if byte == b'(' {
                    comment_depth = 1;
                }
            } else if token_start.is_none() {
                token_start = Some(idx);
            }
        }
        false
    })
}

fn server_has_product(headers: &[Header], product: &str) -> bool {
    header_has_product(headers, "server", product)
}

fn looks_like_ddos_guard_cookie(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix("__ddg") else {
        return false;
    };
    // Legacy __ddgid / __ddgmark and numbered DDoS-Guard families, including
    // current __ddg8_ / __ddg9_ / __ddg10_ captures. Do not accept arbitrary
    // __ddg-prefixed application names.
    if matches!(suffix, "id" | "mark") {
        return true;
    }
    let digit_count = suffix.bytes().take_while(u8::is_ascii_digit).count();
    if digit_count == 0 {
        return false;
    }
    let tail = &suffix[digit_count..];
    tail.is_empty()
        || tail.strip_prefix('_').is_some_and(|rest| {
            rest.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}

// Gcore uses CDN node identifiers such as wa2-hw-edge-gc9 and
// am3-hw-edge-gpig-gc96. X-ID alone is generic (and collides with
// application services), so detection requires both shaped node headers.
fn looks_like_gcore_node(value: &str) -> bool {
    let Some((region, node)) = value.trim().split_once("-hw-edge-") else {
        return false;
    };
    if region.is_empty()
        || !region
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return false;
    }
    let digits = if let Some(digits) = node.strip_prefix("gc") {
        digits
    } else if let Some((flavor, digits)) = node.rsplit_once("-gc") {
        if flavor.is_empty()
            || !flavor
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return false;
        }
        digits
    } else {
        return false;
    };
    (1..=3).contains(&digits.len()) && digits.bytes().all(|byte| byte.is_ascii_digit())
}

// CacheFly's X-CF1 exposes a first-layer node and cache state; X-CF2 is a
// separate stage. Require both and a recognizable CacheFly node grammar.
fn looks_like_cachefly_x_cf1(value: &str) -> bool {
    let mut parts = value.trim().split(':');
    let (Some(id), Some(frontend), Some(stage), Some(epoch), Some(cache), Some(status)) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return false;
    };
    parts.next().is_none()
        && !id.is_empty()
        && id.bytes().all(|byte| byte.is_ascii_digit())
        && frontend.starts_with('f')
        && frontend.contains('.')
        && frontend
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        && !stage.is_empty()
        && stage.bytes().all(|byte| byte.is_ascii_alphabetic())
        && !epoch.is_empty()
        && epoch
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && cache.starts_with("cache")
        && cache.contains('.')
        && cache
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        && matches!(status, "H" | "M" | "B" | "-")
}

fn looks_like_cachefly_stage(value: &str) -> bool {
    matches!(value.trim(), "H" | "M" | "-")
}

// The proprietary header is associated with Variti in independent response
// surveys. Its decimal:decimal shape is a stronger signal than mere presence.
fn looks_like_variti_ccr(value: &str) -> bool {
    let Some((request, stage)) = value.trim().split_once(':') else {
        return false;
    };
    !request.is_empty()
        && !stage.is_empty()
        && request.bytes().all(|byte| byte.is_ascii_digit())
        && stage.bytes().all(|byte| byte.is_ascii_digit())
}

// The Anubis challenge is authored as two JSON script elements in its HTML
// template. A link mentioning Anubis, or a single ID in a documentation page,
// is not enough to identify an active challenge. The scan is bounded even if
// the caller supplies an unusually large response body.
pub(crate) fn has_anubis_challenge_scripts(body: &[u8]) -> bool {
    use std::sync::OnceLock;

    use regex::Regex;

    static SCRIPT: OnceLock<Option<Regex>> = OnceLock::new();
    let Some(script) = SCRIPT.get_or_init(|| {
        Regex::new(
            r#"(?is)<script\b[^>]{0,1024}\bid\s*=\s*["'](anubis_version|anubis_challenge)["'][^>]*>"#,
        )
        .ok()
    }) else {
        return false;
    };
    let limit = body.len().min(64 * 1024);
    let text = String::from_utf8_lossy(&body[..limit]);
    let mut version = false;
    let mut challenge = false;
    for captures in script.captures_iter(&text) {
        match captures.get(1).map(|id| id.as_str().to_ascii_lowercase()) {
            Some(id) if id == "anubis_version" => version = true,
            Some(id) if id == "anubis_challenge" => challenge = true,
            _ => {}
        }
        if version && challenge {
            return true;
        }
    }
    false
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
    // Azion explicitly documents both headers on ordinary delivery responses.
    // Debug-only X-Azion-Edge-Pop is NOT required; neither the provider
    // response nor its location code authenticates the selected socket peer.
    if has_nonempty_header(headers, "x-azion-request-id")
        && has_nonempty_header(headers, "x-azion-edge-location")
    {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "azion",
            "headers:x-azion-request-id+x-azion-edge-location",
        );
    }
    // ArvanCloud's product-specific Server banner is provider participation.
    // Endpoint fusion must still establish the actual client-facing peer.
    if server_has_product(headers, "arvancloud") {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "arvancloud",
            "server:arvancloud",
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
    // Vendor-shaped Gcore node identities are independent of Cache: HIT/MISS.
    // These may also survive another public CDN layer (including Cloudflare).
    if header_values(headers, "x-id-fe").any(looks_like_gcore_node)
        && header_values(headers, "x-id").any(looks_like_gcore_node)
    {
        add(
            &mut elements,
            PathElementRole::Cache,
            "gcore",
            "headers:x-id+x-id-fe-gcore-nodes",
        );
    }
    // CacheFly documents multiple cache layers. Neither an X-CF1 node
    // name nor a generic cache status alone establishes the outer edge.
    if header_values(headers, "x-cf1").any(looks_like_cachefly_x_cf1)
        && header_values(headers, "x-cf2").any(looks_like_cachefly_stage)
    {
        add(
            &mut elements,
            PathElementRole::Cache,
            "cachefly",
            "headers:x-cf1+x-cf2-cachefly-shape",
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
    // The ByteDance/Volcengine CDN family reserves these response headers.
    // Cache participation is independent from any Akamai or other outer CDN
    // that may carry the values unchanged; this is never a TLS edge vote.
    let volc_dcdn_cache_timing = has_header_value(headers, "server", "Volc-DCDN")
        && header_values(headers, "server-timing")
            .any(|value| server_timing_has_metric(value, "cdn-cache"));
    if has_nonempty_header(headers, "x-bdcdn-cache-status")
        || header_values(headers, "x-tt-trace-tag").any(bytedance_cdn_cache_tag)
        || volc_dcdn_cache_timing
    {
        add(
            &mut elements,
            PathElementRole::Cache,
            "bytedance-cdn",
            if has_nonempty_header(headers, "x-bdcdn-cache-status") {
                "header:x-bdcdn-cache-status"
            } else if header_values(headers, "x-tt-trace-tag").any(bytedance_cdn_cache_tag) {
                "header:x-tt-trace-tag:cdn-cache"
            } else {
                "headers:server=volc-dcdn+server-timing:cdn-cache"
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
    if has_header(headers, "akamai-cache-status") {
        add(
            &mut elements,
            PathElementRole::Cache,
            "akamai",
            "header:akamai-cache-status",
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
    if has_header(headers, "fastly-io-info")
        || has_header(headers, "fastly-stats")
        || has_header(headers, "fastly-io-warning")
        || has_header(headers, "fastly-io-error")
    {
        let evidence = if has_header(headers, "fastly-io-info") {
            "header:fastly-io-info"
        } else if has_header(headers, "fastly-stats") {
            "header:fastly-stats"
        } else if has_header(headers, "fastly-io-warning") {
            "header:fastly-io-warning"
        } else {
            "header:fastly-io-error"
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
    if has_header(headers, "x-hcdn-request-id") {
        add(
            &mut elements,
            PathElementRole::EdgeProvider,
            "hostinger-cdn",
            "header:x-hcdn-request-id",
        );
    }
    if has_header(headers, "x-hcdn-cache-status") {
        add(
            &mut elements,
            PathElementRole::Cache,
            "hostinger-cdn",
            "header:x-hcdn-cache-status",
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
    if has_header(headers, "x-azure-ref") || has_header(headers, "x-msedge-ref") {
        add(
            &mut elements,
            PathElementRole::ApplicationPlatform,
            "azure-front-door",
            if has_header(headers, "x-azure-ref") {
                "header:x-azure-ref"
            } else {
                "header:x-msedge-ref"
            },
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
    if has_header(headers, "x-railway-edge")
        || has_header(headers, "x-railway-upstream-zone")
        || has_header(headers, "x-railway-request-id")
    {
        let evidence = if has_header(headers, "x-railway-upstream-zone") {
            "header:x-railway-upstream-zone"
        } else if has_header(headers, "x-railway-edge") {
            "header:x-railway-edge"
        } else {
            "header:x-railway-request-id"
        };
        add(
            &mut elements,
            PathElementRole::ApplicationPlatform,
            "railway",
            evidence,
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
    if via.contains("vegur") || via.contains("heroku-router") {
        add(
            &mut elements,
            PathElementRole::ApplicationPlatform,
            "heroku",
            if via.contains("heroku-router") {
                "via:heroku-router"
            } else {
                "via:vegur"
            },
        );
    }
    if has_header(headers, "x-github-request-id") {
        add(
            &mut elements,
            PathElementRole::ApplicationPlatform,
            "github",
            "header:x-github-request-id",
        );
    }
    if has_header(headers, "x-wix-request-id") {
        add(
            &mut elements,
            PathElementRole::ApplicationPlatform,
            "wix",
            "header:x-wix-request-id",
        );
    }
    if has_header(headers, "ki-cf-cache-status")
        || has_header(headers, "ki-cache-type")
        || has_header(headers, "x-kinsta-cache")
    {
        let evidence = if has_header(headers, "ki-cf-cache-status") {
            "header:ki-cf-cache-status"
        } else if has_header(headers, "ki-cache-type") {
            "header:ki-cache-type"
        } else {
            "header:x-kinsta-cache"
        };
        add(
            &mut elements,
            PathElementRole::ApplicationPlatform,
            "kinsta",
            evidence,
        );
    }
    // Future's paired infrastructure headers identify platform participation,
    // but the labels may describe Vanilla, Hawk, assets, or internal routing.
    // Never infer the client-facing CDN or the implementation of a network
    // hop from a backend/balancer hostname string.
    if has_nonempty_header(headers, "x-ftr-backend")
        && has_nonempty_header(headers, "x-ftr-balancer")
    {
        add(
            &mut elements,
            PathElementRole::ApplicationPlatform,
            "future-publishing",
            "headers:x-ftr-backend+x-ftr-balancer",
        );
    }
    if has_nonempty_header(headers, "x-ftr-cache-status") {
        add(
            &mut elements,
            PathElementRole::Cache,
            "future-publishing",
            "header:x-ftr-cache-status",
        );
    }

    // Flywheel's managed WordPress platform can sit behind Cloudflare or
    // Fastly. Require a product-bearing backend banner and a separate serving
    // header; neither is an outer-edge identity claim.
    if header_has_product(headers, "x-fw-server", "flywheel")
        && has_nonempty_header(headers, "x-fw-serve")
    {
        add(
            &mut elements,
            PathElementRole::ApplicationPlatform,
            "flywheel",
            "headers:x-fw-server+x-fw-serve",
        );
    }

    // Arc XP's support IDs identify the publishing platform, not its CDN.
    if has_nonempty_header(headers, "x-arc-request-id")
        || has_nonempty_header(headers, "x-arc-pb-request-id")
    {
        add(
            &mut elements,
            PathElementRole::ApplicationPlatform,
            "arc-xp",
            if has_nonempty_header(headers, "x-arc-request-id") {
                "header:x-arc-request-id"
            } else {
                "header:x-arc-pb-request-id"
            },
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

    // Both OVH IPLB-generated fields occur in documented OVH responses.
    // Forwarded headers establish LB participation, never selected peer IP.
    if has_nonempty_header(headers, "x-iplb-request-id")
        && has_nonempty_header(headers, "x-iplb-instance")
    {
        add(
            &mut elements,
            PathElementRole::LoadBalancer,
            "ovh-iplb",
            "headers:x-iplb-request-id+x-iplb-instance",
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
    // Version-bearing Server products remain implementation evidence even
    // when an outer CDN preserves the header from a downstream service.
    for (product, label) in [
        ("kestrel", "kestrel"),
        ("gunicorn", "gunicorn"),
        ("tengine", "tengine"),
        ("jetty", "jetty"),
        ("microsoft-httpapi", "microsoft-httpapi"),
        ("uvicorn", "uvicorn"),
        ("lighttpd", "lighttpd"),
    ] {
        if server_has_product(headers, product) {
            add(
                &mut elements,
                PathElementRole::ServerImplementation,
                label,
                format!("server:{product}"),
            );
        }
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
    if has_header(headers, "x-litespeed-cache") || has_header(headers, "x-lsadc-cache") {
        add(
            &mut elements,
            PathElementRole::Cache,
            "litespeed",
            if has_header(headers, "x-lsadc-cache") {
                "header:x-lsadc-cache"
            } else {
                "header:x-litespeed-cache"
            },
        );
    }
    if has_header(headers, "x-kinsta-cache") {
        add(
            &mut elements,
            PathElementRole::Cache,
            "kinsta",
            "header:x-kinsta-cache",
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
    let has_aws_s3_request_id_pair = has_header(headers, "x-amz-id-2")
        && header_values(headers, "x-amz-request-id").any(looks_like_aws_s3_request_id);
    if has_header_value(headers, "server", "AmazonS3") || has_aws_s3_request_id_pair {
        add(
            &mut elements,
            PathElementRole::OriginService,
            "aws-s3",
            if has_header_value(headers, "server", "AmazonS3") {
                "server:amazons3"
            } else {
                "headers:x-amz-id-2+x-amz-request-id-aws-s3-shape"
            },
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
        || has_header(headers, "x-guploader-uploadid")
        || has_header(headers, "x-goog-stored-content-length")
        || has_header(headers, "x-goog-stored-content-encoding")
        || (has_header(headers, "x-goog-generation")
            && has_header(headers, "x-goog-metageneration"))
    {
        let evidence = if has_header(headers, "x-goog-storage-class") {
            "header:x-goog-storage-class"
        } else if has_header(headers, "x-guploader-uploadid") {
            "header:x-guploader-uploadid"
        } else if has_header(headers, "x-goog-stored-content-length") {
            "header:x-goog-stored-content-length"
        } else if has_header(headers, "x-goog-stored-content-encoding") {
            "header:x-goog-stored-content-encoding"
        } else {
            "headers:x-goog-generation+x-goog-metageneration"
        };
        add(
            &mut elements,
            PathElementRole::OriginService,
            "google-cloud-storage",
            evidence,
        );
    }
    if has_header(headers, "x-ms-blob-type")
        || has_header(headers, "x-ms-access-tier")
        || server.contains("windows-azure-blob")
    {
        let evidence = if has_header(headers, "x-ms-blob-type") {
            "header:x-ms-blob-type"
        } else if has_header(headers, "x-ms-access-tier") {
            "header:x-ms-access-tier"
        } else {
            "server:windows-azure-blob"
        };
        add(
            &mut elements,
            PathElementRole::OriginService,
            "azure-blob-storage",
            evidence,
        );
    }
    if has_header(headers, "x-oss-request-id") || has_header_value(headers, "server", "AliyunOSS") {
        add(
            &mut elements,
            PathElementRole::OriginService,
            "alibaba-oss",
            if has_header(headers, "x-oss-request-id") {
                "header:x-oss-request-id"
            } else {
                "server:aliyunoss"
            },
        );
    }
    // Tencent COS request IDs survive independent delivery/proxy layers.
    // Do not confuse Tencent CI's distinct banner with a COS-origin claim.
    if has_nonempty_header(headers, "x-cos-request-id")
        || has_header_value(headers, "server", "tencent-cos")
    {
        add(
            &mut elements,
            PathElementRole::OriginService,
            "tencent-cos",
            if has_nonempty_header(headers, "x-cos-request-id") {
                "header:x-cos-request-id"
            } else {
                "server:tencent-cos"
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
    if has_header(headers, "x-ioriver") {
        add(
            &mut elements,
            PathElementRole::TrafficManagement,
            "ioriver",
            "header:x-ioriver",
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
    // A DDoS-Guard reverse-proxy banner or product-scoped session cookie
    // establishes security-layer participation, not a triggered WAF rule or
    // a verified client-facing TLS endpoint.
    if server_has_product(headers, "ddos-guard") {
        add(
            &mut elements,
            PathElementRole::SecurityMiddleware,
            "ddos-guard",
            "server:ddos-guard",
        );
    }
    if cookies
        .iter()
        .any(|cookie| looks_like_ddos_guard_cookie(cookie))
    {
        add(
            &mut elements,
            PathElementRole::SecurityMiddleware,
            "ddos-guard",
            "cookie:__ddg-family",
        );
    }
    // Variti's response CCR marker identifies the protection service,
    // but does not prove a bot was blocked or the optional WAF was active.
    if header_values(headers, "x-variti-ccr").any(looks_like_variti_ccr) {
        add(
            &mut elements,
            PathElementRole::SecurityMiddleware,
            "variti",
            "header:x-variti-ccr-decimal-pair",
        );
    }
    // Huawei WAF documents both response-session cookies independently;
    // the presence of either is WAF participation, not proof of a block.
    if has_cookie(&cookies, "hwwafsesid") {
        add(
            &mut elements,
            PathElementRole::Waf,
            "huawei-cloud-waf",
            "cookie:HWWAFSESID",
        );
    }
    if has_cookie(&cookies, "hwwafsestime") {
        add(
            &mut elements,
            PathElementRole::Waf,
            "huawei-cloud-waf",
            "cookie:HWWAFSESTIME",
        );
    }
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
    // Qrator's bot-protection dashboard explicitly defines the tracking
    // cookie; Qrator's X-Qrator-* headers instead go toward the origin and
    // must NOT be used as response evidence.
    if has_cookie(&cookies, "qrator_jsid") {
        add(
            &mut elements,
            PathElementRole::BotManagement,
            "qrator",
            "cookie:qrator_jsid",
        );
    }
    // Anubis emits versioned clearance/verification cookies on challenged
    // clients. A body-only challenge is detected separately below.
    if has_cookie(&cookies, "techaro.lol-anubis-auth")
        || has_cookie_prefix(&cookies, "techaro.lol-anubis-auth-")
    {
        add(
            &mut elements,
            PathElementRole::BotManagement,
            "anubis",
            "cookie:techaro.lol-anubis-auth*",
        );
    }
    if has_cookie(&cookies, "techaro.lol-anubis-cookie-verification")
        || has_cookie_prefix(&cookies, "techaro.lol-anubis-cookie-verification-")
    {
        add(
            &mut elements,
            PathElementRole::BotManagement,
            "anubis",
            "cookie:techaro.lol-anubis-cookie-verification*",
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

/// Recognize response participation from headers **and** a captured body.
///
/// Unlike the header-only scanner, this additionally recognizes Anubis
/// challenge pages from the two script tags authored by Anubis itself.
/// Only the first 64 KiB is inspected. HTTP/3's header-only observer should
/// continue to use `detect_path_elements`.
#[must_use]
pub fn detect_path_elements_with_body(headers: &[Header], body: &[u8]) -> Vec<PathElement> {
    let mut elements = detect_path_elements(headers);
    if has_anubis_challenge_scripts(body) {
        add(
            &mut elements,
            PathElementRole::BotManagement,
            "anubis",
            "body:anubis-version+challenge-scripts",
        );
    }
    elements
}
