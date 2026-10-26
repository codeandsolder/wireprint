use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use hickory_resolver::TokioResolver;

use crate::model::{Observation, RoutingContext, RoutingContextSnapshot};

pub const ROUTING_CONTEXT_VERSION: &str = "builtin-routing-context-v1";
const CYMRU_SOURCE: &str = "team-cymru-ip-to-asn";
const CYMRU_V4_ZONE: &str = "origin.asn.cymru.com";
const CYMRU_V6_ZONE: &str = "origin6.asn.cymru.com";
const CYMRU_ASN_ZONE: &str = "asn.cymru.com";

#[derive(Clone)]
pub struct RoutingContextCollector {
    resolver: Option<Arc<TokioResolver>>,
    init_error: Option<Arc<str>>,
    cache: Arc<Mutex<HashMap<IpAddr, RoutingContextSnapshot>>>,
    as_name_cache: Arc<Mutex<HashMap<u32, Option<String>>>>,
}

impl fmt::Debug for RoutingContextCollector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoutingContextCollector")
            .finish_non_exhaustive()
    }
}

impl Default for RoutingContextCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl RoutingContextCollector {
    pub fn new() -> Self {
        let built = TokioResolver::builder_tokio().and_then(|builder| builder.build());
        let (resolver, init_error) = match built {
            Ok(resolver) => (Some(Arc::new(resolver)), None),
            Err(error) => (None, Some(Arc::from(error.to_string()))),
        };
        Self {
            resolver,
            init_error,
            cache: Arc::new(Mutex::new(HashMap::new())),
            as_name_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Collect BGP prefix/origin-AS context for one concrete IP address.
    ///
    /// A snapshot is returned even on lookup failure so a routing-context
    /// enrichment outage cannot turn the target probe itself into a failure.
    pub async fn collect(&self, address: IpAddr) -> RoutingContextSnapshot {
        if let Some(mut cached) = self.cached(address) {
            cached.lookup_reused = true;
            return cached;
        }

        let snapshot = match self.collect_uncached(address).await {
            Ok(snapshot) => snapshot,
            Err(error) => RoutingContextSnapshot {
                classifier: ROUTING_CONTEXT_VERSION.into(),
                source: CYMRU_SOURCE.into(),
                resource: address.to_string(),
                observed_unix_ms: unix_ms(),
                lookup_reused: false,
                contexts: Vec::new(),
                error: Some(format!("{error:#}")),
            },
        };
        self.cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(address, snapshot.clone());
        snapshot
    }

    fn cached(&self, address: IpAddr) -> Option<RoutingContextSnapshot> {
        self.cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&address)
            .cloned()
    }

    async fn collect_uncached(&self, address: IpAddr) -> Result<RoutingContextSnapshot> {
        let observed_unix_ms = unix_ms();
        let Some(resolver) = &self.resolver else {
            bail!(
                "Team Cymru resolver unavailable: {}",
                self.init_error
                    .as_deref()
                    .unwrap_or("unknown resolver init error")
            );
        };
        let query_name = origin_query_name(address);
        let lookup = resolver
            .txt_lookup(query_name.clone())
            .await
            .with_context(|| format!("Team Cymru origin lookup {query_name}"))?;

        let mut origins = Vec::new();
        for record in lookup.answers() {
            if let hickory_resolver::proto::rr::RData::TXT(txt) = &record.data {
                let raw = txt_to_string(txt);
                origins.extend(
                    parse_origin_record(&raw)
                        .with_context(|| format!("parse Team Cymru origin TXT {raw:?}"))?,
                );
            }
        }
        if origins.is_empty() {
            bail!("Team Cymru origin lookup returned no TXT records for {address}");
        }

        // A prefix may legitimately be visible with multiple origins. Keep one
        // context per (prefix, ASN) pair rather than choosing a winner.
        let mut unique = BTreeMap::<(String, u32), OriginRecord>::new();
        for origin in origins {
            unique
                .entry((origin.prefix.clone(), origin.asn))
                .or_insert(origin);
        }

        let mut contexts = Vec::new();
        let mut partial_errors = Vec::new();
        for ((_prefix, asn), origin) in unique {
            let as_name = match self.as_name(asn).await {
                Ok(name) => name,
                Err(error) => {
                    partial_errors.push(format!("AS{asn}: {error:#}"));
                    None
                }
            };
            let mut evidence = vec![
                format!("team-cymru-origin-query:{query_name}"),
                format!("team-cymru-origin-asn:AS{asn}"),
                format!("team-cymru-bgp-prefix:{}", origin.prefix),
            ];
            if let Some(country) = origin.country {
                evidence.push(format!("team-cymru-prefix-country:{country}"));
            }
            if let Some(registry) = origin.registry {
                evidence.push(format!("team-cymru-prefix-registry:{registry}"));
            }
            if let Some(allocated) = origin.allocated {
                evidence.push(format!("team-cymru-prefix-allocated:{allocated}"));
            }
            if as_name.is_some() {
                evidence.push("team-cymru-asn-name".into());
            }
            contexts.push(RoutingContext {
                prefix: Some(origin.prefix),
                asn: Some(asn),
                as_name,
                evidence,
            });
        }

        Ok(RoutingContextSnapshot {
            classifier: ROUTING_CONTEXT_VERSION.into(),
            source: CYMRU_SOURCE.into(),
            resource: address.to_string(),
            observed_unix_ms,
            lookup_reused: false,
            contexts,
            error: (!partial_errors.is_empty()).then(|| partial_errors.join("; ")),
        })
    }

    async fn as_name(&self, asn: u32) -> Result<Option<String>> {
        if let Some(cached) = self
            .as_name_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&asn)
            .cloned()
        {
            return Ok(cached);
        }

        let Some(resolver) = &self.resolver else {
            bail!(
                "Team Cymru resolver unavailable: {}",
                self.init_error
                    .as_deref()
                    .unwrap_or("unknown resolver init error")
            );
        };
        let query_name = format!("AS{asn}.{CYMRU_ASN_ZONE}");
        let lookup = resolver
            .txt_lookup(query_name.clone())
            .await
            .with_context(|| format!("Team Cymru ASN-name lookup {query_name}"))?;
        let mut name = None;
        for record in lookup.answers() {
            if let hickory_resolver::proto::rr::RData::TXT(txt) = &record.data {
                let raw = txt_to_string(txt);
                if let Some(parsed) = parse_asn_record(&raw)?
                    && parsed.asn == asn
                {
                    name = parsed.name;
                    break;
                }
            }
        }
        self.as_name_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(asn, name.clone());
        Ok(name)
    }
}

pub async fn enrich_observation(
    observation: &mut Observation,
    collector: &RoutingContextCollector,
) {
    let Some(address) = observation_routing_address(observation) else {
        return;
    };
    observation.routing_context_snapshot = Some(collector.collect(address).await);
}

pub fn observation_routing_address(observation: &Observation) -> Option<IpAddr> {
    if let Some(selected) = observation
        .selected_endpoint
        .as_deref()
        .and_then(parse_ip_or_socket)
    {
        return Some(selected);
    }
    observation.remote.as_deref().and_then(parse_ip_or_socket)
}

fn parse_ip_or_socket(value: &str) -> Option<IpAddr> {
    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|socket| socket.ip()))
}

fn origin_query_name(address: IpAddr) -> String {
    match address {
        IpAddr::V4(address) => ipv4_origin_query(address),
        IpAddr::V6(address) => ipv6_origin_query(address),
    }
}

fn ipv4_origin_query(address: Ipv4Addr) -> String {
    let octets = address.octets();
    format!(
        "{}.{}.{}.{}.{CYMRU_V4_ZONE}",
        octets[3], octets[2], octets[1], octets[0]
    )
}

fn ipv6_origin_query(address: Ipv6Addr) -> String {
    let mut out = String::with_capacity(32 * 2 + CYMRU_V6_ZONE.len());
    for byte in address.octets().iter().rev() {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:x}.{:x}.", byte & 0x0f, byte >> 4);
    }
    out.push_str(CYMRU_V6_ZONE);
    out
}

fn txt_to_string(txt: &hickory_resolver::proto::rr::rdata::TXT) -> String {
    let bytes = txt
        .txt_data
        .iter()
        .flat_map(|part| part.iter().copied())
        .collect::<Vec<_>>();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OriginRecord {
    asn: u32,
    prefix: String,
    country: Option<String>,
    registry: Option<String>,
    allocated: Option<String>,
}

fn parse_origin_record(raw: &str) -> Result<Vec<OriginRecord>> {
    let fields = raw.split('|').map(str::trim).collect::<Vec<_>>();
    if fields.len() < 2 {
        bail!("expected at least ASN and prefix fields");
    }
    let prefix = fields[1].to_owned();
    if prefix.is_empty() {
        bail!("empty BGP prefix");
    }
    let asns = parse_asn_list(fields[0])?;
    if asns.is_empty() {
        bail!("empty origin ASN list");
    }
    let country = nonempty(fields.get(2).copied());
    let registry = nonempty(fields.get(3).copied());
    let allocated = nonempty(fields.get(4).copied());
    Ok(asns
        .into_iter()
        .map(|asn| OriginRecord {
            asn,
            prefix: prefix.clone(),
            country: country.clone(),
            registry: registry.clone(),
            allocated: allocated.clone(),
        })
        .collect())
}

fn parse_asn_list(value: &str) -> Result<Vec<u32>> {
    let mut out = value
        .split_whitespace()
        .map(|item| {
            item.trim_start_matches(['A', 'S', 'a', 's'])
                .parse::<u32>()
                .with_context(|| format!("parse ASN {item}"))
        })
        .collect::<Result<Vec<_>>>()?;
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AsnRecord {
    asn: u32,
    name: Option<String>,
}

fn parse_asn_record(raw: &str) -> Result<Option<AsnRecord>> {
    let fields = raw.split('|').map(str::trim).collect::<Vec<_>>();
    if fields.is_empty() || fields[0].is_empty() {
        return Ok(None);
    }
    let asn = fields[0]
        .trim_start_matches(['A', 'S', 'a', 's'])
        .parse::<u32>()
        .with_context(|| format!("parse Team Cymru ASN record {raw:?}"))?;
    Ok(Some(AsnRecord {
        asn,
        name: nonempty(fields.get(4).copied()),
    }))
}

fn nonempty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blank_observation() -> Observation {
        Observation {
            target: "https://example.test/".into(),
            observed_unix_ms: 1,
            vantage: None,
            request_profile: "test".into(),
            request_role: None,
            request_provenance: None,
            request_profile_headers: Vec::new(),
            transport_profile: "test".into(),
            transport: None,
            platform: Some("test".into()),
            result: "response".into(),
            elapsed_ms: 1,
            status: None,
            http_version: None,
            transport_protocol: None,
            final_uri: None,
            remote: None,
            selected_endpoint: None,
            dns: None,
            response_headers: Vec::new(),
            path_elements: Vec::new(),
            routing_elements: Vec::new(),
            provider_signals: Vec::new(),
            routing_context_snapshot: None,
            h2_server_preface: None,
            h3_server_fingerprint: None,
            tls_server_morphology: None,
            endpoint_assessment: None,
            body_captured_bytes: None,
            body_prefix_sha256: None,
            body_template_sha256: None,
            body_template_normalizer: None,
            body_prefix: None,
            body_truncated: None,
            outcome: None,
            error: None,
        }
    }

    #[test]
    fn ipv4_query_reverses_octets() {
        assert_eq!(
            origin_query_name("216.90.108.31".parse().unwrap()),
            "31.108.90.216.origin.asn.cymru.com"
        );
    }

    #[test]
    fn ipv6_query_uses_full_reversed_nibbles() {
        let query = origin_query_name("2001:4860:b002::68".parse().unwrap());
        assert!(query.ends_with("origin6.asn.cymru.com"));
        assert!(query.starts_with("8.6.0.0.0.0.0.0."));
        assert_eq!(query.split('.').count(), 36);
    }

    #[test]
    fn origin_parser_preserves_multi_origin_prefixes() {
        let parsed = parse_origin_record(
            "64502 64500 64501 64500 | 203.0.113.0/24 | ZZ | test | 2026-01-01",
        )
        .unwrap();
        assert_eq!(
            parsed.iter().map(|record| record.asn).collect::<Vec<_>>(),
            vec![64_500, 64_501, 64_502]
        );
        assert!(
            parsed
                .iter()
                .all(|record| record.prefix == "203.0.113.0/24")
        );
    }

    #[test]
    fn asn_parser_keeps_description_without_treating_registry_as_name() {
        let parsed = parse_asn_record(
            "13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US",
        )
        .unwrap()
        .unwrap();
        assert_eq!(parsed.asn, 13_335);
        assert_eq!(
            parsed.name.as_deref(),
            Some("CLOUDFLARENET - Cloudflare, Inc., US")
        );
    }

    #[test]
    fn routing_address_prefers_selected_endpoint_over_actual_peer() {
        let mut observation = blank_observation();
        observation.selected_endpoint = Some("203.0.113.10".into());
        observation.remote = Some("198.51.100.20:443".into());
        assert_eq!(
            observation_routing_address(&observation),
            Some("203.0.113.10".parse().unwrap())
        );
    }

    #[test]
    fn routing_address_falls_back_to_socket_peer() {
        let mut observation = blank_observation();
        observation.remote = Some("[2001:db8::10]:443".into());
        assert_eq!(
            observation_routing_address(&observation),
            Some("2001:db8::10".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn cached_lookup_is_marked_reused_without_changing_observation_time() {
        let collector = RoutingContextCollector::new();
        let address: IpAddr = "203.0.113.10".parse().unwrap();
        let snapshot = RoutingContextSnapshot {
            classifier: ROUTING_CONTEXT_VERSION.into(),
            source: CYMRU_SOURCE.into(),
            resource: address.to_string(),
            observed_unix_ms: 123,
            lookup_reused: false,
            contexts: vec![RoutingContext {
                prefix: Some("203.0.113.0/24".into()),
                asn: Some(64_500),
                as_name: Some("TEST-NET".into()),
                evidence: vec!["test".into()],
            }],
            error: None,
        };
        collector
            .cache
            .lock()
            .unwrap()
            .insert(address, snapshot.clone());

        let reused = collector.collect(address).await;
        assert!(reused.lookup_reused);
        assert_eq!(reused.observed_unix_ms, 123);
        assert_eq!(reused.contexts, snapshot.contexts);
    }

    #[test]
    fn endpoint_evidence_copies_collected_context_without_scoring_it() {
        let mut observation = blank_observation();
        observation.routing_context_snapshot = Some(RoutingContextSnapshot {
            classifier: ROUTING_CONTEXT_VERSION.into(),
            source: CYMRU_SOURCE.into(),
            resource: "203.0.113.10".into(),
            observed_unix_ms: 123,
            lookup_reused: false,
            contexts: vec![RoutingContext {
                prefix: Some("203.0.113.0/24".into()),
                asn: Some(64_500),
                as_name: Some("TEST-NET".into()),
                evidence: vec!["test".into()],
            }],
            error: None,
        });
        let evidence = crate::model::EndpointEvidence::from(&observation);
        assert_eq!(evidence.routing_context.len(), 1);
        assert_eq!(evidence.routing_context[0].asn, Some(64_500));
    }
}
