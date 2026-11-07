use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use hickory_resolver::{
    TokioResolver,
    lookup::Lookup,
    proto::rr::{RData, RecordType},
};
use url::Url;
use wreq::dns::{Addrs, GaiResolver, Name, Resolve, Resolving};

use crate::address_family::AddressFamily;
use crate::model::{DnsCnameLink, DnsProvenance, DnsRouteAnswer};

pub const DNS_CAPTURE_VERSION: &str = "builtin-dns-v2";

#[derive(Debug, Clone)]
pub(crate) struct ConnectionResolution {
    sequence: u64,
    pub(crate) observed_unix_ms: u128,
    pub(crate) candidates: Vec<String>,
}

#[derive(Debug, Default)]
struct ResolverState {
    sequence: u64,
    latest: HashMap<String, ConnectionResolution>,
}

#[derive(Clone)]
pub(crate) struct RecordingResolver {
    inner: GaiResolver,
    family: AddressFamily,
    state: Arc<Mutex<ResolverState>>,
}

impl RecordingResolver {
    pub(crate) fn new(family: AddressFamily) -> Self {
        Self {
            inner: GaiResolver::default(),
            family,
            state: Arc::new(Mutex::new(ResolverState::default())),
        }
    }

    pub(crate) fn cursor(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sequence
    }

    pub(crate) fn latest(&self, host: &str) -> Option<ConnectionResolution> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .latest
            .get(&normalize_dns_name(host))
            .cloned()
    }
}

impl Resolve for RecordingResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let inner = self.inner.clone();
        let family = self.family;
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let resolved = inner.resolve(name.clone()).await?;
            let addrs = family.filter(resolved);
            if addrs.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("no {family:?} address resolved for {name}"),
                )
                .into());
            }
            let candidates = unique_ips(addrs.iter().map(SocketAddr::ip));
            let observed_unix_ms = unix_ms();
            let mut state = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.sequence = state.sequence.wrapping_add(1);
            let sequence = state.sequence;
            let _ = state.latest.insert(
                normalize_dns_name(name.as_str()),
                ConnectionResolution {
                    sequence,
                    observed_unix_ms,
                    candidates,
                },
            );
            drop(state);
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RoutingDnsSnapshot {
    pub(crate) observed_unix_ms: u128,
    pub(crate) answers: Vec<DnsRouteAnswer>,
    pub(crate) error: Option<String>,
}

#[derive(Clone)]
pub(crate) struct RoutingDnsSnapshotter {
    resolver: Option<Arc<TokioResolver>>,
    init_error: Option<Arc<str>>,
}

impl RoutingDnsSnapshotter {
    pub(crate) fn new() -> Self {
        let built = TokioResolver::builder_tokio().and_then(|mut builder| {
            builder.options_mut().preserve_intermediates = true;
            builder.build()
        });
        match built {
            Ok(resolver) => Self {
                resolver: Some(Arc::new(resolver)),
                init_error: None,
            },
            Err(error) => Self {
                resolver: None,
                init_error: Some(Arc::from(error.to_string())),
            },
        }
    }

    pub(crate) async fn capture(&self, host: &str) -> RoutingDnsSnapshot {
        let observed_unix_ms = unix_ms();
        let host = normalize_dns_name(host);
        if let Ok(ip) = host.parse::<IpAddr>() {
            let family = if ip.is_ipv4() {
                AddressFamily::Ipv4
            } else {
                AddressFamily::Ipv6
            };
            return RoutingDnsSnapshot {
                observed_unix_ms,
                answers: vec![DnsRouteAnswer {
                    family,
                    ips: vec![ip.to_string()],
                    linked_ips: vec![ip.to_string()],
                    cname_chain: Vec::new(),
                    cname_links: Vec::new(),
                    error: None,
                }],
                error: None,
            };
        }

        let Some(resolver) = &self.resolver else {
            return RoutingDnsSnapshot {
                observed_unix_ms,
                answers: Vec::new(),
                error: self.init_error.as_deref().map(str::to_owned),
            };
        };

        // Independent query results carry their own aliases. LookupIp's A+AAAA
        // union erases the chain-to-address relationship on split CDN steering.
        let (a, aaaa) = tokio::join!(
            resolver.lookup(host.clone(), RecordType::A),
            resolver.lookup(host.clone(), RecordType::AAAA),
        );
        let answers = [
            parse_dns_route_answer(&host, AddressFamily::Ipv4, a),
            parse_dns_route_answer(&host, AddressFamily::Ipv6, aaaa),
        ];
        let error = answers
            .iter()
            .all(|answer| answer.error.is_some())
            .then(|| {
                answers
                    .iter()
                    .filter_map(|answer| answer.error.as_deref())
                    .collect::<Vec<_>>()
                    .join("; ")
            });
        RoutingDnsSnapshot {
            observed_unix_ms,
            answers: answers.into(),
            error,
        }
    }
}

fn parse_dns_route_answer<E: std::fmt::Display>(
    host: &str,
    family: AddressFamily,
    result: Result<Lookup, E>,
) -> DnsRouteAnswer {
    let lookup = match result {
        Ok(lookup) => lookup,
        Err(error) => {
            return DnsRouteAnswer {
                family,
                ips: Vec::new(),
                linked_ips: Vec::new(),
                cname_chain: Vec::new(),
                cname_links: Vec::new(),
                error: Some(error.to_string()),
            };
        }
    };
    parse_dns_lookup(host, family, &lookup)
}

fn parse_dns_lookup(host: &str, family: AddressFamily, lookup: &Lookup) -> DnsRouteAnswer {
    let mut ips = Vec::new();
    let mut address_owners = Vec::new();
    let mut cname_links = Vec::new();
    let mut aliases = HashMap::<String, HashSet<String>>::new();

    for record in lookup.answers() {
        let owner = normalize_dns_name(&record.name.to_string());
        if let Some(ip) = record.data.ip_addr() {
            let relevant = matches!(
                (family, ip),
                (AddressFamily::Ipv4, IpAddr::V4(_)) | (AddressFamily::Ipv6, IpAddr::V6(_))
            );
            if relevant {
                let token = ip.to_string();
                if !ips.contains(&token) {
                    ips.push(token.clone());
                }
                address_owners.push((owner, token));
            }
        } else if let RData::CNAME(cname) = &record.data {
            let target = normalize_dns_name(&cname.0.to_string());
            let _ = aliases
                .entry(owner.clone())
                .or_default()
                .insert(target.clone());
            let link = DnsCnameLink { owner, target };
            if !cname_links.contains(&link) {
                cname_links.push(link);
            }
        }
    }

    let mut cname_chain = Vec::new();
    let mut current = normalize_dns_name(host);
    let mut seen = HashSet::new();
    let mut unambiguous = true;
    while seen.insert(current.clone()) {
        let Some(targets) = aliases.get(&current) else {
            break;
        };
        if targets.len() != 1 {
            unambiguous = false;
            break;
        }
        let Some(next) = targets.iter().next().cloned() else {
            break;
        };
        if seen.contains(&next) || cname_chain.len() >= 64 {
            unambiguous = false;
            break;
        }
        cname_chain.push(next.clone());
        current = next;
    }

    // Do not bind an alias merely because a sibling RR in the same DNS
    // response contains the selected address. Its *owner* must equal the
    // unambiguous terminal CNAME target, or the original host if no aliases.
    let linked_ips = if unambiguous {
        address_owners
            .into_iter()
            .filter_map(|(owner, ip)| (owner == current).then_some(ip))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    DnsRouteAnswer {
        family,
        ips,
        linked_ips,
        cname_chain,
        cname_links,
        error: None,
    }
}

pub(crate) fn build_dns_provenance(
    host: &str,
    cursor: u64,
    connection: Option<&ConnectionResolution>,
    routing: RoutingDnsSnapshot,
) -> DnsProvenance {
    let host = normalize_dns_name(host);
    let mut connection_candidates =
        connection.map_or_default(|resolution| resolution.candidates.clone());
    if connection_candidates.is_empty()
        && let Ok(ip) = host.parse::<IpAddr>()
    {
        connection_candidates.push(ip.to_string());
    }

    DnsProvenance {
        classifier: DNS_CAPTURE_VERSION.into(),
        host,
        connection_candidates,
        connection_resolution_unix_ms: connection.map(|resolution| resolution.observed_unix_ms),
        connection_resolution_reused: connection
            .is_some_and(|resolution| resolution.sequence <= cursor),
        routing_answers: routing.answers,
        routing_snapshot_unix_ms: Some(routing.observed_unix_ms),
        routing_snapshot_error: routing.error,
    }
}

pub(crate) fn selected_endpoint(
    actual_peer: Option<SocketAddr>,
    dns: Option<&DnsProvenance>,
) -> Option<String> {
    let peer_ip = actual_peer?.ip().to_string();
    let dns = dns?;
    dns.connection_candidates
        .iter()
        .any(|candidate| candidate == &peer_ip)
        .then_some(peer_ip)
}

pub(crate) fn host_from_url(value: &str) -> Option<String> {
    Url::parse(value).ok()?.host_str().map(normalize_dns_name)
}

fn unique_ips(ips: impl IntoIterator<Item = IpAddr>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for ip in ips {
        let text = ip.to_string();
        if seen.insert(text.clone()) {
            out.push(text);
        }
    }
    out
}

fn normalize_dns_name(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
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

    #[tokio::test]
    async fn connection_resolver_filters_real_gai_addresses_before_recording() {
        use wreq::dns::{Name, Resolve};

        let ipv4 = RecordingResolver::new(AddressFamily::Ipv4);
        let name = Name::from("127.0.0.1");
        let addresses = ipv4.resolve(name.clone()).await.expect("IPv4 literal");
        assert!(addresses.into_iter().all(|addr| addr.is_ipv4()));
        assert_eq!(
            ipv4.latest("127.0.0.1").expect("recorded").candidates,
            ["127.0.0.1"]
        );

        let ipv6 = RecordingResolver::new(AddressFamily::Ipv6);
        let error = match ipv6.resolve(name).await {
            Ok(_) => panic!("must reject an IPv4-only literal in IPv6 mode"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("no Ipv6 address"));
        assert!(ipv6.latest("127.0.0.1").is_none());

        let ipv6_addr = ipv6.resolve(Name::from("::1")).await.expect("IPv6 literal");
        assert!(ipv6_addr.into_iter().all(|addr| addr.is_ipv6()));
        assert_eq!(ipv6.latest("::1").expect("recorded").candidates, ["::1"]);
    }

    #[test]
    fn selected_endpoint_requires_a_resolver_candidate_match() {
        let dns = DnsProvenance {
            classifier: DNS_CAPTURE_VERSION.into(),
            host: "example.com".into(),
            connection_candidates: vec!["192.0.2.10".into()],
            connection_resolution_unix_ms: Some(1),
            connection_resolution_reused: false,
            routing_answers: Vec::new(),
            routing_snapshot_unix_ms: Some(1),
            routing_snapshot_error: None,
        };
        assert_eq!(
            selected_endpoint(
                Some("192.0.2.10:443".parse().expect("valid test address")),
                Some(&dns)
            ),
            Some("192.0.2.10".into())
        );
        assert_eq!(
            selected_endpoint(
                Some("192.0.2.11:443".parse().expect("valid test address")),
                Some(&dns)
            ),
            None
        );
    }

    fn test_lookup(host: &str, family: AddressFamily, records: Vec<(String, RData)>) -> Lookup {
        use hickory_resolver::proto::{
            op::Query,
            rr::{Name, Record},
        };
        let name = host.parse::<Name>().expect("valid domain");
        let record_type = match family {
            AddressFamily::Ipv4 => RecordType::A,
            AddressFamily::Ipv6 => RecordType::AAAA,
            AddressFamily::Auto => panic!("test needs a concrete family"),
        };
        let records = records
            .into_iter()
            .map(|(owner, data)| {
                Record::from_rdata(owner.parse::<Name>().expect("valid owner"), 60, data)
            })
            .collect::<Vec<_>>();
        Lookup::new_with_max_ttl(Query::query(name, record_type), records)
    }

    fn cname(target: &str) -> RData {
        use hickory_resolver::proto::rr::{Name, rdata::CNAME};
        RData::CNAME(CNAME(target.parse::<Name>().expect("valid alias")))
    }

    fn address(value: &str) -> RData {
        RData::from(value.parse::<IpAddr>().expect("valid IP"))
    }

    #[test]
    fn independent_a_aaaa_answers_preserve_opposing_cname_lineages() {
        let a = test_lookup(
            "m.stripe.network.",
            AddressFamily::Ipv4,
            vec![
                (
                    "m.stripe.network.".into(),
                    cname("prod-m-tree.stripe.network."),
                ),
                (
                    "prod-m-tree.stripe.network.".into(),
                    cname("stripecdn.map.fastly.net."),
                ),
                (
                    "stripecdn.map.fastly.net.".into(),
                    address("151.101.64.176"),
                ),
            ],
        );
        let aaaa = test_lookup(
            "m.stripe.network.",
            AddressFamily::Ipv6,
            vec![
                (
                    "m.stripe.network.".into(),
                    cname("prod-m-tree.stripe.network."),
                ),
                (
                    "prod-m-tree.stripe.network.".into(),
                    cname("d1tcqh4bio8cty.cloudfront.net."),
                ),
                (
                    "d1tcqh4bio8cty.cloudfront.net.".into(),
                    address("2600:9000:290c:fa00:19:7d10:bd80:93a1"),
                ),
            ],
        );
        let answers = vec![
            parse_dns_lookup("m.stripe.network", AddressFamily::Ipv4, &a),
            parse_dns_lookup("m.stripe.network", AddressFamily::Ipv6, &aaaa),
        ];
        let dns = DnsProvenance {
            classifier: DNS_CAPTURE_VERSION.into(),
            host: "m.stripe.network".into(),
            connection_candidates: vec!["151.101.64.176".into()],
            connection_resolution_unix_ms: Some(2),
            connection_resolution_reused: false,
            routing_answers: answers,
            routing_snapshot_unix_ms: Some(1),
            routing_snapshot_error: None,
        };
        assert_eq!(
            dns.routing_snapshot_binding(Some("151.101.64.176")),
            crate::model::RoutingSnapshotBinding::Matched
        );
        let v4 = dns.bound_routing_evidence(Some("151.101.64.176"));
        assert!(v4.contains(&"cname:stripecdn.map.fastly.net".to_owned()));
        assert!(!v4.contains(&"cname:d1tcqh4bio8cty.cloudfront.net".to_owned()));
        let v6 = dns.bound_routing_evidence(Some("2600:9000:290c:fa00:19:7d10:bd80:93a1"));
        assert!(v6.contains(&"cname:d1tcqh4bio8cty.cloudfront.net".to_owned()));
        assert!(!v6.contains(&"cname:stripecdn.map.fastly.net".to_owned()));
        let route = crate::routing::detect_routing_snapshot_elements(&dns);
        assert!(route.iter().any(|element| element.product == "fastly"));
        assert!(
            route
                .iter()
                .any(|element| element.product == "aws-cloudfront")
        );

        let endpoint = crate::fusion::assess_endpoint(&crate::model::EndpointEvidence {
            selected_endpoint: Some("151.101.64.176".into()),
            routing_snapshot_binding: dns.routing_snapshot_binding(Some("151.101.64.176")),
            routing_elements: route.clone(),
            routing_bound_evidence: v4,
            ..crate::model::EndpointEvidence::default()
        });
        assert_eq!(
            endpoint.state,
            crate::model::TerminationState::SingleCandidate
        );
        assert_eq!(endpoint.candidates[0].provider, "fastly");
        assert_eq!(
            endpoint.candidates[0].originating_channels,
            [crate::model::ProviderEvidenceChannel::RoutingDns]
        );
        assert_eq!(
            endpoint
                .path_elements
                .iter()
                .filter(|e| e.role == crate::model::PathElementRole::EdgeProvider)
                .count(),
            2
        );

        let endpoint = crate::fusion::assess_endpoint(&crate::model::EndpointEvidence {
            selected_endpoint: Some("2600:9000:290c:fa00:19:7d10:bd80:93a1".into()),
            routing_snapshot_binding: dns
                .routing_snapshot_binding(Some("2600:9000:290c:fa00:19:7d10:bd80:93a1")),
            routing_elements: route,
            routing_bound_evidence: v6,
            ..crate::model::EndpointEvidence::default()
        });
        assert_eq!(
            endpoint.state,
            crate::model::TerminationState::SingleCandidate
        );
        assert_eq!(endpoint.candidates[0].provider, "aws-cloudfront");
    }

    #[test]
    fn ambiguous_or_unrelated_answer_owners_never_bind_cname_to_socket() {
        let ambiguous = test_lookup(
            "site.example.",
            AddressFamily::Ipv4,
            vec![
                ("site.example.".into(), cname("fastly.map.fastly.net.")),
                ("site.example.".into(), cname("d1.cloudfront.net.")),
                ("fastly.map.fastly.net.".into(), address("192.0.2.10")),
            ],
        );
        let parsed = parse_dns_lookup("site.example", AddressFamily::Ipv4, &ambiguous);
        assert_eq!(parsed.ips, ["192.0.2.10"]);
        assert!(parsed.linked_ips.is_empty());
        assert_eq!(parsed.cname_links.len(), 2);

        let stray = test_lookup(
            "site.example.",
            AddressFamily::Ipv4,
            vec![
                ("site.example.".into(), cname("fastly.map.fastly.net.")),
                ("fastly.map.fastly.net.".into(), address("192.0.2.10")),
                ("unrelated.example.".into(), address("192.0.2.11")),
            ],
        );
        let parsed = parse_dns_lookup("site.example", AddressFamily::Ipv4, &stray);
        assert_eq!(parsed.ips, ["192.0.2.10", "192.0.2.11"]);
        assert_eq!(parsed.linked_ips, ["192.0.2.10"]);

        let flattened = test_lookup(
            "site.example.",
            AddressFamily::Ipv4,
            vec![("site.example.".into(), address("192.0.2.25"))],
        );
        let parsed = parse_dns_lookup("site.example", AddressFamily::Ipv4, &flattened);
        assert!(parsed.cname_chain.is_empty());
        assert_eq!(parsed.linked_ips, ["192.0.2.25"]);
    }

    #[test]
    fn routing_evidence_distinguishes_direct_hosts_from_cname_targets() {
        let direct = crate::routing::detect_routing_elements("d123.cloudfront.net", &[]);
        assert!(direct.iter().any(|e| {
            e.product == "aws-cloudfront" && e.evidence == ["host:d123.cloudfront.net"]
        }));
        let alias = crate::routing::detect_routing_elements(
            "customer.example.net",
            &["d123.cloudfront.net".into()],
        );
        assert!(alias.iter().any(|e| {
            e.product == "aws-cloudfront" && e.evidence == ["cname:d123.cloudfront.net"]
        }));
    }
}
