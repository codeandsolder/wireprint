use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use hickory_resolver::{TokioResolver, config::LookupIpStrategy, proto::rr::RData};
use url::Url;
use wreq::dns::{Addrs, GaiResolver, Name, Resolve, Resolving};

use crate::model::DnsProvenance;

pub const DNS_CAPTURE_VERSION: &str = "builtin-dns-v1";

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

#[derive(Clone, Default)]
pub(crate) struct RecordingResolver {
    inner: GaiResolver,
    state: Arc<Mutex<ResolverState>>,
}

impl RecordingResolver {
    pub(crate) fn cursor(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .sequence
    }

    pub(crate) fn latest(&self, host: &str) -> Option<ConnectionResolution> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .latest
            .get(&normalize_dns_name(host))
            .cloned()
    }
}

impl Resolve for RecordingResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let inner = self.inner.clone();
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let resolved = inner.resolve(name.clone()).await?;
            let addrs = resolved.collect::<Vec<_>>();
            let candidates = unique_ips(addrs.iter().map(SocketAddr::ip));
            let observed_unix_ms = unix_ms();
            let mut state = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.sequence = state.sequence.wrapping_add(1);
            let sequence = state.sequence;
            state.latest.insert(
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
    pub(crate) cname_chain: Vec<String>,
    pub(crate) ips: Vec<String>,
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
            builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
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
            return RoutingDnsSnapshot {
                observed_unix_ms,
                cname_chain: Vec::new(),
                ips: vec![ip.to_string()],
                error: None,
            };
        }

        let Some(resolver) = &self.resolver else {
            return RoutingDnsSnapshot {
                observed_unix_ms,
                cname_chain: Vec::new(),
                ips: Vec::new(),
                error: self.init_error.as_deref().map(str::to_owned),
            };
        };

        match resolver.lookup_ip(host.clone()).await {
            Ok(lookup) => {
                let mut aliases = HashMap::<String, String>::new();
                for record in lookup.as_lookup().answers() {
                    if let RData::CNAME(cname) = &record.data {
                        aliases.insert(
                            normalize_dns_name(&record.name.to_string()),
                            normalize_dns_name(&cname.0.to_string()),
                        );
                    }
                }

                let mut cname_chain = Vec::new();
                let mut seen = HashSet::new();
                let mut current = host;
                while seen.insert(current.clone()) {
                    let Some(next) = aliases.get(&current).cloned() else {
                        break;
                    };
                    cname_chain.push(next.clone());
                    current = next;
                    if cname_chain.len() >= 64 {
                        break;
                    }
                }

                RoutingDnsSnapshot {
                    observed_unix_ms,
                    cname_chain,
                    ips: unique_ips(lookup.iter()),
                    error: None,
                }
            }
            Err(error) => RoutingDnsSnapshot {
                observed_unix_ms,
                cname_chain: Vec::new(),
                ips: Vec::new(),
                error: Some(error.to_string()),
            },
        }
    }
}

pub(crate) fn build_dns_provenance(
    host: &str,
    cursor: u64,
    connection: Option<ConnectionResolution>,
    routing: RoutingDnsSnapshot,
) -> DnsProvenance {
    let host = normalize_dns_name(host);
    let mut connection_candidates = connection
        .as_ref()
        .map(|resolution| resolution.candidates.clone())
        .unwrap_or_default();
    if connection_candidates.is_empty()
        && let Ok(ip) = host.parse::<IpAddr>()
    {
        connection_candidates.push(ip.to_string());
    }

    DnsProvenance {
        classifier: DNS_CAPTURE_VERSION.into(),
        host,
        connection_candidates,
        connection_resolution_unix_ms: connection
            .as_ref()
            .map(|resolution| resolution.observed_unix_ms),
        connection_resolution_reused: connection
            .as_ref()
            .is_some_and(|resolution| resolution.sequence <= cursor),
        cname_chain: routing.cname_chain,
        routing_snapshot_ips: routing.ips,
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

pub(crate) fn routing_names(dns: &DnsProvenance) -> Vec<String> {
    let mut names = Vec::with_capacity(dns.cname_chain.len() + 1);
    names.push(dns.host.clone());
    names.extend(dns.cname_chain.iter().cloned());
    names
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

    #[test]
    fn selected_endpoint_requires_a_resolver_candidate_match() {
        let dns = DnsProvenance {
            classifier: DNS_CAPTURE_VERSION.into(),
            host: "example.com".into(),
            connection_candidates: vec!["192.0.2.10".into()],
            connection_resolution_unix_ms: Some(1),
            connection_resolution_reused: false,
            cname_chain: Vec::new(),
            routing_snapshot_ips: Vec::new(),
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

    #[test]
    fn routing_names_include_direct_provider_hostnames() {
        let dns = DnsProvenance {
            classifier: DNS_CAPTURE_VERSION.into(),
            host: "d123.cloudfront.net".into(),
            connection_candidates: Vec::new(),
            connection_resolution_unix_ms: None,
            connection_resolution_reused: false,
            cname_chain: vec!["terminal.example.net".into()],
            routing_snapshot_ips: Vec::new(),
            routing_snapshot_unix_ms: None,
            routing_snapshot_error: None,
        };
        assert_eq!(
            routing_names(&dns),
            vec!["d123.cloudfront.net", "terminal.example.net"]
        );
    }
}
