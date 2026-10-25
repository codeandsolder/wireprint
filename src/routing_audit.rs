use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::fusion::assess_endpoint;
use crate::model::{EndpointEvidence, Observation, RoutingContext, TerminationState};

pub const ROUTING_CONTEXT_AUDIT_VERSION: &str = "builtin-routing-context-audit-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoutingAuditSample {
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vantage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub contexts: Vec<RoutingContext>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AsnAuditClass {
    PureInSample,
    CrossProviderCollision,
    BroadOrUnresolved,
    InsufficientLabeledHosts,
    Unlabeled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AsnRoutingAudit {
    pub asn: u32,
    pub class: AsnAuditClass,
    pub as_names: Vec<String>,
    pub distinct_hosts: usize,
    pub labeled_hosts: usize,
    pub unlabeled_hosts: usize,
    pub unlabeled_hostnames: Vec<String>,
    pub providers: BTreeMap<String, usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_provider_host_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_provider_purity: Option<f64>,
    pub provider_conflict_hosts: Vec<String>,
    pub prefixes: Vec<String>,
    pub vantages: Vec<String>,
    pub endpoints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderAsnAudit {
    pub provider: String,
    pub distinct_hosts: usize,
    pub asns: BTreeMap<u32, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostRoutingAudit {
    pub host: String,
    pub providers: Vec<String>,
    pub asns: Vec<u32>,
    pub prefixes: Vec<String>,
    pub vantages: Vec<String>,
    pub endpoints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RoutingContextAudit {
    pub classifier: String,
    pub reference_policy: String,
    pub counting_unit: String,
    pub classification_policy: String,
    pub min_labeled_hosts: usize,
    pub sample_count: usize,
    pub distinct_hosts: usize,
    pub distinct_asns: usize,
    pub class_counts: BTreeMap<AsnAuditClass, usize>,
    pub asns: Vec<AsnRoutingAudit>,
    pub providers: Vec<ProviderAsnAudit>,
    pub hosts: Vec<HostRoutingAudit>,
}

pub fn samples_from_observations(observations: &[Observation]) -> Vec<RoutingAuditSample> {
    observations
        .iter()
        .filter_map(|observation| {
            let contexts = observation
                .routing_context_snapshot
                .as_ref()
                .map(|snapshot| snapshot.contexts.clone())
                .unwrap_or_default();
            if contexts.is_empty() {
                return None;
            }

            // Recompute with the current endpoint-fusion implementation rather
            // than trusting a serialized assessment from an older classifier.
            // RoutingContext is carried through EndpointEvidence but is not a
            // provider evidence channel, so it cannot label its own audit row.
            let assessment = assess_endpoint(&EndpointEvidence::from(observation));
            let provider = if assessment.state == TerminationState::SingleCandidate
                && assessment.candidates.len() == 1
            {
                Some(assessment.candidates[0].provider.clone())
            } else {
                None
            };

            let host = observation
                .final_uri
                .as_deref()
                .and_then(hostname)
                .or_else(|| hostname(&observation.target))?;
            let endpoint = observation
                .selected_endpoint
                .clone()
                .or_else(|| observation.remote.clone());

            Some(RoutingAuditSample {
                host,
                provider,
                vantage: observation.vantage.clone(),
                endpoint,
                contexts,
            })
        })
        .collect()
}

pub fn audit_routing_samples(
    samples: &[RoutingAuditSample],
    min_labeled_hosts: usize,
) -> RoutingContextAudit {
    let min_labeled_hosts = min_labeled_hosts.max(1);

    #[derive(Default)]
    struct AsnBuild {
        names: BTreeSet<String>,
        hosts: BTreeSet<String>,
        labeled_hosts: BTreeSet<String>,
        unlabeled_hosts: BTreeSet<String>,
        provider_hosts: BTreeMap<String, BTreeSet<String>>,
        host_providers: BTreeMap<String, BTreeSet<String>>,
        prefixes: BTreeSet<String>,
        vantages: BTreeSet<String>,
        endpoints: BTreeSet<String>,
    }

    #[derive(Default)]
    struct ProviderBuild {
        hosts: BTreeSet<String>,
        asn_hosts: BTreeMap<u32, BTreeSet<String>>,
    }

    #[derive(Default)]
    struct HostBuild {
        providers: BTreeSet<String>,
        asns: BTreeSet<u32>,
        prefixes: BTreeSet<String>,
        vantages: BTreeSet<String>,
        endpoints: BTreeSet<String>,
    }

    let mut by_asn = BTreeMap::<u32, AsnBuild>::new();
    let mut by_provider = BTreeMap::<String, ProviderBuild>::new();
    let mut by_host = BTreeMap::<String, HostBuild>::new();

    for sample in samples {
        let host_slot = by_host.entry(sample.host.clone()).or_default();
        if let Some(provider) = &sample.provider {
            host_slot.providers.insert(provider.clone());
        }
        if let Some(vantage) = &sample.vantage {
            host_slot.vantages.insert(vantage.clone());
        }
        if let Some(endpoint) = &sample.endpoint {
            host_slot.endpoints.insert(endpoint.clone());
        }

        let mut sample_asns = BTreeSet::new();
        for context in &sample.contexts {
            let Some(asn) = context.asn else {
                continue;
            };
            sample_asns.insert(asn);
            let slot = by_asn.entry(asn).or_default();
            slot.hosts.insert(sample.host.clone());
            if let Some(name) = &context.as_name {
                slot.names.insert(name.clone());
            }
            if let Some(prefix) = &context.prefix {
                slot.prefixes.insert(prefix.clone());
                host_slot.prefixes.insert(prefix.clone());
            }
            if let Some(vantage) = &sample.vantage {
                slot.vantages.insert(vantage.clone());
            }
            if let Some(endpoint) = &sample.endpoint {
                slot.endpoints.insert(endpoint.clone());
            }
            host_slot.asns.insert(asn);

            if let Some(provider) = &sample.provider {
                slot.labeled_hosts.insert(sample.host.clone());
                slot.provider_hosts
                    .entry(provider.clone())
                    .or_default()
                    .insert(sample.host.clone());
                slot.host_providers
                    .entry(sample.host.clone())
                    .or_default()
                    .insert(provider.clone());
            } else {
                slot.unlabeled_hosts.insert(sample.host.clone());
            }
        }

        if let Some(provider) = &sample.provider {
            let provider_slot = by_provider.entry(provider.clone()).or_default();
            provider_slot.hosts.insert(sample.host.clone());
            for asn in sample_asns {
                provider_slot
                    .asn_hosts
                    .entry(asn)
                    .or_default()
                    .insert(sample.host.clone());
            }
        }
    }

    // A host may have both labeled and unlabeled observations for the same ASN.
    // Labeled evidence wins only for the accounting of that host; this prevents
    // a transient unresolved retry from making an otherwise labeled host broad.
    for slot in by_asn.values_mut() {
        slot.unlabeled_hosts
            .retain(|host| !slot.labeled_hosts.contains(host));
    }

    let mut class_counts = BTreeMap::new();
    let mut asns = Vec::new();
    for (asn, slot) in by_asn {
        let providers = slot
            .provider_hosts
            .iter()
            .map(|(provider, hosts)| (provider.clone(), hosts.len()))
            .collect::<BTreeMap<_, _>>();
        let top = providers
            .iter()
            .max_by(|left, right| left.1.cmp(right.1).then_with(|| right.0.cmp(left.0)))
            .map(|(provider, count)| (provider.clone(), *count));
        let conflict_hosts = slot
            .host_providers
            .iter()
            .filter(|(_, providers)| providers.len() > 1)
            .map(|(host, _)| host.clone())
            .collect::<Vec<_>>();

        let class = if slot.labeled_hosts.is_empty() {
            AsnAuditClass::Unlabeled
        } else if providers.len() > 1 || !conflict_hosts.is_empty() {
            AsnAuditClass::CrossProviderCollision
        } else if !slot.unlabeled_hosts.is_empty() {
            AsnAuditClass::BroadOrUnresolved
        } else if slot.labeled_hosts.len() < min_labeled_hosts {
            AsnAuditClass::InsufficientLabeledHosts
        } else {
            AsnAuditClass::PureInSample
        };
        *class_counts.entry(class).or_insert(0) += 1;

        let top_provider_purity = top
            .as_ref()
            .map(|(_, count)| *count as f64 / slot.labeled_hosts.len() as f64);
        asns.push(AsnRoutingAudit {
            asn,
            class,
            as_names: slot.names.into_iter().collect(),
            distinct_hosts: slot.hosts.len(),
            labeled_hosts: slot.labeled_hosts.len(),
            unlabeled_hosts: slot.unlabeled_hosts.len(),
            unlabeled_hostnames: slot.unlabeled_hosts.into_iter().collect(),
            providers,
            top_provider: top.as_ref().map(|(provider, _)| provider.clone()),
            top_provider_host_count: top.as_ref().map(|(_, count)| *count),
            top_provider_purity,
            provider_conflict_hosts: conflict_hosts,
            prefixes: slot.prefixes.into_iter().collect(),
            vantages: slot.vantages.into_iter().collect(),
            endpoints: slot.endpoints.into_iter().collect(),
        });
    }

    let providers = by_provider
        .into_iter()
        .map(|(provider, slot)| ProviderAsnAudit {
            provider,
            distinct_hosts: slot.hosts.len(),
            asns: slot
                .asn_hosts
                .into_iter()
                .map(|(asn, hosts)| (asn, hosts.len()))
                .collect(),
        })
        .collect();

    let hosts = by_host
        .into_iter()
        .map(|(host, slot)| HostRoutingAudit {
            host,
            providers: slot.providers.into_iter().collect(),
            asns: slot.asns.into_iter().collect(),
            prefixes: slot.prefixes.into_iter().collect(),
            vantages: slot.vantages.into_iter().collect(),
            endpoints: slot.endpoints.into_iter().collect(),
        })
        .collect::<Vec<_>>();

    RoutingContextAudit {
        classifier: ROUTING_CONTEXT_AUDIT_VERSION.into(),
        reference_policy: "current single-candidate endpoint fusion only; routing context is excluded from provider inference".into(),
        counting_unit: "distinct_hostname".into(),
        classification_policy: "pure_in_sample requires exactly one labeled provider, zero unlabeled hosts, no per-host provider conflict, and at least min_labeled_hosts; it is not a mapping recommendation".into(),
        min_labeled_hosts,
        sample_count: samples.len(),
        distinct_hosts: hosts.len(),
        distinct_asns: asns.len(),
        class_counts,
        asns,
        providers,
        hosts,
    }
}

fn hostname(value: &str) -> Option<String> {
    Url::parse(value)
        .ok()
        .and_then(|url| url.host_str().map(|host| host.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(asn: u32) -> RoutingContext {
        RoutingContext {
            prefix: Some(format!("192.0.2.0/24-{asn}")),
            asn: Some(asn),
            as_name: Some(format!("AS{asn}")),
            evidence: Vec::new(),
        }
    }

    fn sample(host: &str, provider: Option<&str>, asn: u32) -> RoutingAuditSample {
        RoutingAuditSample {
            host: host.into(),
            provider: provider.map(str::to_owned),
            vantage: Some("test".into()),
            endpoint: Some("192.0.2.1".into()),
            contexts: vec![context(asn)],
        }
    }

    #[test]
    fn repeated_requests_do_not_inflate_host_counts() {
        let audit = audit_routing_samples(
            &[
                sample("a.test", Some("cloudflare"), 13_335),
                sample("a.test", Some("cloudflare"), 13_335),
            ],
            2,
        );
        let asn = &audit.asns[0];
        assert_eq!(asn.distinct_hosts, 1);
        assert_eq!(asn.labeled_hosts, 1);
        assert_eq!(asn.providers["cloudflare"], 1);
        assert_eq!(asn.class, AsnAuditClass::InsufficientLabeledHosts);
    }

    #[test]
    fn cross_provider_reuse_is_an_explicit_collision() {
        let audit = audit_routing_samples(
            &[
                sample("a.test", Some("fastly"), 54_113),
                sample("b.test", Some("akamai"), 54_113),
            ],
            2,
        );
        let asn = &audit.asns[0];
        assert_eq!(asn.class, AsnAuditClass::CrossProviderCollision);
        assert_eq!(asn.providers.len(), 2);
        assert_eq!(asn.top_provider_purity, Some(0.5));
    }

    #[test]
    fn unlabeled_hosts_keep_an_asn_from_becoming_a_mapping_candidate() {
        let audit = audit_routing_samples(
            &[
                sample("a.test", Some("cloudflare"), 13_335),
                sample("b.test", Some("cloudflare"), 13_335),
                sample("c.test", None, 13_335),
            ],
            2,
        );
        let asn = &audit.asns[0];
        assert_eq!(asn.class, AsnAuditClass::BroadOrUnresolved);
        assert_eq!(asn.labeled_hosts, 2);
        assert_eq!(asn.unlabeled_hosts, 1);
    }

    #[test]
    fn two_distinct_pure_hosts_are_only_pure_in_sample() {
        let audit = audit_routing_samples(
            &[
                sample("a.test", Some("cloudflare"), 13_335),
                sample("b.test", Some("cloudflare"), 13_335),
            ],
            2,
        );
        let asn = &audit.asns[0];
        assert_eq!(asn.class, AsnAuditClass::PureInSample);
        assert_eq!(asn.top_provider_purity, Some(1.0));
    }

    #[test]
    fn labeled_observation_prevents_unresolved_retry_from_counting_as_unlabeled_host() {
        let audit = audit_routing_samples(
            &[
                sample("a.test", None, 13_335),
                sample("a.test", Some("cloudflare"), 13_335),
                sample("b.test", Some("cloudflare"), 13_335),
            ],
            2,
        );
        let asn = &audit.asns[0];
        assert_eq!(asn.unlabeled_hosts, 0);
        assert_eq!(asn.class, AsnAuditClass::PureInSample);
    }
}
