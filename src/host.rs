use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::model::{EndpointAssessment, Observation, ProviderEvidenceChannel};

pub const HOST_FUSION_VERSION: &str = "builtin-host-v1";
pub const DEFAULT_HOST_FRESHNESS_WINDOW_MS: u128 = 6 * 60 * 60 * 1000;
pub const DEFAULT_SUPPORT_BUCKET_MS: u128 = 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostProviderState {
    Unresolved,
    SingleCurrentProvider,
    MultipleCurrentProvidersOrPathSplit,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostFreshnessBasis {
    TrailingWindow,
    UntimedEvidence,
    NoProviderEvidence,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostProviderSupport {
    CurrentOriginatingEvidence,
    CurrentCrossChannelCorroborated,
    CurrentWithHistoricalCrossChannelCorroboration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostSupportGroup {
    pub provider: String,
    pub channel: ProviderEvidenceChannel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vantage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket_start_unix_ms: Option<u128>,
    pub raw_observations: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_observed_unix_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_observed_unix_ms: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostRouteGroup {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vantage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket_start_unix_ms: Option<u128>,
    pub providers: Vec<String>,
    pub raw_observations: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_observed_unix_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_observed_unix_ms: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostProviderMembership {
    pub provider: String,
    pub support: HostProviderSupport,
    pub current_originating_channels: Vec<ProviderEvidenceChannel>,
    pub current_corroborating_channels: Vec<ProviderEvidenceChannel>,
    pub historical_originating_channels: Vec<ProviderEvidenceChannel>,
    pub historical_corroborating_channels: Vec<ProviderEvidenceChannel>,
    pub current_independent_group_count: usize,
    pub historical_independent_group_count: usize,
    pub current_protocols: Vec<String>,
    pub current_vantages: Vec<String>,
    pub current_endpoints: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_observed_unix_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_observed_unix_ms: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostAssessment {
    pub classifier: String,
    pub host: String,
    pub freshness_window_ms: u128,
    pub support_bucket_ms: u128,
    pub current_basis: HostFreshnessBasis,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_provider_observed_unix_ms: Option<u128>,
    pub state: HostProviderState,
    pub current_provider_set: Vec<String>,
    pub historical_provider_set: Vec<String>,
    pub current_memberships: Vec<HostProviderMembership>,
    pub current_support_groups: Vec<HostSupportGroup>,
    pub historical_support_groups: Vec<HostSupportGroup>,
    pub current_route_groups: Vec<HostRouteGroup>,
    pub raw_endpoint_assessments: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostAggregationConfig {
    pub freshness_window_ms: u128,
    pub support_bucket_ms: u128,
}

impl Default for HostAggregationConfig {
    fn default() -> Self {
        Self {
            freshness_window_ms: DEFAULT_HOST_FRESHNESS_WINDOW_MS,
            support_bucket_ms: DEFAULT_SUPPORT_BUCKET_MS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SupportGroupKey {
    provider: String,
    channel: ProviderEvidenceChannel,
    protocol: Option<String>,
    vantage: Option<String>,
    endpoint: Option<String>,
    bucket_start_unix_ms: Option<u128>,
}

#[derive(Debug, Default)]
struct SupportGroupBuilder {
    raw_observations: usize,
    first_observed_unix_ms: Option<u128>,
    last_observed_unix_ms: Option<u128>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RouteGroupKey {
    protocol: Option<String>,
    vantage: Option<String>,
    endpoint: Option<String>,
    bucket_start_unix_ms: Option<u128>,
}

#[derive(Debug, Default)]
struct RouteGroupBuilder {
    providers: BTreeSet<String>,
    raw_observations: usize,
    first_observed_unix_ms: Option<u128>,
    last_observed_unix_ms: Option<u128>,
}

#[derive(Debug, Default)]
struct MembershipBuilder {
    current_originating_channels: BTreeSet<ProviderEvidenceChannel>,
    current_corroborating_channels: BTreeSet<ProviderEvidenceChannel>,
    historical_originating_channels: BTreeSet<ProviderEvidenceChannel>,
    historical_corroborating_channels: BTreeSet<ProviderEvidenceChannel>,
    current_protocols: BTreeSet<String>,
    current_vantages: BTreeSet<String>,
    current_endpoints: BTreeSet<String>,
    first_observed_unix_ms: Option<u128>,
    last_observed_unix_ms: Option<u128>,
}

fn update_time_range(first: &mut Option<u128>, last: &mut Option<u128>, value: Option<u128>) {
    let Some(value) = value else {
        return;
    };
    *first = Some(first.map_or(value, |current| current.min(value)));
    *last = Some(last.map_or(value, |current| current.max(value)));
}

fn endpoint(assessment: &EndpointAssessment) -> Option<String> {
    assessment
        .selected_endpoint
        .clone()
        .or_else(|| assessment.actual_peer.clone())
}

fn bucket_start(value: Option<u128>, bucket_ms: u128) -> Option<u128> {
    let value = value?;
    if bucket_ms == 0 {
        return Some(value);
    }
    Some(value / bucket_ms * bucket_ms)
}

fn has_provider_candidates(assessment: &EndpointAssessment) -> bool {
    !assessment.candidates.is_empty()
}

fn is_current(
    assessment: &EndpointAssessment,
    latest_provider_observed_unix_ms: Option<u128>,
    freshness_window_ms: u128,
) -> bool {
    match latest_provider_observed_unix_ms {
        Some(latest) => assessment.observed_unix_ms.is_some_and(|observed| {
            observed <= latest && observed >= latest.saturating_sub(freshness_window_ms)
        }),
        None => has_provider_candidates(assessment),
    }
}

fn collect_support_groups<'a>(
    assessments: impl IntoIterator<Item = &'a EndpointAssessment>,
    bucket_ms: u128,
) -> Vec<HostSupportGroup> {
    let mut groups = BTreeMap::<SupportGroupKey, SupportGroupBuilder>::new();
    for assessment in assessments {
        let endpoint = endpoint(assessment);
        for candidate in &assessment.candidates {
            let channels = candidate
                .originating_channels
                .iter()
                .chain(candidate.corroborating_channels.iter());
            for channel in channels {
                let key = SupportGroupKey {
                    provider: candidate.provider.clone(),
                    protocol: assessment.protocol.clone(),
                    channel: *channel,
                    vantage: assessment.vantage.clone(),
                    endpoint: endpoint.clone(),
                    bucket_start_unix_ms: bucket_start(assessment.observed_unix_ms, bucket_ms),
                };
                let slot = groups.entry(key).or_default();
                slot.raw_observations += 1;
                update_time_range(
                    &mut slot.first_observed_unix_ms,
                    &mut slot.last_observed_unix_ms,
                    assessment.observed_unix_ms,
                );
            }
        }
    }

    groups
        .into_iter()
        .map(|(key, built)| HostSupportGroup {
            provider: key.provider,
            channel: key.channel,
            protocol: key.protocol,
            vantage: key.vantage,
            endpoint: key.endpoint,
            bucket_start_unix_ms: key.bucket_start_unix_ms,
            raw_observations: built.raw_observations,
            first_observed_unix_ms: built.first_observed_unix_ms,
            last_observed_unix_ms: built.last_observed_unix_ms,
        })
        .collect()
}

fn collect_route_groups<'a>(
    assessments: impl IntoIterator<Item = &'a EndpointAssessment>,
    bucket_ms: u128,
) -> Vec<HostRouteGroup> {
    let mut groups = BTreeMap::<RouteGroupKey, RouteGroupBuilder>::new();
    for assessment in assessments {
        if assessment.candidates.is_empty() {
            continue;
        }
        let key = RouteGroupKey {
            protocol: assessment.protocol.clone(),
            vantage: assessment.vantage.clone(),
            endpoint: endpoint(assessment),
            bucket_start_unix_ms: bucket_start(assessment.observed_unix_ms, bucket_ms),
        };
        let slot = groups.entry(key).or_default();
        slot.raw_observations += 1;
        slot.providers.extend(
            assessment
                .candidates
                .iter()
                .map(|candidate| candidate.provider.clone()),
        );
        update_time_range(
            &mut slot.first_observed_unix_ms,
            &mut slot.last_observed_unix_ms,
            assessment.observed_unix_ms,
        );
    }

    groups
        .into_iter()
        .map(|(key, built)| HostRouteGroup {
            protocol: key.protocol,
            vantage: key.vantage,
            endpoint: key.endpoint,
            bucket_start_unix_ms: key.bucket_start_unix_ms,
            providers: built.providers.into_iter().collect(),
            raw_observations: built.raw_observations,
            first_observed_unix_ms: built.first_observed_unix_ms,
            last_observed_unix_ms: built.last_observed_unix_ms,
        })
        .collect()
}

pub fn aggregate_host(
    host: impl Into<String>,
    assessments: &[EndpointAssessment],
    config: HostAggregationConfig,
) -> HostAssessment {
    let latest_provider_observed_unix_ms = assessments
        .iter()
        .filter(|assessment| has_provider_candidates(assessment))
        .filter_map(|assessment| assessment.observed_unix_ms)
        .max();

    let current_basis = if latest_provider_observed_unix_ms.is_some() {
        HostFreshnessBasis::TrailingWindow
    } else if assessments.iter().any(has_provider_candidates) {
        HostFreshnessBasis::UntimedEvidence
    } else {
        HostFreshnessBasis::NoProviderEvidence
    };

    let current = assessments
        .iter()
        .filter(|assessment| {
            is_current(
                assessment,
                latest_provider_observed_unix_ms,
                config.freshness_window_ms,
            ) && has_provider_candidates(assessment)
        })
        .collect::<Vec<_>>();

    let historical_provider_set = assessments
        .iter()
        .flat_map(|assessment| assessment.candidates.iter())
        .map(|candidate| candidate.provider.clone())
        .collect::<BTreeSet<_>>();
    let current_provider_set = current
        .iter()
        .flat_map(|assessment| assessment.candidates.iter())
        .map(|candidate| candidate.provider.clone())
        .collect::<BTreeSet<_>>();

    let historical_support_groups =
        collect_support_groups(assessments.iter(), config.support_bucket_ms);
    let current_support_groups =
        collect_support_groups(current.iter().copied(), config.support_bucket_ms);
    let current_route_groups =
        collect_route_groups(current.iter().copied(), config.support_bucket_ms);

    let mut memberships = BTreeMap::<String, MembershipBuilder>::new();
    for assessment in assessments {
        let current_assessment = is_current(
            assessment,
            latest_provider_observed_unix_ms,
            config.freshness_window_ms,
        );
        let endpoint = endpoint(assessment);
        for candidate in &assessment.candidates {
            let slot = memberships.entry(candidate.provider.clone()).or_default();
            slot.historical_originating_channels
                .extend(candidate.originating_channels.iter().copied());
            slot.historical_corroborating_channels
                .extend(candidate.corroborating_channels.iter().copied());
            update_time_range(
                &mut slot.first_observed_unix_ms,
                &mut slot.last_observed_unix_ms,
                assessment.observed_unix_ms,
            );
            if current_assessment {
                if let Some(protocol) = &assessment.protocol {
                    slot.current_protocols.insert(protocol.clone());
                }
                slot.current_originating_channels
                    .extend(candidate.originating_channels.iter().copied());
                slot.current_corroborating_channels
                    .extend(candidate.corroborating_channels.iter().copied());
                if let Some(vantage) = &assessment.vantage {
                    slot.current_vantages.insert(vantage.clone());
                }
                if let Some(endpoint) = &endpoint {
                    slot.current_endpoints.insert(endpoint.clone());
                }
            }
        }
    }

    let current_memberships = current_provider_set
        .iter()
        .filter_map(|provider| {
            let built = memberships.get(provider)?;
            let current_channels = built
                .current_originating_channels
                .iter()
                .chain(built.current_corroborating_channels.iter())
                .copied()
                .collect::<BTreeSet<_>>();
            let historical_channels = built
                .historical_originating_channels
                .iter()
                .chain(built.historical_corroborating_channels.iter())
                .copied()
                .collect::<BTreeSet<_>>();
            let support = if current_channels.len() >= 2 {
                HostProviderSupport::CurrentCrossChannelCorroborated
            } else if historical_channels.len() >= 2 {
                HostProviderSupport::CurrentWithHistoricalCrossChannelCorroboration
            } else {
                HostProviderSupport::CurrentOriginatingEvidence
            };
            Some(HostProviderMembership {
                provider: provider.clone(),
                support,
                current_originating_channels: built
                    .current_originating_channels
                    .iter()
                    .copied()
                    .collect(),
                current_corroborating_channels: built
                    .current_corroborating_channels
                    .iter()
                    .copied()
                    .collect(),
                historical_originating_channels: built
                    .historical_originating_channels
                    .iter()
                    .copied()
                    .collect(),
                historical_corroborating_channels: built
                    .historical_corroborating_channels
                    .iter()
                    .copied()
                    .collect(),
                current_independent_group_count: current_support_groups
                    .iter()
                    .filter(|group| group.provider == *provider)
                    .count(),
                historical_independent_group_count: historical_support_groups
                    .iter()
                    .filter(|group| group.provider == *provider)
                    .count(),
                current_protocols: built.current_protocols.iter().cloned().collect(),
                current_vantages: built.current_vantages.iter().cloned().collect(),
                current_endpoints: built.current_endpoints.iter().cloned().collect(),
                first_observed_unix_ms: built.first_observed_unix_ms,
                last_observed_unix_ms: built.last_observed_unix_ms,
            })
        })
        .collect::<Vec<_>>();

    let state = match current_provider_set.len() {
        0 => HostProviderState::Unresolved,
        1 => HostProviderState::SingleCurrentProvider,
        _ => HostProviderState::MultipleCurrentProvidersOrPathSplit,
    };

    HostAssessment {
        classifier: HOST_FUSION_VERSION.into(),
        host: host.into(),
        freshness_window_ms: config.freshness_window_ms,
        support_bucket_ms: config.support_bucket_ms,
        current_basis,
        latest_provider_observed_unix_ms,
        state,
        current_provider_set: current_provider_set.into_iter().collect(),
        historical_provider_set: historical_provider_set.into_iter().collect(),
        current_memberships,
        current_support_groups,
        historical_support_groups,
        current_route_groups,
        raw_endpoint_assessments: assessments.len(),
    }
}

fn observation_host(observation: &Observation) -> Option<String> {
    observation
        .final_uri
        .as_deref()
        .and_then(|value| Url::parse(value).ok())
        .and_then(|url| url.host_str().map(str::to_owned))
        .or_else(|| {
            Url::parse(&observation.target)
                .ok()
                .and_then(|url| url.host_str().map(str::to_owned))
        })
}

pub fn aggregate_observations(
    observations: &[Observation],
    config: HostAggregationConfig,
) -> Vec<HostAssessment> {
    let mut grouped = BTreeMap::<String, Vec<EndpointAssessment>>::new();
    for observation in observations {
        let Some(assessment) = observation.endpoint_assessment.clone() else {
            continue;
        };
        let Some(host) = observation_host(observation) else {
            continue;
        };
        grouped.entry(host).or_default().push(assessment);
    }

    grouped
        .into_iter()
        .map(|(host, assessments)| aggregate_host(host, &assessments, config))
        .collect()
}
