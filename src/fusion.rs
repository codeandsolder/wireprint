use std::collections::{BTreeMap, BTreeSet};

use crate::model::{
    EndpointAssessment, EndpointEvidence, PathElement, PathElementRole, ProviderCandidate,
    ProviderEvidenceChannel, ProviderSupport, TerminationState,
};

pub const ENDPOINT_FUSION_VERSION: &str = "builtin-endpoint-v1";

impl ProviderEvidenceChannel {
    const fn originates_termination(self) -> bool {
        !matches!(self, Self::TlsMorphology)
    }
}

#[derive(Debug, Default)]
struct CandidateBuilder {
    originating: BTreeSet<ProviderEvidenceChannel>,
    corroborating: BTreeSet<ProviderEvidenceChannel>,
    evidence: BTreeSet<String>,
}

fn push_path_element(target: &mut Vec<PathElement>, incoming: &PathElement) {
    if let Some(existing) = target.iter_mut().find(|item| {
        item.role == incoming.role
            && item.product == incoming.product
            && item.classifier == incoming.classifier
    }) {
        for evidence in &incoming.evidence {
            if !existing.evidence.contains(evidence) {
                existing.evidence.push(evidence.clone());
            }
        }
        return;
    }
    target.push(incoming.clone());
}

fn add_signal(
    candidates: &mut BTreeMap<String, CandidateBuilder>,
    provider: &str,
    channel: ProviderEvidenceChannel,
    evidence: impl IntoIterator<Item = String>,
) {
    let slot = candidates.entry(provider.to_owned()).or_default();
    if channel.originates_termination() {
        let _ = slot.originating.insert(channel);
    } else {
        let _ = slot.corroborating.insert(channel);
    }
    slot.evidence.extend(evidence);
}

/// Fuse one concrete endpoint/vantage observation without inventing hop order.
///
/// Response metadata, provider-managed CNAMEs and H2/H3 provider-family signals
/// may originate a termination candidate. TLS morphology is confirmatory-only.
/// Application-platform and middleware path elements remain participation claims
/// and are preserved verbatim rather than being promoted into outer providers.
#[must_use]
pub fn assess_endpoint(evidence: &EndpointEvidence) -> EndpointAssessment {
    let mut candidates = BTreeMap::<String, CandidateBuilder>::new();
    let mut path_elements = Vec::new();

    for element in &evidence.response_elements {
        push_path_element(&mut path_elements, element);
        if element.role == PathElementRole::EdgeProvider {
            add_signal(
                &mut candidates,
                &element.product,
                ProviderEvidenceChannel::ResponseMetadata,
                element.evidence.clone(),
            );
        }
    }

    for element in &evidence.routing_elements {
        push_path_element(&mut path_elements, element);
        if element.role == PathElementRole::EdgeProvider {
            add_signal(
                &mut candidates,
                &element.product,
                ProviderEvidenceChannel::RoutingCname,
                element.evidence.clone(),
            );
        }
    }

    let mut deferred = Vec::new();
    for signal in &evidence.provider_signals {
        if signal.channel.originates_termination() {
            add_signal(
                &mut candidates,
                &signal.provider,
                signal.channel,
                signal.evidence.clone(),
            );
        } else {
            deferred.push(signal.clone());
        }
    }

    let mut unanchored = Vec::new();
    for signal in deferred {
        if candidates.contains_key(&signal.provider) {
            add_signal(
                &mut candidates,
                &signal.provider,
                signal.channel,
                signal.evidence.clone(),
            );
        } else {
            unanchored.push(signal);
        }
    }

    let candidates = candidates
        .into_iter()
        .filter_map(|(provider, built)| {
            if built.originating.is_empty() {
                return None;
            }
            let support = if built.originating.len() + built.corroborating.len() >= 2 {
                ProviderSupport::CrossChannelCorroborated
            } else {
                ProviderSupport::OriginatingEvidence
            };
            Some(ProviderCandidate {
                provider,
                support,
                originating_channels: built.originating.into_iter().collect(),
                corroborating_channels: built.corroborating.into_iter().collect(),
                evidence: built.evidence.into_iter().collect(),
            })
        })
        .collect::<Vec<_>>();

    let state = match candidates.len() {
        0 => TerminationState::Unresolved,
        1 => TerminationState::SingleCandidate,
        _ => TerminationState::MultipleCandidates,
    };

    EndpointAssessment {
        classifier: ENDPOINT_FUSION_VERSION.into(),
        target: evidence.target.clone(),
        observed_unix_ms: evidence.observed_unix_ms,
        vantage: evidence.vantage.clone(),
        protocol: evidence.protocol.clone(),
        selected_endpoint: evidence.selected_endpoint.clone(),
        actual_peer: evidence.actual_peer.clone(),
        state,
        candidates,
        path_elements,
        unanchored_corroborating_signals: unanchored,
        routing_context: evidence.routing_context.clone(),
    }
}
