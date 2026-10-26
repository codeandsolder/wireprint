use serde::{Deserialize, Serialize};

use crate::h2::H2ServerPreface;
use crate::h3::H3ServerFingerprint;
use crate::tls::TlsServerMorphology;
use crate::transport::TransportProfile;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSet {
    pub profiles: Vec<RequestProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestProfile {
    pub name: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub provenance: Option<String>,
    #[serde(default)]
    pub headers: Vec<Header>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKind {
    ContentLike,
    Redirect,
    Challenge,
    Captcha,
    ExplicitBlock,
    RateLimited,
    ApplicationError,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Outcome {
    pub kind: OutcomeKind,
    pub classifier: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PathElementRole {
    EdgeProvider,
    ApplicationPlatform,
    OriginService,
    ReverseProxy,
    Cache,
    LoadBalancer,
    ApiGateway,
    ServiceMesh,
    IdentityProxy,
    TrafficManagement,
    Waf,
    SecurityMiddleware,
    BotManagement,
    ServerImplementation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathElement {
    pub role: PathElementRole,
    pub product: String,
    pub classifier: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProviderEvidenceChannel {
    ResponseMetadata,
    RoutingCname,
    H2Transport,
    H3Transport,
    TlsMorphology,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderSignal {
    pub provider: String,
    pub channel: ProviderEvidenceChannel,
    pub classifier: String,
    #[serde(default)]
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoutingContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(alias = "holder", skip_serializing_if = "Option::is_none")]
    pub as_name: Option<String>,
    #[serde(default)]
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoutingContextSnapshot {
    pub classifier: String,
    pub source: String,
    pub resource: String,
    pub observed_unix_ms: u128,
    pub lookup_reused: bool,
    #[serde(default)]
    pub contexts: Vec<RoutingContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EndpointEvidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_unix_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vantage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_peer: Option<String>,
    #[serde(default)]
    pub response_elements: Vec<PathElement>,
    #[serde(default)]
    pub routing_elements: Vec<PathElement>,
    #[serde(default)]
    pub provider_signals: Vec<ProviderSignal>,
    #[serde(default)]
    pub routing_context: Vec<RoutingContext>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSupport {
    OriginatingEvidence,
    CrossChannelCorroborated,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TerminationState {
    Unresolved,
    SingleCandidate,
    MultipleCandidates,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderCandidate {
    pub provider: String,
    pub support: ProviderSupport,
    pub originating_channels: Vec<ProviderEvidenceChannel>,
    pub corroborating_channels: Vec<ProviderEvidenceChannel>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndpointAssessment {
    pub classifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_unix_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vantage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_peer: Option<String>,
    pub state: TerminationState,
    pub candidates: Vec<ProviderCandidate>,
    pub path_elements: Vec<PathElement>,
    pub unanchored_corroborating_signals: Vec<ProviderSignal>,
    pub routing_context: Vec<RoutingContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsProvenance {
    pub classifier: String,
    pub host: String,
    #[serde(default)]
    pub connection_candidates: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_resolution_unix_ms: Option<u128>,
    pub connection_resolution_reused: bool,
    #[serde(default)]
    pub cname_chain: Vec<String>,
    #[serde(default)]
    pub routing_snapshot_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_snapshot_unix_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_snapshot_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub target: String,
    pub observed_unix_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vantage: Option<String>,
    pub request_profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_provenance: Option<String>,
    pub request_profile_headers: Vec<Header>,
    pub transport_profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    pub result: String,
    pub elapsed_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsProvenance>,
    pub response_headers: Vec<Header>,
    pub path_elements: Vec<PathElement>,
    #[serde(default)]
    pub routing_elements: Vec<PathElement>,
    #[serde(default)]
    pub provider_signals: Vec<ProviderSignal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_context_snapshot: Option<RoutingContextSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h2_server_preface: Option<H2ServerPreface>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h3_server_fingerprint: Option<H3ServerFingerprint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_server_morphology: Option<TlsServerMorphology>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_assessment: Option<EndpointAssessment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_captured_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_prefix_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_template_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_template_normalizer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl From<&Observation> for EndpointEvidence {
    fn from(observation: &Observation) -> Self {
        Self {
            target: Some(observation.target.clone()),
            observed_unix_ms: Some(observation.observed_unix_ms),
            vantage: observation.vantage.clone(),
            protocol: observation
                .transport_protocol
                .clone()
                .or_else(|| observation.http_version.clone()),
            selected_endpoint: observation.selected_endpoint.clone(),
            actual_peer: observation.remote.clone(),
            response_elements: observation.path_elements.clone(),
            routing_elements: observation.routing_elements.clone(),
            provider_signals: observation.provider_signals.clone(),
            routing_context: observation
                .routing_context_snapshot
                .as_ref()
                .map_or_default(|snapshot| snapshot.contexts.clone()),
        }
    }
}
