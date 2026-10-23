pub mod classify;
pub mod dns;
pub mod fusion;
pub mod h2;
pub mod host;
pub mod model;
pub mod normalize;
pub mod path;
pub mod probe;
pub mod routing;
pub mod transport;

pub use classify::classify_response;
pub use dns::DNS_CAPTURE_VERSION;
pub use fusion::{ENDPOINT_FUSION_VERSION, assess_endpoint};
pub use h2::{
    H2_PREFACE_CLASSIFIER_VERSION, H2ControlFrame, H2FingerprintMatch, H2FingerprintMatchKind,
    H2ServerPreface, H2Setting, classify_h2_preface, provider_signals as h2_provider_signals,
};
pub use host::{
    DEFAULT_HOST_FRESHNESS_WINDOW_MS, DEFAULT_SUPPORT_BUCKET_MS, HOST_FUSION_VERSION,
    HostAggregationConfig, HostAssessment, HostFreshnessBasis, HostProviderMembership,
    HostProviderState, HostProviderSupport, HostRouteGroup, HostSupportGroup, aggregate_host,
    aggregate_observations,
};
pub use model::{
    DnsProvenance, EndpointAssessment, EndpointEvidence, Header, Observation, Outcome, OutcomeKind,
    PathElement, PathElementRole, ProfileSet, ProviderCandidate, ProviderEvidenceChannel,
    ProviderSignal, ProviderSupport, RequestProfile, RoutingContext, TerminationState,
};
pub use normalize::{NORMALIZER_VERSION, normalize_response_template};
pub use path::{PATH_CLASSIFIER_VERSION, detect_path_elements};
pub use probe::{ProbeConfig, probe_batch};
pub use routing::{ROUTING_CLASSIFIER_VERSION, detect_routing_elements};
pub use transport::{PlatformKind, TransportProfile};
