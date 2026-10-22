pub mod classify;
pub mod dns;
pub mod fusion;
pub mod model;
pub mod normalize;
pub mod path;
pub mod probe;
pub mod routing;
pub mod transport;

pub use classify::classify_response;
pub use dns::DNS_CAPTURE_VERSION;
pub use fusion::{ENDPOINT_FUSION_VERSION, assess_endpoint};
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
