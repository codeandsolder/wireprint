pub mod classify;
pub mod fusion;
pub mod model;
pub mod normalize;
pub mod path;
pub mod probe;
pub mod routing;
pub mod transport;

pub use classify::classify_response;
pub use fusion::{
    ENDPOINT_FUSION_VERSION, EndpointAssessment, EndpointEvidence, ProviderCandidate,
    ProviderEvidenceChannel, ProviderSignal, ProviderSupport, RoutingContext, TerminationState,
    assess_endpoint,
};
pub use model::{
    Header, Observation, Outcome, OutcomeKind, PathElement, PathElementRole, ProfileSet,
    RequestProfile,
};
pub use normalize::{NORMALIZER_VERSION, normalize_response_template};
pub use path::{PATH_CLASSIFIER_VERSION, detect_path_elements};
pub use probe::{ProbeConfig, probe_batch};
pub use routing::{ROUTING_CLASSIFIER_VERSION, detect_routing_elements};
pub use transport::{PlatformKind, TransportProfile};
