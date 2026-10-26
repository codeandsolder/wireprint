pub mod classify;
pub mod dns;
pub mod fusion;
pub mod h2;
pub mod h3;
pub mod h3_probe;
pub mod host;
mod hyper_probe;
pub mod model;
pub mod normalize;
pub mod path;
pub mod probe;
pub mod routing;
pub mod routing_audit;
pub mod routing_context;
pub mod tls;
pub mod tls_probe;
pub mod transport;

pub use classify::classify_response;
pub use dns::DNS_CAPTURE_VERSION;
pub use fusion::{ENDPOINT_FUSION_VERSION, assess_endpoint};
pub use h2::{
    H2_PREFACE_CLASSIFIER_VERSION, H2ControlFrame, H2FingerprintMatch, H2FingerprintMatchKind,
    H2ServerPreface, H2Setting, classify_h2_preface, provider_signals as h2_provider_signals,
};
pub use h3::{
    H3_QUIC_CLASSIFIER_VERSION, H3FingerprintMatch, H3FingerprintMatchKind, H3ServerFingerprint,
    H3Setting, QuicStableTransportParameters, QuicTransportParameterWire, QuicTransportStructure,
    QuicVersionInformation, classify_h3_quic, provider_signals as h3_provider_signals,
};
pub use h3_probe::{H3AddressFamily, H3ProbeConfig, probe_h3};
pub use host::{
    DEFAULT_HOST_FRESHNESS_WINDOW_MS, DEFAULT_SUPPORT_BUCKET_MS, HOST_FUSION_VERSION,
    HostAggregationConfig, HostAssessment, HostFreshnessBasis, HostProviderMembership,
    HostProviderState, HostProviderSupport, HostRouteGroup, HostSupportGroup, aggregate_host,
    aggregate_observations,
};
pub use model::{
    DnsProvenance, EndpointAssessment, EndpointEvidence, Header, Observation, Outcome, OutcomeKind,
    PathElement, PathElementRole, ProfileSet, ProviderCandidate, ProviderEvidenceChannel,
    ProviderSignal, ProviderSupport, RequestProfile, RoutingContext, RoutingContextSnapshot,
    TerminationState,
};
pub use normalize::{NORMALIZER_VERSION, normalize_response_template};
pub use path::{PATH_CLASSIFIER_VERSION, detect_path_elements};
pub use probe::{ProbeConfig, probe_batch};
pub use routing::{ROUTING_CLASSIFIER_VERSION, detect_routing_elements};
pub use routing_audit::{
    AsnAuditClass, AsnRoutingAudit, HostRoutingAudit, ProviderAsnAudit,
    ROUTING_CONTEXT_AUDIT_VERSION, RoutingAuditSample, RoutingContextAudit, audit_routing_samples,
    samples_from_observations,
};
pub use routing_context::{
    ROUTING_CONTEXT_VERSION, RoutingContextCollector, enrich_observation as enrich_routing_context,
    observation_routing_address,
};
pub use tls::{
    TLS_MORPHOLOGY_VERSION, TlsExtensionShape, TlsHandshakeMessageShape, TlsMessageCapture,
    TlsMorphologyMatch, TlsServerMorphology, TlsSessionTicketShape,
    provider_signals as tls_provider_signals,
};
pub use tls_probe::{TlsAddressFamily, TlsProbeConfig, probe_tls};
pub use transport::{
    BuiltinTransport, HyperRustlsProfileKind, PlatformKind, TRANSPORT_SCHEMA_VERSION,
    TransportImplementation, TransportObservation, TransportObservationCompleteness,
    TransportProfile, TransportSet, WreqMeasuredProfileKind,
};
