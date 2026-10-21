use serde::{Deserialize, Serialize};

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
    ReverseProxy,
    Cache,
    LoadBalancer,
    ApiGateway,
    ServiceMesh,
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

#[derive(Debug, Clone, Serialize)]
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
    pub request_headers: Vec<Header>,
    pub transport_profile: String,
    pub platform: String,
    pub result: String,
    pub elapsed_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    pub response_headers: Vec<Header>,
    pub path_elements: Vec<PathElement>,
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
