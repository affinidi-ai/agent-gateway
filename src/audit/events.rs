//! Detail types for the governance audit events raised on the request path.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthScheme {
    Jwt,
    ApiKey,
    DidAuth,
    Mtls,
    McpResourceToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitScope {
    Surface,
    SseSessions,
    FabricCapacity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionStage {
    Routing,
    Admission,
    Forward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    NoRoute,
    UnknownVariant,
    VariantDisabled,
    BodyTooLarge,
    ProtocolMismatch,
    InvalidEnvelope,
    InvalidRequestShape,
    VersionUnsupported,
    McpAdmission,
    ExtensionRejected,
    SsrfBlocked,
    ConsentIdentityRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityBindingFailure {
    Absent,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationFailureReason {
    ConsentIdentityMismatch,
    ApiKeyResolutionFailed,
    VaultStoreRejected,
    CoordinatedRefreshUnavailable,
    CredentialsUnavailable,
    AnonymousCaller,
    ContinuationError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestFailureOutcome {
    UpstreamError,
    UpstreamTimeout,
    GatewayFault,
    CircuitOpen,
    ResponseInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Http,
    Fabric,
    McpProxy,
    A2aProxy,
}
