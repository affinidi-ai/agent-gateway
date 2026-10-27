//! Detail types for the governance audit events raised on the request path and by
//! management changes to policies.

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
    /// The request carried no identity binding VP.
    Absent,
    /// The VP failed verification.
    Invalid,
    /// The VP verified, but no trust anchor vouches for its issuer.
    Untrusted,
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

/// A policy change, named as its audit event. A refusal names the change that
/// was attempted with one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyChangeAction {
    PolicyCreated,
    PolicyUpdated,
    PolicyDeleted,
    PolicyAttached,
    PolicyDetached,
    PolicyAttachmentChanged,
}

/// What a policy is attached to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyTargetKind {
    Surface,
    Gateway,
    /// The appliance-wide (global) assignments.
    Appliance,
}

/// Where on its target a policy is attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySlot {
    /// A surface's target request policy, or a gateway's policy.
    Target,
    /// The Access Point inbound policy.
    Inbound,
    /// The target response policy.
    Response,
    /// The policy shared by every transit point.
    Transit,
    /// One transit point's request or response policy.
    TransitPoint,
    McpTool,
    /// The condition of an MCP tool gate.
    McpToolGate,
    /// An appliance-wide plane.
    Plane,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    Enforced,
    MonitorOnly,
}

/// A part of a policy definition a change touched. The record names the part,
/// never its contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyField {
    Rego,
    Name,
    Description,
    Enabled,
    SampleInput,
    Owner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    User,
    Pat,
    /// The gateway itself, e.g. pruning a deleted definition's assignments.
    System,
}

/// Who made a management change: ids only, never a name or credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub kind: ActorKind,
    /// The user id, the access token's id, or `gateway`.
    pub id: String,
    /// For an access token, the id of the user it belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
}

impl Actor {
    pub fn user(id: impl Into<String>) -> Self {
        Self {
            kind: ActorKind::User,
            id: id.into(),
            user_id: None,
        }
    }

    pub fn pat(
        token_id: impl Into<String>,
        user_id: impl Into<String>,
    ) -> Self {
        Self {
            kind: ActorKind::Pat,
            id: token_id.into(),
            user_id: Some(user_id.into()),
        }
    }

    pub fn system() -> Self {
        Self {
            kind: ActorKind::System,
            id: "gateway".to_string(),
            user_id: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyChangeSource {
    Api,
    TemplateImport,
    Onboarding,
    Ownership,
    DefinitionDeleted,
}

/// Why a policy change was refused, by the class of status it got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    Forbidden,
    NotFound,
    Invalid,
    Conflict,
    Limit,
}
