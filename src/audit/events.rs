//! Detail types for the governance audit events raised on the request path and by
//! management changes to policies and to Target Authentication.

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
    TransitPointCaller,
    TransitPointOverflow,
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
    /// The surface's `default_variant_id` names no variant.
    MisconfiguredDefault,
    BodyTooLarge,
    ProtocolMismatch,
    InvalidEnvelope,
    InvalidRequestShape,
    VersionUnsupported,
    McpAdmission,
    ExtensionRejected,
    SsrfBlocked,
    ConsentIdentityRequired,
    /// A Fabric request whose `X-Gateway-Fabric-Hops` is not one integer from 1 to 255.
    FabricHopsInvalid,
    /// A Fabric request past the limit of Fabric crossings.
    FabricChainTooLong,
    /// A Fabric request whose managed agent should get a transit token, which
    /// could not be issued.
    TransitTokenUnavailable,
    /// A Fabric request that a per-user delegated credential binding applies
    /// to, on a surface that does not release them to partners.
    DelegationNotEnabledForPartners,
    /// A Fabric request whose per-user delegated credential needs consent,
    /// which is never started through a partner.
    ConsentNotAvailableForPartners,
    /// A closed Access Point without source authentication refused the
    /// request with `503`.
    AccessPointNotReady,
    /// A request to a Target bound by external consent whose path the vendor
    /// might read otherwise than the gateway, or that is not one the grant is
    /// sent to.
    TargetPathRefused,
    /// A request to a Target bound by external consent with a method the
    /// grant is not sent with.
    TargetMethodRefused,
    /// A request to a Target bound by external consent refused before its
    /// grant is read, for a reason a new connect would not fix.
    ConnectorUnavailable,
    /// The Target credential was not sent: it could not be obtained, or a
    /// `[credential_policy]` rule in `enforce` withheld it.
    TargetAuthFailed,
}

/// What `target.auth.fallback` did with a request whose Target credential was not sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetAuthOutcome {
    /// Refused with 502.
    Rejected,
    /// Forwarded without the credential.
    Passthrough,
}

/// The detail of a `target_auth_failed` refusal. Never a token, an assertion, a token
/// endpoint body or its `error_description`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetAuthRejection {
    pub outcome: TargetAuthOutcome,
    /// The alias of the Transit Point whose credential was not sent; absent for the Target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transit_point: Option<String>,
    /// The token endpoint's OAuth `error` code, when it answered with one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_error: Option<String>,
}

/// The leg of a surface whose Target Authentication a management change set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetAuthLeg {
    Target,
    TransitPoint,
}

/// How a leg obtains the credential it sends; `none` when it sends none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetAuthMethodKind {
    None,
    StaticSecret,
    CredentialProvider,
    CredentialLookup,
}

/// A part of a Target Authentication setting that a change replaced. Names the part only,
/// never its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetAuthField {
    Method,
    SecretId,
    ProviderId,
    HeaderName,
    HeaderFormat,
    Scopes,
    Fallback,
    TargetIdentifier,
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
    /// A consent start or callback state that is missing, not sealed by this
    /// gateway, expired, or of the wrong stage.
    ConsentStateInvalid,
    /// A consent start or callback state that was already used on this process.
    ConsentStateReused,
    /// The path names another provider than the state, or the state's provider
    /// is gone, renamed or no longer an authorization code provider without an
    /// issuer.
    ConsentProviderMismatch,
    /// A consent callback without the binding cookie the start POST set.
    BrowserBindingMismatch,
    /// A consent callback without `iss` from a provider whose issuer is recorded.
    IssMissing,
    /// A consent callback whose `iss` is not the provider's recorded issuer,
    /// or a consent confirmation whose `iss` is not its strategy's issuer.
    IssMismatch,
    /// A consent callback that is malformed or carries no code.
    ConsentResponseInvalid,
    /// The vendor, or the identity provider of a consent confirmation,
    /// answered with an error.
    ConsentDenied,
    /// The provider's redirect URI breaks the consent rules or is another
    /// provider's.
    RedirectUriInvalid,
    /// The provider's authorization endpoint or parameters break the consent rules.
    AuthorizationUrlInvalid,
    /// A consent start POST that did not come from the gateway's start page.
    CrossSiteConsentStart,
    /// The vendor's token endpoint, or the consent confirmation login
    /// client's, refused or failed the code exchange.
    TokenExchangeFailed,
    /// A consent confirmation sign-in gave no ID token that names a caller.
    ConsentIdentityMissing,
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
#[allow(clippy::enum_variant_names, reason = "each variant serializes as its audit event name")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
    /// A management API request changed the policy or where it applies.
    Api,
    /// The tenant owning the policy or gateway was reassigned.
    Ownership,
    /// Deleting a definition removed it from where it applied.
    DefinitionDeleted,
}

/// Why a policy change was refused, by the class of status it got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    /// 403: not permitted, including an appliance limit reached.
    Forbidden,
    /// 404: the policy or target does not exist or is not visible.
    NotFound,
    /// 400 or 422: the change was not valid.
    Invalid,
    /// 409: the change conflicts with what is stored.
    Conflict,
}
