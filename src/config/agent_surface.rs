//! Agent Surface configuration types.
//!
//! An Agent Surface is the primary configuration and runtime entity in the Agent Gateway.
//! It represents a single logical agent — one that the Gateway manages, secures, and
//! mediates on behalf of — and fully describes that agent's inbound surface, outbound
//! targets, identity, policies, and optional transit capabilities.

use serde::{Deserialize, Serialize};

use super::types::{
    CircuitBreakerConfig, CustomMetadata, ExtensionInspectionConfig, ExtensionRules, MirrorConfig,
    OutboundCredentialBinding, RateLimitConfig, RetryConfig, TargetAuthConfig, TimeoutConfig, WorkloadBindingConfig,
    X402Config,
};
use crate::config::header_metadata_mapping::{HeaderMetadataMappingConfig, HeaderMetadataMappingValidationError};
use crate::mpp::MppConfig;
use crate::source_auth::SourceAuthConfig;
use crate::storage::filesystem::StorableEntity;
use crate::trust_registry_verification::TrustCheckElement;

// ─── Top-Level Entity ───────────────────────────────────────────────────────

/// The primary configuration entity. Represents a single managed agent's full
/// surface area: how it's reached, where it routes, what identity it carries,
/// and what it can call out to.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AgentSurface {
    /// Unique identifier (UUID). Assigned at creation time.
    #[serde(default)]
    pub surface_id: String,

    /// Management-plane tenant ownership. Missing means appliance-global.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// Human-readable name (e.g., "sales-agent", "research-assistant").
    pub name: String,

    /// Optional description.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,

    /// Lifecycle status.
    #[serde(default)]
    pub status: SurfaceStatus,

    /// The agent's DID. Gateway-managed (computed from identity resolution)
    /// or externally provided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_did: Option<String>,

    /// Trust registry issuer ownership. The Issuer whose DID is emitted as
    /// `provider_did` in outbound trust-registry extensions and used as the
    /// caller-leg Trust Check `provider_did` template default. Accepts the
    /// legacy `department_id` key on input for backward compatibility with
    /// surfaces persisted before the `department` → `issuer` rename; always
    /// serialised as `issuer_id`.
    #[serde(default, alias = "department_id", skip_serializing_if = "Option::is_none")]
    pub issuer_id: Option<String>,

    /// Tags for grouping, filtering, search.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// The inbound configuration — how callers reach this agent.
    pub access_point: AccessPoint,

    /// The single upstream destination — the managed agent itself.
    pub target: Target,

    /// Optional transit points for agent-initiated outbound calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transit: Option<TransitConfig>,

    /// Opaque UI-only blob persisted on behalf of the management dashboard:
    /// canvas node positions, decorative NPC/human/caller nodes, and any
    /// other layout state. The runtime never reads this; the backend stores
    /// it verbatim so the dashboard can round-trip the visual builder
    /// without polluting the runtime surface config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canvas: Option<serde_json::Value>,

    /// Surface-level variant catalog. Each variant is a sparse
    /// delta over this surface's base form; resolution is performed by
    /// `AgentSurface::resolve_variant`. The legacy `Target::variants` field
    /// has been removed — these surface-level variants are the sole source
    /// of variant data and are consumed by the runtime (e.g. the fabric
    /// message processor).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variants: Vec<crate::config::agent_surface_variants::SurfaceVariant>,

    /// Id (not alias) of the variant addressed by the unmarked URL.
    /// `None` when the surface has no variants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_variant_id: Option<String>,

    /// Credential providers bound to this surface for outbound delegation
    /// (consent_required signalling, OAuth token injection, etc.).
    /// Conceptually distinct from `transit.points[*].transit_credentials`,
    /// which scopes credentials to a specific fabric hop. These apply at the
    /// surface level and survive direct (non-fabric) outbound calls.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbound_credentials: Vec<OutboundCredentialBinding>,

    /// Three independent identity slots, one per edge in the request/response
    /// pipeline. Each slot owns its own extraction config (`payload_extraction`,
    /// `from_api_key`, `from_mtls`, `static`).
    #[serde(default, skip_serializing_if = "SurfaceIdentitySlots::is_empty")]
    pub identity_slots: SurfaceIdentitySlots,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_legacy_metadata_output: Option<super::types::McpLegacyMetadataOutput>,

    #[serde(default, rename = "mcp_protocol_mode", skip_serializing)]
    pub _retired_protocol_mode: super::types::RetiredSetting,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_http: Option<super::types::McpHttpConfig>,

    /// Whether target-leg Trust Checks on this surface are stored per Transit
    /// Point (`transit.points[].trust_check_list`). Stored while the surface
    /// carries any Trust Check list, target or Transit Point, so a release that
    /// predates per-Transit-Point lists refuses to load it. On a write, `true`
    /// declares the body per-Transit-Point; a stored surface with a target list
    /// and without it is converted on load.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub trust_check_split: bool,

    /// Whether a Transit Point of this surface, on the base or in a variant,
    /// authenticates its callers with its own `source_auth`. Stored while one
    /// does, so a release that predates Transit Point `source_auth`, which
    /// would serve that Transit Point without it, refuses to load the surface.
    /// The gateway sets it on every save and on load; a value a write sends is
    /// ignored.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub transit_point_source_auth: bool,
}

/// Three independent identity slots covering the proxy pipeline edges.
///
/// * `inbound`   — CA → AP request: extract caller agent identity from the inbound request body.
/// * `protected` — MA → AP response: extract the protected (managed) agent identity from the response body.
/// * `external`  — EXT → TP response: extract the external agent identity from an outbound response.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SurfaceIdentitySlots {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound: Option<crate::source_auth::ManagedIdentityConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected: Option<crate::source_auth::ManagedIdentityConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external: Option<crate::source_auth::ManagedIdentityConfig>,
}

impl SurfaceIdentitySlots {
    pub fn is_empty(&self) -> bool {
        self.inbound.is_none() && self.protected.is_none() && self.external.is_none()
    }
}

/// Lifecycle status of an Agent Surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../www/default/src/generated/", rename_all = "lowercase"))]
pub enum SurfaceStatus {
    #[default]
    Active,
    Disabled,
    Deleted,
}

// ─── Access Point ───────────────────────────────────────────────────────────

/// Defines the front door of an Agent Surface — how callers discover,
/// authenticate with, and reach this agent through the Gateway.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AccessPoint {
    /// Friendly display name shown in the dashboard (e.g. monitoring
    /// slice picker). Free text; empty / absent renders as "Access
    /// Point". Never used for routing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Network address to bind (e.g., "0.0.0.0:8443").
    pub listen_address: String,

    /// Path prefix distinguishing this surface from others on the same port.
    /// Forms part of the base URL: `https://{host}:{port}{route}`.
    pub route: String,

    /// Agent protocol used for inbound AND Target communication.
    /// The Gateway does not translate between protocols.
    pub protocol: SurfaceProtocol,

    /// How to verify the caller's identity at the transport level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_authentication: Option<CallerAuthentication>,

    /// What we need to know about the caller.
    ///
    /// Deprecated: enforcement is derived from `caller_authentication` presence.
    /// Retained for backward compatibility with stored surfaces.
    #[serde(default, skip_serializing_if = "is_default_caller_context")]
    pub caller_context: CallerContext,

    /// How to derive the agent DID from the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_resolution: Option<IdentityResolution>,

    /// Access-point-level OPA policy (runs before Target pipeline).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_policy: Option<PolicyRef>,

    /// Inbound rate limiting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitConfig>,

    /// Schema validation on inbound request payloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_validation: Option<ExtensionRules>,

    /// Per-element trust-check declarations on the caller leg (AP→MA).
    /// Evaluated in parallel by the Trust Check stage; results land in
    /// `PolicyInput.trust_check_results.caller`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_check_list: Vec<TrustCheckElement>,

    /// Copies selected inbound HTTP headers into A2A message metadata at the
    /// Access Point boundary before identity, policy, trust, and forwarding
    /// controls evaluate the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_metadata_mapping: Option<HeaderMetadataMappingConfig>,

    /// Trust Recorder — writes records to one or more TRs via TrAdmin
    /// DIDComm on the MA→AP response leg.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_recorder: Option<crate::config::types::TrustRecorderConfig>,

    /// Whether to publish this surface to the Gateway's DID document.
    #[serde(default)]
    pub publish_to_did_document: bool,

    /// A2A supported extensions.
    ///
    /// Config-only today; overridable per variant. Publication to the agent
    /// card is tracked separately (FU-4).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_extensions: Vec<String>,

    /// Primary A2A extension URI (used for UI display / metrics grouping).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_extension: Option<String>,

    /// Override agent card location path (relative to base URL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_card_path: Option<String>,

    /// Response custom metadata injection at access-point level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_custom_metadata: Option<CustomMetadata>,

    /// did:webvh managed identity configuration (feature-gated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub didwebvh_identity: Option<DidWebVhIdentityConfig>,

    /// Terminate end-to-end trace propagation at this surface's EGRESS.
    ///
    /// When `false` (default) the surface forwards the request's `trace_id` to the
    /// next hop (via `X-Gateway-Trace-Id`, a transit token, or a fabric message),
    /// so the whole `caller → GW → GW` chain shares one trace. When `true` the
    /// surface keeps the incoming trace for its **own** VP + audit (so the
    /// `caller → … → here` past stays traceable) but forwards a **fresh** id
    /// downstream — an egress firewall, so the trace never crosses this boundary to
    /// the next gateway/agent.
    #[serde(default)]
    pub terminate_trace_id: bool,

    /// A2A protocol settings: the versions this surface accepts and how much of
    /// an inbound request is validated. A2A and AP2 Access Points only. Absent
    /// means [`A2aAccessPointSettings::default`]: both versions, with the
    /// JSON-RPC envelope checked. Surface-level, not overridable per variant;
    /// read it through [`AgentSurface::a2a_settings`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a2a: Option<A2aAccessPointSettings>,
}

/// How much of an inbound A2A request the gateway validates before forwarding it.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum A2aValidation {
    /// Nothing: requests are forwarded as they are. A JSON-RPC batch or a
    /// non-string `method` then reaches policy without a method to match.
    Off,
    /// The JSON-RPC envelope: valid JSON, `"jsonrpc": "2.0"` and a string
    /// `method`, which refuses batches.
    #[default]
    Envelope,
    /// The envelope and the A2A request shape (`messageId`, `role`, `parts`,
    /// `params.id`, the ListTasks `status`).
    Full,
}

impl A2aValidation {
    /// Whether the JSON-RPC envelope is checked.
    pub fn checks_envelope(self) -> bool {
        matches!(self, Self::Envelope | Self::Full)
    }

    /// Whether the A2A request shape is checked.
    pub fn checks_request_shape(self) -> bool {
        self == Self::Full
    }

    /// The setting's value as stored and logged.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Envelope => "envelope",
            Self::Full => "full",
        }
    }
}

/// A2A protocol settings of an A2A Access Point.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "A2aAccessPointSettingsWire")]
pub struct A2aAccessPointSettings {
    /// A2A versions the surface accepts through `A2A-Version` negotiation: a
    /// non-empty subset of [`crate::a2a::version::SUPPORTED_VERSIONS`].
    pub accepted_versions: Vec<String>,

    /// How much of a request is validated before it is forwarded.
    pub validation: A2aValidation,

    /// Whether the JSON this was read from named `accepted_versions`, so the
    /// surface API can tell versions a caller asked for from the default it
    /// filled in. Not serialized, and not part of equality.
    #[serde(skip)]
    pub(crate) accepted_versions_sent: bool,
}

/// The JSON form of [`A2aAccessPointSettings`], which records whether
/// `accepted_versions` was present.
#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct A2aAccessPointSettingsWire {
    accepted_versions: Option<Vec<String>>,
    validation: A2aValidation,
}

impl From<A2aAccessPointSettingsWire> for A2aAccessPointSettings {
    fn from(wire: A2aAccessPointSettingsWire) -> Self {
        let accepted_versions_sent = wire
            .accepted_versions
            .is_some();
        Self {
            accepted_versions: wire
                .accepted_versions
                .unwrap_or_else(|| Self::default().accepted_versions),
            validation: wire.validation,
            accepted_versions_sent,
        }
    }
}

impl PartialEq for A2aAccessPointSettings {
    fn eq(
        &self,
        other: &Self,
    ) -> bool {
        self.accepted_versions == other.accepted_versions && self.validation == other.validation
    }
}

impl Eq for A2aAccessPointSettings {}

impl Default for A2aAccessPointSettings {
    fn default() -> Self {
        Self {
            accepted_versions: crate::a2a::version::SUPPORTED_VERSIONS
                .iter()
                .map(|version| version.to_string())
                .collect(),
            validation: A2aValidation::default(),
            accepted_versions_sent: false,
        }
    }
}

impl A2aAccessPointSettings {
    /// The settings of a surface created with an `a2a-proxy://` target, or whose
    /// Target moves to one: A2A 1.0 only, with the JSON-RPC envelope checked. The
    /// surface API keeps an A2A-proxy surface's versions fixed after that.
    pub fn a2a_proxy() -> Self {
        Self {
            accepted_versions: vec![crate::a2a::version::VERSION_1_0.to_string()],
            validation: A2aValidation::Envelope,
            accepted_versions_sent: false,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self
            .accepted_versions
            .is_empty()
        {
            return Err("access_point.a2a.accepted_versions must name at least one version".to_string());
        }
        for (index, version) in self
            .accepted_versions
            .iter()
            .enumerate()
        {
            if !crate::a2a::version::SUPPORTED_VERSIONS.contains(&version.as_str()) {
                return Err(format!(
                    "access_point.a2a.accepted_versions: unsupported version '{version}' (supported: {})",
                    crate::a2a::version::SUPPORTED_VERSIONS.join(", ")
                ));
            }
            if self.accepted_versions[..index].contains(version) {
                return Err(format!("access_point.a2a.accepted_versions lists '{version}' more than once"));
            }
        }
        Ok(())
    }
}

/// The A2A settings a request on a surface is served with; see
/// [`AgentSurface::a2a_settings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveA2aSettings {
    /// The versions negotiation accepts, in `SUPPORTED_VERSIONS` order.
    pub accepted_versions: &'static [&'static str],
    /// How much of a request is validated.
    pub validation: A2aValidation,
}

/// Agent protocol — governs both inbound and Target communication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../www/default/src/generated/", rename_all = "lowercase"))]
pub enum SurfaceProtocol {
    /// Agent-to-Agent protocol (JSON-RPC 2.0 with A2A extensions).
    #[default]
    A2a,
    /// Agent Payments Protocol (extends A2A with VDC/VC/VP transformation).
    Ap2,
    /// Model Context Protocol (JSON-RPC 2.0 with `_meta`).
    Mcp,
    /// DIDComm messaging protocol (for transit gateways).
    #[serde(rename = "didcomm")]
    #[cfg_attr(test, ts(rename = "didcomm"))]
    DIDComm,
}

/// Caller authentication configuration.
/// Multiple methods can be configured; the Gateway tries them in order.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerAuthentication {
    /// Ordered list of authentication methods. First success wins.
    pub methods: Vec<SourceAuthConfig>,
    /// RFC 9728 discovery for an MCP Access Point whose JWT Bearer method
    /// accepts tokens from an external authorization server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected_resource: Option<crate::protocols::protected_resource::ProtectedResourceConfig>,
}

/// What the Gateway needs to know about the caller.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct CallerContext {
    /// Caller identity requirement mode.
    #[serde(default)]
    pub mode: CallerContextMode,
}

/// How strictly caller identity is required.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum CallerContextMode {
    /// Caller MUST be identifiable. Request rejected if identity cannot be resolved.
    #[default]
    Required,
    /// Gateway attempts to resolve identity but proceeds if it cannot.
    Optional,
    /// No identity extraction at all.
    Anonymous,
}

/// How the Gateway derives the agent DID from the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "strategy", rename_all = "snake_case")]
pub enum IdentityResolution {
    /// Extract identity fields from the request body. Fields are hashed into a DID.
    FromPayload {
        /// Dot-notation field paths to extract (e.g., "agentIdentity.name").
        fields: Vec<String>,
        /// Hash algorithm (default: sha256).
        #[serde(default = "default_hash_algorithm")]
        hash_algorithm: String,
    },
    /// Derive DID from the client certificate CN/SAN.
    FromMtls,
    /// Map API key to a pre-registered agent DID.
    FromApiKey,
    /// Extract DID from JWT claims.
    FromJwtClaims {
        /// Claim name containing the DID or identity (e.g., "sub").
        claim: String,
    },
    /// Fixed DID assigned by the admin.
    Static {
        /// The DID to use for all requests through this surface.
        did: String,
    },
    /// No agent DID resolved.
    None,
}

fn default_hash_algorithm() -> String {
    "sha256".to_string()
}

/// Used by `serde(skip_serializing_if = ...)` so the deprecated
/// `caller_context` block is omitted when it carries no information.
fn is_default_caller_context(v: &CallerContext) -> bool {
    v == &CallerContext::default()
}

/// Reference to an OPA policy definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRef {
    /// ID of the policy definition in the policy store.
    pub policy_definition_id: String,

    /// When `true`, the pipeline fetches the target's agent card and
    /// queries the trust registry before evaluating this policy,
    /// populating `input.agent` in the OPA input. Defaults to `false`
    /// to avoid the extra latency when the policy doesn't need it.
    #[serde(default)]
    pub require_agent_context: bool,
}

// ─── Target ─────────────────────────────────────────────────────────────────

/// The single upstream destination — the actual managed agent.
/// Traffic arriving at `{base}/...` is forwarded here.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// Upstream endpoint (https://, fabric://{gw}/{surface}, proxy://{id}).
    pub endpoint: String,

    /// Service-level credentials (Gateway → Target).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<TargetAuthConfig>,

    /// Request-side OPA policy ("is this caller allowed this operation?").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyRef>,

    /// Response-side OPA policy ("is this response allowed for this caller?").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_policy: Option<PolicyRef>,

    /// Payment requirements (x402 or MPP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_policy: Option<PaymentPolicy>,

    /// Per-tool RBAC (only when protocol = mcp).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mcp_tool_policies: Vec<McpToolPolicyEntry>,

    /// Deprecated. Retained for backwards-compatible deserialization of
    /// surfaces persisted before tool-policy enforcement was unconditional.
    /// Enforcement is now driven solely by `mcp_tool_policies` being
    /// non-empty; this flag has no runtime effect.
    #[serde(default)]
    pub mcp_tool_policies_enabled: bool,

    /// MCP Tool Gating (only when protocol = mcp). A set of condition-gated
    /// allow/deny rules applied to both the `tools/list` response and
    /// `tools/call` requests. See [`McpToolGatingConfig`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_tool_gating: Option<McpToolGatingConfig>,

    /// Networking configuration (timeout, retry, circuit breaker, mirror).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub networking: Option<NetworkingConfig>,

    /// Identity injection (VP binding).
    #[serde(default)]
    pub identity_injection: IdentityInjectionConfig,

    /// Workload Binding for the primary MA→EXT forward leg. When set and
    /// [`WorkloadBindingConfig::enabled`] is `true`, the request pipeline
    /// produces a signed workload-binding VP for the outbound request to this
    /// target (direct HTTP and `fabric://`), binding the managed agent identity
    /// to caller context captured from the inbound `Authorization` bearer JWT.
    /// When `None` (or disabled), request-leg identity injection keeps its
    /// existing behaviour. Analogous to [`TransitPoint::workload_binding`] but
    /// scoped to the surface's primary target rather than a Transit Point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_binding: Option<WorkloadBindingConfig>,

    /// Response extension validation (schema-based).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_rules: Option<ExtensionRules>,

    /// Custom metadata injection (request and/or response).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_metadata: Option<CustomMetadata>,

    /// Response custom metadata injection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_custom_metadata: Option<CustomMetadata>,

    /// Per-element trust-check declarations on the Managed Agent's own target
    /// leg: `a2a-proxy://` targets and fabric send. Requests through a Transit
    /// Point use that Transit Point's `trust_check_list` instead. Results land
    /// in `PolicyInput.trust_check_results.target`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_check_list: Vec<TrustCheckElement>,

    /// MCP proxy backend ID (when endpoint = proxy://{id}).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_proxy_id: Option<String>,

    /// A2A proxy backend ID (when endpoint = a2a-proxy://{id}).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a2a_proxy_id: Option<String>,

    /// Display name for fabric:// endpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fabric_target_name: Option<String>,

    /// Auto-pay MPP challenges for fabric:// targets.
    #[serde(default)]
    pub mpp_auto_pay: bool,

    /// Maximum amount per auto-pay request (safety cap).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mpp_auto_pay_max_amount: Option<String>,

    /// Lets the surface's `outbound_credentials` access tokens cross Fabric
    /// to a `fabric://` peer on modern MCP requests. Off by default.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub fabric_delegated_credentials: bool,
}

/// Payment policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
#[allow(clippy::large_enum_variant)]
pub enum PaymentPolicy {
    /// HTTP 402 Payment Required protocol.
    X402(X402Config),
    /// Machine Payments Protocol.
    Mpp(MppConfig),
}

// ─── Target Variants (legacy, removed) ──────────────────────────────────────
// Legacy `TargetVariant` deleted; variants now live on `AgentSurface.variants`
// as `SurfaceVariant` (see agent_surface_variants.rs).
/// Per-tool policy entry for MCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpToolPolicyEntry {
    /// Tool name to apply this policy to.
    pub tool_name: String,
    /// OPA policy definition ID.
    pub policy_definition_id: String,
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

/// Maximum number of gates allowed in one [`McpToolGatingConfig`], enforced by
/// [`McpToolGatingConfig::validate`].
pub const MCP_TOOL_GATES_MAX: usize = 64;
/// Maximum number of regex patterns allowed in a single [`McpToolGate`].
pub const MCP_TOOL_GATE_PATTERNS_MAX: usize = 64;
/// Maximum length (in bytes) of a single MCP tool gate regex pattern.
pub const MCP_TOOL_GATE_PATTERN_LEN_MAX: usize = 512;

/// MCP Tool Gating configuration.
///
/// A firewall over the MCP tool surface: an ordered set of [`McpToolGate`]
/// rules, each pairing an optional OPA *condition* with an allow/deny
/// *action* (a regex over tool names). Gates are evaluated on both the
/// `tools/list` response (to hide tools) and `tools/call` requests (to block
/// invocation), so a tool that is filtered out of the list cannot be called.
///
/// Composition (firewall model):
/// - A gate is **active** when its condition is met (see [`McpToolGate`]).
/// - A tool is **denied** if any active `Deny` gate matches it.
/// - When at least one active `Allow` gate exists, a tool must match one of
///   them to survive (the union of allow-matches acts as an allow-list).
/// - When no active `Allow` gate matches, the tool falls back to
///   `default_effect` (`allow` = allow-by-default, `deny` = deny-by-default).
/// - `Deny` always overrides `Allow`.
///
/// Size caps ([`MCP_TOOL_GATES_MAX`], [`MCP_TOOL_GATE_PATTERNS_MAX`],
/// [`MCP_TOOL_GATE_PATTERN_LEN_MAX`]) are enforced by [`Self::validate`] so a
/// surface write cannot install an unbounded number of gates/patterns.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolGatingConfig {
    /// Baseline verdict for a tool that matches no active gate. `allow`
    /// (the default) makes gates deny carve-outs over an allow-everything
    /// base; `deny` makes the gates an allow-list over a deny-everything
    /// base. Explicit so "deny unless allowed" stays robust even when every
    /// allow gate is conditional and currently inactive.
    #[serde(default, skip_serializing_if = "McpToolGateEffect::is_allow")]
    pub default_effect: McpToolGateEffect,
    /// Ordered list of gates. Order is preserved for display; the firewall
    /// decision itself is order-independent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gates: Vec<McpToolGate>,
}

/// A single MCP tool gate: an optional condition plus an allow/deny action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolGate {
    /// Stable identifier (assigned by the dashboard).
    pub id: String,
    /// Human-readable name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// Free-text description.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// OPA policy that decides whether this gate is active. The referenced
    /// surface policy is evaluated against the request; an `allow` result
    /// activates the gate and a deny leaves it inactive (its action is
    /// skipped). When `None`, the gate is **always active** (an
    /// unconditional filter). A condition that cannot be evaluated at
    /// runtime fails **closed** (the gate is treated as active).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition_policy_definition_id: Option<String>,
    /// The allow/deny action enforced when the gate is active.
    pub action: McpToolGateAction,
}

/// The allow/deny action of an [`McpToolGate`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolGateAction {
    /// Whether matching tools are allowed (allow-list) or denied (hidden).
    pub effect: McpToolGateEffect,
    /// Regex patterns matched against tool names. Empty/whitespace patterns
    /// are ignored; a gate with no effective pattern matches no tool.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<String>,
}

/// The effect half of an [`McpToolGateAction`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum McpToolGateEffect {
    /// Matching tools form an allow-list; non-matching tools are hidden.
    #[default]
    Allow,
    /// Matching tools are hidden as if they did not exist.
    Deny,
}

impl McpToolGateEffect {
    /// `true` for the `Allow` variant. Used as a serde `skip_serializing_if`
    /// so the default `default_effect` stays out of the persisted JSON.
    pub fn is_allow(&self) -> bool {
        matches!(self, McpToolGateEffect::Allow)
    }
}

impl McpToolGatingConfig {
    /// Returns `true` when the config is a no-op: no gates AND the default
    /// verdict is `allow` (allow-everything). A `deny` default with no gates
    /// is NOT empty — it denies every tool — so the gating stage still runs.
    pub fn is_empty(&self) -> bool {
        self.gates.is_empty() && self.default_effect.is_allow()
    }

    /// Validate that every gate's regex patterns compile and that each gate
    /// declares at least one effective pattern. Returns one error string per
    /// problem so operators see them all at config-write time.
    pub fn validate(
        &self,
        surface_name: &str,
    ) -> Vec<String> {
        let mut errors = Vec::new();
        if self.gates.len() > MCP_TOOL_GATES_MAX {
            errors.push(format!(
                "Surface '{}': MCP tool gating has {} gates (max {})",
                surface_name,
                self.gates.len(),
                MCP_TOOL_GATES_MAX
            ));
        }
        for gate in &self.gates {
            let effective: Vec<&String> = gate
                .action
                .patterns
                .iter()
                .filter(|p| !p.trim().is_empty())
                .collect();
            if effective.is_empty() {
                errors.push(format!(
                    "Surface '{}': MCP tool gate '{}' has no regex patterns; add at least one",
                    surface_name,
                    gate.display_label()
                ));
            }
            if effective.len() > MCP_TOOL_GATE_PATTERNS_MAX {
                errors.push(format!(
                    "Surface '{}': MCP tool gate '{}' has {} patterns (max {})",
                    surface_name,
                    gate.display_label(),
                    effective.len(),
                    MCP_TOOL_GATE_PATTERNS_MAX
                ));
            }
            for pattern in effective {
                if pattern.len() > MCP_TOOL_GATE_PATTERN_LEN_MAX {
                    errors.push(format!(
                        "Surface '{}': MCP tool gate '{}' has a regex of {} chars (max {})",
                        surface_name,
                        gate.display_label(),
                        pattern.len(),
                        MCP_TOOL_GATE_PATTERN_LEN_MAX
                    ));
                    // Skip compiling an over-long pattern — the length cap is
                    // the operative bound and compiling it is the cost we cap.
                    continue;
                }
                if let Err(e) = regex::Regex::new(pattern) {
                    errors.push(format!(
                        "Surface '{}': MCP tool gate '{}' has an invalid regex '{}': {}",
                        surface_name,
                        gate.display_label(),
                        pattern,
                        e
                    ));
                }
            }
        }
        errors
    }
}

impl McpToolGate {
    /// A label for diagnostics: the name when set, else the id.
    pub fn display_label(&self) -> &str {
        if self.name.trim().is_empty() {
            &self.id
        } else {
            &self.name
        }
    }
}

#[cfg(test)]
mod mcp_tool_gating_config_tests {
    use super::{McpToolGate, McpToolGateAction, McpToolGateEffect, McpToolGatingConfig};

    fn gate_with(patterns: Vec<&str>) -> McpToolGate {
        McpToolGate {
            id: "g1".to_string(),
            name: "Gate One".to_string(),
            description: String::new(),
            condition_policy_definition_id: None,
            action: McpToolGateAction {
                effect: McpToolGateEffect::Deny,
                patterns: patterns
                    .into_iter()
                    .map(String::from)
                    .collect(),
            },
        }
    }

    #[test]
    fn valid_patterns_produce_no_errors() {
        let cfg = McpToolGatingConfig {
            gates: vec![gate_with(vec!["^admin_", "delete$"])],
            ..Default::default()
        };
        assert!(
            cfg.validate("surface-a")
                .is_empty()
        );
    }

    #[test]
    fn empty_patterns_report_error() {
        let cfg = McpToolGatingConfig {
            gates: vec![gate_with(vec!["  "])],
            ..Default::default()
        };
        let errors = cfg.validate("surface-a");
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("no regex patterns"));
        assert!(errors[0].contains("Gate One"));
    }

    #[test]
    fn invalid_regex_reports_error() {
        let cfg = McpToolGatingConfig {
            gates: vec![gate_with(vec!["("])],
            ..Default::default()
        };
        let errors = cfg.validate("surface-a");
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("invalid regex"));
    }

    #[test]
    fn too_many_gates_reports_error() {
        use super::MCP_TOOL_GATES_MAX;
        let cfg = McpToolGatingConfig {
            gates: (0..=MCP_TOOL_GATES_MAX)
                .map(|_| gate_with(vec!["x"]))
                .collect(),
            ..Default::default()
        };
        let errors = cfg.validate("surface-a");
        assert!(
            errors
                .iter()
                .any(|e| e.contains("gates (max"))
        );
    }

    #[test]
    fn too_many_patterns_reports_error() {
        use super::MCP_TOOL_GATE_PATTERNS_MAX;
        let patterns: Vec<&str> = (0..=MCP_TOOL_GATE_PATTERNS_MAX)
            .map(|_| "x")
            .collect();
        let cfg = McpToolGatingConfig {
            gates: vec![gate_with(patterns)],
            ..Default::default()
        };
        let errors = cfg.validate("surface-a");
        assert!(
            errors
                .iter()
                .any(|e| e.contains("patterns (max"))
        );
    }

    #[test]
    fn over_long_pattern_reports_error_and_is_not_compiled() {
        use super::MCP_TOOL_GATE_PATTERN_LEN_MAX;
        let long = "a".repeat(MCP_TOOL_GATE_PATTERN_LEN_MAX + 1);
        let cfg = McpToolGatingConfig {
            gates: vec![gate_with(vec![long.as_str()])],
            ..Default::default()
        };
        let errors = cfg.validate("surface-a");
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("chars (max"));
    }

    #[test]
    fn is_empty_reflects_gate_count() {
        assert!(McpToolGatingConfig::default().is_empty());
        assert!(
            !McpToolGatingConfig {
                gates: vec![gate_with(vec!["x"])],
                ..Default::default()
            }
            .is_empty()
        );
        // A deny-by-default config with no gates is NOT empty (it denies all).
        assert!(
            !McpToolGatingConfig {
                default_effect: McpToolGateEffect::Deny,
                ..Default::default()
            }
            .is_empty()
        );
    }

    #[test]
    fn default_effect_serde_round_trips() {
        // `allow` default is omitted from the wire; `deny` is emitted.
        assert_eq!(serde_json::to_string(&McpToolGatingConfig::default()).unwrap(), "{}");
        let deny = McpToolGatingConfig {
            default_effect: McpToolGateEffect::Deny,
            gates: Vec::new(),
        };
        assert_eq!(serde_json::to_string(&deny).unwrap(), r#"{"default_effect":"deny"}"#);

        // Deserialization: absent default → allow; explicit → deny.
        let from_empty: McpToolGatingConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(from_empty.default_effect, McpToolGateEffect::Allow);
        let from_deny: McpToolGatingConfig = serde_json::from_str(r#"{"default_effect":"deny"}"#).unwrap();
        assert_eq!(from_deny.default_effect, McpToolGateEffect::Deny);
    }
}

/// Networking configuration (composes timeout, retry, circuit breaker, mirror).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NetworkingConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<TimeoutConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<RetryConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_breaker: Option<CircuitBreakerConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror: Option<MirrorConfig>,
}

/// Identity injection (VP binding) configuration.
///
/// In addition to the legacy `inject_vp` flag, this struct persists the
/// agent-identity definition the management UI sends as `target.agent_identity`
/// (the API translation layer renames it to `identity_injection` on the wire).
/// The runtime currently only consults `inject_vp`; the remaining fields are
/// stored verbatim so they round-trip cleanly to and from the dashboard until
/// the request pipeline learns to honour them.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct IdentityInjectionConfig {
    /// Whether to inject a signed VP into outbound requests.
    #[serde(default)]
    pub inject_vp: bool,

    /// Identity extraction strategy: `from_payload`, `from_api_key`,
    /// `from_mtls`, `static`, or `from_jwt_claim`.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub identity_type: Option<String>,

    /// API key id (when `identity_type = "from_api_key"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_id: Option<String>,

    /// Certificate id (when `identity_type = "from_mtls"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_id: Option<String>,

    /// Static DID (when `identity_type = "static"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_did: Option<String>,

    /// Validated JWT claim the agent DID is derived from (when
    /// `identity_type = "from_jwt_claim"`). Defaults to `oid` (the Entra
    /// Agent ID object identifier) when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,

    /// Extra claims that namespace the derived DID (when
    /// `identity_type = "from_jwt_claim"`), e.g. `iss` or `tid`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub namespace_claims: Vec<String>,

    /// Top-level payload field that the identity object is read from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta_field: Option<String>,

    /// Dot-notation paths concatenated and hashed to derive the agent DID
    /// (used by `from_payload`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,

    /// JSON Schema describing the expected identity object on the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json_schema: Option<serde_json::Value>,

    /// When true, the raw `_meta.<meta_field>` block is removed from the
    /// request/response after the VP credential is injected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strip_raw_meta: Option<bool>,
}

// ─── Transit Points ─────────────────────────────────────────────────────────

/// Complete transit configuration for an Agent Surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitConfig {
    /// Named transit points (outbound destinations).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub points: Vec<TransitPoint>,

    /// Separate listen address for the outbound/transit listener.
    /// If not set, transit shares the access point's listen address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_listen_address: Option<String>,

    /// Shared settings that apply to all transit points.
    #[serde(flatten)]
    pub shared: SharedTransitConfig,
}

/// Shared transit configuration applied to all transit points.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SharedTransitConfig {
    /// Transit token mode (how caller context is carried).
    #[serde(default)]
    pub transit_token_mode: TransitTokenMode,

    /// How long, in seconds, the transit tokens the Access Point issues live,
    /// from [`MIN_TRANSIT_TOKEN_LIFETIME_SECS`] to the appliance's
    /// `transit_token_max_lifetime_secs` (300 unless `gateway.json` sets it);
    /// unset means [`DEFAULT_TRANSIT_TOKEN_LIFETIME_SECS`]. A variant cannot
    /// override it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transit_token_lifetime_secs: Option<u64>,

    /// Global transit OPA policy (all outbound calls).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transit_policy: Option<PolicyRef>,

    /// Total outbound rate limit across all transit points.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitConfig>,

    /// Inject signed VP into every outbound request.
    #[serde(default = "default_true")]
    pub sign_requests: bool,

    /// Extension validation rules for outbound request bodies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_rules: Option<ExtensionRules>,

    /// Custom metadata injection for outbound requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_metadata: Option<CustomMetadata>,

    /// Response extension validation for transit responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_extension_rules: Option<ExtensionRules>,

    /// Channel-level transit OPA policy definition ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opa_policy_definition_id: Option<String>,

    /// Not enforced: a Transit Point authenticates its callers with its own
    /// [`TransitPoint::source_auth`]. The admin API refuses a surface that sets
    /// it, and one stored with it has every Transit Point request refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_auth: Option<SourceAuthConfig>,
}

/// How long a transit token lives when its surface sets no lifetime, in seconds.
pub const DEFAULT_TRANSIT_TOKEN_LIFETIME_SECS: u64 = 300;

/// The shortest transit token lifetime a surface may set, in seconds.
pub const MIN_TRANSIT_TOKEN_LIFETIME_SECS: u64 = 30;

/// The longest transit token lifetime a surface may set, in seconds, when
/// `gateway.json` does not set `transit_token_max_lifetime_secs`.
pub const DEFAULT_TRANSIT_TOKEN_MAX_LIFETIME_SECS: u64 = 300;

/// The highest value `transit_token_max_lifetime_secs` may take, and so the
/// longest any transit token lives, in seconds. Whoever holds a transit token
/// can use it on its surface's Transit Points for its whole lifetime.
pub const MAX_TRANSIT_TOKEN_LIFETIME_SECS: u64 = 900;

/// Reads an appliance-wide `transit_token_max_lifetime_secs` as `gateway.json`
/// holds it: [`DEFAULT_TRANSIT_TOKEN_MAX_LIFETIME_SECS`] when unset, and
/// refused unless a whole number from [`MIN_TRANSIT_TOKEN_LIFETIME_SECS`] to
/// [`MAX_TRANSIT_TOKEN_LIFETIME_SECS`].
pub fn transit_token_max_lifetime_from(value: Option<&serde_json::Value>) -> Result<u64, String> {
    let Some(value) = value else {
        return Ok(DEFAULT_TRANSIT_TOKEN_MAX_LIFETIME_SECS);
    };
    value
        .as_u64()
        .filter(|max_secs| (MIN_TRANSIT_TOKEN_LIFETIME_SECS..=MAX_TRANSIT_TOKEN_LIFETIME_SECS).contains(max_secs))
        .ok_or_else(|| {
            format!(
                "transit_token_max_lifetime_secs in gateway.json must be from {MIN_TRANSIT_TOKEN_LIFETIME_SECS} \
                 to {MAX_TRANSIT_TOKEN_LIFETIME_SECS} seconds, not {value}"
            )
        })
}

impl SharedTransitConfig {
    /// Refuses a [`Self::transit_token_lifetime_secs`] below
    /// [`MIN_TRANSIT_TOKEN_LIFETIME_SECS`] or above `max_secs`, the appliance's
    /// `transit_token_max_lifetime_secs`.
    pub fn validate_transit_token_lifetime(
        &self,
        max_secs: u64,
    ) -> Result<(), String> {
        match self.transit_token_lifetime_secs {
            Some(secs) if !(MIN_TRANSIT_TOKEN_LIFETIME_SECS..=max_secs).contains(&secs) => Err(format!(
                "transit.transit_token_lifetime_secs must be from {MIN_TRANSIT_TOKEN_LIFETIME_SECS} to {max_secs} \
                 seconds, not {secs} ({max_secs} is transit_token_max_lifetime_secs in gateway.json)"
            )),
            _ => Ok(()),
        }
    }
}

/// Why a surface that sets [`SharedTransitConfig::source_auth`] is refused by the
/// admin API, and has every Transit Point request refused when it is loaded.
pub const TRANSIT_SOURCE_AUTH_REFUSED: &str = "transit.source_auth is not enforced, so a surface that sets it has \
     every Transit Point request refused; remove it, and set source_auth on each Transit Point instead";

/// How the transit token carries caller context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TransitTokenMode {
    /// Context carried in the signed token itself, readable by the managed
    /// agent (stateless, larger token).
    #[default]
    Embedded,
    /// Context stored server-side; token is a short reference key.
    Reference,
}

/// A single named transit point — one outbound destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitPoint {
    /// Stable internal identifier (UUID v4). Auto-generated when missing
    /// so the task monitor, metrics store, and any other component that
    /// needs a durable handle keeps a continuous record across renames
    /// of `name` or `alias`. Never exposed on URLs.
    #[serde(default = "TransitPoint::new_id")]
    pub id: String,

    /// Friendly display name shown in the dashboard. Free text; empty is
    /// allowed. Never used for routing or URL construction — see `alias`.
    #[serde(default)]
    pub name: String,

    /// URL-safe routing identifier for this transit point. Required and
    /// must match `^[a-z][a-z0-9-]*$` (lowercase, digits, dashes; must
    /// start with a letter). Forms the path segment under
    /// `/outbound/<route>/<alias>/...` and the transit-point claim in
    /// transit tokens. Validated server-side on create/update — empty or
    /// malformed values are rejected, not silently coerced.
    #[serde(default)]
    pub alias: String,

    /// The external destination endpoint.
    pub target_endpoint: String,

    /// Protocol spoken by the destination (can differ from the Access Point protocol).
    #[serde(default)]
    pub protocol: TransitProtocol,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_http: Option<super::types::McpHttpConfig>,

    /// Header-to-metadata normalization for A2A/AP2 requests received
    /// by this transit point from the managed agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_metadata_mapping: Option<HeaderMetadataMappingConfig>,

    /// Credentials for the destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_auth: Option<TargetAuthConfig>,

    /// Per-destination OPA policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyRef>,

    /// Per-destination OPA policy evaluated on the response from this
    /// transit point (after upstream replies, before forwarding back).
    /// Independent of the inbound `target.response_policy`, so each TP
    /// flow can carry its own response gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_policy: Option<PolicyRef>,

    /// Per-Transit-Point MCP Tool Gating (only when `protocol = mcp`). A
    /// condition-gated allow/deny firewall applied to this TP's own MCP tool
    /// surface — its `tools/list` response and `tools/call` requests — so a
    /// managed agent calling out through this TP sees (and can invoke) only
    /// the tools this gate permits. Independent of the surface-wide
    /// [`Target::mcp_tool_gating`], which governs the inbound primary target.
    /// When `None`, no per-TP gating is enforced on this outbound leg.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_tool_gating: Option<McpToolGatingConfig>,

    /// Payment policy if the destination charges.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_policy: Option<TransitPaymentPolicy>,

    /// Networking (timeout, retry, circuit breaker).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub networking: Option<NetworkingConfig>,

    /// Per-TP rate limit. Applied at the outbound pipeline before
    /// dispatch to this transit point's target endpoint. When `None`,
    /// no per-TP rate limiting is enforced (the transit-shared and
    /// channel-wide limits still apply).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitConfig>,

    /// VP signing for outbound calls to this destination.
    #[serde(default)]
    pub identity_injection: IdentityInjectionConfig,

    /// Per-TP managed identity extraction from THIS transit point's
    /// response. Analogous to the channel-level
    /// `identity_slots.external` but scoped to a single TP — useful
    /// when different TPs on the same channel speak to agents with
    /// different identity payload shapes. When `None`, the outbound
    /// pipeline falls back to the channel-wide selector built from
    /// `identity_slots.external`. Validated against `json_schema` (if
    /// set) before identity hashing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_identity: Option<crate::source_auth::ManagedIdentityConfig>,

    /// OAuth/API token management for this destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transit_credentials: Option<TransitCredentials>,

    /// Transit Point-scoped Workload Binding. When set and
    /// [`WorkloadBindingConfig::enabled`] is `true`, the outbound pipeline
    /// produces a signed workload-binding VP for calls through this Transit
    /// Point, binding the managed agent identity to the configured caller
    /// context. When `None` (or disabled), outbound identity injection keeps
    /// the flat `identityFields` credential-subject shape. This is the sole
    /// supported location for Workload Binding; the legacy shared
    /// `transit.workload_binding` is not inherited or migrated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_binding: Option<WorkloadBindingConfig>,

    /// The URL on the gateway for this transit point (computed).
    /// Used for agent card URL rewriting.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gateway_url: String,

    /// Override agent card location path for THIS transit point's
    /// destination (relative to the destination origin). Independent of
    /// the access point's [`AccessPoint::agent_card_path`], which governs
    /// the inbound managed-agent card only. When set, outbound agent-card
    /// requests through this TP — and the trust-context card fetch — use
    /// `<destination-origin>/<agent_card_path>` instead of the default
    /// `/.well-known/agent-card.json`. When `None`, the default
    /// well-known paths are used (no fallback to the access point value).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_card_path: Option<String>,

    /// Per-TP outbound listener address override. When set, this TP's
    /// `/outbound/...` route is registered on this address (which must
    /// be one of the gateway's pre-configured outbound listener
    /// addresses) instead of the channel-wide
    /// [`TransitConfig::outbound_listen_address`]. Lets two TPs in the
    /// same surface bind on different outbound ports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_address: Option<String>,

    /// Per-TP listen path override. When set (e.g. `/partner-a-webhook`),
    /// the TP is registered at exactly `<effective_listen_address>{path}`
    /// instead of the derived `/outbound/<channel-route>/<alias>`. Path
    /// must start with `/` and must not contain `..`. Per-listener
    /// uniqueness is enforced at validation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_path: Option<String>,

    /// Whether the outbound pipeline must enforce a valid
    /// `X-Transit-Token` on every call to this TP. Defaults to `true`.
    /// When `false` (and only when `false`), the transit token
    /// validation step is skipped for this TP — useful for development
    /// or for TPs whose callers cannot carry the token.
    #[serde(default = "default_true")]
    pub require_transit_token: bool,

    /// Authenticates the caller of every request to this Transit Point, as
    /// source authentication does on an Access Point, before anything else
    /// runs. [`Self::unenforceable_caller_authentication`] lists the methods a
    /// Transit Point supports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_auth: Option<SourceAuthConfig>,

    /// Serves callers this Transit Point does not authenticate. A Transit
    /// Point that neither requires a transit token nor sets
    /// `mcp_http.authorization` or `source_auth` refuses every request unless
    /// this is set, and only such a Transit Point may set it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_unauthenticated_callers: bool,

    /// Extension inspection for A2A requests from the managed agent to
    /// transit point. When `enabled = true` (the default), the
    /// outbound pipeline rejects any A2A call that does not carry all
    /// URIs listed in `watch_extensions` — mirroring the inbound
    /// `payload_extraction` gate on the access-point side.
    /// Set `enabled = false` to disable the hard gate (soft
    /// observation only) for this transit point.
    #[serde(default)]
    pub extension_inspection: ExtensionInspectionConfig,

    /// Lets the surface's `outbound_credentials` cross Fabric when this
    /// Transit Point's `target_endpoint` is `fabric://`. Off by default.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub fabric_delegated_credentials: bool,

    /// Lets the managed agent call this Transit Point while it serves a
    /// request a paired gateway sent over Fabric: the transit token issued for
    /// that request opens only the Transit Points that set it. Off by default.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_fabric_callers: bool,

    /// Target-leg Trust Checks run on requests the managed agent sends
    /// through this Transit Point, whatever its protocol.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_check_list: Vec<TrustCheckElement>,

    /// Marks a `trust_check_list` copied from the former surface-wide target
    /// list, so the dashboard can ask the operator to review it. The runtime
    /// ignores it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub trust_check_migrated: bool,
}

impl TransitPoint {
    /// Whether delegated credentials must be kept from this Transit Point's
    /// destination: a `fabric://` peer that has not opted in.
    pub fn withholds_delegated_credentials(&self) -> bool {
        self.target_endpoint
            .starts_with("fabric://")
            && !self.fabric_delegated_credentials
    }

    /// Whether this Transit Point authenticates its callers: with a transit
    /// token, `mcp_http.authorization` or `source_auth`.
    pub fn authenticates_callers(&self) -> bool {
        self.require_transit_token
            || self
                .mcp_http
                .as_ref()
                .is_some_and(|http| http.authorization.is_some())
            || self.source_auth.is_some()
    }

    /// Why every request to this Transit Point is refused, when how it
    /// authenticates its callers cannot be enforced: it authenticates none
    /// and does not allow unauthenticated callers, it sets both `source_auth`
    /// and `mcp_http.authorization`, or its `source_auth` is not one a Transit
    /// Point supports. A Transit Point supports `api_key` and
    /// `api_key_provider` read from an HTTP header, `jwt_bearer` that does not
    /// forward the caller's token, and `mtls`.
    pub fn unenforceable_caller_authentication(&self) -> Option<String> {
        let alias = &self.alias;
        let Some(source_auth) = &self.source_auth else {
            return (!self.authenticates_callers() && !self.allow_unauthenticated_callers).then(|| {
                format!(
                    "Transit Point '{alias}' authenticates no caller: require a transit token, set source_auth \
                     or mcp_http.authorization, or set allow_unauthenticated_callers to serve callers it does not \
                     authenticate"
                )
            });
        };
        if self
            .mcp_http
            .as_ref()
            .is_some_and(|http| http.authorization.is_some())
        {
            return Some(format!("Transit Point '{alias}' sets both source_auth and mcp_http.authorization; keep one"));
        }
        if !transit_point_supports_source_auth(source_auth) {
            return Some(format!(
                "Transit Point '{alias}' source_auth must be api_key or api_key_provider read from an HTTP header, \
                 jwt_bearer without forward_header, or mtls"
            ));
        }
        match source_auth {
            SourceAuthConfig::JwtBearer(config)
                if config
                    .audiences
                    .iter()
                    .all(|audience| audience.trim().is_empty()) =>
            {
                Some(format!(
                    "Transit Point '{alias}' source_auth jwt_bearer must name the audiences it accepts, so a token \
                     issued for another service, such as the Access Point, is refused"
                ))
            }
            _ => None,
        }
    }

    /// Refuses a Transit Point whose caller authentication cannot be enforced
    /// ([`Self::unenforceable_caller_authentication`]), or that sets
    /// `allow_unauthenticated_callers` while it authenticates its callers.
    pub fn validate_caller_authentication(&self) -> Result<(), String> {
        if let Some(reason) = self.unenforceable_caller_authentication() {
            return Err(reason);
        }
        if self.allow_unauthenticated_callers && self.authenticates_callers() {
            return Err(format!(
                "Transit Point '{}' sets allow_unauthenticated_callers but authenticates its callers; remove it",
                self.alias
            ));
        }
        Ok(())
    }

    fn new_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Pattern that a transit point alias MUST match to be accepted on
    /// create/update. Lowercase letters, digits, and dashes only; must
    /// start with a letter; max 63 characters. Mirrored by the
    /// dashboard's `TRANSIT_POINT_ALIAS_PATTERN` so both sides reject
    /// the same shapes.
    #[allow(dead_code)]
    pub const ALIAS_PATTERN: &'static str = r"^[a-z][a-z0-9-]{0,62}$";

    /// Validate that the alias is non-empty and matches `ALIAS_PATTERN`.
    /// Returns the offending alias text in the error so the caller can
    /// echo it back to the user verbatim.
    pub fn validate_alias(alias: &str) -> Result<(), String> {
        if alias.is_empty() {
            return Err("alias is required".to_string());
        }
        let mut chars = alias.chars();
        let Some(first) = chars.next() else {
            return Err("alias is required".to_string());
        };
        if !first.is_ascii_lowercase() {
            return Err(format!("alias '{}' must start with a lowercase letter (a-z)", alias));
        }
        if alias.len() > 63 {
            return Err(format!("alias '{}' must be 63 characters or fewer", alias));
        }
        for c in chars {
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
                return Err(format!("alias '{}' may only contain lowercase letters, digits, and dashes", alias));
            }
        }
        Ok(())
    }

    /// The header-to-metadata mapping, or `None` if configured on a protocol
    /// that doesn't support it (only A2A/AP2 messages have the extension it
    /// injects into). Runtime defense-in-depth alongside
    /// `AgentSurface::validate()` and the load-time remediation in
    /// `crate::surfaces::strip_unsupported_header_metadata_mappings`, in case
    /// an invalid mapping ever reaches a running surface another way.
    pub fn header_metadata_mapping_if_supported(&self) -> Option<&HeaderMetadataMappingConfig> {
        header_metadata_mapping_if_protocol_supports_it(
            self.header_metadata_mapping
                .as_ref(),
            matches!(self.protocol, TransitProtocol::A2a | TransitProtocol::Ap2),
        )
    }
}

/// A Transit Point reads a caller's credential from a header and never forwards
/// it, and it serves no DID Auth challenge.
fn transit_point_supports_source_auth(source_auth: &SourceAuthConfig) -> bool {
    use crate::source_auth::models::CredentialExtraction;
    match source_auth {
        SourceAuthConfig::ApiKey(config) => matches!(config.extraction, CredentialExtraction::HttpHeader { .. }),
        SourceAuthConfig::ApiKeyProvider(config) => {
            matches!(config.extraction, CredentialExtraction::HttpHeader { .. })
        }
        SourceAuthConfig::JwtBearer(config) => !config.forward_header,
        SourceAuthConfig::Mtls(_) => true,
        SourceAuthConfig::DidAuth(_) => false,
    }
}

/// Only A2A/AP2 messages carry the extension `header_metadata_mapping`
/// injects into; shared by [`AccessPoint`] and [`TransitPoint`], whose
/// protocol lives in different enums ([`SurfaceProtocol`] / [`TransitProtocol`]).
fn header_metadata_mapping_if_protocol_supports_it(
    mapping: Option<&HeaderMetadataMappingConfig>,
    protocol_supports_it: bool,
) -> Option<&HeaderMetadataMappingConfig> {
    if protocol_supports_it {
        mapping
    } else {
        None
    }
}

/// Protocol for transit points — includes `http` for raw pass-through.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TransitProtocol {
    /// Agent-to-Agent protocol.
    #[default]
    A2a,
    /// Agent Payments Protocol.
    Ap2,
    /// Model Context Protocol.
    Mcp,
    /// Raw HTTP pass-through (no protocol-aware processing).
    Http,
}

/// Payment policy for transit points.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitPaymentPolicy {
    /// Payment protocol type.
    #[serde(rename = "type")]
    pub payment_type: TransitPaymentType,
    /// Automatically pay challenges up to this amount.
    #[serde(default)]
    pub auto_pay: bool,
    /// Maximum amount for auto-pay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_amount: Option<String>,
    /// Currency for max_amount.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransitPaymentType {
    X402,
    Mpp,
}

/// OAuth/API token management bound to a specific transit point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitCredentials {
    /// FK to a configured CredentialProvider.
    pub credential_provider_id: String,
    /// OAuth scopes to request.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// How to handle missing tokens.
    #[serde(default)]
    pub consent_mode: ConsentMode,
    /// How to inject the token into outbound requests.
    #[serde(default)]
    pub inject_as: CredentialInjection,
    /// Timeout (seconds) when `consent_mode = elicit`.
    #[serde(default = "default_transit_elicit_timeout_secs")]
    pub elicit_timeout_secs: u64,
    /// Fallback behaviour when `consent_mode = elicit` and the MCP client
    /// did not advertise the `elicitation` capability.
    #[serde(default)]
    pub elicit_fallback: ElicitFallback,
}

fn default_transit_elicit_timeout_secs() -> u64 {
    300
}

/// How to handle missing delegation tokens.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConsentMode {
    /// Return consent_required signal when token is missing.
    #[default]
    OnDemand,
    /// Block entirely until user has pre-authorized.
    PreAuthorize,
    /// Spec-compliant MCP `elicitation/create` over the open session.
    Elicit,
}

/// Fallback for `consent_mode = elicit` when the MCP client did not advertise
/// the `elicitation` capability during `initialize`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ElicitFallback {
    /// Degrade to the legacy on-demand behaviour (HTTP 401 + consent_required).
    #[default]
    OnDemand,
    /// Fail the in-flight tool call with a JSON-RPC error.
    Fail,
}

/// How to inject delegated credentials into outbound requests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CredentialInjection {
    /// Authorization: Bearer {token}
    #[default]
    BearerHeader,
    /// Custom header with format string.
    CustomHeader { name: String, format: String },
    /// JSON-RPC `_meta.{field}` injection.
    Meta { field: String },
}

// ─── DID:webvh Identity ─────────────────────────────────────────────────────

/// did:webvh managed identity configuration.
/// When configured, the gateway manages a did:webvh DID lifecycle for this surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidWebVhIdentityConfig {
    /// The managed identity ID (references an identity in the identity store).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,

    /// Auto-create the identity if it doesn't exist.
    #[serde(default)]
    pub auto_create: bool,

    /// Custom path segment for the DID (default: derived from surface name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_path: Option<String>,

    /// How the DID identity is injected into outbound requests.
    #[serde(default)]
    pub injection_mode: DidInjectionMode,
}

/// How did:webvh identity is injected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DidInjectionMode {
    /// X-DID-Identity header.
    #[default]
    Header,
    /// X-DID-Signed-Identity header (signed).
    SignedHeader,
    /// Protocol-native injection (A2A extension / MCP `_meta`).
    ProtocolNative,
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn default_true() -> bool {
    true
}

// ─── Conversion from Legacy ChannelMapping ──────────────────────────────────

impl AgentSurface {
    /// Compute the base URL for this surface given the gateway's external host.
    #[allow(dead_code)]
    pub fn base_url(
        &self,
        gateway_host: &str,
    ) -> String {
        let port = self
            .access_point
            .listen_address
            .split(':')
            .next_back()
            .unwrap_or("8443");
        format!("https://{}:{}{}", gateway_host, port, self.access_point.route)
    }

    /// Get the transit point URL template for a given transit point name.
    #[allow(dead_code)]
    pub fn transit_url(
        &self,
        gateway_host: &str,
        transit_name: &str,
    ) -> String {
        format!("{}/transit-point/{}", self.base_url(gateway_host), transit_name)
    }

    /// Look up a transit point by name.
    #[allow(dead_code)]
    pub fn find_transit_point(
        &self,
        name: &str,
    ) -> Option<&TransitPoint> {
        self.transit
            .as_ref()
            .and_then(|t| {
                t.points
                    .iter()
                    .find(|p| p.name == name)
            })
    }
}

// ─── StorableEntity implementation ──────────────────────────────────────────

impl StorableEntity for AgentSurface {
    fn id(&self) -> &str {
        &self.surface_id
    }

    /// Pre-deserialization migration for removed fields.
    ///
    /// The `access_point.trust_registry_verification`,
    /// `target.trust_registry_injection`,
    /// `target.trust_registry_injection_inbound`, and
    /// `transit.trust_registry_verification` fields (plus their variant
    /// overrides mirrors) were removed together with the legacy
    /// Surface-Builder Trust Registry node, and the surface-level
    /// `trusted_binding_issuers` allowlist was replaced by connection-scoped
    /// `Gateway.trusted_issuer_dids`. Stored surfaces persisted before those
    /// removals still carry the keys; because `AgentSurface` (and its child
    /// structs) use `#[serde(deny_unknown_fields)]`, leaving them in place
    /// would fail loading. Strip them here so old configs load, and return
    /// `true` when anything was stripped so the storage layer re-persists
    /// the file without the legacy keys.
    fn migrate_raw_json(value: &mut serde_json::Value) -> anyhow::Result<bool> {
        let stripped = strip_legacy_trust_registry_fields(value);
        let split = split_target_trust_checks_per_transit_point(value);
        warn_target_lists_that_cannot_run(value);
        let marked = mark_transit_point_source_auth(value);
        Ok(stripped || split || marked)
    }
}

/// Keep a stored surface's `transit_point_source_auth` in step with its
/// Transit Points (see [`AgentSurface::has_transit_point_source_auth`]), so a
/// surface file written outside the API is marked when it is first loaded and
/// re-persisted. A Surface Template's surface snapshot is marked the same way.
/// Returns whether the record changed.
pub(crate) fn mark_transit_point_source_auth(value: &mut serde_json::Value) -> bool {
    let any_source_auth = |points: Option<&serde_json::Value>| {
        points
            .and_then(serde_json::Value::as_array)
            .is_some_and(|points| {
                points.iter().any(|point| {
                    point
                        .get("source_auth")
                        .is_some_and(|source_auth| !source_auth.is_null())
                })
            })
    };
    let uses_source_auth = any_source_auth(value.pointer("/transit/points"))
        || value
            .get("variants")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|variants| {
                variants
                    .iter()
                    .any(|variant| any_source_auth(variant.pointer("/overrides/transit/points")))
            });
    let Some(obj) = value.as_object_mut() else {
        return false;
    };
    let marked = obj.get("transit_point_source_auth") == Some(&serde_json::Value::Bool(true));
    match (uses_source_auth, marked) {
        (true, false) => {
            obj.insert("transit_point_source_auth".to_string(), serde_json::Value::Bool(true));
            true
        }
        (false, true) => obj
            .remove("transit_point_source_auth")
            .is_some(),
        _ => false,
    }
}

/// Warn about a stored per-Transit-Point surface whose base or variant
/// `target.trust_check_list` sits on a Managed Agent endpoint that does not run
/// it (see [`endpoint_runs_target_trust_checks`]): those checks never run.
fn warn_target_lists_that_cannot_run(value: &serde_json::Value) {
    if value.get("trust_check_split") != Some(&serde_json::Value::Bool(true)) {
        return;
    }
    let surface_id = value
        .get("surface_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?");
    let base_endpoint = value
        .pointer("/target/endpoint")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let idle = |endpoint: &str, target: Option<&serde_json::Value>| {
        !json_array_at(target, "trust_check_list").is_empty() && !endpoint_runs_target_trust_checks(endpoint)
    };
    if idle(base_endpoint, value.get("target")) {
        tracing::warn!(
            surface_id = %surface_id,
            "target.trust_check_list never runs on this Managed Agent endpoint; only a2a-proxy:// and fabric:// targets run it"
        );
    }
    for variant in value
        .get("variants")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        let target = variant.pointer("/overrides/target");
        let endpoint = target
            .and_then(|t| t.get("endpoint"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or(base_endpoint);
        if idle(endpoint, target) {
            tracing::warn!(
                surface_id = %surface_id,
                variant = variant.get("alias").and_then(serde_json::Value::as_str).unwrap_or("?"),
                "target.trust_check_list never runs on this variant's Managed Agent endpoint; only a2a-proxy:// and \
                 fabric:// targets run it"
            );
        }
    }
}

/// Strip removed keys from a stored [`AgentSurface`] JSON blob.
///
/// Walks the base surface plus every entry in `variants[]`. Returns
/// `true` when at least one key was removed. Pure over `serde_json::Value`;
/// invoked from [`AgentSurface::migrate_raw_json`] at load time and
/// covered by unit tests below.
fn strip_legacy_trust_registry_fields(value: &mut serde_json::Value) -> bool {
    let mut mutated = false;

    if let Some(obj) = value.as_object_mut() {
        if obj
            .remove("trusted_binding_issuers")
            .is_some()
        {
            tracing::warn!(
                surface_id = obj
                    .get("surface_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?"),
                "dropping removed surface field trusted_binding_issuers; trust issuer DIDs on the Remote gateway connection instead"
            );
            mutated = true;
        }
        mutated |= strip_surface_shape_keys(obj);

        if let Some(variants) = obj
            .get_mut("variants")
            .and_then(|v| v.as_array_mut())
        {
            for variant in variants.iter_mut() {
                if let Some(variant_obj) = variant.as_object_mut()
                    && let Some(overrides) = variant_obj
                        .get_mut("overrides")
                        .and_then(|o| o.as_object_mut())
                {
                    mutated |= strip_overrides_keys(overrides);
                }
            }
        }
    }

    mutated
}

/// Move a stored surface's surface-wide `target.trust_check_list` onto its
/// Transit Points.
///
/// Surfaces written before per-Transit-Point lists ran the target list for
/// every Transit Point. Each Transit Point, whatever its protocol, receives a
/// copy flagged `trust_check_migrated`, for the base surface and every
/// variant, so behaviour is unchanged. The target list is then
/// cleared unless the Managed Agent endpoint runs it on its own target leg
/// (`a2a-proxy://` and `fabric://`, see [`endpoint_runs_target_trust_checks`]);
/// elsewhere it only ever ran through Transit Points. Runs once: it returns
/// `true` whenever the base or a variant carries a target list, and sets
/// `trust_check_split` while any Trust Check list remains, target or Transit
/// Point (see [`has_trust_check_lists`]). Surfaces without a target list are
/// left untouched.
pub(crate) fn split_target_trust_checks_per_transit_point(value: &mut serde_json::Value) -> bool {
    split_target_trust_checks(value, endpoint_runs_target_trust_checks)
}

/// [`split_target_trust_checks_per_transit_point`] for a Surface Template's
/// surface snapshot, whose target endpoint may still be unknown: an empty
/// endpoint or a `$` placeholder keeps the target list.
pub(crate) fn split_template_target_trust_checks(value: &mut serde_json::Value) -> bool {
    split_target_trust_checks(value, |endpoint| {
        endpoint.is_empty() || endpoint.starts_with('$') || endpoint_runs_target_trust_checks(endpoint)
    })
}

/// Whether a surface JSON blob carries any Trust Check list: a non-empty
/// `target.trust_check_list` or Transit Point `trust_check_list`, on the base
/// or in any variant override. Such a surface is stored with
/// `trust_check_split: true`, so a release that predates per-Transit-Point
/// lists refuses to load it instead of loading it with no checks.
pub(crate) fn has_trust_check_lists(value: &serde_json::Value) -> bool {
    value
        .as_object()
        .is_some_and(|obj| has_legacy_target_trust_checks(obj) || has_transit_point_trust_checks(obj))
}

fn has_transit_point_trust_checks(obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    let any_point_list = |points: Option<&serde_json::Value>| {
        points
            .and_then(serde_json::Value::as_array)
            .is_some_and(|points| {
                points
                    .iter()
                    .any(|point| !json_array_at(Some(point), "trust_check_list").is_empty())
            })
    };
    any_point_list(
        obj.get("transit")
            .and_then(|t| t.get("points")),
    ) || obj
        .get("variants")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|variants| {
            variants
                .iter()
                .any(|variant| any_point_list(variant.pointer("/overrides/transit/points")))
        })
}

fn split_target_trust_checks(
    value: &mut serde_json::Value,
    keeps_target_list: fn(&str) -> bool,
) -> bool {
    let Some(obj) = value.as_object_mut() else {
        return false;
    };
    if obj
        .get("trust_check_split")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
        || !has_legacy_target_trust_checks(obj)
    {
        return false;
    }

    let surface_id = obj
        .get("surface_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?")
        .to_string();
    let base_endpoint = obj
        .get("target")
        .and_then(|t| t.get("endpoint"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let base_list = json_array_at(obj.get("target"), "trust_check_list");
    let base_points = obj
        .get("transit")
        .and_then(|t| t.get("points"))
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();

    let outcome = obj
        .get_mut("transit")
        .and_then(|t| t.get_mut("points"))
        .and_then(serde_json::Value::as_array_mut)
        .map(|points| copy_trust_checks_onto_points(points, &base_list))
        .unwrap_or_default();
    let base_keeps = keeps_target_list(&base_endpoint);
    let mut base_removed = false;
    if !base_keeps
        && !base_list.is_empty()
        && let Some(target) = obj
            .get_mut("target")
            .and_then(serde_json::Value::as_object_mut)
    {
        base_removed = target
            .remove("trust_check_list")
            .is_some();
    }
    if outcome.changed() || base_removed {
        tracing::info!(
            surface_id = %surface_id,
            transit_points = ?outcome.copied,
            "migrated surface-wide target Trust Checks to Transit Points"
        );
    }
    if base_removed && outcome.copied.is_empty() {
        warn_target_list_removed_without_copy(&surface_id, None);
    }

    let base = BaseTrustChecks {
        surface_id: &surface_id,
        endpoint: &base_endpoint,
        list: &base_list,
        list_after: if base_keeps {
            &base_list
        } else {
            &[]
        },
        points: &base_points,
        copied_any: !outcome.copied.is_empty(),
        keeps_target_list,
    };
    if let Some(variants) = obj
        .get_mut("variants")
        .and_then(serde_json::Value::as_array_mut)
    {
        for variant in variants.iter_mut() {
            split_variant_trust_checks(variant, &base);
        }
    }

    if has_legacy_target_trust_checks(obj) || has_transit_point_trust_checks(obj) {
        obj.insert("trust_check_split".to_string(), serde_json::Value::Bool(true));
    } else {
        obj.remove("trust_check_split");
    }
    true
}

struct BaseTrustChecks<'a> {
    surface_id: &'a str,
    endpoint: &'a str,
    list: &'a [serde_json::Value],
    list_after: &'a [serde_json::Value],
    points: &'a [serde_json::Value],
    copied_any: bool,
    keeps_target_list: fn(&str) -> bool,
}

/// What one variant's overrides say about its target Trust Check list and
/// Transit Points, read once before the variant is migrated.
struct VariantTrustChecks {
    alias: String,
    complete: bool,
    has_target_override: bool,
    endpoint: String,
    own_list: Option<Vec<serde_json::Value>>,
    effective_list: Vec<serde_json::Value>,
    transit_disabled: bool,
    has_own_points: bool,
}

impl VariantTrustChecks {
    fn read(
        alias: String,
        overrides: &serde_json::Map<String, serde_json::Value>,
        base: &BaseTrustChecks<'_>,
    ) -> Self {
        let complete = overrides
            .get("complete")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let target_override = overrides
            .get("target")
            .and_then(serde_json::Value::as_object);
        let own_list = target_override.and_then(|target| match target.get("trust_check_list") {
            Some(list) => Some(
                list.as_array()
                    .cloned()
                    .unwrap_or_default(),
            ),
            None if complete => Some(Vec::new()),
            None => None,
        });
        let effective_list = own_list
            .clone()
            .unwrap_or_else(|| base.list.to_vec());
        let endpoint = target_override
            .and_then(|t| t.get("endpoint"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or(base.endpoint)
            .to_string();
        let transit = overrides
            .get("transit")
            .and_then(serde_json::Value::as_object);
        Self {
            alias,
            complete,
            has_target_override: target_override.is_some(),
            endpoint,
            own_list,
            effective_list,
            transit_disabled: transit
                .and_then(|t| t.get("disabled"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            has_own_points: transit
                .and_then(|t| t.get("points"))
                .is_some_and(serde_json::Value::is_array),
        }
    }

    fn differs_from_base_list(
        &self,
        base: &BaseTrustChecks<'_>,
    ) -> bool {
        self.effective_list.as_slice() != base.list
    }
}

fn split_variant_trust_checks(
    variant: &mut serde_json::Value,
    base: &BaseTrustChecks<'_>,
) {
    let alias = variant
        .get("alias")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?")
        .to_string();
    let Some(overrides) = variant
        .get_mut("overrides")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    let ctx = VariantTrustChecks::read(alias, overrides, base);

    let (outcome, routes_own_points) = copy_variant_trust_checks_onto_points(&ctx, overrides, base);
    let target = fix_variant_target_trust_checks(&ctx, overrides, base);
    let received_copy = if routes_own_points {
        !outcome.copied.is_empty()
    } else {
        base.copied_any
    };
    if target.removed && !received_copy {
        warn_target_list_removed_without_copy(base.surface_id, Some(&ctx.alias));
    }

    if outcome.changed() || target.changed {
        tracing::info!(
            surface_id = %base.surface_id,
            variant = %ctx.alias,
            transit_points = ?outcome.copied,
            "migrated surface-wide target Trust Checks to Transit Points"
        );
    }
}

/// Copy the variant's effective list onto its own Transit Points, or onto a
/// materialised copy of the base points when its list differs from the base
/// list. Returns what changed on those points and whether the variant now
/// routes to points of its own.
fn copy_variant_trust_checks_onto_points(
    ctx: &VariantTrustChecks,
    overrides: &mut serde_json::Map<String, serde_json::Value>,
    base: &BaseTrustChecks<'_>,
) -> (PointsOutcome, bool) {
    if ctx.transit_disabled {
        return (PointsOutcome::default(), true);
    }
    if ctx.has_own_points {
        let outcome = overrides
            .get_mut("transit")
            .and_then(|t| t.get_mut("points"))
            .and_then(serde_json::Value::as_array_mut)
            .map(|points| copy_trust_checks_onto_points(points, &ctx.effective_list))
            .unwrap_or_default();
        return (outcome, true);
    }
    if !ctx.differs_from_base_list(base) || base.points.is_empty() {
        return (PointsOutcome::default(), false);
    }
    let mut points = base.points.to_vec();
    let mut outcome = copy_trust_checks_onto_points(&mut points, &ctx.effective_list);
    outcome.materialised = overrides
        .entry("transit")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .map(|transit| transit.insert("points".to_string(), serde_json::Value::Array(points)))
        .is_some();
    let routes_own_points = outcome.materialised;
    (outcome, routes_own_points)
}

struct TargetListFix {
    changed: bool,
    removed: bool,
}

/// Set the variant's `target.trust_check_list` override to the list its
/// target runs on its own target leg: the effective list where the base's
/// endpoint rule keeps it, none otherwise. Drops the override when it would
/// equal what the variant inherits.
fn fix_variant_target_trust_checks(
    ctx: &VariantTrustChecks,
    overrides: &mut serde_json::Map<String, serde_json::Value>,
    base: &BaseTrustChecks<'_>,
) -> TargetListFix {
    let unchanged = TargetListFix { changed: false, removed: false };
    if !ctx.has_target_override {
        return unchanged;
    }
    let keeps = (base.keeps_target_list)(&ctx.endpoint);
    let desired: Vec<serde_json::Value> = if keeps {
        ctx.effective_list.clone()
    } else {
        Vec::new()
    };
    let resolved_now = ctx
        .own_list
        .clone()
        .unwrap_or_else(|| base.list_after.to_vec());
    if resolved_now == desired {
        return unchanged;
    }
    let Some(target) = overrides
        .get_mut("target")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return unchanged;
    };
    let inherited: &[serde_json::Value] = if ctx.complete {
        &[]
    } else {
        base.list_after
    };
    if desired.as_slice() == inherited {
        target.remove("trust_check_list");
    } else {
        target.insert("trust_check_list".to_string(), serde_json::Value::Array(desired));
    }
    TargetListFix {
        changed: true,
        removed: !keeps && !ctx.effective_list.is_empty(),
    }
}

/// Warn that a non-empty target list was removed and no Transit Point
/// received a copy, so its checks no longer run anywhere.
fn warn_target_list_removed_without_copy(
    surface_id: &str,
    variant: Option<&str>,
) {
    tracing::warn!(
        surface_id = %surface_id,
        variant = variant.unwrap_or_default(),
        "removed the surface-wide target Trust Checks and no Transit Point received a copy; \
         they no longer run"
    );
}

fn has_legacy_target_trust_checks(obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    let non_empty = |target: Option<&serde_json::Value>| !json_array_at(target, "trust_check_list").is_empty();
    non_empty(obj.get("target"))
        || obj
            .get("variants")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|variants| {
                variants
                    .iter()
                    .any(|variant| {
                        non_empty(
                            variant
                                .get("overrides")
                                .and_then(|o| o.get("target")),
                        )
                    })
            })
}

fn json_array_at(
    parent: Option<&serde_json::Value>,
    key: &str,
) -> Vec<serde_json::Value> {
    parent
        .and_then(|p| p.get(key))
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// What [`copy_trust_checks_onto_points`] changed on a set of Transit Points.
#[derive(Default)]
struct PointsOutcome {
    copied: Vec<String>,
    materialised: bool,
}

impl PointsOutcome {
    fn changed(&self) -> bool {
        self.materialised || !self.copied.is_empty()
    }
}

/// Copy a non-empty `list` onto every point that has no list of its own,
/// flagging each copy `trust_check_migrated`.
fn copy_trust_checks_onto_points(
    points: &mut [serde_json::Value],
    list: &[serde_json::Value],
) -> PointsOutcome {
    let mut outcome = PointsOutcome::default();
    if list.is_empty() {
        return outcome;
    }
    for point in points.iter_mut() {
        if !json_array_at(Some(point), "trust_check_list").is_empty() {
            continue;
        }
        let Some(point_obj) = point.as_object_mut() else {
            continue;
        };
        point_obj.insert("trust_check_list".to_string(), serde_json::Value::Array(list.to_vec()));
        point_obj.insert("trust_check_migrated".to_string(), serde_json::Value::Bool(true));
        outcome.copied.push(
            point_obj
                .get("alias")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
        );
    }
    outcome
}

fn strip_surface_shape_keys(obj: &mut serde_json::Map<String, serde_json::Value>) -> bool {
    let mut mutated = false;
    if let Some(ap) = obj
        .get_mut("access_point")
        .and_then(|v| v.as_object_mut())
    {
        mutated |= ap
            .remove("trust_registry_verification")
            .is_some();
    }
    if let Some(target) = obj
        .get_mut("target")
        .and_then(|v| v.as_object_mut())
    {
        mutated |= target
            .remove("trust_registry_injection")
            .is_some();
        mutated |= target
            .remove("trust_registry_injection_inbound")
            .is_some();
    }
    if let Some(transit) = obj
        .get_mut("transit")
        .and_then(|v| v.as_object_mut())
    {
        mutated |= transit
            .remove("trust_registry_verification")
            .is_some();
    }
    mutated
}

fn strip_overrides_keys(overrides: &mut serde_json::Map<String, serde_json::Value>) -> bool {
    let mut mutated = false;
    if let Some(ap) = overrides
        .get_mut("access_point")
        .and_then(|v| v.as_object_mut())
    {
        mutated |= ap
            .remove("trust_registry_verification")
            .is_some();
    }
    if let Some(target) = overrides
        .get_mut("target")
        .and_then(|v| v.as_object_mut())
    {
        mutated |= target
            .remove("trust_registry_injection")
            .is_some();
        mutated |= target
            .remove("trust_registry_injection_inbound")
            .is_some();
    }
    if let Some(transit) = overrides
        .get_mut("transit")
        .and_then(|v| v.as_object_mut())
        && let Some(shared) = transit
            .get_mut("shared")
            .and_then(|v| v.as_object_mut())
    {
        mutated |= shared
            .remove("trust_registry_verification")
            .is_some();
    }
    mutated
}

// ─── Display ────────────────────────────────────────────────────────────────

impl std::fmt::Display for SurfaceProtocol {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::A2a => write!(f, "a2a"),
            Self::Ap2 => write!(f, "ap2"),
            Self::Mcp => write!(f, "mcp"),
            Self::DIDComm => write!(f, "didcomm"),
        }
    }
}

impl std::fmt::Display for TransitProtocol {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::A2a => write!(f, "a2a"),
            Self::Ap2 => write!(f, "ap2"),
            Self::Mcp => write!(f, "mcp"),
            Self::Http => write!(f, "http"),
        }
    }
}

impl std::fmt::Display for SurfaceStatus {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Disabled => write!(f, "disabled"),
            Self::Deleted => write!(f, "deleted"),
        }
    }
}

// ─── Surface-level validation ───────────────────────────────────────

use crate::trust_registry_verification::trust_check_element::TrustCheckElementValidationError;

/// Maximum number of [`TrustCheckElement`]s allowed per leg
/// (`AccessPoint.trust_check_list`, `Target.trust_check_list` and each
/// `TransitPoint.trust_check_list`).
///
/// Kept in sync with the frontend constant of the same name in
/// `www/default/src/components/surface-builder/elements/trust-check/TrustCheckPanel.tsx`,
/// which caps the dashboard's "add query" button so a user can't build a
/// list the API would 400. Bump both together.
pub const TRUST_CHECK_LIST_MAX: usize = 10;

/// Structured Trust Check list validation errors. Pure data — the API
/// layer is responsible for mapping these into the public HTTP error
/// shape. Scoped to Trust Check invariants today; broader surface-level
/// validation lives in dedicated helpers under `identity/handlers/surfaces.rs`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustCheckValidationError {
    #[error("{leg} trust_check_list has {got} elements (max {max})")]
    TrustCheckListTooLong { leg: &'static str, got: usize, max: usize },
    #[error("{leg} trust_check_list contains duplicate element id '{id}'")]
    TrustCheckDuplicateId { leg: &'static str, id: String },
    #[error("{leg} trust_check_list[{index}] (id '{id}'): {source}")]
    TrustCheckElementInvalid {
        leg: &'static str,
        index: usize,
        id: String,
        #[source]
        source: TrustCheckElementValidationError,
    },
    #[error("target A2A Proxy configuration is invalid: {reason}")]
    TargetA2aProxyInvalid { reason: String },
    #[error("header metadata mapping is invalid: {source}")]
    HeaderMetadataMappingInvalid {
        #[source]
        source: HeaderMetadataMappingValidationError,
    },
    #[error("transit point '{alias}' header metadata mapping is invalid: {source}")]
    TransitPointHeaderMetadataMappingInvalid {
        alias: String,
        #[source]
        source: HeaderMetadataMappingValidationError,
    },
    #[error("variant '{alias}': {source}")]
    VariantInvalid {
        alias: String,
        #[source]
        source: Box<TrustCheckValidationError>,
    },
    #[error("access_point.trust_recorder has {got} entries (max {max})")]
    TrustRecorderTooManyEntries { got: usize, max: usize },
    #[error("transit point '{alias}': {source}")]
    TransitPointTrustCheckInvalid {
        alias: String,
        #[source]
        source: Box<TrustCheckValidationError>,
    },
}

/// Walk a `trust_check_list` slice: enforce the `TRUST_CHECK_LIST_MAX`
/// cap, ensure element ids are unique within the list, and delegate the
/// per-element shape check to [`TrustCheckElement::validate`]. The `leg`
/// label rides into every error variant so the API surface can echo
/// `caller` / `target` back to the operator.
pub fn validate_trust_check_list(
    leg: &'static str,
    list: &[TrustCheckElement],
) -> Result<(), TrustCheckValidationError> {
    if list.len() > TRUST_CHECK_LIST_MAX {
        return Err(TrustCheckValidationError::TrustCheckListTooLong {
            leg,
            got: list.len(),
            max: TRUST_CHECK_LIST_MAX,
        });
    }
    let mut seen = std::collections::HashSet::with_capacity(list.len());
    for (index, elem) in list.iter().enumerate() {
        if !seen.insert(elem.id.as_str()) {
            return Err(TrustCheckValidationError::TrustCheckDuplicateId { leg, id: elem.id.clone() });
        }
        if let Err(source) = elem.validate() {
            return Err(TrustCheckValidationError::TrustCheckElementInvalid {
                leg,
                index,
                id: elem.id.clone(),
                source,
            });
        }
    }
    Ok(())
}

impl AccessPoint {
    /// Validate caller-leg trust_check_list and header metadata mapping invariants.
    pub fn validate(&self) -> Result<(), TrustCheckValidationError> {
        validate_trust_check_list("caller", &self.trust_check_list)?;
        if let Some(mapping) = &self.header_metadata_mapping {
            mapping
                .validate(&self.protocol)
                .map_err(|source| TrustCheckValidationError::HeaderMetadataMappingInvalid { source })?;
        }
        if let Some(cfg) = &self.trust_recorder {
            let got = cfg.entries.len();
            if got > crate::config::types::TRUST_RECORDER_ENTRIES_MAX {
                return Err(TrustCheckValidationError::TrustRecorderTooManyEntries {
                    got,
                    max: crate::config::types::TRUST_RECORDER_ENTRIES_MAX,
                });
            }
        }
        Ok(())
    }

    /// The header-to-metadata mapping, or `None` if configured on a protocol
    /// that doesn't support it (only A2A/AP2 messages have the extension it
    /// injects into). Runtime defense-in-depth alongside
    /// `AgentSurface::validate()` and the load-time remediation in
    /// `crate::surfaces::strip_unsupported_header_metadata_mappings`, in case
    /// an invalid mapping ever reaches a running surface another way.
    pub fn header_metadata_mapping_if_supported(&self) -> Option<&HeaderMetadataMappingConfig> {
        header_metadata_mapping_if_protocol_supports_it(
            self.header_metadata_mapping
                .as_ref(),
            matches!(self.protocol, SurfaceProtocol::A2a | SurfaceProtocol::Ap2),
        )
    }
}

const A2A_PROXY_ENDPOINT_PREFIX: &str = "a2a-proxy://";

/// Whether a Managed Agent target at `endpoint` runs `target.trust_check_list`
/// on its own target leg: only `a2a-proxy://` and `fabric://` targets do.
/// Requests through Transit Points run each Transit Point's own list instead.
pub fn endpoint_runs_target_trust_checks(endpoint: &str) -> bool {
    endpoint.starts_with(A2A_PROXY_ENDPOINT_PREFIX) || endpoint.starts_with("fabric://")
}

impl Target {
    /// Validate target-leg trust_check_list invariants.
    pub fn validate(&self) -> Result<(), TrustCheckValidationError> {
        validate_trust_check_list("target", &self.trust_check_list)
    }

    /// Whether this target runs its own `trust_check_list`; see
    /// [`endpoint_runs_target_trust_checks`].
    pub fn runs_own_trust_checks(&self) -> bool {
        endpoint_runs_target_trust_checks(&self.endpoint)
    }

    pub fn validate_a2a_proxy_reference(
        &self,
        protocol: &SurfaceProtocol,
    ) -> Result<(), TrustCheckValidationError> {
        let endpoint_proxy_id = if let Some(proxy_id) = self
            .endpoint
            .strip_prefix(A2A_PROXY_ENDPOINT_PREFIX)
        {
            if proxy_id.is_empty() {
                return Err(TrustCheckValidationError::TargetA2aProxyInvalid {
                    reason: "target.endpoint A2A Proxy id must not be empty".to_string(),
                });
            }
            if proxy_id.trim() != proxy_id {
                return Err(TrustCheckValidationError::TargetA2aProxyInvalid {
                    reason: "target.endpoint A2A Proxy id must not include surrounding whitespace".to_string(),
                });
            }
            Some(proxy_id)
        } else {
            None
        };

        if endpoint_proxy_id.is_some() && !matches!(protocol, SurfaceProtocol::A2a | SurfaceProtocol::Ap2) {
            return Err(TrustCheckValidationError::TargetA2aProxyInvalid {
                reason: "a2a-proxy:// targets are only valid for A2A/AP2 surfaces".to_string(),
            });
        }

        if self.a2a_proxy_id.is_some() && endpoint_proxy_id.is_none() {
            return Err(TrustCheckValidationError::TargetA2aProxyInvalid {
                reason: "a2a_proxy_id requires target.endpoint to use a2a-proxy://{id}".to_string(),
            });
        }

        if let (Some(endpoint_id), Some(field_id)) = (endpoint_proxy_id, self.a2a_proxy_id.as_deref())
            && endpoint_id != field_id
        {
            return Err(TrustCheckValidationError::TargetA2aProxyInvalid {
                reason: "target.endpoint A2A Proxy id must match target.a2a_proxy_id".to_string(),
            });
        }

        Ok(())
    }
}

impl AgentSurface {
    /// Run every structured validation seam the surface exposes today:
    /// caller-leg, target-leg and per-Transit-Point trust_check_list on the
    /// base surface, then the same checks on each variant after merging
    /// its overrides. Outbound (transit) validation still runs through
    /// the legacy `validate_outbound` string path on the API layer.
    pub fn validate(&self) -> Result<(), TrustCheckValidationError> {
        self.access_point.validate()?;
        self.target.validate()?;
        self.target
            .validate_a2a_proxy_reference(&self.access_point.protocol)?;
        self.validate_transit_header_metadata_mappings()?;
        self.validate_transit_trust_checks()?;
        for variant in &self.variants {
            let resolved = match self.resolve_variant(Some(&variant.alias)) {
                Ok(r) => r,
                // Variant-catalog shape errors are surfaced by
                // `validate_variants` on a separate seam, so a variant
                // that cannot be resolved here is skipped \u2014 we are
                // strictly validating the trust_check_list shape.
                Err(_) => continue,
            };
            if let Err(source) = resolved
                .access_point
                .validate()
            {
                return Err(TrustCheckValidationError::VariantInvalid {
                    alias: variant.alias.clone(),
                    source: Box::new(source),
                });
            }
            if let Err(source) = resolved.target.validate() {
                return Err(TrustCheckValidationError::VariantInvalid {
                    alias: variant.alias.clone(),
                    source: Box::new(source),
                });
            }
            if let Err(source) = resolved
                .target
                .validate_a2a_proxy_reference(&resolved.access_point.protocol)
            {
                return Err(TrustCheckValidationError::VariantInvalid {
                    alias: variant.alias.clone(),
                    source: Box::new(source),
                });
            }
            if let Err(source) = resolved.validate_transit_header_metadata_mappings() {
                return Err(TrustCheckValidationError::VariantInvalid {
                    alias: variant.alias.clone(),
                    source: Box::new(source),
                });
            }
            if let Err(source) = resolved.validate_transit_trust_checks() {
                return Err(TrustCheckValidationError::VariantInvalid {
                    alias: variant.alias.clone(),
                    source: Box::new(source),
                });
            }
        }
        Ok(())
    }

    /// True for the Access Point protocols that carry `access_point.a2a`: A2A and AP2.
    pub fn uses_a2a_settings(&self) -> bool {
        matches!(self.access_point.protocol, SurfaceProtocol::A2a | SurfaceProtocol::Ap2)
    }

    /// Whether the base Target or any variant's Target override carries a
    /// non-empty `trust_check_list`.
    pub fn has_target_trust_checks(&self) -> bool {
        !self
            .target
            .trust_check_list
            .is_empty()
            || self
                .variants
                .iter()
                .any(|variant| {
                    variant
                        .overrides
                        .target
                        .as_ref()
                        .and_then(|target| {
                            target
                                .trust_check_list
                                .as_ref()
                        })
                        .is_some_and(|list| !list.is_empty())
                })
    }

    /// Whether any Transit Point, on the base or in a variant override,
    /// carries a non-empty `trust_check_list`.
    pub fn has_transit_point_trust_checks(&self) -> bool {
        let any_point_list = |points: &[TransitPoint]| {
            points.iter().any(|point| {
                !point
                    .trust_check_list
                    .is_empty()
            })
        };
        self.transit
            .as_ref()
            .is_some_and(|transit| any_point_list(&transit.points))
            || self
                .variants
                .iter()
                .any(|variant| {
                    variant
                        .overrides
                        .transit
                        .as_ref()
                        .and_then(|transit| transit.points.as_deref())
                        .is_some_and(any_point_list)
                })
    }

    /// Whether the surface carries any Trust Check list, target or Transit
    /// Point. Such a surface is stored with `trust_check_split: true`, so a
    /// release that predates per-Transit-Point lists refuses to load it
    /// instead of loading it with no checks.
    pub fn has_trust_check_lists(&self) -> bool {
        self.has_target_trust_checks() || self.has_transit_point_trust_checks()
    }

    /// Whether any Transit Point, on the base or in a variant override,
    /// authenticates its callers with its own `source_auth`. Such a surface is
    /// stored with `transit_point_source_auth: true`.
    pub fn has_transit_point_source_auth(&self) -> bool {
        let any_source_auth = |points: &[TransitPoint]| {
            points
                .iter()
                .any(|point| point.source_auth.is_some())
        };
        self.transit
            .as_ref()
            .is_some_and(|transit| any_source_auth(&transit.points))
            || self
                .variants
                .iter()
                .any(|variant| {
                    variant
                        .overrides
                        .transit
                        .as_ref()
                        .and_then(|transit| transit.points.as_deref())
                        .is_some_and(any_source_auth)
                })
    }

    /// True when the Target is an A2A proxy (`a2a-proxy://`).
    pub fn is_a2a_proxy_target(&self) -> bool {
        self.target
            .endpoint
            .starts_with(A2A_PROXY_ENDPOINT_PREFIX)
    }

    /// The A2A settings requests on this surface are served with: the stored
    /// `access_point.a2a`, or its defaults when absent. An `a2a-proxy://` target
    /// takes the stored versions but always checks the JSON-RPC envelope only.
    ///
    /// Call it on the variant-resolved surface, so a variant that points at an
    /// A2A proxy is served as one.
    pub fn a2a_settings(&self) -> EffectiveA2aSettings {
        let defaults;
        let settings = match &self.access_point.a2a {
            Some(settings) => settings,
            None => {
                defaults = A2aAccessPointSettings::default();
                &defaults
            }
        };
        EffectiveA2aSettings {
            accepted_versions: crate::a2a::version::accepted_set(&settings.accepted_versions),
            validation: if self.is_a2a_proxy_target() {
                A2aValidation::Envelope
            } else {
                settings.validation
            },
        }
    }

    /// Whether `access_point.a2a.validation` applies to any request on this
    /// surface: its own Target is not an A2A proxy, or a variant, enabled or
    /// not, points the Target at one that is not. A2A-proxy Targets always
    /// check the envelope only.
    pub fn a2a_validation_applies(&self) -> bool {
        !self.is_a2a_proxy_target()
            || self
                .variants
                .iter()
                .any(|variant| {
                    !self
                        .variant_target(variant)
                        .endpoint
                        .starts_with(A2A_PROXY_ENDPOINT_PREFIX)
                })
    }

    /// The longest a transit token for this surface may live, in seconds: its
    /// `transit.transit_token_lifetime_secs`, or the default when it sets none,
    /// held to [`MIN_TRANSIT_TOKEN_LIFETIME_SECS`] to
    /// [`MAX_TRANSIT_TOKEN_LIFETIME_SECS`]. A Transit Point refuses a token that
    /// lives longer. It depends on the surface alone, never on an instance's
    /// `gateway.json`, so every instance accepts the tokens any other issued.
    pub fn transit_token_lifetime_secs(&self) -> u64 {
        self.transit
            .as_ref()
            .and_then(|transit| {
                transit
                    .shared
                    .transit_token_lifetime_secs
            })
            .unwrap_or(DEFAULT_TRANSIT_TOKEN_LIFETIME_SECS)
            .clamp(MIN_TRANSIT_TOKEN_LIFETIME_SECS, MAX_TRANSIT_TOKEN_LIFETIME_SECS)
    }

    /// How long the transit tokens the Access Point issues for this surface
    /// live, in seconds: [`Self::transit_token_lifetime_secs`], held to
    /// `max_secs`, the appliance's `transit_token_max_lifetime_secs`.
    pub fn issued_transit_token_lifetime_secs(
        &self,
        max_secs: u64,
    ) -> u64 {
        self.transit_token_lifetime_secs()
            .min(max_secs)
            .max(MIN_TRANSIT_TOKEN_LIFETIME_SECS)
    }

    /// What an operator is told when this surface's stored transit token
    /// lifetime is outside the bounds and its tokens are issued for another:
    /// below [`MIN_TRANSIT_TOKEN_LIFETIME_SECS`], or above `max_secs`, the
    /// appliance's `transit_token_max_lifetime_secs`.
    pub fn transit_token_lifetime_adjustment(
        &self,
        max_secs: u64,
    ) -> Option<String> {
        let secs = self
            .transit
            .as_ref()?
            .shared
            .transit_token_lifetime_secs?;
        let reason = if secs < MIN_TRANSIT_TOKEN_LIFETIME_SECS {
            format!("below the shortest, {MIN_TRANSIT_TOKEN_LIFETIME_SECS} seconds")
        } else if secs > max_secs {
            format!("above transit_token_max_lifetime_secs in gateway.json ({max_secs})")
        } else {
            return None;
        };
        Some(format!(
            "Surface '{}' ({}): transit.transit_token_lifetime_secs is {secs}, {reason}; its transit tokens live \
             {} seconds",
            self.name,
            self.surface_id,
            self.issued_transit_token_lifetime_secs(max_secs)
        ))
    }

    /// Validate `access_point.a2a`: it belongs to A2A and AP2 Access Points only,
    /// and must name supported versions. On a surface where its validation level
    /// applies to no request (its Target is an A2A proxy and so is every
    /// variant's), the level must be `envelope` rather than look applied and not be.
    ///
    /// The block and the protocol are surface-level, so variants are not
    /// checked separately. Every Target takes the block's versions; a variant
    /// that points the Target at a URL also takes its validation level.
    pub fn validate_a2a_settings(&self) -> Result<(), String> {
        let Some(settings) = &self.access_point.a2a else {
            return Ok(());
        };
        if !self.uses_a2a_settings() {
            return Err("access_point.a2a requires an A2A or AP2 Access Point".to_string());
        }
        settings.validate()?;
        if !self.a2a_validation_applies() && settings.validation != A2aValidation::Envelope {
            return Err("an A2A proxy target always checks the JSON-RPC envelope only, and no variant points \
                        the Target at a URL that another validation level could apply to: set \
                        access_point.a2a.validation to \"envelope\""
                .to_string());
        }
        Ok(())
    }

    /// A protected resource is advertised only for an MCP Access Point whose
    /// enforced caller authentication method reads JWT Bearer tokens from the
    /// `Authorization` header, where RFC 9728 clients send them, and keeps
    /// them from the Target: MCP forbids passing a client's token through.
    pub fn validate_protected_resource(&self) -> Result<(), String> {
        let Some(protected) = self.protected_resource() else {
            return Ok(());
        };
        if !crate::protocols::protected_resource::supports_protected_resource(&self.access_point.protocol) {
            return Err("requires an MCP Access Point".into());
        }
        protected.validate()?;
        match self.source_auth() {
            Some(SourceAuthConfig::JwtBearer(jwt))
                if jwt
                    .token_header
                    .eq_ignore_ascii_case("authorization")
                    && jwt.token_scheme == "Bearer" =>
            {
                if jwt.forward_header {
                    return Err("cannot be combined with forward_header: the caller's token must not reach the \
                                Target"
                        .into());
                }
                if !jwt.audiences.is_empty() {
                    return Err("requires empty JWT Bearer audiences: tokens must name the protected resource of \
                                the route they call as their audience"
                        .into());
                }
                Ok(())
            }
            _ => Err("requires a first caller authentication method of JWT Bearer reading the Authorization \
                      header with the Bearer scheme"
                .into()),
        }
    }

    pub fn validate_mcp_metadata(&self) -> Result<(), String> {
        self.validate_mcp_metadata_base()?;
        for variant in &self.variants {
            if let Ok(resolved) = self.resolve_variant(Some(&variant.alias)) {
                resolved
                    .validate_mcp_metadata_base()
                    .map_err(|error| format!("variant '{}': {error}", variant.alias))?;
                // `/$alias` reaches the Access Point at `/` itself, so the
                // variant has no path of its own for a resource to name.
                if resolved.access_point.route == "/"
                    && resolved
                        .protected_resource()
                        .is_some()
                {
                    return Err(format!(
                        "variant '{}': access_point.caller_authentication.protected_resource: a variant of an \
                         Access Point at / is not reachable at a resource of its own; move the Access Point off \
                         / or disable the variant",
                        variant.alias
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn validate_mcp_metadata_base(&self) -> Result<(), String> {
        let context = crate::mcp::meta::McpMetadataContext::legacy(self.mcp_legacy_metadata_output);
        let is_mcp = self.access_point.protocol == SurfaceProtocol::Mcp;
        self.validate_protected_resource()
            .map_err(|error| format!("access_point.caller_authentication.protected_resource: {error}"))?;
        if let Some(config) = &self.mcp_http {
            if !is_mcp {
                return Err("mcp_http requires an MCP Access Point".to_string());
            }
            config.validate()?;
            if config.authorization.is_some() && self.source_auth().is_some() {
                return Err("MCP resource authorization cannot be combined with legacy source_auth".into());
            }
        }
        if let Some(transit) = &self.transit {
            for point in &transit.points {
                if let Some(config) = &point.mcp_http {
                    if point.protocol != TransitProtocol::Mcp {
                        return Err(format!("Transit Point '{}': mcp_http requires MCP", point.alias));
                    }
                    config
                        .validate()
                        .map_err(|error| format!("Transit Point '{}': {error}", point.alias))?;
                }
            }
        }
        if is_mcp {
            for (path, custom) in [
                (
                    "target.custom_metadata",
                    self.target
                        .custom_metadata
                        .as_ref(),
                ),
                (
                    "target.response_custom_metadata",
                    self.target
                        .response_custom_metadata
                        .as_ref(),
                ),
                (
                    "access_point.response_custom_metadata",
                    self.access_point
                        .response_custom_metadata
                        .as_ref(),
                ),
            ] {
                if let Some(custom) = custom {
                    crate::mcp::meta::validate_custom_metadata(custom, context)
                        .map_err(|error| format!("{path}: {error}"))?;
                }
            }
            for identity in [self.inbound_identity(), self.protected_identity(), self.external_identity()]
                .into_iter()
                .flatten()
            {
                if let crate::source_auth::ManagedIdentityConfig::PayloadExtraction(config) = identity {
                    crate::mcp::meta::validate_raw_identity_key(&config.meta_field, context)
                        .map_err(|error| error.to_string())?;
                }
            }
        }
        let has_mcp_transit = self
            .transit
            .as_ref()
            .is_some_and(|transit| {
                transit
                    .points
                    .iter()
                    .any(|point| point.protocol == TransitProtocol::Mcp)
            });
        if has_mcp_transit && let Some(transit) = &self.transit {
            if let Some(custom) = &transit.shared.custom_metadata {
                crate::mcp::meta::validate_custom_metadata(custom, context)
                    .map_err(|error| format!("transit.custom_metadata: {error}"))?;
            }
            for point in transit
                .points
                .iter()
                .filter(|point| point.protocol == TransitProtocol::Mcp)
            {
                if let Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(config)) =
                    &point.managed_identity
                {
                    crate::mcp::meta::validate_raw_identity_key(&config.meta_field, context)
                        .map_err(|error| error.to_string())?;
                }
            }
        }
        if is_mcp || has_mcp_transit {
            for binding in &self.outbound_credentials {
                if let super::types::CredentialInjection::Meta { field } = &binding.inject_as {
                    crate::mcp::meta::validate_operator_key(field, context).map_err(|error| error.to_string())?;
                }
            }
        }
        Ok(())
    }

    fn validate_transit_header_metadata_mappings(&self) -> Result<(), TrustCheckValidationError> {
        let Some(transit) = &self.transit else {
            return Ok(());
        };
        for tp in &transit.points {
            let Some(mapping) = &tp.header_metadata_mapping else {
                continue;
            };
            mapping
                .validate_transit(&tp.protocol)
                .map_err(|source| TrustCheckValidationError::TransitPointHeaderMetadataMappingInvalid {
                    alias: tp.alias.clone(),
                    source,
                })?;
        }
        Ok(())
    }

    fn validate_transit_trust_checks(&self) -> Result<(), TrustCheckValidationError> {
        let Some(transit) = &self.transit else {
            return Ok(());
        };
        for tp in &transit.points {
            if tp.trust_check_list.is_empty() {
                continue;
            }
            validate_trust_check_list("target", &tp.trust_check_list).map_err(|source| {
                TrustCheckValidationError::TransitPointTrustCheckInvalid {
                    alias: tp.alias.clone(),
                    source: Box::new(source),
                }
            })?;
        }
        Ok(())
    }

    /// Clear `header_metadata_mapping` on the Access Point, base Transit
    /// Points, and any variant override that targets a protocol other than
    /// A2A/AP2. Returns one human-readable reason per field cleared (empty
    /// if nothing was invalid) for the caller to log before persisting.
    ///
    /// Load-time counterpart to `AgentSurface::validate()`'s save-time
    /// rejection of the same combination: a hand-edited or restored surface
    /// file can still reach storage with an unsupported mapping, and
    /// `strip_mapped_headers` would then silently drop caller headers with
    /// nothing re-injecting the data. Clearing just the mapping (not the
    /// whole surface, unlike the duplicate-route remediation in
    /// `main.rs::disable_duplicate_route_surfaces`) keeps an
    /// otherwise-working MCP/DIDComm surface online.
    ///
    /// Access Point protocol is fixed for the whole surface (variants cannot
    /// override it), so a variant's Access Point override mapping is only
    /// ever invalid when the base protocol itself is invalid. Transit Point
    /// protocol can vary per variant (`TransitOverrides::points` wholesale-
    /// replaces the transit point catalog), so each variant's transit points
    /// are checked against their own protocol.
    pub fn clear_unsupported_header_metadata_mappings(&mut self) -> Vec<String> {
        let mut cleared = Vec::new();

        let ap_protocol = self
            .access_point
            .protocol
            .clone();
        let ap_protocol_supported = matches!(ap_protocol, SurfaceProtocol::A2a | SurfaceProtocol::Ap2);
        if !ap_protocol_supported
            && self
                .access_point
                .header_metadata_mapping
                .take()
                .is_some()
        {
            cleared.push(format!("access_point (protocol {ap_protocol})"));
        }

        if let Some(transit) = self.transit.as_mut() {
            for tp in transit.points.iter_mut() {
                if !matches!(tp.protocol, TransitProtocol::A2a | TransitProtocol::Ap2)
                    && tp
                        .header_metadata_mapping
                        .take()
                        .is_some()
                {
                    cleared.push(format!("transit point '{}' (protocol {})", tp.alias, tp.protocol));
                }
            }
        }

        for variant in self.variants.iter_mut() {
            if !ap_protocol_supported
                && let Some(ap_override) = variant
                    .overrides
                    .access_point
                    .as_mut()
                && ap_override
                    .header_metadata_mapping
                    .take()
                    .is_some()
            {
                cleared.push(format!("variant '{}' access_point override (protocol {ap_protocol})", variant.alias));
            }
            if let Some(points) = variant
                .overrides
                .transit
                .as_mut()
                .and_then(|t| t.points.as_mut())
            {
                for tp in points.iter_mut() {
                    if !matches!(tp.protocol, TransitProtocol::A2a | TransitProtocol::Ap2)
                        && tp
                            .header_metadata_mapping
                            .take()
                            .is_some()
                    {
                        cleared.push(format!(
                            "variant '{}' transit point '{}' (protocol {})",
                            variant.alias, tp.alias, tp.protocol
                        ));
                    }
                }
            }
        }

        cleared
    }
}

/// Structured validation errors for Transit Point-scoped Workload Binding.
/// Pure data — the API layer maps these into the public HTTP error shape.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkloadBindingSurfaceError {
    /// A Transit Point's `caller_context_fields` allowlist is malformed.
    #[error("transit point '{alias}': {source}")]
    ConfigInvalid {
        alias: String,
        #[source]
        source: crate::config::types::WorkloadBindingValidationError,
    },
    /// Workload Binding is enabled on a Transit Point that has no managed
    /// identity source to sign the VP with.
    #[error(
        "transit point '{alias}': Workload Binding is enabled but the surface has no managed identity source to sign the VP"
    )]
    MissingManagedIdentity { alias: String },
    /// The primary target's `caller_context_fields` allowlist is malformed.
    #[error("primary target: {source}")]
    TargetConfigInvalid {
        #[source]
        source: crate::config::types::WorkloadBindingValidationError,
    },
    /// Workload Binding is enabled on the primary target (MA→EXT) but the
    /// surface has no managed identity source to sign the VP with.
    #[error(
        "primary target: Workload Binding is enabled but the surface has no managed identity source to sign the VP"
    )]
    TargetMissingManagedIdentity,
    /// A resolved variant produced an invalid Workload Binding configuration.
    #[error("variant '{alias}': {source}")]
    VariantInvalid {
        alias: String,
        #[source]
        source: Box<WorkloadBindingSurfaceError>,
    },
}

impl AgentSurface {
    /// Validate Transit Point-scoped Workload Binding on the base surface and
    /// on every resolved variant: each enabled binding must have a managed
    /// identity source to sign with, and its `caller_context_fields` allowlist
    /// must pass [`WorkloadBindingConfig::validate`].
    pub fn validate_workload_binding(&self) -> Result<(), WorkloadBindingSurfaceError> {
        Self::validate_workload_binding_points(self)?;
        for variant in &self.variants {
            let resolved = match self.resolve_variant(Some(&variant.alias)) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if let Err(source) = Self::validate_workload_binding_points(&resolved) {
                return Err(WorkloadBindingSurfaceError::VariantInvalid {
                    alias: variant.alias.clone(),
                    source: Box::new(source),
                });
            }
        }
        Ok(())
    }

    /// Whether the surface can resolve a managed agent identity capable of
    /// signing a workload-binding VP for `tp`: either the Transit Point carries
    /// its own managed-identity extraction, the surface has any identity slot
    /// configured, or a managed agent DID is already bound.
    fn has_managed_identity_source(
        &self,
        tp: &TransitPoint,
    ) -> bool {
        tp.managed_identity.is_some() || !self.identity_slots.is_empty() || self.agent_did.is_some()
    }

    /// Whether the surface can resolve a managed agent identity capable of
    /// signing a workload-binding VP on the primary MA→EXT request leg: either
    /// any identity slot is configured, or a managed agent DID is already bound.
    fn has_target_managed_identity_source(&self) -> bool {
        !self.identity_slots.is_empty() || self.agent_did.is_some()
    }

    fn validate_workload_binding_points(surface: &AgentSurface) -> Result<(), WorkloadBindingSurfaceError> {
        if let Some(wb) = &surface
            .target
            .workload_binding
        {
            if let Err(source) = wb.validate() {
                return Err(WorkloadBindingSurfaceError::TargetConfigInvalid { source });
            }
            if wb.enabled && !surface.has_target_managed_identity_source() {
                return Err(WorkloadBindingSurfaceError::TargetMissingManagedIdentity);
            }
        }
        let Some(transit) = &surface.transit else {
            return Ok(());
        };
        for tp in &transit.points {
            let Some(wb) = &tp.workload_binding else {
                continue;
            };
            if let Err(source) = wb.validate() {
                return Err(WorkloadBindingSurfaceError::ConfigInvalid {
                    alias: tp.alias.clone(),
                    source,
                });
            }
            if wb.enabled && !surface.has_managed_identity_source(tp) {
                return Err(WorkloadBindingSurfaceError::MissingManagedIdentity { alias: tp.alias.clone() });
            }
        }
        Ok(())
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #[test]
    fn mcp_http_settings_are_independent_and_reject_non_mcp_protocols() {
        let mut stored = serde_json::json!({
            "surface_id": "http-settings", "name": "http-settings",
            "access_point": {"listen_address": "http://localhost:8080", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "http://localhost:8081"},
            "mcp_http": {"allowed_origins": ["https://console.example"], "max_request_bytes": 2048},
            "transit": {"points": [{"id": "point", "alias": "service", "protocol": "mcp", "target_endpoint": "http://localhost:8082"}]}
        });
        let surface: super::AgentSurface = serde_json::from_value(stored.clone()).unwrap();
        assert_eq!(surface.validate_mcp_metadata(), Ok(()));
        assert_eq!(
            surface
                .mcp_http
                .as_ref()
                .unwrap()
                .max_request_bytes
                .get(),
            2048
        );
        assert!(
            surface
                .transit
                .as_ref()
                .unwrap()
                .points[0]
                .mcp_http
                .is_none()
        );
        stored["access_point"]["protocol"] = serde_json::json!("a2a");
        let surface: super::AgentSurface = serde_json::from_value(stored.clone()).unwrap();
        assert!(
            surface
                .validate_mcp_metadata()
                .unwrap_err()
                .contains("Access Point")
        );
        stored["mcp_http"] = serde_json::Value::Null;
        stored["transit"]["points"][0]["mcp_http"] = serde_json::json!({"allowed_origins": ["https://agent.example"]});
        let surface: super::AgentSurface = serde_json::from_value(stored.clone()).unwrap();
        assert_eq!(surface.validate_mcp_metadata(), Ok(()));
        stored["transit"]["points"][0]["protocol"] = serde_json::json!("a2a");
        let surface: super::AgentSurface = serde_json::from_value(stored).unwrap();
        assert!(
            surface
                .validate_mcp_metadata()
                .unwrap_err()
                .contains("Transit Point")
        );
    }

    #[test]
    fn a_protected_resource_needs_an_mcp_access_point_reading_jwt_bearer_tokens() {
        let jwt = serde_json::json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": []});
        let protected = serde_json::json!({
            "resource": "https://gateway.example/mcp", "authorization_servers": ["https://idp.example"], "scopes": ["tools"]
        });
        let mut stored = serde_json::json!({
            "surface_id": "discovery", "name": "discovery",
            "access_point": {"listen_address": "http://localhost:8080", "route": "/mcp", "protocol": "mcp",
                "caller_authentication": {"methods": [jwt], "protected_resource": protected}},
            "target": {"endpoint": "http://localhost:8081"},
            "variants": [{"id": "beta", "alias": "beta", "name": "Beta", "enabled": true, "overrides": {}}]
        });
        let surface: super::AgentSurface = serde_json::from_value(stored.clone()).unwrap();
        assert_eq!(surface.validate_mcp_metadata(), Ok(()));
        assert_eq!(
            surface
                .protected_resource()
                .map(|protected| protected
                    .authorization_servers
                    .clone()),
            Some(vec!["https://idp.example".to_string()])
        );

        let rejected = |stored: &serde_json::Value| {
            let surface: super::AgentSurface = serde_json::from_value(stored.clone()).unwrap();
            surface
                .validate_mcp_metadata()
                .unwrap_err()
        };
        let mut a2a = stored.clone();
        a2a["access_point"]["protocol"] = serde_json::json!("a2a");
        assert!(rejected(&a2a).contains("requires an MCP Access Point"));
        for method in [
            serde_json::json!({"type": "api_key", "extraction": {"source": "http_header", "field": "x-api-key"}, "secret_id": "key"}),
            serde_json::json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": [], "token_header": "x-token"}),
            serde_json::json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": [], "token_scheme": "Token"}),
            // The token is matched with the scheme as written, so another case
            // would refuse the `Bearer` clients send.
            serde_json::json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": [], "token_scheme": "bearer"}),
        ] {
            let mut changed = stored.clone();
            changed["access_point"]["caller_authentication"]["methods"] = serde_json::json!([method]);
            assert!(rejected(&changed).contains("JWT Bearer"), "{method}");
        }
        let mut root = stored.clone();
        root["access_point"]["route"] = serde_json::json!("/");
        root["access_point"]["caller_authentication"]["protected_resource"]["resource"] =
            serde_json::json!("https://gateway.example/");
        assert!(rejected(&root).contains(
            "variant 'beta': access_point.caller_authentication.protected_resource: a variant of an Access Point at /"
        ));
        root["variants"][0]["enabled"] = serde_json::json!(false);
        assert_eq!(
            serde_json::from_value::<super::AgentSurface>(root)
                .unwrap()
                .validate_mcp_metadata(),
            Ok(())
        );
        let mut no_servers = stored.clone();
        no_servers["access_point"]["caller_authentication"]["protected_resource"]["authorization_servers"] =
            serde_json::json!([]);
        assert!(rejected(&no_servers).starts_with("access_point.caller_authentication.protected_resource:"));

        stored["variants"][0]["overrides"] = serde_json::json!({"access_point": {"caller_authentication": {
            "methods": [{"type": "api_key", "extraction": {"source": "http_header", "field": "x-api-key"}, "secret_id": "key"}],
            "protected_resource": protected
        }}});
        assert!(rejected(&stored).starts_with("variant 'beta': "));
        let forwarded = serde_json::json!({"methods": [
            {"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": [], "forward_header": true}
        ], "protected_resource": protected});
        let mut forwarding = stored.clone();
        forwarding["variants"] = serde_json::json!([]);
        forwarding["access_point"]["caller_authentication"] = forwarded;
        assert!(rejected(&forwarding).contains("forward_header"));
        let mut audience = forwarding.clone();
        audience["access_point"]["caller_authentication"]["methods"] = serde_json::json!([
            {"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": ["https://gateway.example/mcp"]}
        ]);
        assert!(rejected(&audience).contains("requires empty JWT Bearer audiences"));
        let unknown_field = serde_json::json!({
            "methods": [], "protected_resource": {"resource": "https://gateway.example/mcp", "authorization_servers": [], "issuer": "x"}
        });
        assert!(serde_json::from_value::<super::CallerAuthentication>(unknown_field).is_err());
    }

    #[test]
    fn a_stored_retired_protocol_mode_loads_and_is_dropped_on_save() {
        use serde_json::json;

        let stored = json!({
            "surface_id": "mode", "name": "mode",
            "access_point": {"listen_address": "127.0.0.1:8080", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "http://127.0.0.1:8081"},
            "transit": {"points": [{"id": "transit", "alias": "service", "protocol": "mcp", "target_endpoint": "http://127.0.0.1:8082"}]},
            "variants": [{"id": "variant", "alias": "test", "name": "test", "enabled": true, "overrides": {"complete": true}}]
        });
        let without: super::AgentSurface = serde_json::from_value(stored.clone()).unwrap();
        let expected = serde_json::to_value(&without).unwrap();
        for mode in [json!("legacy"), json!("dual"), json!("modern"), json!(null)] {
            let mut legacy = stored.clone();
            legacy["mcp_protocol_mode"] = mode.clone();
            legacy["transit"]["points"][0]["mcp_protocol_mode"] = mode.clone();
            let surface: super::AgentSurface = serde_json::from_value(legacy).unwrap();
            assert_eq!(surface.validate_mcp_metadata(), Ok(()), "{mode}");
            let saved = serde_json::to_value(&surface).unwrap();
            assert_eq!(saved, expected, "{mode} survived a save");
            assert!(
                saved
                    .get("mcp_protocol_mode")
                    .is_none()
            );
            assert!(
                saved["transit"]["points"][0]
                    .get("mcp_protocol_mode")
                    .is_none()
            );
            assert!(
                serde_json::to_value(
                    surface
                        .resolve_variant(Some("test"))
                        .unwrap()
                )
                .unwrap()
                .get("mcp_protocol_mode")
                .is_none()
            );
        }
        let mut unknown = stored;
        unknown["mcp_protocol_modes"] = json!("dual");
        assert!(serde_json::from_value::<super::AgentSurface>(unknown).is_err());
    }

    #[test]
    fn mcp_metadata_configuration_rejects_reserved_keys_on_resolved_variants() {
        use serde_json::json;
        let mut surface: super::AgentSurface = serde_json::from_value(json!({
            "name": "test", "access_point": {"listen_address": "127.0.0.1:8080", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "http://127.0.0.1:8081"},
            "variants": [{"id": "variant", "alias": "test", "name": "test", "enabled": true, "overrides": {"target": {"custom_metadata": {"enabled": true, "injection_target": "meta", "payload": {"progressToken": "invalid"}}}}}]
        })).unwrap();
        let error = surface
            .validate_mcp_metadata()
            .unwrap_err();
        assert!(error.contains("variant 'test'"));
        assert!(error.contains("progressToken"));
        assert_eq!(surface.validate_mcp_metadata_base(), Ok(()));
        let resolved = surface
            .resolve_variant(Some("test"))
            .unwrap();
        assert!(
            resolved
                .validate_mcp_metadata_base()
                .unwrap_err()
                .contains("progressToken")
        );
        surface.variants.clear();
        assert_eq!(surface.validate_mcp_metadata(), Ok(()));
        surface.outbound_credentials = serde_json::from_value(json!([{"credential_provider_id": "provider", "inject_as": {"type": "meta", "field": "io.affinidi.fabric/agent-identity-binding"}}])).unwrap();
        assert!(
            surface
                .validate_mcp_metadata()
                .unwrap_err()
                .contains("reserved")
        );
    }

    #[test]
    fn mcp_transit_metadata_configuration_rejects_reserved_keys() {
        use serde_json::json;
        let surface = |protocol: &str, transit: serde_json::Value| -> super::AgentSurface {
            let mut transit = transit;
            transit["points"] = json!([{"alias": "partner", "protocol": protocol, "target_endpoint": "http://127.0.0.1:8082",
                "managed_identity": transit["managed_identity"].clone()}]);
            serde_json::from_value(json!({
                "name": "test", "access_point": {"listen_address": "127.0.0.1:8080", "route": "/agent", "protocol": "a2a"},
                "target": {"endpoint": "http://127.0.0.1:8081"},
                "transit": transit
            }))
            .unwrap()
        };
        let custom = json!({"custom_metadata": {"enabled": true, "injection_target": "meta", "payload": {"progressToken": "invalid"}}});
        let identity = json!({"managed_identity": {
            "type": "payload_extraction", "meta_field": "progressToken", "fields": ["id"],
            "json_schema": {"type": "object", "properties": {"id": {"type": "string", "x-identity": true}}, "required": ["id"]}
        }});

        let error = surface("mcp", custom.clone())
            .validate_mcp_metadata()
            .unwrap_err();
        assert!(error.contains("transit.custom_metadata"), "{error}");
        assert!(error.contains("progressToken"), "{error}");
        let error = surface("mcp", identity.clone())
            .validate_mcp_metadata()
            .unwrap_err();
        assert!(error.contains("progressToken"), "{error}");
        // The MCP metadata rules apply only where a Transit Point speaks MCP.
        assert_eq!(surface("a2a", custom).validate_mcp_metadata(), Ok(()));
        assert_eq!(surface("a2a", identity).validate_mcp_metadata(), Ok(()));
    }

    #[test]
    fn mcp_metadata_output_defaults_and_variants_preserve_compatibility() {
        use crate::config::McpLegacyMetadataOutput;
        use serde_json::json;

        let original = json!({
            "surface_id": "metadata-config", "name": "metadata",
            "access_point": {"listen_address": "127.0.0.1:8080", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "http://127.0.0.1:8081"}
        });
        let mut surface: super::AgentSurface = serde_json::from_value(original.clone()).unwrap();
        assert_eq!(surface.mcp_legacy_metadata_output, None);
        assert!(
            serde_json::to_value(&surface)
                .unwrap()
                .get("mcp_legacy_metadata_output")
                .is_none()
        );

        for complete in [false, true] {
            surface.mcp_legacy_metadata_output = Some(McpLegacyMetadataOutput::Canonical);
            surface.variants = serde_json::from_value(json!([{
                "id": "metadata-variant", "alias": "test", "name": "test", "enabled": true,
                "overrides": {"complete": complete}
            }]))
            .unwrap();
            assert_eq!(
                surface
                    .resolve_variant(Some("test"))
                    .unwrap()
                    .mcp_legacy_metadata_output,
                Some(McpLegacyMetadataOutput::Canonical)
            );
        }

        for (value, expected) in [
            ("canonical", McpLegacyMetadataOutput::Canonical),
            ("compatibility", McpLegacyMetadataOutput::Compatibility),
        ] {
            let mut configured = original.clone();
            configured["mcp_legacy_metadata_output"] = json!(value);
            let parsed: super::AgentSurface = serde_json::from_value(configured.clone()).unwrap();
            assert_eq!(parsed.mcp_legacy_metadata_output, Some(expected));
            assert_eq!(serde_json::to_value(parsed).unwrap()["mcp_legacy_metadata_output"], value);
            json_patch::merge(&mut configured, &json!({"mcp_legacy_metadata_output": null}));
            let cleared: super::AgentSurface = serde_json::from_value(configured).unwrap();
            assert_eq!(cleared.mcp_legacy_metadata_output, None);
        }
        let mut invalid = original;
        invalid["mcp_legacy_metadata_output"] = json!("modern");
        assert!(serde_json::from_value::<super::AgentSurface>(invalid).is_err());
    }

    #[tokio::test]
    async fn mcp_metadata_output_survives_storage_reload() {
        use crate::config::McpLegacyMetadataOutput;
        use crate::surfaces::{AgentSurfaceStore, FileSystemAgentSurfaceStore};

        let temporary = tempfile::tempdir().unwrap();
        let path = temporary
            .path()
            .join("surfaces");
        let surface = super::AgentSurface {
            surface_id: "metadata-reload".to_string(),
            name: "metadata".to_string(),
            mcp_legacy_metadata_output: Some(McpLegacyMetadataOutput::Canonical),
            ..Default::default()
        };
        let store = FileSystemAgentSurfaceStore::new(path.clone())
            .await
            .unwrap();
        store
            .save(&surface)
            .await
            .unwrap();
        drop(store);
        let reloaded = FileSystemAgentSurfaceStore::new(path)
            .await
            .unwrap();
        assert_eq!(
            reloaded
                .get(&surface.surface_id)
                .await
                .unwrap()
                .unwrap()
                .mcp_legacy_metadata_output,
            Some(McpLegacyMetadataOutput::Canonical)
        );
    }

    use super::*;

    #[test]
    fn migrate_raw_json_strips_all_legacy_trust_registry_keys() {
        // Base surface + shared transit + a variant that overrides all three legacy blocks.
        let mut json = serde_json::json!({
            "surface_id": "s1",
            "name": "s1",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/api",
                "protocol": "a2a",
                "trust_registry_verification": {"enabled": true, "mode": "source"}
            },
            "target": {
                "endpoint": "http://upstream",
                "trust_registry_injection": {"enabled": true},
                "trust_registry_injection_inbound": {"enabled": true, "provider_did": "did:web:x"}
            },
            "transit": {
                "outbound_listen_address": "0.0.0.0:9443",
                "points": [],
                "trust_registry_verification": {"enabled": true, "mode": "target"}
            },
            "variants": [{
                "id": "v1",
                "alias": "dev",
                "enabled": true,
                "overrides": {
                    "access_point": {"trust_registry_verification": {"enabled": true, "mode": "both"}},
                    "target": {
                        "trust_registry_injection": {"enabled": false},
                        "trust_registry_injection_inbound": {"enabled": true}
                    },
                    "transit": {"shared": {"trust_registry_verification": {"enabled": true, "mode": "target"}}}
                }
            }]
        });

        let mutated =
            AgentSurface::migrate_raw_json(&mut json).expect("migration should not error on well-formed JSON");
        assert!(mutated, "migration must report `true` when it strips keys");

        // Base
        assert!(
            json.get("access_point")
                .and_then(|ap| ap.get("trust_registry_verification"))
                .is_none()
        );
        assert!(
            json.get("target")
                .and_then(|t| t.get("trust_registry_injection"))
                .is_none()
        );
        assert!(
            json.get("target")
                .and_then(|t| t.get("trust_registry_injection_inbound"))
                .is_none()
        );
        assert!(
            json.get("transit")
                .and_then(|t| t.get("trust_registry_verification"))
                .is_none()
        );

        // Variant overrides
        let variant_overrides = json["variants"][0]["overrides"]
            .as_object()
            .expect("overrides");
        assert!(
            variant_overrides["access_point"]
                .as_object()
                .and_then(|ap| ap.get("trust_registry_verification"))
                .is_none()
        );
        assert!(
            variant_overrides["target"]
                .as_object()
                .and_then(|t| t.get("trust_registry_injection"))
                .is_none()
        );
        assert!(
            variant_overrides["target"]
                .as_object()
                .and_then(|t| t.get("trust_registry_injection_inbound"))
                .is_none()
        );
        assert!(
            variant_overrides["transit"]["shared"]
                .as_object()
                .and_then(|s| s.get("trust_registry_verification"))
                .is_none()
        );
    }

    #[test]
    fn migrate_raw_json_returns_false_when_no_legacy_keys() {
        let mut json = serde_json::json!({
            "surface_id": "s1",
            "name": "s1",
            "access_point": {"listen_address": "0.0.0.0:8443", "route": "/api", "protocol": "a2a"},
            "target": {"endpoint": "http://upstream"}
        });
        let mutated = AgentSurface::migrate_raw_json(&mut json).expect("migration");
        assert!(!mutated, "migration must be a no-op when no legacy keys are present");
    }

    #[test]
    fn migrate_raw_json_leaves_surface_deserializable() {
        let mut json = serde_json::json!({
            "surface_id": "s1",
            "name": "s1",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/api",
                "protocol": "a2a",
                "trust_registry_verification": {"enabled": true, "mode": "source"}
            },
            "target": {
                "endpoint": "http://upstream",
                "trust_registry_injection": {"enabled": true}
            }
        });
        AgentSurface::migrate_raw_json(&mut json).expect("migration");
        // Post-migration, deserialization must succeed with deny_unknown_fields.
        let _: AgentSurface = serde_json::from_value(json).expect("post-migration surface must deserialize");
    }

    fn legacy_point(
        alias: &str,
        protocol: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "id": format!("tp-{alias}"),
            "alias": alias,
            "target_endpoint": format!("https://{alias}.example/a2a"),
            "protocol": protocol
        })
    }

    fn legacy_surface(
        endpoint: &str,
        trust_check_list: serde_json::Value,
        points: serde_json::Value,
    ) -> serde_json::Value {
        serde_json::json!({
            "surface_id": "legacy-1",
            "name": "legacy",
            "access_point": {"listen_address": "0.0.0.0:8443", "route": "/agents/legacy", "protocol": "a2a"},
            "target": {"endpoint": endpoint, "trust_check_list": trust_check_list},
            "transit": {"points": points}
        })
    }

    fn migrated_point(
        alias: &str,
        protocol: &str,
        list: &serde_json::Value,
    ) -> serde_json::Value {
        let mut point = legacy_point(alias, protocol);
        point["trust_check_list"] = list.clone();
        point["trust_check_migrated"] = serde_json::json!(true);
        point
    }

    fn migrate(json: &mut serde_json::Value) -> bool {
        AgentSurface::migrate_raw_json(json).expect("migration")
    }

    #[test]
    fn migrate_raw_json_copies_target_trust_checks_onto_transit_points_for_http_target() {
        let list = serde_json::json!([transit_trust_check("a"), transit_trust_check("b")]);
        let mut json = legacy_surface(
            "https://managed.example/a2a",
            list.clone(),
            serde_json::json!([legacy_point("tp1", "a2a"), legacy_point("tp2", "ap2")]),
        );

        assert!(migrate(&mut json));

        assert_eq!(
            json["transit"]["points"],
            serde_json::json!([migrated_point("tp1", "a2a", &list), migrated_point("tp2", "ap2", &list)])
        );
        assert_eq!(json["target"], serde_json::json!({"endpoint": "https://managed.example/a2a"}));
        assert_eq!(json["trust_check_split"], serde_json::json!(true), "a Transit Point list remains");
    }

    #[test]
    fn migrate_raw_json_treats_transit_point_without_protocol_as_a2a() {
        let list = serde_json::json!([transit_trust_check("a")]);
        let mut point = legacy_point("tp1", "a2a");
        point
            .as_object_mut()
            .expect("point")
            .remove("protocol");
        let mut json = legacy_surface("http://managed.example", list.clone(), serde_json::json!([point]));

        assert!(migrate(&mut json));

        assert_eq!(json["transit"]["points"][0]["trust_check_list"], list);
        assert_eq!(json["transit"]["points"][0]["trust_check_migrated"], serde_json::json!(true));
        assert!(
            json["target"]
                .get("trust_check_list")
                .is_none()
        );
    }

    #[test]
    fn migrate_raw_json_keeps_target_list_for_fabric_and_a2a_proxy_targets() {
        for endpoint in ["fabric://gw-b/surface-x", "a2a-proxy://worker"] {
            let list = serde_json::json!([transit_trust_check("a")]);
            let mut json = legacy_surface(
                endpoint,
                list.clone(),
                serde_json::json!([legacy_point("tp1", "a2a"), legacy_point("tp2", "a2a")]),
            );

            assert!(migrate(&mut json));

            assert_eq!(
                json["transit"]["points"],
                serde_json::json!([migrated_point("tp1", "a2a", &list), migrated_point("tp2", "a2a", &list)])
            );
            assert_eq!(json["target"]["trust_check_list"], list, "{endpoint} keeps its own target leg");
            assert_eq!(json["trust_check_split"], serde_json::json!(true));
        }
    }

    #[test]
    fn only_a2a_proxy_and_fabric_targets_run_their_own_trust_checks() {
        for endpoint in ["a2a-proxy://worker", "fabric://gw-b/surface-x"] {
            assert!(endpoint_runs_target_trust_checks(endpoint), "{endpoint}");
        }
        for endpoint in
            ["https://managed.example", "http://managed.example", "proxy://mcp-proxy-1", "", "$TARGET_ENDPOINT"]
        {
            assert!(!endpoint_runs_target_trust_checks(endpoint), "{endpoint}");
        }
        let target = Target {
            endpoint: "fabric://gw-b/surface-x".to_string(),
            ..serde_json::from_value(serde_json::json!({"endpoint": ""})).expect("target")
        };
        assert!(target.runs_own_trust_checks());
    }

    #[test]
    fn migrate_raw_json_clears_proxy_and_empty_target_lists_and_still_copies() {
        for endpoint in ["proxy://mcp-proxy-1", ""] {
            let list = serde_json::json!([transit_trust_check("a")]);
            let mut json = legacy_surface(
                endpoint,
                list.clone(),
                serde_json::json!([legacy_point("tp1", "a2a"), legacy_point("tp2", "ap2")]),
            );

            assert!(migrate(&mut json));

            assert_eq!(
                json["transit"]["points"],
                serde_json::json!([migrated_point("tp1", "a2a", &list), migrated_point("tp2", "ap2", &list)])
            );
            assert!(
                json["target"]
                    .get("trust_check_list")
                    .is_none(),
                "{endpoint} does not run the target list"
            );
            assert_eq!(json["trust_check_split"], serde_json::json!(true), "a Transit Point list remains");
        }
    }

    #[test]
    fn migrate_raw_json_copies_onto_mcp_and_http_transit_points_too() {
        let list = serde_json::json!([transit_trust_check("a")]);
        let mut json = legacy_surface(
            "https://managed.example",
            list.clone(),
            serde_json::json!([
                legacy_point("tp-a2a", "a2a"),
                legacy_point("tp-mcp", "mcp"),
                legacy_point("tp-http", "http")
            ]),
        );

        assert!(migrate(&mut json));

        assert_eq!(
            json["transit"]["points"],
            serde_json::json!([
                migrated_point("tp-a2a", "a2a", &list),
                migrated_point("tp-mcp", "mcp", &list),
                migrated_point("tp-http", "http", &list)
            ])
        );
        let surface: AgentSurface = serde_json::from_value(json).expect("migrated surface deserializes");
        assert_eq!(surface.validate(), Ok(()));
        let migrated: Vec<(bool, usize)> = surface
            .transit
            .expect("transit")
            .points
            .iter()
            .map(|tp| (tp.trust_check_migrated, tp.trust_check_list.len()))
            .collect();
        assert_eq!(migrated, vec![(true, 1), (true, 1), (true, 1)]);
    }

    #[test]
    fn migrate_raw_json_does_not_touch_mcp_transit_points_when_no_list_moves() {
        let mut json = legacy_surface(
            "https://managed.example",
            serde_json::json!([]),
            serde_json::json!([legacy_point("tp-mcp", "mcp")]),
        );
        json["variants"] = serde_json::json!([{
            "id": "v1", "alias": "dev", "name": "dev", "enabled": true,
            "overrides": {
                "target": {"endpoint": "fabric://gw-b/surface-x", "trust_check_list": []},
                "transit": {"points": [legacy_point("dev-mcp", "mcp")]}
            }
        }]);
        let before = json.clone();

        assert!(!migrate(&mut json), "nothing to migrate");
        assert_eq!(json, before);
    }

    fn migration_warnings(json: &mut serde_json::Value) -> Vec<(String, String, String)> {
        use crate::observability::trust_check_audit::test_support::{capture, field};
        let surface_id = json["surface_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        capture(|| {
            migrate(json);
        })
        .iter()
        .filter(|event| event.level == "WARN" && field(event, "surface_id") == Some(surface_id.as_str()))
        .map(|event| {
            (
                field(event, "variant")
                    .unwrap_or_default()
                    .to_string(),
                field(event, "transit_points")
                    .unwrap_or_default()
                    .to_string(),
                field(event, "message")
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect()
    }

    #[test]
    fn migrate_raw_json_does_not_warn_when_mcp_and_http_transit_points_receive_copies() {
        let mut json = legacy_surface(
            "https://managed.example",
            serde_json::json!([transit_trust_check("secret-query")]),
            serde_json::json!([legacy_point("tp-mcp", "mcp"), legacy_point("tp-http", "http")]),
        );
        json["surface_id"] = serde_json::json!("legacy-mcp-copies");
        json["variants"] = serde_json::json!([{
            "id": "v1", "alias": "dev", "name": "dev", "enabled": true,
            "overrides": {"transit": {"points": [legacy_point("dev-mcp", "mcp")]}}
        }]);

        assert_eq!(migration_warnings(&mut json), Vec::new());
        assert_eq!(json["transit"]["points"][0]["trust_check_migrated"], serde_json::json!(true));
        assert_eq!(
            json["variants"][0]["overrides"]["transit"]["points"][0]["trust_check_migrated"],
            serde_json::json!(true)
        );
    }

    #[test]
    fn migrate_raw_json_materialises_mcp_base_points_into_a_sparse_variant_with_its_own_list() {
        let base_list = serde_json::json!([transit_trust_check("base")]);
        let variant_list = serde_json::json!([transit_trust_check("variant")]);
        let mut json = legacy_surface(
            "https://managed.example",
            base_list.clone(),
            serde_json::json!([legacy_point("tp-mcp", "mcp")]),
        );
        json["variants"] = serde_json::json!([{
            "id": "v1", "alias": "dev", "name": "dev", "enabled": true,
            "overrides": {"target": {"trust_check_list": variant_list.clone()}}
        }]);

        assert!(migrate(&mut json));

        assert_eq!(json["transit"]["points"], serde_json::json!([migrated_point("tp-mcp", "mcp", &base_list)]));
        assert_eq!(
            json["variants"][0]["overrides"],
            serde_json::json!({"target": {}, "transit": {"points": [migrated_point("tp-mcp", "mcp", &variant_list)]}})
        );
    }

    #[test]
    fn migrate_raw_json_warns_when_a_removed_list_reached_no_transit_point() {
        let mut json = legacy_surface(
            "https://managed.example",
            serde_json::json!([transit_trust_check("a")]),
            serde_json::json!([]),
        );
        json["surface_id"] = serde_json::json!("legacy-lost");
        json["variants"] = serde_json::json!([{
            "id": "v1", "alias": "dev", "name": "dev", "enabled": true,
            "overrides": {
                "target": {"endpoint": "https://dev.example", "trust_check_list": [transit_trust_check("v")]},
                "transit": {"disabled": true}
            }
        }]);

        let warnings = migration_warnings(&mut json);
        let lost: Vec<&str> = warnings
            .iter()
            .filter(|(_, _, message)| message.contains("no Transit Point received a copy"))
            .map(|(variant, _, _)| variant.as_str())
            .collect();

        assert_eq!(lost, vec!["", "dev"]);
    }

    #[test]
    fn migrate_raw_json_does_not_warn_about_a_lost_list_when_a_transit_point_got_it() {
        let mut json = legacy_surface(
            "https://managed.example",
            serde_json::json!([transit_trust_check("a")]),
            serde_json::json!([legacy_point("tp1", "a2a")]),
        );
        json["surface_id"] = serde_json::json!("legacy-kept");

        let warnings = migration_warnings(&mut json);

        assert!(
            warnings
                .iter()
                .all(|(_, _, message)| !message.contains("no Transit Point received a copy")),
            "{warnings:?}"
        );
    }

    #[test]
    fn loading_a_split_surface_warns_about_target_lists_that_never_run() {
        let list = serde_json::json!([transit_trust_check("idle")]);
        let mut json = legacy_surface("https://managed.example", list.clone(), serde_json::json!([]));
        json["surface_id"] = serde_json::json!("split-idle");
        json["trust_check_split"] = serde_json::json!(true);
        json["variants"] = serde_json::json!([
            {"id": "v1", "alias": "dev", "name": "dev", "enabled": true,
             "overrides": {"target": {"endpoint": "https://dev.example", "trust_check_list": list.clone()}}},
            {"id": "v2", "alias": "proxy", "name": "proxy", "enabled": true,
             "overrides": {"target": {"endpoint": "a2a-proxy://worker", "trust_check_list": list.clone()}}}
        ]);
        let before = json.clone();

        let idle: Vec<String> = migration_warnings(&mut json)
            .into_iter()
            .filter(|(_, _, message)| message.contains("never runs"))
            .map(|(variant, _, _)| variant)
            .collect();

        assert_eq!(idle, vec!["".to_string(), "dev".to_string()]);
        assert_eq!(json, before, "a split surface is not converted again");
    }

    #[test]
    fn loading_a_split_surface_whose_target_runs_its_list_does_not_warn() {
        let mut json = legacy_surface(
            "fabric://gw-b/surface-x",
            serde_json::json!([transit_trust_check("runs")]),
            serde_json::json!([]),
        );
        json["surface_id"] = serde_json::json!("split-runs");
        json["trust_check_split"] = serde_json::json!(true);

        assert_eq!(migration_warnings(&mut json), Vec::new());
    }

    #[test]
    fn migrate_raw_json_does_not_warn_when_every_transit_point_is_a2a_or_ap2() {
        let mut json = legacy_surface(
            "https://managed.example",
            serde_json::json!([transit_trust_check("a")]),
            serde_json::json!([legacy_point("tp1", "a2a"), legacy_point("tp2", "ap2")]),
        );
        json["surface_id"] = serde_json::json!("legacy-no-warn");
        json["variants"] = serde_json::json!([{
            "id": "v1", "alias": "dev", "name": "dev", "enabled": true,
            "overrides": {"transit": {"points": [legacy_point("dev-a2a", "a2a")]}}
        }]);

        assert_eq!(migration_warnings(&mut json), Vec::new());
        assert_eq!(json["trust_check_split"], serde_json::json!(true), "a Transit Point list remains");
    }

    #[test]
    fn migrate_raw_json_keeps_a_transit_point_list_that_already_exists() {
        let list = serde_json::json!([transit_trust_check("a")]);
        let own = serde_json::json!([transit_trust_check("own")]);
        let mut existing = legacy_point("tp1", "a2a");
        existing["trust_check_list"] = own.clone();
        let mut json = legacy_surface(
            "https://managed.example",
            list.clone(),
            serde_json::json!([existing.clone(), legacy_point("tp2", "a2a")]),
        );

        assert!(migrate(&mut json));

        assert_eq!(json["transit"]["points"], serde_json::json!([existing, migrated_point("tp2", "a2a", &list)]));
    }

    #[test]
    fn migrate_raw_json_clears_http_target_list_with_or_without_transit_points() {
        let list = serde_json::json!([transit_trust_check("a")]);
        for (points, expected) in [
            (serde_json::json!([]), serde_json::json!([])),
            (
                serde_json::json!([legacy_point("tp-mcp", "mcp")]),
                serde_json::json!([migrated_point("tp-mcp", "mcp", &list)]),
            ),
        ] {
            let mut json = legacy_surface("https://managed.example", list.clone(), points);

            assert!(migrate(&mut json));

            assert_eq!(json["transit"]["points"], expected);
            assert_eq!(json["target"], serde_json::json!({"endpoint": "https://managed.example"}));
            assert_eq!(
                json.get("trust_check_split")
                    .is_some(),
                !expected
                    .as_array()
                    .unwrap()
                    .is_empty(),
                "the marker follows the remaining lists"
            );
        }
    }

    #[test]
    fn migrate_raw_json_only_sets_guard_for_fabric_target_without_transit_points() {
        let list = serde_json::json!([transit_trust_check("a")]);
        let mut json = legacy_surface("fabric://gw-b/surface-x", list, serde_json::json!([]));
        let mut expected = json.clone();
        expected["trust_check_split"] = serde_json::json!(true);

        assert!(migrate(&mut json));

        assert_eq!(json, expected);
    }

    #[test]
    fn migrate_raw_json_leaves_surface_without_target_list_untouched() {
        for list in [serde_json::json!([]), serde_json::Value::Null] {
            let mut json = legacy_surface(
                "https://managed.example",
                serde_json::json!([]),
                serde_json::json!([legacy_point("tp1", "a2a")]),
            );
            if list.is_null() {
                json["target"]
                    .as_object_mut()
                    .expect("target")
                    .remove("trust_check_list");
            }
            let before = json.clone();

            assert!(!migrate(&mut json));

            assert_eq!(json, before);
            assert!(
                json.get("trust_check_split")
                    .is_none()
            );
        }
    }

    #[test]
    fn migrate_raw_json_runs_once() {
        let list = serde_json::json!([transit_trust_check("a")]);
        let mut json = legacy_surface(
            "fabric://gw-b/surface-x",
            list,
            serde_json::json!([legacy_point("tp1", "a2a"), legacy_point("tp2", "a2a")]),
        );
        assert!(migrate(&mut json));
        let migrated = json.clone();

        assert!(!migrate(&mut json));

        assert_eq!(json, migrated);
    }

    #[test]
    fn migrate_raw_json_skips_surface_already_split() {
        let list = serde_json::json!([transit_trust_check("a")]);
        let mut json = legacy_surface("fabric://gw-b/surface-x", list, serde_json::json!([legacy_point("tp1", "a2a")]));
        json["trust_check_split"] = serde_json::json!(true);
        let before = json.clone();

        assert!(!migrate(&mut json));

        assert_eq!(json, before);
    }

    #[test]
    fn migrate_raw_json_applies_variant_target_list_to_its_own_transit_points() {
        let base_list = serde_json::json!([transit_trust_check("base")]);
        let variant_list = serde_json::json!([transit_trust_check("variant")]);
        let mut json = legacy_surface(
            "https://managed.example",
            base_list.clone(),
            serde_json::json!([legacy_point("tp1", "a2a")]),
        );
        json["variants"] = serde_json::json!([{
            "id": "v1", "alias": "dev", "name": "dev", "enabled": true,
            "overrides": {
                "target": {"trust_check_list": variant_list.clone()},
                "transit": {"points": [legacy_point("dev-a2a", "a2a"), legacy_point("dev-mcp", "mcp")]}
            }
        }]);

        assert!(migrate(&mut json));

        assert_eq!(json["transit"]["points"], serde_json::json!([migrated_point("tp1", "a2a", &base_list)]));
        assert_eq!(
            json["variants"][0]["overrides"],
            serde_json::json!({
                "target": {},
                "transit": {"points": [migrated_point("dev-a2a", "a2a", &variant_list), migrated_point("dev-mcp", "mcp", &variant_list)]}
            })
        );
    }

    #[test]
    fn migrate_raw_json_applies_base_list_to_variant_points_without_target_override() {
        let base_list = serde_json::json!([transit_trust_check("base")]);
        let mut json = legacy_surface("https://managed.example", base_list.clone(), serde_json::json!([]));
        json["variants"] = serde_json::json!([{
            "id": "v1", "alias": "dev", "name": "dev", "enabled": true,
            "overrides": {"transit": {"points": [legacy_point("dev-a2a", "a2a")]}}
        }]);

        assert!(migrate(&mut json));

        assert_eq!(
            json["variants"][0]["overrides"],
            serde_json::json!({"transit": {"points": [migrated_point("dev-a2a", "a2a", &base_list)]}})
        );
        assert!(
            json["target"]
                .get("trust_check_list")
                .is_none()
        );
    }

    #[test]
    fn migrate_raw_json_materialises_base_points_into_sparse_variant_with_own_list() {
        let base_list = serde_json::json!([transit_trust_check("base")]);
        let variant_list = serde_json::json!([transit_trust_check("variant")]);
        let mut json = legacy_surface(
            "https://managed.example",
            base_list.clone(),
            serde_json::json!([legacy_point("tp1", "a2a"), legacy_point("tp-mcp", "mcp")]),
        );
        json["variants"] = serde_json::json!([{
            "id": "v1", "alias": "dev", "name": "dev", "enabled": true,
            "overrides": {"target": {"trust_check_list": variant_list.clone()}}
        }]);

        assert!(migrate(&mut json));

        assert_eq!(
            json["transit"]["points"],
            serde_json::json!([migrated_point("tp1", "a2a", &base_list), migrated_point("tp-mcp", "mcp", &base_list)])
        );
        assert_eq!(
            json["variants"][0]["overrides"],
            serde_json::json!({
                "target": {},
                "transit": {"points": [migrated_point("tp1", "a2a", &variant_list), migrated_point("tp-mcp", "mcp", &variant_list)]}
            })
        );
    }

    #[test]
    fn migrate_raw_json_materialises_unflagged_base_points_into_variant_that_cleared_its_list() {
        let base_list = serde_json::json!([transit_trust_check("base")]);
        let mut json =
            legacy_surface("https://managed.example", base_list, serde_json::json!([legacy_point("tp1", "a2a")]));
        json["variants"] = serde_json::json!([
            {
                "id": "v1", "alias": "empty", "name": "empty", "enabled": true,
                "overrides": {"target": {"trust_check_list": []}}
            },
            {
                "id": "v2", "alias": "frozen", "name": "frozen", "enabled": true,
                "overrides": {"complete": true, "target": {"endpoint": "https://frozen.example"}}
            }
        ]);

        assert!(migrate(&mut json));

        assert_eq!(
            json["variants"][0]["overrides"],
            serde_json::json!({
                "target": {"trust_check_list": []},
                "transit": {"points": [legacy_point("tp1", "a2a")]}
            })
        );
        assert_eq!(
            json["variants"][1]["overrides"],
            serde_json::json!({
                "complete": true,
                "target": {"endpoint": "https://frozen.example"},
                "transit": {"points": [legacy_point("tp1", "a2a")]}
            })
        );
    }

    #[test]
    fn migrate_raw_json_leaves_variant_inheriting_base_list_and_points_alone() {
        let base_list = serde_json::json!([transit_trust_check("base")]);
        let mut json =
            legacy_surface("https://managed.example", base_list, serde_json::json!([legacy_point("tp1", "a2a")]));
        let variant = serde_json::json!({
            "id": "v1", "alias": "dev", "name": "dev", "enabled": true,
            "overrides": {"target": {"endpoint": "https://dev.example"}}
        });
        json["variants"] = serde_json::json!([variant.clone()]);

        assert!(migrate(&mut json));

        assert_eq!(json["variants"][0], variant);
    }

    #[test]
    fn migrate_raw_json_does_not_materialise_points_into_variant_with_transit_disabled() {
        let base_list = serde_json::json!([transit_trust_check("base")]);
        let variant_list = serde_json::json!([transit_trust_check("variant")]);
        let mut json =
            legacy_surface("https://managed.example", base_list, serde_json::json!([legacy_point("tp1", "a2a")]));
        json["variants"] = serde_json::json!([{
            "id": "v1", "alias": "dev", "name": "dev", "enabled": true,
            "overrides": {
                "target": {"trust_check_list": variant_list},
                "transit": {"disabled": true}
            }
        }]);

        assert!(migrate(&mut json));

        assert_eq!(json["variants"][0]["overrides"], serde_json::json!({"target": {}, "transit": {"disabled": true}}));
    }

    #[test]
    fn migrate_raw_json_uses_variant_endpoint_to_decide_whether_to_clear() {
        let base_list = serde_json::json!([transit_trust_check("base")]);

        let mut fabric_base = legacy_surface("fabric://gw-b/surface-x", base_list.clone(), serde_json::json!([]));
        fabric_base["variants"] = serde_json::json!([{
            "id": "v1", "alias": "dev", "name": "dev", "enabled": true,
            "overrides": {"target": {"endpoint": "https://dev.example"}}
        }]);
        assert!(migrate(&mut fabric_base));
        assert_eq!(fabric_base["target"]["trust_check_list"], base_list);
        assert_eq!(
            fabric_base["variants"][0]["overrides"]["target"],
            serde_json::json!({"endpoint": "https://dev.example", "trust_check_list": []})
        );

        let mut http_base = legacy_surface("https://managed.example", base_list.clone(), serde_json::json!([]));
        http_base["variants"] = serde_json::json!([{
            "id": "v1", "alias": "mesh", "name": "mesh", "enabled": true,
            "overrides": {"target": {"endpoint": "fabric://gw-b/surface-x"}}
        }]);
        assert!(migrate(&mut http_base));
        assert!(
            http_base["target"]
                .get("trust_check_list")
                .is_none()
        );
        assert_eq!(
            http_base["variants"][0]["overrides"]["target"],
            serde_json::json!({"endpoint": "fabric://gw-b/surface-x", "trust_check_list": base_list})
        );
    }

    #[test]
    fn migrate_raw_json_runs_for_variant_list_when_base_has_none() {
        let variant_list = serde_json::json!([transit_trust_check("variant")]);
        let mut json = legacy_surface(
            "https://managed.example",
            serde_json::json!([]),
            serde_json::json!([legacy_point("tp1", "a2a")]),
        );
        json["variants"] = serde_json::json!([{
            "id": "v1", "alias": "dev", "name": "dev", "enabled": true,
            "overrides": {"target": {"trust_check_list": variant_list.clone()}}
        }]);

        assert!(migrate(&mut json));

        assert_eq!(json["transit"]["points"], serde_json::json!([legacy_point("tp1", "a2a")]));
        assert_eq!(
            json["variants"][0]["overrides"]["transit"]["points"],
            serde_json::json!([migrated_point("tp1", "a2a", &variant_list)])
        );
        assert!(
            json["variants"][0]["overrides"]["target"]
                .get("trust_check_list")
                .is_none()
        );
        assert_eq!(json["trust_check_split"], serde_json::json!(true), "a Transit Point list remains");
    }

    #[test]
    fn migrate_raw_json_output_deserializes_and_validates() {
        let base_list = serde_json::json!([transit_trust_check("base")]);
        let variant_list = serde_json::json!([transit_trust_check("variant")]);
        let mut json = legacy_surface(
            "https://managed.example",
            base_list,
            serde_json::json!([legacy_point("tp1", "a2a"), legacy_point("tp-mcp", "mcp")]),
        );
        json["variants"] = serde_json::json!([
            {
                "id": "v1", "alias": "sparse", "name": "sparse", "enabled": true,
                "overrides": {"target": {"trust_check_list": variant_list}}
            },
            {
                "id": "v2", "alias": "own", "name": "own", "enabled": true,
                "overrides": {"transit": {"points": [legacy_point("own-a2a", "a2a")]}}
            }
        ]);

        assert!(migrate(&mut json));
        let surface: AgentSurface = serde_json::from_value(json).expect("migrated surface must deserialize");

        assert_eq!(surface.validate(), Ok(()));
        assert!(surface.trust_check_split, "Transit Point lists remain");
        assert!(
            surface
                .target
                .trust_check_list
                .is_empty()
        );
        let base_points = &surface
            .transit
            .as_ref()
            .expect("transit")
            .points;
        assert_eq!(base_points[0].trust_check_list[0].id, "base");
        assert!(base_points[0].trust_check_migrated);
        assert_eq!(base_points[1].trust_check_list[0].id, "base", "the MCP Transit Point gets a copy too");
        assert!(base_points[1].trust_check_migrated);
        let sparse = surface
            .resolve_variant(Some("sparse"))
            .expect("sparse variant");
        assert!(
            sparse
                .target
                .trust_check_list
                .is_empty()
        );
        assert_eq!(
            sparse
                .transit
                .as_ref()
                .expect("transit")
                .points[0]
                .trust_check_list[0]
                .id,
            "variant"
        );
        let own = surface
            .resolve_variant(Some("own"))
            .expect("own variant");
        assert_eq!(
            own.transit
                .as_ref()
                .expect("transit")
                .points[0]
                .trust_check_list[0]
                .id,
            "base"
        );
    }

    #[test]
    fn test_minimal_agent_surface_deserializes() {
        let json = r#"{
            "surface_id": "surf-001",
            "name": "calculator",
            "description": "",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/agents/calc",
                "protocol": "mcp"
            },
            "target": {
                "endpoint": "https://calc.internal:4000/mcp"
            }
        }"#;

        let surface: AgentSurface = serde_json::from_str(json).unwrap();
        assert_eq!(surface.surface_id, "surf-001");
        assert_eq!(surface.name, "calculator");
        assert_eq!(surface.access_point.protocol, SurfaceProtocol::Mcp);
        assert_eq!(surface.target.endpoint, "https://calc.internal:4000/mcp");
        assert_eq!(surface.status, SurfaceStatus::Active);
        assert!(surface.transit.is_none());
        // `terminate_trace_id` defaults to false when omitted (egress firewall off).
        assert!(
            !surface
                .access_point
                .terminate_trace_id
        );
    }

    #[test]
    fn surface_protocol_rejects_marketplace_token() {
        let parsed = serde_json::from_str::<SurfaceProtocol>(r#""marketplace""#);
        assert!(parsed.is_err());
    }

    #[test]
    fn terminate_trace_id_round_trips_and_defaults_false() {
        let base = r#"{
            "surface_id": "s",
            "name": "n",
            "description": "",
            "access_point": { "listen_address": "0.0.0.0:8443", "route": "/a", "protocol": "a2a" },
            "target": { "endpoint": "https://x/a2a" }
        }"#;
        let s: AgentSurface = serde_json::from_str(base).unwrap();
        assert!(
            !s.access_point
                .terminate_trace_id,
            "omitted field defaults to false"
        );

        // Explicit true is honoured and survives a serialize → deserialize round trip.
        let mut on = s;
        on.access_point
            .terminate_trace_id = true;
        let json = serde_json::to_string(&on).unwrap();
        let back: AgentSurface = serde_json::from_str(&json).unwrap();
        assert!(
            back.access_point
                .terminate_trace_id,
            "explicit true round-trips"
        );
    }

    #[test]
    fn test_full_agent_surface_deserializes() {
        let json = r#"{
            "surface_id": "surf-002",
            "name": "research-agent",
            "description": "Handles research requests",
            "status": "active",
            "issuer_id": "issuer-research",
            "tags": ["research", "production"],
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/agents/research",
                "protocol": "a2a",
                "caller_context": { "mode": "required" },
                "identity_resolution": {
                    "strategy": "from_payload",
                    "fields": ["agentIdentity.name", "agentIdentity.provider"],
                    "hash_algorithm": "sha256"
                },
                "inbound_policy": { "policy_definition_id": "pol-research-access" },
                "rate_limit": { "requests": 200, "window_secs": 60 }
            },
            "target": {
                "endpoint": "https://research.internal:5000/a2a",
                "auth": {
                    "method": { "static_secret": { "secret_id": "research-token", "header_name": "Authorization", "header_format": "Bearer {value}" } },
                    "fallback": "reject"
                },
                "policy": { "policy_definition_id": "pol-research-methods" },
                "identity_injection": { "inject_vp": true },
                "networking": {
                    "timeout": { "request_secs": 120, "connect_secs": 10, "idle_secs": 60 },
                    "retry": { "max_attempts": 2, "initial_backoff_ms": 500, "max_backoff_ms": 5000, "backoff_multiplier": 2.0, "retryable_status_codes": [502, 503] }
                }
            },
            "transit": {
                "sign_requests": true,
                "transit_token_mode": "embedded",
                "rate_limit": { "requests": 500, "window_secs": 60 },
                "workload_binding": {
                    "agent_fields": ["agentIdentity.name"],
                    "user_fields": [{ "claim": "email", "mask": "email" }]
                },
                "points": [
                    {
                        "name": "arxiv",
                        "target_endpoint": "https://export.arxiv.org/api",
                        "protocol": "http"
                    },
                    {
                        "name": "summarize-gw2",
                        "target_endpoint": "fabric://gw2/summarization-agent",
                        "protocol": "a2a",
                        "payment_policy": {
                            "type": "mpp",
                            "auto_pay": true,
                            "max_amount": "0.50",
                            "currency": "USD"
                        },
                        "identity_injection": { "inject_vp": true }
                    }
                ]
            }
        }"#;

        let surface: AgentSurface = serde_json::from_str(json).unwrap();
        assert_eq!(surface.name, "research-agent");
        assert_eq!(surface.tags, vec!["research", "production"]);
        assert_eq!(
            surface
                .access_point
                .caller_context
                .mode,
            CallerContextMode::Required
        );
        assert!(
            surface
                .target
                .policy
                .is_some()
        );
        assert!(
            surface
                .target
                .identity_injection
                .inject_vp
        );

        let transit = surface
            .transit
            .as_ref()
            .unwrap();
        assert_eq!(transit.points.len(), 2);
        assert_eq!(transit.points[0].name, "arxiv");
        assert_eq!(transit.points[0].protocol, TransitProtocol::Http);
        assert_eq!(transit.points[1].name, "summarize-gw2");
        assert!(
            transit.points[1]
                .payment_policy
                .is_some()
        );
        assert_eq!(
            transit
                .shared
                .transit_token_mode,
            TransitTokenMode::Embedded
        );
    }

    #[test]
    fn access_point_header_metadata_mapping_round_trips_and_validates() {
        let json = serde_json::json!({
            "surface_id": "surf-headers",
            "name": "header surface",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/agents/headers",
                "protocol": "a2a",
                "header_metadata_mapping": {
                    "extension_uri": "https://example.test/extensions/headers/v1",
                    "headers": [
                        { "header": "x-agent-id", "field": "agent_id" },
                        { "header": "x-tenant-id", "field": "tenant_id" }
                    ]
                }
            },
            "target": { "endpoint": "https://headers.internal/a2a" }
        });

        let surface: AgentSurface = serde_json::from_value(json).expect("surface should deserialize");

        surface
            .validate()
            .expect("header metadata mapping should be valid");
        let mapping = surface
            .access_point
            .header_metadata_mapping
            .as_ref()
            .expect("mapping should be present");
        assert!(mapping.strip_mapped_headers);
        assert_eq!(mapping.headers.len(), 2);
        assert_eq!(mapping.headers[0].field, "agent_id");

        let round_trip = serde_json::to_value(&surface).expect("surface should serialize");
        assert_eq!(round_trip["access_point"]["header_metadata_mapping"]["headers"][1]["field"], "tenant_id");
    }

    #[test]
    fn test_base_url_computation() {
        let surface = AgentSurface {
            surface_id: "test".to_string(),
            tenant_id: None,
            name: "test".to_string(),
            description: String::new(),
            status: SurfaceStatus::Active,
            agent_did: None,
            issuer_id: None,
            tags: vec![],
            access_point: AccessPoint {
                name: None,
                listen_address: "0.0.0.0:8443".to_string(),
                route: "/agents/sales".to_string(),
                protocol: SurfaceProtocol::A2a,
                caller_authentication: None,
                caller_context: CallerContext::default(),
                identity_resolution: None,
                inbound_policy: None,
                rate_limit: None,
                extension_validation: None,
                trust_check_list: Vec::new(),
                header_metadata_mapping: None,
                trust_recorder: None,
                publish_to_did_document: false,
                supported_extensions: vec![],
                primary_extension: None,
                agent_card_path: None,
                response_custom_metadata: None,
                didwebvh_identity: None,
                terminate_trace_id: false,
                a2a: None,
            },
            target: Target {
                endpoint: "https://sales.internal:3000/a2a".to_string(),
                auth: None,
                policy: None,
                response_policy: None,
                payment_policy: None,
                mcp_tool_policies: vec![],
                mcp_tool_policies_enabled: false,
                mcp_tool_gating: None,
                networking: None,
                identity_injection: IdentityInjectionConfig::default(),
                workload_binding: None,
                extension_rules: None,
                custom_metadata: None,
                response_custom_metadata: None,
                trust_check_list: Vec::new(),
                mcp_proxy_id: None,
                a2a_proxy_id: None,
                fabric_target_name: None,
                mpp_auto_pay: false,
                mpp_auto_pay_max_amount: None,
                fabric_delegated_credentials: false,
            },
            transit: None,
            canvas: None,
            variants: Vec::new(),
            default_variant_id: None,
            outbound_credentials: Vec::new(),
            identity_slots: Default::default(),
            mcp_legacy_metadata_output: None,
            _retired_protocol_mode: Default::default(),
            mcp_http: None,
            trust_check_split: false,
            transit_point_source_auth: false,
        };

        assert_eq!(surface.base_url("gw.example.com"), "https://gw.example.com:8443/agents/sales");
        assert_eq!(
            surface.transit_url("gw.example.com", "crm"),
            "https://gw.example.com:8443/agents/sales/transit-point/crm"
        );
    }

    #[test]
    fn test_find_transit_point() {
        let surface = AgentSurface {
            surface_id: "test".to_string(),
            tenant_id: None,
            name: "test".to_string(),
            description: String::new(),
            status: SurfaceStatus::Active,
            agent_did: None,
            issuer_id: None,
            tags: vec![],
            access_point: AccessPoint {
                name: None,
                listen_address: "0.0.0.0:8443".to_string(),
                route: "/agents/test".to_string(),
                protocol: SurfaceProtocol::Mcp,
                caller_authentication: None,
                caller_context: CallerContext::default(),
                identity_resolution: None,
                inbound_policy: None,
                rate_limit: None,
                extension_validation: None,
                trust_check_list: Vec::new(),
                header_metadata_mapping: None,
                trust_recorder: None,
                publish_to_did_document: false,
                supported_extensions: vec![],
                primary_extension: None,
                agent_card_path: None,
                response_custom_metadata: None,
                didwebvh_identity: None,
                terminate_trace_id: false,
                a2a: None,
            },
            target: Target {
                endpoint: "https://test.internal/mcp".to_string(),
                auth: None,
                policy: None,
                response_policy: None,
                payment_policy: None,
                mcp_tool_policies: vec![],
                mcp_tool_policies_enabled: false,
                mcp_tool_gating: None,
                networking: None,
                identity_injection: IdentityInjectionConfig::default(),
                workload_binding: None,
                extension_rules: None,
                custom_metadata: None,
                response_custom_metadata: None,
                trust_check_list: Vec::new(),
                mcp_proxy_id: None,
                a2a_proxy_id: None,
                fabric_target_name: None,
                mpp_auto_pay: false,
                mpp_auto_pay_max_amount: None,
                fabric_delegated_credentials: false,
            },
            transit: Some(TransitConfig {
                points: vec![
                    TransitPoint {
                        id: uuid::Uuid::new_v4().to_string(),
                        name: "github-api".to_string(),
                        alias: "github-api".to_string(),
                        target_endpoint: "https://api.github.com".to_string(),
                        protocol: TransitProtocol::Http,
                        mcp_http: None,
                        header_metadata_mapping: None,
                        target_auth: None,
                        policy: None,
                        response_policy: None,
                        mcp_tool_gating: None,
                        payment_policy: None,
                        networking: None,
                        rate_limit: None,
                        identity_injection: IdentityInjectionConfig::default(),
                        managed_identity: None,
                        transit_credentials: None,
                        workload_binding: None,
                        gateway_url: String::new(),
                        agent_card_path: None,
                        listen_address: None,
                        listen_path: None,
                        require_transit_token: true,
                        source_auth: None,
                        allow_unauthenticated_callers: false,
                        extension_inspection: crate::config::types::ExtensionInspectionConfig::default(),
                        fabric_delegated_credentials: false,
                        allow_fabric_callers: false,
                        trust_check_list: Vec::new(),
                        trust_check_migrated: false,
                    },
                    TransitPoint {
                        id: uuid::Uuid::new_v4().to_string(),
                        name: "partner".to_string(),
                        alias: "partner".to_string(),
                        target_endpoint: "fabric://gw2/partner".to_string(),
                        protocol: TransitProtocol::A2a,
                        mcp_http: None,
                        header_metadata_mapping: None,
                        target_auth: None,
                        policy: None,
                        response_policy: None,
                        mcp_tool_gating: None,
                        payment_policy: None,
                        networking: None,
                        rate_limit: None,
                        identity_injection: IdentityInjectionConfig::default(),
                        managed_identity: None,
                        transit_credentials: None,
                        workload_binding: None,
                        gateway_url: String::new(),
                        agent_card_path: None,
                        listen_address: None,
                        listen_path: None,
                        require_transit_token: true,
                        source_auth: None,
                        allow_unauthenticated_callers: false,
                        extension_inspection: crate::config::types::ExtensionInspectionConfig::default(),
                        fabric_delegated_credentials: false,
                        allow_fabric_callers: false,
                        trust_check_list: Vec::new(),
                        trust_check_migrated: false,
                    },
                ],
                outbound_listen_address: None,
                shared: SharedTransitConfig::default(),
            }),
            canvas: None,
            variants: Vec::new(),
            default_variant_id: None,
            outbound_credentials: Vec::new(),
            identity_slots: Default::default(),
            mcp_legacy_metadata_output: None,
            _retired_protocol_mode: Default::default(),
            mcp_http: None,
            trust_check_split: false,
            transit_point_source_auth: false,
        };

        assert!(
            surface
                .find_transit_point("github-api")
                .is_some()
        );
        assert!(
            surface
                .find_transit_point("partner")
                .is_some()
        );
        assert!(
            surface
                .find_transit_point("nonexistent")
                .is_none()
        );
    }

    #[test]
    fn a2a_proxy_target_round_trips_on_base_surface() {
        let json = serde_json::json!({
            "surface_id": "surf-a2a-proxy",
            "name": "copilot-worker",
            "description": "Copilot Worker exposed as A2A",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/agents/copilot-worker",
                "protocol": "a2a"
            },
            "target": {
                "endpoint": "a2a-proxy://worker-proxy",
                "a2a_proxy_id": "worker-proxy"
            }
        });

        let surface: AgentSurface = serde_json::from_value(json).expect("deserialize A2A Proxy target surface");
        surface
            .validate()
            .expect("A2A Proxy target should validate on A2A surface");
        assert_eq!(surface.target.endpoint, "a2a-proxy://worker-proxy");
        assert_eq!(
            surface
                .target
                .a2a_proxy_id
                .as_deref(),
            Some("worker-proxy")
        );

        let round_tripped = serde_json::to_value(&surface).expect("serialize A2A Proxy target surface");
        let again: AgentSurface = serde_json::from_value(round_tripped.clone()).expect("deserialize round trip");
        again
            .validate()
            .expect("round-tripped A2A Proxy target should validate");
        assert_eq!(again.target.endpoint, "a2a-proxy://worker-proxy");
        assert_eq!(
            again
                .target
                .a2a_proxy_id
                .as_deref(),
            Some("worker-proxy")
        );
        assert_eq!(round_tripped["target"]["endpoint"], "a2a-proxy://worker-proxy");
        assert_eq!(round_tripped["target"]["a2a_proxy_id"], "worker-proxy");
    }

    #[test]
    fn trust_check_list_round_trips_on_both_legs() {
        let json = serde_json::json!({
            "surface_id": "surf-tc",
            "name": "tc",
            "description": "",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/agents/tc",
                "protocol": "a2a",
                "trust_check_list": [{
                    "id": "caller-auth",
                    "trust_registry_id": "tr-1",
                    "query_type": "authorization",
                    "query": {
                        "authority_id": "did:web:authority.example",
                        "entity_id": "{{ caller.did }}",
                        "action": "invoke"
                    }
                }]
            },
            "target": {
                "endpoint": "https://upstream/api",
                "trust_check_list": [{
                    "id": "target-recognition",
                    "trust_registry_id": "tr-2",
                    "query_type": "recognition",
                    "query": {
                        "authority_id": "did:web:authority.example",
                        "entity_id": "{{ target.did }}"
                    },
                    "timeout_secs": 10
                }]
            }
        });

        let surface: AgentSurface = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(
            surface
                .access_point
                .trust_check_list
                .len(),
            1
        );
        assert_eq!(
            surface
                .access_point
                .trust_check_list[0]
                .id,
            "caller-auth"
        );
        assert_eq!(
            surface
                .target
                .trust_check_list
                .len(),
            1
        );
        assert_eq!(
            surface
                .target
                .trust_check_list[0]
                .timeout_secs,
            Some(10)
        );

        let round_tripped = serde_json::to_value(&surface).unwrap();
        let again: AgentSurface = serde_json::from_value(round_tripped.clone()).unwrap();
        let round_tripped_again = serde_json::to_value(&again).unwrap();
        assert_eq!(round_tripped, round_tripped_again, "AgentSurface JSON must be stable across a round-trip");
        assert_eq!(
            again
                .access_point
                .trust_check_list[0]
                .id,
            "caller-auth"
        );
        assert_eq!(again.target.trust_check_list[0].timeout_secs, Some(10));
    }

    #[test]
    fn trust_check_list_omitted_when_empty_on_wire() {
        let surface: AgentSurface = serde_json::from_str(
            r#"{
                "surface_id": "surf-empty",
                "name": "empty",
                "description": "",
                "access_point": {
                    "listen_address": "0.0.0.0:8443",
                    "route": "/a",
                    "protocol": "a2a"
                },
                "target": { "endpoint": "https://u/" }
            }"#,
        )
        .unwrap();

        assert!(
            surface
                .access_point
                .trust_check_list
                .is_empty()
        );
        assert!(
            surface
                .target
                .trust_check_list
                .is_empty()
        );

        let wire = serde_json::to_value(&surface).unwrap();
        assert!(
            wire["access_point"]
                .get("trust_check_list")
                .is_none(),
            "empty caller trust_check_list must be omitted on the wire"
        );
        assert!(
            wire["target"]
                .get("trust_check_list")
                .is_none(),
            "empty target trust_check_list must be omitted on the wire"
        );
    }

    #[test]
    fn transit_point_header_metadata_mapping_round_trips_and_validates_on_a2a() {
        let json = serde_json::json!({
            "surface_id": "surf-tp-hmm",
            "name": "tp-hmm",
            "description": "",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/agents/tp-hmm",
                "protocol": "a2a"
            },
            "target": { "endpoint": "https://managed.example/a2a" },
            "transit": {
                "points": [{
                    "id": "tp-a",
                    "alias": "partner-a",
                    "name": "Partner A",
                    "target_endpoint": "https://partner.example/a2a",
                    "protocol": "a2a",
                    "header_metadata_mapping": {
                        "extension_uri": "https://fabric.affinidi.io/extensions/header-metadata/v1",
                        "headers": [
                            { "header": "x-ms-entra-agent-id", "field": "entra_agent_id" },
                            { "header": "x-ms-client-tenant-id", "field": "client_tenant_id" }
                        ],
                        "strip_mapped_headers": false
                    }
                }]
            }
        });

        let surface: AgentSurface = serde_json::from_value(json).expect("deserialize surface");
        surface
            .validate()
            .expect("A2A Transit Point mapping should validate");
        let mapping = surface
            .transit
            .as_ref()
            .expect("transit")
            .points[0]
            .header_metadata_mapping
            .as_ref()
            .expect("mapping");
        assert_eq!(mapping.headers.len(), 2);
        assert!(!mapping.strip_mapped_headers);

        let wire = serde_json::to_value(&surface).expect("serialize surface");
        assert_eq!(wire["transit"]["points"][0]["header_metadata_mapping"]["headers"][0]["field"], "entra_agent_id");
        let again: AgentSurface = serde_json::from_value(wire).expect("deserialize round trip");
        again
            .validate()
            .expect("round-tripped Transit Point mapping should validate");
    }

    #[test]
    fn transit_point_header_metadata_mapping_is_omitted_when_absent() {
        let surface: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "surf-tp-no-hmm",
            "name": "tp-no-hmm",
            "description": "",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/agents/tp-no-hmm",
                "protocol": "a2a"
            },
            "target": { "endpoint": "https://managed.example/a2a" },
            "transit": {
                "points": [{
                    "id": "tp-a",
                    "alias": "partner-a",
                    "target_endpoint": "https://partner.example/a2a",
                    "protocol": "a2a"
                }]
            }
        }))
        .expect("deserialize surface");

        assert!(
            surface
                .transit
                .as_ref()
                .unwrap()
                .points[0]
                .header_metadata_mapping
                .is_none()
        );
        let wire = serde_json::to_value(&surface).expect("serialize surface");
        assert!(
            wire["transit"]["points"][0]
                .get("header_metadata_mapping")
                .is_none()
        );
    }

    #[test]
    fn validate_rejects_transit_point_header_metadata_mapping_on_http() {
        let surface: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "surf-tp-http-hmm",
            "name": "tp-http-hmm",
            "description": "",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/agents/tp-http-hmm",
                "protocol": "a2a"
            },
            "target": { "endpoint": "https://managed.example/a2a" },
            "transit": {
                "points": [{
                    "id": "tp-http",
                    "alias": "partner-http",
                    "target_endpoint": "https://partner.example/http",
                    "protocol": "http",
                    "header_metadata_mapping": {
                        "headers": [{ "header": "x-ms-entra-agent-id", "field": "entra_agent_id" }]
                    }
                }]
            }
        }))
        .expect("deserialize surface");

        match surface.validate() {
            Err(TrustCheckValidationError::TransitPointHeaderMetadataMappingInvalid { alias, source }) => {
                assert_eq!(alias, "partner-http");
                assert_eq!(
                    source,
                    HeaderMetadataMappingValidationError::UnsupportedProtocol { protocol: "http".to_string() }
                );
            }
            other => panic!("expected TransitPointHeaderMetadataMappingInvalid, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_variant_transit_point_header_metadata_mapping_on_http() {
        let surface: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "surf-tp-variant-hmm",
            "name": "tp-variant-hmm",
            "description": "",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/agents/tp-variant-hmm",
                "protocol": "a2a"
            },
            "target": { "endpoint": "https://managed.example/a2a" },
            "transit": {
                "points": [{
                    "id": "tp-a",
                    "alias": "partner-a",
                    "target_endpoint": "https://partner.example/a2a",
                    "protocol": "a2a"
                }]
            },
            "variants": [{
                "id": "variant-dev",
                "alias": "dev",
                "name": "Development",
                "enabled": true,
                "overrides": {
                    "transit": {
                        "points": [{
                            "id": "tp-a",
                            "alias": "partner-a",
                            "target_endpoint": "https://partner.example/http",
                            "protocol": "http",
                            "header_metadata_mapping": {
                                "headers": [{ "header": "x-ms-entra-agent-id", "field": "entra_agent_id" }]
                            }
                        }]
                    }
                }
            }]
        }))
        .expect("deserialize surface");

        match surface.validate() {
            Err(TrustCheckValidationError::VariantInvalid { alias, source }) => {
                assert_eq!(alias, "dev");
                match *source {
                    TrustCheckValidationError::TransitPointHeaderMetadataMappingInvalid { alias, source } => {
                        assert_eq!(alias, "partner-a");
                        assert_eq!(
                            source,
                            HeaderMetadataMappingValidationError::UnsupportedProtocol { protocol: "http".to_string() }
                        );
                    }
                    other => panic!("expected variant TransitPointHeaderMetadataMappingInvalid, got {other:?}"),
                }
            }
            other => panic!("expected VariantInvalid, got {other:?}"),
        }
    }

    fn transit_trust_check(id: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "trust_registry_id": "tr-1",
            "query_type": "recognition",
            "query": {
                "authority_id": "did:web:authority.example",
                "entity_id": "{{ target.did }}"
            }
        })
    }

    fn surface_with_transit_points(points: serde_json::Value) -> AgentSurface {
        serde_json::from_value(serde_json::json!({
            "surface_id": "surf-tp-tc",
            "name": "tp-tc",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/agents/tp-tc",
                "protocol": "a2a"
            },
            "target": { "endpoint": "https://managed.example/a2a" },
            "transit": { "points": points }
        }))
        .expect("deserialize surface")
    }

    fn transit_point_json(
        alias: &str,
        protocol: &str,
        trust_check_list: Vec<serde_json::Value>,
    ) -> serde_json::Value {
        serde_json::json!({
            "id": format!("tp-{alias}"),
            "alias": alias,
            "target_endpoint": format!("https://{alias}.example/a2a"),
            "protocol": protocol,
            "trust_check_list": trust_check_list
        })
    }

    #[test]
    fn validate_accepts_transit_point_trust_check_lists_on_a2a_and_ap2() {
        let surface = surface_with_transit_points(serde_json::json!([
            transit_point_json("tp-a2a", "a2a", vec![transit_trust_check("a"), transit_trust_check("b")]),
            transit_point_json("tp-ap2", "ap2", vec![transit_trust_check("a")]),
            transit_point_json("tp-mcp", "mcp", Vec::new()),
        ]));

        assert_eq!(surface.validate(), Ok(()));
        let points = &surface
            .transit
            .as_ref()
            .expect("transit")
            .points;
        assert_eq!(
            points[0]
                .trust_check_list
                .len(),
            2
        );
        assert_eq!(points[0].trust_check_list[1].id, "b");
        assert!(
            points[2]
                .trust_check_list
                .is_empty()
        );
    }

    #[test]
    fn validate_rejects_transit_point_trust_check_list_over_max() {
        let list = (0..=TRUST_CHECK_LIST_MAX)
            .map(|i| transit_trust_check(&format!("check-{i}")))
            .collect();
        let surface = surface_with_transit_points(serde_json::json!([transit_point_json("partner-a", "a2a", list)]));

        let err = surface
            .validate()
            .expect_err("eleven checks must be rejected");
        assert_eq!(
            err,
            TrustCheckValidationError::TransitPointTrustCheckInvalid {
                alias: "partner-a".to_string(),
                source: Box::new(TrustCheckValidationError::TrustCheckListTooLong {
                    leg: "target",
                    got: TRUST_CHECK_LIST_MAX + 1,
                    max: TRUST_CHECK_LIST_MAX,
                }),
            }
        );
        assert_eq!(
            err.to_string(),
            format!(
                "transit point 'partner-a': target trust_check_list has {} elements (max {TRUST_CHECK_LIST_MAX})",
                TRUST_CHECK_LIST_MAX + 1
            )
        );
    }

    #[test]
    fn validate_rejects_transit_point_trust_check_duplicate_id() {
        let surface = surface_with_transit_points(serde_json::json!([
            transit_point_json("partner-a", "a2a", vec![transit_trust_check("dup")]),
            transit_point_json("partner-b", "a2a", vec![transit_trust_check("dup"), transit_trust_check("dup")]),
        ]));

        assert_eq!(
            surface.validate(),
            Err(TrustCheckValidationError::TransitPointTrustCheckInvalid {
                alias: "partner-b".to_string(),
                source: Box::new(TrustCheckValidationError::TrustCheckDuplicateId {
                    leg: "target",
                    id: "dup".to_string(),
                }),
            })
        );
    }

    #[test]
    fn validate_rejects_transit_point_trust_check_invalid_element() {
        let mut blank_authority = transit_trust_check("bad");
        blank_authority["query"]["authority_id"] = serde_json::json!(" ");
        let surface = surface_with_transit_points(serde_json::json!([transit_point_json(
            "partner-a",
            "a2a",
            vec![blank_authority]
        )]));

        assert_eq!(
            surface.validate(),
            Err(TrustCheckValidationError::TransitPointTrustCheckInvalid {
                alias: "partner-a".to_string(),
                source: Box::new(TrustCheckValidationError::TrustCheckElementInvalid {
                    leg: "target",
                    index: 0,
                    id: "bad".to_string(),
                    source: TrustCheckElementValidationError::AuthorityBlank,
                }),
            })
        );
    }

    #[test]
    fn validate_accepts_stored_trust_check_lists_on_mcp_and_http_transit_points() {
        for protocol in ["mcp", "http"] {
            let mut surface = surface_with_transit_points(serde_json::json!([transit_point_json(
                "partner-x",
                protocol,
                vec![transit_trust_check("a")]
            )]));
            surface.variants = vec![
                serde_json::from_value(serde_json::json!({
                    "id": "variant-dev", "alias": "dev", "name": "Development", "enabled": true,
                    "overrides": {"transit": {"points": [transit_point_json("partner-x", protocol, vec![transit_trust_check("b")])]}}
                }))
                .expect("deserialize variant"),
            ];

            assert_eq!(surface.validate(), Ok(()), "{protocol} lists come from the migration and must load");
        }
    }

    #[test]
    fn validate_still_checks_the_shape_of_mcp_transit_point_lists() {
        let surface = surface_with_transit_points(serde_json::json!([transit_point_json(
            "partner-x",
            "mcp",
            vec![transit_trust_check("dup"), transit_trust_check("dup")]
        )]));

        assert_eq!(
            surface.validate(),
            Err(TrustCheckValidationError::TransitPointTrustCheckInvalid {
                alias: "partner-x".to_string(),
                source: Box::new(TrustCheckValidationError::TrustCheckDuplicateId {
                    leg: "target",
                    id: "dup".to_string(),
                }),
            })
        );
    }

    #[test]
    fn transit_point_trust_check_fields_are_omitted_when_unset() {
        let surface =
            surface_with_transit_points(serde_json::json!([transit_point_json("partner-a", "a2a", Vec::new())]));
        let point = &surface
            .transit
            .as_ref()
            .expect("transit")
            .points[0];
        assert!(
            point
                .trust_check_list
                .is_empty()
        );
        assert!(!point.trust_check_migrated);
        assert!(!surface.trust_check_split);

        let wire = serde_json::to_value(&surface).expect("serialize surface");
        let wire_point = &wire["transit"]["points"][0];
        assert!(
            wire_point
                .get("trust_check_list")
                .is_none()
        );
        assert!(
            wire_point
                .get("trust_check_migrated")
                .is_none()
        );
        assert!(
            wire.get("trust_check_split")
                .is_none()
        );
    }

    #[test]
    fn transit_point_trust_check_fields_round_trip_when_set() {
        let mut point = transit_point_json("partner-a", "a2a", vec![transit_trust_check("partner-recognition")]);
        point["trust_check_migrated"] = serde_json::json!(true);
        let mut surface = surface_with_transit_points(serde_json::json!([point]));
        surface.trust_check_split = true;

        let wire = serde_json::to_value(&surface).expect("serialize surface");
        assert_eq!(wire["trust_check_split"], serde_json::json!(true));
        assert_eq!(wire["transit"]["points"][0]["trust_check_migrated"], serde_json::json!(true));
        assert_eq!(wire["transit"]["points"][0]["trust_check_list"][0]["id"], "partner-recognition");

        let again: AgentSurface = serde_json::from_value(wire).expect("deserialize round trip");
        let again_point = &again
            .transit
            .as_ref()
            .expect("transit")
            .points[0];
        assert!(again.trust_check_split);
        assert!(again_point.trust_check_migrated);
        assert_eq!(
            again_point
                .trust_check_list
                .len(),
            1
        );
        assert_eq!(again_point.trust_check_list[0].trust_registry_id, "tr-1");
    }

    #[test]
    fn stored_surface_with_http_target_trust_check_list_still_loads_and_validates() {
        let surface: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "surf-legacy",
            "name": "legacy",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/agents/legacy",
                "protocol": "a2a"
            },
            "target": {
                "endpoint": "https://managed.example/a2a",
                "trust_check_list": [transit_trust_check("legacy-target")]
            },
            "transit": { "points": [transit_point_json("partner-a", "a2a", Vec::new())] }
        }))
        .expect("stored legacy surface must deserialize");

        assert_eq!(surface.validate(), Ok(()));
        assert!(!surface.trust_check_split);
        assert_eq!(
            surface
                .target
                .trust_check_list[0]
                .id,
            "legacy-target"
        );
    }

    #[test]
    fn access_point_header_metadata_mapping_if_supported_is_none_on_mcp() {
        let surface: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "surf-mcp-hmm",
            "name": "mcp-hmm",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/agents/mcp-hmm",
                "protocol": "mcp",
                "header_metadata_mapping": {
                    "headers": [{ "header": "x-agent-id", "field": "agent_id" }]
                }
            },
            "target": { "endpoint": "https://mcp.internal/mcp" }
        }))
        .expect("deserialize surface");

        assert!(
            surface
                .access_point
                .header_metadata_mapping
                .is_some()
        );
        assert!(
            surface
                .access_point
                .header_metadata_mapping_if_supported()
                .is_none()
        );
    }

    #[test]
    fn access_point_header_metadata_mapping_if_supported_is_some_on_ap2() {
        let surface: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "surf-ap2-hmm",
            "name": "ap2-hmm",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/agents/ap2-hmm",
                "protocol": "ap2",
                "header_metadata_mapping": {
                    "headers": [{ "header": "x-agent-id", "field": "agent_id" }]
                }
            },
            "target": { "endpoint": "https://ap2.internal/ap2" }
        }))
        .expect("deserialize surface");

        assert!(
            surface
                .access_point
                .header_metadata_mapping_if_supported()
                .is_some()
        );
    }

    #[test]
    fn clear_unsupported_header_metadata_mappings_clears_access_point_on_mcp() {
        let mut surface: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "surf-mcp-hmm",
            "name": "mcp-hmm",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/agents/mcp-hmm",
                "protocol": "mcp",
                "header_metadata_mapping": {
                    "headers": [{ "header": "x-agent-id", "field": "agent_id" }]
                }
            },
            "target": { "endpoint": "https://mcp.internal/mcp" }
        }))
        .expect("deserialize surface");

        let cleared = surface.clear_unsupported_header_metadata_mappings();
        assert_eq!(cleared.len(), 1);
        assert!(cleared[0].contains("access_point"));
        assert!(
            surface
                .access_point
                .header_metadata_mapping
                .is_none()
        );

        // Idempotent: a second pass finds nothing left to clear.
        assert!(
            surface
                .clear_unsupported_header_metadata_mappings()
                .is_empty()
        );
    }

    #[test]
    fn clear_unsupported_header_metadata_mappings_leaves_valid_a2a_mapping_untouched() {
        let mut surface: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "surf-a2a-hmm",
            "name": "a2a-hmm",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/agents/a2a-hmm",
                "protocol": "a2a",
                "header_metadata_mapping": {
                    "headers": [{ "header": "x-agent-id", "field": "agent_id" }]
                }
            },
            "target": { "endpoint": "https://a2a.internal/a2a" }
        }))
        .expect("deserialize surface");

        assert!(
            surface
                .clear_unsupported_header_metadata_mappings()
                .is_empty()
        );
        assert!(
            surface
                .access_point
                .header_metadata_mapping
                .is_some()
        );
    }

    #[test]
    fn clear_unsupported_header_metadata_mappings_clears_base_transit_point_on_http() {
        let mut surface: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "surf-tp-http-hmm",
            "name": "tp-http-hmm",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/agents/tp-http-hmm",
                "protocol": "a2a"
            },
            "target": { "endpoint": "https://managed.example/a2a" },
            "transit": {
                "points": [{
                    "id": "tp-http",
                    "alias": "partner-http",
                    "target_endpoint": "https://partner.example/http",
                    "protocol": "http",
                    "header_metadata_mapping": {
                        "headers": [{ "header": "x-ms-entra-agent-id", "field": "entra_agent_id" }]
                    }
                }]
            }
        }))
        .expect("deserialize surface");

        let cleared = surface.clear_unsupported_header_metadata_mappings();
        assert_eq!(cleared.len(), 1);
        assert!(cleared[0].contains("partner-http"));
        let tp = &surface
            .transit
            .as_ref()
            .expect("transit config")
            .points[0];
        assert!(
            tp.header_metadata_mapping
                .is_none()
        );
        // validate() now passes since the invalid mapping is gone.
        surface
            .validate()
            .expect("surface should validate after cleanup");
    }

    #[test]
    fn clear_unsupported_header_metadata_mappings_clears_variant_overrides() {
        let mut surface: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "surf-variant-hmm",
            "name": "variant-hmm",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/agents/variant-hmm",
                "protocol": "mcp"
            },
            "target": { "endpoint": "https://managed.example/mcp" },
            "transit": {
                "points": [{
                    "id": "tp-a",
                    "alias": "partner-a",
                    "target_endpoint": "https://partner.example/a2a",
                    "protocol": "a2a"
                }]
            },
            "variants": [{
                "id": "variant-dev",
                "alias": "dev",
                "name": "Development",
                "enabled": true,
                "overrides": {
                    "access_point": {
                        "header_metadata_mapping": {
                            "headers": [{ "header": "x-agent-id", "field": "agent_id" }]
                        }
                    },
                    "transit": {
                        "points": [{
                            "id": "tp-a",
                            "alias": "partner-a",
                            "target_endpoint": "https://partner.example/http",
                            "protocol": "http",
                            "header_metadata_mapping": {
                                "headers": [{ "header": "x-ms-entra-agent-id", "field": "entra_agent_id" }]
                            }
                        }]
                    }
                }
            }]
        }))
        .expect("deserialize surface");

        let mut cleared = surface.clear_unsupported_header_metadata_mappings();
        cleared.sort();
        assert_eq!(cleared.len(), 2);
        assert!(
            cleared
                .iter()
                .any(|c| c.contains("variant 'dev' access_point override"))
        );
        assert!(
            cleared
                .iter()
                .any(|c| c.contains("variant 'dev' transit point 'partner-a'"))
        );

        let variant = &surface.variants[0];
        assert!(
            variant
                .overrides
                .access_point
                .as_ref()
                .expect("ap override")
                .header_metadata_mapping
                .is_none()
        );
        let tp_override = &variant
            .overrides
            .transit
            .as_ref()
            .expect("transit override")
            .points
            .as_ref()
            .expect("points override")[0];
        assert!(
            tp_override
                .header_metadata_mapping
                .is_none()
        );
    }

    fn elem(id: &str) -> TrustCheckElement {
        TrustCheckElement {
            id: id.to_string(),
            trust_registry_id: "tr-1".to_string(),
            query_type: crate::trust_registry_verification::trust_check_element::TrqpQueryType::Recognition,
            query: crate::trust_registry_verification::trust_check_element::TrqpQueryParams {
                authority_id: "did:web:authority.example".to_string(),
                entity_id: "{{ caller.did }}".to_string(),
                action: None,
                resource: None,
            },
            timeout_secs: None,
            name: None,
        }
    }

    fn surface_with_lists(
        caller: Vec<TrustCheckElement>,
        target: Vec<TrustCheckElement>,
    ) -> AgentSurface {
        let mut s: AgentSurface = serde_json::from_str(
            r#"{
                "surface_id": "surf-v",
                "name": "v",
                "description": "",
                "access_point": {
                    "listen_address": "0.0.0.0:8443",
                    "route": "/a",
                    "protocol": "a2a"
                },
                "target": { "endpoint": "https://u/" }
            }"#,
        )
        .unwrap();
        s.access_point
            .trust_check_list = caller;
        s.target.trust_check_list = target;
        s
    }

    #[test]
    fn validate_passes_with_empty_lists() {
        let s = surface_with_lists(Vec::new(), Vec::new());
        assert_eq!(s.validate(), Ok(()));
    }

    #[test]
    fn validate_allows_a2a_proxy_target_on_a2a_surface() {
        let mut s = surface_with_lists(Vec::new(), Vec::new());
        s.target.endpoint = "a2a-proxy://proxy-1".to_string();
        s.target.a2a_proxy_id = Some("proxy-1".to_string());

        assert_eq!(s.validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_a2a_proxy_target_on_non_a2a_surface() {
        let mut s = surface_with_lists(Vec::new(), Vec::new());
        s.access_point.protocol = SurfaceProtocol::Mcp;
        s.target.endpoint = "a2a-proxy://proxy-1".to_string();
        s.target.a2a_proxy_id = Some("proxy-1".to_string());

        match s.validate() {
            Err(TrustCheckValidationError::TargetA2aProxyInvalid { reason }) => {
                assert_eq!(reason, "a2a-proxy:// targets are only valid for A2A/AP2 surfaces");
            }
            other => panic!("expected TargetA2aProxyInvalid, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_mismatched_a2a_proxy_id() {
        let mut s = surface_with_lists(Vec::new(), Vec::new());
        s.target.endpoint = "a2a-proxy://proxy-1".to_string();
        s.target.a2a_proxy_id = Some("proxy-2".to_string());

        match s.validate() {
            Err(TrustCheckValidationError::TargetA2aProxyInvalid { reason }) => {
                assert_eq!(reason, "target.endpoint A2A Proxy id must match target.a2a_proxy_id");
            }
            other => panic!("expected TargetA2aProxyInvalid, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_blank_a2a_proxy_endpoint_id() {
        let mut s = surface_with_lists(Vec::new(), Vec::new());
        s.target.endpoint = "a2a-proxy://".to_string();

        match s.validate() {
            Err(TrustCheckValidationError::TargetA2aProxyInvalid { reason }) => {
                assert_eq!(reason, "target.endpoint A2A Proxy id must not be empty");
            }
            other => panic!("expected TargetA2aProxyInvalid, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_a2a_proxy_endpoint_id_with_surrounding_whitespace() {
        let mut s = surface_with_lists(Vec::new(), Vec::new());
        s.target.endpoint = "a2a-proxy://proxy-1 ".to_string();

        match s.validate() {
            Err(TrustCheckValidationError::TargetA2aProxyInvalid { reason }) => {
                assert_eq!(reason, "target.endpoint A2A Proxy id must not include surrounding whitespace");
            }
            other => panic!("expected TargetA2aProxyInvalid, got {other:?}"),
        }
    }

    #[test]
    fn validate_passes_at_max_elements_per_leg() {
        let list: Vec<_> = (0..TRUST_CHECK_LIST_MAX)
            .map(|i| elem(&format!("tc-{i}")))
            .collect();
        let s = surface_with_lists(list.clone(), list);
        assert_eq!(s.validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_over_max_elements_on_caller_leg() {
        let list: Vec<_> = (0..=TRUST_CHECK_LIST_MAX)
            .map(|i| elem(&format!("tc-{i}")))
            .collect();
        let s = surface_with_lists(list, Vec::new());
        match s.validate() {
            Err(TrustCheckValidationError::TrustCheckListTooLong { leg, got, max }) => {
                assert_eq!(leg, "caller");
                assert_eq!(got, TRUST_CHECK_LIST_MAX + 1);
                assert_eq!(max, TRUST_CHECK_LIST_MAX);
            }
            other => panic!("expected TrustCheckListTooLong on caller, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_duplicate_id_on_target_leg() {
        let s = surface_with_lists(Vec::new(), vec![elem("dup"), elem("dup")]);
        match s.validate() {
            Err(TrustCheckValidationError::TrustCheckDuplicateId { leg, id }) => {
                assert_eq!(leg, "target");
                assert_eq!(id, "dup");
            }
            other => panic!("expected TrustCheckDuplicateId on target, got {other:?}"),
        }
    }

    #[test]
    fn validate_propagates_element_level_error_with_leg_index_and_id() {
        let mut bad = elem("blank-authority");
        bad.query.authority_id = "   ".to_string();
        let s = surface_with_lists(vec![elem("ok"), bad], Vec::new());
        match s.validate() {
            Err(TrustCheckValidationError::TrustCheckElementInvalid { leg, index, id, source }) => {
                assert_eq!(leg, "caller");
                assert_eq!(index, 1);
                assert_eq!(id, "blank-authority");
                assert_eq!(source, TrustCheckElementValidationError::AuthorityBlank);
            }
            other => panic!("expected TrustCheckElementInvalid, got {other:?}"),
        }
    }

    #[test]
    fn validate_walks_variants_and_reports_alias_on_failure() {
        use crate::config::agent_surface_variants::{AccessPointOverrides, SurfaceOverrides, SurfaceVariant};
        let mut s = surface_with_lists(Vec::new(), Vec::new());
        let ap_override = AccessPointOverrides {
            trust_check_list: Some(vec![elem("dup"), elem("dup")]),
            ..AccessPointOverrides::default()
        };
        let overrides = SurfaceOverrides {
            access_point: Some(ap_override),
            ..SurfaceOverrides::default()
        };
        s.variants = vec![SurfaceVariant {
            id: "v-1".to_string(),
            alias: "shadow".to_string(),
            name: "shadow".to_string(),
            description: String::new(),
            enabled: true,
            overrides,
        }];
        match s.validate() {
            Err(TrustCheckValidationError::VariantInvalid { alias, source }) => {
                assert_eq!(alias, "shadow");
                match *source {
                    TrustCheckValidationError::TrustCheckDuplicateId { leg, id } => {
                        assert_eq!(leg, "caller");
                        assert_eq!(id, "dup");
                    }
                    other => panic!("expected inner TrustCheckDuplicateId, got {other:?}"),
                }
            }
            other => panic!("expected VariantInvalid, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_trust_recorder_over_max_entries() {
        use crate::config::types::{TRUST_RECORDER_ENTRIES_MAX, TrustRecorderConfig, TrustRecorderEntry};
        let mut s = surface_with_lists(Vec::new(), Vec::new());
        let entry = TrustRecorderEntry {
            trust_registry_id: "tr-1".to_string(),
            issuer_did: "did:example:issuer".to_string(),
            authority_did: "did:example:authority".to_string(),
            include_owned_agent: false,
            custom_resources: Vec::new(),
        };
        s.access_point.trust_recorder = Some(TrustRecorderConfig {
            entries: vec![entry; TRUST_RECORDER_ENTRIES_MAX + 1],
        });
        match s.validate() {
            Err(TrustCheckValidationError::TrustRecorderTooManyEntries { got, max }) => {
                assert_eq!(got, TRUST_RECORDER_ENTRIES_MAX + 1);
                assert_eq!(max, TRUST_RECORDER_ENTRIES_MAX);
            }
            other => panic!("expected TrustRecorderTooManyEntries, got {other:?}"),
        }
    }

    #[test]
    fn validate_variant_with_none_override_inherits_base_and_passes() {
        use crate::config::agent_surface_variants::{SurfaceOverrides, SurfaceVariant};
        let s_base = surface_with_lists(vec![elem("tc-ok")], Vec::new());
        let mut s = s_base.clone();
        s.variants = vec![SurfaceVariant {
            id: "v-1".to_string(),
            alias: "inherit".to_string(),
            name: "inherit".to_string(),
            description: String::new(),
            enabled: true,
            overrides: SurfaceOverrides::default(),
        }];
        assert_eq!(s.validate(), Ok(()));
    }

    #[test]
    fn validate_variant_with_empty_override_clears_base_list_and_passes() {
        use crate::config::agent_surface_variants::{AccessPointOverrides, SurfaceOverrides, SurfaceVariant};
        let mut s = surface_with_lists(vec![elem("base-1"), elem("base-2")], Vec::new());
        let ap_override = AccessPointOverrides {
            trust_check_list: Some(Vec::new()),
            ..AccessPointOverrides::default()
        };
        let overrides = SurfaceOverrides {
            access_point: Some(ap_override),
            ..SurfaceOverrides::default()
        };
        s.variants = vec![SurfaceVariant {
            id: "v-1".to_string(),
            alias: "cleared".to_string(),
            name: "cleared".to_string(),
            description: String::new(),
            enabled: true,
            overrides,
        }];
        assert_eq!(s.validate(), Ok(()));
    }

    // ── Transit Point-scoped Workload Binding validation ─────────────────────

    fn wb_surface(
        with_agent_did: bool,
        wb: serde_json::Value,
    ) -> AgentSurface {
        let mut doc = serde_json::json!({
            "surface_id": "surf-wb",
            "name": "wb",
            "description": "",
            "access_point": { "listen_address": "0.0.0.0:8443", "route": "/a", "protocol": "mcp" },
            "target": { "endpoint": "https://u/" },
            "transit": {
                "points": [
                    { "alias": "tp1", "target_endpoint": "https://ext/", "workload_binding": wb }
                ]
            }
        });
        if with_agent_did {
            doc["agent_did"] = serde_json::json!("did:web:agent.example");
        }
        serde_json::from_value(doc).unwrap()
    }

    #[test]
    fn validate_workload_binding_ok_with_managed_identity() {
        let s = wb_surface(
            true,
            serde_json::json!({
                "enabled": true,
                "caller_source": "transit_token",
                "caller_context_fields": ["sub", "email"]
            }),
        );
        assert_eq!(s.validate_workload_binding(), Ok(()));
    }

    #[test]
    fn validate_workload_binding_rejects_missing_managed_identity() {
        let s = wb_surface(
            false,
            serde_json::json!({
                "enabled": true,
                "caller_context_fields": ["sub"]
            }),
        );
        match s.validate_workload_binding() {
            Err(WorkloadBindingSurfaceError::MissingManagedIdentity { alias }) => {
                assert_eq!(alias, "tp1");
            }
            other => panic!("expected MissingManagedIdentity, got {other:?}"),
        }
    }

    #[test]
    fn validate_workload_binding_rejects_duplicate_caller_claim() {
        let s = wb_surface(
            true,
            serde_json::json!({
                "enabled": true,
                "caller_context_fields": ["sub", "sub"]
            }),
        );
        match s.validate_workload_binding() {
            Err(WorkloadBindingSurfaceError::ConfigInvalid { alias, source }) => {
                assert_eq!(alias, "tp1");
                assert_eq!(
                    source,
                    crate::config::types::WorkloadBindingValidationError::Duplicate { name: "sub".into() }
                );
            }
            other => panic!("expected ConfigInvalid, got {other:?}"),
        }
    }

    #[test]
    fn validate_workload_binding_disabled_skips_managed_identity_check() {
        // No managed identity source, but the binding is disabled, so the
        // managed-identity requirement does not apply.
        let s = wb_surface(
            false,
            serde_json::json!({
                "enabled": false,
                "caller_context_fields": ["sub"]
            }),
        );
        assert_eq!(s.validate_workload_binding(), Ok(()));
    }

    #[test]
    fn validate_workload_binding_missing_binding_is_valid() {
        // Transit point present but no workload_binding at all.
        let s: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "surf-nowb",
            "name": "nowb",
            "description": "",
            "access_point": { "listen_address": "0.0.0.0:8443", "route": "/a", "protocol": "mcp" },
            "target": { "endpoint": "https://u/" },
            "transit": { "points": [ { "alias": "tp1", "target_endpoint": "https://ext/" } ] }
        }))
        .unwrap();
        assert_eq!(s.validate_workload_binding(), Ok(()));
    }

    #[test]
    fn validate_workload_binding_no_transit_is_valid() {
        let s = surface_with_lists(Vec::new(), Vec::new());
        assert_eq!(s.validate_workload_binding(), Ok(()));
    }

    #[test]
    fn validate_workload_binding_walks_variants_and_inherits_base_binding() {
        use crate::config::agent_surface_variants::{SurfaceOverrides, SurfaceVariant};
        let mut s = wb_surface(
            true,
            serde_json::json!({
                "enabled": true,
                "caller_context_fields": ["sub"]
            }),
        );
        s.variants = vec![SurfaceVariant {
            id: "v-1".to_string(),
            alias: "inherit".to_string(),
            name: "inherit".to_string(),
            description: String::new(),
            enabled: true,
            overrides: SurfaceOverrides::default(),
        }];
        assert_eq!(s.validate_workload_binding(), Ok(()));
    }

    // ── Primary-target (MA→EXT) Workload Binding validation ──────────────────

    fn target_wb_surface(
        with_agent_did: bool,
        wb: serde_json::Value,
    ) -> AgentSurface {
        let mut doc = serde_json::json!({
            "surface_id": "surf-target-wb",
            "name": "target-wb",
            "description": "",
            "access_point": { "listen_address": "0.0.0.0:8443", "route": "/a", "protocol": "mcp" },
            "target": { "endpoint": "https://u/", "workload_binding": wb }
        });
        if with_agent_did {
            doc["agent_did"] = serde_json::json!("did:web:agent.example");
        }
        serde_json::from_value(doc).unwrap()
    }

    #[test]
    fn validate_target_workload_binding_ok_with_managed_identity() {
        let s = target_wb_surface(
            true,
            serde_json::json!({
                "enabled": true,
                "caller_source": "authorization_bearer_jwt",
                "caller_context_fields": ["sub", "email"]
            }),
        );
        assert_eq!(s.validate_workload_binding(), Ok(()));
    }

    #[test]
    fn validate_target_workload_binding_rejects_missing_managed_identity() {
        let s = target_wb_surface(
            false,
            serde_json::json!({
                "enabled": true,
                "caller_context_fields": ["sub"]
            }),
        );
        assert_eq!(s.validate_workload_binding(), Err(WorkloadBindingSurfaceError::TargetMissingManagedIdentity));
    }

    #[test]
    fn validate_target_workload_binding_rejects_duplicate_caller_claim() {
        let s = target_wb_surface(
            true,
            serde_json::json!({
                "enabled": true,
                "caller_context_fields": ["sub", "sub"]
            }),
        );
        match s.validate_workload_binding() {
            Err(WorkloadBindingSurfaceError::TargetConfigInvalid { source }) => {
                assert_eq!(
                    source,
                    crate::config::types::WorkloadBindingValidationError::Duplicate { name: "sub".into() }
                );
            }
            other => panic!("expected TargetConfigInvalid, got {other:?}"),
        }
    }

    #[test]
    fn validate_target_workload_binding_disabled_skips_managed_identity_check() {
        let s = target_wb_surface(
            false,
            serde_json::json!({
                "enabled": false,
                "caller_context_fields": ["sub"]
            }),
        );
        assert_eq!(s.validate_workload_binding(), Ok(()));
    }

    #[test]
    fn validate_target_workload_binding_walks_variant_override() {
        use crate::config::agent_surface_variants::{SurfaceOverrides, SurfaceVariant, TargetOverrides};
        // Base target WB is disabled (valid); the variant overrides it with an
        // enabled, malformed binding — proving the variant is walked.
        let mut s = target_wb_surface(true, serde_json::json!({ "enabled": false, "caller_context_fields": ["sub"] }));
        s.variants = vec![SurfaceVariant {
            id: "v-1".to_string(),
            alias: "bad".to_string(),
            name: "bad".to_string(),
            description: String::new(),
            enabled: true,
            overrides: SurfaceOverrides {
                target: Some(TargetOverrides {
                    workload_binding: Some(
                        serde_json::from_value(serde_json::json!({
                            "enabled": true,
                            "caller_context_fields": ["sub", "sub"]
                        }))
                        .unwrap(),
                    ),
                    ..TargetOverrides::default()
                }),
                ..SurfaceOverrides::default()
            },
        }];
        match s.validate_workload_binding() {
            Err(WorkloadBindingSurfaceError::VariantInvalid { alias, source }) => {
                assert_eq!(alias, "bad");
                assert!(matches!(*source, WorkloadBindingSurfaceError::TargetConfigInvalid { .. }));
            }
            other => panic!("expected VariantInvalid wrapping TargetConfigInvalid, got {other:?}"),
        }
    }

    #[test]
    fn removed_trusted_binding_issuers_is_stripped_at_load_and_rejected_on_write() {
        let legacy = serde_json::json!({
            "surface_id": "surf-tbi",
            "name": "tbi",
            "description": "",
            "access_point": { "listen_address": "0.0.0.0:8443", "route": "/a", "protocol": "mcp" },
            "target": { "endpoint": "https://u/" },
            "trusted_binding_issuers": ["did:web:gw1.example", "did:web:relay.example"]
        });

        // A write carrying the removed field is an unknown field.
        assert!(serde_json::from_value::<AgentSurface>(legacy.clone()).is_err());

        // A persisted surface is migrated: the key is dropped and the file re-persisted.
        let mut stored = legacy;
        let mutated = AgentSurface::migrate_raw_json(&mut stored).expect("migration");
        assert!(mutated);
        assert!(
            stored
                .get("trusted_binding_issuers")
                .is_none(),
            "{stored}"
        );
        let surface: AgentSurface = serde_json::from_value(stored).expect("migrated surface deserializes");
        assert_eq!(surface.validate_workload_binding(), Ok(()));
    }

    /// Compat: legacy stored surfaces still carry `department_id` on the wire.
    /// The serde alias must accept it verbatim and expose the value on the
    /// canonical `issuer_id` field.
    #[test]
    fn agent_surface_deserializes_legacy_department_id_alias() {
        let json = r#"{
            "surface_id": "surf-legacy",
            "name": "legacy",
            "description": "",
            "department_id": "issuer-legacy-123",
            "access_point": { "listen_address": "0.0.0.0:8443", "route": "/a", "protocol": "mcp" },
            "target": { "endpoint": "https://u/" }
        }"#;
        let s: AgentSurface = serde_json::from_str(json).expect("legacy `department_id` must deserialize");
        assert_eq!(s.issuer_id.as_deref(), Some("issuer-legacy-123"));
    }

    /// Compat: serialisation emits only the canonical `issuer_id` field —
    /// never the legacy `department_id` sibling. External readers that grep
    /// on `department_id` will break the first time a surface is re-saved.
    #[test]
    fn agent_surface_serializes_issuer_id_only() {
        let surface = AgentSurface {
            surface_id: "surf-round-trip".to_string(),
            tenant_id: None,
            name: "rt".to_string(),
            description: String::new(),
            status: SurfaceStatus::Active,
            agent_did: None,
            issuer_id: Some("issuer-42".to_string()),
            tags: Vec::new(),
            access_point: AccessPoint {
                listen_address: "0.0.0.0:8443".to_string(),
                route: "/rt".to_string(),
                protocol: SurfaceProtocol::A2a,
                ..Default::default()
            },
            target: Target {
                endpoint: "https://u/".to_string(),
                ..Default::default()
            },
            transit: None,
            canvas: None,
            variants: Vec::new(),
            default_variant_id: None,
            outbound_credentials: Vec::new(),
            identity_slots: Default::default(),
            mcp_legacy_metadata_output: None,
            _retired_protocol_mode: Default::default(),
            mcp_http: None,
            trust_check_split: false,
            transit_point_source_auth: false,
        };
        let value = serde_json::to_value(&surface).expect("surface must serialize");
        assert_eq!(value["issuer_id"], serde_json::json!("issuer-42"));
        assert!(
            value
                .get("department_id")
                .is_none(),
            "serialised surface must NOT contain the legacy department_id field, got: {}",
            value
        );
    }
}

#[cfg(test)]
mod a2a_settings_tests {
    use super::*;
    use crate::a2a::version::{SUPPORTED_VERSIONS, VERSIONS_0_3_ONLY, VERSIONS_1_0_ONLY};
    use serde_json::json;

    fn surface(
        protocol: &str,
        endpoint: &str,
        a2a: Option<serde_json::Value>,
    ) -> AgentSurface {
        let mut value = json!({
            "surface_id": "s", "name": "s",
            "access_point": {"listen_address": "127.0.0.1:8080", "route": "/agent", "protocol": protocol},
            "target": {"endpoint": endpoint}
        });
        if let Some(a2a) = a2a {
            value["access_point"]["a2a"] = a2a;
        }
        serde_json::from_value(value).expect("surface fixture")
    }

    fn settings(
        versions: &[&str],
        validation: &str,
    ) -> serde_json::Value {
        json!({ "accepted_versions": versions, "validation": validation })
    }

    fn effective(
        accepted_versions: &'static [&'static str],
        validation: A2aValidation,
    ) -> EffectiveA2aSettings {
        EffectiveA2aSettings { accepted_versions, validation }
    }

    #[test]
    fn an_absent_block_means_both_versions_with_envelope_validation() {
        let surface = surface("a2a", "http://agent", None);
        assert_eq!(surface.a2a_settings(), effective(SUPPORTED_VERSIONS, A2aValidation::Envelope));
        assert_eq!(
            A2aAccessPointSettings::default(),
            A2aAccessPointSettings {
                accepted_versions: vec!["0.3".to_string(), "1.0".to_string()],
                validation: A2aValidation::Envelope,
                accepted_versions_sent: false,
            }
        );
    }

    #[test]
    fn validation_levels_check_what_they_name() {
        assert!(!A2aValidation::Off.checks_envelope());
        assert!(!A2aValidation::Off.checks_request_shape());
        assert!(A2aValidation::Envelope.checks_envelope());
        assert!(!A2aValidation::Envelope.checks_request_shape());
        assert!(A2aValidation::Full.checks_envelope());
        assert!(A2aValidation::Full.checks_request_shape());
    }

    #[test]
    fn a_stored_block_is_what_requests_are_served_with() {
        let only_1_0 = surface("a2a", "http://agent", Some(settings(&["1.0"], "off")));
        assert_eq!(only_1_0.a2a_settings(), effective(VERSIONS_1_0_ONLY, A2aValidation::Off));
        let only_0_3 = surface("a2a", "http://agent", Some(settings(&["0.3"], "full")));
        assert_eq!(only_0_3.a2a_settings(), effective(VERSIONS_0_3_ONLY, A2aValidation::Full));
    }

    #[test]
    fn a_partial_block_fills_the_missing_field_with_its_default() {
        let validation_only = surface("a2a", "http://agent", Some(json!({ "validation": "full" })));
        assert_eq!(validation_only.a2a_settings(), effective(SUPPORTED_VERSIONS, A2aValidation::Full));
        let versions_only = surface("a2a", "http://agent", Some(json!({ "accepted_versions": ["1.0"] })));
        assert_eq!(versions_only.a2a_settings(), effective(VERSIONS_1_0_ONLY, A2aValidation::Envelope));
    }

    /// An A2A-proxy Target takes the stored versions, both when absent, and
    /// always checks the envelope only, whatever validation level is stored.
    #[test]
    fn an_a2a_proxy_target_takes_the_stored_versions_with_envelope_validation() {
        for (stored, versions) in [
            (None, SUPPORTED_VERSIONS),
            (Some(settings(&["0.3", "1.0"], "full")), SUPPORTED_VERSIONS),
            (Some(settings(&["1.0"], "envelope")), VERSIONS_1_0_ONLY),
            (Some(settings(&["0.3"], "off")), VERSIONS_0_3_ONLY),
        ] {
            let surface = surface("a2a", "a2a-proxy://worker", stored.clone());
            assert!(surface.is_a2a_proxy_target());
            assert_eq!(surface.a2a_settings(), effective(versions, A2aValidation::Envelope), "{stored:?}");
        }
        assert_eq!(
            A2aAccessPointSettings::a2a_proxy(),
            A2aAccessPointSettings {
                accepted_versions: vec!["1.0".to_string()],
                validation: A2aValidation::Envelope,
                accepted_versions_sent: false,
            }
        );
    }

    /// Whether `accepted_versions` was present is recorded, but neither
    /// serialized nor compared.
    #[test]
    fn the_block_records_whether_accepted_versions_was_named() {
        let named: A2aAccessPointSettings = serde_json::from_value(settings(&["1.0"], "full")).unwrap();
        assert!(named.accepted_versions_sent);
        let omitted: A2aAccessPointSettings = serde_json::from_value(json!({ "validation": "full" })).unwrap();
        assert!(!omitted.accepted_versions_sent);
        assert_eq!(omitted.accepted_versions, vec!["0.3".to_string(), "1.0".to_string()]);

        assert_eq!(serde_json::to_value(&named).unwrap(), settings(&["1.0"], "full"), "the flag is not serialized");
        let constructed = A2aAccessPointSettings {
            validation: A2aValidation::Full,
            ..Default::default()
        };
        assert_eq!(omitted, constructed, "the flag is not part of equality");
    }

    #[test]
    fn the_block_round_trips_and_is_omitted_when_absent() {
        for validation in ["off", "envelope", "full"] {
            let stored = surface("a2a", "http://agent", Some(settings(&["1.0"], validation)));
            let saved = serde_json::to_value(&stored).unwrap();
            assert_eq!(saved["access_point"]["a2a"], settings(&["1.0"], validation));
        }

        let absent = serde_json::to_value(surface("a2a", "http://agent", None)).unwrap();
        assert!(
            absent["access_point"]
                .get("a2a")
                .is_none()
        );
    }

    #[test]
    fn an_unknown_field_or_validation_level_in_the_block_is_refused() {
        for a2a in [json!({"accepted_versions": ["1.0"], "versions": ["1.0"]}), json!({"validation": "strict"})] {
            let result: Result<AgentSurface, _> = serde_json::from_value(json!({
                "surface_id": "s", "name": "s",
                "access_point": {"listen_address": "127.0.0.1:8080", "route": "/agent", "protocol": "a2a", "a2a": a2a},
                "target": {"endpoint": "http://agent"}
            }));
            assert!(result.is_err(), "{a2a}");
        }
    }

    #[test]
    fn valid_settings_pass_validation() {
        for versions in [&["0.3", "1.0"][..], &["1.0"], &["0.3"], &["1.0", "0.3"]] {
            for validation in ["off", "envelope", "full"] {
                let surface = surface("a2a", "http://agent", Some(settings(versions, validation)));
                assert_eq!(surface.validate_a2a_settings(), Ok(()), "{versions:?} {validation}");
            }
        }
        assert_eq!(surface("ap2", "http://agent", Some(settings(&["1.0"], "full"))).validate_a2a_settings(), Ok(()));
        assert_eq!(surface("a2a", "http://agent", None).validate_a2a_settings(), Ok(()));
    }

    #[test]
    fn invalid_version_lists_are_refused() {
        let error = |versions: &[&str]| {
            surface("a2a", "http://agent", Some(settings(versions, "full")))
                .validate_a2a_settings()
                .unwrap_err()
        };
        assert_eq!(error(&[]), "access_point.a2a.accepted_versions must name at least one version");
        assert_eq!(
            error(&["1.0", "2.0"]),
            "access_point.a2a.accepted_versions: unsupported version '2.0' (supported: 0.3, 1.0)"
        );
        assert_eq!(error(&["1.0", "1.0"]), "access_point.a2a.accepted_versions lists '1.0' more than once");
    }

    #[test]
    fn the_block_is_refused_on_a_non_a2a_access_point() {
        for protocol in ["mcp", "didcomm"] {
            let surface = surface(protocol, "http://agent", Some(settings(&["1.0"], "full")));
            assert_eq!(
                surface.validate_a2a_settings(),
                Err("access_point.a2a requires an A2A or AP2 Access Point".to_string()),
                "{protocol}"
            );
        }
    }

    #[test]
    fn an_a2a_proxy_target_accepts_any_versions_with_envelope_validation_only() {
        assert_eq!(surface("a2a", "a2a-proxy://worker", None).validate_a2a_settings(), Ok(()));
        for versions in [&["0.3", "1.0"][..], &["1.0"], &["0.3"]] {
            assert_eq!(
                surface("a2a", "a2a-proxy://worker", Some(settings(versions, "envelope"))).validate_a2a_settings(),
                Ok(()),
                "{versions:?}"
            );
        }
        for validation in ["full", "off"] {
            let error = surface("a2a", "a2a-proxy://worker", Some(settings(&["1.0"], validation)))
                .validate_a2a_settings()
                .unwrap_err();
            assert!(error.starts_with("an A2A proxy target always checks the JSON-RPC envelope only"), "{error}");
        }
        assert!(
            surface("a2a", "a2a-proxy://worker", Some(settings(&[], "envelope")))
                .validate_a2a_settings()
                .is_err(),
            "the version list is still checked"
        );
    }

    fn with_variant_target(
        surface: AgentSurface,
        endpoint: &str,
    ) -> AgentSurface {
        let mut value = serde_json::to_value(surface).unwrap();
        value["variants"] = json!([{
            "id": "v", "alias": "other", "name": "other", "enabled": true,
            "overrides": {"target": {"endpoint": endpoint}}
        }]);
        serde_json::from_value(value).unwrap()
    }

    /// On an A2A-proxy surface with a variant that points the Target at a URL,
    /// the block's validation level configures that variant, while the proxy
    /// Target checks the envelope only. Both take the block's versions.
    #[test]
    fn the_block_configures_a_url_variant_of_an_a2a_proxy_surface() {
        let surface =
            with_variant_target(surface("a2a", "a2a-proxy://worker", Some(settings(&["0.3"], "full"))), "http://agent");
        assert!(surface.a2a_validation_applies());
        assert_eq!(surface.validate_a2a_settings(), Ok(()), "the level applies to the URL variant");

        assert_eq!(surface.a2a_settings(), effective(VERSIONS_0_3_ONLY, A2aValidation::Envelope));
        let url_variant = surface
            .resolve_variant(Some("other"))
            .unwrap();
        assert_eq!(url_variant.a2a_settings(), effective(VERSIONS_0_3_ONLY, A2aValidation::Full));
    }

    #[test]
    fn the_block_still_configures_a_disabled_url_variant_of_an_a2a_proxy_surface() {
        let mut surface =
            with_variant_target(surface("a2a", "a2a-proxy://worker", Some(settings(&["1.0"], "full"))), "http://agent");
        surface.variants[0].enabled = false;
        assert!(surface.a2a_validation_applies(), "the level comes back into use when the variant is enabled");
        assert_eq!(surface.validate_a2a_settings(), Ok(()));
    }

    #[test]
    fn the_validation_level_applies_to_nothing_when_every_target_is_an_a2a_proxy() {
        let proxies_only = with_variant_target(surface("a2a", "a2a-proxy://worker", None), "a2a-proxy://other");
        assert!(!proxies_only.a2a_validation_applies());
        assert!(!surface("a2a", "a2a-proxy://worker", None).a2a_validation_applies());
        assert!(surface("a2a", "http://agent", None).a2a_validation_applies());

        let with_block = |validation| {
            with_variant_target(
                surface("a2a", "a2a-proxy://worker", Some(settings(&["0.3"], validation))),
                "a2a-proxy://other",
            )
            .validate_a2a_settings()
        };
        assert_eq!(with_block("envelope"), Ok(()));
        assert!(
            with_block("full")
                .unwrap_err()
                .starts_with("an A2A proxy target always checks the JSON-RPC envelope only")
        );
    }

    /// A variant that points the Target at an A2A proxy is served as one, and
    /// the surface-level block of a URL base Target stays valid.
    #[test]
    fn a_variant_targeting_an_a2a_proxy_is_served_as_one() {
        let mut value =
            serde_json::to_value(surface("a2a", "http://agent", Some(settings(&["0.3", "1.0"], "full")))).unwrap();
        value["variants"] = json!([{
            "id": "v", "alias": "proxy", "name": "proxy", "enabled": true,
            "overrides": {"target": {"endpoint": "a2a-proxy://worker", "a2a_proxy_id": "worker"}}
        }]);
        let surface: AgentSurface = serde_json::from_value(value).unwrap();

        let resolved = surface
            .resolve_variant(Some("proxy"))
            .unwrap();
        assert_eq!(resolved.a2a_settings(), effective(SUPPORTED_VERSIONS, A2aValidation::Envelope));
        assert_eq!(surface.a2a_settings(), effective(SUPPORTED_VERSIONS, A2aValidation::Full));
        assert_eq!(surface.validate_a2a_settings(), Ok(()));
    }
}

#[cfg(test)]
mod transit_token_lifetime_tests {
    use super::*;
    use serde_json::json;

    fn surface_with_lifetime(lifetime_secs: Option<u64>) -> AgentSurface {
        let mut transit = json!({
            "outbound_listen_address": "http://localhost:9111",
            "points": [{ "alias": "partner", "target_endpoint": "https://partner.example" }]
        });
        if let Some(secs) = lifetime_secs {
            transit["transit_token_lifetime_secs"] = json!(secs);
        }
        serde_json::from_value(json!({
            "name": "lifetime",
            "access_point": { "listen_address": "0.0.0.0:8443", "route": "/lifetime", "protocol": "a2a" },
            "target": { "endpoint": "https://agent.internal" },
            "transit": transit
        }))
        .unwrap()
    }

    fn refusal(
        max_secs: u64,
        secs: u64,
    ) -> String {
        format!(
            "transit.transit_token_lifetime_secs must be from 30 to {max_secs} seconds, not {secs} ({max_secs} is \
             transit_token_max_lifetime_secs in gateway.json)"
        )
    }

    fn shared(surface: &AgentSurface) -> &SharedTransitConfig {
        &surface
            .transit
            .as_ref()
            .unwrap()
            .shared
    }

    #[test]
    fn transit_tokens_live_300_seconds_unless_the_surface_sets_a_lifetime() {
        let mut without_transit = surface_with_lifetime(None);
        without_transit.transit = None;

        assert_eq!(without_transit.transit_token_lifetime_secs(), 300);
        assert_eq!(surface_with_lifetime(None).transit_token_lifetime_secs(), 300);
        for secs in [30, 600, 900] {
            assert_eq!(surface_with_lifetime(Some(secs)).transit_token_lifetime_secs(), secs);
        }
    }

    /// The lifetime a Transit Point checks depends on the surface alone, held
    /// to the fixed 30 to 900 seconds, so instances with different ceilings
    /// accept each other's tokens; the Access Point issues it held to the
    /// appliance's ceiling.
    #[test]
    fn the_access_point_issues_tokens_held_to_the_appliance_ceiling() {
        for (stored, checked) in [(Some(0), 30), (Some(29), 30), (Some(901), 900), (Some(u64::MAX), 900), (None, 300)] {
            assert_eq!(surface_with_lifetime(stored).transit_token_lifetime_secs(), checked, "{stored:?}");
        }
        for (stored, max_secs, issued) in [
            (Some(600), 300, 300),
            (Some(600), 900, 600),
            (Some(60), 300, 60),
            (None, 300, 300),
            (None, 120, 120),
            (Some(10), 300, 30),
            (Some(1200), 900, 900),
            (Some(600), 0, 30),
        ] {
            assert_eq!(
                surface_with_lifetime(stored).issued_transit_token_lifetime_secs(max_secs),
                issued,
                "{stored:?} {max_secs}"
            );
        }
    }

    /// The warning for a stored lifetime the Access Point issues for another
    /// names the surface, the stored value, the bound and where it comes from.
    #[test]
    fn a_stored_lifetime_outside_the_bounds_is_reported_with_the_lifetime_its_tokens_get() {
        let named = |secs: Option<u64>| {
            let mut surface = surface_with_lifetime(secs);
            surface.surface_id = "orders".to_string();
            surface
        };
        assert_eq!(
            named(Some(10)).transit_token_lifetime_adjustment(300),
            Some(
                "Surface 'lifetime' (orders): transit.transit_token_lifetime_secs is 10, below the shortest, 30 \
                 seconds; its transit tokens live 30 seconds"
                    .to_string()
            )
        );
        assert_eq!(
            named(Some(600)).transit_token_lifetime_adjustment(300),
            Some(
                "Surface 'lifetime' (orders): transit.transit_token_lifetime_secs is 600, above \
                 transit_token_max_lifetime_secs in gateway.json (300); its transit tokens live 300 seconds"
                    .to_string()
            )
        );
        assert_eq!(
            named(Some(1200)).transit_token_lifetime_adjustment(900),
            Some(
                "Surface 'lifetime' (orders): transit.transit_token_lifetime_secs is 1200, above \
                 transit_token_max_lifetime_secs in gateway.json (900); its transit tokens live 900 seconds"
                    .to_string()
            )
        );
        for (secs, max_secs) in [(None, 30), (Some(30), 300), (Some(300), 300), (Some(900), 900)] {
            assert_eq!(named(secs).transit_token_lifetime_adjustment(max_secs), None, "{secs:?} {max_secs}");
        }
    }

    #[test]
    fn the_appliance_ceiling_must_be_a_whole_number_from_30_to_900_seconds() {
        assert_eq!(transit_token_max_lifetime_from(None), Ok(300));
        for max_secs in [30, 300, 600, 900] {
            assert_eq!(transit_token_max_lifetime_from(Some(&json!(max_secs))), Ok(max_secs), "{max_secs}");
        }
        for (max_secs, shown) in [
            (json!(0), "0"),
            (json!(29), "29"),
            (json!(901), "901"),
            (json!(u64::MAX), "18446744073709551615"),
            (json!(-1), "-1"),
            (json!(60.5), "60.5"),
            (json!("600"), "\"600\""),
            (serde_json::Value::Null, "null"),
        ] {
            assert_eq!(
                transit_token_max_lifetime_from(Some(&max_secs)),
                Err(format!(
                    "transit_token_max_lifetime_secs in gateway.json must be from 30 to 900 seconds, not {shown}"
                )),
                "{max_secs}"
            );
        }
    }

    #[test]
    fn a_transit_token_lifetime_outside_30_seconds_to_the_appliance_ceiling_is_refused() {
        for (lifetime, max_secs) in [(None, 300), (Some(30), 300), (Some(300), 300), (Some(900), 900), (Some(120), 120)]
        {
            assert_eq!(
                shared(&surface_with_lifetime(lifetime)).validate_transit_token_lifetime(max_secs),
                Ok(()),
                "{lifetime:?} {max_secs}"
            );
        }
        for (secs, max_secs) in [(0, 300), (29, 300), (301, 300), (600, 300), (121, 120), (901, 900), (u64::MAX, 900)] {
            assert_eq!(
                shared(&surface_with_lifetime(Some(secs))).validate_transit_token_lifetime(max_secs),
                Err(refusal(max_secs, secs)),
                "{secs} {max_secs}"
            );
        }
    }

    #[test]
    fn the_transit_token_lifetime_is_stored_only_when_set() {
        let unset = serde_json::to_value(surface_with_lifetime(None)).unwrap();
        assert!(
            unset["transit"]
                .get("transit_token_lifetime_secs")
                .is_none(),
            "{unset}"
        );

        let set = serde_json::to_value(surface_with_lifetime(Some(600))).unwrap();
        assert_eq!(set["transit"]["transit_token_lifetime_secs"], json!(600));
        let reloaded: AgentSurface = serde_json::from_value(set).unwrap();
        assert_eq!(reloaded.transit_token_lifetime_secs(), 600);
    }

    #[test]
    fn a_variant_takes_its_surfaces_transit_token_lifetime_and_cannot_set_its_own() {
        let refused = serde_json::from_value::<crate::config::agent_surface_variants::SharedTransitOverrides>(
            json!({ "transit_token_lifetime_secs": 900 }),
        )
        .unwrap_err();
        assert!(
            refused
                .to_string()
                .contains("unknown field `transit_token_lifetime_secs`"),
            "{refused}"
        );

        let mut surface = surface_with_lifetime(Some(600));
        surface.variants = serde_json::from_value(json!([{
            "id": "candidate", "alias": "candidate", "name": "Candidate",
            "overrides": { "transit": { "shared": { "sign_requests": false } } }
        }]))
        .unwrap();
        assert_eq!(
            surface
                .resolve_variant(Some("candidate"))
                .unwrap()
                .transit_token_lifetime_secs(),
            600
        );
    }
}

#[cfg(test)]
mod transit_point_caller_authentication_tests {
    use super::*;
    use serde_json::json;

    fn point(fields: serde_json::Value) -> TransitPoint {
        let mut point = json!({ "alias": "partner", "target_endpoint": "https://partner.example/mcp" });
        point
            .as_object_mut()
            .unwrap()
            .extend(
                fields
                    .as_object()
                    .unwrap()
                    .clone(),
            );
        serde_json::from_value(point).unwrap()
    }

    fn api_key() -> serde_json::Value {
        json!({
            "type": "api_key", "extraction": { "source": "http_header", "field": "X-API-Key" },
            "secret_id": "partner-callers"
        })
    }

    fn resource_token() -> serde_json::Value {
        json!({ "authorization": { "resource": "https://outbound.example/outbound/route/partner" } })
    }

    const NO_CALLER: &str = "Transit Point 'partner' authenticates no caller: require a transit token, set \
        source_auth or mcp_http.authorization, or set allow_unauthenticated_callers to serve callers it does not \
        authenticate";

    #[test]
    fn a_transit_point_authenticates_its_callers_with_any_one_mechanism() {
        for (case, fields) in [
            ("transit token by default", json!({})),
            ("transit token", json!({ "require_transit_token": true })),
            (
                "resource token",
                json!({ "require_transit_token": false, "protocol": "mcp", "mcp_http": resource_token() }),
            ),
            ("API key", json!({ "require_transit_token": false, "source_auth": api_key() })),
            (
                "API Key Provider",
                json!({ "require_transit_token": false, "source_auth": {
                    "type": "api_key_provider", "extraction": { "source": "http_header", "field": "X-API-Key" },
                    "agent_id": "partner-agent"
                }}),
            ),
            (
                "JWT bearer",
                json!({ "require_transit_token": false, "source_auth": {
                    "type": "jwt_bearer", "jwt_verification_strategy_id": "entra", "audiences": ["api://partner"]
                }}),
            ),
            (
                "mTLS",
                json!({ "require_transit_token": false, "source_auth": {
                    "type": "mtls", "trust": { "type": "ca", "ca_certificate_ids": ["partner-ca"] },
                    "identity_binding": { "type": "subject_cn" }
                }}),
            ),
            ("transit token and API key", json!({ "source_auth": api_key() })),
        ] {
            let point = point(fields);
            assert!(point.authenticates_callers(), "{case}");
            assert_eq!(point.unenforceable_caller_authentication(), None, "{case}");
            assert_eq!(point.validate_caller_authentication(), Ok(()), "{case}");
        }
    }

    #[test]
    fn a_transit_point_that_authenticates_no_caller_must_be_marked_open() {
        let closed = point(json!({ "require_transit_token": false }));
        assert!(!closed.authenticates_callers());
        assert_eq!(closed.unenforceable_caller_authentication(), Some(NO_CALLER.to_string()));
        assert_eq!(closed.validate_caller_authentication(), Err(NO_CALLER.to_string()));

        let open = point(json!({ "require_transit_token": false, "allow_unauthenticated_callers": true }));
        assert_eq!(open.unenforceable_caller_authentication(), None);
        assert_eq!(open.validate_caller_authentication(), Ok(()));
    }

    #[test]
    fn marking_open_a_transit_point_that_authenticates_its_callers_is_refused() {
        for fields in [
            json!({ "allow_unauthenticated_callers": true }),
            json!({ "require_transit_token": false, "allow_unauthenticated_callers": true, "source_auth": api_key() }),
        ] {
            let point = point(fields);
            assert_eq!(point.unenforceable_caller_authentication(), None, "it still authenticates its callers");
            assert_eq!(
                point.validate_caller_authentication(),
                Err("Transit Point 'partner' sets allow_unauthenticated_callers but authenticates its callers; \
                     remove it"
                    .to_string())
            );
        }
    }

    #[test]
    fn source_auth_a_transit_point_cannot_enforce_is_refused() {
        let unsupported = "Transit Point 'partner' source_auth must be api_key or api_key_provider read from an HTTP \
                           header, jwt_bearer without forward_header, or mtls";
        for (case, source_auth, expected) in [
            (
                "DID Auth",
                json!({ "type": "did_auth", "extraction": { "source": "http_header", "field": "X-Session" } }),
                unsupported,
            ),
            (
                "a forwarded JWT",
                json!({ "type": "jwt_bearer", "jwt_verification_strategy_id": "entra", "audiences": [],
                    "forward_header": true }),
                unsupported,
            ),
            (
                "an API key read from MCP _meta",
                json!({ "type": "api_key", "extraction": { "source": "mcp_meta" }, "secret_id": "partner-callers" }),
                unsupported,
            ),
        ] {
            let point = point(json!({ "require_transit_token": false, "source_auth": source_auth }));
            assert_eq!(point.unenforceable_caller_authentication(), Some(expected.to_string()), "{case}");
            assert_eq!(point.validate_caller_authentication(), Err(expected.to_string()), "{case}");
        }

        let both = point(json!({
            "require_transit_token": false, "protocol": "mcp", "mcp_http": resource_token(), "source_auth": api_key()
        }));
        let refusal = "Transit Point 'partner' sets both source_auth and mcp_http.authorization; keep one";
        assert_eq!(both.unenforceable_caller_authentication(), Some(refusal.to_string()));
        assert_eq!(both.validate_caller_authentication(), Err(refusal.to_string()));

        let no_audience = "Transit Point 'partner' source_auth jwt_bearer must name the audiences it accepts, so a \
                           token issued for another service, such as the Access Point, is refused";
        for audiences in [json!([]), json!(["", "  "])] {
            let point = point(json!({ "require_transit_token": false, "source_auth": {
                "type": "jwt_bearer", "jwt_verification_strategy_id": "entra", "audiences": audiences
            }}));
            assert_eq!(point.unenforceable_caller_authentication(), Some(no_audience.to_string()), "{audiences}");
        }
        let named = point(json!({ "require_transit_token": false, "source_auth": {
            "type": "jwt_bearer", "jwt_verification_strategy_id": "entra", "audiences": ["api://crm-transit"]
        }}));
        assert_eq!(named.unenforceable_caller_authentication(), None);
    }

    #[test]
    fn source_auth_and_the_open_flag_are_stored_only_when_set() {
        let stored = serde_json::to_value(point(json!({}))).unwrap();
        assert!(
            stored
                .get("source_auth")
                .is_none(),
            "{stored}"
        );
        assert!(
            stored
                .get("allow_unauthenticated_callers")
                .is_none(),
            "{stored}"
        );

        let stored = serde_json::to_value(point(json!({
            "require_transit_token": false, "allow_unauthenticated_callers": true
        })))
        .unwrap();
        assert_eq!(stored["allow_unauthenticated_callers"], true);
    }

    /// A stored surface whose Transit Point uses `source_auth`, on the base or
    /// only in a variant, is marked when loaded so an older release refuses it,
    /// and the mark is removed once no Transit Point uses `source_auth`.
    #[test]
    fn a_loaded_surface_is_marked_while_a_transit_point_uses_source_auth() {
        let stored = |base: serde_json::Value, variant: Option<serde_json::Value>, marked: bool| {
            let mut surface = json!({
                "name": "callers",
                "access_point": { "listen_address": "0.0.0.0:8443", "route": "/callers", "protocol": "a2a" },
                "target": { "endpoint": "https://agent.internal" },
                "transit": { "points": [base] }
            });
            if let Some(point) = variant {
                surface["variants"] = json!([{ "id": "v", "alias": "dev", "name": "dev",
                    "overrides": { "transit": { "points": [point] } } }]);
            }
            if marked {
                surface["transit_point_source_auth"] = json!(true);
            }
            surface
        };
        let keyed =
            json!({ "alias": "partner", "target_endpoint": "https://partner.example", "source_auth": api_key() });
        let tokened = json!({ "alias": "partner", "target_endpoint": "https://partner.example" });

        for (case, mut record) in [
            ("base", stored(keyed.clone(), None, false)),
            ("variant only", stored(tokened.clone(), Some(keyed.clone()), false)),
        ] {
            assert!(AgentSurface::migrate_raw_json(&mut record).unwrap(), "{case}: re-persisted");
            assert_eq!(record["transit_point_source_auth"], true, "{case}");
            let loaded: AgentSurface = serde_json::from_value(record.clone()).unwrap();
            assert!(loaded.transit_point_source_auth && loaded.has_transit_point_source_auth(), "{case}");
            let mut again = record.clone();
            assert!(!AgentSurface::migrate_raw_json(&mut again).unwrap(), "{case}: already marked");
            assert_eq!(
                serde_json::to_value(&loaded).unwrap()["transit_point_source_auth"],
                true,
                "{case}: a save keeps the mark"
            );
        }

        let mut unused = stored(tokened.clone(), None, true);
        assert!(AgentSurface::migrate_raw_json(&mut unused).unwrap());
        assert!(
            unused
                .get("transit_point_source_auth")
                .is_none(),
            "{unused}"
        );
        let mut plain = stored(tokened, None, false);
        assert!(!AgentSurface::migrate_raw_json(&mut plain).unwrap());
        assert!(
            plain
                .get("transit_point_source_auth")
                .is_none()
        );

        let mut renamed = stored(keyed, None, true);
        let marker = renamed
            .as_object_mut()
            .unwrap()
            .remove("transit_point_source_auth")
            .unwrap();
        renamed["a_field_this_release_does_not_know"] = marker;
        assert!(
            serde_json::from_value::<AgentSurface>(renamed).is_err(),
            "a surface is refused for a top-level field its release does not know, which is what makes an older \
             release refuse the mark"
        );
    }

    #[test]
    fn a_loaded_surface_warns_of_each_transit_point_whose_caller_authentication_cannot_be_enforced() {
        let surface: AgentSurface = serde_json::from_value(json!({
            "name": "callers",
            "access_point": { "listen_address": "0.0.0.0:8443", "route": "/callers", "protocol": "a2a" },
            "target": { "endpoint": "https://agent.internal" },
            "transit": {
                "outbound_listen_address": "http://localhost:9111",
                "points": [
                    { "alias": "partner", "target_endpoint": "https://partner.example", "require_transit_token": false },
                    { "alias": "open", "target_endpoint": "https://open.example", "require_transit_token": false,
                        "allow_unauthenticated_callers": true },
                    { "alias": "both", "target_endpoint": "https://both.example",
                        "allow_unauthenticated_callers": true },
                    { "alias": "keyed", "target_endpoint": "https://keyed.example", "require_transit_token": false,
                        "source_auth": api_key() }
                ]
            },
            "variants": [{ "id": "candidate", "alias": "candidate", "name": "Candidate", "overrides": {
                "transit": { "points": [
                    { "alias": "partner", "target_endpoint": "https://partner.example", "require_transit_token": false },
                    { "alias": "keyed", "target_endpoint": "https://keyed.example", "require_transit_token": false,
                        "source_auth": api_key() }
                ] }
            }}]
        }))
        .unwrap();

        assert_eq!(
            surface.validate_outbound(),
            vec![
                format!("{NO_CALLER}; every request to it is refused"),
                "Transit Point 'both' sets allow_unauthenticated_callers but authenticates its callers; remove it"
                    .to_string(),
                format!("variant 'candidate': {NO_CALLER}; every request to it is refused"),
            ]
        );
    }
}
