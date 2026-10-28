//! Governance audit records: their shape, the builders call sites use, and
//! reading the VP Audit Log.
//!
//! Records are submitted through [`audit`] to the producer in
//! [`crate::audit::producer`], which journals them for every sink that
//! selects them. The VP Audit Log sink writes them to
//! `{log_directory}/delegation-audit.jsonl`, or
//! `_storage/audit/delegation-audit.jsonl` if no log directory is configured.

use crate::audit::events::{
    Actor, AuthScheme, DelegationFailureReason, IdentityBindingFailure, PolicyChangeAction, PolicyChangeSource,
    PolicyField, PolicyMode, PolicySlot, PolicyTargetKind, RateLimitScope, RefusalReason, RejectionReason,
    RejectionStage, RequestFailureOutcome, TargetKind,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;
use tracing::{error, info, warn};

use crate::audit::pipeline::PipelineControl;
use crate::metrics::backends::prometheus::set_audit_pipeline_started;
use crate::server::mode::ServerMode;

/// Global audit file path — for reading the log
static AUDIT_PATH: OnceLock<PathBuf> = OnceLock::new();

/// The audit pipeline, run only while the node is Active.
static AUDIT_PIPELINE: OnceLock<PipelineControl> = OnceLock::new();

/// How often a node waiting for the journal tries to take it.
const AUDIT_JOURNAL_RETRY: Duration = Duration::from_secs(5);

/// Whether any sink selects `vp_injected`, so identity-binding VP injections
/// should be recorded.
pub fn identity_binding_vp_audit_enabled() -> bool {
    crate::audit::producer::producer().wants("vp_injected")
}

/// Caller context captured from source authentication
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct AuditCallerContext {
    /// Authentication method used (e.g. "jwt_bearer", "api_key", "did_auth")
    pub auth_method: String,
    /// `iss` claim (JWT issuer)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// `aud` claim (JWT audience)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// `sub` claim (JWT subject)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Management-API personal access token id, when the caller authenticated
    /// with a PAT rather than a console session. Attributes a management action
    /// (e.g. a delegation-vault revoke) to the exact token used.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub token_id: Option<String>,
    /// Raw caller email captured for administrator-only audit evidence.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub email: Option<String>,
    /// Raw caller display name captured for administrator-only audit evidence.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
    /// Legacy redacted email field retained only to read pre-raw-evidence audit rows.
    /// New events write `email`; remove this after a documented audit-retention window.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub email_redacted: Option<String>,
    /// Legacy redacted name field retained only to read pre-raw-evidence audit rows.
    /// New events write `name`; remove this after a documented audit-retention window.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name_redacted: Option<String>,
    /// SHA-256 fingerprint (hex, lowercase) of the presented client certificate. mTLS only.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mtls_fingerprint: Option<String>,
    /// RFC 4514 distinguished name of the certificate subject. mTLS only.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mtls_subject_dn: Option<String>,
    /// RFC 4514 distinguished name of the certificate issuer. mTLS only.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mtls_issuer_dn: Option<String>,
    /// How the peer cert reached the gateway: `"direct"` (handshake) or
    /// `"forwarded"` (trusted proxy header). mTLS only.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mtls_source: Option<String>,
}

/// A delegation vault audit event
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct DelegationAuditEvent {
    /// Unique id of this record (UUID v4). Lets a sink recognise a record
    /// delivered again. Absent on records stored before it existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    /// ISO-8601 timestamp
    pub timestamp: String,
    /// The type of audit event
    pub event: DelegationAuditAction,
    /// Agent endpoint used as vault namespace key (equals target_endpoint)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_did: Option<String>,
    /// Actual DID identity of the agent (e.g. did:webvh:...)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_identity_did: Option<String>,
    /// SHA-256 hash of the user's identity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_identity_hash: Option<String>,
    /// Credential provider ID (machine-readable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    /// Human-readable provider name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
    /// Channel config ID where the action originated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surface_id: Option<String>,
    /// Human-readable channel name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_name: Option<String>,
    /// Target endpoint the channel proxies to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_endpoint: Option<String>,
    /// Protocol of the channel (a2a, mcp, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// OAuth scopes involved
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    /// Delegation token ID (for token-specific events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    /// How the credential was injected (bearer_header, custom_header, meta)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inject_as: Option<String>,
    /// Whether the operation traversed the fabric (G2G)
    #[serde(default)]
    pub via_fabric: bool,
    /// Caller identity context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller: Option<AuditCallerContext>,
    /// MCP tool name (if this was an MCP tool call)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_tool_name: Option<String>,
    /// VP JWT injected into the upstream response (if identity VP was sent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vp_jwt: Option<String>,
    /// SHA-256 fingerprint of the VP JWT (`sha256:<hex>`). Lets verifiers tie
    /// this record to the exact signed VP that was injected for the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vp_fingerprint: Option<String>,
    /// Request trace ID — correlates all audit events for the same request
    /// (policy decisions, VP injection, credential delegation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Id of the gateway request that produced the record: 16 lowercase hex
    /// characters, one per request. Several records of one request share it,
    /// and an Access Point request and the Transit Point requests it triggers
    /// each have their own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Additional context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Serde default for `PolicyDecision.flow` so pre-existing audit entries (all of
/// which were access-point/ingress decisions) deserialize correctly.
fn default_policy_flow() -> String {
    "access_point".to_string()
}

/// The payment rail (protocol) a [`PaymentEventDetails`] belongs to. Adding a
/// new rail (e.g. a future settlement protocol) is a single enum variant plus a
/// call to the shared [`record_payment_event`] seam — the audit shape itself is
/// protocol-independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentRail {
    /// x402 HTTP paywall.
    X402,
    /// Machine Payments Protocol.
    Mpp,
}

/// A stage in the protocol-independent payment lifecycle. Every rail maps its
/// own internal states onto this canonical vocabulary so the end-to-end audit
/// trail reads the same regardless of protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentStage {
    /// A payment-required (402) challenge was issued to the caller.
    ChallengeIssued,
    /// A presented payment credential is about to be verified.
    VerifyAttempt,
    /// Payment verified successfully.
    Verified,
    /// Payment verification failed (invalid or absent credential).
    Failed,
    /// Funds settled on-chain / with the payment processor.
    Settled,
    /// Settlement failed after a successful verification.
    SettlementFailed,
}

/// Protocol-independent payment lifecycle event. Emitted at every stage of a
/// payment (challenge → verify → settle) for **every** rail (x402, MPP, and
/// future protocols), so the whole end-to-end payment interaction is captured in
/// one audit trail — not only the delegated leg. When the payment was relayed to
/// a remote gateway over the fabric (Model B delegation) `delegated` is true and
/// the remote ids / status are populated; correlation with the remote gateway's
/// own trail is via the shared top-level `trace_id`.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct PaymentEventDetails {
    /// Which payment protocol produced the event.
    pub rail: PaymentRail,
    /// Canonical lifecycle stage.
    pub stage: PaymentStage,
    /// The rail's transaction / correlation id (x402 correlation_id, MPP record id).
    pub transaction_id: String,
    /// Human-readable amount, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    /// Currency / asset / settlement network, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    /// Payment method / scheme, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Payer identifier (from-address / payer DID), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    /// Failure detail for `failed` / `settlement_failed` stages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// True when the payment was relayed to a remote payment gateway over the
    /// fabric (Model B delegation) rather than enforced locally.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub delegated: bool,
    /// Remote payment gateway id (`fabric://{gateway_id}/...`), delegation only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_gateway_id: Option<String>,
    /// Remote payment surface id (`fabric://.../{surface_id}`), delegation only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_surface_id: Option<String>,
    /// HTTP-style status from the remote gateway's response, delegation only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_status: Option<u16>,
}

/// The surface, gateway or appliance-wide set a policy is attached to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct PolicyTarget {
    pub kind: PolicyTargetKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// One management change to a policy definition or to where a policy applies,
/// shared by every policy change event. The policy fields carry the names and
/// formats of [`DelegationAuditAction::PolicyDecision`], so a change joins to the
/// decisions it causes. Never carries the Rego text, the sample input or a
/// request body.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct PolicyChangeDetails {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_definition_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,
    /// `gateway` or `agent_surface`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_content_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_policy_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_policy_content_hash: Option<String>,
    /// The parts of the definition an update changed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed: Vec<PolicyField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<PolicyTarget>,
    /// The decision scope the slot produces (`PolicyScope::as_str`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<PolicySlot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transit_point: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_tool_name: Option<String>,
    /// The MCP tool gate's name, or its id when it has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plane: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<PolicyMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_mode: Option<PolicyMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_enabled: Option<bool>,
    pub actor: Actor,
    pub source: PolicyChangeSource,
    /// On a refusal: the change that was attempted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<PolicyChangeAction>,
    /// On a refusal: the HTTP status the caller received.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<RefusalReason>,
}

impl PolicyChangeDetails {
    /// A change by `actor` through `source` with every other field unset.
    pub fn new(
        actor: Actor,
        source: PolicyChangeSource,
    ) -> Self {
        Self {
            policy_definition_id: None,
            policy_name: None,
            policy_type: None,
            policy_version: None,
            policy_content_hash: None,
            previous_policy_version: None,
            previous_policy_content_hash: None,
            changed: Vec::new(),
            target: None,
            scope: None,
            slot: None,
            variant: None,
            transit_point: None,
            mcp_tool_name: None,
            gate: None,
            plane: None,
            mode: None,
            previous_mode: None,
            enabled: None,
            previous_enabled: None,
            actor,
            source,
            action: None,
            status: None,
            reason: None,
        }
    }
}

/// The type of delegation audit action
// Records are built only for wanted events and serialized straight away, so
// the size of the `PolicyDecision` variant costs nothing worth boxing for.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationAuditAction {
    /// User granted OAuth consent — token stored in vault
    ConsentGranted,
    /// A cached token was injected into an outbound request
    TokenInjected,
    /// An expired token was refreshed and injected
    TokenRefreshed,
    /// Token refresh failed — consent required again
    RefreshFailed,
    /// A consent_required signal was returned to the caller
    ConsentRequired,
    /// A token was revoked via management API
    TokenRevoked,
    /// All tokens for a user were revoked
    UserTokensRevoked,
    /// Token lookup found no match
    TokenNotFound,
    /// A Verifiable Presentation was injected into the response
    VpInjected,
    /// An MCP `elicitation/create` request was sent to the client
    ElicitationSent,
    /// Client returned `action: "accept"` on the elicitation
    ElicitationAccepted,
    /// Client returned `action: "decline"`
    ElicitationDeclined,
    /// Client returned `action: "cancel"`
    ElicitationCancelled,
    /// No response within `elicit_timeout_secs`
    ElicitationTimedOut,
    /// OPA policy decision (allow or deny)
    PolicyDecision {
        scope: String,
        /// Which request flow produced the decision: `access_point` |
        /// `transit_point` | `fabric`. Distinguishes ingress from egress.
        #[serde(default = "default_policy_flow")]
        flow: String,
        policy_id: String,
        /// Resolved human-readable policy name (operator-assigned definition
        /// name); falls back to `policy_id` when unset.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy_name: Option<String>,
        /// Stored policy-definition record id (UUID), when the policy is backed
        /// by a definition — links the entry to the policy record.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy_definition_id: Option<String>,
        decision: String,
        deny_reason: Option<String>,
        surface_id: Option<String>,
        caller_did: Option<String>,
        http_method: Option<String>,
        http_path: Option<String>,
        /// Monotonic version of the enforced policy revision, when versioned.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy_version: Option<u32>,
        /// `sha256:<hex>` content hash of the exact Rego enforced (attestation).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy_content_hash: Option<String>,
        /// Tools a `tools/list` filter took out of the catalog the caller
        /// sees (scope `mcp_tool_list`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        removed_tools: Option<Vec<String>>,
    },
    /// TRQP trust-check outcome. `authority_id` / `entity_id` are
    /// `Option<String>` and omitted from the JSONL on the target-leg
    /// "unavailable" pre-check paths (`AGENT_CARD_UNAVAILABLE`,
    /// `TRUST_REGISTRY_METADATA_UNAVAILABLE`) — matching the wire shape
    /// of [`crate::trust_registry_verification::trust_check_element::TrustCheckResult`].
    TrustCheck {
        leg: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authority_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        entity_id: Option<String>,
        ok: bool,
        error_code: Option<String>,
    },
    /// Trace terminated at this surface's egress. Records the own → downstream
    /// trace mapping so an operator can bridge the terminated trace from this
    /// gateway's own records — the incoming trace never crosses the boundary.
    TraceTerminated {
        /// This gateway's own trace for the request (its audit + caller-facing leg).
        own_trace_id: String,
        /// The fresh trace forwarded downstream (what the next hop sees).
        downstream_trace_id: String,
        /// Which request flow terminated the trace: `access_point` |
        /// `transit_point` | `fabric`.
        flow: String,
    },
    /// Protocol-independent payment lifecycle event (x402, MPP, …). Covers the
    /// whole challenge → verify → settle flow for both locally-enforced payments
    /// and payments delegated to a remote gateway over the fabric (in which case
    /// `delegated` is true and the remote ids / status are populated). Boxed to
    /// keep the enum small.
    PaymentEvent(Box<PaymentEventDetails>),
    /// Source authentication failed. `blocking` is false when the failure was
    /// handed to policy instead of refusing the request.
    AuthFailed {
        scheme: AuthScheme,
        reason: String,
        blocking: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_ip: Option<String>,
    },
    RateLimited {
        scope: RateLimitScope,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_ms: Option<u64>,
    },
    RequestRejected {
        stage: RejectionStage,
        reason: RejectionReason,
        /// The HTTP status the caller received. Legacy MCP refuses a malformed
        /// request with 200 and a JSON-RPC error, so read it with `rpc_error_code`.
        http_status: u16,
        /// The JSON-RPC error code the caller received, when the refusal was one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rpc_error_code: Option<i64>,
        /// On `unknown_variant` only: the alias the URL named, cut to the
        /// longest alias a variant can have. Caller-chosen text.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        requested_variant: Option<String>,
    },
    IdentityBindingFailed {
        outcome: IdentityBindingFailure,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_did: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        issuer_gateway: Option<String>,
        /// Verification-failure detail. Never carries signed VP material.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_detail: Option<String>,
    },
    IdentityBindingVerified {
        agent_did: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        issuer_gateway: Option<String>,
        /// `gateway_attested` or `caller_credential_chained`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        assurance: Option<String>,
    },
    DelegationFailed {
        reason: DelegationFailureReason,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider_id: Option<String>,
    },
    RequestFailed {
        outcome: RequestFailureOutcome,
        target_kind: TargetKind,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        upstream_status: Option<u16>,
        latency_ms: u64,
    },
    RequestCompleted {
        target_kind: TargetKind,
        upstream_status: u16,
        latency_ms: u64,
        request_bytes: u64,
        response_bytes: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ucp_op: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        variant_alias: Option<String>,
    },
    /// A policy definition was created.
    PolicyCreated(Box<PolicyChangeDetails>),
    /// A policy definition was changed (a new version).
    PolicyUpdated(Box<PolicyChangeDetails>),
    /// A policy definition was deleted.
    PolicyDeleted(Box<PolicyChangeDetails>),
    /// A policy now applies at a slot of a surface, gateway or global plane.
    PolicyAttached(Box<PolicyChangeDetails>),
    /// A policy no longer applies at a slot.
    PolicyDetached(Box<PolicyChangeDetails>),
    /// An existing attachment's mode or enabled state changed.
    PolicyAttachmentChanged(Box<PolicyChangeDetails>),
    /// A policy change was refused; `action` names the change attempted.
    PolicyChangeRefused(Box<PolicyChangeDetails>),
}

#[derive(Debug, Deserialize)]
struct EmbeddedPolicyDecisionEvidence {
    scope: String,
    #[serde(default)]
    flow: Option<String>,
    #[serde(default)]
    policy_id: Option<String>,
    #[serde(default)]
    policy_definition_id: Option<String>,
    #[serde(default)]
    surface_id: Option<String>,
    #[serde(default)]
    http_method: Option<String>,
    #[serde(default)]
    http_path: Option<String>,
    #[serde(default)]
    policy_version: Option<u32>,
    #[serde(default)]
    policy_content_hash: Option<String>,
}

struct TracePolicyDecisionEvidence {
    trace_id: String,
    decision: EmbeddedPolicyDecisionEvidence,
}

impl DelegationAuditAction {
    /// Whether this action belongs to the VP Audit Log (`/v1/audit`) rather
    /// than the Credential Delegation Audit Log. Policy, trust, trace,
    /// authentication, identity binding and request outcomes are surfaced
    /// there, so the delegation log filters them out.
    pub fn is_vp_audit(&self) -> bool {
        matches!(
            self,
            Self::PolicyDecision { .. }
                | Self::TrustCheck { .. }
                | Self::TraceTerminated { .. }
                | Self::AuthFailed { .. }
                | Self::RateLimited { .. }
                | Self::RequestRejected { .. }
                | Self::IdentityBindingFailed { .. }
                | Self::IdentityBindingVerified { .. }
                | Self::RequestFailed { .. }
                | Self::RequestCompleted { .. }
                | Self::PolicyCreated(_)
                | Self::PolicyUpdated(_)
                | Self::PolicyDeleted(_)
                | Self::PolicyAttached(_)
                | Self::PolicyDetached(_)
                | Self::PolicyAttachmentChanged(_)
                | Self::PolicyChangeRefused(_)
        )
    }
}

fn decode_jwt_payload(jwt: &str) -> Option<Value> {
    let payload = jwt.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn decode_nested_jwts(
    value: Value,
    depth: usize,
) -> Value {
    if depth > 5 {
        return value;
    }
    match value {
        Value::String(value) => decode_jwt_payload(&value)
            .map(|decoded| decode_nested_jwts(decoded, depth + 1))
            .unwrap_or(Value::String(value)),
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(|value| decode_nested_jwts(value, depth))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, decode_nested_jwts(value, depth)))
                .collect(),
        ),
        other => other,
    }
}

fn decode_vp_value(vp: &str) -> Option<Value> {
    decode_jwt_payload(vp)
        .or_else(|| serde_json::from_str(vp).ok())
        .map(|value| decode_nested_jwts(value, 0))
}

fn collect_policy_decisions(
    value: &Value,
    out: &mut Vec<EmbeddedPolicyDecisionEvidence>,
) {
    match value {
        Value::Object(map) => {
            if let Some(Value::Array(decisions)) = map.get("policyDecisions") {
                for decision in decisions {
                    if let Ok(decision) = serde_json::from_value::<EmbeddedPolicyDecisionEvidence>(decision.clone()) {
                        out.push(decision);
                    }
                }
            }
            for child in map.values() {
                collect_policy_decisions(child, out);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_policy_decisions(value, out);
            }
        }
        _ => {}
    }
}

fn embedded_decision_matches(
    embedded: &EmbeddedPolicyDecisionEvidence,
    scope: &str,
    flow: &str,
    policy_id: &str,
    policy_definition_id: Option<&str>,
    surface_id: Option<&str>,
    http_method: Option<&str>,
    http_path: Option<&str>,
) -> bool {
    if embedded.scope != scope
        || embedded
            .flow
            .as_deref()
            .unwrap_or("access_point")
            != flow
    {
        return false;
    }
    if let Some(definition_id) = policy_definition_id {
        if embedded
            .policy_definition_id
            .as_deref()
            != Some(definition_id)
        {
            return false;
        }
    } else if embedded.policy_id.as_deref() != Some(policy_id) {
        return false;
    }
    if let (Some(expected), Some(actual)) = (surface_id, embedded.surface_id.as_deref())
        && expected != actual
    {
        return false;
    }
    if let (Some(expected), Some(actual)) = (
        http_method,
        embedded
            .http_method
            .as_deref(),
    ) && expected != actual
    {
        return false;
    }
    if let (Some(expected), Some(actual)) = (http_path, embedded.http_path.as_deref())
        && expected != actual
    {
        return false;
    }
    embedded
        .policy_version
        .is_some()
        || embedded
            .policy_content_hash
            .is_some()
}

fn enrich_policy_decisions_from_signed_vps(events: &mut [DelegationAuditEvent]) {
    let mut embedded_decisions = Vec::new();
    for event in events.iter() {
        let Some(trace_id) = event.trace_id.clone() else {
            continue;
        };
        let Some(vp_jwt) = event.vp_jwt.as_deref() else {
            continue;
        };
        let Some(value) = decode_vp_value(vp_jwt) else {
            continue;
        };
        let mut decisions = Vec::new();
        collect_policy_decisions(&value, &mut decisions);
        embedded_decisions.extend(
            decisions
                .into_iter()
                .map(|decision| TracePolicyDecisionEvidence {
                    trace_id: trace_id.clone(),
                    decision,
                }),
        );
    }

    if embedded_decisions.is_empty() {
        return;
    }

    for event in events.iter_mut() {
        let Some(trace_id) = event.trace_id.as_deref() else {
            continue;
        };
        let DelegationAuditAction::PolicyDecision {
            scope,
            flow,
            policy_id,
            policy_definition_id,
            surface_id,
            http_method,
            http_path,
            policy_version,
            policy_content_hash,
            ..
        } = &mut event.event
        else {
            continue;
        };
        if policy_version.is_some() && policy_content_hash.is_some() {
            continue;
        }
        if let Some(embedded) = embedded_decisions
            .iter()
            .find(|embedded| {
                embedded.trace_id == trace_id
                    && embedded_decision_matches(
                        &embedded.decision,
                        scope,
                        flow,
                        policy_id,
                        policy_definition_id.as_deref(),
                        surface_id.as_deref(),
                        http_method.as_deref(),
                        http_path.as_deref(),
                    )
            })
        {
            if policy_version.is_none() {
                *policy_version = embedded
                    .decision
                    .policy_version;
            }
            if policy_content_hash.is_none() {
                *policy_content_hash = embedded
                    .decision
                    .policy_content_hash
                    .clone();
            }
        }
    }
}

/// Sets up the audit pipeline with the VP Audit Log at
/// `{log_directory}/delegation-audit.jsonl` and the journal next to it, and
/// starts it unless the node is in Standby: only the Active node writes the
/// journal (see [`set_audit_pipeline_mode`]). Call once at startup from the
/// orchestrator.
pub async fn init_audit_logger(log_directory: Option<&str>) {
    let dir = log_directory
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("_storage/audit"));
    let audit_path = dir.join("delegation-audit.jsonl");
    if AUDIT_PATH
        .set(audit_path.clone())
        .is_err()
    {
        warn!(target: "credential_delegation", "Audit pipeline already set up");
        return;
    }
    let control = AUDIT_PIPELINE.get_or_init(|| PipelineControl::process_wide(dir, audit_path));
    if crate::server::mode::is_standby() {
        set_audit_pipeline_started(false);
        info!(target: "credential_delegation", "Standby mode: audit pipeline not started until the node becomes active");
        return;
    }
    start_audit_pipeline(control).await;
}

/// Follows the node's mode: an Active node runs the audit pipeline, and a
/// Standby node stops it, releasing the journal for the node taking over. A
/// node becoming Active first re-reads the dashboard settings and forgets its
/// cached integrations (see [`crate::audit::sources::reload_sources`]), so the
/// sinks the pipeline builds as it starts follow what is stored now.
pub async fn set_audit_pipeline_mode(mode: ServerMode) {
    let Some(control) = AUDIT_PIPELINE.get() else {
        return;
    };
    match mode {
        ServerMode::Active => {
            crate::audit::sources::reload_sources().await;
            start_audit_pipeline(control).await;
        }
        ServerMode::Standby => {
            control.stop().await;
            set_audit_pipeline_started(false);
            info!(target: "credential_delegation", "Standby mode: audit pipeline stopped");
        }
    }
}

/// Builds the audit sinks and starts the pipeline. While the sinks cannot be
/// built, or another writer still has the journal open (a node that has not
/// finished stepping down), keeps trying in the background until it starts
/// or the pipeline is stopped for Standby.
async fn start_audit_pipeline(control: &'static PipelineControl) {
    let epoch = control.epoch();
    match control.try_start().await {
        Ok(()) => audit_pipeline_started(),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            set_audit_pipeline_started(false);
            warn!(
                target: "credential_delegation",
                error = %e,
                "Audit pipeline cannot start yet; starting it once it can"
            );
            tokio::spawn(async move {
                match control
                    .start_when_free(AUDIT_JOURNAL_RETRY, &epoch)
                    .await
                {
                    Ok(true) => audit_pipeline_started(),
                    Ok(false) => {}
                    Err(e) => audit_pipeline_failed(&e),
                }
            });
        }
        Err(e) => audit_pipeline_failed(&e),
    }
}

fn audit_pipeline_started() {
    set_audit_pipeline_started(true);
    if let Some(path) = AUDIT_PATH.get() {
        info!(target: "credential_delegation", path = %path.display(), "Audit pipeline started");
    }
}

fn audit_pipeline_failed(e: &std::io::Error) {
    set_audit_pipeline_started(false);
    error!(
        target: "credential_delegation",
        error = %e,
        "Failed to start the audit pipeline; no audit records will be kept or forwarded"
    );
}

/// Whether any audit sink selects `category`. For records whose building
/// needs `.await`; otherwise use [`emit`].
pub fn wants(category: &str) -> bool {
    crate::audit::producer::producer().wants(category)
}

/// Submits a record built after [`wants`] returned true. Non-blocking.
pub fn submit(event: DelegationAuditEvent) {
    crate::audit::producer::producer().submit(event);
}

/// Builds an audit record with `build` and submits it, only when an audit sink
/// selects `category`. Non-blocking; returns at once.
pub fn emit(
    category: &'static str,
    build: impl FnOnce() -> DelegationAuditEvent,
) {
    crate::audit::producer::producer().emit(category, build);
}

/// Convenience: build an audit event with common fields pre-filled
pub(crate) fn new_event_id() -> Option<String> {
    Some(uuid::Uuid::new_v4().to_string())
}

pub fn audit_event(
    action: DelegationAuditAction,
    agent_did: Option<&str>,
    user_hash: Option<&str>,
    provider_id: Option<&str>,
    channel_id: Option<&str>,
) -> DelegationAuditEvent {
    DelegationAuditEvent {
        event_id: new_event_id(),
        timestamp: Utc::now().to_rfc3339(),
        event: action,
        agent_did: agent_did.map(String::from),
        agent_identity_did: None,
        user_identity_hash: user_hash.map(String::from),
        provider_id: provider_id.map(String::from),
        provider_name: None,
        surface_id: channel_id.map(String::from),
        channel_name: None,
        target_endpoint: None,
        protocol: None,
        scopes: None,
        token_id: None,
        inject_as: None,
        via_fabric: false,
        caller: None,
        mcp_tool_name: None,
        vp_jwt: None,
        vp_fingerprint: None,
        trace_id: None,
        request_id: None,
        detail: None,
    }
}

/// Record a protocol-independent payment lifecycle event.
///
/// This is the single seam every payment rail (x402, MPP, and future protocols)
/// calls to append a [`PaymentEventDetails`] to the shared audit trail. It builds
/// the surrounding [`DelegationAuditEvent`], stamps the surface / channel /
/// trace-id / fabric context, and dispatches through the fire-and-forget
/// [`audit`] sink — so wiring a new stage or a new rail is a single call here.
pub fn record_payment_event(
    details: PaymentEventDetails,
    surface_id: Option<&str>,
    channel_name: Option<&str>,
    trace_id: Option<&str>,
    via_fabric: bool,
    vc_jwt: Option<&str>,
) {
    emit("payment", || {
        let mut event =
            audit_event(DelegationAuditAction::PaymentEvent(Box::new(details)), None, None, None, surface_id);
        event.channel_name = channel_name.map(String::from);
        event.trace_id = trace_id.map(String::from);
        event.via_fabric = via_fabric;
        if let Some(jwt) = vc_jwt {
            event.vp_jwt = Some(jwt.to_string());
            event.vp_fingerprint = Some(vp_fingerprint(jwt));
        }
        event
    });
}

/// One identity VP injected into a proxied request or response.
pub struct VpInjection<'a> {
    pub agent_did: Option<&'a str>,
    pub user_hash: Option<&'a str>,
    pub surface_id: Option<&'a str>,
    pub channel_name: &'a str,
    pub target_endpoint: &'a str,
    pub protocol: &'a str,
    pub mcp_tool_name: Option<&'a str>,
    pub vp_jwt: &'a str,
    /// The request's own trace id, which groups the record with its policy
    /// decisions.
    pub trace_id: Option<&'a str>,
    /// Where the VP went, e.g. `request_path` or `response_path`.
    pub detail: String,
    /// The authenticated caller; the request's audit caller when `None`.
    pub caller: Option<AuditCallerContext>,
    pub via_fabric: bool,
}

/// The `vp_injected` record for `injection`: every site records the same
/// fields, including the VP's fingerprint.
pub fn vp_injected_event(injection: VpInjection<'_>) -> DelegationAuditEvent {
    let mut event = audit_event(
        DelegationAuditAction::VpInjected,
        injection.agent_did,
        injection.user_hash,
        None,
        injection.surface_id,
    );
    event.agent_identity_did = injection
        .agent_did
        .map(str::to_string);
    event.channel_name = Some(
        injection
            .channel_name
            .to_string(),
    );
    event.target_endpoint = Some(
        injection
            .target_endpoint
            .to_string(),
    );
    event.protocol = Some(injection.protocol.to_string());
    event.mcp_tool_name = injection
        .mcp_tool_name
        .map(str::to_string);
    event.vp_jwt = Some(injection.vp_jwt.to_string());
    event.vp_fingerprint = Some(vp_fingerprint(injection.vp_jwt));
    event.trace_id = injection
        .trace_id
        .map(str::to_string);
    event.detail = Some(injection.detail);
    event.caller = injection
        .caller
        .or_else(crate::audit::context::current_caller);
    event.via_fabric = injection.via_fabric;
    event
}

/// Compute a `sha256:<hex>` fingerprint for a VP JWT string.
pub fn vp_fingerprint(vp_jwt: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(vp_jwt.as_bytes());
    format!("sha256:{}", hex::encode(hash))
}

/// Build an `AuditCallerContext` from a source-auth identity
pub fn build_caller_context(identity: &crate::source_auth::AuthenticatedIdentity) -> AuditCallerContext {
    match identity {
        crate::source_auth::AuthenticatedIdentity::JwtBearer { subject, claims } => {
            let iss = claims
                .get("iss")
                .and_then(|v| v.as_str())
                .map(String::from);
            let aud = claims
                .get("aud")
                .and_then(|v| {
                    if let Some(s) = v.as_str() {
                        Some(s.to_string())
                    } else if let Some(arr) = v.as_array() {
                        Some(
                            arr.iter()
                                .filter_map(|a| a.as_str())
                                .collect::<Vec<_>>()
                                .join(", "),
                        )
                    } else {
                        None
                    }
                });
            let email = claims
                .get("email")
                .and_then(|v| v.as_str());
            let name = claims
                .get("name")
                .and_then(|v| v.as_str());
            AuditCallerContext {
                auth_method: "jwt_bearer".to_string(),
                iss,
                aud,
                sub: Some(subject.clone()),
                token_id: None,
                email: email.map(String::from),
                name: name.map(String::from),
                email_redacted: None,
                name_redacted: None,
                mtls_fingerprint: None,
                mtls_subject_dn: None,
                mtls_issuer_dn: None,
                mtls_source: None,
            }
        }
        crate::source_auth::AuthenticatedIdentity::ApiKey { key_name } => AuditCallerContext {
            auth_method: "api_key".to_string(),
            iss: None,
            aud: None,
            sub: Some(key_name.clone()),
            token_id: None,
            email: None,
            name: None,
            email_redacted: None,
            name_redacted: None,
            mtls_fingerprint: None,
            mtls_subject_dn: None,
            mtls_issuer_dn: None,
            mtls_source: None,
        },
        crate::source_auth::AuthenticatedIdentity::DidAuth { did } => AuditCallerContext {
            auth_method: "did_auth".to_string(),
            iss: None,
            aud: None,
            sub: Some(did.clone()),
            token_id: None,
            email: None,
            name: None,
            email_redacted: None,
            name_redacted: None,
            mtls_fingerprint: None,
            mtls_subject_dn: None,
            mtls_issuer_dn: None,
            mtls_source: None,
        },
        crate::source_auth::AuthenticatedIdentity::Mtls {
            principal,
            fingerprint,
            subject_dn,
            issuer_dn,
            source,
            ..
        } => AuditCallerContext {
            auth_method: "mtls".to_string(),
            iss: Some(issuer_dn.clone()),
            aud: None,
            sub: Some(principal.clone()),
            token_id: None,
            email: None,
            name: None,
            email_redacted: None,
            name_redacted: None,
            mtls_fingerprint: Some(fingerprint.clone()),
            mtls_subject_dn: Some(subject_dn.clone()),
            mtls_issuer_dn: Some(issuer_dn.clone()),
            mtls_source: Some(match source {
                crate::source_auth::models::PeerCertSource::DirectTls => "direct".to_string(),
                crate::source_auth::models::PeerCertSource::Forwarded => "forwarded".to_string(),
            }),
        },
    }
}

/// Build an `AuditCallerContext` from the caller context a transit token
/// carries onto a Transit Point: the allowlisted `sub`, `email` and `name`
/// claims captured for Workload Binding, with the inbound caller's DID as the
/// subject when no `sub` claim was carried. `None` when the token names no caller.
pub fn transit_caller_context(claims: &crate::proxy::transit_token::TransitTokenClaims) -> Option<AuditCallerContext> {
    let field = |name: &str| {
        claims
            .caller_context_fields
            .get(name)
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    };
    let sub = field("sub").or_else(|| claims.sub.clone());
    let email = field("email");
    let name = field("name");
    if sub.is_none() && email.is_none() && name.is_none() {
        return None;
    }
    Some(AuditCallerContext {
        auth_method: "transit_token".to_string(),
        iss: None,
        aud: None,
        sub,
        token_id: None,
        email,
        name,
        email_redacted: None,
        name_redacted: None,
        mtls_fingerprint: None,
        mtls_subject_dn: None,
        mtls_issuer_dn: None,
        mtls_source: None,
    })
}

/// Build an `AuditCallerContext` from the caller a received identity binding
/// discloses in `workloadBinding.caller`: the `sub`, `email` and `name` the
/// sending gateway chose to include, with that gateway as the issuer. `None`
/// unless a trust anchor vouched for the binding and it names a caller.
pub fn binding_caller_context(binding: &crate::surface_context::IdentityBindingContext) -> Option<AuditCallerContext> {
    if !binding.verified {
        return None;
    }
    let fields = &binding
        .caller
        .as_ref()?
        .fields;
    let field = |name: &str| {
        fields
            .get(name)
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    };
    let (sub, email, name) = (field("sub"), field("email"), field("name"));
    if sub.is_none() && email.is_none() && name.is_none() {
        return None;
    }
    Some(AuditCallerContext {
        auth_method: "workload_binding".to_string(),
        iss: Some(binding.gateway_did.clone()),
        aud: None,
        sub,
        token_id: None,
        email,
        name,
        email_redacted: None,
        name_redacted: None,
        mtls_fingerprint: None,
        mtls_subject_dn: None,
        mtls_issuer_dn: None,
        mtls_source: None,
    })
}

/// Build an `AuditCallerContext` for a management-API caller (delegation-vault
/// management routes). The caller is a console operator authenticated by the
/// session/PAT middleware, so `sub` is the authenticated `user_id` and, when the
/// request arrived on a personal access token, `token_id` records the exact PAT.
///
/// Returns `None` when there is no authenticated principal, so a mutating handler
/// can fail closed rather than record an unattributed revoke.
pub fn management_caller_context(
    user_id: Option<&str>,
    pat_token_id: Option<&str>,
) -> Option<AuditCallerContext> {
    let user_id = user_id.filter(|id| !id.is_empty())?;
    let auth_method = if pat_token_id.is_some() {
        "access_token"
    } else {
        "session"
    };
    Some(AuditCallerContext {
        auth_method: auth_method.to_string(),
        iss: None,
        aud: None,
        sub: Some(user_id.to_string()),
        token_id: pat_token_id.map(String::from),
        email: None,
        name: None,
        email_redacted: None,
        name_redacted: None,
        mtls_fingerprint: None,
        mtls_subject_dn: None,
        mtls_issuer_dn: None,
        mtls_source: None,
    })
}

/// Paginated audit log response
#[derive(Debug, Serialize)]
pub struct AuditLogPage {
    pub events: Vec<DelegationAuditEvent>,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
    pub total_pages: usize,
    /// Per-category event counts across the text-filtered set, computed
    /// **before** the category filter so a dropdown can show how many entries
    /// each category holds regardless of which one is currently selected.
    pub category_counts: std::collections::BTreeMap<String, usize>,
}

/// Return the stable category string for an audit action.
///
/// Used by [`read_audit_log`] to apply the category filter before pagination
/// so `total` and `total_pages` reflect the filtered set.
pub fn action_category(action: &DelegationAuditAction) -> &'static str {
    match action {
        DelegationAuditAction::PolicyDecision { .. } => "policy_decision",
        DelegationAuditAction::TrustCheck { .. } => "trust_check",
        DelegationAuditAction::TraceTerminated { .. } => "trace_terminated",
        DelegationAuditAction::ConsentGranted => "consent_granted",
        DelegationAuditAction::TokenInjected => "token_injected",
        DelegationAuditAction::TokenRefreshed => "token_refreshed",
        DelegationAuditAction::RefreshFailed => "refresh_failed",
        DelegationAuditAction::ConsentRequired => "consent_required",
        DelegationAuditAction::TokenRevoked => "token_revoked",
        DelegationAuditAction::UserTokensRevoked => "user_tokens_revoked",
        DelegationAuditAction::TokenNotFound => "token_not_found",
        DelegationAuditAction::VpInjected => "vp_injected",
        DelegationAuditAction::ElicitationSent => "elicitation_sent",
        DelegationAuditAction::ElicitationAccepted => "elicitation_accepted",
        DelegationAuditAction::ElicitationDeclined => "elicitation_declined",
        DelegationAuditAction::ElicitationCancelled => "elicitation_cancelled",
        DelegationAuditAction::ElicitationTimedOut => "elicitation_timed_out",
        DelegationAuditAction::PaymentEvent(_) => "payment",
        DelegationAuditAction::AuthFailed { .. } => "auth_failed",
        DelegationAuditAction::RateLimited { .. } => "rate_limited",
        DelegationAuditAction::RequestRejected { .. } => "request_rejected",
        DelegationAuditAction::IdentityBindingFailed { .. } => "identity_binding_failed",
        DelegationAuditAction::IdentityBindingVerified { .. } => "identity_binding_verified",
        DelegationAuditAction::DelegationFailed { .. } => "delegation_failed",
        DelegationAuditAction::RequestFailed { .. } => "request_failed",
        DelegationAuditAction::RequestCompleted { .. } => "request_completed",
        DelegationAuditAction::PolicyCreated(_) => "policy_created",
        DelegationAuditAction::PolicyUpdated(_) => "policy_updated",
        DelegationAuditAction::PolicyDeleted(_) => "policy_deleted",
        DelegationAuditAction::PolicyAttached(_) => "policy_attached",
        DelegationAuditAction::PolicyDetached(_) => "policy_detached",
        DelegationAuditAction::PolicyAttachmentChanged(_) => "policy_attachment_changed",
        DelegationAuditAction::PolicyChangeRefused(_) => "policy_change_refused",
    }
}

/// Tally per-category event counts (via [`action_category`]) across a set of
/// events. Used by [`read_audit_log`] to report how many entries each category
/// holds, computed before the category filter is applied.
pub fn tally_categories(events: &[DelegationAuditEvent]) -> std::collections::BTreeMap<String, usize> {
    let mut counts = std::collections::BTreeMap::new();
    for event in events {
        *counts
            .entry(action_category(&event.event).to_string())
            .or_insert(0) += 1;
    }
    counts
}

/// Filters for [`read_audit_log`]. All are applied **before** pagination and
/// the category tally so `total`, `total_pages`, and `category_counts` stay
/// consistent with the returned page.
#[derive(Debug, Default, Clone, Copy)]
pub struct AuditLogFilter<'a> {
    /// Case-insensitive substring match on the raw JSON line.
    pub text: Option<&'a str>,
    /// OR set of action-type categories (comma-separated).
    pub category: Option<&'a str>,
    /// Restrict to policy decisions with this flow (`access_point` | `transit_point` | `fabric`).
    pub flow: Option<&'a str>,
    /// Restrict to policy decisions with this scope (`gateway` | `surface` | `mcp_tool` | `response`).
    pub scope: Option<&'a str>,
    /// Restrict to policy decisions with this decision (`allow` | `deny`).
    pub decision: Option<&'a str>,
    /// Drop VP-audit events (policy decisions / trust checks) entirely.
    pub exclude_vp_audit: bool,
}

/// Read the audit log file with pagination (newest first). Every [`AuditLogFilter`]
/// is applied **before** pagination and the category tally so `total`,
/// `total_pages`, and `category_counts` stay consistent with the returned page.
pub async fn read_audit_log(
    page: usize,
    page_size: usize,
    opts: AuditLogFilter<'_>,
) -> anyhow::Result<AuditLogPage> {
    let path = AUDIT_PATH
        .get()
        .ok_or_else(|| anyhow::anyhow!("Audit logger not initialized"))?;

    let content = tokio::fs::read_to_string(path)
        .await
        .unwrap_or_default();

    // Parse all lines most-recent first. Text filtering happens after VP-backed
    // policy evidence enrichment so full-hash searches can match hydrated
    // PolicyDecision rows even when the original JSONL row predated the fields.
    let mut events: Vec<DelegationAuditEvent> = content
        .lines()
        .rev()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            serde_json::from_str::<DelegationAuditEvent>(line).ok()
        })
        .collect();

    enrich_policy_decisions_from_signed_vps(&mut events);

    if let Some(filter_lower) = opts
        .text
        .map(|f| f.to_lowercase())
    {
        events.retain(|event| {
            serde_json::to_string(event)
                .map(|json| {
                    json.to_lowercase()
                        .contains(&filter_lower)
                })
                .unwrap_or(false)
        });
    }

    // Drop VP-audit events (policy decisions / trust checks) up front so the
    // count, pagination, and category tally all reflect the same filtered set.
    if opts.exclude_vp_audit {
        events.retain(|event| !event.event.is_vp_audit());
    }

    // Policy-decision refinement filters (flow / scope / decision). When any is
    // set the view is restricted to matching PolicyDecision events (non
    // policy-decision events are dropped), so these compose with the category
    // filter and drive the counts/pagination consistently.
    let flow_f = opts
        .flow
        .filter(|s| !s.is_empty());
    let scope_f = opts
        .scope
        .filter(|s| !s.is_empty());
    let decision_f = opts
        .decision
        .filter(|s| !s.is_empty());
    if flow_f.is_some() || scope_f.is_some() || decision_f.is_some() {
        events.retain(|event| match &event.event {
            DelegationAuditAction::PolicyDecision { flow, scope, decision, .. } => {
                flow_f.is_none_or(|f| flow == f)
                    && scope_f.is_none_or(|s| scope == s)
                    && decision_f.is_none_or(|d| decision == d)
            }
            _ => false,
        });
    }

    // Tally per-category counts across the (text + refinement) filtered set,
    // before the category filter narrows it, so the caller can label each
    // category with its count regardless of the current category selection.
    let category_counts = tally_categories(&events);

    // Apply the category filter after counting so total/total_pages reflect the
    // selected category while category_counts still reflect every category. A
    // comma-separated list is treated as an OR set (any matching category is
    // kept); an empty/blank list applies no category filter.
    if let Some(cat) = opts.category {
        let wanted: std::collections::HashSet<&str> = cat
            .split(',')
            .map(|c| c.trim())
            .filter(|c| !c.is_empty())
            .collect();
        if !wanted.is_empty() {
            events.retain(|event| wanted.contains(action_category(&event.event)));
        }
    }

    let total = events.len();
    let total_pages = if total == 0 {
        1
    } else {
        total.div_ceil(page_size)
    };
    let clamped_page = page.clamp(1, total_pages);
    let start = (clamped_page - 1) * page_size;
    let page_events: Vec<DelegationAuditEvent> = events
        .drain(start..)
        .take(page_size)
        .collect();

    Ok(AuditLogPage {
        events: page_events,
        total,
        page: clamped_page,
        page_size,
        total_pages,
        category_counts,
    })
}

/// Emit a policy-decision audit record (`decision` is `allow`, `deny` or
/// `error`) when a sink selects `policy_decision`. Called from
/// [`crate::observability::policy_audit::record_policy_decision`].
pub fn audit_policy_decision(
    scope: &str,
    decision: &str,
    policy_id: &str,
    policy_name: Option<&str>,
    policy_definition_id: Option<&str>,
    deny_reason: Option<&str>,
    surface_id: Option<&str>,
    surface_name: Option<&str>,
    caller_did: Option<&str>,
    http_method: Option<&str>,
    http_path: Option<&str>,
    trace_id: Option<&str>,
    flow: &str,
    policy_version: Option<u32>,
    policy_content_hash: Option<&str>,
    caller: Option<AuditCallerContext>,
    removed_tools: Option<&[String]>,
) {
    emit("policy_decision", || DelegationAuditEvent {
        event_id: new_event_id(),
        timestamp: Utc::now().to_rfc3339(),
        event: DelegationAuditAction::PolicyDecision {
            scope: scope.to_string(),
            flow: flow.to_string(),
            policy_id: policy_id.to_string(),
            policy_name: policy_name
                .filter(|n| !n.is_empty())
                .map(str::to_string),
            policy_definition_id: policy_definition_id
                .filter(|d| !d.is_empty())
                .map(str::to_string),
            decision: decision.to_string(),
            deny_reason: deny_reason.map(str::to_string),
            surface_id: surface_id.map(str::to_string),
            caller_did: caller_did.map(str::to_string),
            http_method: http_method.map(str::to_string),
            http_path: http_path.map(str::to_string),
            policy_version,
            policy_content_hash: policy_content_hash.map(str::to_string),
            removed_tools: removed_tools.map(<[String]>::to_vec),
        },
        agent_did: None,
        agent_identity_did: None,
        user_identity_hash: None,
        provider_id: None,
        provider_name: None,
        surface_id: surface_id.map(str::to_string),
        channel_name: surface_name.map(str::to_string),
        target_endpoint: None,
        protocol: None,
        scopes: None,
        token_id: None,
        inject_as: None,
        via_fabric: false,
        caller,
        mcp_tool_name: None,
        vp_jwt: None,
        vp_fingerprint: None,
        trace_id: trace_id.map(str::to_string),
        request_id: None,
        detail: None,
    });
}

/// Emit a trust-check audit record when a sink selects `trust_check`. Called
/// from [`crate::observability::trust_check_audit::record_trust_check`]. The
/// caller comes from [`crate::audit::context::with_caller`].
///
/// `authority_id` / `entity_id` are `None` on the target-leg pre-check
/// paths (`AGENT_CARD_UNAVAILABLE`, `TRUST_REGISTRY_METADATA_UNAVAILABLE`)
/// so the emitted JSONL omits them, matching the wire shape.
pub fn audit_trust_check(
    surface_id: Option<&str>,
    trace_id: Option<&str>,
    leg: &str,
    authority_id: Option<&str>,
    entity_id: Option<&str>,
    ok: bool,
    error_code: Option<&str>,
) {
    emit("trust_check", || DelegationAuditEvent {
        event_id: new_event_id(),
        timestamp: Utc::now().to_rfc3339(),
        event: DelegationAuditAction::TrustCheck {
            leg: leg.to_string(),
            authority_id: authority_id.map(str::to_string),
            entity_id: entity_id.map(str::to_string),
            ok,
            error_code: error_code.map(str::to_string),
        },
        agent_did: None,
        agent_identity_did: None,
        user_identity_hash: None,
        provider_id: None,
        provider_name: None,
        surface_id: surface_id.map(str::to_string),
        channel_name: None,
        target_endpoint: None,
        protocol: None,
        scopes: None,
        token_id: None,
        inject_as: None,
        via_fabric: false,
        caller: crate::audit::context::current_caller(),
        mcp_tool_name: None,
        vp_jwt: None,
        vp_fingerprint: None,
        trace_id: trace_id.map(str::to_string),
        request_id: None,
        detail: None,
    });
}

/// Emit a dedicated audit event recording that this surface terminated the
/// end-to-end trace at its egress. Carries the own -> downstream trace mapping so
/// an operator can bridge the terminated trace from this gateway's own records
/// without the incoming trace ever crossing the boundary. Correlated
/// (`trace_id`) to this gateway's own request so it appears under the "This
/// request" filter alongside the request's policy decisions.
pub fn audit_trace_terminated(
    surface_id: Option<&str>,
    own_trace_id: &str,
    downstream_trace_id: &str,
    flow: &str,
    via_fabric: bool,
) {
    emit("trace_terminated", || DelegationAuditEvent {
        event_id: new_event_id(),
        timestamp: Utc::now().to_rfc3339(),
        event: DelegationAuditAction::TraceTerminated {
            own_trace_id: own_trace_id.to_string(),
            downstream_trace_id: downstream_trace_id.to_string(),
            flow: flow.to_string(),
        },
        agent_did: None,
        agent_identity_did: None,
        user_identity_hash: None,
        provider_id: None,
        provider_name: None,
        surface_id: surface_id.map(str::to_string),
        channel_name: None,
        target_endpoint: None,
        protocol: None,
        scopes: None,
        token_id: None,
        inject_as: None,
        via_fabric,
        caller: None,
        mcp_tool_name: None,
        vp_jwt: None,
        vp_fingerprint: None,
        trace_id: Some(own_trace_id.to_string()),
        request_id: None,
        detail: Some(format!("downstream_trace_id={downstream_trace_id}")),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_builder_fills_fields() {
        let evt = audit_event(
            DelegationAuditAction::TokenInjected,
            Some("did:web:agent"),
            Some("sha256:user1"),
            Some("github"),
            Some("ch-1"),
        );
        assert!(matches!(evt.event, DelegationAuditAction::TokenInjected));
        assert_eq!(evt.agent_did.as_deref(), Some("did:web:agent"));
        assert_eq!(
            evt.user_identity_hash
                .as_deref(),
            Some("sha256:user1")
        );
        assert_eq!(evt.provider_id.as_deref(), Some("github"));
        assert_eq!(evt.surface_id.as_deref(), Some("ch-1"));
        assert!(!evt.via_fabric);
        assert!(evt.scopes.is_none());
        assert!(evt.token_id.is_none());
        assert!(evt.detail.is_none());
    }

    #[test]
    fn caller_context_preserves_raw_jwt_identity_evidence() {
        let identity = crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject: "alice".to_string(),
            claims: serde_json::json!({
                "iss": "https://issuer.example",
                "aud": "gateway",
                "email": "alice@example.com",
                "name": "Alice Example"
            }),
        };

        let caller = build_caller_context(&identity);

        assert_eq!(caller.auth_method, "jwt_bearer");
        assert_eq!(caller.sub.as_deref(), Some("alice"));
        assert_eq!(caller.email.as_deref(), Some("alice@example.com"));
        assert_eq!(caller.name.as_deref(), Some("Alice Example"));
        assert!(
            caller
                .email_redacted
                .is_none()
        );
        assert!(caller.name_redacted.is_none());
    }

    #[test]
    fn test_audit_event_builder_with_none_fields() {
        let evt = audit_event(DelegationAuditAction::ConsentRequired, None, None, None, None);
        assert!(evt.agent_did.is_none());
        assert!(
            evt.user_identity_hash
                .is_none()
        );
        assert!(evt.provider_id.is_none());
        assert!(evt.surface_id.is_none());
    }

    #[test]
    fn test_audit_event_serialization_includes_event_type() {
        let evt = audit_event(
            DelegationAuditAction::ConsentGranted,
            Some("did:web:agent"),
            Some("sha256:user"),
            Some("github"),
            Some("ch-1"),
        );
        let json = serde_json::to_string(&evt).unwrap();
        assert!(json.contains("\"event\":\"consent_granted\""), "Event should serialize to snake_case, got: {}", json);
        assert!(json.contains("\"agent_did\":\"did:web:agent\""));
        // via_fabric defaults to false
        assert!(json.contains("\"via_fabric\":false"));
    }

    #[test]
    fn test_audit_event_serialization_skips_none_fields() {
        let evt = audit_event(DelegationAuditAction::TokenRevoked, None, None, None, None);
        let json = serde_json::to_string(&evt).unwrap();
        assert!(!json.contains("agent_did"), "None fields should be skipped");
        assert!(!json.contains("scopes"), "None scopes should be skipped");
        assert!(!json.contains("token_id"), "None token_id should be skipped");
        assert!(!json.contains("detail"), "None detail should be skipped");
        assert!(json.contains("\"event\":\"token_revoked\""));
    }

    #[test]
    fn a_policy_change_is_the_body_of_its_event_and_names_only_its_actor_id() {
        let mut change = PolicyChangeDetails::new(Actor::user("u-123"), PolicyChangeSource::Api);
        change.policy_definition_id = Some("deny-pii".to_string());
        change.policy_version = Some(3);
        change.target = Some(PolicyTarget {
            kind: PolicyTargetKind::Surface,
            id: Some("s-1".to_string()),
            name: Some("Orders".to_string()),
        });
        change.slot = Some(PolicySlot::Inbound);
        change.mode = Some(PolicyMode::Enforced);
        let event = audit_event(DelegationAuditAction::PolicyAttached(Box::new(change)), None, None, None, Some("s-1"));

        let json = serde_json::to_value(&event).unwrap();

        assert_eq!(
            json["event"],
            serde_json::json!({"policy_attached": {
                "policy_definition_id": "deny-pii",
                "policy_version": 3,
                "target": {"kind": "surface", "id": "s-1", "name": "Orders"},
                "slot": "inbound",
                "mode": "enforced",
                "actor": {"kind": "user", "id": "u-123"},
                "source": "api",
            }})
        );
        assert!(json.get("detail").is_none());
    }

    #[test]
    fn a_policy_change_event_is_categorised_by_its_name_and_kept_in_the_vp_audit_log() {
        let change = || Box::new(PolicyChangeDetails::new(Actor::system(), PolicyChangeSource::DefinitionDeleted));
        let actions = [
            (DelegationAuditAction::PolicyCreated(change()), "policy_created"),
            (DelegationAuditAction::PolicyUpdated(change()), "policy_updated"),
            (DelegationAuditAction::PolicyDeleted(change()), "policy_deleted"),
            (DelegationAuditAction::PolicyAttached(change()), "policy_attached"),
            (DelegationAuditAction::PolicyDetached(change()), "policy_detached"),
            (DelegationAuditAction::PolicyAttachmentChanged(change()), "policy_attachment_changed"),
            (DelegationAuditAction::PolicyChangeRefused(change()), "policy_change_refused"),
        ];
        for (action, category) in actions {
            assert_eq!(action_category(&action), category);
            assert!(action.is_vp_audit(), "{category}");
            assert_eq!(serde_json::to_value(&action).unwrap()[category]["source"], "definition_deleted");
        }
    }

    #[test]
    fn test_trace_terminated_action_category_and_vp_audit() {
        let action = DelegationAuditAction::TraceTerminated {
            own_trace_id: "own-123".to_string(),
            downstream_trace_id: "down-456".to_string(),
            flow: "fabric".to_string(),
        };
        assert_eq!(action_category(&action), "trace_terminated");
        assert!(action.is_vp_audit());
    }

    #[test]
    fn test_trace_terminated_event_correlates_to_own_trace() {
        let event = DelegationAuditEvent {
            event_id: None,
            timestamp: Utc::now().to_rfc3339(),
            event: DelegationAuditAction::TraceTerminated {
                own_trace_id: "own-123".to_string(),
                downstream_trace_id: "down-456".to_string(),
                flow: "fabric".to_string(),
            },
            agent_did: None,
            agent_identity_did: None,
            user_identity_hash: None,
            provider_id: None,
            provider_name: None,
            surface_id: Some("surface-1".to_string()),
            channel_name: None,
            target_endpoint: None,
            protocol: None,
            scopes: None,
            token_id: None,
            inject_as: None,
            via_fabric: true,
            caller: None,
            mcp_tool_name: None,
            vp_jwt: None,
            vp_fingerprint: None,
            trace_id: Some("own-123".to_string()),
            request_id: None,
            detail: Some("downstream_trace_id=down-456".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event\":{\"trace_terminated\":"), "got: {}", json);
        assert!(json.contains("\"own_trace_id\":\"own-123\""));
        assert!(json.contains("\"downstream_trace_id\":\"down-456\""));
        assert!(json.contains("\"flow\":\"fabric\""));
        assert!(json.contains("\"trace_id\":\"own-123\""), "must correlate to own trace, got: {}", json);
    }

    #[test]
    fn test_audit_event_via_fabric_flag() {
        let mut evt = audit_event(DelegationAuditAction::TokenInjected, None, None, None, None);
        evt.via_fabric = true;
        let json = serde_json::to_string(&evt).unwrap();
        assert!(json.contains("\"via_fabric\":true"));
    }

    #[test]
    fn test_audit_event_with_scopes_and_detail() {
        let mut evt = audit_event(
            DelegationAuditAction::ConsentGranted,
            Some("did:web:agent"),
            Some("sha256:user"),
            Some("github"),
            Some("ch-1"),
        );
        evt.scopes = Some(vec!["repo".to_string(), "read:user".to_string()]);
        evt.detail = Some("User clicked authorize".to_string());
        let json = serde_json::to_string(&evt).unwrap();
        assert!(json.contains("\"scopes\":[\"repo\",\"read:user\"]"));
        assert!(json.contains("\"detail\":\"User clicked authorize\""));
    }

    #[test]
    fn test_payment_event_category_and_serialization() {
        // A locally-enforced MPP verification: delegation fields omitted.
        let local = DelegationAuditAction::PaymentEvent(Box::new(PaymentEventDetails {
            rail: PaymentRail::Mpp,
            stage: PaymentStage::Verified,
            transaction_id: "txn-1".to_string(),
            amount: Some("10".to_string()),
            currency: Some("USDC".to_string()),
            method: Some("card".to_string()),
            payer: Some("did:example:payer".to_string()),
            error: None,
            delegated: false,
            payment_gateway_id: None,
            payment_surface_id: None,
            remote_status: None,
        }));
        assert_eq!(action_category(&local), "payment");
        assert!(!local.is_vp_audit());
        let json = serde_json::to_value(&local).unwrap();
        assert_eq!(json["payment_event"]["rail"], "mpp");
        assert_eq!(json["payment_event"]["stage"], "verified");
        assert_eq!(json["payment_event"]["amount"], "10");
        assert_eq!(json["payment_event"]["transaction_id"], "txn-1");
        // Local payments omit the delegation-only fields entirely.
        assert!(
            json["payment_event"]
                .get("delegated")
                .is_none()
        );
        assert!(
            json["payment_event"]
                .get("payment_gateway_id")
                .is_none()
        );
        assert!(
            json["payment_event"]
                .get("remote_status")
                .is_none()
        );

        // A delegated x402 challenge relayed over the fabric: remote ids present.
        let delegated = DelegationAuditAction::PaymentEvent(Box::new(PaymentEventDetails {
            rail: PaymentRail::X402,
            stage: PaymentStage::ChallengeIssued,
            transaction_id: "txn-2".to_string(),
            amount: None,
            currency: None,
            method: None,
            payer: None,
            error: None,
            delegated: true,
            payment_gateway_id: Some("gw-pay".to_string()),
            payment_surface_id: Some("surface-1".to_string()),
            remote_status: Some(402),
        }));
        let json = serde_json::to_value(&delegated).unwrap();
        assert_eq!(json["payment_event"]["rail"], "x402");
        assert_eq!(json["payment_event"]["stage"], "challenge_issued");
        assert_eq!(json["payment_event"]["delegated"], true);
        assert_eq!(json["payment_event"]["payment_gateway_id"], "gw-pay");
        assert_eq!(json["payment_event"]["remote_status"], 402);
    }

    #[test]
    fn test_all_action_variants_serialize() {
        let actions = vec![
            (DelegationAuditAction::ConsentGranted, "consent_granted"),
            (DelegationAuditAction::TokenInjected, "token_injected"),
            (DelegationAuditAction::TokenRefreshed, "token_refreshed"),
            (DelegationAuditAction::RefreshFailed, "refresh_failed"),
            (DelegationAuditAction::ConsentRequired, "consent_required"),
            (DelegationAuditAction::TokenRevoked, "token_revoked"),
            (DelegationAuditAction::UserTokensRevoked, "user_tokens_revoked"),
            (DelegationAuditAction::TokenNotFound, "token_not_found"),
            (DelegationAuditAction::VpInjected, "vp_injected"),
            (DelegationAuditAction::ElicitationSent, "elicitation_sent"),
            (DelegationAuditAction::ElicitationAccepted, "elicitation_accepted"),
            (DelegationAuditAction::ElicitationDeclined, "elicitation_declined"),
            (DelegationAuditAction::ElicitationCancelled, "elicitation_cancelled"),
            (DelegationAuditAction::ElicitationTimedOut, "elicitation_timed_out"),
        ];

        for (action, expected_name) in actions {
            let json = serde_json::to_string(&action).unwrap();
            assert_eq!(
                json,
                format!("\"{}\"", expected_name),
                "Action {:?} should serialize to {}",
                expected_name,
                expected_name
            );
        }
    }

    #[test]
    fn test_is_vp_audit_classifies_only_policy_and_trust_check() {
        // The two variants that belong to the VP Audit Log (/v1/audit).
        assert!(
            DelegationAuditAction::PolicyDecision {
                scope: "gateway".to_string(),
                flow: "access_point".to_string(),
                policy_id: "pol-1".to_string(),
                policy_name: None,
                policy_definition_id: None,
                decision: "deny".to_string(),
                deny_reason: None,
                surface_id: None,
                caller_did: None,
                http_method: None,
                http_path: None,
                policy_version: None,
                policy_content_hash: None,
                removed_tools: None,
            }
            .is_vp_audit()
        );
        assert!(
            DelegationAuditAction::TrustCheck {
                leg: "caller".to_string(),
                authority_id: Some("did:example:auth".to_string()),
                entity_id: Some("did:example:agent".to_string()),
                ok: false,
                error_code: Some("QUERY_TIMEOUT".to_string()),
            }
            .is_vp_audit()
        );

        // Every credential-delegation variant must NOT be classified as VP audit.
        let delegation_actions = [
            DelegationAuditAction::ConsentGranted,
            DelegationAuditAction::TokenInjected,
            DelegationAuditAction::TokenRefreshed,
            DelegationAuditAction::RefreshFailed,
            DelegationAuditAction::ConsentRequired,
            DelegationAuditAction::TokenRevoked,
            DelegationAuditAction::UserTokensRevoked,
            DelegationAuditAction::TokenNotFound,
            DelegationAuditAction::VpInjected,
            DelegationAuditAction::ElicitationSent,
            DelegationAuditAction::ElicitationAccepted,
            DelegationAuditAction::ElicitationDeclined,
            DelegationAuditAction::ElicitationCancelled,
            DelegationAuditAction::ElicitationTimedOut,
        ];
        for action in delegation_actions {
            assert!(!action.is_vp_audit(), "{:?} should not be classified as VP audit", action);
        }
    }

    fn request_path_actions() -> Vec<(DelegationAuditAction, &'static str)> {
        vec![
            (
                DelegationAuditAction::AuthFailed {
                    scheme: AuthScheme::ApiKey,
                    reason: "unknown_key".to_string(),
                    blocking: true,
                    client_ip: Some("203.0.113.7".to_string()),
                },
                "auth_failed",
            ),
            (
                DelegationAuditAction::RateLimited {
                    scope: RateLimitScope::SseSessions,
                    retry_after_ms: Some(1500),
                },
                "rate_limited",
            ),
            (
                DelegationAuditAction::RequestRejected {
                    stage: RejectionStage::Admission,
                    reason: RejectionReason::BodyTooLarge,
                    http_status: 413,
                    rpc_error_code: Some(-32600),
                    requested_variant: None,
                },
                "request_rejected",
            ),
            (
                DelegationAuditAction::IdentityBindingFailed {
                    outcome: IdentityBindingFailure::Invalid,
                    agent_did: None,
                    issuer_gateway: None,
                    error_detail: Some("signature mismatch".to_string()),
                },
                "identity_binding_failed",
            ),
            (
                DelegationAuditAction::IdentityBindingVerified {
                    agent_did: "did:web:agent.example".to_string(),
                    issuer_gateway: Some("did:web:gw.example".to_string()),
                    assurance: Some("gateway_attested".to_string()),
                },
                "identity_binding_verified",
            ),
            (
                DelegationAuditAction::DelegationFailed {
                    reason: DelegationFailureReason::AnonymousCaller,
                    provider_id: Some("github".to_string()),
                },
                "delegation_failed",
            ),
            (
                DelegationAuditAction::RequestFailed {
                    outcome: RequestFailureOutcome::UpstreamTimeout,
                    target_kind: TargetKind::Fabric,
                    upstream_status: None,
                    latency_ms: 30_000,
                },
                "request_failed",
            ),
            (
                DelegationAuditAction::RequestCompleted {
                    target_kind: TargetKind::McpProxy,
                    upstream_status: 200,
                    latency_ms: 42,
                    request_bytes: 128,
                    response_bytes: 2048,
                    ucp_op: None,
                    variant_alias: Some("beta".to_string()),
                },
                "request_completed",
            ),
        ]
    }

    #[test]
    fn request_path_actions_have_their_category() {
        for (action, category) in request_path_actions() {
            assert_eq!(action_category(&action), category);
        }
    }

    #[test]
    fn request_path_actions_round_trip_through_the_stored_form() {
        for (action, category) in request_path_actions() {
            let stored = serde_json::to_value(&action).unwrap();
            assert!(stored.get(category).is_some(), "{category} is stored under its own key: {stored}");
            let read: DelegationAuditAction = serde_json::from_value(stored.clone()).unwrap();
            assert_eq!(serde_json::to_value(&read).unwrap(), stored, "{category}");
        }
    }

    #[test]
    fn request_path_actions_use_snake_case_values() {
        let stored = serde_json::to_value(DelegationAuditAction::RequestRejected {
            stage: RejectionStage::Admission,
            reason: RejectionReason::ConsentIdentityRequired,
            http_status: 403,
            rpc_error_code: None,
            requested_variant: None,
        })
        .unwrap();
        assert_eq!(stored["request_rejected"]["stage"], "admission");
        assert_eq!(stored["request_rejected"]["reason"], "consent_identity_required");
        assert!(
            stored["request_rejected"]
                .get("rpc_error_code")
                .is_none(),
            "an absent JSON-RPC code is left out of the record"
        );
    }

    #[test]
    fn unknown_value_in_a_closed_field_is_rejected() {
        let stored = serde_json::json!({ "rate_limited": { "scope": "everything" } });
        assert!(serde_json::from_value::<DelegationAuditAction>(stored).is_err());
    }

    #[test]
    fn only_delegation_failed_belongs_to_the_delegation_log() {
        for (action, category) in request_path_actions() {
            assert_eq!(action.is_vp_audit(), category != "delegation_failed", "{category}");
        }
    }

    #[test]
    fn every_new_event_gets_its_own_event_id() {
        let first = audit_event(DelegationAuditAction::ConsentGranted, None, None, None, None);
        let second = audit_event(DelegationAuditAction::ConsentGranted, None, None, None, None);
        let (first, second) = (first.event_id.unwrap(), second.event_id.unwrap());
        assert_ne!(first, second);
        assert!(uuid::Uuid::parse_str(&first).is_ok());
    }

    #[test]
    fn a_stored_line_without_an_event_id_still_reads() {
        let mut stored =
            serde_json::to_value(audit_event(DelegationAuditAction::ConsentGranted, None, None, None, None)).unwrap();
        stored
            .as_object_mut()
            .unwrap()
            .remove("event_id");
        let read: DelegationAuditEvent = serde_json::from_value(stored).unwrap();
        assert_eq!(read.event_id, None);
    }

    #[test]
    fn the_request_id_is_written_when_set_and_omitted_when_not() {
        let mut event = audit_event(DelegationAuditAction::ConsentGranted, None, None, None, None);
        assert!(
            serde_json::to_value(&event)
                .unwrap()
                .get("request_id")
                .is_none()
        );

        event.request_id = Some("0123456789abcdef".to_string());
        let written = serde_json::to_value(&event).unwrap();
        assert_eq!(written["request_id"], "0123456789abcdef");
        let read: DelegationAuditEvent = serde_json::from_value(written).unwrap();
        assert_eq!(read.request_id.as_deref(), Some("0123456789abcdef"));
    }

    #[test]
    fn stored_pre_authorize_blocked_line_is_not_an_audit_event() {
        let stored = serde_json::to_string(&audit_event(DelegationAuditAction::ConsentGranted, None, None, None, None))
            .unwrap()
            .replace("\"consent_granted\"", "\"pre_authorize_blocked\"");
        assert!(stored.contains("\"pre_authorize_blocked\""));
        assert!(serde_json::from_str::<DelegationAuditEvent>(&stored).is_err());
    }

    #[test]
    fn test_tally_categories_counts_per_category() {
        let mk = |action: DelegationAuditAction| audit_event(action, None, None, None, None);
        let events = vec![
            mk(DelegationAuditAction::ConsentGranted),
            mk(DelegationAuditAction::ConsentGranted),
            mk(DelegationAuditAction::TokenInjected),
            mk(DelegationAuditAction::PolicyDecision {
                scope: "gateway".to_string(),
                flow: "access_point".to_string(),
                policy_id: "pol-1".to_string(),
                policy_name: None,
                policy_definition_id: None,
                decision: "allow".to_string(),
                deny_reason: None,
                surface_id: None,
                caller_did: None,
                http_method: None,
                http_path: None,
                policy_version: None,
                policy_content_hash: None,
                removed_tools: None,
            }),
        ];

        let counts = tally_categories(&events);
        assert_eq!(counts.get("consent_granted"), Some(&2));
        assert_eq!(counts.get("token_injected"), Some(&1));
        assert_eq!(counts.get("policy_decision"), Some(&1));
        // Untriggered categories are absent, not zero.
        assert_eq!(counts.get("trust_check"), None);
        // Sum of counts equals the total event count.
        assert_eq!(counts.values().sum::<usize>(), events.len());
    }

    #[test]
    fn test_tally_categories_empty_is_empty() {
        assert!(tally_categories(&[]).is_empty());
    }

    fn unsigned_jwt(payload: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
        format!("{header}.{payload}.signature")
    }

    #[test]
    fn enriches_policy_decision_from_same_trace_signed_vp() {
        let nested_vc = unsigned_jwt(serde_json::json!({
            "credentialSubject": {
                "workloadBinding": {
                    "policyDecisions": [{
                        "scope": "surface",
                        "flow": "fabric",
                        "policy_id": "surface.policy",
                        "policy_definition_id": "surface-def-1",
                        "surface_id": "surface-1",
                        "http_method": "POST",
                        "http_path": "/payments/collect/caviar",
                        "decision": "allow",
                        "policy_version": 4,
                        "policy_content_hash": "sha256:abc123"
                    }]
                }
            }
        }));
        let vp = unsigned_jwt(serde_json::json!({
            "vp": {
                "verifiableCredential": [nested_vc]
            }
        }));
        let mut events = vec![
            DelegationAuditEvent {
                event_id: None,
                timestamp: "2026-08-18T00:00:00Z".to_string(),
                event: DelegationAuditAction::VpInjected,
                agent_did: None,
                agent_identity_did: None,
                user_identity_hash: None,
                provider_id: None,
                provider_name: None,
                surface_id: None,
                channel_name: None,
                target_endpoint: None,
                protocol: None,
                scopes: None,
                token_id: None,
                inject_as: None,
                via_fabric: false,
                caller: None,
                mcp_tool_name: None,
                vp_jwt: Some(vp),
                vp_fingerprint: None,
                trace_id: Some("trace-1".to_string()),
                request_id: None,
                detail: None,
            },
            DelegationAuditEvent {
                event_id: None,
                timestamp: "2026-08-18T00:00:01Z".to_string(),
                event: DelegationAuditAction::PolicyDecision {
                    scope: "surface".to_string(),
                    flow: "fabric".to_string(),
                    policy_id: "surface.policy".to_string(),
                    policy_name: Some("Surface Policy".to_string()),
                    policy_definition_id: Some("surface-def-1".to_string()),
                    decision: "allow".to_string(),
                    deny_reason: None,
                    surface_id: Some("surface-1".to_string()),
                    caller_did: None,
                    http_method: Some("POST".to_string()),
                    http_path: Some("/payments/collect/caviar".to_string()),
                    policy_version: None,
                    policy_content_hash: None,
                    removed_tools: None,
                },
                agent_did: None,
                agent_identity_did: None,
                user_identity_hash: None,
                provider_id: None,
                provider_name: None,
                surface_id: None,
                channel_name: None,
                target_endpoint: None,
                protocol: None,
                scopes: None,
                token_id: None,
                inject_as: None,
                via_fabric: false,
                caller: None,
                mcp_tool_name: None,
                vp_jwt: None,
                vp_fingerprint: None,
                trace_id: Some("trace-1".to_string()),
                request_id: None,
                detail: None,
            },
        ];

        enrich_policy_decisions_from_signed_vps(&mut events);

        match &events[1].event {
            DelegationAuditAction::PolicyDecision {
                policy_version,
                policy_content_hash,
                ..
            } => {
                assert_eq!(*policy_version, Some(4));
                assert_eq!(policy_content_hash.as_deref(), Some("sha256:abc123"));
            }
            other => panic!("expected policy decision, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn audit_policy_decision_records_the_authenticated_caller() {
        let identity = crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject: "user-123".to_string(),
            claims: serde_json::json!({"email": "ada@example.com", "name": "Ada Lovelace"}),
        };
        let ((), events) = crate::audit::producer::capture(async {
            let decide = |caller| {
                audit_policy_decision(
                    "surface",
                    "deny",
                    "surface.policy",
                    Some("Deny unknown callers"),
                    None,
                    Some("caller not recognised"),
                    Some("surface-1"),
                    Some("Surface one"),
                    None,
                    Some("POST"),
                    Some("/a2a"),
                    Some("trace-1"),
                    "access_point",
                    Some(3),
                    Some("sha256:abc"),
                    caller,
                    None,
                )
            };
            decide(Some(build_caller_context(&identity)));
            decide(None);
        })
        .await;

        assert_eq!(events.len(), 2);
        let caller = events[0]
            .caller
            .as_ref()
            .expect("the decision names the human principal");
        assert_eq!(caller.auth_method, "jwt_bearer");
        assert_eq!(caller.sub.as_deref(), Some("user-123"));
        assert_eq!(caller.email.as_deref(), Some("ada@example.com"));
        assert_eq!(caller.name.as_deref(), Some("Ada Lovelace"));
        assert!(events[1].caller.is_none(), "a request without source auth has no caller context");

        let row = serde_json::to_value(&events[0]).unwrap();
        assert_eq!(row["caller"]["email"], "ada@example.com");
        assert_eq!(row["event"]["policy_decision"]["policy_name"], "Deny unknown callers");
        assert_eq!(row["event"]["policy_decision"]["policy_version"], 3);
        assert_eq!(row["event"]["policy_decision"]["policy_content_hash"], "sha256:abc");
    }

    fn transit_claims(
        sub: Option<&str>,
        fields: serde_json::Value,
    ) -> crate::proxy::transit_token::TransitTokenClaims {
        serde_json::from_value(serde_json::json!({
            "iss": "gw-1",
            "sub": sub,
            "surface_id": "surface-1",
            "iat": 0,
            "exp": 0,
            "jti": "jti-1",
            "caller_context_fields": fields,
        }))
        .unwrap()
    }

    #[test]
    fn transit_caller_context_carries_the_allowlisted_human_claims() {
        let caller = transit_caller_context(&transit_claims(
            Some("did:web:caller"),
            serde_json::json!({"sub": "user-123", "email": "ada@example.com", "name": "Ada Lovelace", "roles": ["x"]}),
        ))
        .unwrap();

        assert_eq!(caller.auth_method, "transit_token");
        assert_eq!(caller.sub.as_deref(), Some("user-123"), "the carried JWT subject wins over the caller DID");
        assert_eq!(caller.email.as_deref(), Some("ada@example.com"));
        assert_eq!(caller.name.as_deref(), Some("Ada Lovelace"));
    }

    #[test]
    fn transit_caller_context_falls_back_to_the_caller_did() {
        let caller =
            transit_caller_context(&transit_claims(Some("did:web:caller"), serde_json::json!({"email": ""}))).unwrap();

        assert_eq!(caller.sub.as_deref(), Some("did:web:caller"));
        assert_eq!(caller.email, None, "an empty claim is not a principal");
        assert_eq!(caller.name, None);
    }

    #[test]
    fn transit_caller_context_is_absent_without_any_caller() {
        assert!(transit_caller_context(&transit_claims(None, serde_json::json!({}))).is_none());
        assert!(
            transit_caller_context(&transit_claims(None, serde_json::json!({"email": 7}))).is_none(),
            "non-string claims are ignored"
        );
    }

    fn binding(
        verified: bool,
        caller_fields: Option<serde_json::Value>,
    ) -> crate::surface_context::IdentityBindingContext {
        crate::surface_context::IdentityBindingContext {
            verified,
            agent_did: "did:key:agent".to_string(),
            gateway_did: "did:web:gw-1".to_string(),
            identity_fields: std::collections::HashMap::new(),
            caller: caller_fields.map(|fields| crate::surface_context::CallerBindingContext {
                fields: serde_json::from_value(fields).unwrap(),
                user_hash: Some("hash-1".to_string()),
                assurance: "gateway_attested".to_string(),
                identity_source: Some("jwt_bearer".to_string()),
            }),
            delegated: true,
            target: None,
            intent: None,
            inbound_credentials: Vec::new(),
        }
    }

    #[test]
    fn a_verified_binding_names_the_caller_its_gateway_disclosed() {
        let caller = binding_caller_context(&binding(
            true,
            Some(serde_json::json!({"sub": "user-123", "email": "ada@example.com", "name": "Ada Lovelace"})),
        ))
        .unwrap();

        assert_eq!(caller.auth_method, "workload_binding");
        assert_eq!(caller.iss.as_deref(), Some("did:web:gw-1"), "the gateway that signed the binding");
        assert_eq!(caller.sub.as_deref(), Some("user-123"));
        assert_eq!(caller.email.as_deref(), Some("ada@example.com"));
        assert_eq!(caller.name.as_deref(), Some("Ada Lovelace"));
    }

    #[test]
    fn a_binding_names_no_caller_unless_verified_and_disclosed() {
        let disclosed = Some(serde_json::json!({"email": "ada@example.com"}));
        assert!(binding_caller_context(&binding(false, disclosed)).is_none(), "no trust anchor vouched for it");
        assert!(binding_caller_context(&binding(true, None)).is_none());
        assert!(binding_caller_context(&binding(true, Some(serde_json::json!({"email": ""})))).is_none());
    }

    fn injection<'a>(caller: Option<AuditCallerContext>) -> VpInjection<'a> {
        VpInjection {
            agent_did: Some("did:web:agent"),
            user_hash: Some("sha256:user"),
            surface_id: Some("surface-1"),
            channel_name: "alpha",
            target_endpoint: "https://target.example/a2a",
            protocol: "a2a",
            mcp_tool_name: None,
            vp_jwt: "header.payload.signature",
            trace_id: Some("trace-1"),
            detail: "request_path".to_string(),
            caller,
            via_fabric: false,
        }
    }

    #[test]
    fn a_vp_injection_record_has_the_full_field_set() {
        let identity = crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject: "user-1".to_string(),
            claims: serde_json::json!({}),
        };
        let event = vp_injected_event(injection(Some(build_caller_context(&identity))));

        assert!(matches!(event.event, DelegationAuditAction::VpInjected));
        assert_eq!(event.trace_id.as_deref(), Some("trace-1"));
        assert_eq!(event.detail.as_deref(), Some("request_path"));
        assert_eq!(event.vp_jwt.as_deref(), Some("header.payload.signature"));
        assert_eq!(event.vp_fingerprint, Some(vp_fingerprint("header.payload.signature")));
        assert_eq!(
            event
                .caller
                .as_ref()
                .and_then(|caller| caller.sub.as_deref()),
            Some("user-1")
        );
        assert_eq!(
            event
                .agent_identity_did
                .as_deref(),
            Some("did:web:agent")
        );
        assert_eq!(event.surface_id.as_deref(), Some("surface-1"));
        assert_eq!(event.channel_name.as_deref(), Some("alpha"));
    }

    #[tokio::test]
    async fn a_vp_injection_without_a_caller_takes_the_requests_caller() {
        let identity = crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject: "user-2".to_string(),
            claims: serde_json::json!({}),
        };
        let event = crate::audit::context::with_caller(Some(build_caller_context(&identity)), async {
            vp_injected_event(injection(None))
        })
        .await;
        assert_eq!(
            event
                .caller
                .as_ref()
                .and_then(|caller| caller.sub.as_deref()),
            Some("user-2")
        );
    }

    #[tokio::test]
    async fn a_trust_check_record_carries_its_surface_and_trace() {
        let ((), events) = crate::audit::producer::capture(async {
            audit_trust_check(Some("surface-1"), Some("trace-1"), "caller", Some("did:a"), Some("did:e"), true, None);
        })
        .await;
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0]
                .surface_id
                .as_deref(),
            Some("surface-1")
        );
        assert_eq!(events[0].trace_id.as_deref(), Some("trace-1"));
    }

    #[test]
    fn emitting_before_the_pipeline_starts_does_not_panic() {
        emit("token_injected", || audit_event(DelegationAuditAction::TokenInjected, None, None, None, None));
        submit(audit_event(DelegationAuditAction::TokenInjected, None, None, None, None));
    }
}
