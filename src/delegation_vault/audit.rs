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
    RejectionStage, RequestFailureOutcome, TargetAuthField, TargetAuthLeg, TargetAuthMethodKind, TargetAuthRejection,
    TargetKind,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::{error, info, warn};

use super::read_scope::VaultReadScope;
use crate::audit::log_files;
use crate::audit::pipeline::PipelineControl;
use crate::metrics::backends::prometheus::set_audit_pipeline_started;
use crate::server::mode::ServerMode;

/// Global audit file path — for reading the log
static AUDIT_PATH: OnceLock<PathBuf> = OnceLock::new();

#[cfg(test)]
tokio::task_local! {
    static AUDIT_PATH_OVERRIDE: Option<PathBuf>;
}

/// Runs `future` reading the VP Audit Log from `path` instead of the one set
/// up at startup.
#[cfg(test)]
pub async fn reading_audit_log_from<F: std::future::Future>(
    path: PathBuf,
    future: F,
) -> F::Output {
    AUDIT_PATH_OVERRIDE
        .scope(Some(path), future)
        .await
}

/// Runs `future` as if no VP Audit Log were set up, so reading it fails.
#[cfg(test)]
pub async fn without_an_audit_log<F: std::future::Future>(future: F) -> F::Output {
    AUDIT_PATH_OVERRIDE
        .scope(None, future)
        .await
}

#[cfg(not(test))]
fn audit_log_path() -> Option<PathBuf> {
    AUDIT_PATH.get().cloned()
}

#[cfg(test)]
fn audit_log_path() -> Option<PathBuf> {
    AUDIT_PATH_OVERRIDE
        .try_with(Option::clone)
        .unwrap_or_else(|_| AUDIT_PATH.get().cloned())
}

/// Bytes of the history one read examines, from the rotation `[audit]`
/// configured at startup. Set beside [`AUDIT_PATH`], which the same reads use,
/// so a read never takes it from a rotation the pipeline does not run with.
static AUDIT_SCAN_BYTES: OnceLock<u64> = OnceLock::new();

/// The advisory size of the history `[audit] vp_audit_log_soft_cap_bytes` asks
/// to be told about, reported beside the history's size on an audit page.
static AUDIT_SOFT_CAP_BYTES: OnceLock<u64> = OnceLock::new();

/// Bytes the audit history takes on disk, as the running VP Audit Log sink
/// keeps it: measured once when it opens the log, then followed as records are
/// appended and as retention deletes. `u64::MAX` means no sink has published
/// one yet — a Standby node, or before the pipeline starts — and a read then
/// measures the directory itself.
static AUDIT_HISTORY_BYTES: AtomicU64 = AtomicU64::new(u64::MAX);

/// Publishes the size of the audit history for the audit pages to report.
/// Called by [`crate::audit::audit_log_sink::AuditLogSink`], the only writer.
pub fn publish_history_bytes(bytes: u64) {
    AUDIT_HISTORY_BYTES.store(bytes, Ordering::Relaxed);
}

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
    /// The value of the JWT verification strategy's principal claim, when the
    /// strategy names a claim other than `sub`: the subject the caller is
    /// identified by. `sub` then holds the token's own `sub`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub principal: Option<String>,
    /// Management-API personal access token id, when the caller authenticated
    /// with a PAT rather than a console session. Attributes a management action
    /// (e.g. a delegation-vault revoke) to the exact token used.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub token_id: Option<String>,
    /// The caller's identity hash, for a caller of a request a paired gateway
    /// sent over Fabric that the receiving surface verified
    /// (`fabric_verified`): the value its delegated credentials are keyed by.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub user_identity_hash: Option<String>,
    /// The paired gateway that sent the request over Fabric, for a
    /// `fabric_verified` or `fabric_asserted` caller, and for the caller of a
    /// delegated credential released on Fabric receive: its issuer DID, else
    /// its Remote gateway record id.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub peer_gateway: Option<String>,
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
    /// The id of the credential provider involved. A tenant's access token
    /// reads the record only when that provider is its tenant's. A
    /// `consent_granted` the OAuth callback wrote in earlier releases holds
    /// the provider's `provider_id` slug instead, so only appliance-wide
    /// callers read it.
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
    /// The variant of the surface `surface_id` names that served the request:
    /// the variant's alias, `_base_` when the base surface served it, or
    /// `_unknown_` when the URL named a variant the surface doesn't have.
    /// Absent outside surface requests and on a misconfigured default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_variant: Option<String>,
    /// Additional context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The tenant of the surface the record is about, on records that say
    /// whose surface they are. Absent for an appliance-wide surface and on
    /// records stored before it existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
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
    /// The delegated payment is held for human review.
    Held,
    /// Whether the delegated payment was taken is not known: the payment gateway
    /// did not answer in time or its answer was unusable, and the caller was
    /// told to retry the same request with the same credential.
    Unconfirmed,
    /// Funds are held until the Target delivers.
    Authorized,
    /// Held funds were released without a charge.
    Voided,
    /// Funds settled on-chain / with the payment processor.
    Settled,
    /// Settlement failed after a successful verification.
    SettlementFailed,
}

/// Protocol-independent payment event. Emitted for every outcome of a payment
/// delegated to agent-pay (challenge, paid, held for review, rejected,
/// unavailable): `delegated` is true and the remote ids / status are populated;
/// correlation with the agent-pay gateway's own trail is via the shared
/// top-level `trace_id`. Legacy x402/MPP settlement records may still appear.
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
    /// What agent-pay reported for a delegated payment, delegation only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<Box<DelegatedPaymentFacts>>,
}

/// The facts of one delegated payment, as recorded by the payment gate. Never
/// carries the payment credential; the payer is a hash or a verified agent DID.
#[derive(Debug, Clone, Default, PartialEq, Serialize, serde::Deserialize)]
pub struct DelegatedPaymentFacts {
    /// MCP tool, A2A method or HTTP path the payment was for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// Variant alias of the caller's surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    /// DID of the agent-pay gateway that answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_did: Option<String>,
    /// Oversight case of a held payment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_id: Option<String>,
    /// Fingerprint of agent-pay's receipt credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vc_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// MPP receipt `reference`, or the x402 settlement transaction hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_reference: Option<String>,
    /// MPP receipt `challengeId`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
    /// x402 settlement network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    pub latency_ms: u64,
    /// agent-pay's authorization of funds held until the Target delivers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_id: Option<String>,
    /// The manifest price, when the receipt names a different amount; the
    /// event's `amount` and `currency` are then the receipt's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quoted_amount: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quoted_currency: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub price_mismatch: bool,
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
    /// On a surface slot: the variant whose slot was written, or `_base_` for
    /// a base slot, which also applies to every variant inheriting it. Records
    /// written before the rename stored it as `variant`.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "variant")]
    pub surface_variant: Option<String>,
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
            surface_variant: None,
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

/// A management change to the Target Authentication of one leg of a surface: the Target or a
/// Transit Point, of the base surface or of a variant as it resolves. Names the method and
/// credential provider before and after; never a secret id, header name, header format or value.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct TargetAuthChangeDetails {
    pub actor: Actor,
    /// The variant's alias, or `_base_` for the base surface.
    pub surface_variant: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant_id: Option<String>,
    pub leg: TargetAuthLeg,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transit_point_id: Option<String>,
    /// The Transit Point's alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transit_point: Option<String>,
    pub previous_method: TargetAuthMethodKind,
    pub method: TargetAuthMethodKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    /// The parts a change to an existing setting replaced; empty when the setting was added or
    /// removed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed: Vec<TargetAuthField>,
}

/// A secret deleted with `force=true` through the management API. Names the secret by its id
/// and each record that still used it by kind and id; never the secret's value or a record's
/// name.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct SecretForceDeleteDetails {
    pub actor: Actor,
    pub secret_id: String,
    pub force: bool,
    #[serde(default)]
    pub referrers: Vec<SecretReferrerDetails>,
}

/// A record that used a secret when it was force-deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct SecretReferrerDetails {
    pub kind: String,
    pub id: String,
}

/// What became of a call through a connector's Transit Point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorCallOutcome {
    /// The call, carrying the grant, was sent and the vendor answered.
    Forwarded,
    /// The call was refused before it was forwarded, or its grant was refused
    /// by the vendor.
    Refused,
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
        /// Alias of the Transit Point the request was routed to; omitted
        /// outside the outbound path.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transit_point: Option<String>,
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
    /// Protocol-independent payment event: an agent-pay delegated payment
    /// outcome (challenge, paid, held for review, rejected, unavailable), or a
    /// legacy x402/MPP settlement record. Boxed to keep the enum small.
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
    /// A call through a Transit Point with a connector grant: forwarded to the
    /// vendor, or refused before it was. Carries no argument, token or
    /// vendor text.
    ConnectorCall {
        /// The Transit Point (hop) the call went through.
        transit_point: String,
        /// Whose grant the binding uses: the owner's, or the caller's own.
        /// The record's `user_identity_hash` is the caller either way.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subject: Option<crate::config::agent_surface::GrantSubject>,
        outcome: ConnectorCallOutcome,
        /// On `forwarded`: the class of the vendor's answer (`2xx`, `4xx`...).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status_class: Option<String>,
        /// On `refused`: the fixed reason the caller was told
        /// (`connect_required`, `scope_insufficient`, `connector_unavailable`)
        /// or `caller_not_identified`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        /// On `refused`: the fixed cause inside that reason.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cause: Option<String>,
    },
    RateLimited {
        scope: RateLimitScope,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_ms: Option<u64>,
        /// The Transit Point whose per-caller limit refused the request.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transit_point: Option<String>,
    },
    RequestRejected {
        stage: RejectionStage,
        reason: RejectionReason,
        /// The HTTP status the caller received, on HTTP paths only; absent on
        /// Fabric, where no HTTP response is involved. Legacy MCP refuses a
        /// malformed request with 200 and a JSON-RPC error, so read it with
        /// `rpc_error_code`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        http_status: Option<u16>,
        /// The JSON-RPC error code the caller received, when the refusal was one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rpc_error_code: Option<i64>,
        /// On `unknown_variant` only: the alias the URL named, cut to the
        /// longest alias a variant can have. Caller-chosen text.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        requested_variant: Option<String>,
        /// On `target_auth_failed` only: whether the request was refused or forwarded
        /// without the credential, and the token endpoint's OAuth `error` code.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_auth: Option<TargetAuthRejection>,
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
    /// The Target Authentication of one leg of a surface was added, changed or removed.
    TargetAuthChanged(Box<TargetAuthChangeDetails>),
    /// A secret was deleted with `force=true`, with or without records still using it.
    SecretForceDeleted(Box<SecretForceDeleteDetails>),
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
                | Self::TargetAuthChanged(_)
                | Self::SecretForceDeleted(_)
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

/// The policy decisions embedded in one record's signed VP, if it carries one.
/// Decoding a VP is the most expensive step of an audit read, so it runs only
/// for the records a page needs it for.
fn trace_evidence_of(
    trace_id: &str,
    vp_jwt: &str,
    out: &mut Vec<TracePolicyDecisionEvidence>,
) {
    let Some(value) = decode_vp_value(vp_jwt) else {
        return;
    };
    let mut decisions = Vec::new();
    collect_policy_decisions(&value, &mut decisions);
    out.extend(
        decisions
            .into_iter()
            .map(|decision| TracePolicyDecisionEvidence {
                trace_id: trace_id.to_string(),
                decision,
            }),
    );
}

/// Whether this record is a policy decision whose policy version or content
/// hash is missing, so the signed VP of its trace would fill it in.
fn needs_trace_evidence(event: &DelegationAuditEvent) -> bool {
    matches!(
        &event.event,
        DelegationAuditAction::PolicyDecision {
            policy_version,
            policy_content_hash,
            ..
        } if policy_version.is_none() || policy_content_hash.is_none()
    ) && event.trace_id.is_some()
}

/// Fills in the policy version and content hash of the policy decisions in
/// `events` from the evidence embedded in their trace's signed VP, for rows
/// written before those fields existed.
fn apply_trace_evidence(
    events: &mut [DelegationAuditEvent],
    embedded_decisions: &[TracePolicyDecisionEvidence],
) {
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
/// `{log_directory}/delegation-audit.jsonl` and the journal next to it, rotated
/// as `audit` says, and starts it unless the node is in Standby: only the
/// Active node writes the journal (see [`set_audit_pipeline_mode`]). Call once
/// at startup from the orchestrator.
pub async fn init_audit_logger(
    log_directory: Option<&str>,
    audit: &crate::config::AuditConfig,
) {
    let rotation = audit.rotation();
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
    let _ = AUDIT_SCAN_BYTES.set(rotation.scan_budget());
    let _ = AUDIT_SOFT_CAP_BYTES.set(audit.vp_audit_log_soft_cap_bytes);
    let control = AUDIT_PIPELINE.get_or_init(|| PipelineControl::process_wide(dir, audit_path, rotation));
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
        surface_variant: None,
        detail: None,
        tenant_id: None,
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
        crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject,
            principal_claim,
            claims,
        } => {
            let named_by_sub = principal_claim == crate::jwt_bearer::models::DEFAULT_PRINCIPAL_CLAIM;
            let (sub, principal) = if named_by_sub {
                (Some(subject.clone()), None)
            } else {
                let carried = claims
                    .get(principal_claim.as_str())
                    .and_then(|v| v.as_str())
                    .filter(|value| !value.is_empty() && *value == subject.as_str());
                (
                    claims
                        .get("sub")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    carried.map(String::from),
                )
            };
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
                sub,
                principal,
                token_id: None,
                email: email.map(String::from),
                name: name.map(String::from),
                email_redacted: None,
                name_redacted: None,
                mtls_fingerprint: None,
                mtls_subject_dn: None,
                mtls_issuer_dn: None,
                mtls_source: None,
                user_identity_hash: None,
                peer_gateway: None,
            }
        }
        crate::source_auth::AuthenticatedIdentity::ApiKey { key_name, .. } => AuditCallerContext {
            principal: None,
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
            user_identity_hash: None,
            peer_gateway: None,
        },
        crate::source_auth::AuthenticatedIdentity::DidAuth { did } => AuditCallerContext {
            principal: None,
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
            user_identity_hash: None,
            peer_gateway: None,
        },
        crate::source_auth::AuthenticatedIdentity::Mtls {
            principal,
            fingerprint,
            subject_dn,
            issuer_dn,
            source,
            ..
        } => AuditCallerContext {
            principal: None,
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
            user_identity_hash: None,
            peer_gateway: None,
        },
    }
}

/// Build the `AuditCallerContext` of a delegated credential released on Fabric
/// receive: the caller the receiving surface's own `source_auth` or resource
/// token verified on the request ([`build_caller_context`]), with the paired
/// gateway that sent it as `peer_gateway`: its issuer DID, else its Remote
/// gateway record id.
pub fn fabric_receive_caller_context(
    identity: &crate::source_auth::AuthenticatedIdentity,
    peer_issuer_did: Option<&str>,
    peer_gateway_id: &str,
) -> AuditCallerContext {
    AuditCallerContext {
        peer_gateway: Some(
            peer_issuer_did
                .unwrap_or(peer_gateway_id)
                .to_string(),
        ),
        ..build_caller_context(identity)
    }
}

/// Build an `AuditCallerContext` from the caller context a transit token
/// carries onto a Transit Point: the allowlisted `sub`, `email` and `name`
/// claims captured for Workload Binding, with the inbound caller's DID as the
/// subject when no `sub` claim was carried. `None` when the token names no caller.
/// A token issued for a request a peer gateway sent names the peer (its issuer
/// DID, else its Remote gateway record id) as `peer_gateway`. It is
/// `fabric_verified` when it names the caller the receiving surface verified
/// (`fabric.principal_hash`), with that caller's identity hash and allowlisted
/// `sub`, `email` and `name` only, and no `iss`, since the peer issued none of
/// them. It is `fabric_asserted` otherwise, with the caller DID a presentation
/// from one of the peer's connection issuers carried (`fabric.caller_did`),
/// which this gateway did not verify, as `sub` and the peer that vouched for
/// it as `iss`. Both are a `fabric_peer` caller in Transit Point policy.
pub fn transit_caller_context(claims: &crate::proxy::transit_token::TransitTokenClaims) -> Option<AuditCallerContext> {
    let field = |name: &str| {
        claims
            .caller_context_fields
            .get(name)
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    };
    if let Some(fabric) = &claims.fabric {
        let verified = fabric
            .principal_hash
            .is_some();
        let peer = fabric
            .peer_issuer_did
            .clone()
            .unwrap_or_else(|| fabric.peer_gateway_id.clone());
        return Some(AuditCallerContext {
            principal: None,
            auth_method: if verified {
                "fabric_verified"
            } else {
                "fabric_asserted"
            }
            .to_string(),
            iss: (!verified).then(|| peer.clone()),
            aud: None,
            sub: if verified {
                field("sub")
            } else {
                fabric.caller_did.clone()
            },
            token_id: None,
            email: verified
                .then(|| field("email"))
                .flatten(),
            name: verified
                .then(|| field("name"))
                .flatten(),
            email_redacted: None,
            name_redacted: None,
            mtls_fingerprint: None,
            mtls_subject_dn: None,
            mtls_issuer_dn: None,
            mtls_source: None,
            user_identity_hash: fabric.principal_hash.clone(),
            peer_gateway: Some(peer),
        });
    }
    let sub = field("sub").or_else(|| claims.sub.clone());
    let email = field("email");
    let name = field("name");
    if sub.is_none() && email.is_none() && name.is_none() {
        return None;
    }
    Some(AuditCallerContext {
        principal: None,
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
        user_identity_hash: None,
        peer_gateway: None,
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
        principal: None,
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
        user_identity_hash: None,
        peer_gateway: None,
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
        principal: None,
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
        user_identity_hash: None,
        peer_gateway: None,
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
    /// Whether the read stopped before the end of the audit history — its scan
    /// budget ran out, or a rotated file is missing or unreadable — so `total`,
    /// `total_pages` and `category_counts` describe the records it reached
    /// rather than the whole history.
    pub truncated: bool,
    /// Lines the read met in the history and could not return as records: one
    /// longer than the walk's line buffer, or one an interrupted append left
    /// half-written. The counts are lower bounds by this many, and the records
    /// are not in the page. Counted apart from `truncated`, because the read
    /// did reach the end of the history.
    pub dropped_records: usize,
    /// Bytes the audit history takes on disk: the live log and every rotated
    /// file beside it. `0` unless an appliance-wide caller reads the page.
    pub history_bytes: u64,
    /// The size an operator asked to be told about
    /// (`[audit] vp_audit_log_soft_cap_bytes`), or `0` when none is set or
    /// the caller is not appliance-wide.
    /// Advisory: nothing happens when the history passes it.
    pub soft_cap_bytes: u64,
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
        DelegationAuditAction::ConnectorCall { .. } => "connector_call",
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
        DelegationAuditAction::TargetAuthChanged(_) => "target_auth_changed",
        DelegationAuditAction::SecretForceDeleted(_) => "secret_force_deleted",
    }
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

/// Owned [`AuditLogFilter`], so a read can carry its filters onto a blocking
/// thread.
#[derive(Debug, Default, Clone)]
struct OwnedAuditLogFilter {
    text: Option<String>,
    category: Option<String>,
    flow: Option<String>,
    scope: Option<String>,
    decision: Option<String>,
    exclude_vp_audit: bool,
}

impl From<AuditLogFilter<'_>> for OwnedAuditLogFilter {
    fn from(opts: AuditLogFilter<'_>) -> Self {
        Self {
            text: opts.text.map(String::from),
            category: opts
                .category
                .map(String::from),
            flow: opts.flow.map(String::from),
            scope: opts.scope.map(String::from),
            decision: opts
                .decision
                .map(String::from),
            exclude_vp_audit: opts.exclude_vp_audit,
        }
    }
}

/// The filters one read applies to each record as it walks the history,
/// prepared once for the whole walk.
struct PreparedFilter<'a> {
    /// The records the caller may read: a tenant's token keeps only those of
    /// its own tenant's credential providers.
    reader: &'a VaultReadScope,
    text: Option<String>,
    categories: std::collections::HashSet<&'a str>,
    flow: Option<&'a str>,
    scope: Option<&'a str>,
    decision: Option<&'a str>,
    exclude_vp_audit: bool,
    /// Whether a refinement restricts the view to policy decisions, so a line
    /// that does not name one is dropped before it is parsed.
    policy_decisions_only: bool,
}

/// The stored tag of [`DelegationAuditAction::PolicyDecision`]. Every policy
/// decision carries it, so a line without it is not one.
const POLICY_DECISION_TAG: &str = "\"policy_decision\"";

/// What one stored line was to a read: a record it keeps, a record a filter
/// drops, or a line it could not read as a record at all. The last is told
/// apart from the others so a page can say that what it counted is not
/// everything the history holds.
// The kept record is moved straight into the page being built, so boxing it
// here would cost an allocation per record read to save nothing.
#[allow(clippy::large_enum_variant)]
enum Tallied {
    Kept(DelegationAuditEvent),
    Filtered,
    Unreadable,
}

impl<'a> PreparedFilter<'a> {
    fn new(
        filter: &'a OwnedAuditLogFilter,
        reader: &'a VaultReadScope,
    ) -> Self {
        let refinement = |value: &'a Option<String>| {
            value
                .as_deref()
                .filter(|value| !value.is_empty())
        };
        Self {
            reader,
            text: filter
                .text
                .as_ref()
                .map(|text| text.to_lowercase()),
            categories: filter
                .category
                .as_deref()
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|category| !category.is_empty())
                .collect(),
            flow: refinement(&filter.flow),
            scope: refinement(&filter.scope),
            decision: refinement(&filter.decision),
            exclude_vp_audit: filter.exclude_vp_audit,
            policy_decisions_only: refinement(&filter.flow).is_some()
                || refinement(&filter.scope).is_some()
                || refinement(&filter.decision).is_some(),
        }
    }

    /// The record this stored line holds, unless the caller may not read it or
    /// one of the filters applied before the category tally drops it. The text
    /// filter matches the line as it is stored, so a record no view keeps costs
    /// no parse.
    fn tallied(
        &self,
        line: &str,
    ) -> Tallied {
        if let Some(text) = &self.text
            && !line
                .to_lowercase()
                .contains(text)
        {
            return Tallied::Filtered;
        }
        // A view of policy decisions parses only the lines that name one: on a
        // busy history most records are something else, and parsing each of
        // them to drop it is the bulk of what a page load costs. The same
        // shortcut must not be taken for the category filter, however cheap it
        // looks: the tally below runs before `in_category`, so the counts
        // describe every category of the records the other filters kept, and
        // skipping the unselected ones would make each of their counts read 0
        // exactly while an operator is choosing which to filter to.
        if self.policy_decisions_only && !line.contains(POLICY_DECISION_TAG) {
            return Tallied::Filtered;
        }
        // A line left half-written by a crash is not a record and is not
        // counted as one; the page says so rather than passing silently over
        // evidence it could not read. It names no provider a tenant's scope
        // can be checked against, so only an appliance-wide caller is told.
        let Ok(event) = serde_json::from_str::<DelegationAuditEvent>(line) else {
            return if *self.reader == VaultReadScope::Appliance {
                Tallied::Unreadable
            } else {
                Tallied::Filtered
            };
        };
        // A record the caller may not read is dropped before anything below
        // counts it, so `total`, `total_pages` and `category_counts` describe
        // only the caller's records, and the text filter cannot probe others.
        if !self
            .reader
            .reads(event.provider_id.as_deref())
        {
            return Tallied::Filtered;
        }
        if self.exclude_vp_audit && event.event.is_vp_audit() {
            return Tallied::Filtered;
        }
        // Policy-decision refinements (flow / scope / decision). When any is
        // set the view is restricted to matching PolicyDecision records, so
        // they compose with the category filter and drive the counts and
        // pagination consistently.
        if self.flow.is_some() || self.scope.is_some() || self.decision.is_some() {
            let DelegationAuditAction::PolicyDecision { flow, scope, decision, .. } = &event.event else {
                return Tallied::Filtered;
            };
            let kept = self
                .flow
                .is_none_or(|wanted| flow == wanted)
                && self
                    .scope
                    .is_none_or(|wanted| scope == wanted)
                && self
                    .decision
                    .is_none_or(|wanted| decision == wanted);
            if !kept {
                return Tallied::Filtered;
            }
        }
        Tallied::Kept(event)
    }

    /// Whether the category filter keeps `event`. Applied after the tally, so
    /// `total` and `total_pages` follow the selected category while
    /// `category_counts` still describes every category. A comma-separated list
    /// is an OR set; a blank one filters nothing.
    fn in_category(
        &self,
        event: &DelegationAuditEvent,
    ) -> bool {
        self.categories.is_empty()
            || self
                .categories
                .contains(action_category(&event.event))
    }
}

/// How many reads walk the audit log at once. Parsing the history is the most
/// expensive thing the gateway does off the request path, so concurrent
/// readers — a second dashboard tab, or a filter changed while a page is still
/// loading — wait for each other instead of multiplying that cost. The permit
/// belongs to the blocking read, not to the request that asked for it: a
/// request cancelled mid-read (a disconnect, a reload) leaves the read running,
/// and it must still bar the next one until it is done.
static AUDIT_READS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

/// Runs one audit read on a blocking thread, holding a permit of `reads` for as
/// long as the read runs rather than for as long as the caller waits for it.
async fn under_read_permit<T: Send + 'static>(
    reads: &'static tokio::sync::Semaphore,
    read: impl FnOnce() -> T + Send + 'static,
) -> anyhow::Result<T> {
    let permit = reads.acquire().await?;
    Ok(tokio::task::spawn_blocking(move || {
        let _permit = permit;
        read()
    })
    .await?)
}

/// Bytes of the history one read examines, from the rotation the pipeline was
/// started with, or the default rotation's budget before startup set one.
fn scan_bytes() -> u64 {
    AUDIT_SCAN_BYTES
        .get()
        .copied()
        .unwrap_or_else(|| log_files::Rotation::default().scan_budget())
}

/// The size of the history an operator asked to be told about, or the built-in
/// one before startup set it. Advisory: nothing is enforced at it.
fn soft_cap_bytes() -> u64 {
    AUDIT_SOFT_CAP_BYTES
        .get()
        .copied()
        .unwrap_or(log_files::HISTORY_SOFT_CAP_BYTES)
}

/// Bytes the audit history takes on disk: the running sink's count, which
/// costs nothing to read, or the directory itself while no sink has published
/// one. Called on the blocking thread, because the fallback lists the audit
/// directory.
fn history_bytes_of(path: &Path) -> u64 {
    match AUDIT_HISTORY_BYTES.load(Ordering::Relaxed) {
        u64::MAX => log_files::history_bytes(path),
        published => published,
    }
}

/// Read the audit log with pagination (newest first). Only the records `reader`
/// may read are kept, and every [`AuditLogFilter`] is applied to them **before**
/// pagination and the category tally, so `total`, `total_pages`, and
/// `category_counts` stay consistent with the returned page and count no other
/// record.
///
/// A read walks back from the live log through the rotated files, holding only
/// the page it returns, so it costs the same memory whatever the history has
/// grown to. It examines [`log_files::Rotation::scan_budget`] bytes of the
/// history, which covers every file a configured rotation keeps;
/// [`AuditLogPage::truncated`] says a read stopped before the end of the
/// history, in which case the counts describe the part it reached.
pub async fn read_audit_log(
    page: usize,
    page_size: usize,
    opts: AuditLogFilter<'_>,
    reader: VaultReadScope,
) -> anyhow::Result<AuditLogPage> {
    let path = audit_log_path().ok_or_else(|| anyhow::anyhow!("Audit logger not initialized"))?;
    let filter = OwnedAuditLogFilter::from(opts);

    under_read_permit(&AUDIT_READS, move || {
        let history_bytes = history_bytes_of(&path);
        let prepared = PreparedFilter::new(&filter, &reader);
        read_audit_window(&path, page, page_size, &prepared, scan_bytes(), soft_cap_bytes(), history_bytes)
    })
    .await?
}

/// Walk the audit history into one page. Runs on a blocking thread: the
/// history is read, parsed and filtered off the async runtime, so audit reads
/// never hold up proxy traffic.
///
/// Every filter but the category one is applied to each record as it is met, so
/// the counts and the page describe the same set, and only the page's own
/// records are kept: the page itself, and the last `page_size` matches, which
/// are the page a request past the end of the log clamps to. Memory therefore
/// follows the page size, not the size of the history.
///
/// The walk stops after `scan_bytes` of the history and says so through
/// [`AuditLogPage::truncated`], which a missing rotated file also sets: `total`
/// and `category_counts` are then exact for the records the walk saw, and not
/// for the whole history.
fn read_audit_window(
    path: &Path,
    page: usize,
    page_size: usize,
    prepared: &PreparedFilter<'_>,
    scan_bytes: u64,
    soft_cap_bytes: u64,
    history_bytes: u64,
) -> anyhow::Result<AuditLogPage> {
    let page = page.max(1);
    let page_size = page_size.max(1);
    let start = page
        .saturating_sub(1)
        .saturating_mul(page_size);

    let mut lines = log_files::HistoryLines::open(path);
    let mut truncated = false;
    let mut category_counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut total = 0usize;
    let mut page_events: Vec<DelegationAuditEvent> = Vec::new();
    let mut last_page: std::collections::VecDeque<DelegationAuditEvent> = std::collections::VecDeque::new();
    let mut unreadable = 0usize;
    loop {
        // Charged in the history's own bytes, which is what the budget is
        // written in: the lines the walk dropped or passed over cost it too.
        // Checked before the next line is read, so a budget smaller than the
        // newest record still returns that record.
        if lines.consumed() > scan_bytes {
            truncated = true;
            break;
        }
        let Some(line) = lines.next_line()? else {
            break;
        };
        let event = match prepared.tallied(line.trim()) {
            Tallied::Kept(event) => event,
            Tallied::Filtered => continue,
            Tallied::Unreadable => {
                unreadable += 1;
                continue;
            }
        };
        *category_counts
            .entry(action_category(&event.event).to_string())
            .or_insert(0) += 1;
        if !prepared.in_category(&event) {
            continue;
        }
        if total >= start && page_events.len() < page_size {
            page_events.push(event.clone());
        }
        total += 1;
        if last_page.len() == page_size {
            last_page.pop_front();
        }
        last_page.push_back(event);
    }
    // Read after the walk, not before: a rotated file the walk could not open
    // is only met as it reaches it.
    truncated |= lines.gap();
    let dropped_records = lines
        .dropped()
        .saturating_add(unreadable);
    if dropped_records > 0 {
        warn!(
            target: "credential_delegation",
            dropped_records,
            "Lines of the VP Audit Log could not be read as records; the page's counts are lower bounds"
        );
    }

    let total_pages = if total == 0 {
        1
    } else {
        total.div_ceil(page_size)
    };
    let clamped_page = page.clamp(1, total_pages);
    let mut events = if clamped_page == page {
        page_events
    } else {
        let on_last_page = total - (clamped_page - 1) * page_size;
        let from = last_page.len() - on_last_page;
        Vec::from(last_page.split_off(from))
    };

    enrich_page_from_signed_vps(path, &mut events, scan_bytes)?;

    // The size of the history describes every tenant's records, so only an
    // appliance-wide caller is told it, and the cap it is shown against.
    let told = |bytes: u64| {
        if *prepared.reader == VaultReadScope::Appliance {
            bytes
        } else {
            0
        }
    };
    Ok(AuditLogPage {
        events,
        total,
        page: clamped_page,
        page_size,
        total_pages,
        category_counts,
        truncated,
        dropped_records,
        history_bytes: told(history_bytes),
        soft_cap_bytes: told(soft_cap_bytes),
    })
}

/// Most embedded decisions one page collects, so a trace whose VP carries an
/// unexpected number of them cannot grow a read without bound.
const MAX_TRACE_EVIDENCE: usize = 1024;

/// The traces whose signed VP a page still needs. An empty trace id is left
/// out: it names no trace, and looking for it as a substring would match every
/// line and decode a VP for each one.
fn traces_needing_evidence(events: &[DelegationAuditEvent]) -> std::collections::HashSet<String> {
    events
        .iter()
        .filter(|event| needs_trace_evidence(event))
        .filter_map(|event| event.trace_id.clone())
        .filter(|trace| !trace.is_empty())
        .collect()
}

#[derive(serde::Deserialize)]
struct TraceVpCarrier {
    #[serde(default)]
    trace_id: Option<String>,
    #[serde(default)]
    vp_jwt: Option<String>,
}

/// Fills in the policy version and content hash of the page's policy decisions
/// from the signed VP of each one's trace, for rows written before those fields
/// existed. Only the traces of the page's own rows are looked for, and only a
/// line that names one of them and carries a VP is parsed, so a page decodes at
/// most one VP per row it shows rather than one per record in the history.
///
/// This is a second walk of the same history, under the same budget as the
/// first: the traces it looks for are only known once the page has been
/// selected. It stops as soon as every trace it wants has been found, which on
/// a page of recent rows is within a few records of where it started, because a
/// trace's signed presentation is written in the same request as its decision.
/// A page whose rows are old is the case that costs a second walk, and it costs
/// it only while such rows are on the page.
fn enrich_page_from_signed_vps(
    path: &Path,
    events: &mut [DelegationAuditEvent],
    scan_bytes: u64,
) -> anyhow::Result<()> {
    let traces = traces_needing_evidence(events);
    if traces.is_empty() {
        return Ok(());
    }

    let mut lines = log_files::HistoryLines::open(path);
    let mut embedded_decisions = Vec::new();
    let mut found: std::collections::HashSet<&str> = std::collections::HashSet::new();
    while found.len() < traces.len() && embedded_decisions.len() < MAX_TRACE_EVIDENCE {
        if lines.consumed() > scan_bytes {
            break;
        }
        let Some(line) = lines.next_line()? else {
            break;
        };
        if !line.contains("\"vp_jwt\"")
            || !traces
                .iter()
                .any(|trace| line.contains(trace.as_str()))
        {
            continue;
        }
        let Ok(carrier) = serde_json::from_str::<TraceVpCarrier>(line.trim()) else {
            continue;
        };
        let (Some(trace_id), Some(vp_jwt)) = (carrier.trace_id, carrier.vp_jwt) else {
            continue;
        };
        let Some(wanted) = traces.get(&trace_id) else {
            continue;
        };
        found.insert(wanted.as_str());
        trace_evidence_of(&trace_id, &vp_jwt, &mut embedded_decisions);
    }

    apply_trace_evidence(events, &embedded_decisions);
    Ok(())
}

/// The stored tag of [`DelegationAuditAction::PaymentEvent`]. Every payment
/// record carries it, so a line without it is not one.
const PAYMENT_EVENT_TAG: &str = "\"payment_event\"";

/// One page of the `payment` records of the audit history, newest first.
pub struct PaymentEventsPage {
    pub events: Vec<DelegationAuditEvent>,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
    pub total_pages: usize,
    /// Whether the walk stopped before the end of the history, so `total`
    /// describes the records it reached rather than every payment record the
    /// appliance kept.
    pub truncated: bool,
    /// Lines the walk met and could not return as records; the counts are
    /// lower bounds by this many. See [`AuditLogPage::dropped_records`].
    pub dropped_records: usize,
}

impl PaymentEventsPage {
    /// The empty page a caller gets before the audit pipeline is set up, or
    /// when the read failed. `truncated` then says the page is not the whole
    /// history rather than letting nothing pass for everything.
    fn empty(
        page: usize,
        page_size: usize,
        truncated: bool,
    ) -> Self {
        Self {
            events: Vec::new(),
            total: 0,
            page: page.max(1),
            page_size: page_size.max(1),
            total_pages: 1,
            truncated,
            dropped_records: 0,
        }
    }
}

/// Walks the audit history for the `payment` records `keep` admits, newest
/// first, into one page: the live log, then back through the rotated files,
/// one line at a time, parsing only the lines that name a payment record, and
/// stopping after `scan_bytes` of the history.
///
/// Only the page asked for and the last `page_size` matches are held, so the
/// memory a payments read costs follows the page and not the history — the
/// same bound [`read_audit_window`] keeps, by the same means. The two walks
/// are deliberately separate for now: folding them into one reader is the
/// right end state, and the moment for it is when `total` stops being counted
/// by walking at all.
fn payment_events_in(
    path: &Path,
    scan_bytes: u64,
    page: usize,
    page_size: usize,
    keep: &dyn Fn(&DelegationAuditEvent) -> bool,
) -> anyhow::Result<PaymentEventsPage> {
    let page = page.max(1);
    let page_size = page_size.max(1);
    let start = page
        .saturating_sub(1)
        .saturating_mul(page_size);

    let mut lines = log_files::HistoryLines::open(path);
    let mut truncated = false;
    let mut total = 0usize;
    let mut unreadable = 0usize;
    let mut page_events: Vec<DelegationAuditEvent> = Vec::new();
    let mut last_page: std::collections::VecDeque<DelegationAuditEvent> = std::collections::VecDeque::new();
    loop {
        if lines.consumed() > scan_bytes {
            truncated = true;
            break;
        }
        let Some(line) = lines.next_line()? else {
            break;
        };
        if !line.contains(PAYMENT_EVENT_TAG) {
            continue;
        }
        let Ok(event) = serde_json::from_str::<DelegationAuditEvent>(line.trim()) else {
            unreadable += 1;
            continue;
        };
        if !matches!(event.event, DelegationAuditAction::PaymentEvent(_)) || !keep(&event) {
            continue;
        }
        if total >= start && page_events.len() < page_size {
            page_events.push(event.clone());
        }
        total += 1;
        if last_page.len() == page_size {
            last_page.pop_front();
        }
        last_page.push_back(event);
    }
    truncated |= lines.gap();
    let dropped_records = lines
        .dropped()
        .saturating_add(unreadable);
    if dropped_records > 0 {
        warn!(
            target: "credential_delegation",
            dropped_records,
            "Lines of the VP Audit Log could not be read as records; the payments page's counts are lower bounds"
        );
    }

    let total_pages = if total == 0 {
        1
    } else {
        total.div_ceil(page_size)
    };
    let clamped_page = page.clamp(1, total_pages);
    let events = if clamped_page == page {
        page_events
    } else {
        let on_last_page = total - (clamped_page - 1) * page_size;
        let from = last_page.len() - on_last_page;
        Vec::from(last_page.split_off(from))
    };

    Ok(PaymentEventsPage {
        events,
        total,
        page: clamped_page,
        page_size,
        total_pages,
        truncated,
        dropped_records,
    })
}

/// One page of the `payment` records the VP Audit Log keeps, newest first,
/// read under the permit audit reads share and on a blocking thread. `keep`
/// decides which records the caller may see, inside the walk, so the page and
/// `total` describe the same set. Empty before the audit pipeline is set up,
/// while the log does not exist, or when the read failed — which is reported
/// as truncated, so a payments view never presents what it could not read as
/// the whole history.
pub async fn read_payment_events(
    page: usize,
    page_size: usize,
    keep: impl Fn(&DelegationAuditEvent) -> bool + Send + 'static,
) -> PaymentEventsPage {
    let Some(path) = AUDIT_PATH.get().cloned() else {
        return PaymentEventsPage::empty(page, page_size, false);
    };
    let read =
        under_read_permit(&AUDIT_READS, move || payment_events_in(&path, scan_bytes(), page, page_size, &keep)).await;
    match read {
        Ok(Ok(events)) => events,
        Ok(Err(e)) | Err(e) => {
            warn!(target: "credential_delegation", error = %e, "Failed to read the VP Audit Log's payments");
            PaymentEventsPage::empty(page, page_size, true)
        }
    }
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
        surface_variant: None,
        detail: None,
        tenant_id: None,
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
    transit_point: Option<&str>,
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
            transit_point: transit_point.map(str::to_string),
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
        surface_variant: None,
        detail: None,
        tenant_id: None,
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
        surface_variant: None,
        detail: Some(format!("downstream_trace_id={downstream_trace_id}")),
        tenant_id: None,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audit_line(provider: &str) -> String {
        let event = audit_event(DelegationAuditAction::TokenInjected, None, None, Some(provider), None);
        format!("{}\n", serde_json::to_string(&event).unwrap())
    }

    /// A record the Credential Delegation Audit Log discards: it belongs to the
    /// VP Audit Log, and one per request is the bulk of a busy history.
    fn vp_audit_line() -> String {
        let event = audit_event(
            DelegationAuditAction::TraceTerminated {
                own_trace_id: "own".to_string(),
                downstream_trace_id: "down".to_string(),
                flow: "fabric".to_string(),
            },
            None,
            None,
            None,
            None,
        );
        format!("{}\n", serde_json::to_string(&event).unwrap())
    }

    /// A policy decision whose stored row predates the policy version and
    /// content hash fields, so a page has to take them from its trace's VP.
    fn policy_decision_line(trace_id: &str) -> String {
        let mut event = audit_event(
            DelegationAuditAction::PolicyDecision {
                scope: "surface".to_string(),
                flow: "fabric".to_string(),
                policy_id: "surface.policy".to_string(),
                policy_name: None,
                policy_definition_id: Some("surface-def-1".to_string()),
                decision: "allow".to_string(),
                deny_reason: None,
                surface_id: Some("surface-1".to_string()),
                caller_did: None,
                http_method: None,
                http_path: None,
                policy_version: None,
                policy_content_hash: None,
                removed_tools: None,
            },
            None,
            None,
            None,
            None,
        );
        event.trace_id = Some(trace_id.to_string());
        format!("{}\n", serde_json::to_string(&event).unwrap())
    }

    /// The `vp_injected` record carrying the signed evidence for `trace_id`.
    fn vp_evidence_line(trace_id: &str) -> String {
        let vp = signed_vp_with_policy_decision();
        let mut event = audit_event(DelegationAuditAction::VpInjected, None, None, None, None);
        event.trace_id = Some(trace_id.to_string());
        event.vp_jwt = Some(vp);
        format!("{}\n", serde_json::to_string(&event).unwrap())
    }

    fn delegation_only() -> OwnedAuditLogFilter {
        OwnedAuditLogFilter {
            exclude_vp_audit: true,
            ..Default::default()
        }
    }

    fn whole_history() -> u64 {
        log_files::MAX_SCAN_BYTES
    }

    /// A read on the built-in advisory size, which only the test below asserts
    /// about; it shadows [`super::read_audit_window`] so the other tests read
    /// as what they are about.
    fn read_audit_window(
        path: &Path,
        page: usize,
        page_size: usize,
        filter: &OwnedAuditLogFilter,
        scan_bytes: u64,
    ) -> anyhow::Result<AuditLogPage> {
        super::read_audit_window(
            path,
            page,
            page_size,
            &PreparedFilter::new(filter, &VaultReadScope::Appliance),
            scan_bytes,
            log_files::HISTORY_SOFT_CAP_BYTES,
            log_files::history_bytes(path),
        )
    }

    /// A stored `payment` record of the trace `trace-<id>`.
    fn payment_line(id: &str) -> String {
        let mut event = audit_event(
            DelegationAuditAction::PaymentEvent(Box::new(PaymentEventDetails {
                rail: PaymentRail::X402,
                stage: PaymentStage::Verified,
                transaction_id: id.to_string(),
                amount: None,
                currency: None,
                method: None,
                payer: None,
                error: None,
                delegated: true,
                payment_gateway_id: None,
                payment_surface_id: None,
                remote_status: None,
                delegation: None,
            })),
            None,
            None,
            None,
            Some("s-1"),
        );
        event.trace_id = Some(format!("trace-{id}"));
        format!("{}\n", serde_json::to_string(&event).unwrap())
    }

    fn payment_lines(count: usize) -> String {
        (0..count)
            .map(|n| payment_line(&n.to_string()))
            .collect()
    }

    /// One page of the payment records of the history at `path`, with every
    /// record visible to the caller.
    fn payments(
        path: &Path,
        scan_bytes: u64,
        page: usize,
        page_size: usize,
    ) -> PaymentEventsPage {
        payment_events_in(path, scan_bytes, page, page_size, &|_| true).unwrap()
    }

    fn payment_traces(page: &PaymentEventsPage) -> Vec<&str> {
        page.events
            .iter()
            .filter_map(|event| event.trace_id.as_deref())
            .collect()
    }

    fn written(
        dir: &tempfile::TempDir,
        contents: &str,
    ) -> PathBuf {
        let path = dir
            .path()
            .join("delegation-audit.jsonl");
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn a_read_returns_the_newest_records_first() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = written(&dir, &format!("{}{}", audit_line("first"), audit_line("second")));

        let page = read_audit_window(&path, 1, 10, &OwnedAuditLogFilter::default(), whole_history()).unwrap();

        assert_eq!(page.total, 2);
        assert_eq!(page.total_pages, 1);
        assert_eq!(
            page.events[0]
                .provider_id
                .as_deref(),
            Some("second")
        );
        assert_eq!(
            page.events[1]
                .provider_id
                .as_deref(),
            Some("first")
        );
        assert!(!page.truncated, "the whole history was walked");
    }

    #[test]
    fn a_filter_finds_its_records_behind_a_flood_of_records_it_discards() {
        let dir = tempfile::TempDir::new().unwrap();
        let noise: String = (0..200)
            .map(|_| vp_audit_line())
            .collect();
        let path = written(&dir, &format!("{}{noise}", audit_line("delegated")));

        let page = read_audit_window(&path, 1, 10, &delegation_only(), whole_history()).unwrap();

        assert_eq!(page.total, 1, "the record behind the discarded ones is still found");
        assert_eq!(
            page.events[0]
                .provider_id
                .as_deref(),
            Some("delegated")
        );
        let counts = &page.category_counts;
        assert_eq!(counts.get("token_injected"), Some(&1));
        assert_eq!(counts.get("trace_terminated"), None, "a record the filter drops is counted nowhere");
        assert!(!page.truncated);
    }

    #[test]
    fn a_text_search_finds_a_rare_term_far_back_in_the_history() {
        let dir = tempfile::TempDir::new().unwrap();
        let noise: String = (0..200)
            .map(|_| vp_audit_line())
            .collect();
        let path = written(&dir, &format!("{}{noise}", audit_line("needle-provider")));
        let filter = OwnedAuditLogFilter {
            text: Some("NEEDLE-provider".to_string()),
            ..Default::default()
        };

        let page = read_audit_window(&path, 1, 10, &filter, whole_history()).unwrap();

        assert_eq!(page.total, 1, "the search is not limited to the newest records");
        assert_eq!(
            page.events[0]
                .provider_id
                .as_deref(),
            Some("needle-provider")
        );
    }

    #[test]
    fn a_text_search_for_a_term_no_record_holds_finds_nothing() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = written(&dir, &audit_line("delegated"));
        let filter = OwnedAuditLogFilter {
            text: Some("no-such-provider".to_string()),
            ..Default::default()
        };

        let page = read_audit_window(&path, 1, 10, &filter, whole_history()).unwrap();

        assert_eq!(page.total, 0);
        assert_eq!(page.total_pages, 1);
        assert!(page.events.is_empty());
        let counts = &page.category_counts;
        assert!(counts.is_empty(), "nothing is counted");
    }

    #[test]
    fn a_read_walks_back_into_the_rotated_files_for_the_records_it_wants() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = written(&dir, &vp_audit_line());
        std::fs::write(PathBuf::from(format!("{}.1", path.display())), audit_line("rotated-out")).unwrap();

        let page = read_audit_window(&path, 1, 10, &delegation_only(), whole_history()).unwrap();

        assert_eq!(page.total, 1, "the live log held nothing this view keeps");
        assert_eq!(
            page.events[0]
                .provider_id
                .as_deref(),
            Some("rotated-out")
        );
        assert!(!page.truncated);
    }

    /// A read as the caller `scope` describes, over the whole history.
    fn scoped_read(
        path: &Path,
        filter: &OwnedAuditLogFilter,
        scope: &VaultReadScope,
    ) -> AuditLogPage {
        super::read_audit_window(
            path,
            1,
            10,
            &PreparedFilter::new(filter, scope),
            whole_history(),
            log_files::HISTORY_SOFT_CAP_BYTES,
            log_files::history_bytes(path),
        )
        .unwrap()
    }

    /// The scope of a token of the tenant that owns the provider `cp-a`.
    fn tenant_a() -> VaultReadScope {
        VaultReadScope::Tenant(std::collections::HashSet::from(["cp-a".to_string()]))
    }

    fn text_filter(text: &str) -> OwnedAuditLogFilter {
        OwnedAuditLogFilter {
            text: Some(text.to_string()),
            ..Default::default()
        }
    }

    /// A tenant reads its own providers' records from the rotated files as
    /// from the live log, and neither the counts nor the text filter see any
    /// other record.
    #[test]
    fn a_tenant_reads_only_its_own_records_in_the_live_log_and_the_rotated_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = written(&dir, &format!("{}{}", audit_line("cp-a"), audit_line("cp-b")));
        std::fs::write(
            PathBuf::from(format!("{}.1", path.display())),
            format!("{}{}", audit_line("cp-b"), audit_line("cp-a")),
        )
        .unwrap();

        let page = scoped_read(&path, &OwnedAuditLogFilter::default(), &tenant_a());
        let providers: Vec<Option<&str>> = page
            .events
            .iter()
            .map(|event| event.provider_id.as_deref())
            .collect();
        assert_eq!(providers, [Some("cp-a"), Some("cp-a")], "one from the live log, one from the rotated file");
        assert_eq!((page.total, page.total_pages), (2, 1));
        assert_eq!(page.category_counts, std::collections::BTreeMap::from([("token_injected".to_string(), 2)]));

        let probe = scoped_read(&path, &text_filter("cp-b"), &tenant_a());
        assert_eq!((probe.total, probe.events.len()), (0, 0));
        assert!(
            probe
                .category_counts
                .is_empty()
        );
    }

    /// A line the read cannot parse names no provider the caller can be
    /// checked against, so only an appliance-wide caller is told of it; a
    /// tenant's text filter cannot learn what another tenant's half-written
    /// record holds.
    #[test]
    fn a_half_written_line_is_counted_only_for_an_appliance_wide_caller() {
        let dir = tempfile::TempDir::new().unwrap();
        let crashed = audit_line("cp-b");
        let cut = crashed
            .find("cp-b")
            .expect("the record names its provider")
            + "cp-b\"".len();
        let path = written(&dir, &format!("{}{}", audit_line("cp-a"), &crashed[..cut]));
        let probe = text_filter("cp-b");

        assert_eq!(scoped_read(&path, &probe, &tenant_a()).dropped_records, 0, "a tenant's filter learns nothing");
        assert_eq!(
            scoped_read(&path, &probe, &VaultReadScope::Appliance).dropped_records,
            1,
            "an appliance-wide caller is still told its counts are lower bounds"
        );
    }

    /// The size of the history on disk describes every tenant's records, so
    /// only an appliance-wide caller is told it, and the cap it is shown
    /// against.
    #[test]
    fn only_an_appliance_wide_caller_is_told_the_size_of_the_history() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = written(&dir, &format!("{}{}", audit_line("cp-a"), audit_line("cp-b")));
        let measured = log_files::history_bytes(&path);
        let read = |scope: &VaultReadScope| {
            super::read_audit_window(
                &path,
                1,
                10,
                &PreparedFilter::new(&OwnedAuditLogFilter::default(), scope),
                whole_history(),
                4096,
                measured,
            )
            .unwrap()
        };

        let tenant = read(&tenant_a());
        assert_eq!(
            (tenant.total, tenant.history_bytes, tenant.soft_cap_bytes),
            (1, 0, 0),
            "a tenant reads its own record, not the size of every tenant's"
        );
        let appliance = read(&VaultReadScope::Appliance);
        assert_eq!((appliance.total, appliance.history_bytes, appliance.soft_cap_bytes), (2, measured, 4096));
    }

    #[test]
    fn a_page_reports_the_size_of_the_history_against_the_advisory_cap() {
        let dir = tempfile::TempDir::new().unwrap();
        let live = audit_line("live");
        let rotated = audit_line("rotated");
        let path = written(&dir, &live);
        std::fs::write(PathBuf::from(format!("{}.1", path.display())), &rotated).unwrap();

        let measured = log_files::history_bytes(&path);
        let page = super::read_audit_window(
            &path,
            1,
            10,
            &PreparedFilter::new(&OwnedAuditLogFilter::default(), &VaultReadScope::Appliance),
            whole_history(),
            4096,
            measured,
        )
        .unwrap();

        assert_eq!(measured, (live.len() + rotated.len()) as u64, "the size is the live log plus every rotated file");
        assert_eq!(page.history_bytes, measured, "and the page reports what it was given");
        assert_eq!(page.soft_cap_bytes, 4096, "the advisory size is reported as configured");
    }

    #[test]
    fn a_record_the_read_could_not_read_is_counted_without_calling_the_read_partial() {
        let dir = tempfile::TempDir::new().unwrap();
        // The half-written line an append interrupted by a crash leaves at the
        // end of the live log.
        let crashed = audit_line("half-written");
        let path = written(&dir, &format!("{}{}", audit_line("whole"), &crashed[..crashed.len() / 2]));

        let page = read_audit_window(&path, 1, 10, &OwnedAuditLogFilter::default(), whole_history()).unwrap();

        assert_eq!(page.total, 1, "the record beside it is still counted");
        assert_eq!(page.dropped_records, 1, "the fragment is counted as a record the read could not return");
        assert!(
            !page.truncated,
            "the read reached the end of the history, so it is not reported as having stopped early"
        );
    }

    #[test]
    fn a_read_stops_at_its_scan_budget_and_reports_partial_counts() {
        let dir = tempfile::TempDir::new().unwrap();
        let newest = audit_line("second");
        // One byte under the newest record: the walk stops once it has consumed
        // *more* than the budget, so a budget it has not yet exceeded always
        // returns the record it is reading, however small that budget is.
        let budget = newest.len() as u64 - 1;
        let path = written(&dir, &format!("{}{newest}", audit_line("first")));

        let page = read_audit_window(&path, 1, 10, &OwnedAuditLogFilter::default(), budget).unwrap();

        assert_eq!(page.total, 1, "only the records the walk reached are counted");
        assert_eq!(
            page.events[0]
                .provider_id
                .as_deref(),
            Some("second")
        );
        assert!(page.truncated, "the history held more than the budget");
        assert_eq!(page.dropped_records, 0, "stopping early is not a record the read could not read");
    }

    #[test]
    fn a_budget_that_ends_with_the_history_is_not_reported_as_truncated() {
        let dir = tempfile::TempDir::new().unwrap();
        let contents = format!("{}{}", audit_line("first"), audit_line("second"));
        let budget = contents.len() as u64;
        let path = written(&dir, &contents);
        std::fs::write(PathBuf::from(format!("{}.1", path.display())), "").unwrap();

        let page = read_audit_window(&path, 1, 10, &OwnedAuditLogFilter::default(), budget).unwrap();

        assert_eq!(page.total, 2);
        assert!(!page.truncated, "an empty older file is not more history");
    }

    #[test]
    fn a_missing_rotated_file_is_read_past_and_reported() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = written(&dir, &audit_line("live"));
        // `.2` is missing from the middle of the history, as a crash during a
        // rotation leaves it.
        std::fs::write(PathBuf::from(format!("{}.3", path.display())), audit_line("newest rotated")).unwrap();
        std::fs::write(PathBuf::from(format!("{}.1", path.display())), audit_line("behind the gap")).unwrap();

        let page = read_audit_window(&path, 1, 10, &OwnedAuditLogFilter::default(), whole_history()).unwrap();

        assert_eq!(page.total, 3, "the records behind the gap are still counted");
        assert_eq!(
            page.events[2]
                .provider_id
                .as_deref(),
            Some("behind the gap")
        );
        assert!(page.truncated, "the missing file is not in any count");
    }

    #[test]
    fn the_category_tally_spans_every_category_while_the_page_follows_the_filter() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = written(&dir, &format!("{}{}", audit_line("delegated"), vp_audit_line()));
        let filter = OwnedAuditLogFilter {
            category: Some("token_injected".to_string()),
            ..Default::default()
        };

        let page = read_audit_window(&path, 1, 10, &filter, whole_history()).unwrap();

        let counts = &page.category_counts;
        assert_eq!(page.total, 1, "the page holds the selected category only");
        assert_eq!(counts.get("token_injected"), Some(&1));
        assert_eq!(counts.get("trace_terminated"), Some(&1), "the tally still counts the categories the filter hides");
    }

    #[test]
    fn a_refinement_filter_keeps_only_the_policy_decisions_that_match() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = written(&dir, &format!("{}{}", audit_line("delegated"), policy_decision_line("trace-1")));
        let matching = OwnedAuditLogFilter {
            decision: Some("allow".to_string()),
            ..Default::default()
        };
        let other = OwnedAuditLogFilter {
            decision: Some("deny".to_string()),
            ..Default::default()
        };

        let allowed = read_audit_window(&path, 1, 10, &matching, whole_history()).unwrap();
        let denied = read_audit_window(&path, 1, 10, &other, whole_history()).unwrap();

        assert_eq!(allowed.total, 1, "only the matching policy decision is kept");
        let counts = &allowed.category_counts;
        assert_eq!(counts.get("policy_decision"), Some(&1));
        assert_eq!(
            counts.get("token_injected"),
            None,
            "a record that is not a policy decision is dropped before it is parsed"
        );
        assert_eq!(denied.total, 0, "no record has the other decision");
    }

    #[test]
    fn a_page_in_range_holds_its_own_slice_of_the_history() {
        let dir = tempfile::TempDir::new().unwrap();
        let records: String = (0..5)
            .map(|n| audit_line(&format!("record-{n}")))
            .collect();
        let path = written(&dir, &records);

        let page = read_audit_window(&path, 2, 2, &OwnedAuditLogFilter::default(), whole_history()).unwrap();

        assert_eq!(page.total, 5);
        assert_eq!(page.total_pages, 3);
        assert_eq!(page.page, 2);
        let shown: Vec<Option<&str>> = page
            .events
            .iter()
            .map(|event| event.provider_id.as_deref())
            .collect();
        assert_eq!(shown, vec![Some("record-2"), Some("record-1")], "newest first, second page");
    }

    #[test]
    fn a_page_past_the_end_clamps_to_the_last_page() {
        let dir = tempfile::TempDir::new().unwrap();
        let records: String = (0..5)
            .map(|n| audit_line(&format!("record-{n}")))
            .collect();
        let path = written(&dir, &records);

        let page = read_audit_window(&path, 9, 2, &OwnedAuditLogFilter::default(), whole_history()).unwrap();

        assert_eq!(page.page, 3, "the page is clamped to the last one");
        assert_eq!(page.total, 5);
        let shown: Vec<Option<&str>> = page
            .events
            .iter()
            .map(|event| event.provider_id.as_deref())
            .collect();
        assert_eq!(shown, vec![Some("record-0")], "the last page holds the oldest record alone");
    }

    #[test]
    fn a_page_decision_takes_its_policy_version_from_a_vp_outside_the_page() {
        let dir = tempfile::TempDir::new().unwrap();
        let filler: String = (0..5)
            .map(|n| audit_line(&format!("record-{n}")))
            .collect();
        let path =
            written(&dir, &format!("{}{filler}{}", vp_evidence_line("trace-1"), policy_decision_line("trace-1")));

        let page = read_audit_window(&path, 1, 1, &OwnedAuditLogFilter::default(), whole_history()).unwrap();

        assert_eq!(page.events.len(), 1, "the page holds the policy decision alone");
        match &page.events[0].event {
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

    #[test]
    fn only_the_traces_a_page_still_needs_are_looked_for() {
        let decision = |trace: Option<&str>| {
            let line = policy_decision_line(trace.unwrap_or_default());
            let mut event: DelegationAuditEvent = serde_json::from_str(line.trim()).unwrap();
            event.trace_id = trace.map(str::to_string);
            event
        };
        let stored = {
            let mut event = decision(Some("trace-done"));
            if let DelegationAuditAction::PolicyDecision {
                policy_version,
                policy_content_hash,
                ..
            } = &mut event.event
            {
                *policy_version = Some(4);
                *policy_content_hash = Some("sha256:abc123".to_string());
            }
            event
        };
        let events = vec![decision(Some("trace-1")), decision(Some("")), decision(None), stored];

        let traces = traces_needing_evidence(&events);

        assert_eq!(traces, std::collections::HashSet::from(["trace-1".to_string()]));
    }

    #[test]
    fn a_page_without_a_policy_decision_needing_evidence_is_returned_as_stored() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = written(&dir, &format!("{}{}", vp_evidence_line("trace-1"), audit_line("delegated")));

        let page = read_audit_window(&path, 1, 1, &OwnedAuditLogFilter::default(), whole_history()).unwrap();

        assert_eq!(page.total, 2);
        assert_eq!(
            page.events[0]
                .provider_id
                .as_deref(),
            Some("delegated"),
            "the newest record is returned untouched"
        );
    }

    #[test]
    fn a_page_reports_whether_the_whole_history_was_read() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = written(&dir, &audit_line("delegated"));

        let page = read_audit_window(&path, 1, 10, &OwnedAuditLogFilter::default(), whole_history()).unwrap();
        let body = serde_json::to_value(&page).unwrap();

        assert_eq!(body["truncated"], serde_json::json!(false), "the field reaches the API");
        assert_eq!(body["total"], serde_json::json!(1));
    }

    #[tokio::test]
    async fn a_cancelled_request_holds_the_read_permit_until_the_read_is_done() {
        static READS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
        let (started, has_started) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();

        let reading = tokio::spawn(async move {
            under_read_permit(&READS, move || {
                let _ = started.send(());
                let _ = released.recv();
            })
            .await
        });
        has_started
            .await
            .expect("the read reached its blocking work");
        reading.abort();

        assert!(READS.try_acquire().is_err(), "the permit is held by the read the cancelled request started");

        release.send(()).unwrap();
        let waited = tokio::time::timeout(std::time::Duration::from_secs(5), READS.acquire()).await;

        assert!(
            waited
                .expect("the permit is released once the read finishes")
                .is_ok(),
            "the next read may start"
        );
    }

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
            principal_claim: "sub".to_string(),
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
        assert!(caller.principal.is_none(), "a caller named by sub has no separate principal");
    }

    /// A strategy that names callers by another claim keeps the token's own
    /// `sub` in the record, so it matches the identity provider's logs, and
    /// adds the claim's value as the principal.
    #[test]
    fn caller_context_keeps_the_tokens_sub_beside_another_principal_claim() {
        let identity = crate::source_auth::AuthenticatedIdentity::JwtBearer {
            principal_claim: "oid".to_string(),
            subject: "person-1".to_string(),
            claims: serde_json::json!({ "iss": "https://issuer.example", "sub": "pairwise-sub", "oid": "person-1" }),
        };
        let caller = build_caller_context(&identity);
        assert_eq!(caller.sub.as_deref(), Some("pairwise-sub"));
        assert_eq!(caller.principal.as_deref(), Some("person-1"));
        let without_sub = crate::source_auth::AuthenticatedIdentity::JwtBearer {
            principal_claim: "oid".to_string(),
            subject: "person-1".to_string(),
            claims: serde_json::json!({ "iss": "https://issuer.example", "oid": "person-1" }),
        };
        assert_eq!(build_caller_context(&without_sub).sub, None);
        let without_oid = crate::source_auth::AuthenticatedIdentity::JwtBearer {
            principal_claim: "oid".to_string(),
            subject: "<none>".to_string(),
            claims: serde_json::json!({ "iss": "https://issuer.example", "sub": "pairwise-sub" }),
        };
        let caller = build_caller_context(&without_oid);
        assert_eq!(caller.principal, None, "a token without the claim has no principal, not the placeholder");
        assert_eq!(caller.sub.as_deref(), Some("pairwise-sub"));
    }

    /// The caller of a credential released on Fabric receive is the one the
    /// receiving surface verified, with the peer gateway that sent the request:
    /// its issuer DID, else its record id. A direct caller names no peer.
    #[test]
    fn a_fabric_receive_caller_names_the_peer_and_a_direct_caller_none() {
        let identity = crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject: "alice".to_string(),
            claims: serde_json::json!({ "iss": "https://issuer.example", "sub": "alice" }),
            principal_claim: "sub".to_string(),
        };

        let received = fabric_receive_caller_context(&identity, Some("did:web:partner.example"), "partner-record");
        assert_eq!(
            (received.auth_method.as_str(), received.iss.as_deref(), received.sub.as_deref()),
            ("jwt_bearer", Some("https://issuer.example"), Some("alice"))
        );
        assert_eq!(
            received
                .peer_gateway
                .as_deref(),
            Some("did:web:partner.example")
        );
        assert_eq!(
            fabric_receive_caller_context(&identity, None, "partner-record")
                .peer_gateway
                .as_deref(),
            Some("partner-record")
        );
        assert_eq!(build_caller_context(&identity).peer_gateway, None);
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
    fn a_stored_policy_change_that_names_its_variant_variant_reads_back_as_surface_variant() {
        let stored = serde_json::json!({
            "policy_definition_id": "deny-pii",
            "slot": "inbound",
            "variant": "beta",
            "actor": {"kind": "user", "id": "u-123"},
            "source": "api",
        });

        let change: PolicyChangeDetails = serde_json::from_value(stored).unwrap();

        assert_eq!(
            change
                .surface_variant
                .as_deref(),
            Some("beta")
        );
        let written = serde_json::to_value(&change).unwrap();
        assert_eq!(written["surface_variant"], "beta");
        assert!(
            written
                .get("variant")
                .is_none(),
            "{written}"
        );
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
            surface_variant: None,
            detail: Some("downstream_trace_id=down-456".to_string()),
            tenant_id: None,
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
    fn only_payment_records_are_read_from_the_log_newest_first() {
        let payment = |id: &str| {
            let mut event = audit_event(
                DelegationAuditAction::PaymentEvent(Box::new(PaymentEventDetails {
                    rail: PaymentRail::X402,
                    stage: PaymentStage::Failed,
                    transaction_id: id.to_string(),
                    amount: None,
                    currency: None,
                    method: None,
                    payer: None,
                    error: Some("payment_event mentioned".to_string()),
                    delegated: true,
                    payment_gateway_id: None,
                    payment_surface_id: None,
                    remote_status: None,
                    delegation: None,
                })),
                None,
                None,
                None,
                Some("s-1"),
            );
            event.trace_id = Some(format!("trace-{id}"));
            serde_json::to_string(&event).unwrap()
        };
        let mut other = audit_event(DelegationAuditAction::VpInjected, None, None, None, Some("s-1"));
        other.detail = Some("\"payment_event\" in a detail".to_string());
        let dir = tempfile::TempDir::new().unwrap();
        // The oldest record is in a rotated file, as it is on an appliance
        // that has been taking payments for a while.
        let path = written(
            &dir,
            &[serde_json::to_string(&other).unwrap(), "not json \"payment_event\"".to_string(), payment("new")]
                .join("\n"),
        );
        std::fs::write(PathBuf::from(format!("{}.1", path.display())), format!("{}\n", payment("old"))).unwrap();

        let read = payments(&path, whole_history(), 1, 50);

        assert_eq!(payment_traces(&read), vec!["trace-new", "trace-old"], "a rotated payment record is in the view");
        assert_eq!(read.total, 2, "both are counted");
        assert_eq!(read.dropped_records, 1, "the line that is not a record is counted, not passed over");
        assert!(!read.truncated, "the walk still reached the end of the history");
        let elsewhere = tempfile::TempDir::new().unwrap();
        let empty = payments(&written(&elsewhere, ""), whole_history(), 1, 50);
        assert!(empty.events.is_empty(), "a log with no payment records reads as none");
        assert!(!empty.truncated, "and says so as the whole history");
        assert_eq!(empty.dropped_records, 0);
    }

    #[test]
    fn a_payments_page_holds_its_own_slice_and_clamps_past_the_end() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = written(&dir, &payment_lines(5));

        let first = payments(&path, whole_history(), 1, 2);
        let past_the_end = payments(&path, whole_history(), 9, 2);

        assert_eq!(payment_traces(&first), vec!["trace-4", "trace-3"], "newest first");
        assert_eq!((first.total, first.total_pages, first.page), (5, 3, 1));
        assert_eq!(payment_traces(&past_the_end), vec!["trace-0"], "the last page, not an empty one");
        assert_eq!(past_the_end.page, 3, "a page past the end clamps to the last");
    }

    #[test]
    fn a_payments_read_counts_only_the_records_its_caller_may_see() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = written(&dir, &payment_lines(4));

        let page = payment_events_in(&path, whole_history(), 1, 50, &|event| {
            event
                .trace_id
                .as_deref()
                .is_some_and(|trace| trace == "trace-1" || trace == "trace-3")
        })
        .unwrap();

        assert_eq!(payment_traces(&page), vec!["trace-3", "trace-1"]);
        assert_eq!(page.total, 2, "the records the caller may not see are in no count");
    }

    #[test]
    fn a_payment_read_that_stops_at_its_budget_reports_it() {
        let dir = tempfile::TempDir::new().unwrap();
        let newest = audit_line("second");
        let path = written(&dir, &format!("{}{newest}", audit_line("first")));

        let read = payments(&path, newest.len() as u64, 1, 50);

        assert!(read.events.is_empty(), "neither record is a payment record");
        assert!(read.truncated, "the history held more than the budget");
    }

    #[test]
    fn the_audit_read_and_the_payments_read_agree_on_the_same_history() {
        let dir = tempfile::TempDir::new().unwrap();
        // Payment records in the live log and in a rotated file, with records
        // of other kinds between them.
        let path = written(&dir, &format!("{}{}{}", audit_line("noise"), payment_lines(3), vp_audit_line()));
        std::fs::write(PathBuf::from(format!("{}.1", path.display())), payment_line("rotated")).unwrap();

        let audit = read_audit_window(
            &path,
            1,
            50,
            &OwnedAuditLogFilter {
                category: Some("payment".to_string()),
                ..Default::default()
            },
            whole_history(),
        )
        .unwrap();
        let payments = payments(&path, whole_history(), 1, 50);

        assert_eq!(audit.total, payments.total, "the two reads count the same payment records");
        assert_eq!(
            audit
                .events
                .iter()
                .filter_map(|event| event.trace_id.as_deref())
                .collect::<Vec<_>>(),
            payment_traces(&payments),
            "and hand them back in the same order"
        );
        assert_eq!(audit.truncated, payments.truncated, "and agree on whether they saw all of it");
        assert_eq!(audit.dropped_records, payments.dropped_records, "and on how many records neither could read");
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
            delegation: None,
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
            delegation: None,
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
                transit_point: None,
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
                    transit_point: None,
                },
                "rate_limited",
            ),
            (
                DelegationAuditAction::RequestRejected {
                    stage: RejectionStage::Admission,
                    reason: RejectionReason::BodyTooLarge,
                    http_status: Some(413),
                    rpc_error_code: Some(-32600),
                    requested_variant: None,
                    target_auth: None,
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
            http_status: Some(403),
            rpc_error_code: None,
            requested_variant: None,
            target_auth: None,
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
    fn the_category_tally_counts_every_record_the_walk_sees() {
        let dir = tempfile::TempDir::new().unwrap();
        let consent = audit_event(DelegationAuditAction::ConsentGranted, None, None, None, None);
        let consent = format!("{}\n", serde_json::to_string(&consent).unwrap());
        let path =
            written(&dir, &format!("{consent}{consent}{}{}", audit_line("delegated"), policy_decision_line("trace-1")));

        let page = read_audit_window(&path, 1, 10, &OwnedAuditLogFilter::default(), whole_history()).unwrap();

        let counts = &page.category_counts;
        assert_eq!(page.total, 4);
        assert_eq!(counts.get("consent_granted"), Some(&2));
        assert_eq!(counts.get("token_injected"), Some(&1));
        assert_eq!(counts.get("policy_decision"), Some(&1));
        assert_eq!(counts.get("trust_check"), None, "an untriggered category is absent, not zero");
        assert_eq!(counts.values().sum::<usize>(), page.total);
    }

    fn unsigned_jwt(payload: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
        format!("{header}.{payload}.signature")
    }

    /// A signed VP carrying the policy decision a proxied call was governed by,
    /// with the policy version and content hash an older stored row lacks.
    fn signed_vp_with_policy_decision() -> String {
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
        unsigned_jwt(serde_json::json!({
            "vp": {
                "verifiableCredential": [nested_vc]
            }
        }))
    }

    #[test]
    fn enriches_policy_decision_from_same_trace_signed_vp() {
        let vp = signed_vp_with_policy_decision();
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
                surface_variant: None,
                detail: None,
                tenant_id: None,
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
                surface_variant: None,
                detail: None,
                tenant_id: None,
            },
        ];

        let mut evidence = Vec::new();
        trace_evidence_of("trace-1", &signed_vp_with_policy_decision(), &mut evidence);
        apply_trace_evidence(&mut events, &evidence);

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
            principal_claim: "sub".to_string(),
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

    fn fabric_transit_claims(
        caller_did: Option<&str>,
        peer_issuer_did: Option<&str>,
        principal_hash: Option<&str>,
        fields: serde_json::Value,
    ) -> crate::proxy::transit_token::TransitTokenClaims {
        let mut claims = transit_claims(None, fields);
        claims.identity_source = Some("fabric-presentation".to_string());
        claims.fabric = Some(crate::proxy::transit_token::FabricTransitClaims {
            peer_gateway_id: "partner-record".to_string(),
            peer_issuer_did: peer_issuer_did.map(str::to_string),
            hops: 1,
            caller_did: caller_did.map(str::to_string),
            principal_hash: principal_hash.map(str::to_string),
        });
        claims
    }

    /// A token issued for a request a peer gateway sent names its caller as
    /// the peer asserted it, with the peer as the issuer, never as a caller the
    /// transit token verified.
    #[test]
    fn a_fabric_issued_token_names_the_caller_its_peer_asserted() {
        let caller = transit_caller_context(&fabric_transit_claims(
            Some("did:web:victim"),
            Some("did:web:partner"),
            None,
            serde_json::json!({}),
        ))
        .unwrap();
        assert_eq!(caller.auth_method, "fabric_asserted");
        assert_eq!(caller.iss.as_deref(), Some("did:web:partner"));
        assert_eq!(caller.peer_gateway.as_deref(), Some("did:web:partner"));
        assert_eq!(caller.sub.as_deref(), Some("did:web:victim"));
        assert_eq!(caller.user_identity_hash, None);

        let caller = transit_caller_context(&fabric_transit_claims(None, None, None, serde_json::json!({}))).unwrap();
        assert_eq!(caller.auth_method, "fabric_asserted");
        assert_eq!(caller.iss.as_deref(), Some("partner-record"), "the peer's record without an issuer DID");
        assert_eq!(caller.peer_gateway.as_deref(), Some("partner-record"));
        assert_eq!(caller.sub, None);
    }

    /// A token naming the caller the receiving surface verified on a peer's
    /// request names that caller by its identity hash and the claims the
    /// surface verified, and the peer that sent the request as
    /// `peer_gateway`, never as the issuer of those claims, and never by the
    /// DID the peer asserted.
    #[test]
    fn a_fabric_issued_token_names_the_caller_its_receiving_surface_verified() {
        let caller = transit_caller_context(&fabric_transit_claims(
            Some("did:web:victim"),
            Some("did:web:partner"),
            Some("receiver-verified-hash"),
            serde_json::json!({"sub": "alice", "email": "ada@example.com", "name": "Ada"}),
        ))
        .unwrap();
        assert_eq!(caller.auth_method, "fabric_verified");
        assert_eq!(
            caller
                .user_identity_hash
                .as_deref(),
            Some("receiver-verified-hash")
        );
        assert_eq!(caller.peer_gateway.as_deref(), Some("did:web:partner"));
        assert_eq!(caller.iss, None, "the peer did not issue the claims the receiving surface verified");
        assert_eq!(caller.sub.as_deref(), Some("alice"));
        assert_eq!(caller.email.as_deref(), Some("ada@example.com"));
        assert_eq!(caller.name.as_deref(), Some("Ada"));

        // A caller verified by an API key has no claims: its hash names it.
        let caller = transit_caller_context(&fabric_transit_claims(
            Some("did:web:victim"),
            Some("did:web:partner"),
            Some("receiver-verified-hash"),
            serde_json::json!({}),
        ))
        .unwrap();
        assert_eq!(caller.auth_method, "fabric_verified");
        assert_eq!(
            caller
                .user_identity_hash
                .as_deref(),
            Some("receiver-verified-hash")
        );
        assert_eq!(caller.peer_gateway.as_deref(), Some("did:web:partner"));
        assert_eq!(caller.iss, None);
        assert_eq!(caller.sub, None, "the asserted DID never names a verified caller");
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
            principal_claim: "sub".to_string(),
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
            principal_claim: "sub".to_string(),
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
            audit_trust_check(
                Some("surface-1"),
                None,
                Some("trace-1"),
                "caller",
                Some("did:a"),
                Some("did:e"),
                true,
                None,
            );
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

    #[tokio::test]
    async fn a_trust_check_record_carries_its_transit_point() {
        let ((), events) = crate::audit::producer::capture(async {
            audit_trust_check(
                Some("surface-1"),
                Some("partner-a"),
                Some("trace-1"),
                "target",
                None,
                None,
                false,
                Some("AGENT_CARD_UNAVAILABLE"),
            );
        })
        .await;
        assert_eq!(events.len(), 1);
        let wire = serde_json::to_value(&events[0]).expect("serialize record");
        assert_eq!(wire["event"]["trust_check"]["transit_point"], serde_json::json!("partner-a"));
        let again: DelegationAuditEvent = serde_json::from_value(wire).expect("deserialize record");
        match again.event {
            DelegationAuditAction::TrustCheck { transit_point, leg, .. } => {
                assert_eq!(transit_point.as_deref(), Some("partner-a"));
                assert_eq!(leg, "target");
            }
            other => panic!("expected a trust check, got {other:?}"),
        }
    }

    #[test]
    fn a_trust_check_record_without_a_transit_point_omits_it_and_still_reads() {
        let action = DelegationAuditAction::TrustCheck {
            leg: "caller".to_string(),
            authority_id: None,
            entity_id: None,
            ok: true,
            error_code: None,
            transit_point: None,
        };
        let wire = serde_json::to_value(&action).expect("serialize action");
        assert_eq!(wire["trust_check"]["leg"], serde_json::json!("caller"));
        assert!(
            wire["trust_check"]
                .get("transit_point")
                .is_none(),
            "{wire}"
        );

        match serde_json::from_value::<DelegationAuditAction>(wire).expect("deserialize action") {
            DelegationAuditAction::TrustCheck { transit_point, ok, .. } => {
                assert_eq!(transit_point, None);
                assert!(ok);
            }
            other => panic!("expected a trust check, got {other:?}"),
        }
    }

    #[test]
    fn emitting_before_the_pipeline_starts_does_not_panic() {
        emit("token_injected", || audit_event(DelegationAuditAction::TokenInjected, None, None, None, None));
        submit(audit_event(DelegationAuditAction::TokenInjected, None, None, None, None));
    }
}
