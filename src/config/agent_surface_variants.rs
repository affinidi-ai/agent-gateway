//! Surface Variants — full-surface snapshots addressed by `$alias`.
//!
//! A `SurfaceVariant` carries a sparse delta over the base
//! [`AgentSurface`]. Resolving a variant produces a fully materialised
//! `AgentSurface` with the variant's overrides applied. This module owns
//! the storage shape and merge logic.

use serde::{Deserialize, Serialize};

use super::agent_surface::{
    AccessPoint, AgentSurface, CallerAuthentication, CallerContext, DidWebVhIdentityConfig, IdentityInjectionConfig,
    IdentityResolution, McpToolGatingConfig, McpToolPolicyEntry, NetworkingConfig, PaymentPolicy, PolicyRef,
    SharedTransitConfig, SurfaceIdentitySlots, Target, TransitConfig, TransitPoint,
};
use super::types::{CustomMetadata, ExtensionRules, OutboundCredentialBinding, RateLimitConfig, TargetAuthConfig};
use crate::config::header_metadata_mapping::HeaderMetadataMappingConfig;
use crate::source_auth::SourceAuthConfig;

// ─── SurfaceVariant ─────────────────────────────────────────────────────────

/// A complete, named, switchable snapshot of an [`AgentSurface`], stored as
/// a sparse delta over the base.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceVariant {
    /// Stable UUID identifier. Survives renames of `alias` and `name`.
    pub id: String,

    /// URL-safe alias used in `IN_HOST/route$alias/...` and
    /// `OUT_HOST/route$alias/tp-name/...`. Grammar: `^[a-z0-9-]{1,32}$`.
    pub alias: String,

    /// Human-readable name shown in the dashboard.
    pub name: String,

    /// Free-text description.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,

    /// Whether this variant accepts traffic. Disabled variants are still
    /// resolvable for debugging and UI display, but the proxy answers any
    /// request that selects a disabled variant with HTTP 503 ("listener
    /// temporarily unavailable") — not 404 — to signal that the route
    /// exists but is intentionally switched off.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Sparse delta over the base surface.
    #[serde(default, skip_serializing_if = "SurfaceOverrides::is_empty")]
    pub overrides: SurfaceOverrides,
}

impl SurfaceVariant {
    /// Compiled regex pattern for `alias` validation. Mirrored by the
    /// dashboard so both sides reject the same shapes.
    #[allow(dead_code)]
    pub const ALIAS_PATTERN: &'static str = r"^[a-z0-9-]{1,32}$";

    /// Returns `Ok(())` if the alias matches `ALIAS_PATTERN`. The error
    /// message includes the offending alias for echoing back to the user.
    pub fn validate_alias(alias: &str) -> Result<(), String> {
        if alias.is_empty() {
            return Err("variant alias is required".to_string());
        }
        if alias.len() > 32 {
            return Err(format!("variant alias '{alias}' must be 32 characters or fewer"));
        }
        for c in alias.chars() {
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
                return Err(format!("variant alias '{alias}' may only contain lowercase letters, digits, and dashes"));
            }
        }
        Ok(())
    }
}

/// Errors returned by [`AgentSurface::validate_variants`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VariantValidationError {
    /// A variant's `alias` failed grammar validation.
    InvalidAlias { id: String, reason: String },
    /// Two variants on the same surface share an alias.
    DuplicateAlias(String),
    /// Two variants on the same surface share an id.
    DuplicateId(String),
    /// `default_variant_id` is set but no variant has that id.
    DefaultMissing(String),
}

impl std::fmt::Display for VariantValidationError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::InvalidAlias { id, reason } => write!(f, "variant '{id}': {reason}"),
            Self::DuplicateAlias(a) => write!(f, "duplicate variant alias '{a}'"),
            Self::DuplicateId(i) => write!(f, "duplicate variant id '{i}'"),
            Self::DefaultMissing(i) => write!(f, "default_variant_id '{i}' does not match any variant"),
        }
    }
}

impl std::error::Error for VariantValidationError {}

fn default_true() -> bool {
    true
}

// ─── SurfaceOverrides ───────────────────────────────────────────────────────

/// A delta over an [`AgentSurface`].
///
/// Two semantics are supported, selected by the `complete` flag:
///
/// - `complete: false` (default, legacy) — sparse merge. `None` at any
///   `Option<T>` field means "inherit from base"; `Some(v)` means "use
///   `v`". Vector/map fields nested in the override sub-shapes are
///   replaced wholesale when `Some`, never merged element-wise.
/// - `complete: true` — frozen snapshot. Every overridable field is
///   wholesale-replaced from the override, including `Option<T>` fields
///   set to `None` (which clear base's value). Surface-level identifier
///   fields on the base (`access_point.listen_address`, `.route`,
///   `.protocol`, `transit.outbound_listen_address`) are still carried
///   from base — variants cannot change those. Use this when the
///   variant is a fully-snapshotted copy of the surface at create time
///   and must not silently inherit later base edits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceOverrides {
    /// Wholesale-replace flag — see struct docs.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub complete: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_point: Option<AccessPointOverrides>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetOverrides>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transit: Option<TransitOverrides>,

    /// Per-variant identity-slot bindings (inbound / protected / external).
    /// Slots are defined in full per variant — they are not shared with the
    /// base surface — so rotating a credential in one variant cannot
    /// silently affect another. When `Some`, replaces the base surface's
    /// `identity_slots` wholesale at resolve time. When `None`, the base
    /// surface's slots are used as-is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_slots: Option<SurfaceIdentitySlots>,

    /// Per-variant outbound credential bindings (consent_required signalling,
    /// OAuth token injection, etc.). Replaces the base surface's
    /// `outbound_credentials` list wholesale when `Some`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_credentials: Option<Vec<OutboundCredentialBinding>>,

    /// Per-variant override of the management dashboard's opaque canvas
    /// blob (positions, viewport, canvas-only NPC/human/caller nodes).
    /// When `Some`, replaces the base surface's `canvas` wholesale at
    /// resolve time so each variant can keep its own layout — including
    /// positions for variant-only transit points and any external
    /// endpoint nodes that exist only on the canvas. The runtime never
    /// reads this field; it round-trips verbatim for the dashboard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canvas: Option<serde_json::Value>,
}

impl SurfaceOverrides {
    /// `true` when no field is overridden — equivalent to "this variant is
    /// identical to base." The `complete` flag is ignored: a complete
    /// override with no payload fields is still semantically empty.
    pub fn is_empty(&self) -> bool {
        self.access_point.is_none()
            && self.target.is_none()
            && self.transit.is_none()
            && self.identity_slots.is_none()
            && self
                .outbound_credentials
                .is_none()
            && self.canvas.is_none()
    }
}

// ─── AccessPointOverrides ───────────────────────────────────────────────────

/// Overridable subset of [`AccessPoint`].
///
/// Excludes `listen_address`, `route`, and `protocol` — those are
/// surface-level and cannot vary per variant.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessPointOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_authentication: Option<CallerAuthentication>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_context: Option<CallerContext>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_resolution: Option<IdentityResolution>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_policy: Option<PolicyRef>,

    /// Inbound rate limit override (Access Point ingress only). Outbound
    /// rate limits live on `TransitPoint.rate_limit` and
    /// `SharedTransitConfig.rate_limit`; the Target itself carries no
    /// rate limit, so there is no inbound/outbound overlap on a single
    /// field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_validation: Option<ExtensionRules>,

    /// Caller-leg trust-check declarations override (AP→MA). Replaces
    /// the base `trust_check_list` wholesale when `Some`; `None`
    /// inherits the base list in partial mode and clears it in
    /// `complete` mode (mirrors the sibling Option-wrapped fields).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_check_list: Option<Vec<crate::trust_registry_verification::TrustCheckElement>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_metadata_mapping: Option<HeaderMetadataMappingConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_recorder: Option<crate::config::types::TrustRecorderConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish_to_did_document: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported_extensions: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_extension: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_card_path: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_custom_metadata: Option<CustomMetadata>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub didwebvh_identity: Option<DidWebVhIdentityConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminate_trace_id: Option<bool>,
}

impl AccessPointOverrides {
    fn apply(
        self,
        base: &mut AccessPoint,
        complete: bool,
    ) {
        // `complete` mode wholesale-replaces Option-wrapped base fields
        // (including with None). Required (non-Option) base fields are
        // unchanged when the override is None either way — the frontend
        // is expected to always populate them in complete mode.
        if complete {
            base.caller_authentication = self.caller_authentication;
        } else if let Some(v) = self.caller_authentication {
            base.caller_authentication = Some(v);
        }
        if let Some(v) = self.caller_context {
            base.caller_context = v;
        }
        if complete {
            base.identity_resolution = self.identity_resolution;
        } else if let Some(v) = self.identity_resolution {
            base.identity_resolution = Some(v);
        }
        if complete {
            base.inbound_policy = self.inbound_policy;
        } else if let Some(v) = self.inbound_policy {
            base.inbound_policy = Some(v);
        }
        if complete {
            base.rate_limit = self.rate_limit;
        } else if let Some(v) = self.rate_limit {
            base.rate_limit = Some(v);
        }
        if complete {
            base.extension_validation = self.extension_validation;
        } else if let Some(v) = self.extension_validation {
            base.extension_validation = Some(v);
        }
        if complete {
            base.trust_check_list = self
                .trust_check_list
                .unwrap_or_default();
        } else if let Some(v) = self.trust_check_list {
            base.trust_check_list = v;
        }
        if complete {
            base.header_metadata_mapping = self.header_metadata_mapping;
        } else if let Some(v) = self.header_metadata_mapping {
            base.header_metadata_mapping = Some(v);
        }
        if complete {
            base.trust_recorder = self.trust_recorder;
        } else if let Some(v) = self.trust_recorder {
            base.trust_recorder = Some(v);
        }
        if let Some(v) = self.publish_to_did_document {
            base.publish_to_did_document = v;
        }
        if let Some(v) = self.supported_extensions {
            base.supported_extensions = v;
        }
        if complete {
            base.primary_extension = self.primary_extension;
        } else if let Some(v) = self.primary_extension {
            base.primary_extension = Some(v);
        }
        if complete {
            base.agent_card_path = self.agent_card_path;
        } else if let Some(v) = self.agent_card_path {
            base.agent_card_path = Some(v);
        }
        if complete {
            base.response_custom_metadata = self.response_custom_metadata;
        } else if let Some(v) = self.response_custom_metadata {
            base.response_custom_metadata = Some(v);
        }
        if complete {
            base.didwebvh_identity = self.didwebvh_identity;
        } else if let Some(v) = self.didwebvh_identity {
            base.didwebvh_identity = Some(v);
        }
        if let Some(v) = self.terminate_trace_id {
            base.terminate_trace_id = v;
        }
    }
}

// ─── TargetOverrides ────────────────────────────────────────────────────────

/// Overridable subset of [`Target`].
///
/// `endpoint` is overridable — the dev/test/prod use case relies on it.
/// The legacy `variants` and `default_variant_id` fields on `Target` are
/// **not** overridable per variant; variants are managed at the surface
/// level only.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<TargetAuthConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyRef>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_policy: Option<PolicyRef>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_policy: Option<PaymentPolicy>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_tool_policies: Option<Vec<McpToolPolicyEntry>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_tool_policies_enabled: Option<bool>,

    /// MCP Tool Gating override. Replaces the base config wholesale when
    /// `Some`; `None` inherits the base in partial mode and clears it in
    /// `complete` mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_tool_gating: Option<McpToolGatingConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub networking: Option<NetworkingConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_injection: Option<IdentityInjectionConfig>,

    /// Primary-target Workload Binding override (MA→EXT). Replaces the
    /// base `workload_binding` wholesale when `Some`; `None` inherits the
    /// base in partial mode and clears it in `complete` mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_binding: Option<crate::config::types::WorkloadBindingConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_rules: Option<ExtensionRules>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_metadata: Option<CustomMetadata>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_custom_metadata: Option<CustomMetadata>,

    /// Target-leg trust-check declarations override (MA→TP). Replaces
    /// the base `trust_check_list` wholesale when `Some`; `None`
    /// inherits the base list in partial mode and clears it in
    /// `complete` mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_check_list: Option<Vec<crate::trust_registry_verification::TrustCheckElement>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_proxy_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a2a_proxy_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fabric_target_name: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mpp_auto_pay: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mpp_auto_pay_max_amount: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fabric_delegated_credentials: Option<bool>,
}

impl TargetOverrides {
    fn apply(
        self,
        base: &mut Target,
        complete: bool,
    ) {
        if let Some(v) = self.endpoint {
            base.endpoint = v;
        }
        if complete {
            base.auth = self.auth;
        } else if let Some(v) = self.auth {
            base.auth = Some(v);
        }
        if complete {
            base.policy = self.policy;
        } else if let Some(v) = self.policy {
            base.policy = Some(v);
        }
        if complete {
            base.response_policy = self.response_policy;
        } else if let Some(v) = self.response_policy {
            base.response_policy = Some(v);
        }
        if complete {
            base.payment_policy = self.payment_policy;
        } else if let Some(v) = self.payment_policy {
            base.payment_policy = Some(v);
        }
        if let Some(v) = self.mcp_tool_policies {
            base.mcp_tool_policies = v;
        }
        if let Some(v) = self.mcp_tool_policies_enabled {
            base.mcp_tool_policies_enabled = v;
        }
        if complete {
            base.mcp_tool_gating = self.mcp_tool_gating;
        } else if let Some(v) = self.mcp_tool_gating {
            base.mcp_tool_gating = Some(v);
        }
        if complete {
            base.networking = self.networking;
        } else if let Some(v) = self.networking {
            base.networking = Some(v);
        }
        if let Some(v) = self.identity_injection {
            base.identity_injection = v;
        }
        if complete {
            base.workload_binding = self.workload_binding;
        } else if let Some(v) = self.workload_binding {
            base.workload_binding = Some(v);
        }
        if complete {
            base.extension_rules = self.extension_rules;
        } else if let Some(v) = self.extension_rules {
            base.extension_rules = Some(v);
        }
        if complete {
            base.custom_metadata = self.custom_metadata;
        } else if let Some(v) = self.custom_metadata {
            base.custom_metadata = Some(v);
        }
        if complete {
            base.response_custom_metadata = self.response_custom_metadata;
        } else if let Some(v) = self.response_custom_metadata {
            base.response_custom_metadata = Some(v);
        }
        if complete {
            base.trust_check_list = self
                .trust_check_list
                .unwrap_or_default();
        } else if let Some(v) = self.trust_check_list {
            base.trust_check_list = v;
        }
        if complete {
            base.mcp_proxy_id = self.mcp_proxy_id;
        } else if let Some(v) = self.mcp_proxy_id {
            base.mcp_proxy_id = Some(v);
        }
        if complete {
            base.a2a_proxy_id = self.a2a_proxy_id;
        } else if let Some(v) = self.a2a_proxy_id {
            base.a2a_proxy_id = Some(v);
        }
        if complete {
            base.fabric_target_name = self.fabric_target_name;
        } else if let Some(v) = self.fabric_target_name {
            base.fabric_target_name = Some(v);
        }
        if let Some(v) = self.mpp_auto_pay {
            base.mpp_auto_pay = v;
        }
        if complete {
            base.mpp_auto_pay_max_amount = self.mpp_auto_pay_max_amount;
        } else if let Some(v) = self.mpp_auto_pay_max_amount {
            base.mpp_auto_pay_max_amount = Some(v);
        }
        if complete {
            base.fabric_delegated_credentials = self
                .fabric_delegated_credentials
                .unwrap_or(false);
        } else if let Some(v) = self.fabric_delegated_credentials {
            base.fabric_delegated_credentials = v;
        }
    }
}

// ─── TransitOverrides ───────────────────────────────────────────────────────

/// Overridable subset of [`TransitConfig`].
///
/// `outbound_listen_address` is **not** overridable per variant — like
/// `listen_address`, it is a per-surface listener binding.
///
/// `points` is replaced wholesale when present (you cannot merge individual
/// transit points within a variant; you supply the entire catalog).
/// `shared` is also a wholesale `SharedTransitOverrides` substruct so
/// individual shared fields can be overridden.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitOverrides {
    /// Replaces the entire transit config when set. Use this when the
    /// variant differs structurally (e.g. dev has no outbound at all).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,

    /// When `Some`, replaces `transit.points` wholesale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub points: Option<Vec<TransitPoint>>,

    /// Field-level overrides for `transit.shared`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared: Option<SharedTransitOverrides>,
}

impl TransitOverrides {
    fn apply(
        self,
        base: &mut Option<TransitConfig>,
        complete: bool,
    ) {
        if matches!(self.disabled, Some(true)) {
            *base = None;
            return;
        }
        let target = base.get_or_insert_with(|| TransitConfig {
            points: Vec::new(),
            outbound_listen_address: None,
            shared: SharedTransitConfig::default(),
        });
        if let Some(v) = self.points {
            target.points = v;
        }
        if let Some(v) = self.shared {
            v.apply(&mut target.shared, complete);
        }
    }
}

/// Overridable subset of [`SharedTransitConfig`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedTransitOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transit_token_mode: Option<super::agent_surface::TransitTokenMode>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transit_policy: Option<PolicyRef>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_requests: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_rules: Option<ExtensionRules>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_metadata: Option<CustomMetadata>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_extension_rules: Option<ExtensionRules>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opa_policy_definition_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_auth: Option<SourceAuthConfig>,
}

impl SharedTransitOverrides {
    fn apply(
        self,
        base: &mut SharedTransitConfig,
        complete: bool,
    ) {
        if let Some(v) = self.transit_token_mode {
            base.transit_token_mode = v;
        }
        if complete {
            base.transit_policy = self.transit_policy;
        } else if let Some(v) = self.transit_policy {
            base.transit_policy = Some(v);
        }
        if complete {
            base.rate_limit = self.rate_limit;
        } else if let Some(v) = self.rate_limit {
            base.rate_limit = Some(v);
        }
        if let Some(v) = self.sign_requests {
            base.sign_requests = v;
        }
        if complete {
            base.extension_rules = self.extension_rules;
        } else if let Some(v) = self.extension_rules {
            base.extension_rules = Some(v);
        }
        if complete {
            base.custom_metadata = self.custom_metadata;
        } else if let Some(v) = self.custom_metadata {
            base.custom_metadata = Some(v);
        }
        if complete {
            base.response_extension_rules = self.response_extension_rules;
        } else if let Some(v) = self.response_extension_rules {
            base.response_extension_rules = Some(v);
        }
        if complete {
            base.opa_policy_definition_id = self.opa_policy_definition_id;
        } else if let Some(v) = self.opa_policy_definition_id {
            base.opa_policy_definition_id = Some(v);
        }
        if complete {
            base.source_auth = self.source_auth;
        } else if let Some(v) = self.source_auth {
            base.source_auth = Some(v);
        }
    }
}

// ─── Resolver ───────────────────────────────────────────────────────────────

/// Errors returned by [`AgentSurface::resolve_variant`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VariantResolveError {
    /// A `$alias` was supplied but no variant on the surface matches.
    UnknownAlias(String),
    /// The matched variant is `enabled: false`.
    DisabledVariant(String),
    /// `default_variant_id` is set but no variant has that id. This is a
    /// surface-validation failure that the resolver surfaces verbatim so
    /// the caller can decide whether to fall back to the base.
    MisconfiguredDefault(String),
}

impl std::fmt::Display for VariantResolveError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::UnknownAlias(a) => write!(f, "no variant with alias '{a}' on this surface"),
            Self::DisabledVariant(a) => write!(f, "variant '{a}' is disabled"),
            Self::MisconfiguredDefault(id) => {
                write!(f, "default_variant_id '{id}' does not match any variant")
            }
        }
    }
}

impl std::error::Error for VariantResolveError {}

impl AgentSurface {
    /// Resolve a variant by alias and return a fully-materialised
    /// `AgentSurface` with that variant's overrides applied.
    ///
    /// - When `alias` is `Some`, the named variant is selected.
    /// - When `alias` is `None`, the default variant is selected.
    /// - When the surface has no `variants[]` (or `variants[]` is empty),
    ///   the surface is returned as-is regardless of `alias`. This
    ///   preserves "no variants configured" behaviour during the
    ///   migration window.
    ///
    /// The returned surface has its `variants[]` cleared and
    /// `default_variant_id` set to `None` — the runtime never sees the
    /// variant catalog because resolution has already happened.
    pub fn resolve_variant(
        &self,
        alias: Option<&str>,
    ) -> Result<AgentSurface, VariantResolveError> {
        if self.variants.is_empty() {
            let mut clone = self.clone();
            clone.variants.clear();
            clone.default_variant_id = None;
            return Ok(clone);
        }

        let target_alias = match alias {
            Some(a) => a.to_string(),
            None => match &self.default_variant_id {
                Some(id) => match self
                    .variants
                    .iter()
                    .find(|v| &v.id == id)
                {
                    Some(v) => v.alias.clone(),
                    None => return Err(VariantResolveError::MisconfiguredDefault(id.clone())),
                },
                None => {
                    let mut clone = self.clone();
                    clone.variants.clear();
                    clone.default_variant_id = None;
                    return Ok(clone);
                }
            },
        };

        let variant = match self
            .variants
            .iter()
            .find(|v| v.alias == target_alias)
        {
            Some(v) => v,
            None => return Err(VariantResolveError::UnknownAlias(target_alias)),
        };

        if !variant.enabled {
            return Err(VariantResolveError::DisabledVariant(target_alias));
        }

        let mut resolved = self.clone();
        resolved.variants.clear();
        resolved.default_variant_id = None;

        let overrides = variant.overrides.clone();
        let complete = overrides.complete;
        if let Some(ap) = overrides.access_point {
            ap.apply(&mut resolved.access_point, complete);
        }
        if let Some(t) = overrides.target {
            t.apply(&mut resolved.target, complete);
        }
        if let Some(tr) = overrides.transit {
            tr.apply(&mut resolved.transit, complete);
        }
        if let Some(slots) = overrides.identity_slots {
            resolved.identity_slots = slots;
        }
        if let Some(creds) = overrides.outbound_credentials {
            resolved.outbound_credentials = creds;
        }
        // Per-variant canvas blob fully replaces the base — the
        // dashboard captures positions for variant-only TPs and any
        // canvas-only NPCs (e.g. "External Target" connected to a
        // variant-introduced TP) here so they survive a save/reload.
        if let Some(canvas) = overrides.canvas {
            resolved.canvas = Some(canvas);
        }

        Ok(resolved)
    }

    /// Return the alias of the default variant, if any. Returns `None`
    /// when the surface has no variants or `default_variant_id` is unset
    /// or doesn't match.
    #[allow(dead_code)]
    pub fn default_variant_alias(&self) -> Option<&str> {
        let id = self
            .default_variant_id
            .as_ref()?;
        self.variants
            .iter()
            .find(|v| &v.id == id)
            .map(|v| v.alias.as_str())
    }

    /// Validate the variant catalog on this surface:
    ///
    /// - Every variant's `alias` matches [`SurfaceVariant::ALIAS_PATTERN`].
    /// - Aliases are unique within the surface.
    /// - Ids are unique within the surface.
    /// - `default_variant_id`, when set, matches an existing variant.
    /// - `default_variant_id = None` is allowed even when `variants[]` is
    ///   non-empty: alias-less requests resolve to the bare base surface
    ///   (the implicit "base" default).
    ///
    /// Empty `variants[]` is considered valid for the migration window;
    /// surfaces written by the new model always carry at least a "default"
    /// variant.
    pub fn validate_variants(&self) -> Result<(), VariantValidationError> {
        if self.variants.is_empty() {
            return Ok(());
        }

        let mut seen_aliases: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut seen_ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for v in &self.variants {
            SurfaceVariant::validate_alias(&v.alias)
                .map_err(|reason| VariantValidationError::InvalidAlias { id: v.id.clone(), reason })?;
            if !seen_aliases.insert(v.alias.as_str()) {
                return Err(VariantValidationError::DuplicateAlias(v.alias.clone()));
            }
            if !seen_ids.insert(v.id.as_str()) {
                return Err(VariantValidationError::DuplicateId(v.id.clone()));
            }
        }

        match &self.default_variant_id {
            None => Ok(()),
            Some(id) => {
                if !seen_ids.contains(id.as_str()) {
                    Err(VariantValidationError::DefaultMissing(id.clone()))
                } else {
                    Ok(())
                }
            }
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::agent_surface::{AccessPoint, IdentityInjectionConfig, SurfaceProtocol, SurfaceStatus, Target};

    fn base_surface() -> AgentSurface {
        AgentSurface {
            surface_id: "surface-1".to_string(),
            tenant_id: None,
            name: "test".to_string(),
            description: String::new(),
            status: SurfaceStatus::Active,
            agent_did: None,
            issuer_id: None,
            tags: Vec::new(),
            access_point: AccessPoint {
                name: None,
                listen_address: "0.0.0.0:8443".to_string(),
                route: "/api".to_string(),
                protocol: SurfaceProtocol::A2a,
                caller_authentication: None,
                caller_context: Default::default(),
                identity_resolution: None,
                inbound_policy: None,
                rate_limit: None,
                extension_validation: None,
                trust_check_list: Vec::new(),
                header_metadata_mapping: None,
                trust_recorder: None,
                publish_to_did_document: false,
                supported_extensions: Vec::new(),
                primary_extension: None,
                agent_card_path: None,
                response_custom_metadata: None,
                didwebvh_identity: None,
                terminate_trace_id: false,
            },
            target: Target {
                endpoint: "https://prod.example.com".to_string(),
                auth: None,
                policy: None,
                response_policy: None,
                payment_policy: None,
                mcp_tool_policies: Vec::new(),
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
        }
    }

    fn variant(
        id: &str,
        alias: &str,
        overrides: SurfaceOverrides,
    ) -> SurfaceVariant {
        SurfaceVariant {
            id: id.to_string(),
            alias: alias.to_string(),
            name: alias.to_string(),
            description: String::new(),
            enabled: true,
            overrides,
        }
    }

    // ── Alias validation ────────────────────────────────────────────────

    #[test]
    fn alias_validation_accepts_grammar() {
        for ok in ["a", "abc", "dev", "v1", "long-name", "0123456789012345678901234567890a"] {
            assert!(SurfaceVariant::validate_alias(ok).is_ok(), "should accept '{ok}'");
        }
    }

    #[test]
    fn alias_validation_rejects_bad_grammar() {
        assert!(SurfaceVariant::validate_alias("").is_err(), "empty");
        assert!(SurfaceVariant::validate_alias("UPPER").is_err(), "uppercase");
        assert!(SurfaceVariant::validate_alias("under_score").is_err(), "underscore");
        assert!(SurfaceVariant::validate_alias("dev$prod").is_err(), "dollar");
        assert!(SurfaceVariant::validate_alias("a/b").is_err(), "slash");
        let too_long = "a".repeat(33);
        assert!(SurfaceVariant::validate_alias(&too_long).is_err(), "too long");
    }

    // ── Empty variants[] passes through ─────────────────────────────────

    #[test]
    fn empty_variants_pass_through() {
        let s = base_surface();
        let resolved = s
            .resolve_variant(None)
            .expect("resolve");
        assert_eq!(resolved.target.endpoint, "https://prod.example.com");
        assert!(resolved.variants.is_empty());
        assert_eq!(resolved.default_variant_id, None);
    }

    #[test]
    fn empty_variants_with_alias_pass_through() {
        // Migration window: when no variants are configured, alias is
        // ignored instead of returning `UnknownAlias`.
        let s = base_surface();
        let resolved = s
            .resolve_variant(Some("dev"))
            .expect("resolve");
        assert_eq!(resolved.target.endpoint, "https://prod.example.com");
    }

    // ── Resolution by alias ─────────────────────────────────────────────

    #[test]
    fn resolves_named_variant_overriding_endpoint() {
        let mut s = base_surface();
        s.variants = vec![
            variant("id-default", "default", SurfaceOverrides::default()),
            variant(
                "id-dev",
                "dev",
                SurfaceOverrides {
                    target: Some(TargetOverrides {
                        endpoint: Some("https://dev.example.com".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ),
        ];
        s.default_variant_id = Some("id-default".to_string());

        let resolved = s
            .resolve_variant(Some("dev"))
            .expect("resolve dev");
        assert_eq!(resolved.target.endpoint, "https://dev.example.com");

        let resolved_default = s
            .resolve_variant(None)
            .expect("resolve default");
        assert_eq!(
            resolved_default
                .target
                .endpoint,
            "https://prod.example.com"
        );
    }

    #[test]
    fn variant_override_can_switch_to_a2a_proxy_target() {
        let mut s = base_surface();
        s.variants = vec![variant(
            "id-copilot",
            "copilot",
            SurfaceOverrides {
                target: Some(TargetOverrides {
                    endpoint: Some("a2a-proxy://worker-proxy".to_string()),
                    a2a_proxy_id: Some("worker-proxy".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )];

        let resolved = s
            .resolve_variant(Some("copilot"))
            .expect("resolve copilot variant");
        assert_eq!(resolved.target.endpoint, "a2a-proxy://worker-proxy");
        assert_eq!(
            resolved
                .target
                .a2a_proxy_id
                .as_deref(),
            Some("worker-proxy")
        );
        resolved
            .validate()
            .expect("resolved A2A Proxy target variant should validate");

        let round_tripped = serde_json::to_value(&s).expect("serialize variant surface");
        let again: AgentSurface = serde_json::from_value(round_tripped).expect("deserialize variant surface");
        let resolved_again = again
            .resolve_variant(Some("copilot"))
            .expect("resolve copilot variant after round-trip");
        assert_eq!(resolved_again.target.endpoint, "a2a-proxy://worker-proxy");
        assert_eq!(
            resolved_again
                .target
                .a2a_proxy_id
                .as_deref(),
            Some("worker-proxy")
        );
    }

    #[test]
    fn unknown_alias_errors() {
        let mut s = base_surface();
        s.variants = vec![variant("id-default", "default", SurfaceOverrides::default())];
        s.default_variant_id = Some("id-default".to_string());

        let err = s
            .resolve_variant(Some("nope"))
            .unwrap_err();
        assert_eq!(err, VariantResolveError::UnknownAlias("nope".to_string()));
    }

    #[test]
    fn disabled_variant_errors() {
        let mut s = base_surface();
        let mut dev = variant("id-dev", "dev", SurfaceOverrides::default());
        dev.enabled = false;
        s.variants = vec![variant("id-default", "default", SurfaceOverrides::default()), dev];
        s.default_variant_id = Some("id-default".to_string());

        let err = s
            .resolve_variant(Some("dev"))
            .unwrap_err();
        assert_eq!(err, VariantResolveError::DisabledVariant("dev".to_string()));
    }

    #[test]
    fn misconfigured_default_errors() {
        let mut s = base_surface();
        s.variants = vec![variant("id-default", "default", SurfaceOverrides::default())];
        s.default_variant_id = Some("does-not-exist".to_string());

        let err = s
            .resolve_variant(None)
            .unwrap_err();
        assert_eq!(err, VariantResolveError::MisconfiguredDefault("does-not-exist".to_string()));
    }

    #[test]
    fn default_variant_alias_lookup() {
        let mut s = base_surface();
        s.variants = vec![variant("id-prod", "prod", SurfaceOverrides::default())];
        s.default_variant_id = Some("id-prod".to_string());

        assert_eq!(s.default_variant_alias(), Some("prod"));

        s.default_variant_id = Some("missing".to_string());
        assert_eq!(s.default_variant_alias(), None);

        s.default_variant_id = None;
        assert_eq!(s.default_variant_alias(), None);
    }

    // ── Override application semantics ──────────────────────────────────

    #[test]
    fn empty_overrides_yields_self_minus_variant_catalog() {
        let mut s = base_surface();
        s.variants = vec![variant("id-default", "default", SurfaceOverrides::default())];
        s.default_variant_id = Some("id-default".to_string());

        let resolved = s
            .resolve_variant(None)
            .expect("resolve");
        // Variant catalog stripped from resolved view.
        assert!(resolved.variants.is_empty());
        assert_eq!(resolved.default_variant_id, None);
        // All other fields identical.
        assert_eq!(resolved.target.endpoint, s.target.endpoint);
        assert_eq!(
            resolved
                .access_point
                .listen_address,
            s.access_point.listen_address
        );
    }

    #[test]
    fn target_endpoint_override_does_not_leak_into_other_variants() {
        let mut s = base_surface();
        s.variants = vec![
            variant("id-default", "default", SurfaceOverrides::default()),
            variant(
                "id-dev",
                "dev",
                SurfaceOverrides {
                    target: Some(TargetOverrides {
                        endpoint: Some("https://dev.example.com".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ),
        ];
        s.default_variant_id = Some("id-default".to_string());

        let dev = s
            .resolve_variant(Some("dev"))
            .unwrap();
        let prod = s
            .resolve_variant(None)
            .unwrap();

        assert_eq!(dev.target.endpoint, "https://dev.example.com");
        assert_eq!(prod.target.endpoint, "https://prod.example.com");
        // Original surface untouched.
        assert_eq!(s.target.endpoint, "https://prod.example.com");
    }

    /// Frozen-snapshot mode: when the variant's overrides carry
    /// `complete: true`, `Option<T>` fields on the base must be
    /// wholesale-replaced \u2014 even with `None` \u2014 instead of inherited.
    /// This stops base edits from silently leaking into variants that
    /// were captured before the edit.
    #[test]
    fn complete_overrides_clear_base_option_fields() {
        let mut s = base_surface();
        // Base has a caller-auth strategy set.
        s.access_point
            .caller_authentication = Some(CallerAuthentication { methods: Vec::new() });
        // Variant override carries no caller-auth but is marked complete.
        s.variants = vec![variant(
            "id-frozen",
            "frozen",
            SurfaceOverrides {
                complete: true,
                access_point: Some(AccessPointOverrides::default()),
                ..Default::default()
            },
        )];

        let resolved = s
            .resolve_variant(Some("frozen"))
            .unwrap();
        assert!(
            resolved
                .access_point
                .caller_authentication
                .is_none(),
            "complete override must clear base's caller_authentication"
        );
        // Surface-level identifier preserved from base.
        assert_eq!(
            resolved
                .access_point
                .listen_address,
            "0.0.0.0:8443"
        );
    }

    /// Legacy (sparse) overrides must continue to inherit `None` from
    /// base, so existing storage with `complete: false` keeps working.
    #[test]
    fn sparse_overrides_inherit_base_option_fields() {
        let mut s = base_surface();
        s.access_point
            .caller_authentication = Some(CallerAuthentication { methods: Vec::new() });
        s.variants = vec![variant(
            "id-legacy",
            "legacy",
            SurfaceOverrides {
                // complete: false (default)
                access_point: Some(AccessPointOverrides::default()),
                ..Default::default()
            },
        )];

        let resolved = s
            .resolve_variant(Some("legacy"))
            .unwrap();
        assert!(
            resolved
                .access_point
                .caller_authentication
                .is_some(),
            "sparse override must inherit base's caller_authentication"
        );
    }

    #[test]
    fn variant_overrides_trust_check_list_on_both_legs() {
        use crate::trust_registry_verification::TrustCheckElement;

        let element_for = |id: &str, registry: &str| -> TrustCheckElement {
            serde_json::from_value(serde_json::json!({
                "id": id,
                "trust_registry_id": registry,
                "query_type": "authorization",
                "query": {
                    "authority_id": "did:web:authority.example",
                    "entity_id": "{{ caller.did }}",
                    "action": "invoke"
                }
            }))
            .unwrap()
        };

        let mut s = base_surface();
        s.access_point
            .trust_check_list = vec![element_for("base-caller", "tr-base")];
        s.target.trust_check_list = vec![element_for("base-target", "tr-base")];
        s.variants = vec![
            variant(
                "id-replace",
                "replace",
                SurfaceOverrides {
                    access_point: Some(AccessPointOverrides {
                        trust_check_list: Some(vec![element_for("variant-caller", "tr-variant")]),
                        ..Default::default()
                    }),
                    target: Some(TargetOverrides {
                        trust_check_list: Some(vec![element_for("variant-target", "tr-variant")]),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ),
            variant(
                "id-inherit",
                "inherit",
                SurfaceOverrides {
                    access_point: Some(AccessPointOverrides::default()),
                    target: Some(TargetOverrides::default()),
                    ..Default::default()
                },
            ),
            variant(
                "id-frozen",
                "frozen",
                SurfaceOverrides {
                    complete: true,
                    access_point: Some(AccessPointOverrides::default()),
                    target: Some(TargetOverrides::default()),
                    ..Default::default()
                },
            ),
        ];

        let replace = s
            .resolve_variant(Some("replace"))
            .unwrap();
        assert_eq!(
            replace
                .access_point
                .trust_check_list
                .len(),
            1
        );
        assert_eq!(
            replace
                .access_point
                .trust_check_list[0]
                .id,
            "variant-caller"
        );
        assert_eq!(
            replace
                .target
                .trust_check_list[0]
                .id,
            "variant-target"
        );

        let inherit = s
            .resolve_variant(Some("inherit"))
            .unwrap();
        assert_eq!(
            inherit
                .access_point
                .trust_check_list[0]
                .id,
            "base-caller"
        );
        assert_eq!(
            inherit
                .target
                .trust_check_list[0]
                .id,
            "base-target"
        );

        let frozen = s
            .resolve_variant(Some("frozen"))
            .unwrap();
        assert!(
            frozen
                .access_point
                .trust_check_list
                .is_empty(),
            "complete override with None must clear base's trust_check_list"
        );
        assert!(
            frozen
                .target
                .trust_check_list
                .is_empty()
        );
    }

    #[test]
    fn transit_disabled_clears_transit() {
        let mut s = base_surface();
        s.transit = Some(TransitConfig {
            points: Vec::new(),
            outbound_listen_address: Some("0.0.0.0:9000".to_string()),
            shared: SharedTransitConfig::default(),
        });
        s.variants = vec![
            variant("id-default", "default", SurfaceOverrides::default()),
            variant(
                "id-dev",
                "dev",
                SurfaceOverrides {
                    transit: Some(TransitOverrides {
                        disabled: Some(true),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ),
        ];
        s.default_variant_id = Some("id-default".to_string());

        let dev = s
            .resolve_variant(Some("dev"))
            .unwrap();
        assert!(dev.transit.is_none(), "dev variant disables transit");

        let prod = s
            .resolve_variant(None)
            .unwrap();
        assert!(prod.transit.is_some(), "default keeps transit");
    }

    #[test]
    fn fabric_delegated_credentials_override_fails_closed_in_complete_mode() {
        let mut s = base_surface();
        s.target
            .fabric_delegated_credentials = true;
        let target = |value: Option<bool>| {
            Some(TargetOverrides {
                fabric_delegated_credentials: value,
                ..Default::default()
            })
        };
        s.variants = vec![
            variant(
                "id-sparse",
                "sparse",
                SurfaceOverrides {
                    target: target(None),
                    ..Default::default()
                },
            ),
            variant(
                "id-frozen",
                "frozen",
                SurfaceOverrides {
                    complete: true,
                    target: target(None),
                    ..Default::default()
                },
            ),
            variant(
                "id-off",
                "off",
                SurfaceOverrides {
                    target: target(Some(false)),
                    ..Default::default()
                },
            ),
        ];

        let resolved = |alias| {
            s.resolve_variant(Some(alias))
                .unwrap()
                .target
                .fabric_delegated_credentials
        };
        assert!(resolved("sparse"));
        assert!(!resolved("frozen"));
        assert!(!resolved("off"));

        s.target
            .fabric_delegated_credentials = false;
        s.variants = vec![variant(
            "id-on",
            "on",
            SurfaceOverrides {
                target: target(Some(true)),
                ..Default::default()
            },
        )];
        assert!(
            s.resolve_variant(Some("on"))
                .unwrap()
                .target
                .fabric_delegated_credentials
        );
    }

    // ── JSON round-trip ─────────────────────────────────────────────────

    #[test]
    fn variant_json_round_trip() {
        let v = variant(
            "id-dev",
            "dev",
            SurfaceOverrides {
                target: Some(TargetOverrides {
                    endpoint: Some("https://dev.example.com".to_string()),
                    mpp_auto_pay: Some(true),
                    ..Default::default()
                }),
                access_point: Some(AccessPointOverrides {
                    publish_to_did_document: Some(true),
                    primary_extension: Some("https://ucp.dev/v1".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );

        let json = serde_json::to_string(&v).expect("serialise");
        let back: SurfaceVariant = serde_json::from_str(&json).expect("deserialise");

        assert_eq!(back.id, v.id);
        assert_eq!(back.alias, v.alias);
        assert_eq!(back.enabled, v.enabled);
        let tgt = back
            .overrides
            .target
            .as_ref()
            .expect("target overrides");
        assert_eq!(tgt.endpoint.as_deref(), Some("https://dev.example.com"));
        assert_eq!(tgt.mpp_auto_pay, Some(true));
        let ap = back
            .overrides
            .access_point
            .as_ref()
            .expect("ap overrides");
        assert_eq!(ap.publish_to_did_document, Some(true));
        assert_eq!(
            ap.primary_extension
                .as_deref(),
            Some("https://ucp.dev/v1")
        );
    }

    #[test]
    fn empty_overrides_serialise_compactly() {
        let v = variant("id-default", "default", SurfaceOverrides::default());
        let json = serde_json::to_string(&v).expect("serialise");
        // SurfaceOverrides::is_empty() should suppress the `overrides` field.
        assert!(!json.contains("overrides"), "compact JSON: {json}");
    }

    #[test]
    fn deny_unknown_fields_on_variant() {
        let bad = r#"{
            "id": "x",
            "alias": "x",
            "name": "x",
            "wat": true
        }"#;
        let r: Result<SurfaceVariant, _> = serde_json::from_str(bad);
        assert!(r.is_err(), "unknown field must be rejected");
    }

    /// Per-variant `canvas` overrides must wholesale-replace the base
    /// `canvas` blob at resolve time. Without this, variant-only TPs
    /// and any canvas-only NPC nodes attached to them lose their
    /// positions on save/reload.
    #[test]
    fn canvas_override_replaces_base_canvas_on_resolve() {
        let mut s = base_surface();
        s.canvas = Some(serde_json::json!({"version": 1, "nodes": [{"id": "base-tp"}]}));
        let v_canvas = serde_json::json!({
            "version": 1,
            "nodes": [
                {"id": "variant-tp", "position": {"x": 100.0, "y": 50.0}},
                {"id": "__managed-agent-npc__", "position": {"x": 200.0, "y": 80.0}}
            ]
        });
        let v = variant(
            "v-1",
            "v1",
            SurfaceOverrides {
                canvas: Some(v_canvas.clone()),
                ..Default::default()
            },
        );
        s.variants.push(v);
        s.default_variant_id = Some("v-1".to_string());

        let resolved_default = s
            .resolve_variant(None)
            .expect("resolve default");
        assert_eq!(resolved_default.canvas, Some(v_canvas.clone()));

        // Resolving the bare base (no variants) keeps base's canvas.
        let mut bare = base_surface();
        bare.canvas = Some(serde_json::json!({"version": 1, "nodes": [{"id": "base-tp"}]}));
        let resolved_bare = bare
            .resolve_variant(None)
            .expect("resolve bare");
        assert_eq!(resolved_bare.canvas, Some(serde_json::json!({"version": 1, "nodes": [{"id": "base-tp"}]})));
    }

    /// `is_empty()` must return `false` when only `canvas` is set so the
    /// `overrides` field is not silently elided on serialise.
    #[test]
    fn canvas_only_override_is_not_empty() {
        let mut o = SurfaceOverrides::default();
        assert!(o.is_empty());
        o.canvas = Some(serde_json::json!({"version": 1, "nodes": []}));
        assert!(!o.is_empty(), "canvas-only override must serialise");
    }

    #[test]
    fn deny_unknown_fields_on_overrides() {
        let bad = r#"{ "target": { "endpoint": "x", "wat": true } }"#;
        let r: Result<SurfaceOverrides, _> = serde_json::from_str(bad);
        assert!(r.is_err(), "unknown field on TargetOverrides must be rejected");
    }

    // ── Resolved surface idempotence ────────────────────────────────────

    #[test]
    fn resolving_default_twice_is_idempotent() {
        let mut s = base_surface();
        s.variants = vec![
            variant("id-default", "default", SurfaceOverrides::default()),
            variant(
                "id-dev",
                "dev",
                SurfaceOverrides {
                    target: Some(TargetOverrides {
                        endpoint: Some("https://dev.example.com".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ),
        ];
        s.default_variant_id = Some("id-default".to_string());

        let r1 = s
            .resolve_variant(None)
            .unwrap();
        // The resolved surface has empty variants; resolving again is a
        // no-op pass-through.
        let r2 = r1
            .resolve_variant(None)
            .unwrap();
        assert_eq!(r1.target.endpoint, r2.target.endpoint);
        assert_eq!(r1.access_point.listen_address, r2.access_point.listen_address);
    }

    /// The dashboard's `buildVariantsWireSlice` writes variants in the
    /// shape produced by [`computeOverridesFromPayload`]. This test
    /// proves that shape deserializes into `SurfaceVariant` cleanly
    /// and that `resolve_variant` produces the expected merged surface.
    #[test]
    fn dashboard_wire_shape_round_trips() {
        // Build a base surface, then attach two variants in the exact
        // JSON shape the dashboard sends:
        //   - default ("v1"): empty overrides
        //   - "fast" ("v2"): bumps target.endpoint and access_point.publish_to_did_document
        let mut s = base_surface();
        let wire = serde_json::json!([
            {
                "id": "v1",
                "alias": "def",
                "name": "Default",
                "enabled": true,
                "overrides": {}
            },
            {
                "id": "v2",
                "alias": "fast",
                "name": "Fast",
                "enabled": true,
                "overrides": {
                    "access_point": {
                        "publish_to_did_document": true
                    },
                    "target": {
                        "endpoint": "https://fast.example.com"
                    }
                }
            }
        ]);
        s.variants = serde_json::from_value(wire).expect("wire-shape variants[] must deserialize");
        s.default_variant_id = Some("v1".to_string());

        // Default URL → resolves to base unchanged.
        let resolved_default = s
            .resolve_variant(None)
            .unwrap();
        assert_eq!(
            resolved_default
                .target
                .endpoint,
            "https://prod.example.com"
        );
        assert!(
            !resolved_default
                .access_point
                .publish_to_did_document
        );
        assert!(
            resolved_default
                .variants
                .is_empty()
        );
        assert!(
            resolved_default
                .default_variant_id
                .is_none()
        );

        // $fast → endpoint replaced, did flag flipped, base AP otherwise preserved.
        let resolved_fast = s
            .resolve_variant(Some("fast"))
            .unwrap();
        assert_eq!(resolved_fast.target.endpoint, "https://fast.example.com");
        assert!(
            resolved_fast
                .access_point
                .publish_to_did_document
        );
        assert_eq!(
            resolved_fast
                .access_point
                .listen_address,
            "0.0.0.0:8443"
        );

        // Unknown alias → routing error (caller maps this to 404).
        let err = s
            .resolve_variant(Some("missing"))
            .unwrap_err();
        assert!(matches!(err, VariantResolveError::UnknownAlias(ref a) if a == "missing"));
    }

    // ── Per-variant identity_slots & outbound_credentials ──────────────

    #[test]
    fn identity_slots_override_replaces_base_wholesale() {
        use crate::source_auth::ManagedIdentityConfig;

        let mut s = base_surface();
        // Base surface has a configured `inbound` slot.
        s.identity_slots = SurfaceIdentitySlots {
            inbound: Some(ManagedIdentityConfig::Static {
                did: "did:web:base".to_string(),
            }),
            protected: None,
            external: None,
        };

        // Variant supplies a different `external` slot — and crucially
        // does NOT inherit the base's `inbound`. Per-variant slots are
        // full bindings, not a sparse merge.
        let variant_slots = SurfaceIdentitySlots {
            inbound: None,
            protected: None,
            external: Some(ManagedIdentityConfig::Static {
                did: "did:web:variant-ext".to_string(),
            }),
        };

        s.variants = vec![
            variant("id-default", "default", SurfaceOverrides::default()),
            variant(
                "id-dev",
                "dev",
                SurfaceOverrides {
                    identity_slots: Some(variant_slots.clone()),
                    ..Default::default()
                },
            ),
        ];
        s.default_variant_id = Some("id-default".to_string());

        let dev = s
            .resolve_variant(Some("dev"))
            .unwrap();
        assert!(
            dev.identity_slots
                .inbound
                .is_none(),
            "variant slot bundle is wholesale"
        );
        assert!(
            dev.identity_slots
                .external
                .is_some()
        );

        let default = s
            .resolve_variant(None)
            .unwrap();
        assert!(
            default
                .identity_slots
                .inbound
                .is_some(),
            "default keeps base slots"
        );
        assert!(
            default
                .identity_slots
                .external
                .is_none()
        );
    }

    #[test]
    fn outbound_credentials_override_replaces_base_wholesale() {
        let base_bindings: Vec<OutboundCredentialBinding> = serde_json::from_value(serde_json::json!([{
            "credential_provider_id": "p-base"
        }]))
        .expect("base bindings");
        let variant_bindings: Vec<OutboundCredentialBinding> = serde_json::from_value(serde_json::json!([{
            "credential_provider_id": "p-variant-a"
        }, {
            "credential_provider_id": "p-variant-b"
        }]))
        .expect("variant bindings");

        let mut s = base_surface();
        s.outbound_credentials = base_bindings.clone();
        s.variants = vec![
            variant("id-default", "default", SurfaceOverrides::default()),
            variant(
                "id-dev",
                "dev",
                SurfaceOverrides {
                    outbound_credentials: Some(variant_bindings.clone()),
                    ..Default::default()
                },
            ),
        ];
        s.default_variant_id = Some("id-default".to_string());

        let dev = s
            .resolve_variant(Some("dev"))
            .unwrap();
        assert_eq!(dev.outbound_credentials.len(), 2);
        assert_eq!(dev.outbound_credentials[0].credential_provider_id, "p-variant-a");

        let default = s
            .resolve_variant(None)
            .unwrap();
        assert_eq!(
            default
                .outbound_credentials
                .len(),
            1
        );
        assert_eq!(default.outbound_credentials[0].credential_provider_id, "p-base");
    }

    #[test]
    fn surface_overrides_is_empty_tracks_new_fields() {
        let mut o = SurfaceOverrides::default();
        assert!(o.is_empty());

        o.identity_slots = Some(SurfaceIdentitySlots::default());
        assert!(!o.is_empty(), "identity_slots makes overrides non-empty");

        let o2 = SurfaceOverrides {
            outbound_credentials: Some(Vec::new()),
            ..Default::default()
        };
        assert!(!o2.is_empty(), "outbound_credentials makes overrides non-empty");
    }

    // ── validate_variants() invariants ──────────────────────────────────

    #[test]
    fn validate_empty_variants_is_ok() {
        let s = base_surface();
        assert!(s.validate_variants().is_ok());
    }

    #[test]
    fn validate_allows_none_default_with_variants() {
        // `default_variant_id = None` is valid even when variants[] is
        // non-empty: alias-less URLs resolve to the bare base surface
        // (the implicit "base" default — no overrides applied).
        let mut s = base_surface();
        s.variants = vec![variant("id-1", "default", SurfaceOverrides::default())];
        s.default_variant_id = None;
        assert!(s.validate_variants().is_ok());
    }

    #[test]
    fn validate_default_must_match_existing() {
        let mut s = base_surface();
        s.variants = vec![variant("id-1", "default", SurfaceOverrides::default())];
        s.default_variant_id = Some("missing".to_string());
        assert_eq!(s.validate_variants(), Err(VariantValidationError::DefaultMissing("missing".to_string())));
    }

    #[test]
    fn validate_rejects_duplicate_alias() {
        let mut s = base_surface();
        s.variants = vec![
            variant("id-1", "dup", SurfaceOverrides::default()),
            variant("id-2", "dup", SurfaceOverrides::default()),
        ];
        s.default_variant_id = Some("id-1".to_string());
        assert_eq!(s.validate_variants(), Err(VariantValidationError::DuplicateAlias("dup".to_string())));
    }

    #[test]
    fn validate_rejects_duplicate_id() {
        let mut s = base_surface();
        s.variants =
            vec![variant("dup", "a", SurfaceOverrides::default()), variant("dup", "b", SurfaceOverrides::default())];
        s.default_variant_id = Some("dup".to_string());
        assert_eq!(s.validate_variants(), Err(VariantValidationError::DuplicateId("dup".to_string())));
    }

    #[test]
    fn validate_rejects_bad_alias_grammar() {
        let mut s = base_surface();
        s.variants = vec![variant("id-1", "BAD_ALIAS", SurfaceOverrides::default())];
        s.default_variant_id = Some("id-1".to_string());
        match s.validate_variants() {
            Err(VariantValidationError::InvalidAlias { id, .. }) => assert_eq!(id, "id-1"),
            other => panic!("expected InvalidAlias, got {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_well_formed_catalog() {
        let mut s = base_surface();
        s.variants = vec![
            variant("id-default", "default", SurfaceOverrides::default()),
            variant("id-dev", "dev", SurfaceOverrides::default()),
        ];
        s.default_variant_id = Some("id-default".to_string());
        assert!(s.validate_variants().is_ok());
    }
}
