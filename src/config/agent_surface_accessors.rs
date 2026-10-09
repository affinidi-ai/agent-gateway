//! Channel-shaped accessors on [`AgentSurface`].
//!
//! Downstream consumers are moving from `&ChannelMapping` to
//! `&AgentSurface`. Many sites read fields whose names changed namespace
//! (e.g. `channel.target_endpoint` → `surface.target.endpoint`) or
//! whose nesting changed (e.g. `channel.timeout` →
//! `surface.target.networking.timeout`), and some compare against the
//! legacy `ChannelProtocol` enum.
//!
//! These methods provide one-line accessors that mirror the
//! ChannelMapping field shapes so call-site sweeps can be mechanical.
//!
//! New code SHOULD prefer reading from the surface fields directly
//! (`surface.target.endpoint`, `surface.access_point.route`, etc.) —
//! these accessors exist to bridge the migration without forcing every
//! downstream comparison to also flip enum types at the same time.

use super::agent_surface::{AgentSurface, NetworkingConfig, SurfaceProtocol, Target};
use super::types::{
    ChannelProtocol, CircuitBreakerConfig, CustomMetadata, ExtensionRules, MirrorConfig, RetryConfig, TargetAuthConfig,
    TimeoutConfig,
};

impl AgentSurface {
    // ── Identity / addressing ───────────────────────────────────────────────

    /// `Some(surface_id)` — matches `ChannelMapping::config_id` shape.
    /// Surface IDs are non-optional, but legacy callers expect `Option`.
    #[inline]
    pub fn config_id(&self) -> Option<&str> {
        Some(&self.surface_id)
    }

    /// Owned variant for legacy `config_id.clone().unwrap_or_else(...)` callers.
    #[inline]
    pub fn config_id_string(&self) -> String {
        self.surface_id.clone()
    }

    /// Access-point listen address (e.g. `0.0.0.0:8443`).
    #[inline]
    pub fn listen_address(&self) -> &str {
        &self
            .access_point
            .listen_address
    }

    /// Access-point route (URL prefix).
    #[inline]
    pub fn route(&self) -> &str {
        &self.access_point.route
    }

    /// Target upstream endpoint.
    #[inline]
    pub fn target_endpoint(&self) -> &str {
        &self.target.endpoint
    }

    // ── Protocol mapping ────────────────────────────────────────────────────

    /// Returns the surface protocol mapped onto the legacy
    /// [`ChannelProtocol`] enum so existing call sites can keep using
    /// `== ChannelProtocol::Mcp` comparisons during the migration.
    #[inline]
    pub fn channel_protocol(&self) -> ChannelProtocol {
        match self.access_point.protocol {
            SurfaceProtocol::A2a => ChannelProtocol::A2a,
            SurfaceProtocol::Ap2 => ChannelProtocol::Ap2,
            SurfaceProtocol::Mcp => ChannelProtocol::Mcp,
            SurfaceProtocol::DIDComm => ChannelProtocol::DIDComm,
        }
    }

    // ── Target shorthands ───────────────────────────────────────────────────

    /// First caller-authentication method on the access point. Mirrors the
    /// legacy `ChannelMapping::source_auth` field, which carried only the
    /// first configured method.
    #[inline]
    pub fn source_auth(&self) -> Option<&crate::source_auth::SourceAuthConfig> {
        self.access_point
            .caller_authentication
            .as_ref()
            .and_then(|ca| ca.methods.first())
    }

    /// Lift the surface `target.identity_injection` back to the legacy
    /// `ManagedIdentityConfig` shape used by the proxy/MCP pipelines.
    /// Returns `None` when the injection has no recognized type.
    ///
    /// **Deprecated**: prefer the slot-specific accessors
    /// [`Self::inbound_identity`], [`Self::protected_identity`], and
    /// [`Self::external_identity`]. Retained as an alias for `protected_identity()`
    /// until all call sites are migrated.
    #[inline]
    pub fn managed_identity(&self) -> Option<crate::source_auth::ManagedIdentityConfig> {
        self.protected_identity()
            .cloned()
            .or_else(|| {
                crate::config::agent_surface_compat::identity_injection_to_managed_identity(
                    &self.target.identity_injection,
                )
            })
    }

    /// Slot 1 — caller identity extracted from inbound request (CA → AP).
    #[inline]
    pub fn inbound_identity(&self) -> Option<&crate::source_auth::ManagedIdentityConfig> {
        self.identity_slots
            .inbound
            .as_ref()
    }

    /// True when slot 1 derives the caller identity from the request body
    /// (`payload_extraction`). Credential-derived modes (`from_jwt_claim`,
    /// `from_api_key`, `from_mtls`, `static`) source the identity from the
    /// validated credential, not the body, so extension inspection must not
    /// require an inbound identity extension for them.
    #[inline]
    pub fn inbound_identity_requires_payload(&self) -> bool {
        matches!(self.identity_slots.inbound, Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(_)))
    }

    /// Slot 2 — protected agent identity extracted from response (MA → AP).
    #[inline]
    pub fn protected_identity(&self) -> Option<&crate::source_auth::ManagedIdentityConfig> {
        self.identity_slots
            .protected
            .as_ref()
    }

    /// Slot 3 — external agent identity extracted from outbound response (EXT → TP).
    #[inline]
    pub fn external_identity(&self) -> Option<&crate::source_auth::ManagedIdentityConfig> {
        self.identity_slots
            .external
            .as_ref()
    }

    /// Target extension validation rules (request side).
    #[inline]
    pub fn extension_rules(&self) -> Option<&crate::config::types::ExtensionRules> {
        self.target
            .extension_rules
            .as_ref()
    }

    /// Outbound credential bindings for delegation/consent. Prefers the
    /// surface-level `outbound_credentials` field; falls back to projecting
    /// `transit.points[*].transit_credentials` when only the per-hop shape
    /// is populated. Mirrors the conversion in
    /// `agent_surface_compat::to_channel_mapping`.
    pub fn outbound_credentials(&self) -> Vec<crate::config::types::OutboundCredentialBinding> {
        use crate::config::types::{
            ConsentMode, CredentialInjection, CredentialRequirement, OutboundCredentialBinding,
        };
        if !self
            .outbound_credentials
            .is_empty()
        {
            return self
                .outbound_credentials
                .clone();
        }
        self.transit
            .as_ref()
            .map(|t| {
                t.points
                    .iter()
                    .filter_map(|point| {
                        point
                            .transit_credentials
                            .as_ref()
                            .map(|cred| OutboundCredentialBinding {
                                credential_provider_id: cred
                                    .credential_provider_id
                                    .clone(),
                                scopes: cred.scopes.clone(),
                                required_for: CredentialRequirement::All,
                                consent_mode: match cred.consent_mode {
                                    crate::config::agent_surface::ConsentMode::OnDemand => ConsentMode::OnDemand,
                                    crate::config::agent_surface::ConsentMode::PreAuthorize => {
                                        ConsentMode::PreAuthorize
                                    }
                                    crate::config::agent_surface::ConsentMode::Elicit => ConsentMode::Elicit,
                                },
                                inject_as: match &cred.inject_as {
                                    crate::config::agent_surface::CredentialInjection::BearerHeader => {
                                        CredentialInjection::BearerHeader
                                    }
                                    crate::config::agent_surface::CredentialInjection::CustomHeader {
                                        name,
                                        format,
                                    } => CredentialInjection::CustomHeader {
                                        name: name.clone(),
                                        format: format.clone(),
                                    },
                                    crate::config::agent_surface::CredentialInjection::Meta { field } => {
                                        CredentialInjection::Meta { field: field.clone() }
                                    }
                                },
                                elicit_timeout_secs: cred.elicit_timeout_secs,
                                elicit_fallback: match cred.elicit_fallback {
                                    crate::config::agent_surface::ElicitFallback::OnDemand => {
                                        crate::config::types::ElicitFallback::OnDemand
                                    }
                                    crate::config::agent_surface::ElicitFallback::Fail => {
                                        crate::config::types::ElicitFallback::Fail
                                    }
                                },
                            })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Target service-level credentials.
    #[inline]
    pub fn target_auth(&self) -> Option<&TargetAuthConfig> {
        self.target.auth.as_ref()
    }

    /// Target custom-metadata injection (request side).
    #[inline]
    pub fn custom_metadata(&self) -> Option<&CustomMetadata> {
        self.target
            .custom_metadata
            .as_ref()
    }

    /// Target custom-metadata injection (response side).
    #[inline]
    pub fn response_custom_metadata(&self) -> Option<&CustomMetadata> {
        self.target
            .response_custom_metadata
            .as_ref()
    }

    /// Response-side extension rules (for validation).
    #[inline]
    pub fn response_extension_rules(&self) -> Option<&ExtensionRules> {
        self.target
            .extension_rules
            .as_ref()
    }

    /// Auto-pay MPP challenges for fabric:// targets.
    #[inline]
    pub fn mpp_auto_pay(&self) -> bool {
        self.target.mpp_auto_pay
    }

    // ── Networking shorthands ───────────────────────────────────────────────

    #[inline]
    fn networking(&self) -> Option<&NetworkingConfig> {
        self.target
            .networking
            .as_ref()
    }

    #[inline]
    pub fn timeout(&self) -> Option<&TimeoutConfig> {
        self.networking()
            .and_then(|n| n.timeout.as_ref())
    }

    #[inline]
    pub fn retry(&self) -> Option<&RetryConfig> {
        self.networking()
            .and_then(|n| n.retry.as_ref())
    }

    #[inline]
    pub fn circuit_breaker(&self) -> Option<&CircuitBreakerConfig> {
        self.networking()
            .and_then(|n| n.circuit_breaker.as_ref())
    }

    #[inline]
    pub fn mirror(&self) -> Option<&MirrorConfig> {
        self.networking()
            .and_then(|n| n.mirror.as_ref())
    }

    // ── Policy ──────────────────────────────────────────────────────────────

    /// Whether OPA enforcement is enabled at the target (request side).
    /// Matches the legacy `ChannelMapping::opa_enabled` boolean.
    #[inline]
    pub fn opa_enabled(&self) -> bool {
        self.target.policy.is_some()
    }

    /// Whether an access-point-level (inbound) OPA policy is configured.
    /// Distinct from [`Self::opa_enabled`], which gates the target-side
    /// policy. Both can be configured independently and are evaluated
    /// against the same `PolicyInput`.
    #[inline]
    pub fn inbound_opa_enabled(&self) -> bool {
        self.access_point
            .inbound_policy
            .is_some()
    }

    /// Access-point-level OPA policy definition ID, if any.
    #[inline]
    pub fn inbound_opa_policy_definition_id(&self) -> Option<&str> {
        self.access_point
            .inbound_policy
            .as_ref()
            .map(|p| {
                p.policy_definition_id
                    .as_str()
            })
    }

    /// Request-side OPA policy definition ID, if any.
    #[inline]
    pub fn opa_policy_definition_id(&self) -> Option<&str> {
        self.target
            .policy
            .as_ref()
            .map(|p| {
                p.policy_definition_id
                    .as_str()
            })
    }

    /// Response-side OPA policy definition ID, if any.
    #[inline]
    pub fn response_policy_definition_id(&self) -> Option<&str> {
        self.target
            .response_policy
            .as_ref()
            .map(|p| {
                p.policy_definition_id
                    .as_str()
            })
    }

    // ── Payment policy variants ─────────────────────────────────────────────

    /// Returns the legacy x402 config when the target's payment policy is
    /// the X402 variant — mirrors the legacy `channel.payment_policy`.
    #[inline]
    pub fn x402_config(&self) -> Option<&crate::config::types::X402Config> {
        match self
            .target
            .payment_policy
            .as_ref()?
        {
            crate::config::agent_surface::PaymentPolicy::X402(c) => Some(c),
            _ => None,
        }
    }

    /// Returns the MPP config when the target's payment policy is the MPP
    /// variant — mirrors the legacy `channel.mpp_policy`.
    #[inline]
    pub fn mpp_config(&self) -> Option<&crate::mpp::MppConfig> {
        match self
            .target
            .payment_policy
            .as_ref()?
        {
            crate::config::agent_surface::PaymentPolicy::Mpp(c) => Some(c),
            _ => None,
        }
    }

    /// Mirrors legacy `channel.mpp_auto_pay_max_amount`.
    #[inline]
    pub fn mpp_auto_pay_max_amount(&self) -> Option<&str> {
        self.target
            .mpp_auto_pay_max_amount
            .as_deref()
    }

    // ── Access-point shorthands ─────────────────────────────────────────────

    /// Mirrors legacy `channel.override_agent_card_location` — true when
    /// the access point overrides the default agent card location.
    #[inline]
    pub fn override_agent_card_location(&self) -> bool {
        self.access_point
            .agent_card_path
            .is_some()
    }

    /// Mirrors legacy `channel.agent_card_location_path`.
    #[inline]
    pub fn agent_card_location_path(&self) -> Option<&str> {
        self.access_point
            .agent_card_path
            .as_deref()
    }

    /// Trust Recorder configuration on the MA→AP response leg.
    #[inline]
    pub fn trust_recorder(&self) -> Option<&crate::config::types::TrustRecorderConfig> {
        self.access_point
            .trust_recorder
            .as_ref()
    }

    /// Mirrors legacy `channel.didwebvh_identity` — projects the surface's
    /// `agent_surface::DidWebVhIdentityConfig` onto the legacy
    /// `types::DidWebVhIdentityConfig` shape (uuid + DidInjectionMode enum)
    /// the identity manager / surface_integration consumers expect.
    /// Returns `None` when no didwebvh identity is configured or when the
    /// stored identity_id is not a parseable UUID.
    #[cfg(feature = "didwebvh")]
    #[inline]
    pub fn didwebvh_identity_legacy(&self) -> Option<crate::config::types::DidWebVhIdentityConfig> {
        let d = self
            .access_point
            .didwebvh_identity
            .as_ref()?;
        let identity_id = d
            .identity_id
            .as_ref()
            .and_then(|id| uuid::Uuid::parse_str(id).ok())?;
        Some(crate::config::types::DidWebVhIdentityConfig {
            identity_id,
            auto_create: d.auto_create,
            did_path: d.did_path.clone(),
            injection_mode: match d.injection_mode {
                crate::config::agent_surface::DidInjectionMode::Header => {
                    crate::config::types::DidInjectionMode::Header
                }
                crate::config::agent_surface::DidInjectionMode::SignedHeader => {
                    crate::config::types::DidInjectionMode::SignedHeader
                }
                crate::config::agent_surface::DidInjectionMode::ProtocolNative => {
                    crate::config::types::DidInjectionMode::ProtocolNative
                }
            },
        })
    }

    // ── Target shorthands ───────────────────────────────────────────────────

    /// Whether the gateway should bind the extracted inbound identity into a
    /// VP and inject it on the outbound request.
    ///
    /// Returns `true` when either:
    /// - the legacy `target.identity_injection.inject_vp` flag is set (kept
    ///   for surfaces persisted with the old single-block identity model), or
    /// - the new `identity_slots.inbound` is configured. Dropping the
    ///   Identity element on the inbound (CA→AP) edge is treated as an
    ///   explicit signal that the caller identity should travel onwards —
    ///   otherwise the user has no way to enable VP injection through the
    ///   surface builder, which doesn't expose a separate toggle.
    #[inline]
    pub fn inject_identity_vp(&self) -> bool {
        self.target
            .identity_injection
            .inject_vp
            || self
                .identity_slots
                .inbound
                .is_some()
    }

    /// The primary target's Workload Binding config, when set and enabled.
    /// Drives the configurable workload-binding VP on the MA→EXT request leg.
    #[inline]
    pub fn target_workload_binding(&self) -> Option<&crate::config::types::WorkloadBindingConfig> {
        self.target
            .workload_binding
            .as_ref()
            .filter(|wb| wb.enabled)
    }

    // ── Transit shorthands ──────────────────────────────────────────────────

    /// Returns the set of transit points reachable from this surface.
    /// Returns the slice when transit is configured; an empty slice otherwise.
    #[inline]
    pub fn transit_points(&self) -> &[crate::config::agent_surface::TransitPoint] {
        match self.transit.as_ref() {
            Some(t) => &t.points,
            None => &[],
        }
    }

    // ── Protocol / extension helpers ────────────────────────────────────────

    /// Mirrors `ChannelMapping::is_ucp()` — true when the access point is
    /// A2A and at least one of the advertised extensions is a UCP extension.
    pub fn is_ucp(&self) -> bool {
        if !matches!(self.access_point.protocol, SurfaceProtocol::A2a) {
            return false;
        }
        if let Some(ref primary) = self
            .access_point
            .primary_extension
            && primary.contains("ucp.dev")
        {
            return true;
        }
        self.access_point
            .supported_extensions
            .iter()
            .any(|ext| ext.contains("ucp.dev"))
    }

    // ── Tags-derived flags ──────────────────────────────────────────────────

    /// True when this surface was lifted from a `ChannelType::Onboarding`
    /// channel (encoded as the `system:onboarding` tag during compat
    /// projection). Mirrors the `state.channel.channel_type ==
    /// ChannelType::Onboarding` comparison.
    pub fn is_onboarding(&self) -> bool {
        self.tags
            .iter()
            .any(|t| t == "system:onboarding")
    }

    // ── Borrow-typed view helpers ───────────────────────────────────────────

    /// Borrow the target struct (commonly needed for callers that read
    /// several fields in succession).
    #[inline]
    #[allow(dead_code)]
    pub fn target(&self) -> &Target {
        &self.target
    }

    /// Validate outbound (transit) configuration. Returns a list of error
    /// strings; empty means valid. Mirrors `ChannelMapping::validate_outbound`
    /// but reads directly from the surface's `transit` block.
    pub fn validate_outbound(&self) -> Vec<String> {
        let mut errors = Vec::new();

        let Some(transit) = self.transit.as_ref() else {
            return errors;
        };
        if transit.points.is_empty() {
            return errors;
        }

        let has_channel_listen_address = transit
            .outbound_listen_address
            .as_ref()
            .is_some_and(|a| !a.trim().is_empty());
        let all_points_have_listen_address = transit
            .points
            .iter()
            .all(|tp| {
                tp.listen_address
                    .as_ref()
                    .is_some_and(|a| !a.trim().is_empty())
            });
        if !has_channel_listen_address && !all_points_have_listen_address {
            errors.push(
                "outbound.enabled is true but outbound_listen_address is not set and one or more transit points lack listen_address — an outbound listener is required"
                    .to_string(),
            );
        }

        let mut seen_aliases = std::collections::HashSet::new();
        for tp in &transit.points {
            if let Err(e) = super::types::validate_outbound_alias(&tp.alias) {
                errors.push(format!("outbound_virtual_channel '{}': {}", tp.alias, e));
            }
            if !seen_aliases.insert(tp.alias.clone()) {
                errors.push(format!("outbound_virtual_channel alias '{}' is not unique within this channel", tp.alias));
            }
        }

        let mut seen_listener_paths: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
        for tp in &transit.points {
            if let Some(ref p) = tp.listen_path {
                if let Err(e) = super::types::validate_outbound_listen_path(p) {
                    errors.push(format!("outbound_virtual_channel '{}': {}", tp.alias, e));
                    continue;
                }
                let effective_addr = tp
                    .listen_address
                    .clone()
                    .or_else(|| {
                        transit
                            .outbound_listen_address
                            .clone()
                    })
                    .unwrap_or_default();
                let key = (effective_addr, p.clone());
                if !seen_listener_paths.insert(key) {
                    errors.push(format!(
                        "outbound_virtual_channel '{}': listen_path '{}' collides with another VC on the same listener",
                        tp.alias, p
                    ));
                }
            }
        }

        errors
    }

    /// Map legacy `ChannelMapping::channel_type` from the surface tag set.
    /// Mirrors the inverse projection in `agent_surface_compat::to_channel_mapping_inner`.
    #[inline]
    pub fn channel_type(&self) -> super::types::SurfaceType {
        if self
            .tags
            .iter()
            .any(|t| t == "system:onboarding")
        {
            super::types::SurfaceType::Onboarding
        } else if self
            .tags
            .iter()
            .any(|t| t == "system")
        {
            super::types::SurfaceType::System
        } else {
            super::types::SurfaceType::default()
        }
    }

    /// Project the surface's `target.mcp_tool_policies` (entries) into
    /// the legacy `McpToolPolicy` shape used by the dashboard/UI DTOs.
    /// The actual policy text lives in the OPA definition store and
    /// is intentionally not duplicated here.
    pub fn mcp_tool_policies_legacy(&self) -> Vec<super::types::McpToolPolicy> {
        self.target
            .mcp_tool_policies
            .iter()
            .map(|entry| super::types::McpToolPolicy {
                id: entry.tool_name.clone(),
                name: entry.tool_name.clone(),
                description: entry.description.clone(),
                policy: String::new(),
                enforce: true,
                priority: 0,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::agent_surface::{AccessPoint, IdentityInjectionConfig, SurfaceStatus};

    fn surface(protocol: SurfaceProtocol) -> AgentSurface {
        AgentSurface {
            surface_id: "surf-1".to_string(),
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
                protocol,
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
                supported_extensions: vec![],
                primary_extension: None,
                agent_card_path: None,
                response_custom_metadata: None,
                #[cfg(feature = "didwebvh")]
                didwebvh_identity: None,
                terminate_trace_id: false,
            },
            target: Target {
                endpoint: "https://upstream:9000".to_string(),
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
            variants: vec![],
            default_variant_id: None,
            outbound_credentials: vec![],
            identity_slots: Default::default(),
            mcp_legacy_metadata_output: None,
            _retired_protocol_mode: Default::default(),
            mcp_http: None,
        }
    }

    #[test]
    fn protocol_maps_through() {
        let s = surface(SurfaceProtocol::Mcp);
        assert_eq!(s.channel_protocol(), ChannelProtocol::Mcp);
        let s = surface(SurfaceProtocol::A2a);
        assert_eq!(s.channel_protocol(), ChannelProtocol::A2a);
    }

    #[test]
    fn config_id_wraps_surface_id() {
        let s = surface(SurfaceProtocol::A2a);
        assert_eq!(s.config_id(), Some("surf-1"));
        assert_eq!(s.config_id_string(), "surf-1");
    }

    #[test]
    fn target_endpoint_borrowed() {
        let s = surface(SurfaceProtocol::A2a);
        assert_eq!(s.target_endpoint(), "https://upstream:9000");
    }

    #[test]
    fn opa_enabled_derived_from_policy() {
        let mut s = surface(SurfaceProtocol::A2a);
        assert!(!s.opa_enabled());
        s.target.policy = Some(crate::config::agent_surface::PolicyRef {
            policy_definition_id: "pd-1".to_string(),
            require_agent_context: false,
        });
        assert!(s.opa_enabled());
        assert_eq!(s.opa_policy_definition_id(), Some("pd-1"));
    }

    #[test]
    fn inbound_opa_enabled_derived_from_access_point_policy() {
        let mut s = surface(SurfaceProtocol::A2a);
        assert!(!s.inbound_opa_enabled());
        assert!(
            s.inbound_opa_policy_definition_id()
                .is_none()
        );
        s.access_point.inbound_policy = Some(crate::config::agent_surface::PolicyRef {
            policy_definition_id: "inbound-pd-1".to_string(),
            require_agent_context: false,
        });
        assert!(s.inbound_opa_enabled());
        assert_eq!(s.inbound_opa_policy_definition_id(), Some("inbound-pd-1"));
        assert!(!s.opa_enabled(), "inbound policy must not flip the target-side opa_enabled flag");
    }

    #[test]
    fn networking_helpers_drill_into_nested_struct() {
        let mut s = surface(SurfaceProtocol::A2a);
        assert!(s.timeout().is_none());
        assert!(s.retry().is_none());
        assert!(s.mirror().is_none());
        s.target.networking = Some(NetworkingConfig {
            timeout: Some(TimeoutConfig::default()),
            retry: None,
            circuit_breaker: None,
            mirror: None,
        });
        assert!(s.timeout().is_some());
        assert!(s.retry().is_none());
    }

    #[test]
    fn is_ucp_a2a_with_primary_ucp_extension() {
        let mut s = surface(SurfaceProtocol::A2a);
        s.access_point
            .primary_extension = Some("https://ucp.dev/foo".to_string());
        assert!(s.is_ucp());
    }

    #[test]
    fn is_ucp_false_when_not_a2a() {
        let mut s = surface(SurfaceProtocol::Mcp);
        s.access_point
            .primary_extension = Some("https://ucp.dev/foo".to_string());
        assert!(!s.is_ucp());
    }

    #[test]
    fn is_onboarding_from_tag() {
        let mut s = surface(SurfaceProtocol::A2a);
        assert!(!s.is_onboarding());
        s.tags
            .push("system:onboarding".to_string());
        assert!(s.is_onboarding());
    }

    #[test]
    fn inject_identity_vp_false_when_nothing_configured() {
        let s = surface(SurfaceProtocol::A2a);
        assert!(!s.inject_identity_vp());
    }

    #[test]
    fn inject_identity_vp_true_from_legacy_flag() {
        let mut s = surface(SurfaceProtocol::A2a);
        s.target
            .identity_injection
            .inject_vp = true;
        assert!(s.inject_identity_vp());
    }

    #[test]
    fn inject_identity_vp_true_when_inbound_slot_configured() {
        use crate::source_auth::ManagedIdentityConfig;
        use crate::source_auth::models::PayloadExtractionConfig;
        let mut s = surface(SurfaceProtocol::A2a);
        assert!(!s.inject_identity_vp());
        s.identity_slots.inbound = Some(ManagedIdentityConfig::PayloadExtraction(PayloadExtractionConfig {
            extension_uri: None,
            meta_field: "agentIdentity".to_string(),
            ..Default::default()
        }));
        assert!(s.inject_identity_vp(), "dropping Identity element on inbound edge should imply VP injection");
    }
}
