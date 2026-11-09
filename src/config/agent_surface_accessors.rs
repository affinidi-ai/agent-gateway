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

    /// Caller-authentication methods on the access point, in configured order.
    #[inline]
    pub fn source_auth_methods(&self) -> &[crate::source_auth::SourceAuthConfig] {
        self.access_point
            .caller_authentication
            .as_ref()
            .map_or(&[], |ca| ca.methods.as_slice())
    }

    /// Whether any caller-authentication method forwards the caller's own
    /// credential to the Target (`jwt_bearer` with `forward_header`).
    pub fn forwards_caller_credential(&self) -> bool {
        self.source_auth_methods()
            .iter()
            .any(
                |auth| matches!(auth, crate::source_auth::SourceAuthConfig::JwtBearer(config) if config.forward_header),
            )
    }

    /// Whether every caller-authentication method forwards the caller's own
    /// credential to the Target: a request is forwarded with the credential of
    /// the method it matched, so a method that forwards none leaves its callers
    /// without one.
    pub fn forwards_every_caller_credential(&self) -> bool {
        let methods = self.source_auth_methods();
        !methods.is_empty()
            && methods.iter().all(
                |auth| matches!(auth, crate::source_auth::SourceAuthConfig::JwtBearer(config) if config.forward_header),
            )
    }

    #[inline]
    pub fn has_source_auth(&self) -> bool {
        !self
            .source_auth_methods()
            .is_empty()
    }

    /// The caller-authentication method chosen for this request; see
    /// [`crate::source_auth::models::select_source_auth_method`].
    pub fn source_auth_for_request(
        &self,
        headers: &axum::http::HeaderMap,
        peer_cert: Option<&crate::source_auth::models::PeerCertInfo>,
    ) -> Option<crate::source_auth::models::SourceAuthSelection<'_>> {
        crate::source_auth::models::select_source_auth_method(self.source_auth_methods(), headers, peer_cert.is_some())
    }

    /// The DID Auth method, which serves the `/authenticate` endpoints.
    pub fn did_auth_config(&self) -> Option<&crate::source_auth::models::DidAuthAuthConfig> {
        self.source_auth_methods()
            .iter()
            .find_map(|method| match method {
                crate::source_auth::SourceAuthConfig::DidAuth(config) => Some(config),
                _ => None,
            })
    }

    /// Every header a caller-authentication method reads. The gateway consumes
    /// these credentials, so none of them is forwarded.
    pub fn source_credential_headers(&self) -> Vec<&str> {
        self.source_auth_methods()
            .iter()
            .filter_map(|method| method.credential_header_name())
            .collect()
    }

    /// The DID Auth configurations that mint sessions: the Access Point's DID
    /// Auth caller-authentication method, of which there is at most one, on the
    /// surface and in each variant whose overrides set the Access Point's caller
    /// authentication, with that variant. That method serves `/authenticate`,
    /// and a Transit Point mints no session.
    pub fn session_did_auth_configs(
        &self
    ) -> Vec<(Option<&super::agent_surface_variants::SurfaceVariant>, &crate::source_auth::models::DidAuthAuthConfig)>
    {
        fn did_auth(
            authentication: &super::agent_surface::CallerAuthentication
        ) -> Option<&crate::source_auth::models::DidAuthAuthConfig> {
            authentication
                .methods
                .iter()
                .find_map(|method| match method {
                    crate::source_auth::SourceAuthConfig::DidAuth(config) => Some(config),
                    _ => None,
                })
        }
        self.access_point
            .caller_authentication
            .as_ref()
            .and_then(did_auth)
            .map(|config| (None, config))
            .into_iter()
            .chain(
                self.variants
                    .iter()
                    .filter_map(move |variant| {
                        variant
                            .overrides
                            .access_point
                            .as_ref()?
                            .caller_authentication
                            .as_ref()
                            .and_then(did_auth)
                            .map(|config| (Some(variant), config))
                    }),
            )
            .collect()
    }

    /// Whether any of the Access Point's caller-authentication methods
    /// accepts a caller who names itself: DID Auth without `allowed_dids`
    /// accepts any DID that signs its challenge, so whoever mints one is
    /// authenticated, and named by nobody the gateway can check. No grant by
    /// binding is released to such callers.
    pub fn admits_self_named_callers(&self) -> bool {
        self.access_point
            .caller_authentication
            .as_ref()
            .is_some_and(|authentication| {
                authentication
                    .methods
                    .iter()
                    .any(|method| {
                        matches!(method, crate::source_auth::SourceAuthConfig::DidAuth(config)
                            if config.allowed_dids.is_empty())
                    })
            })
    }

    /// Whether any of the Access Point's caller-authentication methods
    /// accepts a token minted for any service: a JWT bearer method stored
    /// without `audiences` skips the audience check, and one whose
    /// `audience_claim` is `azp` or `client_id` checks only the client the
    /// token was issued to, unless the Access Point publishes a protected
    /// resource, whose `resource` is then the only audience accepted. Whoever
    /// holds a token of the issuer, for any of its relying parties, is then a
    /// caller. No grant by binding is released to such callers.
    pub fn admits_tokens_for_any_audience(&self) -> bool {
        self.access_point
            .caller_authentication
            .as_ref()
            .is_some_and(|authentication| {
                authentication
                    .protected_resource
                    .is_none()
                    && authentication
                        .methods
                        .iter()
                        .any(|method| {
                            matches!(method, crate::source_auth::SourceAuthConfig::JwtBearer(config)
                                if config.audiences.is_empty() || !config.audience_claim.is_aud())
                        })
            })
    }

    /// One warning for the surface, and for each variant that overrides its
    /// caller authentication, naming each JWT bearer method stored without
    /// `audiences` beside no protected resource. Such a method skips the
    /// audience check; a save refuses a new one.
    pub fn unchecked_audience_warnings(&self) -> Vec<String> {
        let warnings = |view: &Self, place: String| -> Vec<String> {
            if view
                .protected_resource()
                .is_some()
            {
                return Vec::new();
            }
            view.source_auth_methods()
                .iter()
                .filter_map(|method| match method {
                    crate::source_auth::SourceAuthConfig::JwtBearer(config)
                        if config.audiences.is_empty() && config.audience_claim.is_aud() =>
                    {
                        Some(format!(
                            "{place}the Access Point's jwt_bearer method (strategy '{}') names no audience, so it \
                             accepts a token its identity provider issued for any other service and the caller that \
                             token names; list the audiences it accepts, or set audience_claim to client_id or azp for \
                             an identity provider that issues no aud. A method without an audience is deprecated and \
                             will be refused in the next major release, 2.0.0",
                            config.jwt_verification_strategy_id
                        ))
                    }
                    _ => None,
                })
                .collect()
        };
        let variants = self
            .variants
            .iter()
            .filter(|variant| {
                variant
                    .overrides
                    .access_point
                    .as_ref()
                    .is_some_and(|access_point| {
                        access_point
                            .caller_authentication
                            .is_some()
                    })
            })
            .filter_map(|variant| {
                self.resolve_variant(Some(&variant.alias))
                    .ok()
                    .map(|view| warnings(&view, format!("variant '{}': ", variant.alias)))
            })
            .flatten();
        warnings(self, String::new())
            .into_iter()
            .chain(variants)
            .collect()
    }

    /// RFC 9728 settings of the Access Point's caller authentication.
    #[inline]
    pub fn protected_resource(&self) -> Option<&crate::protocols::protected_resource::ProtectedResourceConfig> {
        self.access_point
            .caller_authentication
            .as_ref()
            .and_then(|ca| ca.protected_resource.as_ref())
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

    /// Whether calls through `point` resolve a managed agent identity, as the
    /// outbound pipeline resolves it: the Transit Point's own
    /// `managed_identity`, else the surface's when the Transit Point injects a
    /// VP, in any mode but `from_jwt_claim`, which is inbound only.
    pub fn transit_point_has_managed_identity(
        &self,
        point: &super::agent_surface::TransitPoint,
    ) -> bool {
        point
            .managed_identity
            .clone()
            .or_else(|| {
                point
                    .identity_injection
                    .inject_vp
                    .then(|| self.managed_identity())
                    .flatten()
            })
            .is_some_and(|identity| !matches!(identity, crate::source_auth::ManagedIdentityConfig::FromJwtClaim { .. }))
    }

    /// Whether the surface issues a managed agent identity: an `a2a-proxy://` target always
    /// does, otherwise one configured on its target or on any Transit Point. Unlike
    /// [`Self::transit_point_has_managed_identity`], a target `from_jwt_claim` counts, since
    /// the target is reached on the inbound leg where that mode applies.
    pub fn has_managed_identity(&self) -> bool {
        self.is_a2a_proxy_target()
            || self
                .managed_identity()
                .is_some()
            || self
                .transit
                .as_ref()
                .is_some_and(|transit| {
                    transit
                        .points
                        .iter()
                        .any(|point| {
                            point
                                .managed_identity
                                .is_some()
                        })
                })
    }

    /// Why this surface's caller authentication cannot tell apart the users a
    /// paired gateway sends requests for over Fabric, or `None` when it can.
    /// Delegated per-user credentials for Fabric callers, on its Target and on
    /// its Transit Points, are keyed by the caller it verifies, so
    /// only a credential that names the end user keeps one user's grant from
    /// another's: a resource token (`mcp_http.authorization`), or a
    /// `jwt_bearer` method with an audience (its own, or the one
    /// `protected_resource` binds) and a JWT verification strategy. The admin
    /// API also checks that the strategy names an issuer. An `mtls` method
    /// never verifies a request that arrives over Fabric, so it is no gap: it
    /// leaves such a request with no verified caller, which is refused.
    pub fn fabric_caller_authentication_gap(&self) -> Option<&'static str> {
        use crate::source_auth::SourceAuthConfig;
        let methods = self
            .access_point
            .caller_authentication
            .as_ref()
            .map(|authentication| {
                authentication
                    .methods
                    .as_slice()
            })
            .unwrap_or_default();
        let resource_tokens = self
            .mcp_http
            .as_ref()
            .is_some_and(|http| http.authorization.is_some());
        let verifies_over_fabric = methods
            .iter()
            .any(|method| !matches!(method, SourceAuthConfig::Mtls(_)));
        if !verifies_over_fabric {
            return (!resource_tokens).then_some("it verifies no caller");
        }
        methods
            .iter()
            .find_map(|method| match method {
                SourceAuthConfig::JwtBearer(jwt)
                    if jwt
                        .jwt_verification_strategy_id
                        .trim()
                        .is_empty() =>
                {
                    Some("its jwt_bearer method names no JWT verification strategy, so no issuer")
                }
                SourceAuthConfig::JwtBearer(jwt)
                    if jwt.audiences.is_empty()
                        && self
                            .protected_resource()
                            .is_none() =>
                {
                    Some(
                        "its jwt_bearer method names no audience, so it accepts a token the identity provider issued \
                         for another service",
                    )
                }
                SourceAuthConfig::JwtBearer(jwt)
                    if !jwt.audience_claim.is_aud()
                        && self
                            .protected_resource()
                            .is_none() =>
                {
                    Some(
                        "its jwt_bearer method checks the client a token was issued to, not its audience, so it \
                         accepts a token the identity provider issued to that client for another service",
                    )
                }
                SourceAuthConfig::JwtBearer(_) => None,
                SourceAuthConfig::ApiKey(_) => Some(
                    "an api_key method names every key in its secret as one caller, the partner's and direct \
                     callers' alike",
                ),
                SourceAuthConfig::ApiKeyProvider(_) => {
                    Some("an api_key_provider key names the client that holds it, not a user")
                }
                SourceAuthConfig::DidAuth(_) => {
                    Some("a did_auth session names the DID that signed in, not the user a partner acts for")
                }
                SourceAuthConfig::Mtls(_) => None,
            })
    }

    /// Whether this view's Target is an `http://` or `https://` URL exactly as
    /// written ([`crate::config::agent_surface::endpoint_is_http_url`]), the
    /// only Target Fabric receive dials through a client pinned to the address
    /// it vetted, and so the only one it sends a delegated credential.
    pub fn target_is_http_url(&self) -> bool {
        crate::config::agent_surface::endpoint_is_http_url(&self.target.endpoint)
    }

    /// Whether this view releases its Target's per-user grants to legacy
    /// Fabric requests: its Target is an HTTP or HTTPS URL
    /// ([`Self::target_is_http_url`]) that sets
    /// `delegated_credentials_for_fabric_callers`, and its caller
    /// authentication tells a partner's users apart
    /// ([`Self::fabric_caller_authentication_gap`]).
    pub fn releases_target_grants_to_fabric_callers(&self) -> bool {
        self.target
            .delegated_credentials_for_fabric_callers
            && self.target_is_http_url()
            && self
                .fabric_caller_authentication_gap()
                .is_none()
    }

    /// The agent half of the vault key of this view's Target grants: the
    /// surface on a view that releases them to Fabric callers, so one grant
    /// serves a person whichever agent acts for them, directly or through a
    /// partner; otherwise the agent a direct caller's request names, else the
    /// surface. Fabric receive passes `None`, so nothing a partner names is
    /// ever the agent half.
    pub fn target_grant_agent_did<'a>(
        &'a self,
        caller_agent_did: Option<&'a str>,
    ) -> &'a str {
        if self.releases_target_grants_to_fabric_callers() {
            return &self.surface_id;
        }
        caller_agent_did.unwrap_or(&self.surface_id)
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

    /// True when slot 1 identifies the caller by the API key it presented
    /// (`from_api_key`).
    #[inline]
    pub fn inbound_identity_from_api_key(&self) -> bool {
        matches!(self.identity_slots.inbound, Some(crate::source_auth::ManagedIdentityConfig::FromApiKey { .. }))
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
    /// `agent_surface_compat::to_channel_mapping`. For display only: inject
    /// with [`Self::target_outbound_credentials`] or
    /// [`Self::transit_point_outbound_credentials`]. A Transit Point's
    /// `consent_mode = external` binding is not one of these.
    pub fn outbound_credentials(&self) -> Vec<crate::config::types::OutboundCredentialBinding> {
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
                            .and_then(transit_credential_binding)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Outbound credential bindings for an Access Point request to the
    /// surface's Target. Only the surface-level `outbound_credentials`;
    /// never a Transit Point's `transit_credentials`, nor the Target's
    /// `consent_mode = external` binding, which
    /// [`Self::target_external_credentials`] returns instead.
    pub fn target_outbound_credentials(&self) -> Vec<crate::config::types::OutboundCredentialBinding> {
        self.agent_keyed_outbound_credentials()
            .cloned()
            .collect()
    }

    /// The surface-level `outbound_credentials` an agent-keyed path serves:
    /// every one but the Access Point Target's `consent_mode = external`
    /// binding.
    pub fn agent_keyed_outbound_credentials(
        &self
    ) -> impl Iterator<Item = &crate::config::types::OutboundCredentialBinding> {
        self.outbound_credentials
            .iter()
            .filter(|binding| !binding.is_external())
    }

    /// Whether the surface has a surface-level binding an agent-keyed path
    /// serves.
    pub fn has_agent_keyed_outbound_credentials(&self) -> bool {
        self.agent_keyed_outbound_credentials()
            .next()
            .is_some()
    }

    /// The Access Point Target's `consent_mode = external` binding, whose
    /// grant is kept by binding under the hop `target`.
    pub fn target_external_credentials(&self) -> Option<&crate::config::types::OutboundCredentialBinding> {
        self.outbound_credentials
            .iter()
            .find(|binding| binding.is_external())
    }

    /// Outbound credential bindings for a request through one Transit Point.
    /// Prefers the surface-level `outbound_credentials` field, without the
    /// Access Point Target's `consent_mode = external` binding; otherwise
    /// only that point's own `transit_credentials`, never another point's,
    /// unless it is a `consent_mode = external` binding, which
    /// [`Self::transit_point_external_credentials`] returns instead.
    pub fn transit_point_outbound_credentials(
        &self,
        point: &super::agent_surface::TransitPoint,
    ) -> Vec<crate::config::types::OutboundCredentialBinding> {
        if !self
            .outbound_credentials
            .is_empty()
        {
            return self.target_outbound_credentials();
        }
        point
            .transit_credentials
            .as_ref()
            .and_then(transit_credential_binding)
            .into_iter()
            .collect()
    }

    /// A Transit Point's `consent_mode = external` binding, whose grant is
    /// kept by binding. It applies whatever the surface-level
    /// `outbound_credentials` say.
    pub fn transit_point_external_credentials<'a>(
        &self,
        point: &'a super::agent_surface::TransitPoint,
    ) -> Option<&'a super::agent_surface::TransitCredentials> {
        point
            .transit_credentials
            .as_ref()
            .filter(|credentials| credentials.is_external())
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

    /// Whether the Target's payment policy charges the Access Point's callers,
    /// here or through a payment gateway.
    pub fn charges_callers(&self) -> bool {
        match self
            .target
            .payment_policy
            .as_ref()
        {
            Some(crate::config::agent_surface::PaymentPolicy::X402(config)) => config.enabled,
            Some(crate::config::agent_surface::PaymentPolicy::Mpp(config)) => config.enabled,
            Some(crate::config::agent_surface::PaymentPolicy::AgentPay(_)) => true,
            None => false,
        }
    }

    /// The target's agent-pay payment policy, if any.
    #[inline]
    pub fn agent_pay_policy(&self) -> Option<&crate::config::agent_surface::AgentPayPolicy> {
        match self
            .target
            .payment_policy
            .as_ref()?
        {
            crate::config::agent_surface::PaymentPolicy::AgentPay(policy) => Some(policy),
            _ => None,
        }
    }

    /// Gateways the `agent_pay` policies of the Target and of every variant name.
    pub fn payment_gateway_ids(&self) -> Vec<&str> {
        let variant_policies = self
            .variants
            .iter()
            .filter_map(|variant| {
                variant
                    .overrides
                    .target
                    .as_ref()?
                    .payment_policy
                    .as_ref()
            });
        self.target
            .payment_policy
            .iter()
            .chain(variant_policies)
            .filter_map(|policy| match policy {
                crate::config::agent_surface::PaymentPolicy::AgentPay(policy) => Some(
                    policy
                        .payment_gateway_id
                        .trim(),
                ),
                _ => None,
            })
            .filter(|id| !id.is_empty())
            .collect()
    }

    /// Gateways reached over `fabric://` by the Target, the Transit Points and
    /// every variant's overrides of them.
    pub fn fabric_gateway_ids(&self) -> Vec<&str> {
        let variant_targets = self
            .variants
            .iter()
            .filter_map(|variant| {
                variant
                    .overrides
                    .target
                    .as_ref()?
                    .endpoint
                    .as_deref()
            });
        let transit_points = self
            .transit
            .iter()
            .flat_map(|transit| transit.points.iter())
            .chain(
                self.variants
                    .iter()
                    .filter_map(|variant| {
                        variant
                            .overrides
                            .transit
                            .as_ref()?
                            .points
                            .as_ref()
                    })
                    .flatten(),
            )
            .map(|point| point.target_endpoint.as_str());
        std::iter::once(self.target.endpoint.as_str())
            .chain(variant_targets)
            .chain(transit_points)
            .filter_map(|endpoint| {
                endpoint
                    .strip_prefix("fabric://")?
                    .split('/')
                    .next()
                    .filter(|id| !id.is_empty())
            })
            .collect()
    }

    /// Whether the target carries an enabled local x402 or MPP policy, which
    /// is no longer supported. Requests to such a surface fail closed.
    #[inline]
    pub fn payment_policy_unsupported(&self) -> bool {
        self.target
            .payment_policy
            .as_ref()
            .is_some_and(crate::config::agent_surface::PaymentPolicy::is_unsupported_legacy)
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

    /// Whether a request to the Target carries a presentation of the agent in
    /// its body: an identity VP ([`Self::inject_identity_vp`]), a workload
    /// binding, or the surface's DID injected `protocol_native`.
    pub fn presents_the_agent_to_the_target(&self) -> bool {
        self.inject_identity_vp()
            || self
                .target_workload_binding()
                .is_some()
            || self
                .access_point
                .didwebvh_identity
                .as_ref()
                .is_some_and(|did| did.injection_mode == super::agent_surface::DidInjectionMode::ProtocolNative)
    }

    /// Whether the Target is sent operator-configured custom metadata, in the
    /// request body or in `X-Gateway-*` headers.
    pub fn injects_custom_metadata(&self) -> bool {
        self.custom_metadata()
            .is_some_and(|metadata| metadata.enabled)
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

        if transit
            .shared
            .source_auth
            .is_some()
        {
            errors.push(crate::config::agent_surface::TRANSIT_SOURCE_AUTH_REFUSED.to_string());
        }
        let variant_points = self
            .variants
            .iter()
            .flat_map(|variant| {
                variant
                    .overrides
                    .transit
                    .iter()
                    .filter_map(|transit| transit.points.as_ref())
                    .flatten()
                    .map(|tp| (format!("variant '{}': ", variant.alias), tp))
            });
        for (prefix, tp) in transit
            .points
            .iter()
            .map(|tp| (String::new(), tp))
            .chain(variant_points)
        {
            if let Some(reason) = tp.unenforceable_caller_authentication() {
                errors.push(format!("{prefix}{reason}; every request to it is refused"));
            } else if let Err(error) = tp.validate_caller_authentication() {
                errors.push(format!("{prefix}{error}"));
            }
        }
        for variant in &self.variants {
            if variant
                .overrides
                .transit
                .as_ref()
                .and_then(|transit| transit.shared.as_ref())
                .is_some_and(|shared| shared.source_auth.is_some())
            {
                errors.push(format!(
                    "variant '{}': {}",
                    variant.alias,
                    crate::config::agent_surface::TRANSIT_SOURCE_AUTH_REFUSED
                ));
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

/// A Transit Point's binding as an outbound credential binding, or `None`
/// for a `consent_mode = external` binding, which no agent-keyed path serves.
fn transit_credential_binding(
    cred: &super::agent_surface::TransitCredentials
) -> Option<crate::config::types::OutboundCredentialBinding> {
    use crate::config::agent_surface as surface;
    use crate::config::types::{ConsentMode, CredentialRequirement, ElicitFallback};
    Some(crate::config::types::OutboundCredentialBinding {
        credential_provider_id: cred
            .credential_provider_id
            .clone(),
        scopes: cred.scopes.clone(),
        required_for: CredentialRequirement::All,
        consent_mode: match cred.consent_mode {
            surface::ConsentMode::OnDemand => ConsentMode::OnDemand,
            surface::ConsentMode::PreAuthorize => ConsentMode::PreAuthorize,
            surface::ConsentMode::Elicit => ConsentMode::Elicit,
            surface::ConsentMode::External => return None,
        },
        inject_as: cred
            .inject_as
            .to_binding_injection(),
        elicit_timeout_secs: cred.elicit_timeout_secs,
        elicit_fallback: match cred.elicit_fallback {
            surface::ElicitFallback::OnDemand => ElicitFallback::OnDemand,
            surface::ElicitFallback::Fail => ElicitFallback::Fail,
        },
        subject: None,
    })
}

impl super::agent_surface::CredentialInjection {
    /// The same injection as an outbound credential binding names it.
    pub fn to_binding_injection(&self) -> crate::config::types::CredentialInjection {
        use crate::config::types::CredentialInjection;
        match self {
            Self::BearerHeader => CredentialInjection::BearerHeader,
            Self::CustomHeader { name, format } => CredentialInjection::CustomHeader {
                name: name.clone(),
                format: format.clone(),
            },
            Self::Meta { field } => CredentialInjection::Meta { field: field.clone() },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::agent_surface::{AccessPoint, IdentityInjectionConfig, SurfaceStatus};

    fn agent_pay(gateway_id: &str) -> crate::config::agent_surface::PaymentPolicy {
        serde_json::from_value(serde_json::json!({
            "type": "agent_pay",
            "payment_gateway_id": gateway_id,
            "payment_surface_id": "pay-1",
        }))
        .unwrap()
    }

    fn variant(overrides: serde_json::Value) -> crate::config::agent_surface_variants::SurfaceVariant {
        serde_json::from_value(serde_json::json!({
            "id": "v-1",
            "alias": "pro",
            "name": "Pro",
            "overrides": overrides,
        }))
        .unwrap()
    }

    fn transit(endpoints: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "points": endpoints
                .iter()
                .enumerate()
                .map(|(i, endpoint)| serde_json::json!({"alias": format!("tp-{i}"), "target_endpoint": endpoint}))
                .collect::<Vec<_>>(),
        })
    }

    #[test]
    fn payment_gateway_ids_come_from_the_target_and_every_variant() {
        let mut s = surface(SurfaceProtocol::Mcp);
        assert!(
            s.payment_gateway_ids()
                .is_empty()
        );
        s.target.payment_policy = Some(agent_pay("pay-gw"));
        s.variants.push(variant(
            serde_json::json!({"target": {"payment_policy": serde_json::to_value(agent_pay("pay-gw-2")).unwrap()}}),
        ));
        s.variants.push(variant(
            serde_json::json!({"target": {"payment_policy": serde_json::to_value(agent_pay(" ")).unwrap()}}),
        ));
        assert_eq!(s.payment_gateway_ids(), vec!["pay-gw", "pay-gw-2"]);
    }

    #[test]
    fn fabric_gateway_ids_come_from_targets_and_transit_points() {
        let mut s = surface(SurfaceProtocol::Mcp);
        s.target.endpoint = "https://upstream.example/mcp".to_string();
        assert!(
            s.fabric_gateway_ids()
                .is_empty()
        );
        s.target.endpoint = "fabric://gw-target/surface".to_string();
        s.transit = Some(serde_json::from_value(transit(&["fabric://gw-transit/s", "https://x.example"])).unwrap());
        s.variants
            .push(variant(serde_json::json!({
                "target": {"endpoint": "fabric://gw-variant/s"},
                "transit": transit(&["fabric://gw-variant-transit/s", "fabric:///nothing"]),
            })));
        assert_eq!(s.fabric_gateway_ids(), vec!["gw-target", "gw-variant", "gw-transit", "gw-variant-transit"]);
    }

    fn surface_with_methods(methods: serde_json::Value) -> AgentSurface {
        let mut surface = surface(SurfaceProtocol::A2a);
        surface
            .access_point
            .caller_authentication =
            Some(serde_json::from_value(serde_json::json!({ "methods": methods })).expect("caller authentication"));
        surface
    }

    /// Grants by binding are withheld from callers of a JWT method that does
    /// not bind the token to this gateway: one stored without audiences, or
    /// one that checks only the client, unless a protected resource binds
    /// `aud`.
    #[test]
    fn admits_tokens_for_any_audience_unless_aud_is_checked() {
        let jwt = |extra: serde_json::Value| {
            let mut method = serde_json::json!({ "type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": ["app-1"] });
            method
                .as_object_mut()
                .unwrap()
                .extend(
                    extra
                        .as_object()
                        .unwrap()
                        .clone(),
                );
            surface_with_methods(serde_json::json!([method]))
        };
        for (case, surface, admits) in [
            ("an audience", jwt(serde_json::json!({})), false),
            ("no audience", jwt(serde_json::json!({ "audiences": [] })), true),
            ("client_id", jwt(serde_json::json!({ "audience_claim": "client_id" })), true),
            ("azp", jwt(serde_json::json!({ "audience_claim": "azp" })), true),
        ] {
            assert_eq!(surface.admits_tokens_for_any_audience(), admits, "{case}");
            let mut bound = surface.clone();
            bound
                .access_point
                .caller_authentication
                .as_mut()
                .unwrap()
                .protected_resource = Some(crate::protocols::protected_resource::ProtectedResourceConfig {
                resource: "https://gateway.example/mcp".to_string(),
                authorization_servers: vec!["https://issuer.example".to_string()],
                scopes: Vec::new(),
            });
            assert!(!bound.admits_tokens_for_any_audience(), "{case} beside a protected resource");
        }
    }

    #[test]
    fn unchecked_audience_warnings_name_each_stored_method_without_an_audience() {
        let no_audience =
            serde_json::json!({ "type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": [] });
        let mut surface = surface_with_methods(serde_json::json!([no_audience.clone()]));
        surface.variants = serde_json::from_value(serde_json::json!([
            { "id": "v-inherits", "name": "inherits", "alias": "inherits", "overrides": {} },
            { "id": "v-own", "name": "own", "alias": "own", "overrides": { "access_point": { "caller_authentication": { "methods": [
                { "type": "jwt_bearer", "jwt_verification_strategy_id": "partner", "audiences": [] }
            ] } } } },
            { "id": "v-fixed", "name": "fixed", "alias": "fixed", "overrides": { "access_point": { "caller_authentication": { "methods": [
                { "type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": ["api://agent"] }
            ] } } } }
        ]))
        .unwrap();

        let warnings = surface.unchecked_audience_warnings();
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(
            warnings[0].starts_with("the Access Point's jwt_bearer method (strategy 'idp') names no audience")
                && warnings[0].contains("deprecated and will be refused in the next major release, 2.0.0"),
            "{}",
            warnings[0]
        );
        assert!(
            warnings[1].starts_with("variant 'own': the Access Point's jwt_bearer method (strategy 'partner')"),
            "{}",
            warnings[1]
        );

        let named = surface_with_methods(serde_json::json!([
            { "type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": ["api://agent"] },
            { "type": "jwt_bearer", "jwt_verification_strategy_id": "cognito", "audiences": ["app-1"],
              "audience_claim": "client_id", "token_header": "X-Token" }
        ]));
        assert!(
            named
                .unchecked_audience_warnings()
                .is_empty()
        );
    }

    #[test]
    fn did_auth_config_is_found_at_any_position() {
        let surface = surface_with_methods(serde_json::json!([
            {"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": []},
            {"type": "did_auth", "extraction": {"source": "http_header", "field": "X-Session-Token"}}
        ]));
        assert!(
            surface
                .did_auth_config()
                .is_some()
        );
        assert!(
            surface_with_methods(serde_json::json!([]))
                .did_auth_config()
                .is_none()
        );
    }

    #[test]
    fn every_method_header_is_a_source_credential_header() {
        let surface = surface_with_methods(serde_json::json!([
            {"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": []},
            {"type": "api_key", "extraction": {"source": "http_header", "field": "X-API-Key"}, "secret_id": "keys"},
            {"type": "mtls", "trust": {"type": "pinned", "certificate_ids": ["c1"]}, "identity_binding": {"type": "fingerprint"}}
        ]));
        assert_eq!(surface.source_credential_headers(), ["Authorization", "X-API-Key"]);
        assert!(!surface_with_methods(serde_json::json!([])).has_source_auth());
        assert!(surface.has_source_auth());
    }

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
                a2a: None,
                public: None,
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
                delegated_credentials_for_fabric_callers: false,
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
            trust_check_split: false,
            transit_point_source_auth: false,
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

    #[test]
    fn has_managed_identity_reads_the_target_and_every_transit_point() {
        let mut point: crate::config::agent_surface::TransitPoint =
            serde_json::from_value(serde_json::json!({"alias": "out", "target_endpoint": "https://out.example"}))
                .unwrap();
        let mut s = surface(SurfaceProtocol::A2a);
        s.transit = Some(serde_json::from_value(serde_json::json!({"points": [point.clone()]})).unwrap());
        assert!(!s.has_managed_identity());

        point.managed_identity = Some(crate::source_auth::ManagedIdentityConfig::FromMtls {
            certificate_id: "cert".to_string(),
        });
        s.transit = Some(serde_json::from_value(serde_json::json!({"points": [point]})).unwrap());
        assert!(s.has_managed_identity());

        let mut target_only = surface(SurfaceProtocol::A2a);
        target_only
            .target
            .identity_injection
            .identity_type = Some("from_jwt_claim".to_string());
        assert!(target_only.has_managed_identity());

        let mut a2a_proxy = surface(SurfaceProtocol::A2a);
        a2a_proxy.target.endpoint = "a2a-proxy://worker".to_string();
        assert!(a2a_proxy.has_managed_identity());
    }

    #[test]
    fn transit_point_outbound_credentials_use_only_that_points_own_credentials() {
        let point = |value: serde_json::Value| -> crate::config::agent_surface::TransitPoint {
            serde_json::from_value(value).unwrap()
        };
        let providers = |bindings: Vec<crate::config::types::OutboundCredentialBinding>| {
            bindings
                .into_iter()
                .map(|binding| binding.credential_provider_id)
                .collect::<Vec<_>>()
        };
        let partner = point(serde_json::json!({"alias": "partner", "target_endpoint": "https://partner.example/mcp",
            "transit_credentials": {"credential_provider_id": "provider-a"}}));
        let peer = point(serde_json::json!({"alias": "peer", "target_endpoint": "fabric://peer/surface",
            "fabric_delegated_credentials": true}));
        let mut s = surface(SurfaceProtocol::Mcp);
        s.transit =
            Some(serde_json::from_value(serde_json::json!({"points": [partner.clone(), peer.clone()]})).unwrap());

        assert!(
            s.transit_point_outbound_credentials(&peer)
                .is_empty()
        );
        assert_eq!(providers(s.transit_point_outbound_credentials(&partner)), vec!["provider-a"]);
        assert_eq!(providers(s.outbound_credentials()), vec!["provider-a"]);
        assert!(
            s.target_outbound_credentials()
                .is_empty()
        );

        let peer_with_own = point(serde_json::json!({"alias": "peer", "target_endpoint": "fabric://peer/surface",
            "fabric_delegated_credentials": true, "transit_credentials": {"credential_provider_id": "provider-b"}}));
        assert_eq!(providers(s.transit_point_outbound_credentials(&peer_with_own)), vec!["provider-b"]);

        s.outbound_credentials =
            vec![serde_json::from_value(serde_json::json!({"credential_provider_id": "surface-provider"})).unwrap()];
        assert_eq!(providers(s.transit_point_outbound_credentials(&peer_with_own)), vec!["surface-provider"]);
        assert_eq!(providers(s.target_outbound_credentials()), vec!["surface-provider"]);
        assert!(
            s.target_external_credentials()
                .is_none()
        );
    }

    /// The Access Point Target's external consent binding is served by its
    /// grant by binding only: no agent-keyed path, on the Target or a Transit
    /// Point, is given it.
    #[test]
    fn the_access_point_targets_external_binding_reaches_no_agent_keyed_path() {
        let mut s = surface(SurfaceProtocol::Mcp);
        s.outbound_credentials = serde_json::from_value(serde_json::json!([
            {"credential_provider_id": "vendor", "consent_mode": "external", "subject": "owner"},
            {"credential_provider_id": "agent-keyed"}
        ]))
        .unwrap();
        let point: crate::config::agent_surface::TransitPoint = serde_json::from_value(serde_json::json!({
            "alias": "partner", "target_endpoint": "https://partner.example/mcp"}))
        .unwrap();
        let providers = |bindings: Vec<crate::config::types::OutboundCredentialBinding>| {
            bindings
                .into_iter()
                .map(|binding| binding.credential_provider_id)
                .collect::<Vec<_>>()
        };

        assert_eq!(providers(s.target_outbound_credentials()), vec!["agent-keyed"]);
        assert_eq!(providers(s.transit_point_outbound_credentials(&point)), vec!["agent-keyed"]);
        let external = s
            .target_external_credentials()
            .expect("the Target's external binding");
        assert_eq!(external.credential_provider_id, "vendor");
        assert_eq!(external.subject, Some(crate::config::agent_surface::GrantSubject::Owner));
        assert!(s.has_agent_keyed_outbound_credentials());

        s.outbound_credentials
            .truncate(1);
        assert!(
            s.target_outbound_credentials()
                .is_empty()
        );
        assert!(!s.has_agent_keyed_outbound_credentials());
        assert_eq!(providers(s.outbound_credentials()), vec!["vendor"], "the display keeps every binding");
    }

    #[test]
    fn validate_outbound_warns_about_transit_source_auth_set_by_a_variant() {
        let surface: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "surf-1", "name": "test", "status": "active",
            "access_point": { "listen_address": "http://localhost:8080", "route": "/test", "protocol": "a2a" },
            "target": { "endpoint": "http://localhost:9000" },
            "transit": { "outbound_listen_address": "http://localhost:9001",
                "points": [{ "alias": "partner", "target_endpoint": "http://localhost:9002" }] },
            "variants": [
                { "id": "v1", "alias": "staging", "name": "Staging", "enabled": true,
                    "overrides": { "transit": { "shared": { "source_auth": {
                        "type": "api_key",
                        "extraction": { "source": "http_header", "field": "X-API-Key" },
                        "secret_id": "transit-caller-key"
                    } } } } },
                { "id": "v2", "alias": "plain", "name": "Plain", "enabled": true,
                    "overrides": { "transit": { "shared": { "sign_requests": true } } } }
            ]
        }))
        .unwrap();

        assert_eq!(
            surface.validate_outbound(),
            vec![format!("variant 'staging': {}", crate::config::agent_surface::TRANSIT_SOURCE_AUTH_REFUSED)]
        );
    }

    /// A view releases its Target's per-user grants to Fabric callers only when
    /// its Target is an HTTP or HTTPS URL that sets the switch and its caller
    /// authentication tells a partner's users apart: a JWT naming an audience
    /// or a resource token, with an mTLS method beside one of them, and no
    /// method that names every user alike. On any other Target, including one
    /// written with an upper-case scheme or a leading space, which Fabric
    /// receive would not dial through its pinned client, the view keeps its
    /// grants per agent, as with the switch off.
    #[test]
    fn releases_target_grants_to_fabric_callers_needs_the_switch_and_callers_told_apart() {
        use serde_json::json;
        let jwt = |audiences: serde_json::Value| json!({ "type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": audiences });
        let api_key = json!({ "type": "api_key", "extraction": { "source": "http_header", "field": "X-API-Key" }, "secret_id": "keys" });
        let mtls = json!({ "type": "mtls", "trust": { "type": "pinned", "certificate_ids": ["c1"] },
            "identity_binding": { "type": "fingerprint" } });
        let mut resource_tokens = surface_with_methods(json!([mtls.clone()]));
        resource_tokens.mcp_http = Some(
            serde_json::from_value(json!({ "authorization": { "resource": "https://gateway.example/mcp" } })).unwrap(),
        );

        for (case, view, tells_users_apart) in [
            ("a JWT naming an audience", surface_with_methods(json!([jwt(json!(["api://agent"]))])), true),
            ("a resource token beside mTLS", resource_tokens, true),
            (
                "mTLS beside a JWT naming an audience",
                surface_with_methods(json!([mtls.clone(), jwt(json!(["api://agent"]))])),
                true,
            ),
            ("an API key", surface_with_methods(json!([api_key.clone()])), false),
            (
                "an API Key Provider key",
                surface_with_methods(json!([{ "type": "api_key_provider", "agent_id": "keys",
                    "extraction": { "source": "http_header", "field": "X-API-Key" } }])),
                false,
            ),
            (
                "DID Auth",
                surface_with_methods(
                    json!([{ "type": "did_auth", "extraction": { "source": "http_header", "field": "X-Session-Token" } }]),
                ),
                false,
            ),
            ("a JWT naming no audience", surface_with_methods(json!([jwt(json!([]))])), false),
            (
                "a JWT checking only its client",
                surface_with_methods(json!([{ "type": "jwt_bearer", "jwt_verification_strategy_id": "idp",
                    "audiences": ["app-1"], "audience_claim": "client_id" }])),
                false,
            ),
            ("mTLS only", surface_with_methods(json!([mtls.clone()])), false),
            (
                "an API key beside a JWT naming an audience",
                surface_with_methods(json!([jwt(json!(["api://agent"])), api_key])),
                false,
            ),
            ("no caller authentication", surface(SurfaceProtocol::A2a), false),
        ] {
            for switch in [false, true] {
                let mut view = view.clone();
                view.target
                    .delegated_credentials_for_fabric_callers = switch;
                assert_eq!(
                    view.releases_target_grants_to_fabric_callers(),
                    switch && tells_users_apart,
                    "{case}, switch {switch}"
                );
            }
        }

        for (endpoint, releases) in [
            ("fabric://peer-gateway/peer-surface", false),
            ("proxy://tools", false),
            ("a2a-proxy://worker", false),
            ("HTTPS://upstream:9000", false),
            ("HTTP://upstream:9000", false),
            (" https://upstream:9000", false),
            ("http://upstream:9000", true),
            ("https://upstream:9000", true),
        ] {
            let mut view = surface_with_methods(json!([jwt(json!(["api://agent"]))]));
            view.target
                .delegated_credentials_for_fabric_callers = true;
            view.target.endpoint = endpoint.to_string();
            assert_eq!(view.target_is_http_url(), releases, "{endpoint}");
            assert_eq!(view.releases_target_grants_to_fabric_callers(), releases, "{endpoint}");
            assert_eq!(
                view.target_grant_agent_did(Some("did:web:planner.example")),
                if releases {
                    "surf-1"
                } else {
                    "did:web:planner.example"
                },
                "{endpoint}"
            );
        }
    }

    /// On a view that releases its Target's grants to Fabric callers the agent
    /// half of their key is the surface, whatever agent a caller names;
    /// otherwise it is the agent a direct caller names, else the surface.
    #[test]
    fn target_grant_agent_did_is_the_surface_once_the_target_releases_grants_to_partners() {
        let mut view = surface_with_methods(serde_json::json!([{ "type": "jwt_bearer",
            "jwt_verification_strategy_id": "idp", "audiences": ["api://agent"] }]));
        assert_eq!(view.target_grant_agent_did(Some("did:web:planner.example")), "did:web:planner.example");
        assert_eq!(view.target_grant_agent_did(None), "surf-1");

        view.target
            .delegated_credentials_for_fabric_callers = true;
        assert_eq!(view.target_grant_agent_did(Some("did:web:planner.example")), "surf-1");
        assert_eq!(view.target_grant_agent_did(None), "surf-1");

        let mut shared_key = surface_with_methods(serde_json::json!([{ "type": "api_key",
            "extraction": { "source": "http_header", "field": "X-API-Key" }, "secret_id": "keys" }]));
        shared_key
            .target
            .delegated_credentials_for_fabric_callers = true;
        assert_eq!(
            shared_key.target_grant_agent_did(Some("did:web:planner.example")),
            "did:web:planner.example",
            "a view that cannot release grants to partners keeps them per agent"
        );
    }
}
