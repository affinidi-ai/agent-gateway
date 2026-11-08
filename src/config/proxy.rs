//! Proxy configuration implementation

use super::network::NetworkConfig;
use super::types::*;
use std::path::PathBuf;
use tracing::{error, info, warn};

#[allow(dead_code)]
impl BootstrapConfig {
    /// Reads `transit_token_max_lifetime_secs` from `gateway.json` when the
    /// gateway starts, refusing anything but a whole number from 30 to 900
    /// seconds, and pins it: every later [`Self::load_network_config`], such as
    /// a reload's, takes the pinned value instead of the file's. A change takes
    /// a restart, and an edit, valid or not, never reaches a running gateway.
    pub fn pin_transit_token_max_lifetime(&mut self) -> anyhow::Result<u64> {
        let network_path = &self.config_files.gateway;
        let in_file = NetworkConfig::transit_token_max_lifetime_in_file(network_path)?;
        let max_secs = crate::config::agent_surface::transit_token_max_lifetime_from(in_file.as_ref())
            .map_err(|error| anyhow::anyhow!("{network_path}: {error}"))?;
        self.pinned_transit_token_max_lifetime_secs = Some(max_secs);
        Ok(max_secs)
    }

    /// Reads `external_consent_resource_origins` from `gateway.json` when the
    /// gateway starts and pins it: provider create and surface save keep the
    /// value they started with, so every later [`Self::load_network_config`],
    /// such as a reload's, takes the pinned value instead of the file's, and
    /// the requests a reload serves check the same origins. A change takes a
    /// restart.
    pub fn pin_external_consent_resource_origins(
        &mut self
    ) -> anyhow::Result<std::collections::HashMap<String, Vec<String>>> {
        let origins = NetworkConfig::load_from_file(&self.config_files.gateway)?.external_consent_resource_origins;
        self.pinned_external_consent_resource_origins = Some(origins.clone());
        Ok(origins)
    }

    /// Reads `external_consent_issuers` from `gateway.json` when the gateway
    /// starts and pins it, as [`Self::pin_external_consent_resource_origins`]
    /// pins the resource origins: provider create, surface save and the
    /// connect API keep the value they started with, so every later
    /// [`Self::load_network_config`] takes it too. A change takes a restart.
    pub fn pin_external_consent_issuers(
        &mut self
    ) -> anyhow::Result<Option<std::collections::HashMap<String, Vec<String>>>> {
        let issuers = NetworkConfig::load_from_file(&self.config_files.gateway)?.external_consent_issuers;
        self.pinned_external_consent_issuers = Some(issuers.clone());
        Ok(issuers)
    }

    /// Load network configuration from the configured path, with the
    /// `transit_token_max_lifetime_secs`, `external_consent_resource_origins`
    /// and `external_consent_issuers` pinned at startup, once pinned. A `WARN` says when the file holds a
    /// different value, which takes a restart.
    pub fn load_network_config(&self) -> anyhow::Result<NetworkConfig> {
        let network_path = &self.config_files.gateway;
        info!("Loading network configuration from: {}", network_path);
        let mut network_config = NetworkConfig::load_from_file(network_path)?;
        if let Some(max_secs) = self.pinned_transit_token_max_lifetime_secs {
            network_config.transit_token_max_lifetime_secs = max_secs;
            let in_file = NetworkConfig::transit_token_max_lifetime_in_file(network_path)?;
            if let Some(ignored) = ignored_transit_token_max_lifetime(in_file.as_ref(), max_secs) {
                warn!("{network_path}: {ignored}");
            }
        }
        if let Some(origins) = &self.pinned_external_consent_resource_origins
            && network_config.external_consent_resource_origins != *origins
        {
            warn!(
                "{network_path}: external_consent_resource_origins differs from the value the gateway started with, \
                 which it keeps until it restarts"
            );
            network_config.external_consent_resource_origins = origins.clone();
        }
        if let Some(issuers) = &self.pinned_external_consent_issuers
            && network_config.external_consent_issuers != *issuers
        {
            warn!(
                "{network_path}: external_consent_issuers differs from the value the gateway started with, which it \
                 keeps until it restarts"
            );
            network_config.external_consent_issuers = issuers.clone();
        }

        if let Some((old_domain, new_domain)) = network_config.normalize_localhost_did_domain() {
            warn!(
                "did.domain '{}' resolves incorrectly for localhost DID methods; using '{}' so did:web/did:webvh resolve over a configured inbound localhost listener",
                old_domain, new_domain
            );
        }

        Ok(network_config)
    }

    /// Load x402 headers configuration from x402.json
    pub fn load_x402_headers(&self) -> anyhow::Result<X402Headers> {
        let x402_path = &self.config_files.x402;
        info!("Loading x402 headers configuration from: {}", x402_path);

        // Read and parse x402.json to extract headers section
        let contents = std::fs::read_to_string(x402_path)?;
        let config: serde_json::Value = serde_json::from_str(&contents)?;

        // Extract headers section
        if let Some(headers) = config.get("headers") {
            let x402_headers: X402Headers = serde_json::from_value(headers.clone())?;
            info!(
                "Loaded x402 headers: payment_required={}, payment_signature={}, payment_response={}",
                x402_headers.payment_required, x402_headers.payment_signature, x402_headers.payment_response
            );
            Ok(x402_headers)
        } else {
            warn!("No 'headers' section found in x402.json, using defaults");
            Ok(X402Headers::default())
        }
    }

    /// Load full x402 configuration from x402.json
    pub fn load_x402_config(&self) -> anyhow::Result<X402Config> {
        let x402_path = &self.config_files.x402;
        info!("Loading x402 configuration from: {}", x402_path);

        // Read and parse x402.json
        let contents = std::fs::read_to_string(x402_path)?;
        let config: X402Config = serde_json::from_str(&contents)?;

        info!("Loaded x402 config: enabled={}, verification_mode={:?}", config.enabled, config.verification_mode);
        Ok(config)
    }

    /// Load x402 metadata (network/token information) from x402.json
    /// Returns X402ConfigResponse with network definitions, token symbols, decimals
    pub fn load_x402_metadata(&self) -> anyhow::Result<crate::identity::handlers::config::X402ConfigResponse> {
        let x402_path = &self.config_files.x402;
        info!("Loading x402 metadata from: {}", x402_path);

        // Read and parse x402.json
        let contents = std::fs::read_to_string(x402_path)?;
        let metadata: crate::identity::handlers::config::X402ConfigResponse = serde_json::from_str(&contents)?;

        info!(
            "Loaded x402 metadata: {} networks, {} payment schemes",
            metadata.networks.len(),
            metadata.payment_schemes.len()
        );
        Ok(metadata)
    }
}

#[allow(dead_code)]
impl GatewayConfig {
    /// Create a default configuration
    pub fn default_config() -> Self {
        use crate::config::agent_surface::{AccessPoint, AgentSurface, SurfaceProtocol, SurfaceStatus, Target};
        Self {
            surfaces: vec![AgentSurface {
                surface_id: String::new(),
                tenant_id: None,
                name: "default-agent".to_string(),
                description: "Default agent channel".to_string(),
                status: SurfaceStatus::Active,
                agent_did: None,
                issuer_id: None,
                tags: Vec::new(),
                access_point: AccessPoint {
                    listen_address: "0.0.0.0:8443".to_string(),
                    route: "/".to_string(),
                    protocol: SurfaceProtocol::A2a,
                    ..Default::default()
                },
                target: Target {
                    endpoint: "https://agent.example.com/a2a/v1".to_string(),
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
                signing: None,
                trust_check_split: false,
                transit_point_source_auth: false,
            }],
            tls: TlsConfig {
                cert_path: PathBuf::from("cert.pem"),
                key_path: PathBuf::from("key.pem"),
                verify_upstream: true,
                client_auth: Default::default(),
            },
            a2a: A2aConfig::default(),
            mcp: McpConfig::default(),
            logging: LoggingConfig::default(),
            extension_inspection: ExtensionInspectionConfig::default(),
            integration: IntegrationConfig::default_config(),
            facilitator_mode: crate::config::types::FacilitatorMode::default(),
            x402_headers: X402Headers::default(),
        }
    }

    /// One line per surface, disabled ones included, whose stored transit token
    /// lifetime is held to a bound: below `max_secs`, the appliance's
    /// `transit_token_max_lifetime_secs`, or above 900 seconds. The gateway logs
    /// each at `WARN` when it starts; none stops it.
    pub fn transit_token_lifetime_adjustments(
        &self,
        max_secs: u64,
    ) -> Vec<String> {
        self.surfaces
            .iter()
            .filter_map(|surface| surface.transit_token_lifetime_adjustment(max_secs))
            .collect()
    }

    /// One line per surface whose stored DID Auth `session_ttl_seconds` is above
    /// the longest a session lasts. Such a surface loads, and its sessions are
    /// held to the longest; the gateway logs each line at `WARN` when it starts.
    pub fn did_auth_session_ttl_adjustments(&self) -> Vec<String> {
        use crate::source_auth::models::DidAuthAuthConfig;

        self.surfaces
            .iter()
            .flat_map(|surface| {
                surface
                    .session_did_auth_configs()
                    .into_iter()
                    .filter_map(move |(variant, cfg)| {
                        let ttl = cfg
                            .session_ttl_seconds
                            .filter(|ttl| *ttl > DidAuthAuthConfig::MAX_SESSION_TTL_SECONDS)?;
                        let place = variant.map_or_else(String::new, |variant| format!("variant '{}' ", variant.alias));
                        Some(format!(
                            "Surface '{}' ({}): {place}did_auth.session_ttl_seconds is {ttl}, above the longest, {} \
                             seconds; its sessions last {} seconds",
                            surface.name,
                            surface.surface_id,
                            DidAuthAuthConfig::MAX_SESSION_TTL_SECONDS,
                            cfg.effective_session_ttl_seconds()
                        ))
                    })
            })
            .collect()
    }

    /// Validate the configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(continuations) = &self.mcp.continuations {
            continuations.validate()?;
        }
        // Validate channels
        if self.surfaces.is_empty() {
            warn!("At least one channel must be configured");
        }

        // Validate each channel
        for (idx, surface) in self
            .surfaces
            .iter()
            .enumerate()
        {
            let channel_id = surface
                .config_id()
                .map(|id| format!(" ({}.json)", id))
                .unwrap_or_default();

            if surface.name.is_empty() {
                anyhow::bail!("Channel {}{} has empty name", idx, channel_id);
            }
            if surface
                .listen_address()
                .is_empty()
            {
                anyhow::bail!("Channel '{}'{} has empty listen_address", surface.name, channel_id);
            }
            if surface
                .target_endpoint()
                .is_empty()
            {
                anyhow::bail!("Channel '{}'{} has empty target_endpoint", surface.name, channel_id);
            }

            // Validate authentication configuration
            validate_source_auth_surface(surface)?;

            if surface.payment_policy_unsupported() {
                warn!(
                    "Surface '{}'{}: local x402/MPP payment is no longer supported; requests answer 503 until the \
                     payment policy points at an agent-pay surface (connecting a payment gateway needs the \
                     agent_pay_delegation feature flag)",
                    surface.name, channel_id
                );
            }
            if let Some(policy) = surface.agent_pay_policy() {
                for error in policy.validate() {
                    warn!("Surface '{}'{}: agent_pay payment policy: {}", surface.name, channel_id, error);
                }
            }
            if surface.target.mpp_auto_pay {
                warn!("Surface '{}'{}: mpp_auto_pay is no longer supported and is ignored", surface.name, channel_id);
            }
        }

        // Check for duplicate route+port combinations
        // Multiple channels can share the same port if they have different routes
        let mut seen_route_port_combos = std::collections::HashSet::new();
        for surface in self.surfaces.iter() {
            // Disabled surfaces register no routes anywhere (inbound routing
            // and `group_outbound_vcs_by_port` both skip them), so they must
            // not hold a route claim here either — disabling one copy is the
            // remediation for a duplicated surface, and it has to allow the
            // gateway to boot.
            if surface.status == crate::config::agent_surface::SurfaceStatus::Disabled {
                continue;
            }
            let channel_id = surface
                .config_id()
                .map(|id| format!(" ({}.json)", id))
                .unwrap_or_default();

            let listen_address = surface.listen_address();
            let route = surface.route();

            // Extract port from listen_address
            let port = listen_address
                .split(':')
                .next_back()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Invalid listen_address format for channel '{}'{}: {}",
                        surface.name,
                        channel_id,
                        listen_address
                    )
                })?;

            // Normalize route (ensure it starts with /)
            let normalized_route = if route.starts_with('/') {
                route.to_string()
            } else {
                format!("/{}", route)
            };

            let combo = format!("{}:{}", port, normalized_route);
            if !seen_route_port_combos.insert(combo.clone()) {
                anyhow::bail!(
                    "Duplicate route+port combination '{}' for channel '{}'{}. Each route on a port must be unique.",
                    combo,
                    surface.name,
                    channel_id
                );
            }
        }

        // Note: Channel names are human-readable labels and do NOT need to be unique
        // Only config_id must be unique (enforced by filesystem/database)

        // Validate TLS certificate paths
        if !self.tls.cert_path.exists() {
            anyhow::bail!("TLS certificate file not found: {:?}", self.tls.cert_path);
        }

        if !self.tls.key_path.exists() {
            anyhow::bail!("TLS key file not found: {:?}", self.tls.key_path);
        }

        Ok(())
    }
}

/// Validate a loaded surface's `source_auth` at boot: every rule of a save but
/// the DID Auth session TTL bound, which a stored value is held to at runtime
/// (see [`GatewayConfig::did_auth_session_ttl_adjustments`]). A
/// `from_jwt_claim` identity beside a method other than `jwt_bearer`, and an
/// inbound `from_api_key` identity beside a method other than an API key, are
/// only warned about here: stored surfaces predating the rule booted with
/// them, and saving them enforces it.
fn validate_source_auth_surface(surface: &crate::config::agent_surface::AgentSurface) -> anyhow::Result<()> {
    use crate::source_auth::SourceAuthConfig;

    validate_stored_source_auth_methods(surface)?;
    if let Err(error) = validate_jwt_claim_identity(surface) {
        warn!("{error}; callers that authenticate with another method are refused until the surface is fixed");
    }
    if surface.inbound_identity_from_api_key()
        && surface
            .source_auth_methods()
            .iter()
            .any(|method| !matches!(method, SourceAuthConfig::ApiKey(_) | SourceAuthConfig::ApiKeyProvider(_)))
    {
        warn!(
            "Channel '{}': inbound identity from_api_key requires every source authentication method to be api_key \
             or api_key_provider; callers that authenticate with another method are refused until the surface is fixed",
            surface.name
        );
    }
    Ok(())
}

/// The methods the source authentication fallback dropped from one place of a
/// surface: the base Access Point, or a variant overriding its caller
/// authentication.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceAuthFallback {
    /// `None` for the base surface, else the variant's alias.
    pub variant: Option<String>,
    /// The rule the stored methods broke.
    pub reason: String,
    /// Each dropped method as [`describe_source_auth_method`] names it, so an
    /// operator can rebuild it.
    pub dropped: Vec<String>,
}

/// Serve a stored surface whose source authentication methods break the
/// rules for several methods with its first method alone, the only one the
/// gateway enforced before those rules, when that method is valid on its own.
/// The base Access Point and each enabled variant overriding its caller
/// authentication are checked as resolved, and trimmed independently.
/// Returns what was dropped; the caller logs it
/// ([`log_source_auth_fallbacks`]) and may persist the surface.
pub fn fall_back_to_first_source_auth_method(
    surface: &mut crate::config::agent_surface::AgentSurface
) -> Vec<SourceAuthFallback> {
    let mut fallbacks = Vec::new();
    if let Err(error) = validate_stored_source_auth_methods(surface) {
        let mut first_only = surface.clone();
        if let Some(authentication) = first_only
            .access_point
            .caller_authentication
            .as_mut()
        {
            let dropped = authentication
                .methods
                .split_off(1.min(authentication.methods.len()));
            if validate_stored_source_auth_methods(&first_only).is_ok() {
                *surface = first_only;
                fallbacks.push(SourceAuthFallback {
                    variant: None,
                    reason: error.to_string(),
                    dropped: dropped
                        .iter()
                        .map(describe_source_auth_method)
                        .collect(),
                });
            }
        }
    }
    for index in 0..surface.variants.len() {
        let variant = &surface.variants[index];
        let overrides_methods = variant
            .overrides
            .access_point
            .as_ref()
            .and_then(|access_point| {
                access_point
                    .caller_authentication
                    .as_ref()
            })
            .is_some_and(|authentication| authentication.methods.len() > 1);
        if !variant.enabled || !overrides_methods {
            continue;
        }
        let alias = variant.alias.clone();
        let Ok(resolved) = surface.resolve_variant(Some(&alias)) else {
            continue;
        };
        let Err(error) = validate_stored_source_auth_methods(&resolved) else {
            continue;
        };
        let mut first_only = surface.clone();
        let Some(authentication) = first_only.variants[index]
            .overrides
            .access_point
            .as_mut()
            .and_then(|access_point| {
                access_point
                    .caller_authentication
                    .as_mut()
            })
        else {
            continue;
        };
        let dropped = authentication
            .methods
            .split_off(1);
        let valid_alone = first_only
            .resolve_variant(Some(&alias))
            .is_ok_and(|resolved| validate_stored_source_auth_methods(&resolved).is_ok());
        if valid_alone {
            *surface = first_only;
            fallbacks.push(SourceAuthFallback {
                variant: Some(alias),
                reason: error.to_string(),
                dropped: dropped
                    .iter()
                    .map(describe_source_auth_method)
                    .collect(),
            });
        }
    }
    fallbacks
}

/// Log each place of `surface` the source authentication fallback trimmed,
/// naming the dropped methods so an operator can restore them.
pub fn log_source_auth_fallbacks(
    surface: &crate::config::agent_surface::AgentSurface,
    fallbacks: &[SourceAuthFallback],
) {
    for fallback in fallbacks {
        error!(
            surface = %surface.name,
            surface_id = %surface.surface_id,
            variant = fallback.variant.as_deref().unwrap_or(""),
            dropped = %fallback.dropped.join("; "),
            "source authentication methods the gateway refuses ({}) — serving only the first method; resolve via the \
             UI or API",
            fallback.reason
        );
    }
}

/// Log [`additional_source_auth_method_notices`] for `surfaces` at `WARN`, as
/// the gateway does once when it starts.
pub fn log_additional_source_auth_method_notices(surfaces: &[crate::config::agent_surface::AgentSurface]) {
    for notice in surfaces
        .iter()
        .flat_map(additional_source_auth_method_notices)
    {
        warn!("{notice}");
    }
}

/// Apply [`fall_back_to_first_source_auth_method`] to surfaces held in memory,
/// as a DynamoDB load does, logging each trim.
pub fn fall_back_to_first_source_auth_methods_in_memory(surfaces: &mut [crate::config::agent_surface::AgentSurface]) {
    for surface in surfaces {
        let fallbacks = fall_back_to_first_source_auth_method(surface);
        log_source_auth_fallbacks(surface, &fallbacks);
    }
}

/// A source authentication method as its tag, credential location and
/// non-secret references (strategy, secret, provider agent, certificates), so
/// a log line can name a method well enough to rebuild it.
pub fn describe_source_auth_method(method: &crate::source_auth::SourceAuthConfig) -> String {
    use crate::source_auth::SourceAuthConfig;
    use crate::source_auth::models::MtlsTrust;

    let location = describe_credential_source(method.credential_source());
    let reference = match method {
        SourceAuthConfig::JwtBearer(config) => format!(", strategy '{}'", config.jwt_verification_strategy_id),
        SourceAuthConfig::ApiKey(config) => format!(", secret '{}'", config.secret_id),
        SourceAuthConfig::ApiKeyProvider(config) => format!(", provider agent '{}'", config.agent_id),
        SourceAuthConfig::DidAuth(_) => String::new(),
        SourceAuthConfig::Mtls(config) => match &config.trust {
            MtlsTrust::Pinned { certificate_ids } => format!(", pinned certificates {certificate_ids:?}"),
            MtlsTrust::Ca { ca_certificate_ids, .. } => format!(", CA certificates {ca_certificate_ids:?}"),
        },
    };
    format!("{} (reads {location}{reference})", method.method_tag())
}

fn describe_credential_source(source: crate::source_auth::models::CredentialSource<'_>) -> String {
    use crate::source_auth::models::CredentialSource;

    match source {
        CredentialSource::Header(name) => format!("the '{name}' header"),
        CredentialSource::McpMeta => "MCP _meta".to_string(),
        CredentialSource::A2aExtension => "the A2A message extension".to_string(),
        CredentialSource::ClientCertificate => "the client certificate".to_string(),
    }
}

/// One line per surface, and per variant overriding its caller
/// authentication, with more than one source authentication method, naming
/// the methods after the first. Releases before several methods were
/// supported enforced only the first, so on upgrade the later ones start
/// authenticating callers; the gateway logs each line at startup so an
/// operator can check them.
pub fn additional_source_auth_method_notices(surface: &crate::config::agent_surface::AgentSurface) -> Vec<String> {
    let describe = |label: String, methods: &[crate::source_auth::SourceAuthConfig]| {
        (methods.len() > 1).then(|| {
            let later = methods
                .iter()
                .enumerate()
                .skip(1)
                .map(|(index, method)| format!("{} ({})", index + 1, method.method_tag()))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "{label}: source authentication methods after the first authenticate callers: {later}; releases \
                 before several methods were supported enforced only the first"
            )
        })
    };
    let base = format!("Surface '{}' ({})", surface.name, surface.surface_id);
    let variants = surface
        .variants
        .iter()
        .filter_map(|variant| {
            let methods = &variant
                .overrides
                .access_point
                .as_ref()?
                .caller_authentication
                .as_ref()?
                .methods;
            describe(format!("{base} variant '{}'", variant.alias), methods)
        });
    describe(base.clone(), surface.source_auth_methods())
        .into_iter()
        .chain(variants)
        .collect()
}

/// The rules a stored surface's source authentication methods must meet to
/// load: each method's own, those that let a request select one method, and,
/// beside protected resource metadata, JWT Bearer only as the first method,
/// since every request to such a surface would otherwise fail its metadata
/// check.
fn validate_stored_source_auth_methods(surface: &crate::config::agent_surface::AgentSurface) -> anyhow::Result<()> {
    let methods = surface.source_auth_methods();
    for method in methods {
        validate_stored_source_auth_method(method, &surface.name)?;
    }
    validate_method_selection(methods, &surface.name)?;
    if surface.has_later_jwt_bearer_beside_discovery() {
        anyhow::bail!(
            "Channel '{}': caller_authentication.protected_resource {}",
            surface.name,
            crate::config::agent_surface::LATER_JWT_BEARER_BESIDE_DISCOVERY
        );
    }
    Ok(())
}

/// Validate a surface's `source_auth` configuration on the HTTP save path
/// (`identity::handlers::surfaces::validate_and_save_surface`, before
/// `store.save`).
///
/// Enforces the mTLS trust rules the runtime relies on, every
/// `DidAuthAuthConfig` invariant boot also checks (see
/// [`validate_did_auth_config`]), the DID Auth session TTL bound on every
/// method that mints sessions, the surface's and each variant's
/// ([`AgentSurface::session_did_auth_configs`](crate::config::agent_surface::AgentSurface::session_did_auth_configs)),
/// unless `stored`, the surface as stored, has the same TTL in the same place,
/// the rules that let a request select one method (each method reads its own
/// credential location, at most one is DID Auth), and the `from_jwt_claim`
/// rule boot only warns about.
pub fn validate_source_auth_config(
    surface: &crate::config::agent_surface::AgentSurface,
    stored: Option<&crate::config::agent_surface::AgentSurface>,
) -> anyhow::Result<()> {
    let methods = surface.source_auth_methods();
    for method in methods {
        validate_stored_source_auth_method(method, &surface.name)?;
    }
    let stored_configs = stored.map_or_else(Vec::new, |stored| stored.session_did_auth_configs());
    for (variant, cfg) in surface.session_did_auth_configs() {
        let kept = stored_configs
            .iter()
            .any(|(stored_variant, stored_cfg)| {
                stored_variant.map(|variant| &variant.id) == variant.map(|variant| &variant.id)
                    && stored_cfg.session_ttl_seconds == cfg.session_ttl_seconds
            });
        if !kept {
            let place = variant.map_or_else(String::new, |variant| format!("variant '{}' ", variant.alias));
            validate_session_ttl_bound(cfg.session_ttl_seconds, &surface.name, &place)?;
        }
    }
    validate_method_selection(methods, &surface.name)?;
    validate_jwt_claim_identity(surface)
}

/// Validate one source authentication method being saved, set on the Access
/// Point or a Transit Point of the surface named `surface_name`. The DID Auth
/// session TTL bound applies only to a TTL that `stored`, the method stored in
/// its place, does not already have: a surface stored above it loads, and its
/// sessions are held to the bound, so a save that keeps the TTL is accepted.
pub(crate) fn validate_source_auth_method(
    src: &crate::source_auth::SourceAuthConfig,
    stored: Option<&crate::source_auth::SourceAuthConfig>,
    surface_name: &str,
) -> anyhow::Result<()> {
    use crate::source_auth::SourceAuthConfig;

    validate_stored_source_auth_method(src, surface_name)?;
    if let SourceAuthConfig::DidAuth(cfg) = src {
        let kept = matches!(
            stored,
            Some(SourceAuthConfig::DidAuth(stored)) if stored.session_ttl_seconds == cfg.session_ttl_seconds
        );
        if !kept {
            validate_session_ttl_bound(cfg.session_ttl_seconds, surface_name, "")?;
        }
    }
    Ok(())
}

/// Refuse a DID Auth `session_ttl_seconds` above
/// [`DidAuthAuthConfig::MAX_SESSION_TTL_SECONDS`](crate::source_auth::models::DidAuthAuthConfig::MAX_SESSION_TTL_SECONDS).
fn validate_session_ttl_bound(
    session_ttl_seconds: Option<u64>,
    surface_name: &str,
    place: &str,
) -> anyhow::Result<()> {
    use crate::source_auth::models::DidAuthAuthConfig;

    if let Some(ttl) = session_ttl_seconds.filter(|ttl| *ttl > DidAuthAuthConfig::MAX_SESSION_TTL_SECONDS) {
        anyhow::bail!(
            "Channel '{}': {place}did_auth.session_ttl_seconds {} exceeds max {}",
            surface_name,
            ttl,
            DidAuthAuthConfig::MAX_SESSION_TTL_SECONDS
        );
    }
    Ok(())
}

/// The rules a stored source authentication method must meet to load.
fn validate_stored_source_auth_method(
    src: &crate::source_auth::SourceAuthConfig,
    surface_name: &str,
) -> anyhow::Result<()> {
    use crate::source_auth::models::{MtlsTrust, SourceAuthConfig};

    match src {
        SourceAuthConfig::Mtls(cfg) => match &cfg.trust {
            MtlsTrust::Pinned { certificate_ids } => {
                if certificate_ids.is_empty() {
                    anyhow::bail!("Channel '{}': mTLS pinned trust requires at least one certificate_id", surface_name);
                }
            }
            MtlsTrust::Ca {
                ca_certificate_ids,
                check_crl,
                require_ocsp,
                ..
            } => {
                if ca_certificate_ids.is_empty() {
                    anyhow::bail!("Channel '{}': mTLS CA trust requires at least one ca_certificate_id", surface_name);
                }
                if *check_crl {
                    anyhow::bail!(
                        "Channel '{}': mTLS CA trust has check_crl=true but CRL checking is not yet implemented; set check_crl=false",
                        surface_name
                    );
                }
                if *require_ocsp {
                    anyhow::bail!(
                        "Channel '{}': mTLS CA trust has require_ocsp=true but OCSP stapling is not yet implemented; set require_ocsp=false",
                        surface_name
                    );
                }
            }
        },
        SourceAuthConfig::JwtBearer(_) | SourceAuthConfig::ApiKey(_) | SourceAuthConfig::ApiKeyProvider(_) => {}
        SourceAuthConfig::DidAuth(cfg) => validate_did_auth_config(cfg, surface_name)?,
    }
    Ok(())
}

/// A request selects its method by the credential it carries, so two methods
/// reading the same location would be indistinguishable, and a method reading
/// the request body, where no credential is looked for, could only ever be the
/// fallback.
fn validate_method_selection(
    methods: &[crate::source_auth::SourceAuthConfig],
    surface_name: &str,
) -> anyhow::Result<()> {
    use crate::source_auth::models::{CredentialSource, SourceAuthConfig};

    let describe = describe_credential_source;
    for (position, method) in methods.iter().enumerate() {
        let source = method.credential_source();
        if methods.len() > 1 && matches!(source, CredentialSource::McpMeta | CredentialSource::A2aExtension) {
            anyhow::bail!(
                "Channel '{}': source authentication method {} ({}) reads {}; with more than one method, each must read a header or the client certificate",
                surface_name,
                position + 1,
                method.method_tag(),
                describe(source)
            );
        }
        if let Some(earlier_position) = methods[..position]
            .iter()
            .position(|earlier| {
                earlier
                    .credential_source()
                    .same_as(&source)
            })
        {
            anyhow::bail!(
                "Channel '{}': source authentication methods {} ({}) and {} ({}) both read {}; each method needs its own credential location",
                surface_name,
                earlier_position + 1,
                methods[earlier_position].method_tag(),
                position + 1,
                method.method_tag(),
                describe(source)
            );
        }
    }
    if methods
        .iter()
        .filter(|method| matches!(method, SourceAuthConfig::DidAuth(_)))
        .count()
        > 1
    {
        anyhow::bail!("Channel '{}': source authentication allows at most one did_auth method", surface_name);
    }
    Ok(())
}

/// `from_jwt_claim` derives a DID from the caller's verified JWT, so every
/// caller must authenticate with a JWT.
fn validate_jwt_claim_identity(surface: &crate::config::agent_surface::AgentSurface) -> anyhow::Result<()> {
    use crate::source_auth::{ManagedIdentityConfig, SourceAuthConfig};

    let transit_identities = surface
        .transit
        .iter()
        .flat_map(|transit| transit.points.iter())
        .filter_map(|point| point.managed_identity.clone());
    let uses_jwt_claim = [
        surface
            .inbound_identity()
            .cloned(),
        surface
            .external_identity()
            .cloned(),
        surface.managed_identity(),
    ]
    .into_iter()
    .flatten()
    .chain(transit_identities)
    .any(|identity| matches!(identity, ManagedIdentityConfig::FromJwtClaim { .. }));
    if uses_jwt_claim
        && surface
            .source_auth_methods()
            .iter()
            .any(|method| !matches!(method, SourceAuthConfig::JwtBearer(_)))
    {
        anyhow::bail!(
            "Channel '{}': from_jwt_claim identity requires every source authentication method to be jwt_bearer",
            surface.name
        );
    }
    Ok(())
}

/// Validate a per-surface `DidAuthAuthConfig`. Splits the checks into three
/// concerns — DID allow-list, TTL bounds, JWS algorithm allow-list — each
/// bailing with a channel-scoped message so an operator can trace a rejected
/// config back to the exact field.
fn validate_did_auth_config(
    cfg: &crate::source_auth::models::DidAuthAuthConfig,
    surface_name: &str,
) -> anyhow::Result<()> {
    validate_allowed_dids(&cfg.allowed_dids, surface_name)?;
    validate_ttls(cfg.challenge_ttl_seconds, cfg.session_ttl_seconds, surface_name)?;
    validate_allowed_algorithms(&cfg.allowed_algorithms, surface_name)?;
    Ok(())
}

fn validate_allowed_dids(
    allowed_dids: &[String],
    surface_name: &str,
) -> anyhow::Result<()> {
    for (i, did) in allowed_dids
        .iter()
        .enumerate()
    {
        let trimmed = did.trim();
        if trimmed.is_empty() {
            anyhow::bail!("Channel '{}': did_auth.allowed_dids[{}] is blank", surface_name, i);
        }
        if !trimmed.starts_with("did:") {
            anyhow::bail!(
                "Channel '{}': did_auth.allowed_dids[{}] '{}' must start with 'did:'",
                surface_name,
                i,
                trimmed
            );
        }
    }
    Ok(())
}

fn validate_ttls(
    challenge_ttl_seconds: Option<u64>,
    session_ttl_seconds: Option<u64>,
    surface_name: &str,
) -> anyhow::Result<()> {
    use crate::source_auth::models::DidAuthAuthConfig;

    if let Some(ttl) = challenge_ttl_seconds {
        if ttl == 0 {
            anyhow::bail!("Channel '{}': did_auth.challenge_ttl_seconds must be > 0", surface_name);
        }
        if ttl > DidAuthAuthConfig::MAX_CHALLENGE_TTL_SECONDS {
            anyhow::bail!(
                "Channel '{}': did_auth.challenge_ttl_seconds {} exceeds max {}",
                surface_name,
                ttl,
                DidAuthAuthConfig::MAX_CHALLENGE_TTL_SECONDS
            );
        }
    }
    if session_ttl_seconds == Some(0) {
        anyhow::bail!("Channel '{}': did_auth.session_ttl_seconds must be > 0", surface_name);
    }
    Ok(())
}

fn validate_allowed_algorithms(
    allowed_algorithms: &[String],
    surface_name: &str,
) -> anyhow::Result<()> {
    use crate::source_auth::models::DidAuthAuthConfig;

    for alg in allowed_algorithms {
        if !DidAuthAuthConfig::SUPPORTED_ALGORITHMS.contains(&alg.as_str()) {
            anyhow::bail!(
                "Channel '{}': did_auth.allowed_algorithms entry '{}' is unsupported (supported: {:?})",
                surface_name,
                alg,
                DidAuthAuthConfig::SUPPORTED_ALGORITHMS
            );
        }
    }
    Ok(())
}

/// Why the `transit_token_max_lifetime_secs` `gateway.json` holds is not in
/// force, while the gateway keeps `pinned_secs`, the value it started with;
/// `None` when the file holds that value.
fn ignored_transit_token_max_lifetime(
    in_file: Option<&serde_json::Value>,
    pinned_secs: u64,
) -> Option<String> {
    match crate::config::agent_surface::transit_token_max_lifetime_from(in_file) {
        Ok(file_secs) if file_secs == pinned_secs => None,
        Ok(file_secs) => Some(format!(
            "transit_token_max_lifetime_secs is {file_secs} in gateway.json, but the gateway keeps {pinned_secs}, \
             the value it started with, until it restarts"
        )),
        Err(error) => Some(format!(
            "{error}; the gateway keeps {pinned_secs}, the value it started with, and will refuse to start with \
             this value"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface_with_caller_auth(
        methods: serde_json::Value,
        extra: serde_json::Value,
    ) -> crate::config::agent_surface::AgentSurface {
        let mut surface = serde_json::json!({
            "surface_id": "s1",
            "name": "multi",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/multi",
                "protocol": "a2a",
                "caller_authentication": { "methods": methods }
            },
            "target": { "endpoint": "https://agent.internal" }
        });
        if let (Some(surface), Some(extra)) = (surface.as_object_mut(), extra.as_object()) {
            surface.extend(extra.clone());
        }
        serde_json::from_value(surface).unwrap()
    }

    fn jwt_method() -> serde_json::Value {
        serde_json::json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "strat-1", "audiences": []})
    }

    fn api_key_method(header: &str) -> serde_json::Value {
        serde_json::json!({
            "type": "api_key",
            "extraction": {"source": "http_header", "field": header},
            "secret_id": "keys"
        })
    }

    fn did_auth_method(header: &str) -> serde_json::Value {
        serde_json::json!({"type": "did_auth", "extraction": {"source": "http_header", "field": header}})
    }

    #[test]
    fn notices_name_the_methods_after_the_first_on_the_surface_and_its_variants() {
        let single = surface_with_caller_auth(serde_json::json!([jwt_method()]), serde_json::json!({}));
        assert!(additional_source_auth_method_notices(&single).is_empty());

        let surface = surface_with_caller_auth(
            serde_json::json!([jwt_method(), api_key_method("X-API-Key")]),
            serde_json::json!({"variants": [
                {"id": "v1", "alias": "partners", "name": "Partners", "overrides": {"access_point": {
                    "caller_authentication": {"methods": [api_key_method("X-API-Key"), did_auth_method("X-DID")]}
                }}},
                {"id": "v2", "alias": "plain", "name": "Plain"}
            ]}),
        );
        let notices = additional_source_auth_method_notices(&surface);
        assert_eq!(notices.len(), 2, "{notices:?}");
        assert!(
            notices[0].starts_with("Surface 'multi' (s1): ")
                && notices[0].contains("authenticate callers: 2 (api_key);"),
            "{}",
            notices[0]
        );
        assert!(
            notices[1].starts_with("Surface 'multi' (s1) variant 'partners': ")
                && notices[1].contains("authenticate callers: 2 (did_auth);"),
            "{}",
            notices[1]
        );
    }

    #[test]
    fn methods_on_distinct_credential_locations_are_accepted() {
        let surface = surface_with_caller_auth(
            serde_json::json!([jwt_method(), api_key_method("X-API-Key")]),
            serde_json::json!({}),
        );
        validate_source_auth_config(&surface, None).unwrap();
    }

    #[test]
    fn methods_sharing_a_header_are_rejected_case_insensitively() {
        let surface = surface_with_caller_auth(
            serde_json::json!([jwt_method(), api_key_method("authorization")]),
            serde_json::json!({}),
        );
        let error = validate_source_auth_config(&surface, None)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "Channel 'multi': source authentication methods 1 (jwt_bearer) and 2 (api_key) both read the \
             'authorization' header; each method needs its own credential location"
        );
    }

    #[test]
    fn a_second_did_auth_method_is_rejected() {
        let surface = surface_with_caller_auth(
            serde_json::json!([did_auth_method("X-Session-A"), did_auth_method("X-Session-B")]),
            serde_json::json!({}),
        );
        let error = validate_source_auth_config(&surface, None)
            .unwrap_err()
            .to_string();
        assert_eq!(error, "Channel 'multi': source authentication allows at most one did_auth method");
    }

    #[test]
    fn a_body_extracted_method_is_rejected_beside_another_method() {
        let body_method = serde_json::json!({
            "type": "api_key",
            "extraction": {"source": "mcp_meta"},
            "secret_id": "keys"
        });
        let surface =
            surface_with_caller_auth(serde_json::json!([jwt_method(), body_method.clone()]), serde_json::json!({}));
        let error = validate_source_auth_config(&surface, None)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "Channel 'multi': source authentication method 2 (api_key) reads MCP _meta; with more than one method, \
             each must read a header or the client certificate"
        );

        let alone = surface_with_caller_auth(serde_json::json!([body_method]), serde_json::json!({}));
        validate_source_auth_config(&alone, None).unwrap();
    }

    #[test]
    fn every_method_is_validated_not_only_the_first() {
        let surface = surface_with_caller_auth(
            serde_json::json!([
                jwt_method(),
                {"type": "did_auth", "extraction": {"source": "http_header", "field": "X-Session"}, "challenge_ttl_seconds": 0}
            ]),
            serde_json::json!({}),
        );
        let error = validate_source_auth_config(&surface, None)
            .unwrap_err()
            .to_string();
        assert_eq!(error, "Channel 'multi': did_auth.challenge_ttl_seconds must be > 0");
    }

    #[test]
    fn from_jwt_claim_identity_requires_every_method_to_be_jwt_bearer() {
        let inbound = serde_json::json!({"identity_slots": {"inbound": {"type": "from_jwt_claim"}}});
        let mixed =
            surface_with_caller_auth(serde_json::json!([jwt_method(), api_key_method("X-API-Key")]), inbound.clone());
        let error = validate_source_auth_config(&mixed, None)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "Channel 'multi': from_jwt_claim identity requires every source authentication method to be jwt_bearer"
        );

        let jwt_only = surface_with_caller_auth(serde_json::json!([jwt_method()]), inbound);
        validate_source_auth_config(&jwt_only, None).unwrap();
    }

    #[test]
    fn from_jwt_claim_on_the_protected_slot_or_a_transit_point_also_requires_jwt_bearer() {
        let methods = serde_json::json!([jwt_method(), api_key_method("X-API-Key")]);
        for extra in [
            serde_json::json!({"identity_slots": {"protected": {"type": "from_jwt_claim"}}}),
            serde_json::json!({"transit": {"points": [{
                "alias": "partner",
                "target_endpoint": "https://partner.example",
                "managed_identity": {"type": "from_jwt_claim"}
            }]}}),
        ] {
            let surface = surface_with_caller_auth(methods.clone(), extra);
            let error = validate_source_auth_config(&surface, None)
                .unwrap_err()
                .to_string();
            assert!(error.contains("from_jwt_claim identity requires"), "{error}");
        }
    }

    #[test]
    fn boot_validation_only_warns_about_from_jwt_claim_beside_other_methods() {
        let surface = surface_with_caller_auth(
            serde_json::json!([api_key_method("X-API-Key")]),
            serde_json::json!({"identity_slots": {"inbound": {"type": "from_jwt_claim"}}}),
        );
        validate_source_auth_surface(&surface).unwrap();
        assert!(validate_source_auth_config(&surface, None).is_err(), "saving still refuses it");

        let shared = surface_with_caller_auth(
            serde_json::json!([jwt_method(), api_key_method("authorization")]),
            serde_json::json!({}),
        );
        assert!(validate_source_auth_surface(&shared).is_err(), "only a fallback can make it boot");
    }

    #[test]
    fn a_surface_breaking_the_method_rules_falls_back_to_its_first_method() {
        let mut surface = surface_with_caller_auth(
            serde_json::json!([jwt_method(), api_key_method("authorization")]),
            serde_json::json!({}),
        );
        let fallbacks = fall_back_to_first_source_auth_method(&mut surface);
        assert_eq!(fallbacks.len(), 1, "{fallbacks:?}");
        assert_eq!(fallbacks[0].variant, None);
        assert!(
            fallbacks[0]
                .reason
                .contains("both read the 'authorization' header"),
            "{:?}",
            fallbacks[0]
        );
        assert_eq!(fallbacks[0].dropped, ["api_key (reads the 'authorization' header, secret 'keys')"]);
        assert_eq!(
            surface
                .source_auth_methods()
                .len(),
            1
        );
        validate_source_auth_surface(&surface).unwrap();

        let mut valid = surface_with_caller_auth(
            serde_json::json!([jwt_method(), api_key_method("X-API-Key")]),
            serde_json::json!({}),
        );
        assert!(fall_back_to_first_source_auth_method(&mut valid).is_empty());
        assert_eq!(
            valid
                .source_auth_methods()
                .len(),
            2
        );
    }

    #[test]
    fn a_later_jwt_bearer_beside_discovery_falls_back_to_the_first_method() {
        let second_jwt = serde_json::json!({
            "type": "jwt_bearer", "jwt_verification_strategy_id": "internal", "audiences": ["internal"],
            "token_header": "X-Internal-Token"
        });
        let mut surface =
            surface_with_caller_auth(serde_json::json!([jwt_method(), second_jwt]), serde_json::json!({}));
        surface
            .access_point
            .caller_authentication
            .as_mut()
            .unwrap()
            .protected_resource = Some(
            serde_json::from_value(serde_json::json!({
                "resource": "https://gateway.example/mcp/alpha",
                "authorization_servers": ["https://idp.example"]
            }))
            .unwrap(),
        );
        assert!(validate_source_auth_surface(&surface).is_err(), "boot refuses it without the fallback");

        let fallbacks = fall_back_to_first_source_auth_method(&mut surface);
        assert_eq!(fallbacks.len(), 1, "{fallbacks:?}");
        assert!(
            fallbacks[0]
                .reason
                .contains("allows JWT Bearer only as the first"),
            "{:?}",
            fallbacks[0]
        );
        assert_eq!(fallbacks[0].dropped, ["jwt_bearer (reads the 'X-Internal-Token' header, strategy 'internal')"]);
        assert_eq!(
            surface
                .source_auth_methods()
                .len(),
            1
        );
        validate_source_auth_surface(&surface).unwrap();
    }

    #[test]
    fn an_enabled_variant_breaking_the_method_rules_falls_back_on_its_own() {
        let override_methods = |methods: serde_json::Value| serde_json::json!({"access_point": {"caller_authentication": {"methods": methods}}});
        let breaking = serde_json::json!([jwt_method(), api_key_method("authorization")]);
        let mut surface = surface_with_caller_auth(
            serde_json::json!([jwt_method(), api_key_method("X-API-Key")]),
            serde_json::json!({"variants": [
                {"id": "v1", "alias": "broken", "name": "Broken", "overrides": override_methods(breaking.clone())},
                {"id": "v2", "alias": "off", "name": "Off", "enabled": false, "overrides": override_methods(breaking)}
            ]}),
        );

        let fallbacks = fall_back_to_first_source_auth_method(&mut surface);
        assert_eq!(fallbacks.len(), 1, "{fallbacks:?}");
        assert_eq!(
            fallbacks[0]
                .variant
                .as_deref(),
            Some("broken")
        );
        assert_eq!(fallbacks[0].dropped, ["api_key (reads the 'authorization' header, secret 'keys')"]);
        let methods_of = |surface: &crate::config::agent_surface::AgentSurface, alias: &str| {
            surface
                .variants
                .iter()
                .find(|variant| variant.alias == alias)
                .and_then(|variant| {
                    variant
                        .overrides
                        .access_point
                        .as_ref()
                })
                .and_then(|access_point| {
                    access_point
                        .caller_authentication
                        .as_ref()
                })
                .map_or(0, |authentication| authentication.methods.len())
        };
        assert_eq!(methods_of(&surface, "broken"), 1);
        assert_eq!(methods_of(&surface, "off"), 2, "a disabled variant is left as stored");
        assert_eq!(
            surface
                .source_auth_methods()
                .len(),
            2,
            "the base keeps its valid methods"
        );
    }

    #[test]
    fn other_identity_modes_allow_mixed_methods() {
        let surface = surface_with_caller_auth(
            serde_json::json!([jwt_method(), api_key_method("X-API-Key")]),
            serde_json::json!({"identity_slots": {"protected": {"type": "static", "did": "did:web:agent.example"}}}),
        );
        validate_source_auth_config(&surface, None).unwrap();
    }

    #[test]
    fn a_reload_names_a_longest_transit_token_lifetime_it_does_not_apply() {
        assert_eq!(ignored_transit_token_max_lifetime(Some(&serde_json::json!(600)), 600), None);
        assert_eq!(ignored_transit_token_max_lifetime(None, 300), None);
        assert_eq!(
            ignored_transit_token_max_lifetime(Some(&serde_json::json!(900)), 300).as_deref(),
            Some(
                "transit_token_max_lifetime_secs is 900 in gateway.json, but the gateway keeps 300, the value it \
                 started with, until it restarts"
            )
        );
        assert_eq!(
            ignored_transit_token_max_lifetime(None, 600).as_deref(),
            Some(
                "transit_token_max_lifetime_secs is 300 in gateway.json, but the gateway keeps 600, the value it \
                 started with, until it restarts"
            )
        );
        for (refused, shown) in [
            (serde_json::json!(0), "0"),
            (serde_json::json!(29), "29"),
            (serde_json::json!(901), "901"),
            (serde_json::json!("ten"), "\"ten\""),
        ] {
            assert_eq!(
                ignored_transit_token_max_lifetime(Some(&refused), 300),
                Some(format!(
                    "transit_token_max_lifetime_secs in gateway.json must be from 30 to 900 seconds, not {shown}; the \
                     gateway keeps 300, the value it started with, and will refuse to start with this value"
                ))
            );
        }
    }

    /// At startup a stored lifetime below 30 seconds is held to 30 and one above
    /// the appliance's longest to it, each named in one line, disabled surfaces
    /// included; a lifetime within the bounds is not named.
    #[test]
    fn startup_holds_a_stored_lifetime_outside_the_bounds_to_the_nearer_one() {
        let surface_living = |id: &str, secs: u64, status: &str| {
            serde_json::from_value(serde_json::json!({
                "surface_id": id,
                "name": id,
                "status": status,
                "access_point": { "listen_address": "0.0.0.0:8443", "route": "/lifetime", "protocol": "a2a" },
                "target": { "endpoint": "https://agent.internal" },
                "transit": {
                    "transit_token_lifetime_secs": secs,
                    "points": [{ "alias": "partner", "target_endpoint": "https://partner.example" }]
                }
            }))
            .unwrap()
        };
        let mut config = GatewayConfig::default_config();

        config.surfaces = vec![
            surface_living("short", 10, "active"),
            surface_living("short-disabled", 5, "disabled"),
            surface_living("longest", 600, "active"),
            surface_living("too-long", 601, "active"),
            surface_living("too-long-disabled", 1200, "disabled"),
        ];
        assert_eq!(
            config.transit_token_lifetime_adjustments(600),
            [
                "Surface 'short' (short): transit.transit_token_lifetime_secs is 10, below the shortest, 30 seconds; \
                 its transit tokens live 30 seconds",
                "Surface 'short-disabled' (short-disabled): transit.transit_token_lifetime_secs is 5, below the \
                 shortest, 30 seconds; its transit tokens live 30 seconds",
                "Surface 'too-long' (too-long): transit.transit_token_lifetime_secs is 601, above \
                 transit_token_max_lifetime_secs in gateway.json (600); its transit tokens live 600 seconds",
                "Surface 'too-long-disabled' (too-long-disabled): transit.transit_token_lifetime_secs is 1200, above \
                 transit_token_max_lifetime_secs in gateway.json (600); its transit tokens live 600 seconds",
            ]
        );

        config.surfaces = vec![surface_living("short", 30, "active"), surface_living("longest", 300, "active")];
        assert!(
            config
                .transit_token_lifetime_adjustments(300)
                .is_empty()
        );
    }

    /// A stored DID Auth session TTL above the longest loads, named in one line
    /// at startup with the TTL its sessions are held to; a save of it is refused.
    #[test]
    fn startup_loads_a_stored_session_ttl_above_the_longest_and_names_it() {
        let surface_with_session_ttl = |id: &str, ttl: Option<u64>| -> crate::config::agent_surface::AgentSurface {
            let mut method = serde_json::json!({
                "type": "did_auth",
                "extraction": { "source": "http_header", "field": "X-DID-Auth-Session" },
                "allowed_dids": ["did:example:alice"]
            });
            if let Some(ttl) = ttl {
                method["session_ttl_seconds"] = ttl.into();
            }
            serde_json::from_value(serde_json::json!({
                "surface_id": id,
                "name": id,
                "access_point": {
                    "listen_address": "0.0.0.0:8443", "route": format!("/{id}"), "protocol": "mcp",
                    "caller_authentication": { "methods": [method] }
                },
                "target": { "endpoint": "https://agent.internal" }
            }))
            .unwrap()
        };
        let mut config = GatewayConfig::default_config();
        config.surfaces = vec![
            surface_with_session_ttl("too-long", Some(172_800)),
            surface_with_session_ttl("longest", Some(86_400)),
            surface_with_session_ttl("default", None),
        ];

        for surface in &config.surfaces {
            validate_source_auth_surface(surface).expect("a stored session TTL above the longest loads");
        }
        assert_eq!(
            config.did_auth_session_ttl_adjustments(),
            ["Surface 'too-long' (too-long): did_auth.session_ttl_seconds is 172800, above the longest, 86400 \
              seconds; its sessions last 86400 seconds"]
        );
        let error =
            validate_source_auth_config(&config.surfaces[0], None).expect_err("a save above the longest is refused");
        assert_eq!(error.to_string(), "Channel 'too-long': did_auth.session_ttl_seconds 172800 exceeds max 86400");
        validate_source_auth_config(&config.surfaces[1], None).expect("a save of the longest passes");
        validate_source_auth_config(&config.surfaces[0], Some(&config.surfaces[0]))
            .expect("a save that keeps a stored TTL above the longest passes");
        let longer = surface_with_session_ttl("too-long", Some(172_801));
        validate_source_auth_config(&longer, Some(&config.surfaces[0]))
            .expect_err("a save that changes a stored TTL above the longest to another is refused");
        validate_source_auth_config(&config.surfaces[0], Some(&config.surfaces[1]))
            .expect_err("a save that raises a stored TTL above the longest is refused");
        validate_source_auth_config(&config.surfaces[0], Some(&config.surfaces[2]))
            .expect_err("a save that sets a TTL above the longest where none was is refused");

        assert!(
            validate_source_auth_surface(&surface_with_session_ttl("zero", Some(0))).is_err(),
            "a stored session TTL of zero still stops the load"
        );
    }

    /// A variant's own Access Point DID Auth mints its sessions too: a TTL
    /// above the longest there is named at startup and refused on a save that
    /// sets it, and kept on one that leaves it. A DID Auth method that is not
    /// the first mints no session and is neither named nor refused.
    #[test]
    fn a_variants_session_ttl_above_the_longest_is_named_and_refused_as_the_surfaces() {
        let did_auth = |ttl: u64| {
            serde_json::json!({
                "type": "did_auth",
                "extraction": { "source": "http_header", "field": "X-DID-Auth-Session" },
                "allowed_dids": ["did:example:alice"],
                "session_ttl_seconds": ttl
            })
        };
        let surface = |base_ttl: u64, variant_ttl: u64| -> crate::config::agent_surface::AgentSurface {
            serde_json::from_value(serde_json::json!({
                "surface_id": "varied",
                "name": "varied",
                "access_point": {
                    "listen_address": "0.0.0.0:8443", "route": "/varied", "protocol": "mcp",
                    "caller_authentication": { "methods": [
                        { "type": "api_key", "extraction": { "source": "http_header", "field": "X-API-Key" },
                            "secret_id": "caller-key" },
                        did_auth(base_ttl)
                    ] }
                },
                "target": { "endpoint": "https://agent.internal" },
                "variants": [{ "id": "v-1", "alias": "candidate", "name": "candidate", "enabled": true,
                    "overrides": { "access_point": { "caller_authentication": { "methods": [did_auth(variant_ttl)] } } } }]
            }))
            .unwrap()
        };
        let mut config = GatewayConfig::default_config();
        config.surfaces = vec![surface(3_600, 172_800)];
        assert_eq!(
            config.did_auth_session_ttl_adjustments(),
            ["Surface 'varied' (varied): variant 'candidate' did_auth.session_ttl_seconds is 172800, above the \
              longest, 86400 seconds; its sessions last 86400 seconds"]
        );
        let error = validate_source_auth_config(&config.surfaces[0], None)
            .expect_err("a variant's TTL above the longest is refused on a save that sets it");
        assert_eq!(
            error.to_string(),
            "Channel 'varied': variant 'candidate' did_auth.session_ttl_seconds 172800 exceeds max 86400"
        );
        validate_source_auth_config(&config.surfaces[0], Some(&config.surfaces[0]))
            .expect("a save that keeps the variant's stored TTL passes");
        config.surfaces = vec![surface(3_600, 86_400)];
        assert!(
            config
                .did_auth_session_ttl_adjustments()
                .is_empty()
        );

        // A DID Auth method after the first mints sessions too, so its TTL is
        // bounded like the first method's.
        config.surfaces = vec![surface(604_800, 86_400)];
        assert_eq!(
            config.did_auth_session_ttl_adjustments(),
            ["Surface 'varied' (varied): did_auth.session_ttl_seconds is 604800, above the longest, 86400 seconds; \
              its sessions last 86400 seconds"]
        );
        let error = validate_source_auth_config(&config.surfaces[0], None)
            .expect_err("a later DID Auth method's TTL above the longest is refused");
        assert_eq!(error.to_string(), "Channel 'varied': did_auth.session_ttl_seconds 604800 exceeds max 86400");
    }

    /// The longest lifetime is read once, when the gateway starts; every later
    /// load of `gateway.json` keeps that value, whatever the file says, so a
    /// reload neither changes it nor fails on it.
    #[test]
    fn the_longest_transit_token_lifetime_is_pinned_when_the_gateway_starts() {
        let dir = tempfile::tempdir().unwrap();
        let gateway_json = dir
            .path()
            .join("gateway.json");
        let write = |max_secs: serde_json::Value| {
            std::fs::write(
                &gateway_json,
                serde_json::json!({
                    "did": { "domain": "test.local" },
                    "webauthn": { "rp_id": "localhost", "external_origin": "https://localhost" },
                    "integration": { "types": [], "categories": [] },
                    "listeners": [],
                    "routes": {},
                    "transit_token_max_lifetime_secs": max_secs
                })
                .to_string(),
            )
            .unwrap();
        };
        let mut bootstrap: BootstrapConfig =
            toml::from_str(&crate::render_default_bootstrap_toml("", "").unwrap()).unwrap();
        bootstrap.config_files.gateway = gateway_json
            .to_string_lossy()
            .into_owned();

        for refused in ["0", "29", "901", "\"ten\"", "-1", "60.5"] {
            write(serde_json::from_str(refused).unwrap());
            let error = bootstrap
                .pin_transit_token_max_lifetime()
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(&format!(
                    "transit_token_max_lifetime_secs in gateway.json must be from 30 to 900 seconds, not {refused}"
                )),
                "{error}"
            );
        }

        write(serde_json::json!(600));
        assert_eq!(
            bootstrap
                .pin_transit_token_max_lifetime()
                .unwrap(),
            600
        );
        for on_disk in [serde_json::json!(300), serde_json::json!(0), serde_json::json!(901), serde_json::json!("ten")]
        {
            write(on_disk.clone());
            assert_eq!(
                bootstrap
                    .load_network_config()
                    .unwrap()
                    .transit_token_max_lifetime_secs,
                600,
                "{on_disk}"
            );
        }
    }

    /// `external_consent_issuers`, which provider create, surface save, the
    /// connect API and every request check, is pinned at startup too: a later
    /// load keeps it, whether the file adds, changes or removes it.
    #[test]
    fn the_external_consent_issuers_are_pinned_when_the_gateway_starts() {
        let dir = tempfile::tempdir().unwrap();
        let gateway_json = dir
            .path()
            .join("gateway.json");
        let write = |issuers: Option<serde_json::Value>| {
            let mut config = serde_json::json!({
                "did": { "domain": "test.local" },
                "webauthn": { "rp_id": "localhost", "external_origin": "https://localhost" },
                "integration": { "types": [], "categories": [] },
                "listeners": [],
                "routes": {}
            });
            if let Some(issuers) = issuers {
                config["external_consent_issuers"] = issuers;
            }
            std::fs::write(&gateway_json, config.to_string()).unwrap();
        };
        let mut bootstrap: BootstrapConfig =
            toml::from_str(&crate::render_default_bootstrap_toml("", "").unwrap()).unwrap();
        bootstrap.config_files.gateway = gateway_json
            .to_string_lossy()
            .into_owned();
        write(Some(serde_json::json!({ "https://accounts.example": [] })));
        let pinned = bootstrap
            .pin_external_consent_issuers()
            .unwrap();
        let expected = Some(std::collections::HashMap::from([("https://accounts.example".to_string(), Vec::new())]));
        assert_eq!(pinned, expected);
        for on_disk in [None, Some(serde_json::json!({})), Some(serde_json::json!({ "https://other.example": [] }))] {
            write(on_disk.clone());
            assert_eq!(
                bootstrap
                    .load_network_config()
                    .unwrap()
                    .external_consent_issuers,
                expected,
                "{on_disk:?}"
            );
        }

        write(None);
        assert_eq!(
            bootstrap
                .pin_external_consent_issuers()
                .unwrap(),
            None
        );
        write(Some(serde_json::json!({ "https://accounts.example": [] })));
        assert_eq!(
            bootstrap
                .load_network_config()
                .unwrap()
                .external_consent_issuers,
            None,
            "a list added after startup takes a restart"
        );
    }

    /// Provider create and surface save read `external_consent_resource_origins`
    /// from the configuration the gateway started with, so every later load of
    /// `gateway.json`, a reload's included, keeps that value too: the requests
    /// a reload rebuilds check the same origins create and save accepted.
    #[test]
    fn the_external_consent_resource_origins_are_pinned_when_the_gateway_starts() {
        let dir = tempfile::tempdir().unwrap();
        let gateway_json = dir
            .path()
            .join("gateway.json");
        let write = |origins: serde_json::Value| {
            std::fs::write(
                &gateway_json,
                serde_json::json!({
                    "did": { "domain": "test.local" },
                    "webauthn": { "rp_id": "localhost", "external_origin": "https://localhost" },
                    "integration": { "types": [], "categories": [] },
                    "listeners": [],
                    "routes": {},
                    "external_consent_resource_origins": origins
                })
                .to_string(),
            )
            .unwrap();
        };
        let mut bootstrap: BootstrapConfig =
            toml::from_str(&crate::render_default_bootstrap_toml("", "").unwrap()).unwrap();
        bootstrap.config_files.gateway = gateway_json
            .to_string_lossy()
            .into_owned();
        let started = serde_json::json!({ "https://accounts.example": ["https://api.example"] });
        write(started.clone());
        let pinned = bootstrap
            .pin_external_consent_resource_origins()
            .unwrap();
        let expected: std::collections::HashMap<String, Vec<String>> = serde_json::from_value(started).unwrap();
        assert_eq!(pinned, expected);

        for on_disk in
            [serde_json::json!({}), serde_json::json!({ "https://accounts.example": ["https://elsewhere.example"] })]
        {
            write(on_disk.clone());
            assert_eq!(
                bootstrap
                    .load_network_config()
                    .unwrap()
                    .external_consent_resource_origins,
                expected,
                "{on_disk}"
            );
        }
    }
}
