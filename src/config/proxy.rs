//! Proxy configuration implementation

use super::network::NetworkConfig;
use super::types::*;
use std::path::PathBuf;
use tracing::{info, warn};

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

    /// Load test endpoints configuration from test-endpoints.json
    pub fn load_test_endpoints_config(&self) -> anyhow::Result<TestEndpointsConfig> {
        let test_endpoints_path = &self
            .config_files
            .test_endpoints;
        info!("Loading test endpoints configuration from: {}", test_endpoints_path);

        // Read and parse test-endpoints.json
        let contents = std::fs::read_to_string(test_endpoints_path)?;
        let config: TestEndpointsConfig = serde_json::from_str(&contents)?;

        info!(
            "Loaded test endpoints config: evm={}, solana_devnet={}, solana_mainnet={}",
            config.evm.is_some(),
            config.solana_devnet.is_some(),
            config
                .solana_mainnet
                .is_some()
        );
        Ok(config)
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
        use crate::source_auth::{SourceAuthConfig, models::DidAuthAuthConfig};

        self.surfaces
            .iter()
            .filter_map(|surface| {
                let Some(SourceAuthConfig::DidAuth(cfg)) = surface.source_auth() else {
                    return None;
                };
                let ttl = cfg
                    .session_ttl_seconds
                    .filter(|ttl| *ttl > DidAuthAuthConfig::MAX_SESSION_TTL_SECONDS)?;
                Some(format!(
                    "Surface '{}' ({}): did_auth.session_ttl_seconds is {ttl}, above the longest, {} seconds; its \
                     sessions last {} seconds",
                    surface.name,
                    surface.surface_id,
                    DidAuthAuthConfig::MAX_SESSION_TTL_SECONDS,
                    cfg.effective_session_ttl_seconds()
                ))
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
                     payment policy points at an agent-pay surface",
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
/// (see [`GatewayConfig::did_auth_session_ttl_adjustments`]).
fn validate_source_auth_surface(surface: &crate::config::agent_surface::AgentSurface) -> anyhow::Result<()> {
    match surface.source_auth() {
        Some(src) => validate_stored_source_auth_method(src, &surface.name),
        None => Ok(()),
    }
}

/// Validate a surface's `source_auth` configuration on the HTTP save path
/// (`identity::handlers::surfaces::validate_and_save_surface`, before
/// `store.save`).
///
/// Enforces the mTLS trust rules the runtime relies on, every
/// `DidAuthAuthConfig` invariant boot also checks (see
/// [`validate_did_auth_config`]), and the DID Auth session TTL bound, unless
/// `stored`, the surface as stored, has the same TTL.
pub fn validate_source_auth_config(
    surface: &crate::config::agent_surface::AgentSurface,
    stored: Option<&crate::config::agent_surface::AgentSurface>,
) -> anyhow::Result<()> {
    match surface.source_auth() {
        Some(src) => validate_source_auth_method(src, stored.and_then(|stored| stored.source_auth()), &surface.name),
        None => Ok(()),
    }
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
            validate_session_ttl_bound(cfg.session_ttl_seconds, surface_name)?;
        }
    }
    Ok(())
}

/// Refuse a DID Auth `session_ttl_seconds` above
/// [`DidAuthAuthConfig::MAX_SESSION_TTL_SECONDS`](crate::source_auth::models::DidAuthAuthConfig::MAX_SESSION_TTL_SECONDS).
fn validate_session_ttl_bound(
    session_ttl_seconds: Option<u64>,
    surface_name: &str,
) -> anyhow::Result<()> {
    use crate::source_auth::models::DidAuthAuthConfig;

    if let Some(ttl) = session_ttl_seconds.filter(|ttl| *ttl > DidAuthAuthConfig::MAX_SESSION_TTL_SECONDS) {
        anyhow::bail!(
            "Channel '{}': did_auth.session_ttl_seconds {} exceeds max {}",
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
