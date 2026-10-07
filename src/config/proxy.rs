//! Proxy configuration implementation

use super::network::NetworkConfig;
use super::types::*;
use std::path::PathBuf;
use tracing::{info, warn};

#[allow(dead_code)]
impl BootstrapConfig {
    /// Load network configuration from the configured path
    pub fn load_network_config(&self) -> anyhow::Result<NetworkConfig> {
        let network_path = &self.config_files.gateway;
        info!("Loading network configuration from: {}", network_path);
        let mut network_config = NetworkConfig::load_from_file(network_path)?;

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

            // Validate MPP configuration if present
            if let Some(mpp_config) = surface.mpp_config() {
                for warning in mpp_config.validate(&surface.name) {
                    warn!("{}", warning);
                }
            }

            if let Some(x402) = surface.x402_config()
                && let Some(ref triggers) = x402.mcp_payment_triggers
            {
                for warning in triggers.validate(&surface.name) {
                    warn!("{}", warning);
                }
            }

            // Warn if mpp_auto_pay is enabled but no mpp_policy is set
            if surface.mpp_auto_pay() && surface.mpp_config().is_none() {
                warn!(
                    "[mpp] Channel '{}'{}: mpp_auto_pay is enabled but no mpp_policy is configured",
                    surface.name, channel_id
                );
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

fn validate_source_auth_surface(surface: &crate::config::agent_surface::AgentSurface) -> anyhow::Result<()> {
    validate_source_auth_config(surface)
}

/// Validate a surface's `source_auth` configuration.
///
/// Runs on **both** persistence paths:
/// - boot-time / TOML: called from [`GatewayConfig::validate`];
/// - HTTP API (`PUT/PATCH /v1/surfaces/...`): called from
///   `identity::handlers::surfaces::validate_and_save_surface` before
///   `store.save`.
///
/// Enforces the mTLS trust rules the runtime relies on plus every
/// `DidAuthAuthConfig` invariant (see [`validate_did_auth_config`]) so a
/// dashboard save cannot persist values that would otherwise be rejected on
/// the next process restart.
pub fn validate_source_auth_config(surface: &crate::config::agent_surface::AgentSurface) -> anyhow::Result<()> {
    use crate::source_auth::models::{MtlsTrust, SourceAuthConfig};

    let Some(src) = surface.source_auth() else {
        return Ok(());
    };

    match src {
        SourceAuthConfig::Mtls(cfg) => match &cfg.trust {
            MtlsTrust::Pinned { certificate_ids } => {
                if certificate_ids.is_empty() {
                    anyhow::bail!("Channel '{}': mTLS pinned trust requires at least one certificate_id", surface.name);
                }
            }
            MtlsTrust::Ca {
                ca_certificate_ids,
                check_crl,
                require_ocsp,
                ..
            } => {
                if ca_certificate_ids.is_empty() {
                    anyhow::bail!("Channel '{}': mTLS CA trust requires at least one ca_certificate_id", surface.name);
                }
                if *check_crl {
                    anyhow::bail!(
                        "Channel '{}': mTLS CA trust has check_crl=true but CRL checking is not yet implemented; set check_crl=false",
                        surface.name
                    );
                }
                if *require_ocsp {
                    anyhow::bail!(
                        "Channel '{}': mTLS CA trust has require_ocsp=true but OCSP stapling is not yet implemented; set require_ocsp=false",
                        surface.name
                    );
                }
            }
        },
        SourceAuthConfig::JwtBearer(_) | SourceAuthConfig::ApiKey(_) | SourceAuthConfig::ApiKeyProvider(_) => {}
        SourceAuthConfig::DidAuth(cfg) => validate_did_auth_config(cfg, &surface.name)?,
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
    if let Some(ttl) = session_ttl_seconds
        && ttl == 0
    {
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
