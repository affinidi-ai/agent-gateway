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

    /// Load network configuration from the configured path, with the
    /// `transit_token_max_lifetime_secs` pinned at startup, once pinned. A
    /// `WARN` says when the file holds a different value, which takes a
    /// restart.
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

/// Boot-time source auth validation. A `from_jwt_claim` identity beside a
/// method other than `jwt_bearer` is only warned about here: stored surfaces
/// predating the rule booted with it, and saving them enforces it.
fn validate_source_auth_surface(surface: &crate::config::agent_surface::AgentSurface) -> anyhow::Result<()> {
    validate_source_auth_methods(surface)?;
    if let Err(error) = validate_jwt_claim_identity(surface) {
        warn!("{error}; callers that authenticate with another method are refused until the surface is fixed");
    }
    Ok(())
}

/// Serve a stored surface whose source authentication methods break the
/// rules for several methods with its first method alone, the only one the
/// gateway enforced before those rules, when that method is valid on its own.
/// Returns the rule broken; the caller logs it and persists the surface.
pub fn fall_back_to_first_source_auth_method(
    surface: &mut crate::config::agent_surface::AgentSurface
) -> Option<String> {
    let error = validate_source_auth_methods(surface).err()?;
    let mut first_only = surface.clone();
    first_only
        .access_point
        .caller_authentication
        .as_mut()?
        .methods
        .truncate(1);
    validate_source_auth_methods(&first_only).ok()?;
    *surface = first_only;
    Some(error.to_string())
}

/// Validate a surface's `source_auth` configuration.
///
/// Runs on **both** persistence paths:
/// - boot-time / TOML: called from [`GatewayConfig::validate`], which only
///   warns about the `from_jwt_claim` rule, after stored surfaces breaking the
///   other rules fell back to their first method
///   ([`fall_back_to_first_source_auth_method`]);
/// - HTTP API (`PUT/PATCH /v1/surfaces/...`): called from
///   `identity::handlers::surfaces::validate_and_save_surface` before
///   `store.save`.
///
/// Enforces the mTLS trust rules the runtime relies on, every
/// `DidAuthAuthConfig` invariant (see [`validate_did_auth_config`]), and the
/// rules that let a request select one method: each method reads its own
/// credential location, and at most one is DID Auth. A dashboard save cannot
/// persist values that would otherwise be rejected on the next process restart.
pub fn validate_source_auth_config(surface: &crate::config::agent_surface::AgentSurface) -> anyhow::Result<()> {
    validate_source_auth_methods(surface)?;
    validate_jwt_claim_identity(surface)
}

fn validate_source_auth_methods(surface: &crate::config::agent_surface::AgentSurface) -> anyhow::Result<()> {
    let methods = surface.source_auth_methods();
    for method in methods {
        validate_source_auth_method(method, &surface.name)?;
    }
    validate_method_selection(methods, &surface.name)
}

fn validate_source_auth_method(
    method: &crate::source_auth::SourceAuthConfig,
    surface_name: &str,
) -> anyhow::Result<()> {
    use crate::source_auth::models::{MtlsTrust, SourceAuthConfig};

    match method {
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

    let describe = |source: CredentialSource<'_>| match source {
        CredentialSource::Header(name) => format!("the '{name}' header"),
        CredentialSource::McpMeta => "MCP _meta".to_string(),
        CredentialSource::A2aExtension => "the A2A message extension".to_string(),
        CredentialSource::ClientCertificate => "the client certificate".to_string(),
    };
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
    fn methods_on_distinct_credential_locations_are_accepted() {
        let surface = surface_with_caller_auth(
            serde_json::json!([jwt_method(), api_key_method("X-API-Key")]),
            serde_json::json!({}),
        );
        validate_source_auth_config(&surface).unwrap();
    }

    #[test]
    fn methods_sharing_a_header_are_rejected_case_insensitively() {
        let surface = surface_with_caller_auth(
            serde_json::json!([jwt_method(), api_key_method("authorization")]),
            serde_json::json!({}),
        );
        let error = validate_source_auth_config(&surface)
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
        let error = validate_source_auth_config(&surface)
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
        let error = validate_source_auth_config(&surface)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "Channel 'multi': source authentication method 2 (api_key) reads MCP _meta; with more than one method, \
             each must read a header or the client certificate"
        );

        let alone = surface_with_caller_auth(serde_json::json!([body_method]), serde_json::json!({}));
        validate_source_auth_config(&alone).unwrap();
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
        let error = validate_source_auth_config(&surface)
            .unwrap_err()
            .to_string();
        assert_eq!(error, "Channel 'multi': did_auth.challenge_ttl_seconds must be > 0");
    }

    #[test]
    fn from_jwt_claim_identity_requires_every_method_to_be_jwt_bearer() {
        let inbound = serde_json::json!({"identity_slots": {"inbound": {"type": "from_jwt_claim"}}});
        let mixed =
            surface_with_caller_auth(serde_json::json!([jwt_method(), api_key_method("X-API-Key")]), inbound.clone());
        let error = validate_source_auth_config(&mixed)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "Channel 'multi': from_jwt_claim identity requires every source authentication method to be jwt_bearer"
        );

        let jwt_only = surface_with_caller_auth(serde_json::json!([jwt_method()]), inbound);
        validate_source_auth_config(&jwt_only).unwrap();
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
            let error = validate_source_auth_config(&surface)
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
        assert!(validate_source_auth_config(&surface).is_err(), "saving still refuses it");

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
        let reason = fall_back_to_first_source_auth_method(&mut surface).unwrap();
        assert!(reason.contains("both read the 'authorization' header"), "{reason}");
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
        assert!(fall_back_to_first_source_auth_method(&mut valid).is_none());
        assert_eq!(
            valid
                .source_auth_methods()
                .len(),
            2
        );
    }

    #[test]
    fn other_identity_modes_allow_mixed_methods() {
        let surface = surface_with_caller_auth(
            serde_json::json!([jwt_method(), api_key_method("X-API-Key")]),
            serde_json::json!({"identity_slots": {"protected": {"type": "static", "did": "did:web:agent.example"}}}),
        );
        validate_source_auth_config(&surface).unwrap();
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
}
