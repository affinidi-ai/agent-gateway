//! Embedded x402 facilitator implementation
//!
//! This module provides an embedded instance of the x402 facilitator
//! instead of requiring a separate service. It uses:
//! - x402-facilitator-local for core facilitator logic
//! - x402-chain-eip155 for EVM chain support (EIP-3009, Permit2)
//! - x402-chain-solana for Solana chain support (SPL Token transfers)
//!
//! The facilitator performs:
//! - Signature verification
//! - On-chain nonce checking (prevents replay attacks)
//! - Balance validation
//! - Settlement coordination

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{Level, debug, error, info, instrument, span, warn};
use x402_chain_eip155::chain::Eip155ChainProvider;
use x402_chain_eip155::chain::config::{Eip155ChainConfig, Eip155ChainConfigInner, EvmPrivateKey, RpcConfig};
use x402_chain_eip155::chain::types::Eip155ChainReference;
use x402_chain_eip155::{V1Eip155Exact, V2Eip155Exact};
use x402_chain_solana::chain::SolanaChainProvider;
use x402_chain_solana::chain::config::{SolanaChainConfig, SolanaChainConfigInner, SolanaSignerConfig};
use x402_chain_solana::chain::types::SolanaChainReference;
use x402_chain_solana::{V1SolanaExact, V2SolanaExact};
use x402_facilitator_local::FacilitatorLocal;
use x402_types::{
    chain::{ChainId, ChainIdPattern, ChainProviderOps, ChainRegistry, FromConfig},
    config::LiteralOrEnv,
    facilitator::Facilitator,
    proto,
    scheme::{
        SchemeBlueprints, SchemeConfig, SchemeRegistry, X402SchemeFacilitator, X402SchemeFacilitatorBuilder,
        X402SchemeId,
    },
};

use crate::config::types::X402Config;

/// Errors that can occur when working with the embedded facilitator
#[derive(Debug, thiserror::Error)]
pub enum EmbeddedFacilitatorError {
    #[error("No RPC endpoints configured for embedded facilitator")]
    NoRpcEndpoints,

    #[error(
        "No chain providers were successfully created - ensure at least one RPC endpoint has a corresponding private key configured"
    )]
    NoValidProviders,

    #[error("Invalid chain ID format: {0}")]
    InvalidChainId(String),

    #[error("Unknown network name: {0}")]
    UnknownNetwork(String),

    #[error("Invalid RPC URL {url}: {error}")]
    InvalidRpcUrl { url: String, error: String },

    #[error("Invalid private key for chain {chain}: {error}")]
    InvalidPrivateKey { chain: String, error: String },

    #[error("Environment variable {0} not set")]
    MissingEnvVar(String),

    #[error("Failed to create EVM provider for {chain}: {error}")]
    ProviderCreationFailed { chain: String, error: String },

    #[error("Failed to parse chain ID number: {0}")]
    ChainIdParseFailed(String),
}

/// Global embedded facilitator instance with config hash for validation
static EMBEDDED_FACILITATOR: RwLock<Option<(u64, Arc<EmbeddedFacilitator>)>> = RwLock::const_new(None);

/// Compute a hash of the config to detect changes
fn compute_config_hash(config: &X402Config) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();

    // Hash RPC endpoints
    let mut rpc_keys: Vec<_> = config
        .rpc_endpoints
        .keys()
        .collect();
    rpc_keys.sort();
    for key in rpc_keys {
        key.hash(&mut hasher);
        if let Some(value) = config.rpc_endpoints.get(key) {
            value.hash(&mut hasher);
        }
    }

    // Hash private keys (keys only, not values for security)
    if let Some(keys) = &config.facilitator_private_keys {
        let mut key_names: Vec<_> = keys.keys().collect();
        key_names.sort();
        for key in key_names {
            key.hash(&mut hasher);
        }
    }

    hasher.finish()
}

/// Resolve environment variable or return literal value
fn resolve_env_or_literal(value: &str) -> Result<String, EmbeddedFacilitatorError> {
    if let Some(env_var) = value.strip_prefix('$') {
        std::env::var(env_var).map_err(|_| EmbeddedFacilitatorError::MissingEnvVar(env_var.to_string()))
    } else {
        Ok(value.to_string())
    }
}

/// Parse chain ID from network name or CAIP-2 format
fn parse_chain_id(network: &str) -> Result<ChainId, EmbeddedFacilitatorError> {
    if network.contains(':') {
        network
            .parse()
            .map_err(|_| EmbeddedFacilitatorError::InvalidChainId(network.to_string()))
    } else {
        // Legacy network name to ChainId conversion
        let chain_id_str = match network {
            "ethereum" => "eip155:1",
            "base" => "eip155:8453",
            "optimism" => "eip155:10",
            "arbitrum" => "eip155:42161",
            "polygon" => "eip155:137",
            "avalanche" => "eip155:43114",
            _ => {
                return Err(EmbeddedFacilitatorError::UnknownNetwork(network.to_string()));
            }
        };

        chain_id_str
            .parse()
            .map_err(|_| EmbeddedFacilitatorError::InvalidChainId(network.to_string()))
    }
}

/// Validate configuration before initialization
fn validate_config(config: &X402Config) -> Result<(), EmbeddedFacilitatorError> {
    if config
        .rpc_endpoints
        .is_empty()
    {
        return Err(EmbeddedFacilitatorError::NoRpcEndpoints);
    }

    // Check that at least one RPC endpoint has a corresponding private key
    // (We don't require ALL endpoints to have keys - only the ones that will be used for settlement)
    let has_any_key = config
        .facilitator_private_keys
        .as_ref()
        .map(|keys| !keys.is_empty())
        .unwrap_or(false);

    if !has_any_key {
        warn!("No private keys configured for any chain - payment settlement will not work");
    }

    Ok(())
}

/// Get or initialize the embedded facilitator
/// Returns cached instance if config hasn't changed
#[instrument(skip(config), fields(chains = config.rpc_endpoints.len()))]
pub async fn get_embedded_facilitator(
    config: &X402Config
) -> Result<Arc<EmbeddedFacilitator>, EmbeddedFacilitatorError> {
    let config_hash = compute_config_hash(config);

    // Check if we have a cached instance with matching config
    {
        let cached = EMBEDDED_FACILITATOR
            .read()
            .await;
        if let Some((hash, facilitator)) = cached.as_ref() {
            if *hash == config_hash {
                debug!("Reusing cached embedded facilitator");
                return Ok(Arc::clone(facilitator));
            }
            info!("Config changed, reinitializing embedded facilitator");
        }
    }

    // Validate config before initialization
    validate_config(config)?;

    // Initialize new instance
    let facilitator = EmbeddedFacilitator::new(config).await?;
    let facilitator_arc = Arc::new(facilitator);

    // Store in global cache
    {
        let mut cached = EMBEDDED_FACILITATOR
            .write()
            .await;
        *cached = Some((config_hash, Arc::clone(&facilitator_arc)));
    }

    Ok(facilitator_arc)
}

/// Chain provider enum (mirrors x402-rs facilitator pattern)
#[derive(Debug, Clone)]
enum ChainProvider {
    Eip155(Arc<Eip155ChainProvider>),
    Solana(Arc<SolanaChainProvider>),
}

impl ChainProviderOps for ChainProvider {
    fn chain_id(&self) -> ChainId {
        match self {
            ChainProvider::Eip155(provider) => provider.chain_id(),
            ChainProvider::Solana(provider) => provider.chain_id(),
        }
    }

    fn signer_addresses(&self) -> Vec<String> {
        match self {
            ChainProvider::Eip155(provider) => provider.signer_addresses(),
            ChainProvider::Solana(provider) => provider.signer_addresses(),
        }
    }
}

// Implement scheme builder for V1Eip155Exact with our ChainProvider enum
impl X402SchemeFacilitatorBuilder<&ChainProvider> for V1Eip155Exact {
    fn build(
        &self,
        provider: &ChainProvider,
        config: Option<serde_json::Value>,
    ) -> Result<Box<dyn X402SchemeFacilitator>, Box<dyn std::error::Error>> {
        let ChainProvider::Eip155(eip155_provider) = provider else {
            return Err("V1Eip155Exact requires EIP-155 chain provider".into());
        };
        X402SchemeFacilitatorBuilder::build(self, Arc::clone(eip155_provider), config)
    }
}

// Implement scheme builder for V2Eip155Exact with our ChainProvider enum
impl X402SchemeFacilitatorBuilder<&ChainProvider> for V2Eip155Exact {
    fn build(
        &self,
        provider: &ChainProvider,
        config: Option<serde_json::Value>,
    ) -> Result<Box<dyn X402SchemeFacilitator>, Box<dyn std::error::Error>> {
        let ChainProvider::Eip155(eip155_provider) = provider else {
            return Err("V2Eip155Exact requires EIP-155 chain provider".into());
        };
        X402SchemeFacilitatorBuilder::build(self, Arc::clone(eip155_provider), config)
    }
}

// Implement scheme builder for V1SolanaExact with our ChainProvider enum
impl X402SchemeFacilitatorBuilder<&ChainProvider> for V1SolanaExact {
    fn build(
        &self,
        provider: &ChainProvider,
        config: Option<serde_json::Value>,
    ) -> Result<Box<dyn X402SchemeFacilitator>, Box<dyn std::error::Error>> {
        let ChainProvider::Solana(solana_provider) = provider else {
            return Err("V1SolanaExact requires Solana chain provider".into());
        };
        X402SchemeFacilitatorBuilder::build(self, Arc::clone(solana_provider), config)
    }
}

// Implement scheme builder for V2SolanaExact with our ChainProvider enum
impl X402SchemeFacilitatorBuilder<&ChainProvider> for V2SolanaExact {
    fn build(
        &self,
        provider: &ChainProvider,
        config: Option<serde_json::Value>,
    ) -> Result<Box<dyn X402SchemeFacilitator>, Box<dyn std::error::Error>> {
        let ChainProvider::Solana(solana_provider) = provider else {
            return Err("V2SolanaExact requires Solana chain provider".into());
        };
        X402SchemeFacilitatorBuilder::build(self, Arc::clone(solana_provider), config)
    }
}

/// Embedded facilitator instance with multi-chain support (EVM + Solana)
pub struct EmbeddedFacilitator {
    facilitator: Arc<FacilitatorLocal<SchemeRegistry>>,
}

impl EmbeddedFacilitator {
    /// Create a new embedded facilitator with multi-chain providers (EVM + Solana)
    #[instrument(skip(config), fields(chains = config.rpc_endpoints.len()))]
    pub async fn new(config: &X402Config) -> Result<Self, EmbeddedFacilitatorError> {
        let span = span!(Level::INFO, "embedded_facilitator_init");
        let _enter = span.enter();

        info!("Initializing embedded x402 facilitator with {} chain(s)", config.rpc_endpoints.len());

        // Debug: Log what private keys we have
        if let Some(keys) = &config.facilitator_private_keys {
            info!("Facilitator has {} private keys configured:", keys.len());
            for chain_id in keys.keys() {
                info!("  - Private key available for: {}", chain_id);
            }
        } else {
            warn!("Facilitator has NO private keys configured!");
        }

        // Build chain registry with EIP-155 providers
        let mut providers: HashMap<ChainId, ChainProvider> = HashMap::new();

        for (network, rpc_url) in &config.rpc_endpoints {
            // Parse chain ID (handles both CAIP-2 and legacy network names)
            let chain_id = parse_chain_id(network)?;

            // Use the original network string for key lookup to preserve the format (base58 for Solana)
            // The ChainId.to_string() method may convert formats (e.g., base58 to hex), but the
            // facilitator_private_keys map uses the original network format from x402.json
            let chain_id_str = chain_id.to_string();
            let network_key = network.as_str(); // Use original network string for key lookup

            // Check if we have a private key for this network
            // If not, skip it (the network can still be used for verification, just not settlement)
            let key_config = match config
                .facilitator_private_keys
                .as_ref()
                .and_then(|keys| keys.get(network_key))
            {
                Some(key) => key,
                None => {
                    warn!(chain = %chain_id, network_key = %network_key, "No private key configured for this chain - skipping provider creation (chain can be used for verification but not settlement)");
                    continue;
                }
            };

            // Handle different chain types based on namespace
            if let Some(eip155_id) = chain_id_str.strip_prefix("eip155:") {
                // EVM chain handling
                debug!(chain = %chain_id, rpc = %rpc_url, "Adding EVM chain");

                let chain_id_num = eip155_id
                    .parse::<u64>()
                    .map_err(|e| EmbeddedFacilitatorError::ChainIdParseFailed(e.to_string()))?;

                // Resolve facilitator private key
                let private_key = resolve_env_or_literal(&key_config.private_key)?;

                // Parse private key hex string to EvmPrivateKey
                let evm_key: EvmPrivateKey = private_key
                    .parse()
                    .map_err(|e| EmbeddedFacilitatorError::InvalidPrivateKey {
                        chain: chain_id_str.clone(),
                        error: e,
                    })?;

                // Wrap in LiteralOrEnv
                let signer_config = LiteralOrEnv::from_literal(evm_key);

                // Get chain-specific config or use defaults
                let eip1559 = true; // TODO: Make configurable per chain
                let flashblocks = false; // TODO: Make configurable per chain
                let rate_limit = 100; // TODO: Make configurable per chain
                let receipt_timeout_secs = 30; // TODO: Make configurable per chain

                // Build Eip155ChainConfig
                let chain_config = Eip155ChainConfig {
                    chain_reference: Eip155ChainReference::new(chain_id_num),
                    inner: Eip155ChainConfigInner {
                        eip1559,
                        flashblocks,
                        signers: vec![signer_config],
                        rpc: vec![RpcConfig {
                            http: x402_types::config::LiteralOrEnv::from_literal(rpc_url.parse().map_err(
                                |e: url::ParseError| EmbeddedFacilitatorError::InvalidRpcUrl {
                                    url: rpc_url.clone(),
                                    error: e.to_string(),
                                },
                            )?),
                            rate_limit: Some(rate_limit),
                        }],
                        receipt_timeout_secs,
                    },
                };

                // Use from_config to build the provider
                let provider = Arc::new(
                    Eip155ChainProvider::from_config(&chain_config)
                        .await
                        .map_err(|e| EmbeddedFacilitatorError::ProviderCreationFailed {
                            chain: chain_id_str.clone(),
                            error: e.to_string(),
                        })?,
                );

                providers.insert(chain_id.clone(), ChainProvider::Eip155(provider));
                info!(chain = %chain_id, "Successfully registered EVM chain");
            } else if network_key.starts_with("solana:") {
                // Solana chain handling
                // The CAIP-2 reference is a truncated version (32 chars), so we need to fetch
                // the full genesis hash from the RPC endpoint
                let caip2_reference = chain_id_str
                    .strip_prefix("solana:")
                    .ok_or_else(|| {
                        EmbeddedFacilitatorError::InvalidChainId(format!("Expected solana: prefix in {}", chain_id_str))
                    })?;

                debug!(
                    chain = %chain_id,
                    rpc = %rpc_url,
                    caip2_reference = %caip2_reference,
                    network_key = %network_key,
                    "Adding Solana chain - fetching full genesis hash from RPC"
                );

                // Resolve facilitator private key
                let private_key = resolve_env_or_literal(&key_config.private_key)?;

                // Create signer config - SolanaSignerConfig expects a JSON string value (not an object)
                // The private key should be a base58-encoded Solana keypair
                // When deserializing from a JSON string, it creates a LiteralOrEnv::Literal internally
                debug!(chain = %chain_id, "Creating Solana signer config from private key");
                let signer_config: SolanaSignerConfig =
                    serde_json::from_str(&format!("\"{}\"", private_key)).map_err(|e| {
                        EmbeddedFacilitatorError::InvalidPrivateKey {
                            chain: network_key.to_string(),
                            error: format!(
                                "Failed to parse Solana private key: {}. Expected base58-encoded keypair.",
                                e
                            ),
                        }
                    })?;

                // Validate the keypair can actually be created to prevent panics later
                // Decode base58 and validate the keypair structure
                let keypair_bytes = bs58::decode(&private_key)
                    .into_vec()
                    .map_err(|e| EmbeddedFacilitatorError::InvalidPrivateKey {
                        chain: network_key.to_string(),
                        error: format!("Invalid base58 encoding for Solana keypair: {}", e),
                    })?;

                if keypair_bytes.len() != 64 {
                    return Err(EmbeddedFacilitatorError::InvalidPrivateKey {
                        chain: network_key.to_string(),
                        error: format!(
                            "Invalid Solana keypair length: expected 64 bytes, got {}. Please regenerate the keypair.",
                            keypair_bytes.len()
                        ),
                    });
                }

                // Validate the keypair structure by attempting to create it
                // This will catch issues like mismatched public key vs private key
                solana_sdk::signature::keypair_from_seed(&keypair_bytes[..32]).map_err(|e| {
                    EmbeddedFacilitatorError::InvalidPrivateKey {
                        chain: network_key.to_string(),
                        error: format!(
                            "Invalid Solana keypair: {}. The keypair may be corrupted. Please regenerate the keypair.",
                            e
                        ),
                    }
                })?;

                info!(chain = %chain_id, "Validated Solana keypair successfully");

                // Use the CAIP-2 reference directly as UTF-8 bytes
                // SolanaChainReference expects the truncated base58 string (32 chars) as UTF-8, not decoded hash bytes
                // The CAIP-13 spec uses a 32-character truncation of the genesis hash for the reference
                debug!(chain = %chain_id, caip2_ref = %caip2_reference, "Using CAIP-2 reference for Solana chain");

                let genesis_bytes: [u8; 32] = caip2_reference
                    .as_bytes()
                    .try_into()
                    .map_err(|_| {
                        EmbeddedFacilitatorError::InvalidChainId(format!(
                            "CAIP-2 Solana reference must be exactly 32 characters, got {}: {}",
                            caip2_reference.len(),
                            caip2_reference
                        ))
                    })?;

                // Build SolanaChainConfig
                let chain_config = SolanaChainConfig {
                    chain_reference: SolanaChainReference::new(genesis_bytes),
                    inner: SolanaChainConfigInner {
                        signer: signer_config,
                        rpc: x402_types::config::LiteralOrEnv::from_literal(rpc_url.parse().map_err(
                            |e: url::ParseError| EmbeddedFacilitatorError::InvalidRpcUrl {
                                url: rpc_url.clone(),
                                error: e.to_string(),
                            },
                        )?),
                        pubsub: None,                    // Optional WebSocket endpoint for real-time updates
                        max_compute_unit_limit: 400_000, // Default Solana compute limit
                        max_compute_unit_price: 1_000_000, // Default priority fee
                    },
                };

                // Use from_config to build the provider
                debug!(
                    chain = %chain_id,
                    rpc = %rpc_url,
                    genesis_ref = %caip2_reference,
                    "Creating Solana chain provider with config"
                );

                let provider = Arc::new(
                    SolanaChainProvider::from_config(&chain_config)
                        .await
                        .map_err(|e| {
                            let error_msg = format!("Failed to create Solana provider: {}", e);
                            warn!(chain = %chain_id, error = %error_msg, "Solana provider creation failed");
                            EmbeddedFacilitatorError::ProviderCreationFailed {
                                chain: chain_id_str.clone(),
                                error: error_msg,
                            }
                        })?,
                );

                // Log the signer addresses for verification
                let signer_addrs = provider.signer_addresses();
                info!(
                    chain = %chain_id,
                    signer_addresses = ?signer_addrs,
                    "Successfully registered Solana chain with {} signer(s)",
                    signer_addrs.len()
                );

                providers.insert(chain_id.clone(), ChainProvider::Solana(provider));
            } else {
                warn!(chain = %chain_id, "Unsupported chain namespace - skipping");
                continue;
            }
        }

        if providers.is_empty() {
            return Err(EmbeddedFacilitatorError::NoValidProviders);
        }

        info!(
            "Initialized {} chain provider(s) for payment settlement out of {} configured RPC endpoint(s)",
            providers.len(),
            config.rpc_endpoints.len()
        );

        let chain_registry = ChainRegistry::new(providers);

        // Build scheme blueprints - register both EVM and Solana schemes
        let v1_eip155 = V1Eip155Exact;
        let v2_eip155 = V2Eip155Exact;
        let v1_solana = V1SolanaExact;
        let v2_solana = V2SolanaExact;

        info!("[DEBUG x402] Registering scheme blueprints:");
        info!(
            "  - V1Eip155Exact: id='{}', namespace='{}', scheme='{}', version={}",
            v1_eip155.id(),
            v1_eip155.namespace(),
            v1_eip155.scheme(),
            v1_eip155.x402_version()
        );
        info!(
            "  - V2Eip155Exact: id='{}', namespace='{}', scheme='{}', version={}",
            v2_eip155.id(),
            v2_eip155.namespace(),
            v2_eip155.scheme(),
            v2_eip155.x402_version()
        );
        info!(
            "  - V1SolanaExact: id='{}', namespace='{}', scheme='{}', version={}",
            v1_solana.id(),
            v1_solana.namespace(),
            v1_solana.scheme(),
            v1_solana.x402_version()
        );
        info!(
            "  - V2SolanaExact: id='{}', namespace='{}', scheme='{}', version={}",
            v2_solana.id(),
            v2_solana.namespace(),
            v2_solana.scheme(),
            v2_solana.x402_version()
        );

        let scheme_blueprints = SchemeBlueprints::<ChainProvider>::new()
            .and_register(v1_eip155)
            .and_register(v2_eip155)
            .and_register(v1_solana)
            .and_register(v2_solana);

        info!("Registered payment schemes: V1Eip155Exact, V2Eip155Exact (EIP-3009), V1SolanaExact, V2SolanaExact");

        // Configure schemes with explicit patterns for EVM and Solana chains
        let scheme_configs: Vec<SchemeConfig> = vec![
            // V1 EIP155 Exact - for all EVM chains using protocol v1
            SchemeConfig {
                enabled: true,
                id: "v1-eip155-exact".to_string(),
                chains: ChainIdPattern::Wildcard {
                    namespace: "eip155".to_string(),
                },
                config: None,
            },
            // V2 EIP155 Exact - for all EVM chains using protocol v2 (EIP-3009)
            SchemeConfig {
                enabled: true,
                id: "v2-eip155-exact".to_string(),
                chains: ChainIdPattern::Wildcard {
                    namespace: "eip155".to_string(),
                },
                config: None,
            },
            // V1 Solana Exact - for all Solana chains using protocol v1
            SchemeConfig {
                enabled: true,
                id: "v1-solana-exact".to_string(),
                chains: ChainIdPattern::Wildcard {
                    namespace: "solana".to_string(),
                },
                config: Some(serde_json::json!({
                    "allow_additional_instructions": true,
                    "max_instruction_count": 10,
                    "allowed_program_ids": [
                        "DjVE6JNiYqPL2QXyCUUh8rNjHrbz9hXHNYt99MQ59qw1",  // Phantom Lighthouse
                        "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",   // Memo Program
                        "ComputeBudget111111111111111111111111111111"   // ComputeBudgetProgram (wallet-added)
                    ],
                    "blocked_program_ids": [],
                    "require_fee_payer_not_in_instructions": true
                })),
            },
            // V2 Solana Exact - for all Solana chains using protocol v2
            SchemeConfig {
                enabled: true,
                id: "v2-solana-exact".to_string(),
                chains: ChainIdPattern::Wildcard {
                    namespace: "solana".to_string(),
                },
                config: Some(serde_json::json!({
                    "allow_additional_instructions": true,
                    "max_instruction_count": 10,
                    "allowed_program_ids": [
                        "DjVE6JNiYqPL2QXyCUUh8rNjHrbz9hXHNYt99MQ59qw1",  // Phantom Lighthouse
                        "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",   // Memo Program
                        "ComputeBudget111111111111111111111111111111"   // ComputeBudgetProgram (wallet-added)
                    ],
                    "blocked_program_ids": [],
                    "require_fee_payer_not_in_instructions": true
                })),
            },
        ];

        info!("[DEBUG x402] Building scheme registry with {} configured schemes", scheme_configs.len());

        // Log all scheme config IDs for debugging
        for config in &scheme_configs {
            info!(
                "[DEBUG x402] SchemeConfig: id='{}', chains={}, enabled={}",
                config.id, config.chains, config.enabled
            );
        }

        // Build scheme registry (doesn't return Result, just SchemeRegistry)
        let scheme_registry = SchemeRegistry::build(chain_registry, scheme_blueprints, &scheme_configs);

        info!("[DEBUG x402] Scheme registry built successfully");

        // Create facilitator instance
        let facilitator = FacilitatorLocal::new(scheme_registry);

        info!("Embedded x402 facilitator initialized successfully");

        Ok(Self {
            facilitator: Arc::new(facilitator),
        })
    }

    /// Verify a payment authorization
    ///
    /// This performs:
    /// - Signature verification (EIP-712)
    /// - On-chain nonce checking
    /// - Balance validation
    /// - Timestamp validation
    #[instrument(skip(self, request), fields(scheme = ?request))]
    pub async fn verify(
        &self,
        request: proto::VerifyRequest,
    ) -> Result<proto::VerifyResponse, String> {
        debug!("Verifying payment via embedded facilitator");

        let result = self
            .facilitator
            .verify(&request)
            .await
            .map_err(|e| {
                let error_msg = format!("Facilitator verification failed: {}", e);
                error!("[x402 Facilitator] SDK Error type: {:?}", std::any::type_name_of_val(&e));
                error!("[x402 Facilitator] SDK Error message: {}", e);
                error!("[x402 Facilitator] SDK Error debug: {:?}", e);
                error_msg
            });

        if result.is_err() {
            error!("[x402 Facilitator] ========== SDK VERIFICATION FAILED ==========");
            error!("[x402 Facilitator] Payment verification failed");
        }

        result
    }

    /// Settle a payment on-chain
    ///
    /// This submits the signed authorization to the blockchain
    /// for execution (e.g., EIP-3009 receiveWithAuthorization)
    #[instrument(skip(self, request), fields(scheme = ?request))]
    pub async fn settle(
        &self,
        request: proto::SettleRequest,
    ) -> Result<proto::SettleResponse, String> {
        debug!("Settling payment via embedded facilitator");

        let result = self
            .facilitator
            .settle(&request)
            .await
            .map_err(|e| format!("Facilitator settlement failed: {}", e));

        if result.is_err() {
            error!("[x402 Facilitator] Payment settlement failed");
        }

        result
    }
}
