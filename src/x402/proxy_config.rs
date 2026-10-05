//! Configuration types for X402 Proxy wallets and networks.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::info;

/// Main configuration for X402 Proxy functionality
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402ProxyConfig {
    /// Network definitions (blockchains and RPC endpoints)
    #[serde(default)]
    pub networks: Vec<NetworkDefinition>,

    /// Wallet configurations
    #[serde(default)]
    pub wallets: Vec<X402WalletConfig>,

    /// Stripe payment methods for MPP card payments (client-side).
    /// Each entry is a stored PaymentMethod that can be used to fulfil
    /// `method: "card"` / `method: "stripe"` challenges.
    #[serde(default)]
    pub stripe_payment_methods: Vec<StripePaymentMethodConfig>,
}

/// Network definition (blockchain configuration)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDefinition {
    /// Unique network identifier (e.g., "base-sepolia", "solana-devnet")
    pub id: String,

    /// Display name
    pub name: String,

    /// Chain type: "evm", "solana", etc.
    pub chain_type: String,

    /// Chain ID for EVM networks
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,

    /// RPC endpoint URL
    pub rpc_endpoint: String,

    /// Optional description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Wallet configuration for X402 Proxy payments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402WalletConfig {
    /// Unique wallet identifier
    pub id: String,

    /// Display name
    pub name: String,

    /// Optional description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Wallet bindings (one per network)
    pub bindings: Vec<WalletBinding>,
}

/// Wallet binding for a specific network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBinding {
    /// Network identifier (must match a NetworkDefinition.id)
    pub network: String,

    /// Wallet address on this network
    pub address: String,

    /// Private key - can be a literal key or a secret reference starting with $SECRET:
    pub private_key: String,

    /// Supported token symbols with priority
    pub symbols: Vec<SymbolConfig>,
}

impl WalletBinding {
    /// Get the private key value
    /// If the private_key starts with $SECRET:, load from secrets store
    /// Otherwise, return the literal value
    pub async fn get_private_key_value(
        &self,
        secrets_store: &dyn crate::secrets::SecretsStore,
    ) -> anyhow::Result<String> {
        if self
            .private_key
            .starts_with("$SECRET:")
        {
            // Extract secret ID (everything after $SECRET:)
            let secret_id = &self.private_key[8..]; // Skip $SECRET:

            let secret = secrets_store
                .get_by_secret_id(secret_id)
                .await
                .with_context(|| format!("Failed to load private key secret: {}", secret_id))?;

            match secret {
                Some(s) => Ok(s.value),
                None => Err(anyhow::anyhow!("Private key secret not found: {}", secret_id)),
            }
        } else {
            // Return literal private key
            Ok(self.private_key.clone())
        }
    }
}

/// Symbol configuration with priority
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolConfig {
    /// Token symbol (e.g., "USDC", "ETH", "SOL")
    pub symbol: String,

    /// Priority (higher = preferred), used for selecting between multiple options
    pub priority: i32,

    /// Token contract address (for ERC-20, SPL tokens, etc.)
    /// Use "native" for native network currency
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_address: Option<String>,

    /// Number of decimals for this token (e.g., 6 for USDC, 18 for ETH)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u8>,

    /// USD price per token (for cost estimation and display)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usd_price: Option<f64>,
}

/// Stripe payment method configuration for MPP card payments.
///
/// Stored in `x402-proxy.json` alongside wallet/network config so that
/// the MPP proxy can automatically fulfil `card` challenges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripePaymentMethodConfig {
    /// Stripe PaymentMethod identifier (e.g. "pm_1234...")
    pub payment_method_id: String,

    /// Currencies this PM supports (lowercase, e.g. ["usd", "eur"])
    pub currencies: Vec<String>,

    /// Priority (higher = preferred), same semantics as SymbolConfig
    #[serde(default)]
    pub priority: i32,

    /// Human-readable label (e.g. "Visa ending 4242")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl X402ProxyConfig {
    /// Load configuration from file
    #[allow(dead_code)]
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        info!("Loading X402 Proxy configuration from: {}", path.display());

        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read X402 Proxy config file: {}", path.display()))?;

        let config: X402ProxyConfig = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse X402 Proxy config file: {}", path.display()))?;

        info!("Loaded {} networks and {} wallets", config.networks.len(), config.wallets.len());

        Ok(config)
    }
}

/// Load X402 Proxy configuration from bootstrap config.
///
/// Reads `x402-proxy.json` from the configured path.
pub fn load_x402_proxy_config(bootstrap_config: &crate::config::BootstrapConfig) -> Result<X402ProxyConfig> {
    let config_path: &String = &bootstrap_config
        .config_files
        .x402_proxy;
    X402ProxyConfig::from_file(config_path)
}
