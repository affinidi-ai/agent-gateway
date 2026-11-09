//! MPP protocol types
//!
//! Types for the Machine Payments Protocol (MPP), following the IETF
//! draft-httpauth-payment-00 specification.

use crate::observability::loggable;
use serde::{Deserialize, Serialize};

/// Verification mode for crypto payment proofs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MppVerificationMode {
    /// Accept any proof as-is (testing / trust-the-client)
    #[default]
    Passthrough,

    /// Verify on-chain: fetch tx receipt via RPC, check status + amount + recipient
    Onchain,

    /// Signature-only: verify EIP-3009 / Permit2 EIP-712 signatures offline (no RPC)
    Signature,

    /// Both: try signature verification first, then on-chain receipt check
    Full,
}

/// MPP payment method configuration for a channel.
/// Each method represents one way the server can accept payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MppPaymentMethod {
    /// Payment method identifier (lowercase ASCII), e.g. "tempo", "card", "lightning"
    pub method: String,

    /// Payment intent type, e.g. "charge"
    pub intent: String,

    /// Currency / token identifier (e.g. token contract address or currency code)
    pub currency: String,

    /// Recipient address or account identifier
    pub recipient: String,

    /// Default amount to charge (human-readable, e.g. "0.01")
    pub amount: String,

    /// Optional blockchain network (for crypto methods)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
}

/// MPP channel configuration (stored in `mpp_policy` on a channel)
#[derive(Clone, Serialize, Deserialize)]
pub struct MppConfig {
    /// Whether MPP payments are required for this channel
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Protection space (realm) — typically the domain or service name
    pub realm: String,

    /// HMAC-SHA256 secret key for stateless challenge binding (base64-encoded)
    /// Can be an environment variable reference (e.g. "$MPP_SECRET_KEY")
    pub secret_key: String,

    /// Stripe secret API key for server-side payment verification (card methods).
    /// Can be an environment variable reference (e.g. "$STRIPE_SECRET_KEY").
    /// Required when `payment_methods` includes `method: "card"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stripe_secret_key: Option<String>,

    /// Payment methods offered by this endpoint
    #[serde(default)]
    pub payment_methods: Vec<MppPaymentMethod>,

    /// Challenge TTL in seconds (how long a challenge is valid)
    #[serde(default = "default_challenge_ttl")]
    pub challenge_ttl_seconds: u64,

    /// MCP payment trigger mode (regex-based). See
    /// [`crate::config::types::McpPaymentTriggers`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_payment_triggers: Option<crate::config::types::McpPaymentTriggers>,

    /// For A2A/AP2: structured method filters with optional message content regex
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a2a_method_filters: Option<Vec<crate::config::types::A2AMethodFilter>>,

    /// Verification timeout in milliseconds
    #[serde(default = "default_verification_timeout")]
    pub verification_timeout_ms: u64,

    /// Verification mode for crypto payment proofs (tempo/evm/crypto methods).
    /// Default: passthrough (accept proofs without checking chain).
    #[serde(default)]
    pub crypto_verification_mode: MppVerificationMode,

    /// RPC endpoints keyed by CAIP-2 network identifier
    /// e.g. `{"eip155:8453": "https://mainnet.base.org"}`
    #[serde(default)]
    pub rpc_endpoints: std::collections::HashMap<String, String>,

    /// Minimum block confirmations for on-chain verification
    #[serde(default)]
    pub min_confirmations: u64,
}

fn default_challenge_ttl() -> u64 {
    300 // 5 minutes
}

fn default_verification_timeout() -> u64 {
    10000 // 10 seconds
}

fn default_true() -> bool {
    true
}

impl Default for MppConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            realm: String::new(),
            secret_key: String::new(),
            stripe_secret_key: None,
            payment_methods: vec![],
            challenge_ttl_seconds: default_challenge_ttl(),
            mcp_payment_triggers: None,
            a2a_method_filters: None,
            verification_timeout_ms: default_verification_timeout(),
            crypto_verification_mode: MppVerificationMode::default(),
            rpc_endpoints: std::collections::HashMap::new(),
            min_confirmations: 0,
        }
    }
}

impl std::fmt::Debug for MppConfig {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        let rpc_endpoint_origins: std::collections::BTreeMap<&str, String> = self
            .rpc_endpoints
            .iter()
            .map(|(network, url)| (network.as_str(), loggable::origin(url)))
            .collect();
        f.debug_struct("MppConfig")
            .field("enabled", &self.enabled)
            .field("realm", &self.realm)
            .field("secret_key", &loggable::REDACTED)
            .field(
                "stripe_secret_key",
                &self
                    .stripe_secret_key
                    .as_ref()
                    .map(|_| loggable::REDACTED),
            )
            .field("payment_methods", &self.payment_methods)
            .field("challenge_ttl_seconds", &self.challenge_ttl_seconds)
            .field("mcp_payment_triggers", &self.mcp_payment_triggers)
            .field("a2a_method_filters", &self.a2a_method_filters)
            .field("verification_timeout_ms", &self.verification_timeout_ms)
            .field("crypto_verification_mode", &self.crypto_verification_mode)
            .field("rpc_endpoints", &rpc_endpoint_origins)
            .field("min_confirmations", &self.min_confirmations)
            .finish()
    }
}

/// A single MPP challenge as issued in a `WWW-Authenticate: Payment` header.
///
/// Per the spec, the challenge uses auth-param syntax with these fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MppChallenge {
    /// Challenge identifier (HMAC-SHA256 binding of all parameters)
    pub id: String,

    /// Protection space
    pub realm: String,

    /// Payment method identifier (lowercase)
    pub method: String,

    /// Payment intent type (e.g. "charge")
    pub intent: String,

    /// Base64url-encoded JCS-serialized JSON with payment-method-specific data
    pub request: String,

    /// Challenge expiration timestamp (RFC 3339)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    /// Content digest of request body per RFC 9530
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,

    /// Human-readable description (display only, not for verification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Server-defined correlation data (base64url JCS JSON)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opaque: Option<String>,
}

/// An MPP credential sent by the client in `Authorization: Payment <base64url>`.
///
/// The decoded JSON structure per the spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MppCredential {
    /// Echoed challenge parameters
    pub challenge: MppChallengeEcho,

    /// Optional payer identifier (RECOMMENDED: DID format)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// Method-specific payment proof
    pub payload: serde_json::Value,
}

/// The `challenge` object echoed back in the credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MppChallengeEcho {
    /// Challenge identifier
    pub id: String,

    /// Protection space
    pub realm: String,

    /// Payment method identifier
    pub method: String,

    /// Payment intent type
    pub intent: String,

    /// Base64url-encoded payment request (echoed from challenge)
    pub request: String,

    /// Challenge expiration (if present in original challenge)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    /// Content digest (if present in original challenge)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,

    /// Description (if present in original challenge)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Opaque correlation data (if present in original challenge)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opaque: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpp_config_defaults() {
        let config = MppConfig::default();
        assert!(config.enabled);
        assert_eq!(config.challenge_ttl_seconds, 300);
        assert_eq!(config.verification_timeout_ms, 10000);
        assert!(
            config
                .payment_methods
                .is_empty()
        );
    }

    #[test]
    fn test_mpp_config_deserialize() {
        let json = r#"{
            "enabled": true,
            "realm": "api.example.com",
            "secret_key": "dGVzdA==",
            "payment_methods": [
                {
                    "method": "tempo",
                    "intent": "charge",
                    "currency": "0x20c0000000000000000000000000000000000000",
                    "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00",
                    "amount": "0.01",
                    "network": "tempo"
                }
            ],
            "challenge_ttl_seconds": 600,
            "mcp_payment_triggers": {"mode": "match", "patterns": ["^expensive_tool$"]}
        }"#;

        let config: MppConfig = serde_json::from_str(json).unwrap();
        assert!(config.enabled);
        assert_eq!(config.realm, "api.example.com");
        assert_eq!(config.payment_methods.len(), 1);
        assert_eq!(config.payment_methods[0].method, "tempo");
        assert_eq!(config.challenge_ttl_seconds, 600);
        match config
            .mcp_payment_triggers
            .as_ref()
            .unwrap()
        {
            crate::config::types::McpPaymentTriggers::Match { patterns } => {
                assert_eq!(patterns, &vec!["^expensive_tool$".to_string()]);
            }
            other => panic!("expected Match mode, got {other:?}"),
        }
    }

    #[test]
    fn test_mpp_credential_deserialize() {
        let json = r#"{
            "challenge": {
                "id": "test-challenge-0001",
                "realm": "api.example.com",
                "method": "tempo",
                "intent": "charge",
                "request": "eyJhbW91bnQiOiIwLjAxIiwiY3VycmVuY3kiOiJ1c2QiLCJyZWNpcGllbnQiOiIweGFiYyJ9",
                "expires": "2026-03-27T12:05:00Z"
            },
            "source": "did:key:z6ExampleKeyId000001",
            "payload": {
                "proof": "0xabc123"
            }
        }"#;

        let credential: MppCredential = serde_json::from_str(json).unwrap();
        assert_eq!(credential.challenge.id, "test-challenge-0001");
        assert_eq!(credential.challenge.method, "tempo");
        assert_eq!(credential.source.unwrap(), "did:key:z6ExampleKeyId000001");
    }

    #[test]
    fn test_mpp_config_debug_redacts_secret_keys_and_rpc_paths() {
        let config = MppConfig {
            realm: "api.example.com".to_string(),
            secret_key: "bXBwLWhtYWMtc2VjcmV0LWtleQ==".to_string(),
            stripe_secret_key: Some("stripe-secret-marker".to_string()),
            rpc_endpoints: std::collections::HashMap::from([(
                "eip155:8453".to_string(),
                "https://base-mainnet.example.com/v2/rpc-provider-key".to_string(),
            )]),
            ..Default::default()
        };

        let rendered = format!("{config:?}");

        assert!(!rendered.contains("bXBwLWhtYWMtc2VjcmV0LWtleQ=="), "{rendered}");
        assert!(!rendered.contains("stripe-secret-marker"), "{rendered}");
        assert!(!rendered.contains("rpc-provider-key"), "{rendered}");
        assert!(rendered.contains("secret_key: \"<redacted>\""), "{rendered}");
        assert!(rendered.contains("stripe_secret_key: Some(\"<redacted>\")"), "{rendered}");
        assert!(rendered.contains("\"eip155:8453\": \"https://base-mainnet.example.com\""), "{rendered}");
        assert!(rendered.contains("realm: \"api.example.com\""), "{rendered}");
    }

    #[test]
    fn test_mpp_config_debug_shows_absent_stripe_key_as_none() {
        let rendered = format!("{:?}", MppConfig::default());

        assert!(rendered.contains("stripe_secret_key: None"), "{rendered}");
    }
}
