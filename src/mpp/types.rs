//! MPP protocol types
//!
//! Types for the Machine Payments Protocol (MPP), following the IETF
//! draft-httpauth-payment-00 specification.

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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl MppConfig {
    /// Validate the MPP configuration and return warnings for likely misconfigurations.
    /// Called at config load time to surface problems early.
    pub fn validate(
        &self,
        channel_name: &str,
    ) -> Vec<String> {
        let mut warnings = Vec::new();

        if !self.enabled {
            return warnings;
        }

        // Check secret key is present
        if self.secret_key.is_empty() {
            warnings.push(format!(
                "[mpp] Channel '{}': secret_key is empty — challenge HMAC binding will fail",
                channel_name
            ));
        }

        // Check at least one payment method is configured
        if self
            .payment_methods
            .is_empty()
        {
            warnings.push(format!(
                "[mpp] Channel '{}': no payment_methods configured — 402 challenges will have empty methods",
                channel_name
            ));
        }

        // Check crypto verification mode requires rpc_endpoints
        let has_crypto_methods = self
            .payment_methods
            .iter()
            .any(|m| {
                let method = m.method.to_lowercase();
                method == "tempo" || method == "crypto" || method == "evm" || method == "eip3009" || method == "permit2"
            });

        if has_crypto_methods
            && matches!(self.crypto_verification_mode, MppVerificationMode::Onchain | MppVerificationMode::Full)
            && self.rpc_endpoints.is_empty()
        {
            warnings.push(format!(
                "[mpp] Channel '{}': crypto_verification_mode is {:?} but rpc_endpoints is empty — on-chain verification will fail",
                channel_name, self.crypto_verification_mode
            ));
        }

        // Check card methods require stripe_secret_key
        let has_card_methods = self
            .payment_methods
            .iter()
            .any(|m| m.method.to_lowercase() == "card");
        if has_card_methods
            && self
                .stripe_secret_key
                .is_none()
        {
            warnings.push(format!(
                "[mpp] Channel '{}': payment_methods includes 'card' but stripe_secret_key is not set",
                channel_name
            ));
        }

        // Check realm is set
        if self.realm.is_empty() {
            warnings.push(format!(
                "[mpp] Channel '{}': realm is empty — challenges will have an empty protection space",
                channel_name
            ));
        }

        warnings
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

/// Payment request data encoded in the `request` parameter.
/// This is the decoded content of the base64url `request` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MppPaymentRequest {
    /// Amount to charge (human-readable string)
    pub amount: String,

    /// Currency identifier
    pub currency: String,

    /// Recipient address or account
    pub recipient: String,

    /// Optional additional method-specific details
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
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

/// Payment receipt returned in the `Payment-Receipt` header on success.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MppReceipt {
    /// Always "success" (receipts only issued on successful payment)
    pub status: String,

    /// Payment method used
    pub method: String,

    /// RFC 3339 settlement timestamp
    pub timestamp: String,

    /// Method-specific reference (tx hash, invoice id, etc.)
    pub reference: String,
}

/// RFC 9457 Problem Details for error responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MppProblemDetails {
    /// Problem type URI
    #[serde(rename = "type")]
    pub problem_type: String,

    /// Short human-readable summary
    pub title: String,

    /// HTTP status code
    pub status: u16,

    /// Human-readable explanation
    pub detail: String,

    /// Challenge ID (for correlation)
    #[serde(rename = "challengeId", skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
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
    fn test_mpp_receipt_serialize() {
        let receipt = MppReceipt {
            status: "success".to_string(),
            method: "tempo".to_string(),
            timestamp: "2026-03-27T12:00:00Z".to_string(),
            reference: "0xdeadbeef".to_string(),
        };

        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("\"status\":\"success\""));
        assert!(json.contains("\"method\":\"tempo\""));
    }

    #[test]
    fn test_mpp_problem_details_serialize() {
        let problem = MppProblemDetails {
            problem_type: "https://paymentauth.org/problems/payment-required".to_string(),
            title: "Payment Required".to_string(),
            status: 402,
            detail: "Payment is required.".to_string(),
            challenge_id: Some("abc123".to_string()),
        };

        let json = serde_json::to_string(&problem).unwrap();
        assert!(json.contains("\"type\":\"https://paymentauth.org/problems/payment-required\""));
        assert!(json.contains("\"challengeId\":\"abc123\""));
    }

    #[test]
    fn test_validate_disabled_config_no_warnings() {
        let config = MppConfig {
            enabled: false,
            ..Default::default()
        };
        let warnings = config.validate("test-channel");
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_validate_empty_secret_key_warns() {
        let config = MppConfig {
            enabled: true,
            realm: "test.example.com".to_string(),
            secret_key: String::new(),
            ..Default::default()
        };
        let warnings = config.validate("test-channel");
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("secret_key is empty"))
        );
    }

    #[test]
    fn test_validate_no_payment_methods_warns() {
        let config = MppConfig {
            enabled: true,
            realm: "test.example.com".to_string(),
            secret_key: "dGVzdA==".to_string(),
            payment_methods: vec![],
            ..Default::default()
        };
        let warnings = config.validate("test-channel");
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("no payment_methods"))
        );
    }

    #[test]
    fn test_validate_onchain_without_rpc_warns() {
        let config = MppConfig {
            enabled: true,
            realm: "test.example.com".to_string(),
            secret_key: "dGVzdA==".to_string(),
            payment_methods: vec![MppPaymentMethod {
                method: "tempo".to_string(),
                intent: "charge".to_string(),
                currency: "usd".to_string(),
                recipient: "0xabc".to_string(),
                amount: "1.00".to_string(),
                network: None,
            }],
            crypto_verification_mode: MppVerificationMode::Onchain,
            rpc_endpoints: std::collections::HashMap::new(),
            ..Default::default()
        };
        let warnings = config.validate("test-channel");
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("rpc_endpoints is empty"))
        );
    }

    #[test]
    fn test_validate_card_without_stripe_warns() {
        let config = MppConfig {
            enabled: true,
            realm: "test.example.com".to_string(),
            secret_key: "dGVzdA==".to_string(),
            payment_methods: vec![MppPaymentMethod {
                method: "card".to_string(),
                intent: "charge".to_string(),
                currency: "usd".to_string(),
                recipient: "acct_123".to_string(),
                amount: "5.00".to_string(),
                network: None,
            }],
            stripe_secret_key: None,
            ..Default::default()
        };
        let warnings = config.validate("test-channel");
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("stripe_secret_key"))
        );
    }

    #[test]
    fn test_validate_empty_realm_warns() {
        let config = MppConfig {
            enabled: true,
            realm: String::new(),
            secret_key: "dGVzdA==".to_string(),
            ..Default::default()
        };
        let warnings = config.validate("test-channel");
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("realm is empty"))
        );
    }

    #[test]
    fn test_validate_well_configured_no_warnings() {
        let config = MppConfig {
            enabled: true,
            realm: "api.example.com".to_string(),
            secret_key: "dGVzdA==".to_string(),
            stripe_secret_key: None,
            payment_methods: vec![MppPaymentMethod {
                method: "tempo".to_string(),
                intent: "charge".to_string(),
                currency: "usd".to_string(),
                recipient: "0xabc".to_string(),
                amount: "0.01".to_string(),
                network: Some("eip155:8453".to_string()),
            }],
            crypto_verification_mode: MppVerificationMode::Passthrough,
            rpc_endpoints: std::collections::HashMap::new(),
            ..Default::default()
        };
        let warnings = config.validate("test-channel");
        assert!(warnings.is_empty());
    }
}
