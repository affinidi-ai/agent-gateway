//! PII redaction for storage export
//!
//! Provides JSON field-level redaction and regex-based text redaction
//! to remove personally identifiable information before export.

use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

/// Directories excluded entirely from export (contain key material / auth credentials)
pub const EXCLUDED_DIRS: &[&str] =
    &["identities", "secrets", "vc_keys", "passkeys", "apikeys", "certificates", "sessions", "avatars"];

/// JSON keys whose values are DIDs — replaced with `did:redacted:{hash8}`
const DID_KEYS: &[&str] = &[
    "did",
    "our_did",
    "their_did",
    "mediator_did",
    "identity_did",
    "connection_point_did",
    "our_temporary_did",
    "our_secure_did",
    "their_temporary_did",
    "their_secure_did",
];

/// JSON keys whose values are direct PII — replaced with `[REDACTED]`
const PII_KEYS: &[&str] = &["username", "user_id", "first_name", "last_name", "saml_id"];

/// JSON keys whose values are auth/secret material — replaced with `[REDACTED-SECRET]`
const SECRET_KEYS: &[&str] = &[
    "token",
    "session_id",
    "access_token",
    "secret",
    "secret_id",
    "api_key",
    "api_key_secret_id",
    "auth_header",
    "password",
    "private_key",
    "private_key_pem",
    "oob_message",
    "oob_url",
    "challenge",
    "token_secret_id",
];

/// JSON keys whose values are wallet/financial PII — replaced with `[REDACTED-WALLET]`
const WALLET_KEYS: &[&str] = &["pay_to", "from_address", "tx_hash"];

/// JSON keys whose entire subtree values should be deep-redacted
/// (all string values replaced, because content is free-form and may contain credentials)
const DEEP_REDACT_KEYS: &[&str] = &["configuration"];

static EMAIL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").unwrap());

static IPV4_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap());

static DID_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"did:[a-z]+:[A-Za-z0-9._:%-]+").unwrap());

/// Returns true if the given directory name should be excluded from export.
pub fn is_excluded_dir(dir_name: &str) -> bool {
    EXCLUDED_DIRS.contains(&dir_name)
}

/// Produce a short correlation-safe hash of a DID value.
/// Returns first 8 hex chars of SHA-256, allowing cross-reference in the export
/// without revealing the actual DID.
fn did_hash(did: &str) -> String {
    let hash = Sha256::digest(did.as_bytes());
    format!("did:redacted:{}", hex::encode(&hash[..4]))
}

/// Redact a DID string value, preserving correlation via hash.
fn redact_did(value: &str) -> String {
    if value.starts_with("did:") {
        did_hash(value)
    } else {
        value.to_string()
    }
}

/// Check if a string value looks like an email address.
fn is_email(value: &str) -> bool {
    EMAIL_RE.is_match(value)
}

/// Recursively redact PII from a JSON value based on key names.
pub fn redact_json(value: &mut Value) {
    redact_json_inner(value, false);
}

fn redact_json_inner(
    value: &mut Value,
    deep_redact: bool,
) {
    match value {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                let key_lower = key.to_lowercase();
                if let Some(val) = map.get_mut(&key) {
                    if DEEP_REDACT_KEYS.contains(&key_lower.as_str()) {
                        // Deep-redact: replace all string values in this subtree
                        deep_redact_strings(val);
                    } else if DID_KEYS.contains(&key_lower.as_str()) {
                        if let Value::String(s) = val {
                            *s = redact_did(s);
                        }
                    } else if PII_KEYS.contains(&key_lower.as_str()) {
                        if let Value::String(s) = val
                            && !s.is_empty()
                        {
                            *s = "[REDACTED]".to_string();
                        }
                    } else if SECRET_KEYS.contains(&key_lower.as_str()) {
                        if let Value::String(s) = val
                            && !s.is_empty()
                        {
                            *s = "[REDACTED-SECRET]".to_string();
                        }
                    } else if WALLET_KEYS.contains(&key_lower.as_str()) {
                        if let Value::String(s) = val
                            && !s.is_empty()
                        {
                            *s = "[REDACTED-WALLET]".to_string();
                        }
                    } else if key_lower == "email" {
                        if let Value::String(s) = val
                            && !s.is_empty()
                        {
                            *s = "[REDACTED-EMAIL]".to_string();
                        }
                    } else if deep_redact {
                        deep_redact_strings(val);
                    } else {
                        // Check if string value looks like a DID or email even under unknown keys
                        if let Value::String(s) = val {
                            if s.starts_with("did:") && s.len() > 10 {
                                *s = did_hash(s);
                            } else if is_email(s) {
                                *s = "[REDACTED-EMAIL]".to_string();
                            }
                        } else {
                            redact_json_inner(val, false);
                        }
                    }
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_json_inner(item, deep_redact);
            }
        }
        _ => {}
    }
}

/// Replace all string values in a JSON subtree with `[REDACTED-CONFIG]`.
/// Used for free-form configuration blocks that may contain credentials.
fn deep_redact_strings(value: &mut Value) {
    match value {
        Value::String(s) if !s.is_empty() => {
            *s = "[REDACTED-CONFIG]".to_string();
        }
        Value::Object(map) => {
            for val in map.values_mut() {
                deep_redact_strings(val);
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                deep_redact_strings(item);
            }
        }
        _ => {} // numbers, bools, nulls are safe
    }
}

/// Redact PII patterns in plain text content (logs, config files).
pub fn redact_text(content: &str) -> String {
    let result = EMAIL_RE.replace_all(content, "[REDACTED-EMAIL]");
    let result = DID_RE.replace_all(&result, "did:redacted:***");
    let result = IPV4_RE.replace_all(&result, "[REDACTED-IP]");
    result.into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_excluded_dirs() {
        assert!(is_excluded_dir("identities"));
        assert!(is_excluded_dir("secrets"));
        assert!(is_excluded_dir("avatars"));
        assert!(!is_excluded_dir("channels"));
        assert!(!is_excluded_dir("metrics"));
    }

    #[test]
    fn test_did_hash_consistency() {
        let hash1 = did_hash("did:peer:abc123");
        let hash2 = did_hash("did:peer:abc123");
        assert_eq!(hash1, hash2, "same DID should produce same hash");
        assert!(hash1.starts_with("did:redacted:"));
        assert_eq!(hash1.len(), "did:redacted:".len() + 8);
    }

    #[test]
    fn test_did_hash_different_dids() {
        let hash1 = did_hash("did:peer:abc123");
        let hash2 = did_hash("did:peer:xyz789");
        assert_ne!(hash1, hash2, "different DIDs should produce different hashes");
    }

    #[test]
    fn test_redact_json_session() {
        let mut val = json!({
            "token": "secret-session-token",
            "username": "alice",
            "user_id": "u-123",
            "created_at": "2025-01-01T00:00:00Z",
            "expires_at": "2025-01-02T00:00:00Z"
        });
        redact_json(&mut val);
        assert_eq!(val["token"], "[REDACTED-SECRET]");
        assert_eq!(val["username"], "[REDACTED]");
        assert_eq!(val["user_id"], "[REDACTED]");
        assert_eq!(val["created_at"], "2025-01-01T00:00:00Z");
    }

    #[test]
    fn test_redact_json_gateway() {
        let mut val = json!({
            "name": "my-gateway",
            "description": "Test gateway",
            "did": "did:peer:2.Ez6LSkGy4e7xNAREqtBPSmUu2Ni4GcmPBkJHbaSqcjgCcw.Vz6Mkud87w",
            "exposed_channels": ["ch-1", "ch-2"]
        });
        redact_json(&mut val);
        assert!(
            val["did"]
                .as_str()
                .unwrap()
                .starts_with("did:redacted:")
        );
        assert_eq!(val["name"], "my-gateway"); // config name preserved
    }

    #[test]
    fn test_redact_json_x402_transaction() {
        let mut val = json!({
            "correlation_id": "corr-123",
            "settlement": {
                "tx_hash": "0xabcdef1234567890",
                "pay_to": "0xWalletAddress123",
                "from_address": "0xSenderAddress456",
                "amount": "1.5",
                "network": "base-mainnet"
            }
        });
        redact_json(&mut val);
        assert_eq!(val["settlement"]["tx_hash"], "[REDACTED-WALLET]");
        assert_eq!(val["settlement"]["pay_to"], "[REDACTED-WALLET]");
        assert_eq!(val["settlement"]["from_address"], "[REDACTED-WALLET]");
        assert_eq!(val["settlement"]["amount"], "1.5"); // amount preserved
    }

    #[test]
    fn test_redact_json_integration_configuration() {
        let mut val = json!({
            "name": "email-notifier",
            "configuration": {
                "smtp_host": "smtp.example.com",
                "smtp_user": "admin@example.com",
                "smtp_password": "hunter2",
                "port": 587
            },
            "content": {
                "subject": "Alert",
                "body": "Hello"
            }
        });
        redact_json(&mut val);
        assert_eq!(val["configuration"]["smtp_host"], "[REDACTED-CONFIG]");
        assert_eq!(val["configuration"]["smtp_password"], "[REDACTED-CONFIG]");
        assert_eq!(val["configuration"]["port"], 587); // numbers preserved
        assert_eq!(val["name"], "email-notifier"); // name outside config preserved
    }

    #[test]
    fn test_redact_json_connection_with_dids() {
        let mut val = json!({
            "our_temporary_did": "did:key:z6Mk123",
            "our_secure_did": "did:peer:2.abc",
            "their_temporary_did": "did:key:z6Mk456",
            "their_secure_did": "did:peer:2.xyz",
            "mediator_did": "did:web:mediator.example.com",
            "invitation_id": "inv-001"
        });
        redact_json(&mut val);
        for key in ["our_temporary_did", "our_secure_did", "their_temporary_did", "their_secure_did", "mediator_did"] {
            assert!(
                val[key]
                    .as_str()
                    .unwrap()
                    .starts_with("did:redacted:"),
                "key {key} not redacted"
            );
        }
        assert_eq!(val["invitation_id"], "inv-001");
    }

    #[test]
    fn test_redact_json_email_in_value() {
        let mut val = json!({
            "notification_to": "user@example.com",
            "count": 5
        });
        redact_json(&mut val);
        assert_eq!(val["notification_to"], "[REDACTED-EMAIL]");
        assert_eq!(val["count"], 5);
    }

    #[test]
    fn test_redact_json_empty_values_unchanged() {
        let mut val = json!({
            "token": "",
            "username": "",
            "email": ""
        });
        redact_json(&mut val);
        assert_eq!(val["token"], "");
        assert_eq!(val["username"], "");
        assert_eq!(val["email"], "");
    }

    #[test]
    fn test_redact_text_emails() {
        let input = "Sending to user@example.com and admin@test.org";
        let result = redact_text(input);
        assert!(!result.contains("user@example.com"));
        assert!(!result.contains("admin@test.org"));
        assert!(result.contains("[REDACTED-EMAIL]"));
    }

    #[test]
    fn test_redact_text_ips() {
        let input = "Connection from 192.168.1.100 to 10.0.0.1";
        let result = redact_text(input);
        assert!(!result.contains("192.168.1.100"));
        assert!(!result.contains("10.0.0.1"));
        assert!(result.contains("[REDACTED-IP]"));
    }

    #[test]
    fn test_redact_text_dids() {
        let input = "Resolved did:peer:2.Ez6LSk from did:web:example.com";
        let result = redact_text(input);
        assert!(!result.contains("did:peer:2.Ez6LSk"));
        assert!(!result.contains("did:web:example.com"));
        assert!(result.contains("did:redacted:***"));
    }

    #[test]
    fn test_redact_text_mixed() {
        let input = "2025-03-18 10:00:00 [INFO] User admin@corp.com from 10.1.2.3 resolved did:key:z6Mk12345";
        let result = redact_text(input);
        assert!(result.contains("2025-03-18 10:00:00 [INFO]"));
        assert!(!result.contains("admin@corp.com"));
        assert!(!result.contains("10.1.2.3"));
        assert!(!result.contains("did:key:z6Mk12345"));
    }
}
