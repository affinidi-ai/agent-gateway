//! Shared identity hash computation utilities
//!
//! This module provides canonical hash computation for agent identities.
//! The same hash algorithm is used by:
//! - `IdentitySelector` for A2A/outbound channel identity extraction
//! - `onboard` handler for agent self-registration
//!
//! This ensures consistent identity hashing across both flows.

use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Compute canonical identity hash from a map of field paths to values.
///
/// The hash is computed as follows:
/// 1. Convert all values to strings
/// 2. Sort entries alphabetically by key (field path)
/// 3. Format as `key1=value1|key2=value2|...`
/// 4. Compute SHA256 hash of the resulting string
///
/// # Arguments
/// * `fields` - Map of field paths (dot notation) to JSON values
///
/// # Returns
/// * Hex-encoded SHA256 hash string
///
/// # Example
/// ```ignore
/// let mut fields = HashMap::new();
/// fields.insert("agentIdentity.role".to_string(), json!("merchant"));
/// fields.insert("agentIdentity.merchantInfo.name".to_string(), json!("Test Merchant"));
///
/// let hash = compute_canonical_identity_hash(&fields);
/// // Hash of: "agentIdentity.merchantInfo.name=Test Merchant|agentIdentity.role=merchant"
/// ```
pub fn compute_canonical_identity_hash(fields: &HashMap<String, serde_json::Value>) -> String {
    // Convert values to strings and collect as tuples
    let mut identity_values: Vec<(String, String)> = fields
        .iter()
        .map(|(path, value)| {
            let value_str = value_to_string(value);
            (path.clone(), value_str)
        })
        .collect();

    // Sort by field path to ensure deterministic ordering
    identity_values.sort_by(|a, b| a.0.cmp(&b.0));

    // Create canonical string representation: "field1=value1|field2=value2|..."
    let identity_string = identity_values
        .iter()
        .map(|(path, value)| format!("{}={}", path, value))
        .collect::<Vec<_>>()
        .join("|");

    // Compute SHA256 hash
    let mut hasher = Sha256::new();
    hasher.update(identity_string.as_bytes());
    let hash = hasher.finalize();

    format!("{:x}", hash)
}

/// Convert a JSON value to its string representation for hashing.
///
/// - Strings are returned as-is
/// - Numbers and booleans are converted to string representation
/// - Other types (arrays, objects, null) use JSON serialization
fn value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::f32::consts::PI;

    use super::*;
    use serde_json::json;

    #[test]
    fn test_compute_canonical_identity_hash_basic() {
        let mut fields = HashMap::new();
        fields.insert("agentIdentity.role".to_string(), json!("merchant"));

        let hash = compute_canonical_identity_hash(&fields);

        // Hash should be deterministic
        let hash2 = compute_canonical_identity_hash(&fields);
        assert_eq!(hash, hash2);

        // Hash should be 64 hex characters (SHA256)
        assert_eq!(hash.len(), 64);
        assert!(
            hash.chars()
                .all(|c| c.is_ascii_hexdigit())
        );
    }

    #[test]
    fn test_compute_canonical_identity_hash_sorted_order() {
        // Fields added in different order should produce same hash
        let mut fields1 = HashMap::new();
        fields1.insert("z.field".to_string(), json!("last"));
        fields1.insert("a.field".to_string(), json!("first"));

        let mut fields2 = HashMap::new();
        fields2.insert("a.field".to_string(), json!("first"));
        fields2.insert("z.field".to_string(), json!("last"));

        assert_eq!(compute_canonical_identity_hash(&fields1), compute_canonical_identity_hash(&fields2));
    }

    #[test]
    fn test_compute_canonical_identity_hash_different_types() {
        let mut fields = HashMap::new();
        fields.insert("string_field".to_string(), json!("text"));
        fields.insert("number_field".to_string(), json!(42));
        fields.insert("bool_field".to_string(), json!(true));

        let hash = compute_canonical_identity_hash(&fields);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_compute_canonical_identity_hash_empty() {
        let fields: HashMap<String, serde_json::Value> = HashMap::new();
        let hash = compute_canonical_identity_hash(&fields);

        // Empty input should still produce a valid hash
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_value_to_string() {
        assert_eq!(value_to_string(&json!("hello")), "hello");
        assert_eq!(value_to_string(&json!(42)), "42");
        assert_eq!(value_to_string(&json!(true)), "true");
        assert_eq!(value_to_string(&json!(false)), "false");
        assert_eq!(value_to_string(&json!(PI)), "3.1415927");
        assert_eq!(value_to_string(&json!(3.12)), "3.12");
    }
}
