use anyhow::{Context, Result};
use jsonschema::Validator;
use serde_json::Value as JsonValue;
use std::sync::Arc;
use tracing::{debug, info};

use super::VCIssuer;
use super::filesystem::IdentityOrigin;
use super::identity_hash::compute_canonical_identity_hash;

/// Identity selector for extracting stable identity fields and computing deterministic hashes
pub struct IdentitySelector {
    /// Compiled JSON Schema validator for structural validation
    schema_validator: Validator,
    /// Field paths to extract for identity computation (marked with x-identity: true in schema)
    identity_fields: Vec<String>,
    /// VC issuer for generating DIDs
    vc_issuer: Arc<VCIssuer>,
}

/// Result of identity computation containing both SHA256 hash and DID
#[derive(Debug, Clone)]
pub struct IdentityResult {
    /// The SHA256 hash of the identity fields (internal use)
    #[allow(dead_code)]
    pub hash: String,
    /// The did:web identifier for the agent
    pub did: String,
    /// Whether this is a newly created identity
    pub is_new: bool,
    /// How the DID was established (see `IdentityVerification`).
    pub verification: crate::surface_context::IdentityVerification,
    /// The extracted x-identity fields (needed for VP creation on request path)
    pub identity_fields: std::collections::HashMap<String, JsonValue>,
    /// Issuer DID of the caller from agent-identity-credential VP
    pub issuer_did: Option<String>,
}

impl IdentitySelector {
    /// Create a new identity selector from JSON Schema
    /// The schema will be used to validate the payload structure
    /// Fields marked with "x-identity": true will be extracted for identity computation
    pub fn new(
        schema: &JsonValue,
        vc_issuer: Arc<VCIssuer>,
    ) -> Result<Self> {
        let schema_validator = Validator::options()
            .build(schema)
            .context("Failed to compile identity JSON schema")?;

        // Extract fields marked with x-identity: true
        let identity_fields = extract_identity_fields(schema, "");

        Ok(Self {
            schema_validator,
            identity_fields,
            vc_issuer,
        })
    }

    /// Check if this selector has any identity fields marked
    pub fn has_identity_fields(&self) -> bool {
        !self
            .identity_fields
            .is_empty()
    }

    /// Validate `payload` against the compiled JSON schema only.
    ///
    /// Returns `Err` when the payload does not conform to the schema.
    /// Use this when you need schema enforcement without also computing
    /// the identity hash (e.g. when identity hashing is skipped because
    /// the schema declares no `x-identity` fields, or when validation
    /// must be reported as a distinct pipeline step).
    pub fn validate(
        &self,
        payload: &JsonValue,
    ) -> Result<()> {
        let detail = format_schema_errors(&self.schema_validator, payload);
        if !detail.is_empty() {
            anyhow::bail!("payload does not conform to identity JSON schema: {}", detail);
        }
        Ok(())
    }

    /// Get a reference to the VC issuer
    pub fn get_vc_issuer(&self) -> Arc<VCIssuer> {
        Arc::clone(&self.vc_issuer)
    }

    /// Extract only the x-identity fields from a payload
    /// Returns a map of field path to value for all fields marked with x-identity: true
    pub fn extract_identity_fields(
        &self,
        payload: &JsonValue,
    ) -> std::collections::HashMap<String, JsonValue> {
        let mut fields = std::collections::HashMap::new();

        for field_path in &self.identity_fields {
            if let Some(value) = extract_field_value(payload, field_path) {
                fields.insert(field_path.clone(), value.clone());
            }
        }

        fields
    }

    /// Compute identity and return DID (preferred method)
    /// This validates the payload, computes the identity hash, and gets/creates a DID
    pub async fn compute_identity(
        &self,
        payload: &JsonValue,
        channel_name: &str,
        channel_config_id: Option<String>,
        issuer_id: Option<String>,
        origin: IdentityOrigin,
    ) -> Result<IdentityResult> {
        // Compute the SHA256 hash (validates schema and extracts identity fields)
        let hash = self.compute_identity_hash(payload, channel_name)?;

        // Extract only the x-identity fields for storage
        let identity_fields = self.extract_identity_fields(payload);

        // Use the VC issuer to get or create a DID for this identity
        // Pass the hash and extracted fields so we only store x-identity marked fields
        let fields = identity_fields.clone();
        let hash_arg = Some(hash.clone());
        let response = match origin {
            IdentityOrigin::Managed => {
                self.vc_issuer
                    .issue_or_get_managed_credential(fields, hash_arg, channel_config_id, issuer_id)
                    .await
            }
            IdentityOrigin::ExternalCaller => {
                self.vc_issuer
                    .issue_or_get_caller_credential(fields, hash_arg, channel_config_id, issuer_id)
                    .await
            }
        }
        .context("Failed to issue or retrieve DID for identity")?;

        info!(
            channel = channel_name,
            sha256 = %hash,
            did = %response.did,
            is_new = response.is_new,
            "Computed agent identity with DID"
        );

        Ok(IdentityResult {
            verification: crate::surface_context::IdentityVerification::Unverified,
            hash,
            did: response.did,
            is_new: response.is_new,
            identity_fields,
            issuer_did: None,
        })
    }

    /// Validate the payload conforms to the schema and extract identity hash
    /// Returns Ok(hash) if validation passes and identity can be computed
    /// Returns Err if validation fails or identity fields are missing
    pub fn compute_identity_hash(
        &self,
        payload: &JsonValue,
        channel_name: &str,
    ) -> Result<String> {
        // First, check if all identity fields exist (including parent paths)
        // We do this BEFORE schema validation so we can provide clear error messages
        // Users don't need to add x-identity fields to 'required' - we check them explicitly
        for field_path in &self.identity_fields {
            if extract_field_value(payload, field_path).is_none() {
                anyhow::bail!(
                    "Identity field '{}' (marked with x-identity: true) not found in payload. \
                     Ensure this field and all parent objects exist in the request.",
                    field_path
                );
            }
        }

        // Now validate against JSON Schema for other structural requirements
        let detail = format_schema_errors(&self.schema_validator, payload);
        if !detail.is_empty() {
            anyhow::bail!("Identity schema validation failed: {}", detail);
        }
        debug!(channel = channel_name, "Identity schema validation passed");

        // Extract identity fields into a HashMap for the shared hash computation
        let identity_fields = self.extract_identity_fields(payload);

        if identity_fields.is_empty() {
            anyhow::bail!("No identity fields could be extracted from payload");
        }

        // Use the shared canonical hash computation
        let hash_str = compute_canonical_identity_hash(&identity_fields);

        debug!(
            channel = channel_name,
            hash = %hash_str,
            field_count = identity_fields.len(),
            "Computed identity hash"
        );

        Ok(hash_str)
    }
}

/// Format every JSON Schema validation error against `payload` as a single
/// human-readable string. Returns an empty string when the payload is valid.
///
/// Each error entry includes the JSON Pointer to the offending instance
/// location (or `<root>`) and the validator's message, e.g.
/// `agentIdentity.provisioningInfo: "configFlags" is a required property`.
/// Capped at 10 entries to keep error responses bounded.
fn format_schema_errors(
    validator: &Validator,
    payload: &JsonValue,
) -> String {
    let mut entries: Vec<String> = validator
        .iter_errors(payload)
        .map(|e| {
            let path = e.instance_path().to_string();
            let location = if path.is_empty() {
                "<root>".to_string()
            } else {
                path.trim_start_matches('/')
                    .replace('/', ".")
            };
            format!("{}: {}", location, e)
        })
        .take(10)
        .collect();
    if entries.is_empty() {
        return String::new();
    }
    // Stable order so identical payloads produce identical messages
    entries.sort();
    entries.join("; ")
}

/// Extract field paths marked with x-identity: true from JSON Schema
/// Recursively traverses the schema and builds dot-notation paths
fn extract_identity_fields(
    schema: &JsonValue,
    current_path: &str,
) -> Vec<String> {
    let mut fields = Vec::new();

    if let Some(obj) = schema.as_object() {
        // Check if this field is marked as identity
        if let Some(x_identity) = obj.get("x-identity")
            && x_identity.as_bool() == Some(true)
            && !current_path.is_empty()
        {
            fields.push(current_path.to_string());
        }

        // Traverse properties if this is an object schema
        if let Some(properties) = obj
            .get("properties")
            .and_then(|p| p.as_object())
        {
            for (prop_name, prop_schema) in properties {
                let new_path = if current_path.is_empty() {
                    prop_name.clone()
                } else {
                    format!("{}.{}", current_path, prop_name)
                };
                fields.extend(extract_identity_fields(prop_schema, &new_path));
            }
        }
    }

    fields
}

/// Extract a field value from a JSON payload using a dot-notation path
/// Supports nested objects: "agentIdentity.provisioningInfo.cloudProvider"
fn extract_field_value<'a>(
    payload: &'a JsonValue,
    path: &str,
) -> Option<&'a JsonValue> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = payload;

    for part in parts {
        match current {
            JsonValue::Object(map) => {
                current = map.get(part)?;
            }
            _ => return None,
        }
    }

    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_field_value() {
        let payload = json!({
            "did": "did:example:123",
            "agentIdentity": {
                "provisioningInfo": {
                    "cloudProvider": "aws"
                }
            }
        });

        assert_eq!(extract_field_value(&payload, "did"), Some(&json!("did:example:123")));

        assert_eq!(extract_field_value(&payload, "agentIdentity.provisioningInfo.cloudProvider"), Some(&json!("aws")));

        assert_eq!(extract_field_value(&payload, "nonexistent"), None);
    }

    #[test]
    fn test_extract_identity_fields() {
        let schema = json!({
            "type": "object",
            "properties": {
                "did": {
                    "type": "string",
                    "x-identity": true
                },
                "agentId": {
                    "type": "string",
                    "x-identity": true
                },
                "timestamp": {
                    "type": "string"
                },
                "nested": {
                    "type": "object",
                    "properties": {
                        "value": {
                            "type": "string",
                            "x-identity": true
                        }
                    }
                }
            }
        });

        let fields = extract_identity_fields(&schema, "");
        assert_eq!(fields.len(), 3);
        assert!(fields.contains(&"did".to_string()));
        assert!(fields.contains(&"agentId".to_string()));
        assert!(fields.contains(&"nested.value".to_string()));
    }

    #[test]
    fn format_schema_errors_names_missing_required_field() {
        let schema = json!({
            "type": "object",
            "properties": {
                "agentIdentity": {
                    "type": "object",
                    "properties": {
                        "provisioningInfo": {
                            "type": "object",
                            "properties": {
                                "configFlags": { "type": "object" }
                            },
                            "required": ["configFlags"]
                        }
                    },
                    "required": ["provisioningInfo"]
                }
            }
        });
        let validator = Validator::options()
            .build(&schema)
            .unwrap();
        let payload = json!({ "agentIdentity": { "provisioningInfo": {} } });
        let detail = format_schema_errors(&validator, &payload);
        assert!(
            detail.contains("agentIdentity.provisioningInfo"),
            "detail should mention the failing path, got: {detail}"
        );
        assert!(detail.contains("configFlags"), "detail should name the missing field, got: {detail}");
    }

    #[test]
    fn format_schema_errors_empty_when_payload_valid() {
        let schema = json!({ "type": "object", "required": ["a"], "properties": { "a": { "type": "string" } } });
        let validator = Validator::options()
            .build(&schema)
            .unwrap();
        let payload = json!({ "a": "ok" });
        assert!(format_schema_errors(&validator, &payload).is_empty());
    }

    // Note: test_compute_identity_hash_deterministic() has been removed
    // because IdentitySelector now requires a VCIssuer parameter.
    // The compute_identity_hash method is still available and tested
    // indirectly through the compute_identity method.

    #[tokio::test]
    async fn validate_accepts_payload_conforming_to_schema() {
        let (vc_issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let schema = json!({
            "type": "object",
            "required": ["cloudProvider", "model"],
            "properties": {
                "cloudProvider": {"type": "string"},
                "model": {"type": "string"}
            },
            "additionalProperties": false
        });
        let selector = IdentitySelector::new(&schema, Arc::new(vc_issuer)).unwrap();
        let payload = json!({"cloudProvider": "aws", "model": "gpt-4"});
        assert!(
            selector
                .validate(&payload)
                .is_ok()
        );
    }

    #[tokio::test]
    async fn validate_rejects_payload_missing_required_field() {
        let (vc_issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let schema = json!({
            "type": "object",
            "required": ["cloudProvider", "model"],
            "properties": {
                "cloudProvider": {"type": "string"},
                "model": {"type": "string"}
            }
        });
        let selector = IdentitySelector::new(&schema, Arc::new(vc_issuer)).unwrap();
        let payload = json!({"cloudProvider": "aws"});
        let err = selector
            .validate(&payload)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("does not conform"),
            "unexpected error message: {err}"
        );
    }

    #[tokio::test]
    async fn validate_rejects_payload_with_wrong_field_type() {
        let (vc_issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let schema = json!({
            "type": "object",
            "properties": {
                "model": {"type": "string"}
            }
        });
        let selector = IdentitySelector::new(&schema, Arc::new(vc_issuer)).unwrap();
        let payload = json!({"model": 42});
        assert!(
            selector
                .validate(&payload)
                .is_err()
        );
    }

    async fn computed_origin(
        origin: IdentityOrigin,
        model: &str,
    ) -> Option<IdentityOrigin> {
        use crate::identity::store::IdentityStore;
        use crate::identity::test_helpers::{MockIdentityStore, MockVpChallengeStore};
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MockIdentityStore::new());
        let vc_issuer = VCIssuer::new(
            temp_dir.path(),
            "example.com",
            store.clone() as Arc<dyn IdentityStore>,
            Arc::new(MockVpChallengeStore::new()),
            None,
            None,
        )
        .await
        .unwrap();
        let schema = json!({
            "type": "object",
            "properties": { "model": { "type": "string", "x-identity": true } }
        });
        let selector = IdentitySelector::new(&schema, Arc::new(vc_issuer)).unwrap();

        let result = selector
            .compute_identity(&json!({ "model": model }), "surface-a", None, None, origin)
            .await
            .unwrap();

        store
            .find_by_hash(&result.hash)
            .await
            .unwrap()
            .and_then(|record| record.origin)
    }

    #[tokio::test]
    async fn compute_identity_records_managed_origin() {
        assert_eq!(computed_origin(IdentityOrigin::Managed, "agent-a").await, Some(IdentityOrigin::Managed));
    }

    #[tokio::test]
    async fn compute_identity_records_external_caller_origin() {
        assert_eq!(
            computed_origin(IdentityOrigin::ExternalCaller, "caller-b").await,
            Some(IdentityOrigin::ExternalCaller)
        );
    }

    #[tokio::test]
    async fn validate_works_when_schema_has_no_identity_fields() {
        let (vc_issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let schema = json!({
            "type": "object",
            "required": ["a"],
            "properties": {"a": {"type": "string"}}
        });
        let selector = IdentitySelector::new(&schema, Arc::new(vc_issuer)).unwrap();
        assert!(!selector.has_identity_fields());
        assert!(
            selector
                .validate(&json!({"a": "ok"}))
                .is_ok()
        );
        assert!(
            selector
                .validate(&json!({}))
                .is_err()
        );
    }
}
