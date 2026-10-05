//! Request-body validation and normalisation helpers for the Authorities
//! module. All functions are pure and return `(StatusCode, String)` errors
//! shaped for the axum handler layer.

use axum::http::StatusCode;

/// Validate the shape of `context`. Absent or `null` are accepted; a bare
/// primitive / array is rejected so the field stays useful as a bag of
/// properties for Rego / template consumers.
pub fn validate_context(value: &Option<serde_json::Value>) -> Result<(), (StatusCode, String)> {
    match value {
        None => Ok(()),
        Some(v) if v.is_null() => Ok(()),
        Some(serde_json::Value::Object(_)) => Ok(()),
        Some(_) => Err((StatusCode::BAD_REQUEST, "Authority context must be a JSON object".to_string())),
    }
}

/// Normalise `context` for storage: convert an explicit `null` into `None`
/// so an operator toggling the field between empty / object round-trips
/// cleanly without leaving stray `null` values on disk.
pub fn normalize_context(value: Option<serde_json::Value>) -> Option<serde_json::Value> {
    match value {
        Some(v) if v.is_null() => None,
        other => other,
    }
}

pub fn validate_name(name: &str) -> Result<String, (StatusCode, String)> {
    let trimmed = name.trim().to_string();
    if trimmed.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Authority name cannot be empty".to_string()));
    }
    Ok(trimmed)
}

pub fn validate_did(did: &str) -> Result<String, (StatusCode, String)> {
    let trimmed = did.trim().to_string();
    if trimmed.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Authority DID cannot be empty".to_string()));
    }
    if !trimmed.starts_with("did:") {
        return Err((StatusCode::BAD_REQUEST, "Authority DID must start with 'did:'".to_string()));
    }
    Ok(trimmed)
}

pub fn normalize_description(description: Option<String>) -> Option<String> {
    description
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn validate_context_accepts_none_null_and_objects() {
        assert!(validate_context(&None).is_ok());
        assert!(validate_context(&Some(serde_json::Value::Null)).is_ok());
        assert!(validate_context(&Some(json!({}))).is_ok());
        assert!(validate_context(&Some(json!({ "a": 1 }))).is_ok());
    }

    #[test]
    fn validate_context_rejects_arrays_and_primitives() {
        for bad in [json!("s"), json!(1), json!(true), json!([1, 2])] {
            let err = validate_context(&Some(bad)).unwrap_err();
            assert_eq!(err.0, StatusCode::BAD_REQUEST);
            assert_eq!(err.1, "Authority context must be a JSON object");
        }
    }

    #[test]
    fn normalize_context_collapses_null_to_none_but_preserves_objects() {
        assert!(normalize_context(None).is_none());
        assert!(normalize_context(Some(serde_json::Value::Null)).is_none());
        assert_eq!(normalize_context(Some(json!({ "a": 1 }))), Some(json!({ "a": 1 })));
    }

    #[test]
    fn validate_name_trims_and_rejects_blank() {
        assert_eq!(validate_name("  Acme  ").unwrap(), "Acme");
        let err = validate_name("   ").unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1, "Authority name cannot be empty");
    }

    #[test]
    fn validate_did_requires_did_prefix() {
        assert_eq!(validate_did("  did:web:acme.example  ").unwrap(), "did:web:acme.example");

        let err = validate_did("").unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1, "Authority DID cannot be empty");

        let err = validate_did("acme").unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1, "Authority DID must start with 'did:'");
    }

    #[test]
    fn normalize_description_trims_and_collapses_blank_to_none() {
        assert_eq!(normalize_description(None), None);
        assert_eq!(normalize_description(Some("   ".to_string())), None);
        assert_eq!(normalize_description(Some("  Anchor  ".to_string())), Some("Anchor".to_string()));
    }
}
