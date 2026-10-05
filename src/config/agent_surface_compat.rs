//! Identity-injection helpers shared between `AgentSurface` and the legacy
//! `ManagedIdentityConfig` shape still consumed by the proxy pipeline.

use crate::config::agent_surface::IdentityInjectionConfig;
/// Map the surface's `target.identity_injection` to the legacy
/// `ManagedIdentityConfig` the proxy pipeline still consumes. All five
/// extraction strategies the UI exposes (`from_payload`, `from_api_key`,
/// `from_mtls`, `static`, `from_jwt_claim`) are persisted faithfully so user
/// configuration is not silently dropped on round-trip; runtime support for
/// the non-payload variants is wired in incrementally.
pub(crate) fn identity_injection_to_managed_identity(
    ii: &IdentityInjectionConfig
) -> Option<crate::source_auth::ManagedIdentityConfig> {
    use crate::source_auth::ManagedIdentityConfig;
    use crate::source_auth::models::PayloadExtractionConfig;

    let kind = ii.identity_type.as_deref()?;
    match kind {
        "from_payload" => {
            let meta_field = ii
                .meta_field
                .clone()
                .filter(|s| !s.is_empty())?;
            let extension_rules = ii
                .json_schema
                .as_ref()
                .map(|schema| crate::config::ExtensionRules {
                    json_schema: Some(schema.clone()),
                    rules: vec![],
                    filter_rules: vec![],
                    default_action: None,
                });
            Some(ManagedIdentityConfig::PayloadExtraction(PayloadExtractionConfig {
                extension_uri: None,
                meta_field,
                fields: ii.fields.clone(),
                json_schema: ii.json_schema.clone(),
                extension_rules,
                strip_raw_meta: ii
                    .strip_raw_meta
                    .unwrap_or(false),
            }))
        }
        "from_api_key" => {
            let api_key_id = ii
                .api_key_id
                .clone()
                .filter(|s| !s.is_empty())?;
            Some(ManagedIdentityConfig::FromApiKey { api_key_id })
        }
        "from_mtls" => {
            let certificate_id = ii
                .certificate_id
                .clone()
                .filter(|s| !s.is_empty())?;
            Some(ManagedIdentityConfig::FromMtls { certificate_id })
        }
        "static" => {
            let did = ii
                .static_did
                .clone()
                .filter(|s| !s.is_empty())?;
            Some(ManagedIdentityConfig::Static { did })
        }
        "from_jwt_claim" => {
            let claim = ii
                .claim
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(crate::source_auth::models::default_jwt_identity_claim);
            Some(ManagedIdentityConfig::FromJwtClaim {
                claim,
                namespace_claims: ii.namespace_claims.clone(),
            })
        }
        _ => None,
    }
}

/// Reverse of [`identity_injection_to_managed_identity`]: lift the legacy
/// `ManagedIdentityConfig` fields back onto a surface
/// `IdentityInjectionConfig`. Preserves the caller-supplied
/// `inject_vp` flag.
#[cfg(test)]
pub(crate) fn managed_identity_into_identity_injection(
    mi: Option<&crate::source_auth::ManagedIdentityConfig>,
    inject_vp: bool,
) -> IdentityInjectionConfig {
    use crate::source_auth::ManagedIdentityConfig;

    let mut out = IdentityInjectionConfig {
        inject_vp,
        ..Default::default()
    };
    match mi {
        Some(ManagedIdentityConfig::PayloadExtraction(cfg)) => {
            out.identity_type = Some("from_payload".to_string());
            out.meta_field = Some(cfg.meta_field.clone());
            out.fields = cfg.fields.clone();
            // Prefer top-level json_schema; fall back to extension_rules.json_schema
            let schema = cfg
                .json_schema
                .as_ref()
                .or_else(|| {
                    cfg.extension_rules
                        .as_ref()
                        .and_then(|er| er.json_schema.as_ref())
                });
            if let Some(schema) = schema {
                out.json_schema = Some(schema.clone());
            }
        }
        Some(ManagedIdentityConfig::FromApiKey { api_key_id }) => {
            out.identity_type = Some("from_api_key".to_string());
            out.api_key_id = Some(api_key_id.clone());
        }
        Some(ManagedIdentityConfig::FromMtls { certificate_id }) => {
            out.identity_type = Some("from_mtls".to_string());
            out.certificate_id = Some(certificate_id.clone());
        }
        Some(ManagedIdentityConfig::Static { did }) => {
            out.identity_type = Some("static".to_string());
            out.static_did = Some(did.clone());
        }
        Some(ManagedIdentityConfig::FromJwtClaim { claim, namespace_claims }) => {
            out.identity_type = Some("from_jwt_claim".to_string());
            out.claim = Some(claim.clone());
            out.namespace_claims = namespace_claims.clone();
        }
        None => {}
    }
    out
}

#[cfg(test)]
mod tests {
    // ── identity_injection_to_managed_identity ───────────────────────────────

    #[test]
    fn test_identity_injection_json_schema_forwarded_to_extension_rules() {
        use crate::config::agent_surface::IdentityInjectionConfig;
        use crate::source_auth::ManagedIdentityConfig;

        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "agentIdentity": {
                    "type": "object",
                    "properties": {
                        "llmInfo": {
                            "type": "object",
                            "properties": {
                                "provider": { "type": "string", "x-identity": true }
                            }
                        }
                    }
                }
            }
        });

        let ii = IdentityInjectionConfig {
            inject_vp: true,
            identity_type: Some("from_payload".to_string()),
            meta_field: Some("agentIdentity".to_string()),
            json_schema: Some(schema.clone()),
            ..Default::default()
        };

        let result = super::identity_injection_to_managed_identity(&ii);
        let Some(ManagedIdentityConfig::PayloadExtraction(cfg)) = result else {
            panic!("expected PayloadExtraction");
        };
        assert_eq!(cfg.meta_field, "agentIdentity");
        let ext_rules = cfg
            .extension_rules
            .expect("extension_rules must be Some when json_schema is set");
        assert_eq!(ext_rules.json_schema.as_ref(), Some(&schema));
        assert!(ext_rules.rules.is_empty());
    }

    #[test]
    fn test_identity_injection_no_json_schema_gives_no_extension_rules() {
        use crate::config::agent_surface::IdentityInjectionConfig;
        use crate::source_auth::ManagedIdentityConfig;

        let ii = IdentityInjectionConfig {
            inject_vp: false,
            identity_type: Some("from_payload".to_string()),
            meta_field: Some("agentIdentity".to_string()),
            json_schema: None,
            ..Default::default()
        };

        let result = super::identity_injection_to_managed_identity(&ii);
        let Some(ManagedIdentityConfig::PayloadExtraction(cfg)) = result else {
            panic!("expected PayloadExtraction");
        };
        assert!(cfg.extension_rules.is_none());
    }

    #[test]
    fn test_identity_injection_from_jwt_claim_roundtrips() {
        use crate::config::agent_surface::IdentityInjectionConfig;
        use crate::source_auth::ManagedIdentityConfig;

        let ii = IdentityInjectionConfig {
            inject_vp: false,
            identity_type: Some("from_jwt_claim".to_string()),
            claim: Some("oid".to_string()),
            namespace_claims: vec!["iss".to_string(), "tid".to_string()],
            ..Default::default()
        };

        let mi = super::identity_injection_to_managed_identity(&ii).expect("some");
        let ManagedIdentityConfig::FromJwtClaim {
            ref claim,
            ref namespace_claims,
        } = mi
        else {
            panic!("expected FromJwtClaim, got {mi:?}");
        };
        assert_eq!(claim, "oid");
        assert_eq!(namespace_claims, &vec!["iss".to_string(), "tid".to_string()]);

        let back = super::managed_identity_into_identity_injection(Some(&mi), false);
        assert_eq!(back.identity_type.as_deref(), Some("from_jwt_claim"));
        assert_eq!(back.claim.as_deref(), Some("oid"));
        assert_eq!(back.namespace_claims, vec!["iss".to_string(), "tid".to_string()]);
    }

    #[test]
    fn test_identity_injection_from_jwt_claim_defaults_claim_to_oid() {
        use crate::config::agent_surface::IdentityInjectionConfig;
        use crate::source_auth::ManagedIdentityConfig;

        let ii = IdentityInjectionConfig {
            identity_type: Some("from_jwt_claim".to_string()),
            ..Default::default()
        };

        let mi = super::identity_injection_to_managed_identity(&ii).expect("some");
        let ManagedIdentityConfig::FromJwtClaim {
            ref claim,
            ref namespace_claims,
        } = mi
        else {
            panic!("expected FromJwtClaim, got {mi:?}");
        };
        assert_eq!(claim, "oid", "empty/omitted claim defaults to oid");
        assert!(namespace_claims.is_empty());
    }
}
