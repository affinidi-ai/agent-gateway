//! Save checks for identities that take a DID from a caller credential, and the
//! warning for a Transit Point whose JWT claim identity is not namespaced.

use super::{
    SurfaceApiError, jwt_bearer_methods, labelled_bad_request, surface_views, transit_point_name,
    variant_sets_caller_authentication,
};
use crate::config::agent_surface::AgentSurface;

pub(crate) const TRANSIT_API_KEY_NEEDS_API_KEY_CALLER: &str = "Identity 'From API Key' without an api_key_id needs \
     the Transit Point's caller authentication (source_auth) to be API Key or API Key Provider";
pub(crate) const TRANSIT_JWT_CLAIM_NEEDS_JWT_CALLER: &str =
    "Identity 'From JWT Claims' needs the Transit Point's caller authentication (source_auth) to be JWT Bearer";
pub(crate) const MTLS_IDENTITY_NEEDS_ID: &str = "Identity 'From mTLS certificate' needs a non-empty certificate_id";
pub(crate) const TRANSIT_MTLS_NEEDS_MTLS_CALLER: &str = "Identity 'From mTLS certificate' without a certificate_id \
     needs the Transit Point's caller authentication (source_auth) to be mTLS";

/// Refuse a `from_mtls` identity without a `certificate_id` outside a Transit
/// Point: those slots read only a stored certificate.
pub(super) fn validate_mtls_identities(
    surface: &AgentSurface,
    label: &str,
) -> Result<(), SurfaceApiError> {
    let protected = surface.managed_identity();
    for (slot, identity) in [
        ("identity_slots.inbound", surface.inbound_identity()),
        ("identity_slots.protected", protected.as_ref()),
        ("identity_slots.external", surface.external_identity()),
    ] {
        if identity.and_then(crate::source_auth::ManagedIdentityConfig::caller_credential)
            == Some(crate::source_auth::CallerCredential::Mtls)
        {
            return Err(labelled_bad_request(label, &format!("{slot}: {MTLS_IDENTITY_NEEDS_ID}")));
        }
    }
    Ok(())
}

/// Refuse a Transit Point whose own identity takes its DID from a caller
/// credential its own caller authentication does not verify.
pub(super) fn validate_transit_caller_identities(
    surface: &AgentSurface,
    label: &str,
) -> Result<(), SurfaceApiError> {
    use crate::source_auth::CallerCredential;

    let refused = surface
        .transit
        .iter()
        .flat_map(|transit| transit.points.iter())
        .find_map(|point| {
            point
                .unverified_caller_credential()
                .map(|credential| (point, credential))
        });
    let Some((point, credential)) = refused else {
        return Ok(());
    };
    let needs = match credential {
        CallerCredential::ApiKey => TRANSIT_API_KEY_NEEDS_API_KEY_CALLER,
        CallerCredential::JwtBearer => TRANSIT_JWT_CLAIM_NEEDS_JWT_CALLER,
        CallerCredential::Mtls => TRANSIT_MTLS_NEEDS_MTLS_CALLER,
    };
    Err(labelled_bad_request(label, &format!("Transit Point '{}': {needs}", point.alias)))
}

/// Each Transit Point, on the surface or in an enabled variant, whose own
/// identity is `from_jwt_claim` without `iss` in its `namespace_claims` and
/// whose `jwt_bearer` strategy is not one its view's Access Point accepts. Its
/// DID is keyed on the claim values alone, so a token from another identity
/// provider carrying the same values gets the same DID.
pub(super) fn unnamespaced_transit_claim_warnings(surface: &AgentSurface) -> Vec<String> {
    use crate::source_auth::ManagedIdentityConfig;
    let mut warnings = Vec::new();
    for (variant, view) in surface_views(surface) {
        let (access_point, transit_points) = jwt_bearer_methods(&view, variant.as_deref());
        for (alias, config) in &transit_points {
            let strategy = config
                .jwt_verification_strategy_id
                .as_str();
            let unnamespaced = view
                .transit_points()
                .iter()
                .find(|point| point.alias == *alias)
                .and_then(|point| {
                    point
                        .managed_identity
                        .as_ref()
                })
                .is_some_and(|identity| {
                    matches!(identity, ManagedIdentityConfig::FromJwtClaim { namespace_claims, .. }
                        if !namespace_claims.iter().any(|claim| claim == "iss"))
                });
            if !unnamespaced
                || access_point
                    .iter()
                    .any(|method| method.jwt_verification_strategy_id == strategy)
            {
                continue;
            }
            let access_point_name = match variant
                .as_deref()
                .filter(|variant| variant_sets_caller_authentication(surface, variant))
            {
                Some(variant) => format!("the Access Point of variant '{variant}'"),
                None => "the Access Point".to_string(),
            };
            let warning = format!(
                "Transit Point {} takes its managed agent's DID from a JWT claim verified through strategy \
                 '{strategy}', which {access_point_name} does not use: a token from another identity provider \
                 with the same claim value gets the same DID; add 'iss' to namespace_claims",
                transit_point_name(surface, variant.as_deref(), alias)
            );
            if !warnings.contains(&warning) {
                warnings.push(warning);
            }
        }
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::agent_surface_variants::SurfaceVariant;
    use crate::identity::handlers::surfaces::validation_tests::{
        api_key_caller, base_surface, jwt_caller, provider_caller, refusal, with_transit,
    };
    use crate::identity::handlers::surfaces::{validate_api_key_identities, validate_resolved_variants};

    #[test]
    fn a_transit_point_claim_identity_from_another_strategy_without_iss_is_warned_of() {
        let point = |strategy: &str, namespace_claims: serde_json::Value| {
            serde_json::json!({ "alias": "crm", "target_endpoint": "https://crm.example", "require_transit_token": false,
                "source_auth": { "type": "jwt_bearer", "jwt_verification_strategy_id": strategy,
                    "audiences": ["api://crm-transit"] },
                "managed_identity": { "type": "from_jwt_claim", "claim": "oid", "namespace_claims": namespace_claims } })
        };
        let surface_with = |access_point_methods: serde_json::Value,
                            base: serde_json::Value,
                            variant_points: Option<serde_json::Value>|
         -> AgentSurface {
            let overrides = match variant_points {
                Some(points) => serde_json::json!({ "transit": { "points": points } }),
                None => serde_json::json!({}),
            };
            serde_json::from_value(serde_json::json!({
                "name": "agent",
                "access_point": { "listen_address": "0.0.0.0:8443", "route": "/a2a", "protocol": "a2a",
                    "caller_authentication": { "methods": access_point_methods } },
                "target": { "endpoint": "https://agent.internal" },
                "transit": { "outbound_listen_address": "http://localhost:9111", "points": [base] },
                "variants": [{ "id": "beta", "alias": "beta", "name": "Beta", "enabled": true,
                    "overrides": overrides }]
            }))
            .unwrap()
        };
        let workforce = serde_json::json!([{ "type": "jwt_bearer", "jwt_verification_strategy_id": "workforce",
            "audiences": ["api://agent"] }]);
        let warning = |name: &str, strategy: &str| {
            format!(
                "Transit Point {name} takes its managed agent's DID from a JWT claim verified through strategy \
                 '{strategy}', which the Access Point does not use: a token from another identity provider with \
                 the same claim value gets the same DID; add 'iss' to namespace_claims"
            )
        };

        let other_strategy = surface_with(workforce.clone(), point("partner-keys", serde_json::json!(["tid"])), None);
        assert_eq!(unnamespaced_transit_claim_warnings(&other_strategy), vec![warning("'crm'", "partner-keys")]);

        let no_access_point_jwt = surface_with(
            serde_json::json!([{ "type": "api_key", "extraction": { "source": "http_header", "field": "X-API-Key" },
                "secret_id": "agent-key" }]),
            point("workforce", serde_json::json!([])),
            None,
        );
        assert_eq!(unnamespaced_transit_claim_warnings(&no_access_point_jwt), vec![warning("'crm'", "workforce")]);

        let in_variant = surface_with(
            workforce.clone(),
            point("workforce", serde_json::json!([])),
            Some(serde_json::json!([point("partner-keys", serde_json::json!([]))])),
        );
        assert_eq!(
            unnamespaced_transit_claim_warnings(&in_variant),
            vec![warning("'crm' in variant 'beta'", "partner-keys")]
        );

        let mut variant_access_point = surface_with(workforce.clone(), point("workforce", serde_json::json!([])), None);
        variant_access_point.variants[0].overrides = serde_json::from_value(serde_json::json!({
            "access_point": { "caller_authentication": { "methods": [{ "type": "jwt_bearer",
                "jwt_verification_strategy_id": "partner-keys", "audiences": ["api://agent"] }] } }
        }))
        .unwrap();
        assert_eq!(
            unnamespaced_transit_claim_warnings(&variant_access_point),
            vec![
                "Transit Point 'crm' takes its managed agent's DID from a JWT claim verified through strategy \
                 'workforce', which the Access Point of variant 'beta' does not use: a token from another identity \
                 provider with the same claim value gets the same DID; add 'iss' to namespace_claims"
                    .to_string()
            ]
        );

        for (case, surface) in [
            (
                "same strategy as the Access Point",
                surface_with(workforce.clone(), point("workforce", serde_json::json!([])), None),
            ),
            (
                "namespaced by iss",
                surface_with(workforce.clone(), point("partner-keys", serde_json::json!(["iss"])), None),
            ),
        ] {
            assert!(unnamespaced_transit_claim_warnings(&surface).is_empty(), "{case}");
        }
    }

    fn presented_key_transit(
        source_auth: Option<serde_json::Value>,
        api_key_id: Option<&str>,
    ) -> serde_json::Value {
        let mut point = serde_json::json!({
            "alias": "tr1", "target_endpoint": "https://partner.example",
            "managed_identity": { "type": "from_api_key" }
        });
        if let Some(source_auth) = source_auth {
            point["source_auth"] = source_auth;
        }
        if let Some(id) = api_key_id {
            point["managed_identity"]["api_key_id"] = serde_json::json!(id);
        }
        serde_json::json!({ "points": [point] })
    }

    #[test]
    fn transit_point_from_api_key_without_a_key_id_is_accepted_behind_api_key_caller_authentication() {
        for (case, source_auth) in [("api key", api_key_caller("caller-keys")), ("api key provider", provider_caller())]
        {
            for id in [None, Some(""), Some("  ")] {
                let s = with_transit(base_surface(), presented_key_transit(Some(source_auth.clone()), id));
                assert!(validate_transit_caller_identities(&s, "").is_ok(), "{case} {id:?}");
            }
        }
    }

    #[test]
    fn transit_point_from_api_key_without_a_key_id_is_refused_without_api_key_caller_authentication() {
        let expected = format!("Transit Point 'tr1': {TRANSIT_API_KEY_NEEDS_API_KEY_CALLER}");
        for (case, source_auth) in [("no caller authentication", None), ("jwt bearer", Some(jwt_caller()))] {
            let s = with_transit(base_surface(), presented_key_transit(source_auth, None));
            assert_eq!(refusal(validate_transit_caller_identities(&s, "")), expected, "{case}");
        }

        let keyed = with_transit(base_surface(), presented_key_transit(Some(jwt_caller()), Some("managed-key")));
        assert!(validate_transit_caller_identities(&keyed, "").is_ok(), "a stored key needs no API key caller");
        assert!(validate_api_key_identities(&keyed, "").is_ok(), "a stored key");
    }

    #[test]
    fn transit_point_from_api_key_refusal_names_the_transit_point_and_its_caller_authentication() {
        assert_eq!(
            TRANSIT_API_KEY_NEEDS_API_KEY_CALLER,
            "Identity 'From API Key' without an api_key_id needs the Transit Point's caller authentication \
             (source_auth) to be API Key or API Key Provider"
        );
    }

    #[test]
    fn a_variant_transit_point_from_api_key_without_a_key_id_needs_api_key_caller_authentication() {
        let variant = |source_auth: serde_json::Value| SurfaceVariant {
            id: "v-candidate".to_string(),
            alias: "candidate".to_string(),
            name: "candidate".to_string(),
            description: String::new(),
            enabled: true,
            overrides: serde_json::from_value(serde_json::json!({
                "transit": presented_key_transit(Some(source_auth), None)
            }))
            .unwrap(),
        };
        let mut s = with_transit(base_surface(), presented_key_transit(Some(provider_caller()), None));
        s.variants
            .push(variant(jwt_caller()));
        assert_eq!(
            refusal(validate_resolved_variants(&s)),
            format!("Variant 'candidate': Transit Point 'tr1': {TRANSIT_API_KEY_NEEDS_API_KEY_CALLER}")
        );

        s.variants[0].enabled = false;
        assert!(validate_resolved_variants(&s).is_ok(), "a disabled variant is not resolved");

        s.variants[0] = variant(api_key_caller("caller-keys"));
        assert!(validate_resolved_variants(&s).is_ok(), "an API key variant");
    }

    fn jwt_claim_transit(source_auth: Option<serde_json::Value>) -> serde_json::Value {
        let mut point = serde_json::json!({
            "alias": "tr1", "target_endpoint": "https://partner.example",
            "managed_identity": { "type": "from_jwt_claim", "claim": "oid", "namespace_claims": ["tid"] }
        });
        if let Some(source_auth) = source_auth {
            point["source_auth"] = source_auth;
        }
        serde_json::json!({ "points": [point] })
    }

    #[test]
    fn transit_point_from_jwt_claim_is_accepted_behind_jwt_bearer_caller_authentication() {
        let s = with_transit(base_surface(), jwt_claim_transit(Some(jwt_caller())));
        assert!(validate_transit_caller_identities(&s, "").is_ok());
    }

    #[test]
    fn transit_point_from_jwt_claim_is_refused_without_jwt_bearer_caller_authentication() {
        let expected = format!("Transit Point 'tr1': {TRANSIT_JWT_CLAIM_NEEDS_JWT_CALLER}");
        for (case, source_auth) in [
            ("no caller authentication", None),
            ("api key", Some(api_key_caller("caller-keys"))),
            ("api key provider", Some(provider_caller())),
        ] {
            let s = with_transit(base_surface(), jwt_claim_transit(source_auth));
            assert_eq!(refusal(validate_transit_caller_identities(&s, "")), expected, "{case}");
        }
        assert_eq!(
            TRANSIT_JWT_CLAIM_NEEDS_JWT_CALLER,
            "Identity 'From JWT Claims' needs the Transit Point's caller authentication (source_auth) to be JWT Bearer"
        );
    }

    #[test]
    fn a_variant_transit_point_from_jwt_claim_needs_jwt_bearer_caller_authentication() {
        let variant = |source_auth: serde_json::Value| SurfaceVariant {
            id: "v-candidate".to_string(),
            alias: "candidate".to_string(),
            name: "candidate".to_string(),
            description: String::new(),
            enabled: true,
            overrides: serde_json::from_value(serde_json::json!({
                "transit": jwt_claim_transit(Some(source_auth))
            }))
            .unwrap(),
        };
        let mut s = with_transit(base_surface(), jwt_claim_transit(Some(jwt_caller())));
        s.variants
            .push(variant(provider_caller()));
        assert_eq!(
            refusal(validate_resolved_variants(&s)),
            format!("Variant 'candidate': Transit Point 'tr1': {TRANSIT_JWT_CLAIM_NEEDS_JWT_CALLER}")
        );

        s.variants[0].enabled = false;
        assert!(validate_resolved_variants(&s).is_ok(), "a disabled variant is not resolved");

        s.variants[0] = variant(jwt_caller());
        assert!(validate_resolved_variants(&s).is_ok(), "a JWT Bearer variant");
    }

    fn mtls_caller() -> serde_json::Value {
        serde_json::json!({
            "type": "mtls",
            "trust": { "type": "ca", "ca_certificate_ids": ["agents-ca"] },
            "identity_binding": { "type": "subject_cn" }
        })
    }

    fn caller_certificate_transit(
        source_auth: Option<serde_json::Value>,
        certificate_id: Option<&str>,
    ) -> serde_json::Value {
        let mut point = serde_json::json!({
            "alias": "tr1", "target_endpoint": "https://partner.example",
            "managed_identity": { "type": "from_mtls" }
        });
        if let Some(source_auth) = source_auth {
            point["source_auth"] = source_auth;
        }
        if let Some(id) = certificate_id {
            point["managed_identity"]["certificate_id"] = serde_json::json!(id);
        }
        serde_json::json!({ "points": [point] })
    }

    #[test]
    fn transit_point_from_mtls_without_a_certificate_id_is_accepted_behind_mtls_caller_authentication() {
        for id in [None, Some(""), Some("  ")] {
            let s = with_transit(base_surface(), caller_certificate_transit(Some(mtls_caller()), id));
            assert!(validate_transit_caller_identities(&s, "").is_ok(), "{id:?}");
            assert!(validate_mtls_identities(&s, "").is_ok(), "{id:?}");
        }
    }

    #[test]
    fn transit_point_from_mtls_without_a_certificate_id_is_refused_without_mtls_caller_authentication() {
        let expected = format!("Transit Point 'tr1': {TRANSIT_MTLS_NEEDS_MTLS_CALLER}");
        for (case, source_auth) in [
            ("no caller authentication", None),
            ("api key", Some(api_key_caller("caller-keys"))),
            ("api key provider", Some(provider_caller())),
            ("jwt bearer", Some(jwt_caller())),
        ] {
            let s = with_transit(base_surface(), caller_certificate_transit(source_auth, None));
            assert_eq!(refusal(validate_transit_caller_identities(&s, "")), expected, "{case}");
        }
        assert_eq!(
            TRANSIT_MTLS_NEEDS_MTLS_CALLER,
            "Identity 'From mTLS certificate' without a certificate_id needs the Transit Point's caller \
             authentication (source_auth) to be mTLS"
        );

        let stored =
            with_transit(base_surface(), caller_certificate_transit(Some(api_key_caller("k")), Some("cert-1")));
        assert!(validate_transit_caller_identities(&stored, "").is_ok(), "a stored certificate needs no mTLS caller");
    }

    #[test]
    fn a_variant_transit_point_from_mtls_without_a_certificate_id_needs_mtls_caller_authentication() {
        let variant = |source_auth: serde_json::Value| SurfaceVariant {
            id: "v-candidate".to_string(),
            alias: "candidate".to_string(),
            name: "candidate".to_string(),
            description: String::new(),
            enabled: true,
            overrides: serde_json::from_value(serde_json::json!({
                "transit": caller_certificate_transit(Some(source_auth), None)
            }))
            .unwrap(),
        };
        let mut s = with_transit(base_surface(), caller_certificate_transit(Some(mtls_caller()), None));
        s.variants
            .push(variant(api_key_caller("caller-keys")));
        assert_eq!(
            refusal(validate_resolved_variants(&s)),
            format!("Variant 'candidate': Transit Point 'tr1': {TRANSIT_MTLS_NEEDS_MTLS_CALLER}")
        );

        s.variants[0].enabled = false;
        assert!(validate_resolved_variants(&s).is_ok(), "a disabled variant is not resolved");

        s.variants[0] = variant(mtls_caller());
        assert!(validate_resolved_variants(&s).is_ok(), "an mTLS variant");
    }

    #[test]
    fn other_slots_refuse_from_mtls_without_a_certificate_id() {
        let from_mtls = |id: Option<&str>| {
            Some(crate::source_auth::ManagedIdentityConfig::FromMtls {
                certificate_id: id.map(str::to_string),
            })
        };
        for slot in ["inbound", "protected", "external"] {
            for id in [None, Some(""), Some(" ")] {
                let mut s = base_surface();
                match slot {
                    "inbound" => s.identity_slots.inbound = from_mtls(id),
                    "protected" => s.identity_slots.protected = from_mtls(id),
                    _ => s.identity_slots.external = from_mtls(id),
                }
                assert_eq!(
                    refusal(validate_mtls_identities(&s, "")),
                    format!("identity_slots.{slot}: {MTLS_IDENTITY_NEEDS_ID}"),
                    "{slot} {id:?}"
                );
            }
            let mut s = base_surface();
            match slot {
                "inbound" => s.identity_slots.inbound = from_mtls(Some("cert-1")),
                "protected" => s.identity_slots.protected = from_mtls(Some("cert-1")),
                _ => s.identity_slots.external = from_mtls(Some("cert-1")),
            }
            assert!(validate_mtls_identities(&s, "").is_ok(), "{slot} with a certificate");
        }
    }
}
