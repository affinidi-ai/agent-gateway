//! Boot warnings for stored identities that take a DID from a caller
//! credential nothing verifies.

/// The warnings for a surface whose inbound, protected or external identity is
/// `from_mtls` without a non-empty `certificate_id`, which only a Transit
/// Point's own identity may take from its caller: one for the base surface,
/// and one for each enabled variant as resolved with such a slot the base does
/// not already warn about.
pub(super) fn unnamed_mtls_identity_warnings(surface: &crate::config::agent_surface::AgentSurface) -> Vec<String> {
    let unnamed = |surface: &crate::config::agent_surface::AgentSurface| {
        [
            (
                "inbound",
                surface
                    .inbound_identity()
                    .cloned(),
            ),
            ("protected", surface.managed_identity()),
            (
                "external",
                surface
                    .external_identity()
                    .cloned(),
            ),
        ]
        .into_iter()
        .filter(|(_, identity)| {
            identity
                .as_ref()
                .is_some_and(|identity| {
                    identity.caller_credential() == Some(crate::source_auth::CallerCredential::Mtls)
                })
        })
        .map(|(slot, _)| slot)
        .collect::<Vec<_>>()
    };
    let base = unnamed(surface);
    let variants = surface
        .variants
        .iter()
        .filter_map(|variant| {
            surface
                .resolve_variant(Some(&variant.alias))
                .ok()
                .filter(|resolved| {
                    unnamed(resolved)
                        .iter()
                        .any(|slot| !base.contains(slot))
                })
                .map(|_| format!("Channel '{}' variant '{}'", surface.name, variant.alias))
        });
    (!base.is_empty())
        .then(|| format!("Channel '{}'", surface.name))
        .into_iter()
        .chain(variants)
        .map(|scope| {
            format!(
                "{scope}: identity from_mtls without a certificate_id; requests other than discovery reads are \
                 refused until the surface is fixed"
            )
        })
        .collect()
}

/// One warning per Transit Point whose own identity takes its DID from a
/// caller credential its own `source_auth` does not verify: the base surface's,
/// and those of each enabled variant as resolved that the base does not already
/// warn about.
pub(super) fn transit_caller_identity_warnings(surface: &crate::config::agent_surface::AgentSurface) -> Vec<String> {
    use crate::source_auth::CallerCredential;

    let refused = |surface: &crate::config::agent_surface::AgentSurface| {
        surface
            .transit
            .iter()
            .flat_map(|transit| transit.points.iter())
            .filter_map(|point| {
                point
                    .unverified_caller_credential()
                    .map(|credential| (point.alias.clone(), credential))
            })
            .collect::<Vec<_>>()
    };
    let base = refused(surface);
    let variants = surface
        .variants
        .iter()
        .filter_map(|variant| {
            surface
                .resolve_variant(Some(&variant.alias))
                .ok()
                .map(|resolved| (variant, resolved))
        })
        .flat_map(|(variant, resolved)| {
            refused(&resolved)
                .into_iter()
                .filter(|point| !base.contains(point))
                .map(|point| (format!("Channel '{}' variant '{}'", surface.name, variant.alias), point))
                .collect::<Vec<_>>()
        });
    base.iter()
        .cloned()
        .map(|point| (format!("Channel '{}'", surface.name), point))
        .chain(variants)
        .map(|(scope, (alias, credential))| {
            let (mode, needs) = match credential {
                CallerCredential::ApiKey => ("from_api_key without an api_key_id", "api_key or api_key_provider"),
                CallerCredential::JwtBearer => ("from_jwt_claim", "jwt_bearer"),
                CallerCredential::Mtls => ("from_mtls without a certificate_id", "mtls"),
            };
            format!(
                "{scope}: Transit Point '{alias}' takes its managed identity {mode} but its source_auth is not \
                 {needs}; requests other than discovery reads are refused until the surface is fixed"
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::proxy::tests::{api_key_method, jwt_method, surface_with_caller_auth};
    use crate::config::proxy::validate_source_auth_surface;

    fn transit_point(
        alias: &str,
        managed_identity: serde_json::Value,
        source_auth: Option<serde_json::Value>,
    ) -> serde_json::Value {
        let mut point = serde_json::json!({
            "alias": alias,
            "target_endpoint": "https://partner.example",
            "managed_identity": managed_identity
        });
        if let Some(source_auth) = source_auth {
            point["source_auth"] = source_auth;
        }
        point
    }

    fn variant(
        alias: &str,
        enabled: bool,
        points: serde_json::Value,
    ) -> serde_json::Value {
        serde_json::json!({
            "id": format!("v-{alias}"), "alias": alias, "name": alias, "description": "", "enabled": enabled,
            "overrides": { "transit": { "points": points } }
        })
    }

    #[test]
    fn boot_warns_about_each_transit_point_whose_caller_authentication_cannot_give_its_identity() {
        let jwt_point = |source_auth| transit_point("jwt", serde_json::json!({"type": "from_jwt_claim"}), source_auth);
        let mtls_point = |source_auth| transit_point("mtls", serde_json::json!({"type": "from_mtls"}), source_auth);
        let key_point = |source_auth| transit_point("key", serde_json::json!({"type": "from_api_key"}), source_auth);
        let surface = surface_with_caller_auth(
            serde_json::json!([api_key_method("X-API-Key")]),
            serde_json::json!({
                "transit": {"points": [
                    jwt_point(Some(api_key_method("X-API-Key"))),
                    mtls_point(None),
                    key_point(Some(jwt_method())),
                    transit_point("stored", serde_json::json!({"type": "from_mtls", "certificate_id": "cert-1"}), None),
                ]},
            }),
        );

        assert_eq!(
            transit_caller_identity_warnings(&surface),
            [
                "Channel 'multi': Transit Point 'jwt' takes its managed identity from_jwt_claim but its source_auth \
                 is not jwt_bearer; requests other than discovery reads are refused until the surface is fixed",
                "Channel 'multi': Transit Point 'mtls' takes its managed identity from_mtls without a certificate_id \
                 but its source_auth is not mtls; requests other than discovery reads are refused until the surface is fixed",
                "Channel 'multi': Transit Point 'key' takes its managed identity from_api_key without an api_key_id \
                 but its source_auth is not api_key or api_key_provider; requests other than discovery reads are refused until the surface \
                 is fixed",
            ]
        );
        validate_source_auth_surface(&surface).unwrap();

        let fixed = surface_with_caller_auth(
            serde_json::json!([api_key_method("X-API-Key")]),
            serde_json::json!({"transit": {"points": [
                jwt_point(Some(jwt_method())),
                key_point(Some(api_key_method("X-API-Key"))),
            ]}}),
        );
        assert!(transit_caller_identity_warnings(&fixed).is_empty());
    }

    #[test]
    fn boot_warns_about_a_slot_from_mtls_without_a_certificate_id_or_with_a_blank_one() {
        let warning = "Channel 'multi': identity from_mtls without a certificate_id; requests other than discovery \
                       reads are refused until the surface is fixed";
        for (case, identity) in [
            ("no id", serde_json::json!({"type": "from_mtls"})),
            ("blank id", serde_json::json!({"type": "from_mtls", "certificate_id": "  "})),
        ] {
            for slot in ["inbound", "protected", "external"] {
                let surface = surface_with_caller_auth(
                    serde_json::json!([api_key_method("X-API-Key")]),
                    serde_json::json!({"identity_slots": {slot: identity.clone()}}),
                );
                assert_eq!(unnamed_mtls_identity_warnings(&surface), [warning], "{case} on {slot}");
            }
        }
        let stored = surface_with_caller_auth(
            serde_json::json!([api_key_method("X-API-Key")]),
            serde_json::json!({"identity_slots": {"protected": {"type": "from_mtls", "certificate_id": "cert-1"}}}),
        );
        assert!(unnamed_mtls_identity_warnings(&stored).is_empty());

        let slot_variant = |alias: &str, enabled: bool| {
            serde_json::json!({
                "id": format!("v-{alias}"), "alias": alias, "name": alias, "description": "", "enabled": enabled,
                "overrides": { "identity_slots": { "external": {"type": "from_mtls"} } }
            })
        };
        let with_variants = surface_with_caller_auth(
            serde_json::json!([api_key_method("X-API-Key")]),
            serde_json::json!({
                "identity_slots": {"protected": {"type": "from_mtls", "certificate_id": "cert-1"}},
                "variants": [slot_variant("candidate", true), slot_variant("parked", false)],
            }),
        );
        assert_eq!(
            unnamed_mtls_identity_warnings(&with_variants),
            ["Channel 'multi' variant 'candidate': identity from_mtls without a certificate_id; requests other than \
              discovery reads are refused until the surface is fixed"]
        );
    }

    #[test]
    fn boot_warns_about_a_transit_point_of_an_enabled_variant_naming_the_variant() {
        let surface = surface_with_caller_auth(
            serde_json::json!([api_key_method("X-API-Key")]),
            serde_json::json!({
                "transit": {"points": [
                    transit_point("tr1", serde_json::json!({"type": "from_jwt_claim"}), Some(jwt_method())),
                ]},
                "variants": [
                    variant("candidate", true, serde_json::json!([
                        transit_point("tr1", serde_json::json!({"type": "from_jwt_claim"}), None),
                    ])),
                    variant("parked", false, serde_json::json!([
                        transit_point("tr1", serde_json::json!({"type": "from_jwt_claim"}), None),
                    ])),
                    variant("fine", true, serde_json::json!([
                        transit_point("tr1", serde_json::json!({"type": "from_jwt_claim"}), Some(jwt_method())),
                    ])),
                ],
            }),
        );

        assert_eq!(
            transit_caller_identity_warnings(&surface),
            ["Channel 'multi' variant 'candidate': Transit Point 'tr1' takes its managed identity from_jwt_claim but \
              its source_auth is not jwt_bearer; requests other than discovery reads are refused until the surface is fixed"]
        );
    }

    #[test]
    fn boot_warns_once_about_a_base_transit_point_a_variant_keeps() {
        let surface = surface_with_caller_auth(
            serde_json::json!([api_key_method("X-API-Key")]),
            serde_json::json!({
                "transit": {"points": [transit_point("tr1", serde_json::json!({"type": "from_mtls"}), None)]},
                "variants": [{
                    "id": "v-candidate", "alias": "candidate", "name": "candidate", "description": "",
                    "enabled": true, "overrides": {}
                }],
            }),
        );

        let warnings = transit_caller_identity_warnings(&surface);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].starts_with("Channel 'multi': Transit Point 'tr1'"), "{warnings:?}");
    }
}
