//! Save-time rules for a surface's `caller_key`: the setting itself, a header no other part of
//! the surface uses, in any variant, and a secret long enough to derive keys from. A PUT that
//! leaves `caller_key` out keeps the stored one.

use crate::config::agent_surface::AgentSurface;
use crate::config::target_auth_rules::same_header_name;

use super::surfaces::SurfaceApiError;

/// Refuses a `caller_key` that is invalid on its own or whose header the surface, or one of
/// its variants as it resolves, already reads or sends: a source authentication credential
/// header, a Target or delegated credential header, or a header metadata mapping header.
pub(super) fn validate_caller_key(surface: &AgentSurface) -> Result<(), SurfaceApiError> {
    let Some(config) = surface.caller_key.as_ref() else {
        return Ok(());
    };
    config
        .validate()
        .map_err(SurfaceApiError::BadRequest)?;
    let places = std::iter::once(None).chain(
        surface
            .variants
            .iter()
            .map(|variant| Some(variant.alias.as_str())),
    );
    for (alias, view) in places.zip(super::surface_tenancy::resolved_views(surface)?) {
        if let Some(used_by) = header_user(&view, &config.header) {
            let place = alias
                .map(|alias| format!(" in variant '{alias}'"))
                .unwrap_or_default();
            return Err(SurfaceApiError::BadRequest(format!(
                "caller_key.header {} is already used by {used_by}{place}",
                config.header
            )));
        }
    }
    Ok(())
}

/// The save warnings of a surface's `caller_key`, for the surface and each variant as it
/// resolves: a Target that never receives a caller key (`fabric://`, `proxy://`,
/// `a2a-proxy://`, or bound by external consent), and an `http` Target, which receives it in
/// clear while `credential_policy.target_https` is `warn` and none while it is `enforce`.
pub(super) fn caller_key_warnings(surface: &AgentSurface) -> Vec<String> {
    target_warnings(surface, crate::config::credential_policy::credential_policy().target_https)
}

fn target_warnings(
    surface: &AgentSurface,
    target_https: crate::config::credential_policy::RuleMode,
) -> Vec<String> {
    if surface.caller_key.is_none() {
        return Vec::new();
    }
    let places = std::iter::once(None).chain(
        surface
            .variants
            .iter()
            .map(|variant| Some(variant.alias.as_str())),
    );
    let views = super::surface_tenancy::resolved_views(surface).unwrap_or_default();
    places
        .zip(views)
        .filter_map(|(alias, view)| {
            let place = alias
                .map(|alias| format!(" in variant '{alias}'"))
                .unwrap_or_default();
            let endpoint = view.target.endpoint.trim();
            let never = ["fabric://", "proxy://", "a2a-proxy://"]
                .into_iter()
                .find(|scheme| endpoint.starts_with(scheme))
                .map(|scheme| format!("its {scheme} Target"))
                .or_else(|| {
                    crate::proxy::target_grant::binds_the_target(&view)
                        .then(|| "its Target, bound by external consent,".to_string())
                });
            if let Some(target) = never {
                Some(format!("caller_key has no effect{place}: {target} is never sent a caller key"))
            } else if !crate::proxy::caller_key::sent_in_clear(endpoint) {
                None
            } else if target_https.is_enforced() {
                Some(format!(
                    "caller_key has no effect{place}: the Target is not https, and no caller key is sent while \
                     credential_policy.target_https is enforce"
                ))
            } else {
                Some(format!(
                    "caller_key{place} sends caller keys in clear to a Target that is not https; they will be \
                     withheld once credential_policy.target_https is enforce"
                ))
            }
        })
        .collect()
}

/// What else on `view` reads or sends `header`, if anything.
fn header_user(
    view: &AgentSurface,
    header: &str,
) -> Option<&'static str> {
    let mapped: Vec<&str> = view
        .access_point
        .header_metadata_mapping_if_supported()
        .map(|mapping| {
            mapping
                .headers
                .iter()
                .map(|mapped| mapped.header.trim())
                .collect()
        })
        .unwrap_or_default();
    [
        ("source authentication", view.source_credential_headers()),
        ("a Target or delegated credential", crate::proxy::handler::target_credential_header_names(view)),
        ("header metadata mapping", mapped),
    ]
    .into_iter()
    .find(|(_, names)| {
        names
            .iter()
            .any(|name| same_header_name(name, header))
    })
    .map(|(user, _)| user)
}

/// Refuses a `caller_key` whose secret holds fewer than
/// [`crate::config::caller_key::MIN_SECRET_BYTES`] bytes. Whether the secret exists and the
/// surface may use it is checked with the surface's other references.
pub(super) async fn validate_caller_key_secret(
    state: &crate::identity::state::IdentityApiState,
    surface: &AgentSurface,
) -> Result<(), SurfaceApiError> {
    let Some(config) = surface.caller_key.as_ref() else {
        return Ok(());
    };
    let store = state
        .secrets_store
        .as_ref()
        .ok_or_else(|| SurfaceApiError::InternalError("Secret store is not configured".to_string()))?;
    let secret = store
        .get_by_secret_id(&config.secret_id)
        .await
        .map_err(|error| super::surface_tenancy::internal("Secret", error))?
        .ok_or_else(|| super::surface_tenancy::inaccessible("Secret"))?;
    let value = zeroize::Zeroizing::new(secret.value);
    if crate::config::caller_key::long_enough(&value) {
        Ok(())
    } else {
        Err(SurfaceApiError::BadRequest(format!(
            "caller_key.secret_id must name a secret of at least {} bytes",
            crate::config::caller_key::MIN_SECRET_BYTES
        )))
    }
}

/// PUT carries the whole record, and the Surface Builder does not show `caller_key`, so a PUT
/// that leaves it out keeps the stored one. Removal is explicit: a `null`, with PUT or PATCH.
pub(super) fn retain_caller_key(
    surface: &mut AgentSurface,
    existing: &AgentSurface,
    sent: &serde_json::Value,
) {
    if sent
        .get("caller_key")
        .is_none()
    {
        surface.caller_key = existing.caller_key.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface(extra: serde_json::Value) -> AgentSurface {
        let mut json = serde_json::json!({
            "surface_id": "surface-1",
            "name": "surface-1",
            "access_point": { "listen_address": "0.0.0.0:9000", "route": "/agent", "protocol": "a2a" },
            "target": { "endpoint": "https://agent.example" },
        });
        for (key, value) in extra
            .as_object()
            .expect("an object")
        {
            json[key] = value.clone();
        }
        serde_json::from_value(json).expect("surface parses")
    }

    fn refusal(surface: &AgentSurface) -> Option<String> {
        match validate_caller_key(surface) {
            Ok(()) => None,
            Err(SurfaceApiError::BadRequest(message)) => Some(message),
            Err(other) => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn a_surface_without_caller_key_or_with_a_valid_one_saves() {
        assert_eq!(refusal(&surface(serde_json::json!({}))), None);
        assert_eq!(refusal(&surface(serde_json::json!({ "caller_key": { "secret_id": "caller-keys" } }))), None);
    }

    #[test]
    fn an_invalid_caller_key_is_refused() {
        for header in ["x-api-key", "x-user-vault-key", "Host"] {
            let invalid =
                surface(serde_json::json!({ "caller_key": { "secret_id": "caller-keys", "header": header } }));
            assert_eq!(
                refusal(&invalid),
                Some(
                    "caller_key.header must be x-caller-key, or x-caller-key- followed by lower-case letters and digits \
                     in words joined by single hyphens, at most 64 characters"
                        .to_string()
                ),
                "{header}"
            );
        }
    }

    #[test]
    fn a_caller_key_header_another_setting_reads_or_sends_is_refused() {
        let cases = [
            (
                serde_json::json!({
                    "caller_key": { "secret_id": "caller-keys", "header": "x-caller-key-client" },
                    "access_point": {
                        "listen_address": "0.0.0.0:9000", "route": "/agent", "protocol": "a2a",
                        "caller_authentication": { "methods": [
                            { "type": "api_key", "extraction": { "source": "http_header", "field": "X-Caller-Key-Client" }, "secret_id": "key" }
                        ] }
                    }
                }),
                "caller_key.header x-caller-key-client is already used by source authentication",
            ),
            (
                serde_json::json!({
                    "caller_key": { "secret_id": "caller-keys", "header": "x-caller-key-vendor" },
                    "target": {
                        "endpoint": "https://agent.example",
                        "auth": { "method": { "static_secret": {
                            "secret_id": "vendor", "header_name": "X-Caller-Key-Vendor", "header_format": "{value}"
                        } } }
                    }
                }),
                "caller_key.header x-caller-key-vendor is already used by a Target or delegated credential",
            ),
            (
                serde_json::json!({
                    "caller_key": { "secret_id": "caller-keys", "header": "x-caller-key-tenant" },
                    "access_point": {
                        "listen_address": "0.0.0.0:9000", "route": "/agent", "protocol": "a2a",
                        "header_metadata_mapping": { "headers": [ { "header": "X-Caller-Key-Tenant", "field": "tenant" } ] }
                    }
                }),
                "caller_key.header x-caller-key-tenant is already used by header metadata mapping",
            ),
        ];
        for (extra, message) in cases {
            assert_eq!(refusal(&surface(extra)), Some(message.to_string()), "{message}");
        }
    }

    #[test]
    fn a_caller_key_header_a_variant_sends_is_refused() {
        let with_variant = surface(serde_json::json!({
            "caller_key": { "secret_id": "caller-keys", "header": "x-caller-key-vendor" },
            "variants": [ {
                "id": "variant-1", "alias": "beta", "name": "Beta",
                "overrides": { "target": {
                    "endpoint": "https://agent.example",
                    "auth": { "method": { "static_secret": {
                        "secret_id": "vendor", "header_name": "x_caller_key_vendor", "header_format": "{value}"
                    } } }
                } }
            } ]
        }));
        assert_eq!(
            refusal(&with_variant),
            Some(
                "caller_key.header x-caller-key-vendor is already used by a Target or delegated credential in variant 'beta'"
                    .to_string()
            )
        );
    }

    fn keyed(target: serde_json::Value) -> AgentSurface {
        surface(serde_json::json!({ "caller_key": { "secret_id": "caller-keys" }, "target": target }))
    }

    #[test]
    fn a_caller_key_to_an_https_target_or_none_at_all_saves_without_a_warning() {
        use crate::config::credential_policy::RuleMode;
        for mode in [RuleMode::Warn, RuleMode::Enforce] {
            assert!(
                target_warnings(&keyed(serde_json::json!({ "endpoint": "https://agent.example" })), mode).is_empty()
            );
            let mut plain = keyed(serde_json::json!({ "endpoint": "http://agent.example" }));
            plain.caller_key = None;
            assert!(target_warnings(&plain, mode).is_empty(), "no caller_key");
        }
    }

    #[test]
    fn a_caller_key_its_target_never_receives_warns() {
        use crate::config::credential_policy::RuleMode;
        for (endpoint, target) in [
            ("fabric://did:example:peer/surface", "its fabric:// Target"),
            ("proxy://memory", "its proxy:// Target"),
            ("a2a-proxy://agent", "its a2a-proxy:// Target"),
        ] {
            assert_eq!(
                target_warnings(&keyed(serde_json::json!({ "endpoint": endpoint })), RuleMode::Warn),
                [format!("caller_key has no effect: {target} is never sent a caller key")]
            );
        }
        let mut bound = keyed(serde_json::json!({ "endpoint": "https://vendor.example" }));
        bound.outbound_credentials = serde_json::from_value(serde_json::json!([
            { "credential_provider_id": "vendor", "consent_mode": "external", "subject": "owner" }
        ]))
        .expect("binding parses");
        assert_eq!(
            target_warnings(&bound, RuleMode::Warn),
            ["caller_key has no effect: its Target, bound by external consent, is never sent a caller key"]
        );
    }

    #[test]
    fn a_caller_key_to_an_http_target_warns_by_target_https_mode() {
        use crate::config::credential_policy::RuleMode;
        let http = keyed(serde_json::json!({ "endpoint": "http://agent.example" }));
        assert_eq!(
            target_warnings(&http, RuleMode::Warn),
            ["caller_key sends caller keys in clear to a Target that is not https; they will be withheld once \
              credential_policy.target_https is enforce"]
        );
        assert_eq!(
            target_warnings(&http, RuleMode::Enforce),
            ["caller_key has no effect: the Target is not https, and no caller key is sent while \
              credential_policy.target_https is enforce"]
        );
    }

    #[test]
    fn a_variant_whose_target_is_not_https_warns_by_name() {
        use crate::config::credential_policy::RuleMode;
        let with_variant = surface(serde_json::json!({
            "caller_key": { "secret_id": "caller-keys" },
            "variants": [ {
                "id": "variant-1", "alias": "beta", "name": "Beta",
                "overrides": { "target": { "endpoint": "http://beta.example" } }
            } ]
        }));
        assert_eq!(
            target_warnings(&with_variant, RuleMode::Enforce),
            ["caller_key has no effect in variant 'beta': the Target is not https, and no caller key is sent \
              while credential_policy.target_https is enforce"]
        );
    }

    #[test]
    fn a_put_without_caller_key_keeps_the_stored_one_and_a_null_removes_it() {
        let stored = surface(serde_json::json!({ "caller_key": { "secret_id": "caller-keys" } }));
        let mut omitted = surface(serde_json::json!({}));
        retain_caller_key(&mut omitted, &stored, &serde_json::json!({ "name": "surface-1" }));
        assert_eq!(omitted.caller_key, stored.caller_key);

        let mut removed = surface(serde_json::json!({}));
        retain_caller_key(&mut removed, &stored, &serde_json::json!({ "name": "surface-1", "caller_key": null }));
        assert_eq!(removed.caller_key, None);

        let mut replaced = surface(serde_json::json!({ "caller_key": { "secret_id": "other-keys" } }));
        retain_caller_key(
            &mut replaced,
            &stored,
            &serde_json::json!({ "name": "surface-1", "caller_key": { "secret_id": "other-keys" } }),
        );
        assert_eq!(
            replaced
                .caller_key
                .map(|config| config.secret_id),
            Some("other-keys".to_string())
        );
    }
}
