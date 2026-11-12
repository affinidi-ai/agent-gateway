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
    if value.len() >= crate::config::caller_key::MIN_SECRET_BYTES {
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
        let invalid = surface(serde_json::json!({ "caller_key": { "secret_id": "caller-keys", "header": "Host" } }));
        assert_eq!(refusal(&invalid), Some("caller_key.header must be lower case".to_string()));
    }

    #[test]
    fn a_caller_key_header_another_setting_reads_or_sends_is_refused() {
        let cases = [
            (
                serde_json::json!({
                    "caller_key": { "secret_id": "caller-keys", "header": "x-api-key" },
                    "access_point": {
                        "listen_address": "0.0.0.0:9000", "route": "/agent", "protocol": "a2a",
                        "caller_authentication": { "methods": [
                            { "type": "api_key", "extraction": { "source": "http_header", "field": "X-API-Key" }, "secret_id": "key" }
                        ] }
                    }
                }),
                "caller_key.header x-api-key is already used by source authentication",
            ),
            (
                serde_json::json!({
                    "caller_key": { "secret_id": "caller-keys", "header": "x-vendor-key" },
                    "target": {
                        "endpoint": "https://agent.example",
                        "auth": { "method": { "static_secret": {
                            "secret_id": "vendor", "header_name": "X-Vendor-Key", "header_format": "{value}"
                        } } }
                    }
                }),
                "caller_key.header x-vendor-key is already used by a Target or delegated credential",
            ),
            (
                serde_json::json!({
                    "caller_key": { "secret_id": "caller-keys", "header": "x-tenant" },
                    "access_point": {
                        "listen_address": "0.0.0.0:9000", "route": "/agent", "protocol": "a2a",
                        "header_metadata_mapping": { "headers": [ { "header": "X-Tenant", "field": "tenant" } ] }
                    }
                }),
                "caller_key.header x-tenant is already used by header metadata mapping",
            ),
        ];
        for (extra, message) in cases {
            assert_eq!(refusal(&surface(extra)), Some(message.to_string()), "{message}");
        }
    }

    #[test]
    fn a_caller_key_header_a_variant_sends_is_refused() {
        let with_variant = surface(serde_json::json!({
            "caller_key": { "secret_id": "caller-keys", "header": "x-vendor-key" },
            "variants": [ {
                "id": "variant-1", "alias": "beta", "name": "Beta",
                "overrides": { "target": {
                    "endpoint": "https://agent.example",
                    "auth": { "method": { "static_secret": {
                        "secret_id": "vendor", "header_name": "x-vendor-key", "header_format": "{value}"
                    } } }
                } }
            } ]
        }));
        assert_eq!(
            refusal(&with_variant),
            Some(
                "caller_key.header x-vendor-key is already used by a Target or delegated credential in variant 'beta'"
                    .to_string()
            )
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
