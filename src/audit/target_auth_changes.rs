//! Records of management changes to the Target Authentication of a surface's legs. Each names
//! the actor of the management request it is built in and is written only when a sink selects
//! its event.

use std::collections::{BTreeMap, BTreeSet};

use crate::audit::context::current_actor;
use crate::audit::events::{Actor, TargetAuthField, TargetAuthLeg, TargetAuthMethodKind};
use crate::config::agent_surface::AgentSurface;
use crate::config::agent_surface_variants::SurfaceVariant;
use crate::config::{TargetAuthConfig, TargetAuthMethod};
use crate::delegation_vault::audit::{
    DelegationAuditAction, TargetAuthChangeDetails, action_category, audit_event, emit,
};

/// A leg of a surface: the variant's id (`None` for the base surface) and the Transit Point's id
/// (`None` for the Target).
type LegKey = (Option<String>, Option<String>);

/// What names a leg in a record, and the Target Authentication it sends.
struct Leg {
    surface_variant: String,
    transit_point: Option<String>,
    authentication: Option<TargetAuthConfig>,
}

/// Every leg of `surface`, of the base surface and of each variant as it resolves.
fn legs(surface: Option<&AgentSurface>) -> BTreeMap<LegKey, Leg> {
    let mut legs = BTreeMap::new();
    let Some(surface) = surface else {
        return legs;
    };
    let views = std::iter::once(None)
        .chain(
            surface
                .variants
                .iter()
                .map(Some),
        )
        .map(|variant| {
            (
                variant,
                surface
                    .serve_selected(variant)
                    .surface,
            )
        });
    for (variant, view) in views {
        let variant_id = variant.map(|variant| variant.id.clone());
        let surface_variant = variant.map_or(SurfaceVariant::BASE, |variant| variant.alias.as_str());
        legs.insert(
            (variant_id.clone(), None),
            Leg {
                surface_variant: surface_variant.to_string(),
                transit_point: None,
                authentication: view.target.auth,
            },
        );
        for point in view
            .transit
            .into_iter()
            .flat_map(|transit| transit.points)
        {
            legs.insert(
                (variant_id.clone(), Some(point.id)),
                Leg {
                    surface_variant: surface_variant.to_string(),
                    transit_point: Some(point.alias),
                    authentication: point.target_auth,
                },
            );
        }
    }
    legs
}

fn method(authentication: Option<&TargetAuthConfig>) -> TargetAuthMethodKind {
    match authentication.map(|authentication| &authentication.method) {
        None => TargetAuthMethodKind::None,
        Some(TargetAuthMethod::StaticSecret { .. }) => TargetAuthMethodKind::StaticSecret,
        Some(TargetAuthMethod::CredentialProvider { .. }) => TargetAuthMethodKind::CredentialProvider,
        Some(TargetAuthMethod::CredentialLookup) => TargetAuthMethodKind::CredentialLookup,
    }
}

fn provider_id(authentication: Option<&TargetAuthConfig>) -> Option<String> {
    match &authentication?.method {
        TargetAuthMethod::CredentialProvider { provider_id, .. } => Some(provider_id.clone()),
        _ => None,
    }
}

/// The parts of a setting `after` replaced in `before`. The `auth_type` dashboard hint is not
/// one: the request path never reads it.
fn changed_fields(
    before: &TargetAuthConfig,
    after: &TargetAuthConfig,
) -> Vec<TargetAuthField> {
    let secret = |auth: &TargetAuthConfig| match &auth.method {
        TargetAuthMethod::StaticSecret { secret_id, .. } => Some(secret_id.clone()),
        _ => None,
    };
    let header_format = |auth: &TargetAuthConfig| match &auth.method {
        TargetAuthMethod::StaticSecret { header_format, .. }
        | TargetAuthMethod::CredentialProvider { header_format, .. } => Some(header_format.clone()),
        TargetAuthMethod::CredentialLookup => None,
    };
    let scopes = |auth: &TargetAuthConfig| match &auth.method {
        TargetAuthMethod::CredentialProvider { scopes, .. } => scopes.clone(),
        _ => Vec::new(),
    };
    [
        (TargetAuthField::Method, method(Some(before)) != method(Some(after))),
        (TargetAuthField::SecretId, secret(before) != secret(after)),
        (TargetAuthField::ProviderId, provider_id(Some(before)) != provider_id(Some(after))),
        (TargetAuthField::HeaderName, before.method.header_name() != after.method.header_name()),
        (TargetAuthField::HeaderFormat, header_format(before) != header_format(after)),
        (TargetAuthField::Scopes, scopes(before) != scopes(after)),
        (TargetAuthField::Fallback, before.fallback != after.fallback),
        (TargetAuthField::TargetIdentifier, before.target_identifier != after.target_identifier),
    ]
    .into_iter()
    .filter_map(|(field, differs)| differs.then_some(field))
    .collect()
}

/// One record for each leg whose Target Authentication `after` sets differently from `before`,
/// in leg order: the base surface's Target, then its Transit Points by id, then each variant's.
/// A leg that is new or gone counts as having none on the other side; a variant inheriting a
/// changed base setting is recorded too, as its requests send the new credential.
pub fn target_auth_changes(
    actor: &Actor,
    before: Option<&AgentSurface>,
    after: Option<&AgentSurface>,
) -> Vec<TargetAuthChangeDetails> {
    let mut previous = legs(before);
    let mut current = legs(after);
    let keys: BTreeSet<LegKey> = previous
        .keys()
        .chain(current.keys())
        .cloned()
        .collect();
    let mut changes = Vec::new();
    for key in keys {
        let old = previous.remove(&key);
        let new = current.remove(&key);
        let old_authentication = old
            .as_ref()
            .and_then(|leg| leg.authentication.as_ref());
        let new_authentication = new
            .as_ref()
            .and_then(|leg| leg.authentication.as_ref());
        let changed = match (old_authentication, new_authentication) {
            (None, None) => continue,
            (Some(old), Some(new)) => {
                let changed = changed_fields(old, new);
                if changed.is_empty() {
                    continue;
                }
                changed
            }
            _ => Vec::new(),
        };
        let Some(named) = new.as_ref().or(old.as_ref()) else {
            continue;
        };
        let (variant_id, transit_point_id) = key;
        changes.push(TargetAuthChangeDetails {
            actor: actor.clone(),
            surface_variant: named.surface_variant.clone(),
            variant_id,
            leg: if transit_point_id.is_some() {
                TargetAuthLeg::TransitPoint
            } else {
                TargetAuthLeg::Target
            },
            transit_point_id,
            transit_point: named.transit_point.clone(),
            previous_method: method(old_authentication),
            method: method(new_authentication),
            previous_provider_id: provider_id(old_authentication),
            provider_id: provider_id(new_authentication),
            changed,
        });
    }
    changes
}

/// Records [`target_auth_changes`] of a surface write. Writes nothing outside a management
/// request: startup migrations, replication and configuration reloads are not user changes.
pub fn surface_written(
    before: Option<&AgentSurface>,
    after: Option<&AgentSurface>,
) {
    let Some(actor) = current_actor() else {
        return;
    };
    let Some(surface) = after.or(before) else {
        return;
    };
    for change in target_auth_changes(&actor, before, after) {
        let action = DelegationAuditAction::TargetAuthChanged(Box::new(change));
        let surface_id = surface.surface_id.clone();
        let name = surface.name.clone();
        emit(action_category(&action), move || {
            let mut event = audit_event(action, None, None, None, Some(&surface_id));
            event.channel_name = Some(name);
            event
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::context::in_management_request;
    use crate::audit::events::{TargetAuthField, TargetAuthLeg, TargetAuthMethodKind};
    use crate::audit::producer::capture;
    use serde_json::{Value, json};

    fn static_secret(secret: &str) -> Value {
        json!({ "method": { "static_secret": {
            "secret_id": secret, "header_name": "X-Target-Key", "header_format": "Token {value}"
        } } })
    }

    fn provider(provider_id: &str) -> Value {
        json!({ "method": { "credential_provider": {
            "provider_id": provider_id, "header_name": "X-Provider-Token", "header_format": "Bearer {value}"
        } } })
    }

    fn surface(target_auth: Option<Value>) -> Value {
        let mut surface = json!({
            "surface_id": "s-1",
            "name": "Orders",
            "access_point": { "listen_address": "0.0.0.0:8443", "route": "/orders", "protocol": "a2a" },
            "target": { "endpoint": "https://upstream" },
        });
        if let Some(auth) = target_auth {
            surface["target"]["auth"] = auth;
        }
        surface
    }

    fn with_transit_point(
        mut surface: Value,
        target_auth: Option<Value>,
    ) -> Value {
        let mut point = json!({ "id": "tp-1", "alias": "billing", "target_endpoint": "https://billing" });
        if let Some(auth) = target_auth {
            point["target_auth"] = auth;
        }
        surface["transit"] = json!({ "points": [point] });
        surface
    }

    fn with_variant(
        mut surface: Value,
        target_auth: Option<Value>,
    ) -> Value {
        let mut overrides = json!({});
        if let Some(auth) = target_auth {
            overrides["target"] = json!({ "auth": auth });
        }
        surface["variants"] = json!([{ "id": "v-1", "alias": "beta", "name": "Beta", "overrides": overrides }]);
        surface
    }

    fn parse(surface: Value) -> AgentSurface {
        serde_json::from_value(surface).expect("a surface")
    }

    fn changes(
        before: Option<Value>,
        after: Option<Value>,
    ) -> Vec<TargetAuthChangeDetails> {
        let before = before.map(parse);
        let after = after.map(parse);
        target_auth_changes(&Actor::user("u-1"), before.as_ref(), after.as_ref())
    }

    #[test]
    fn a_write_that_keeps_every_target_authentication_records_nothing() {
        let stored = with_transit_point(surface(Some(static_secret("key-a"))), Some(provider("p-1")));
        let mut renamed = stored.clone();
        renamed["name"] = json!("Renamed");
        renamed["target"]["auth"]["auth_type"] = json!("api_key");

        assert!(changes(Some(stored), Some(renamed)).is_empty());
        assert!(changes(None, Some(surface(None))).is_empty());
    }

    #[test]
    fn adding_a_target_authentication_records_its_method() {
        let recorded = changes(Some(surface(None)), Some(surface(Some(static_secret("key-a")))));

        assert_eq!(recorded.len(), 1, "{recorded:?}");
        let change = &recorded[0];
        assert_eq!(change.actor, Actor::user("u-1"));
        assert_eq!(change.leg, TargetAuthLeg::Target);
        assert_eq!(change.surface_variant, "_base_");
        assert_eq!(change.variant_id, None);
        assert_eq!(change.transit_point_id, None);
        assert_eq!(change.previous_method, TargetAuthMethodKind::None);
        assert_eq!(change.method, TargetAuthMethodKind::StaticSecret);
        assert_eq!(change.previous_provider_id, None);
        assert_eq!(change.provider_id, None);
        assert!(change.changed.is_empty());
    }

    #[test]
    fn creating_a_surface_records_each_leg_that_sends_a_credential() {
        let created = with_transit_point(surface(Some(static_secret("key-a"))), Some(provider("p-1")));

        let recorded = changes(None, Some(created));

        let legs: Vec<_> = recorded
            .iter()
            .map(|change| (change.leg, change.previous_method, change.method))
            .collect();
        assert_eq!(
            legs,
            vec![
                (TargetAuthLeg::Target, TargetAuthMethodKind::None, TargetAuthMethodKind::StaticSecret),
                (TargetAuthLeg::TransitPoint, TargetAuthMethodKind::None, TargetAuthMethodKind::CredentialProvider),
            ]
        );
    }

    #[test]
    fn removing_a_target_authentication_records_the_method_it_had() {
        let recorded = changes(Some(surface(Some(provider("p-1")))), Some(surface(None)));

        assert_eq!(recorded.len(), 1, "{recorded:?}");
        assert_eq!(recorded[0].previous_method, TargetAuthMethodKind::CredentialProvider);
        assert_eq!(recorded[0].method, TargetAuthMethodKind::None);
        assert_eq!(
            recorded[0]
                .previous_provider_id
                .as_deref(),
            Some("p-1")
        );
        assert_eq!(recorded[0].provider_id, None);
    }

    #[test]
    fn deleting_a_surface_records_each_leg_that_sent_a_credential() {
        let recorded = changes(Some(surface(Some(static_secret("key-a")))), None);

        assert_eq!(recorded.len(), 1, "{recorded:?}");
        assert_eq!(recorded[0].previous_method, TargetAuthMethodKind::StaticSecret);
        assert_eq!(recorded[0].method, TargetAuthMethodKind::None);
    }

    #[test]
    fn switching_the_method_records_both_methods_and_the_new_provider() {
        let recorded = changes(Some(surface(Some(static_secret("key-a")))), Some(surface(Some(provider("p-1")))));

        assert_eq!(recorded.len(), 1, "{recorded:?}");
        let change = &recorded[0];
        assert_eq!(change.previous_method, TargetAuthMethodKind::StaticSecret);
        assert_eq!(change.method, TargetAuthMethodKind::CredentialProvider);
        assert_eq!(change.previous_provider_id, None);
        assert_eq!(change.provider_id.as_deref(), Some("p-1"));
        assert_eq!(
            change.changed,
            vec![
                TargetAuthField::Method,
                TargetAuthField::SecretId,
                TargetAuthField::ProviderId,
                TargetAuthField::HeaderName,
                TargetAuthField::HeaderFormat,
            ]
        );
    }

    #[test]
    fn switching_the_provider_records_both_providers() {
        let recorded = changes(Some(surface(Some(provider("p-1")))), Some(surface(Some(provider("p-2")))));

        assert_eq!(recorded.len(), 1, "{recorded:?}");
        let change = &recorded[0];
        assert_eq!(change.previous_method, TargetAuthMethodKind::CredentialProvider);
        assert_eq!(change.method, TargetAuthMethodKind::CredentialProvider);
        assert_eq!(
            change
                .previous_provider_id
                .as_deref(),
            Some("p-1")
        );
        assert_eq!(change.provider_id.as_deref(), Some("p-2"));
        assert_eq!(change.changed, vec![TargetAuthField::ProviderId]);
    }

    #[test]
    fn each_part_of_a_setting_is_named_when_it_changes() {
        type Edit = fn(&mut Value);
        let parts: [(TargetAuthField, Edit); 5] = [
            (TargetAuthField::SecretId, |auth| auth["method"]["static_secret"]["secret_id"] = json!("key-b")),
            (TargetAuthField::HeaderName, |auth| auth["method"]["static_secret"]["header_name"] = json!("X-Other")),
            (TargetAuthField::HeaderFormat, |auth| auth["method"]["static_secret"]["header_format"] = json!("{value}")),
            (TargetAuthField::Fallback, |auth| auth["fallback"] = json!("passthrough")),
            (TargetAuthField::TargetIdentifier, |auth| auth["target_identifier"] = json!("orders")),
        ];
        for (field, edit) in parts {
            let mut auth = static_secret("key-a");
            edit(&mut auth);
            let recorded = changes(Some(surface(Some(static_secret("key-a")))), Some(surface(Some(auth))));
            assert_eq!(recorded.len(), 1, "{field:?}: {recorded:?}");
            assert_eq!(recorded[0].changed, vec![field]);
        }

        let mut scoped = provider("p-1");
        scoped["method"]["credential_provider"]["scopes"] = json!(["orders.read"]);
        let recorded = changes(Some(surface(Some(provider("p-1")))), Some(surface(Some(scoped))));
        assert_eq!(recorded[0].changed, vec![TargetAuthField::Scopes]);
    }

    #[test]
    fn a_transit_point_leg_is_named_by_its_id_and_alias() {
        let base = surface(None);
        let recorded = changes(
            Some(with_transit_point(base.clone(), Some(static_secret("key-a")))),
            Some(with_transit_point(base, Some(provider("p-1")))),
        );

        assert_eq!(recorded.len(), 1, "{recorded:?}");
        let change = &recorded[0];
        assert_eq!(change.leg, TargetAuthLeg::TransitPoint);
        assert_eq!(
            change
                .transit_point_id
                .as_deref(),
            Some("tp-1")
        );
        assert_eq!(
            change
                .transit_point
                .as_deref(),
            Some("billing")
        );
        assert_eq!(change.surface_variant, "_base_");
        assert_eq!(change.previous_method, TargetAuthMethodKind::StaticSecret);
        assert_eq!(change.method, TargetAuthMethodKind::CredentialProvider);
    }

    #[test]
    fn a_variant_leg_is_named_by_the_variants_id_and_alias() {
        let base = surface(Some(static_secret("key-a")));
        let recorded = changes(
            Some(with_variant(base.clone(), Some(static_secret("key-a")))),
            Some(with_variant(base, Some(provider("p-1")))),
        );

        assert_eq!(recorded.len(), 1, "{recorded:?}");
        let change = &recorded[0];
        assert_eq!(change.leg, TargetAuthLeg::Target);
        assert_eq!(change.surface_variant, "beta");
        assert_eq!(change.variant_id.as_deref(), Some("v-1"));
        assert_eq!(change.method, TargetAuthMethodKind::CredentialProvider);
    }

    #[test]
    fn a_base_change_a_variant_inherits_is_recorded_for_the_variant_too() {
        let recorded = changes(
            Some(with_variant(surface(Some(static_secret("key-a"))), None)),
            Some(with_variant(surface(Some(provider("p-1"))), None)),
        );

        let variants: Vec<_> = recorded
            .iter()
            .map(|change| {
                change
                    .surface_variant
                    .as_str()
            })
            .collect();
        assert_eq!(variants, vec!["_base_", "beta"]);
    }

    #[tokio::test]
    async fn a_management_request_records_the_change_without_a_secret_or_header() {
        let before = parse(with_transit_point(surface(None), Some(static_secret("transit-key"))));
        let after = parse(with_transit_point(surface(Some(static_secret("target-key"))), None));

        let ((), records) = capture(in_management_request(Actor::user("u-1"), async {
            surface_written(Some(&before), Some(&after));
        }))
        .await;

        assert_eq!(records.len(), 2, "{records:?}");
        for record in &records {
            assert_eq!(action_category(&record.event), "target_auth_changed");
            assert!(record.event.is_vp_audit());
            assert_eq!(record.surface_id.as_deref(), Some("s-1"));
            assert_eq!(record.channel_name.as_deref(), Some("Orders"));
            let written = serde_json::to_string(record).unwrap();
            for hidden in ["target-key", "transit-key", "X-Target-Key", "Token {value}", "header", "secret_id"] {
                assert!(!written.contains(hidden), "{hidden} in {written}");
            }
            let json = serde_json::to_value(record).unwrap();
            assert_eq!(json["event"]["target_auth_changed"]["actor"], json!({"kind": "user", "id": "u-1"}));
        }
    }

    #[tokio::test]
    async fn a_write_outside_a_management_request_records_nothing() {
        let after = parse(surface(Some(static_secret("key-a"))));

        let ((), records) = capture(async {
            surface_written(None, Some(&after));
        })
        .await;

        assert!(records.is_empty(), "{records:?}");
    }
}
