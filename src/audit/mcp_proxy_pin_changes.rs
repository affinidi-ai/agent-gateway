//! Records of management saves that changed the pin of a `proxy://` Transit Point's
//! `consent_mode: external` binding: the MCP Proxy state its grant may go through and its tools
//! be shown in. Each names the actor of the management request it is built in and is written
//! only when a sink selects its event; each is also logged at info, with the pins and ids only.

use std::collections::BTreeMap;

use tracing::info;

use crate::audit::context::current_actor;
use crate::audit::events::Actor;
use crate::config::agent_surface::AgentSurface;
use crate::config::agent_surface_variants::SurfaceVariant;
use crate::delegation_vault::audit::{
    DelegationAuditAction, McpProxyPinChangeDetails, action_category, audit_event, emit,
};

/// A pinned binding: where it is held, its Transit Point, its MCP Proxy and its pin.
struct Pinned {
    surface_variant: String,
    variant_id: Option<String>,
    transit_point: String,
    mcp_proxy_id: String,
    pin: String,
}

/// The pinned bindings of `surface` by Transit Point id: those of its own Transit Points and of
/// each variant's own. Such a Transit Point id names one Transit Point in one place.
fn pinned(surface: Option<&AgentSurface>) -> BTreeMap<String, Pinned> {
    let mut pinned = BTreeMap::new();
    let Some(surface) = surface else {
        return pinned;
    };
    let lists = surface
        .transit
        .iter()
        .map(|transit| (None, transit.points.as_slice()))
        .chain(
            surface
                .variants
                .iter()
                .filter_map(|variant| {
                    variant
                        .overrides
                        .transit
                        .as_ref()
                        .and_then(|transit| transit.points.as_deref())
                        .map(|points| (Some(variant), points))
                }),
        );
    for (variant, points) in lists {
        for point in points {
            let Some(binding) = point
                .transit_credentials
                .as_ref()
                .filter(|binding| binding.is_external())
            else {
                continue;
            };
            let (Some(pin), Some(mcp_proxy_id)) =
                (binding.mcp_proxy_pin.as_ref(), crate::mcp_proxies::types::transit_proxy_id(&point.target_endpoint))
            else {
                continue;
            };
            pinned.insert(
                point.id.clone(),
                Pinned {
                    surface_variant: variant
                        .map_or(SurfaceVariant::BASE, |variant| variant.alias.as_str())
                        .to_string(),
                    variant_id: variant.map(|variant| variant.id.clone()),
                    transit_point: point.alias.clone(),
                    mcp_proxy_id: mcp_proxy_id.to_string(),
                    pin: pin.clone(),
                },
            );
        }
    }
    pinned
}

/// One record for each binding `after` pins differently from `before`, in Transit Point id
/// order: a binding pinned for the first time (no `previous_pin`, as a new binding, or one that
/// names another proxy than before), or one pinned to the same proxy as it is now in place of the
/// pin it had. A binding that lost its pin, or that `after` no longer has, is not one.
pub fn mcp_proxy_pin_changes(
    actor: &Actor,
    before: Option<&AgentSurface>,
    after: Option<&AgentSurface>,
) -> Vec<McpProxyPinChangeDetails> {
    let previous = pinned(before);
    pinned(after)
        .into_iter()
        .filter_map(|(transit_point_id, now)| {
            let previous_pin = previous
                .get(&transit_point_id)
                .filter(|previous| previous.mcp_proxy_id == now.mcp_proxy_id)
                .map(|previous| previous.pin.clone());
            (previous_pin.as_deref() != Some(now.pin.as_str())).then(|| McpProxyPinChangeDetails {
                actor: actor.clone(),
                surface_variant: now.surface_variant,
                variant_id: now.variant_id,
                transit_point_id,
                transit_point: now.transit_point,
                mcp_proxy_id: now.mcp_proxy_id,
                previous_pin,
                pin: now.pin,
            })
        })
        .collect()
}

/// Records and logs [`mcp_proxy_pin_changes`] of a surface write. Writes nothing outside a
/// management request: startup migrations, replication and configuration reloads keep the
/// stored pins and are not user changes.
pub fn surface_written(
    before: Option<&AgentSurface>,
    after: Option<&AgentSurface>,
) {
    let Some(actor) = current_actor() else {
        return;
    };
    let Some(surface) = after else {
        return;
    };
    for change in mcp_proxy_pin_changes(&actor, before, after) {
        info!(
            target: "credential_delegation",
            surface_id = ?surface.surface_id,
            surface_variant = ?change.surface_variant,
            transit_point_id = ?change.transit_point_id,
            transit_point = ?change.transit_point,
            mcp_proxy_id = ?change.mcp_proxy_id,
            previous_pin = ?change.previous_pin,
            pin = ?change.pin,
            "A surface save pinned a Transit Point's grant binding to its MCP Proxy as the proxy is now"
        );
        let action = DelegationAuditAction::McpProxyPinChanged(Box::new(change));
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
    use crate::audit::producer::capture;
    use serde_json::{Value, json};

    fn surface(
        points: Value,
        variant_points: Option<Value>,
    ) -> AgentSurface {
        let mut surface = json!({
            "surface_id": "s-1",
            "name": "Drive agent",
            "access_point": { "listen_address": "0.0.0.0:8443", "route": "/drive", "protocol": "mcp" },
            "target": { "endpoint": "https://upstream" },
            "transit": { "points": points },
        });
        if let Some(points) = variant_points {
            surface["variants"] = json!([{ "id": "v-1", "alias": "beta", "name": "Beta",
                "overrides": { "transit": { "points": points } } }]);
        }
        serde_json::from_value(surface).unwrap()
    }

    fn point(
        id: &str,
        endpoint: &str,
        pin: Option<&str>,
    ) -> Value {
        let mut binding = json!({ "credential_provider_id": "google", "consent_mode": "external",
            "subject": "owner" });
        if let Some(pin) = pin {
            binding["mcp_proxy_pin"] = json!(pin);
        }
        json!({ "id": id, "alias": format!("{id}-alias"), "target_endpoint": endpoint, "protocol": "mcp",
            "transit_credentials": binding })
    }

    /// A pin new to its binding and a pin replaced for the same proxy are each one change,
    /// with the earlier pin when there was one; an unchanged pin, a binding that lost its pin
    /// and a binding of an `https` Transit Point are none.
    #[test]
    fn a_new_or_replaced_pin_is_a_change_and_an_unchanged_one_is_not() {
        let actor = Actor::user("u-1");
        let before = surface(
            json!([
                point("tp-same", "proxy://drive", Some("sha256:aa")),
                point("tp-moved", "proxy://drive", Some("sha256:aa")),
                point("tp-lost", "proxy://drive", Some("sha256:aa")),
                point("tp-https", "https://vendor.example/mcp", None),
            ]),
            Some(json!([point("tp-variant", "proxy://drive", Some("sha256:aa"))])),
        );
        let after = surface(
            json!([
                point("tp-same", "proxy://drive", Some("sha256:aa")),
                point("tp-moved", "proxy://drive", Some("sha256:bb")),
                point("tp-lost", "proxy://drive", None),
                point("tp-https", "https://vendor.example/mcp", None),
                point("tp-new", "proxy://sheets", Some("sha256:cc")),
            ]),
            Some(json!([point("tp-variant", "proxy://drive", Some("sha256:bb"))])),
        );
        let changes = mcp_proxy_pin_changes(&actor, Some(&before), Some(&after));
        let seen: Vec<_> = changes
            .iter()
            .map(|change| {
                (
                    change
                        .transit_point_id
                        .as_str(),
                    change
                        .surface_variant
                        .as_str(),
                    change.mcp_proxy_id.as_str(),
                    change.previous_pin.as_deref(),
                    change.pin.as_str(),
                )
            })
            .collect();
        assert_eq!(
            seen,
            [
                ("tp-moved", "_base_", "drive", Some("sha256:aa"), "sha256:bb"),
                ("tp-new", "_base_", "sheets", None, "sha256:cc"),
                ("tp-variant", "beta", "drive", Some("sha256:aa"), "sha256:bb"),
            ]
        );
        assert_eq!(
            changes[2]
                .variant_id
                .as_deref(),
            Some("v-1")
        );
        assert!(mcp_proxy_pin_changes(&actor, Some(&after), Some(&after)).is_empty());
    }

    /// A save in a management request records each change, naming the surface, the Transit
    /// Point, the proxy and the pins, and logs it; outside one it records nothing.
    #[tokio::test]
    async fn a_management_save_records_and_logs_each_change() {
        use crate::component_tests::helpers::formatted_logs::FormattedLogs;
        let before = surface(json!([point("tp-1", "proxy://drive", Some("sha256:aa"))]), None);
        let after = surface(json!([point("tp-1", "proxy://drive", Some("sha256:bb"))]), None);
        let logs = FormattedLogs::capture();
        let ((), records) =
            capture(in_management_request(Actor::user("u-1"), async { surface_written(Some(&before), Some(&after)) }))
                .await;
        assert_eq!(records.len(), 1);
        assert_eq!(action_category(&records[0].event), "mcp_proxy_pin_changed");
        assert!(records[0].event.is_vp_audit());
        assert_eq!(
            records[0]
                .surface_id
                .as_deref(),
            Some("s-1")
        );
        let stored = serde_json::to_value(&records[0].event).unwrap();
        let change = &stored["mcp_proxy_pin_changed"];
        assert_eq!(
            (
                change["transit_point_id"].clone(),
                change["transit_point"].clone(),
                change["mcp_proxy_id"].clone(),
                change["previous_pin"].clone(),
                change["pin"].clone()
            ),
            (json!("tp-1"), json!("tp-1-alias"), json!("drive"), json!("sha256:aa"), json!("sha256:bb"))
        );
        let text = logs.text();
        assert!(
            text.contains(r#"transit_point_id="tp-1""#)
                && text.contains(r#"mcp_proxy_id="drive""#)
                && text.contains(r#"previous_pin=Some("sha256:aa")"#)
                && text.contains(r#"pin="sha256:bb""#),
            "{text}"
        );

        let ((), records) = capture(async { surface_written(Some(&before), Some(&after)) }).await;
        assert!(records.is_empty(), "not a management change: {records:?}");
    }
}
