use std::collections::HashMap;

use serde_json::json;

use super::delivery::dispatch::dispatch;
use crate::gateways::connection_points::types::GatewayConnectionPoint;

pub fn trigger_connection_point_created(connection_point: &GatewayConnectionPoint) {
    dispatch("connection_point.created", connection_point_values(None, Some(connection_point)));
}

/// Raises nothing when the change leaves what an integration sees as it was.
pub fn trigger_connection_point_updated(
    old_connection_point: &GatewayConnectionPoint,
    new_connection_point: &GatewayConnectionPoint,
) {
    if shared_state(old_connection_point) == shared_state(new_connection_point) {
        return;
    }
    dispatch(
        "connection_point.updated",
        connection_point_values(Some(old_connection_point), Some(new_connection_point)),
    );
}

pub fn trigger_connection_point_deleted(connection_point: &GatewayConnectionPoint) {
    dispatch("connection_point.deleted", connection_point_values(Some(connection_point), None));
}

/// A connection point event's values: the connection point before and after as JSON (empty
/// when absent), and its fields as it is now (or was, once deleted).
fn connection_point_values(
    old: Option<&GatewayConnectionPoint>,
    new: Option<&GatewayConnectionPoint>,
) -> HashMap<String, String> {
    let state = |connection_point: Option<&GatewayConnectionPoint>| {
        connection_point
            .map(|connection_point| shared_state(connection_point).to_string())
            .unwrap_or_default()
    };
    let mut values = HashMap::from([("OLD_STATE".to_string(), state(old)), ("NEW_STATE".to_string(), state(new))]);
    if let Some(connection_point) = new.or(old) {
        values.extend([
            ("CP_ID".to_string(), connection_point.id.clone()),
            ("CP_NAME".to_string(), connection_point.name.clone()),
            (
                "CP_DESCRIPTION".to_string(),
                connection_point
                    .description
                    .clone(),
            ),
            (
                "CP_DID".to_string(),
                connection_point
                    .connection_point_did
                    .clone(),
            ),
            (
                "GATEWAY_ID".to_string(),
                connection_point
                    .gateway_id
                    .clone(),
            ),
            (
                "MEDIATOR_ID".to_string(),
                connection_point
                    .mediator_id
                    .clone(),
            ),
        ]);
    }
    values
}

/// The connection point without its invitation and secret, which let whoever holds them
/// connect.
fn shared_state(connection_point: &GatewayConnectionPoint) -> serde_json::Value {
    json!({
        "id": connection_point.id,
        "gateway_id": connection_point.gateway_id,
        "mediator_id": connection_point.mediator_id,
        "connection_point_did": connection_point.connection_point_did,
        "name": connection_point.name,
        "description": connection_point.description,
        "cp_type": connection_point.cp_type,
        "enabled": connection_point.enabled,
        "exposed_channels": connection_point.exposed_channels,
        "did_method": connection_point.did_method,
        "use_count": connection_point.use_count,
        "expires_at": connection_point.expires_at,
        "created_at": connection_point.created_at,
        "last_used_at": connection_point.last_used_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateways::connection_points::types::ConnectionPointType;
    use crate::integrations::delivery::dispatch::dispatched;

    const SECRET: &str = "pairing-secret-7f3a";
    const OOB_URL: &str = "https://mediator.example/oob?_oobid=oob-7f3a";

    fn connection_point(name: &str) -> GatewayConnectionPoint {
        GatewayConnectionPoint::new(
            "gw-1".to_string(),
            "mediator-1".to_string(),
            "did:peer:cp".to_string(),
            name.to_string(),
            "Order intake".to_string(),
            "oob-7f3a".to_string(),
            OOB_URL.to_string(),
            json!({"_oobid": "oob-7f3a", "secret": SECRET}),
            None,
            ConnectionPointType::User,
            SECRET.to_string(),
        )
    }

    fn json(text: &str) -> serde_json::Value {
        serde_json::from_str(text).expect("json")
    }

    #[test]
    fn a_new_connection_point_has_only_a_new_state() {
        let created = connection_point("Orders");

        let values = connection_point_values(None, Some(&created));

        assert_eq!(values["OLD_STATE"], "");
        let new_state = json(&values["NEW_STATE"]);
        assert_eq!(new_state["id"], created.id);
        assert_eq!(new_state["name"], "Orders");
        assert_eq!(new_state["connection_point_did"], "did:peer:cp");
        assert_eq!(new_state["enabled"], true);
        assert_eq!(values["CP_ID"], created.id);
        assert_eq!(values["CP_NAME"], "Orders");
        assert_eq!(values["CP_DESCRIPTION"], "Order intake");
        assert_eq!(values["CP_DID"], "did:peer:cp");
        assert_eq!(values["GATEWAY_ID"], "gw-1");
        assert_eq!(values["MEDIATOR_ID"], "mediator-1");
    }

    #[test]
    fn an_update_has_both_states_and_the_fields_as_they_are_now() {
        let old = connection_point("Orders");
        let mut new = old.clone();
        new.name = "Returns".to_string();
        new.enabled = false;

        let values = connection_point_values(Some(&old), Some(&new));

        assert_eq!(json(&values["OLD_STATE"])["name"], "Orders");
        assert_eq!(json(&values["NEW_STATE"])["name"], "Returns");
        assert_eq!(json(&values["NEW_STATE"])["enabled"], false);
        assert_eq!(values["CP_NAME"], "Returns");
    }

    #[test]
    fn a_deleted_connection_point_has_only_an_old_state_and_its_last_fields() {
        let deleted = connection_point("Orders");

        let values = connection_point_values(Some(&deleted), None);

        assert_eq!(values["NEW_STATE"], "");
        assert_eq!(json(&values["OLD_STATE"])["name"], "Orders");
        assert_eq!(values["CP_ID"], deleted.id);
        assert_eq!(values["CP_NAME"], "Orders");
    }

    #[test]
    fn the_invitation_and_secret_are_never_sent() {
        let old = connection_point("Orders");
        let new = connection_point("Returns");

        let values = connection_point_values(Some(&old), Some(&new));

        for state in [&values["OLD_STATE"], &values["NEW_STATE"]] {
            let state = json(state);
            for field in ["secret", "oob_id", "oob_url", "oob_message", "runtime_status"] {
                assert!(state.get(field).is_none(), "{field}");
            }
        }
        for (name, value) in &values {
            assert!(!value.contains(SECRET), "{name}");
            assert!(!value.contains("oob-7f3a"), "{name}");
        }
    }

    #[test]
    fn the_state_names_the_exposed_surfaces() {
        let mut exposing = connection_point("Orders");
        exposing.exposed_channels = vec!["surface-1".to_string()];

        let values = connection_point_values(None, Some(&exposing));

        assert_eq!(json(&values["NEW_STATE"])["exposed_channels"], json!(["surface-1"]));
    }

    #[tokio::test]
    async fn an_update_that_changes_nothing_raises_nothing() {
        let unchanged = connection_point("Orders");

        trigger_connection_point_updated(&unchanged, &unchanged.clone());

        assert!(dispatched::with("CP_ID", &unchanged.id).is_empty());
    }

    #[tokio::test]
    async fn changing_the_exposed_surfaces_raises_updated() {
        let old = connection_point("Orders");
        let mut new = old.clone();
        new.exposed_channels = vec!["surface-1".to_string()];

        trigger_connection_point_updated(&old, &new);

        assert_eq!(dispatched::with("CP_ID", &old.id), ["connection_point.updated"]);
    }
}
