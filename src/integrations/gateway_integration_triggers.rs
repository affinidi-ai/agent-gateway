use std::collections::HashMap;

use super::delivery::dispatch::dispatch;
use crate::gateways::types::Gateway;

pub fn trigger_gateway_created(gateway: &Gateway) {
    dispatch("gateway.created", gateway_values(None, Some(gateway)));
}

/// Also raises `gateway.status_changed` when the status changed.
pub fn trigger_gateway_updated(
    old_gateway: &Gateway,
    new_gateway: &Gateway,
) {
    dispatch("gateway.updated", gateway_values(Some(old_gateway), Some(new_gateway)));
    if format!("{:?}", old_gateway.status) != format!("{:?}", new_gateway.status) {
        dispatch("gateway.status_changed", gateway_values(Some(old_gateway), Some(new_gateway)));
    }
}

pub fn trigger_gateway_deleted(gateway: &Gateway) {
    dispatch("gateway.deleted", gateway_values(Some(gateway), None));
}

pub fn trigger_gateway_accessed(gateway: &Gateway) {
    dispatch("gateway.accessed", gateway_values(None, Some(gateway)));
}

/// A gateway event's values: the gateway before and after as JSON (empty when absent), the
/// gateway's fields as it is now (or was, once deleted), and its previous status.
fn gateway_values(
    old: Option<&Gateway>,
    new: Option<&Gateway>,
) -> HashMap<String, String> {
    let state = |gateway: Option<&Gateway>| {
        gateway
            .map(|gateway| serde_json::to_string(gateway).unwrap_or_default())
            .unwrap_or_default()
    };
    let mut values = HashMap::from([("OLD_STATE".to_string(), state(old)), ("NEW_STATE".to_string(), state(new))]);
    if let Some(gateway) = new.or(old) {
        values.extend([
            ("GATEWAY_ID".to_string(), gateway.id.clone()),
            ("GATEWAY_NAME".to_string(), gateway.name.clone()),
            ("GATEWAY_DESCRIPTION".to_string(), gateway.description.clone()),
            ("GATEWAY_DID".to_string(), gateway.did.clone()),
            ("GATEWAY_TYPE".to_string(), format!("{:?}", gateway.gateway_type)),
            ("GATEWAY_STATUS".to_string(), format!("{:?}", gateway.status)),
        ]);
    }
    if let (Some(old), Some(_)) = (old, new) {
        values.insert("GATEWAY_OLD_STATUS".to_string(), format!("{:?}", old.status));
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateways::types::{GatewayStatus, GatewayType};

    fn gateway(name: &str) -> Gateway {
        Gateway::new(
            name.to_string(),
            "Edge gateway".to_string(),
            "did:web:edge.example".to_string(),
            GatewayType::Remote,
        )
    }

    #[test]
    fn a_new_gateway_has_only_a_new_state() {
        let created = gateway("edge");

        let values = gateway_values(None, Some(&created));

        assert_eq!(values["OLD_STATE"], "");
        let new_state: serde_json::Value = serde_json::from_str(&values["NEW_STATE"]).expect("json");
        assert_eq!(new_state["name"], "edge");
        assert_eq!(values["GATEWAY_ID"], created.id);
        assert_eq!(values["GATEWAY_NAME"], "edge");
        assert_eq!(values["GATEWAY_DESCRIPTION"], "Edge gateway");
        assert_eq!(values["GATEWAY_DID"], "did:web:edge.example");
        assert_eq!(values["GATEWAY_TYPE"], "Remote");
        assert!(!values.contains_key("GATEWAY_OLD_STATUS"));
    }

    #[test]
    fn a_change_describes_the_gateway_as_it_is_now_and_its_previous_status() {
        let before = gateway("edge");
        let mut after = before.clone();
        after.name = "edge-renamed".to_string();
        after.status = GatewayStatus::Disabled;

        let values = gateway_values(Some(&before), Some(&after));

        assert_eq!(values["GATEWAY_NAME"], "edge-renamed");
        assert_eq!(values["GATEWAY_STATUS"], "Disabled");
        assert_eq!(values["GATEWAY_OLD_STATUS"], format!("{:?}", before.status));
        let old_state: serde_json::Value = serde_json::from_str(&values["OLD_STATE"]).expect("json");
        assert_eq!(old_state["name"], "edge");
    }

    #[test]
    fn a_deleted_gateway_is_described_as_it_was() {
        let deleted = gateway("edge");

        let values = gateway_values(Some(&deleted), None);

        assert_eq!(values["NEW_STATE"], "");
        assert_eq!(values["GATEWAY_NAME"], "edge");
    }
}
