//! What still depends on a remote gateway: surfaces that take payments
//! through it, surfaces that route to it over `fabric://`, and payments it
//! holds that are not settled yet.

use std::sync::Arc;

use axum::http::StatusCode;

use crate::config::agent_surface::AgentSurface;
use crate::surfaces::{AgentSurfaceStore, FileSystemAgentSurfaceStore};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GatewayUsage {
    pub payment_surfaces: usize,
    pub fabric_surfaces: usize,
    pub unsettled_payments: usize,
}

impl GatewayUsage {
    pub fn of(
        surfaces: &[AgentSurface],
        gateway_id: &str,
        unsettled_payments: usize,
    ) -> Self {
        let count = |ids: fn(&AgentSurface) -> Vec<&str>| {
            surfaces
                .iter()
                .filter(|surface| ids(surface).contains(&gateway_id))
                .count()
        };
        Self {
            payment_surfaces: count(AgentSurface::payment_gateway_ids),
            fabric_surfaces: count(AgentSurface::fabric_gateway_ids),
            unsettled_payments,
        }
    }

    /// Why the gateway cannot be deleted or disabled while payments depend on it.
    pub fn removal_conflict(&self) -> Option<String> {
        if self.payment_surfaces == 0 && self.unsettled_payments == 0 {
            return None;
        }
        Some(format!(
            "Gateway takes payments for {} surface(s) and holds {} unsettled payment(s); point those surfaces at \
             another payment gateway and wait for the payments to settle first",
            self.payment_surfaces, self.unsettled_payments
        ))
    }
}

pub async fn gateway_usage(
    surface_store: Option<&Arc<FileSystemAgentSurfaceStore>>,
    gateway_id: &str,
) -> Result<GatewayUsage, (StatusCode, String)> {
    let surfaces = surface_store
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Surface store not configured".to_string()))?
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list surfaces: {e}")))?;
    let unsettled = crate::payments_ledger::global()
        .map(|ledger| crate::payments_ledger::unsettled_payments(&ledger, gateway_id))
        .unwrap_or(0);
    Ok(GatewayUsage::of(&surfaces, gateway_id, unsettled))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface(
        id: &str,
        endpoint: &str,
        payment_gateway_id: Option<&str>,
    ) -> AgentSurface {
        let mut surface: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": id,
            "name": id,
            "access_point": {"listen_address": "0.0.0.0:8443", "route": "/x", "protocol": "mcp"},
            "target": {"endpoint": endpoint},
        }))
        .unwrap();
        surface.target.payment_policy = payment_gateway_id.map(|gw| {
            serde_json::from_value(serde_json::json!({
                "type": "agent_pay",
                "payment_gateway_id": gw,
                "payment_surface_id": "pay-1",
            }))
            .unwrap()
        });
        surface
    }

    #[test]
    fn usage_counts_payment_and_fabric_surfaces_of_one_gateway() {
        let surfaces = [
            surface("a", "https://up.example", Some("pay")),
            surface("b", "fabric://pay/s", None),
            surface("c", "fabric://other/s", Some("other")),
        ];
        assert_eq!(
            GatewayUsage::of(&surfaces, "pay", 3),
            GatewayUsage {
                payment_surfaces: 1,
                fabric_surfaces: 1,
                unsettled_payments: 3,
            }
        );
        assert_eq!(GatewayUsage::of(&surfaces, "none", 0), GatewayUsage::default());
    }

    #[test]
    fn only_payment_use_blocks_removal() {
        assert_eq!(
            GatewayUsage {
                fabric_surfaces: 2,
                ..Default::default()
            }
            .removal_conflict(),
            None
        );
        let conflict = GatewayUsage {
            payment_surfaces: 1,
            ..Default::default()
        }
        .removal_conflict()
        .unwrap();
        assert!(conflict.starts_with("Gateway takes payments for 1 surface(s) and holds 0 unsettled payment(s)"));
        assert!(
            GatewayUsage {
                unsettled_payments: 1,
                ..Default::default()
            }
            .removal_conflict()
            .is_some()
        );
    }
}
