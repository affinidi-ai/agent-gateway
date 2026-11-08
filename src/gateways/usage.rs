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
    /// `None` when the payments ledger is not available, so it is not known.
    pub unsettled_payments: Option<usize>,
}

impl GatewayUsage {
    pub fn of(
        surfaces: &[AgentSurface],
        gateway_id: &str,
        unsettled_payments: Option<usize>,
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

    /// Why `gateway` cannot be deleted or disabled: `409` while payments depend
    /// on it, and `503` for a payment gateway while the payments ledger, which
    /// would say whether it holds unsettled payments, is not available.
    pub fn removal_refusal(
        &self,
        gateway: &super::types::Gateway,
    ) -> Option<(StatusCode, String)> {
        let unsettled = self
            .unsettled_payments
            .unwrap_or(0);
        if self.payment_surfaces > 0 || unsettled > 0 {
            return Some((
                StatusCode::CONFLICT,
                format!(
                    "Gateway takes payments for {} surface(s) and holds {unsettled} unsettled payment(s); point \
                     those surfaces at another payment gateway and wait for the payments to settle first",
                    self.payment_surfaces
                ),
            ));
        }
        (self
            .unsettled_payments
            .is_none()
            && gateway.is_payment_gateway())
        .then(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "The payments ledger is not available, so whether this payment gateway holds unsettled payments \
                 is not known; try again once it is"
                    .to_string(),
            )
        })
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
    let unsettled =
        crate::payments_ledger::global().map(|ledger| crate::payments_ledger::unsettled_payments(&ledger, gateway_id));
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
            GatewayUsage::of(&surfaces, "pay", Some(3)),
            GatewayUsage {
                payment_surfaces: 1,
                fabric_surfaces: 1,
                unsettled_payments: Some(3),
            }
        );
        assert_eq!(GatewayUsage::of(&surfaces, "none", None), GatewayUsage::default());
    }

    fn gateway(role: super::super::types::GatewayRole) -> super::super::types::Gateway {
        let mut gateway = super::super::types::Gateway::new(
            "gw".into(),
            String::new(),
            "did:web:gw.example".into(),
            super::super::types::GatewayType::Remote,
        );
        gateway.role = role;
        gateway
    }

    #[test]
    fn only_payment_use_blocks_removal() {
        use super::super::types::GatewayRole;

        let payment = gateway(GatewayRole::Payment);
        let idle = |usage: GatewayUsage| GatewayUsage {
            unsettled_payments: Some(0),
            ..usage
        };
        assert_eq!(
            idle(GatewayUsage {
                fabric_surfaces: 2,
                ..Default::default()
            })
            .removal_refusal(&payment),
            None
        );
        let (status, conflict) = idle(GatewayUsage {
            payment_surfaces: 1,
            ..Default::default()
        })
        .removal_refusal(&payment)
        .unwrap();
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(conflict.starts_with("Gateway takes payments for 1 surface(s) and holds 0 unsettled payment(s)"));
        assert_eq!(
            GatewayUsage {
                unsettled_payments: Some(1),
                ..Default::default()
            }
            .removal_refusal(&payment)
            .map(|(status, _)| status),
            Some(StatusCode::CONFLICT)
        );
    }

    #[test]
    fn a_payment_gateway_is_not_removed_while_the_ledger_is_unavailable() {
        use super::super::types::GatewayRole;

        let unknown = GatewayUsage::default();
        assert_eq!(
            unknown
                .removal_refusal(&gateway(GatewayRole::Payment))
                .map(|(status, _)| status),
            Some(StatusCode::SERVICE_UNAVAILABLE)
        );
        assert_eq!(unknown.removal_refusal(&gateway(GatewayRole::Peer)), None, "a peer holds no payments");
    }
}
