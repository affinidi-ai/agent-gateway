use axum::Json;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::config::agent_surface::{AgentPayPolicy, AgentSurface};
use crate::gateways::payment_manifest::{ManifestFetchError, PaymentManifest};

/// Payment settings on a resolved surface that this gateway no longer
/// supports: an enabled local x402 or MPP policy, MPP auto-pay, and payment
/// policies on Transit Points. Returns one message per problem.
pub fn unsupported_payment_settings(surface: &AgentSurface) -> Vec<String> {
    let mut problems = Vec::new();
    if surface.payment_policy_unsupported() {
        problems.push(
            "local x402/MPP payment policies are no longer supported; use an agent_pay payment policy".to_string(),
        );
    }
    if surface.target.mpp_auto_pay
        || surface
            .target
            .mpp_auto_pay_max_amount
            .as_deref()
            .is_some_and(|amount| !amount.trim().is_empty())
    {
        problems.push("mpp_auto_pay and mpp_auto_pay_max_amount are no longer supported".to_string());
    }
    for point in surface
        .transit
        .iter()
        .flat_map(|transit| transit.points.iter())
        .filter(|point| point.payment_policy.is_some())
    {
        problems.push(format!("Transit Point '{}': payment_policy is no longer supported", point.name));
    }
    problems
}

/// An `agent_pay` policy must name a connected, user-created Remote gateway.
pub fn check_payment_gateway(gateway: &crate::gateways::types::Gateway) -> Result<(), String> {
    if gateway.gateway_type != crate::gateways::types::GatewayType::Remote
        || gateway.creation_type != crate::gateways::types::GatewayCreationType::User
    {
        return Err(format!("payment gateway '{}' is not a user-created Remote gateway", gateway.id));
    }
    Ok(())
}

/// How fetching the payment surface's manifest affects a save.
#[derive(Debug, PartialEq)]
pub enum ManifestOutcome {
    /// The manifest was fetched and stored as the policy's snapshot.
    Verified,
    /// The payment gateway did not answer; the save goes ahead unverified.
    Unverified(String),
}

/// The snapshot `stored` already holds when it names the same payment gateway
/// and payment surface as `policy`, which a save keeps while the payment
/// gateway cannot be asked again.
pub fn verified_snapshot<'a>(
    policy: &AgentPayPolicy,
    stored: Option<&'a AgentPayPolicy>,
) -> Option<&'a PaymentManifest> {
    stored
        .filter(|stored| {
            stored.payment_gateway_id == policy.payment_gateway_id
                && stored.payment_surface_id == policy.payment_surface_id
        })
        .and_then(|stored| {
            stored
                .manifest_snapshot
                .as_ref()
        })
}

/// Replaces the policy's `manifest_snapshot` with the freshly fetched
/// manifest. A manifest that is missing or offers no payment point refuses
/// the save. An unreachable payment gateway leaves the policy unverified and
/// keeps `retained`, the snapshot already verified for the same payment
/// surface, when there is one.
pub fn apply_manifest(
    policy: &mut AgentPayPolicy,
    fetched: Result<Option<PaymentManifest>, ManifestFetchError>,
    retained: Option<&PaymentManifest>,
) -> Result<ManifestOutcome, String> {
    policy.manifest_snapshot = None;
    match fetched {
        Ok(Some(manifest)) if manifest.is_payable() => {
            policy.manifest_snapshot = Some(manifest);
            Ok(ManifestOutcome::Verified)
        }
        Ok(Some(_)) => Err(format!("payment surface '{}' offers no payment points", policy.payment_surface_id)),
        Ok(None) => Err(format!(
            "payment surface '{}' is not a payment surface on the payment gateway",
            policy.payment_surface_id
        )),
        Err(ManifestFetchError::Rejected(_)) => {
            Err(format!("the payment gateway refused to describe payment surface '{}'", policy.payment_surface_id))
        }
        Err(ManifestFetchError::Unavailable(_)) => {
            policy.manifest_snapshot = retained.cloned();
            Ok(ManifestOutcome::Unverified(format!(
                "the payment gateway could not be reached, so payment surface '{}' was not verified{}",
                policy.payment_surface_id,
                if retained.is_some() {
                    "; its last verified manifest was kept"
                } else {
                    ""
                }
            )))
        }
    }
}

/// Request body for validating OPA policy
#[derive(Debug, Deserialize)]
pub struct ValidatePolicyRequest {
    pub policy: String,
}

/// Response for policy validation
#[derive(Debug, Serialize)]
pub struct ValidatePolicyResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Validate OPA/Rego policy syntax
pub async fn validate_policy(Json(payload): Json<ValidatePolicyRequest>) -> Json<ValidatePolicyResponse> {
    debug!("Validating OPA policy (length: {} bytes)", payload.policy.len());

    // Empty policy is valid
    if payload
        .policy
        .trim()
        .is_empty()
    {
        return Json(ValidatePolicyResponse { valid: true, error: None });
    }

    // Try to load the policy to validate syntax
    let test_engine = crate::policies::OpaEngine::new();
    match test_engine.load_policy("test_validation", &payload.policy) {
        Ok(_) => {
            debug!("Policy validation successful");
            Json(ValidatePolicyResponse { valid: true, error: None })
        }
        Err(e) => {
            debug!("Policy validation failed: {}", e);
            Json(ValidatePolicyResponse { valid: false, error: Some(e) })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateways::payment_manifest::PaymentPoint;
    use crate::gateways::types::{Gateway, GatewayCreationType, GatewayType};

    fn payable_manifest() -> PaymentManifest {
        PaymentManifest {
            payment_points: vec![PaymentPoint {
                id: "x402:base".into(),
                protocol: "x402".into(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn policy_with_client_snapshot() -> AgentPayPolicy {
        AgentPayPolicy {
            payment_gateway_id: "gw-1".into(),
            payment_surface_id: "pay-1".into(),
            manifest_snapshot: Some(PaymentManifest {
                version: "client-supplied".into(),
                ..payable_manifest()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn a_payable_manifest_replaces_the_client_snapshot() {
        let mut policy = policy_with_client_snapshot();
        assert_eq!(apply_manifest(&mut policy, Ok(Some(payable_manifest())), None), Ok(ManifestOutcome::Verified));
        assert_eq!(policy.manifest_snapshot, Some(payable_manifest()));
    }

    #[test]
    fn a_missing_or_empty_manifest_refuses_the_save() {
        let mut policy = policy_with_client_snapshot();
        let err = apply_manifest(&mut policy, Ok(None), None).unwrap_err();
        assert_eq!(err, "payment surface 'pay-1' is not a payment surface on the payment gateway");
        assert_eq!(policy.manifest_snapshot, None);

        let err = apply_manifest(&mut policy, Ok(Some(PaymentManifest::default())), None).unwrap_err();
        assert_eq!(err, "payment surface 'pay-1' offers no payment points");
        assert_eq!(policy.manifest_snapshot, None);
    }

    #[test]
    fn a_refusing_peer_refuses_the_save() {
        let mut policy = policy_with_client_snapshot();
        let err = apply_manifest(&mut policy, Err(ManifestFetchError::Rejected("channel not exposed".into())), None)
            .unwrap_err();
        assert_eq!(err, "the payment gateway refused to describe payment surface 'pay-1'");
        assert_eq!(policy.manifest_snapshot, None);
    }

    #[test]
    fn an_unreachable_peer_leaves_the_policy_unverified_without_a_snapshot() {
        let mut policy = policy_with_client_snapshot();
        let outcome =
            apply_manifest(&mut policy, Err(ManifestFetchError::Unavailable("timeout".into())), None).unwrap();
        assert_eq!(
            outcome,
            ManifestOutcome::Unverified(
                "the payment gateway could not be reached, so payment surface 'pay-1' was not verified".into()
            )
        );
        assert_eq!(policy.manifest_snapshot, None);
    }

    fn stored_policy(
        gateway: &str,
        surface: &str,
        snapshot: Option<PaymentManifest>,
    ) -> AgentPayPolicy {
        AgentPayPolicy {
            payment_gateway_id: gateway.into(),
            payment_surface_id: surface.into(),
            manifest_snapshot: snapshot,
            ..Default::default()
        }
    }

    #[test]
    fn an_unreachable_peer_keeps_the_snapshot_already_verified_for_the_same_payment_surface() {
        let verified = PaymentManifest {
            version: "verified".into(),
            ..payable_manifest()
        };
        let stored = stored_policy("gw-1", "pay-1", Some(verified.clone()));
        let mut policy = policy_with_client_snapshot();
        let retained = verified_snapshot(&policy, Some(&stored));
        assert_eq!(retained, Some(&verified));

        let outcome =
            apply_manifest(&mut policy, Err(ManifestFetchError::Unavailable("timeout".into())), retained).unwrap();
        assert_eq!(
            outcome,
            ManifestOutcome::Unverified(
                "the payment gateway could not be reached, so payment surface 'pay-1' was not verified; its last \
                 verified manifest was kept"
                    .into()
            )
        );
        assert_eq!(policy.manifest_snapshot, Some(verified));
    }

    #[test]
    fn a_snapshot_is_kept_only_for_the_same_payment_gateway_and_surface() {
        let policy = stored_policy("gw-1", "pay-1", None);
        let snapshot = Some(payable_manifest());
        assert!(verified_snapshot(&policy, Some(&stored_policy("gw-1", "pay-1", snapshot.clone()))).is_some());
        assert!(verified_snapshot(&policy, Some(&stored_policy("gw-2", "pay-1", snapshot.clone()))).is_none());
        assert!(verified_snapshot(&policy, Some(&stored_policy("gw-1", "pay-2", snapshot))).is_none());
        assert!(verified_snapshot(&policy, Some(&stored_policy("gw-1", "pay-1", None))).is_none());
        assert!(verified_snapshot(&policy, None).is_none());
    }

    #[test]
    fn a_reachable_peer_replaces_a_retained_snapshot_and_a_refusal_drops_it() {
        let retained = payable_manifest();
        let fresh = PaymentManifest {
            version: "fresh".into(),
            ..payable_manifest()
        };
        let mut policy = policy_with_client_snapshot();
        assert_eq!(
            apply_manifest(&mut policy, Ok(Some(fresh.clone())), Some(&retained)),
            Ok(ManifestOutcome::Verified)
        );
        assert_eq!(policy.manifest_snapshot, Some(fresh));

        assert!(apply_manifest(&mut policy, Ok(None), Some(&retained)).is_err());
        assert_eq!(policy.manifest_snapshot, None);
        assert!(apply_manifest(&mut policy, Err(ManifestFetchError::Rejected("no".into())), Some(&retained)).is_err());
        assert_eq!(policy.manifest_snapshot, None);
    }

    #[test]
    fn only_user_created_remote_gateways_take_payments() {
        let gateway = |gateway_type, creation_type| {
            Gateway::new_with_creation_type(
                "gw".into(),
                String::new(),
                "did:web:gw".into(),
                gateway_type,
                creation_type,
            )
        };
        assert!(check_payment_gateway(&gateway(GatewayType::Remote, GatewayCreationType::User)).is_ok());
        let system = gateway(GatewayType::Remote, GatewayCreationType::System);
        assert_eq!(
            check_payment_gateway(&system),
            Err(format!("payment gateway '{}' is not a user-created Remote gateway", system.id))
        );
        assert!(check_payment_gateway(&gateway(GatewayType::SelfGateway, GatewayCreationType::User)).is_err());
    }

    #[test]
    fn a_surface_without_local_payment_settings_has_no_problems() {
        let surface = AgentSurface::default();
        assert!(unsupported_payment_settings(&surface).is_empty());
    }

    #[test]
    fn a_blank_auto_pay_cap_is_not_a_problem_but_a_set_one_is() {
        let mut surface = AgentSurface::default();
        surface
            .target
            .mpp_auto_pay_max_amount = Some("  ".into());
        assert!(unsupported_payment_settings(&surface).is_empty());
        surface
            .target
            .mpp_auto_pay_max_amount = Some("0.50".into());
        assert_eq!(
            unsupported_payment_settings(&surface),
            vec!["mpp_auto_pay and mpp_auto_pay_max_amount are no longer supported".to_string()]
        );
    }
}
