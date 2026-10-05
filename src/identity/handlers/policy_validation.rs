use axum::Json;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Validate an x402 payment policy and resolve each requirement's `pay_to`
/// from the global recipient address book.
///
/// Frontend / API callers only supply `recipient_id` (+ `network`). The
/// on-chain address is always re-derived server-side from the global
/// `recipient_addresses` config so a compromised or malicious caller can't
/// redirect payments. `pay_to` is overwritten in place even if the caller
/// pre-populated it.
pub fn validate_payment_policy(
    cfg: &mut crate::config::X402Config,
    recipients: &[crate::identity::handlers::config::X402RecipientAddress],
    label: &str,
) -> Result<(), String> {
    // Delegation mode (`provider = agent_pay`): the whole paywall is delegated
    // to a remote payment surface over `fabric://`. This gateway owns no
    // payment requirements or recipient wallets — the remote surface supplies
    // the 402 challenge. Validate the delegation target instead, and skip the
    // local requirement/recipient resolution below.
    if !cfg.provider.is_local() {
        crate::x402::delegate::delegation_target(cfg).map_err(|e| format!("{label}: {e}"))?;
        return Ok(());
    }

    if cfg
        .payment_requirements
        .is_empty()
    {
        return Err(format!("{label}: at least one payment requirement is required"));
    }
    for req in cfg
        .payment_requirements
        .iter_mut()
    {
        if req
            .recipient_id
            .trim()
            .is_empty()
        {
            return Err(format!("{label}: payment requirement for network '{}' is missing recipient_id", req.network));
        }
        let recipient = recipients
            .iter()
            .find(|r| r.id == req.recipient_id)
            .ok_or_else(|| format!("{label}: unknown recipient_id '{}'", req.recipient_id))?;
        let address = recipient
            .addresses
            .get(&req.network)
            .ok_or_else(|| {
                format!(
                    "{label}: recipient '{}' has no address configured for network '{}'",
                    req.recipient_id, req.network
                )
            })?;
        req.pay_to = address.clone();
    }
    Ok(())
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
    use super::validate_payment_policy;
    use crate::config::X402Config;
    use crate::config::types::X402Provider;

    #[test]
    fn local_provider_requires_at_least_one_requirement() {
        // Default (provider = local) with no requirements is rejected.
        let mut cfg = X402Config::default();
        let err = validate_payment_policy(&mut cfg, &[], "Surface payment policy").unwrap_err();
        assert!(err.contains("at least one payment requirement is required"), "unexpected error: {err}");
    }

    #[test]
    fn delegation_skips_requirement_and_recipient_checks() {
        // Delegation mode (provider = agent_pay) with a valid target must pass
        // even with no payment_requirements and no recipient address book.
        let mut cfg = X402Config {
            provider: X402Provider::AgentPay,
            payment_gateway_id: Some("gw-1".into()),
            payment_surface_id: Some("pay-ch".into()),
            ..Default::default()
        };
        assert!(validate_payment_policy(&mut cfg, &[], "Surface payment policy").is_ok());
    }

    #[test]
    fn delegation_missing_target_is_rejected_with_label() {
        let mut cfg = X402Config {
            provider: X402Provider::AgentPay,
            ..Default::default()
        };
        let err = validate_payment_policy(&mut cfg, &[], "Surface payment policy").unwrap_err();
        assert!(err.contains("payment delegation misconfigured"), "unexpected error: {err}");
        assert!(err.starts_with("Surface payment policy:"), "label must be prefixed: {err}");
    }
}
