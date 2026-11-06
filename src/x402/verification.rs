use axum::http::HeaderMap;

use crate::config::types::X402PaymentRequirement;

/// The x402 payment signature a request carries in `payment_signature_header`.
pub fn extract_payment_signature(
    headers: &HeaderMap,
    payment_signature_header: &str,
) -> Option<String> {
    headers
        .get(payment_signature_header)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Resolve which of the surface's issued payment requirements a caller's `accepted` refers to.
///
/// `accepted` is caller-controlled. It must name an issued requirement exactly in everything
/// verification and settlement act on: scheme, network, asset, recipient, amount, asset transfer
/// method, and the EIP-712 domain `name` and `version` in `extra`. The amount must equal the
/// configured one for both `exact` and `upto`, since `upto` settles the amount the payer
/// authorised as the maximum. EVM addresses compare case-insensitively, as the 402 challenge
/// issues them lowercased.
pub(crate) fn resolve_payment_requirement(
    accepted: &X402PaymentRequirement,
    issued: &[X402PaymentRequirement],
) -> Result<X402PaymentRequirement, String> {
    let mut accepted = accepted.clone();
    super::normalize_requirement_addresses(&mut accepted);
    issued
        .iter()
        .find(|requirement| {
            matches!(requirement.scheme.as_str(), "exact" | "upto")
                && requirement.scheme == accepted.scheme
                && requirement.network == accepted.network
                && requirement.asset == accepted.asset
                && requirement.pay_to == accepted.pay_to
                && same_amount(&accepted.amount, &requirement.amount)
                && requirement.asset_transfer_method() == accepted.asset_transfer_method()
                && eip712_domain_of(requirement) == eip712_domain_of(&accepted)
        })
        .cloned()
        .ok_or_else(|| "Payment does not match any payment requirement issued for this resource".to_string())
}

fn same_amount(
    offered: &str,
    required: &str,
) -> bool {
    use alloy::primitives::U256;
    matches!(
        (U256::from_str_radix(offered, 10), U256::from_str_radix(required, 10)),
        (Ok(offered), Ok(required)) if offered == required
    )
}

fn eip712_domain_of(requirement: &X402PaymentRequirement) -> (Option<&str>, Option<&str>) {
    let field = |name: &str| {
        requirement
            .extra
            .as_ref()
            .and_then(|extra| extra.get(name))
            .and_then(|value| value.as_str())
    };
    (field("name"), field("version"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MERCHANT: &str = "0x00000000000000000000000000000000000000AA";
    const ATTACKER: &str = "0x00000000000000000000000000000000000000BB";
    const TOKEN: &str = "0x00000000000000000000000000000000000000CC";

    fn requirement(
        scheme: &str,
        pay_to: &str,
        amount: &str,
    ) -> X402PaymentRequirement {
        X402PaymentRequirement {
            scheme: scheme.to_string(),
            network: "eip155:1".to_string(),
            amount: amount.to_string(),
            asset: TOKEN.to_string(),
            recipient_id: String::new(),
            pay_to: pay_to.to_string(),
            max_timeout_seconds: 300,
            extra: Some(serde_json::json!({"name": "USDC", "version": "2", "assetTransferMethod": "eip3009"})),
        }
    }

    fn configured() -> X402PaymentRequirement {
        requirement("exact", MERCHANT, "1000000")
    }

    const NOT_ISSUED: &str = "Payment does not match any payment requirement issued for this resource";

    fn issued(requirements: &[X402PaymentRequirement]) -> Vec<X402PaymentRequirement> {
        requirements
            .iter()
            .cloned()
            .map(|mut requirement| {
                crate::x402::normalize_requirement_addresses(&mut requirement);
                requirement
            })
            .collect()
    }

    #[test]
    fn resolves_accepted_echoing_the_issued_requirement() {
        let issued = issued(&[configured()]);

        let resolved = resolve_payment_requirement(&issued[0], &issued).unwrap();

        assert_eq!(resolved.pay_to, MERCHANT.to_lowercase());
        assert_eq!(resolved.asset, TOKEN.to_lowercase());
        assert_eq!(resolved.amount, "1000000");
    }

    #[test]
    fn resolves_evm_addresses_case_insensitively() {
        let resolved = resolve_payment_requirement(&configured(), &issued(&[configured()])).unwrap();

        assert_eq!(resolved.pay_to, MERCHANT.to_lowercase());
    }

    #[test]
    fn resolution_returns_the_issued_requirement_not_the_callers() {
        let mut accepted = configured();
        accepted.max_timeout_seconds = 1;
        accepted.extra =
            Some(serde_json::json!({"name": "USDC", "version": "2", "assetTransferMethod": "eip3009", "decimals": 99}));

        let resolved = resolve_payment_requirement(&accepted, &issued(&[configured()])).unwrap();

        assert_eq!(resolved.max_timeout_seconds, 300);
        assert_eq!(resolved.extra, configured().extra);
    }

    #[test]
    fn rejects_accepted_naming_another_eip712_domain_or_transfer_method() {
        let with_extra = |extra: serde_json::Value| {
            let mut accepted = configured();
            accepted.extra = Some(extra);
            accepted
        };

        for accepted in [
            with_extra(serde_json::json!({"name": "Forged", "version": "2", "assetTransferMethod": "eip3009"})),
            with_extra(serde_json::json!({"name": "USDC", "version": "9", "assetTransferMethod": "eip3009"})),
            with_extra(serde_json::json!({"name": "USDC", "version": "2", "assetTransferMethod": "permit2"})),
            with_extra(serde_json::json!({"assetTransferMethod": "eip3009"})),
        ] {
            assert_eq!(
                resolve_payment_requirement(&accepted, &issued(&[configured()])).unwrap_err(),
                NOT_ISSUED,
                "{:?}",
                accepted.extra
            );
        }
    }

    #[test]
    fn selects_among_requirements_that_differ_only_in_transfer_method() {
        let mut permit2 = configured();
        permit2.extra = Some(serde_json::json!({"name": "USDC", "version": "2", "assetTransferMethod": "permit2"}));
        let issued = issued(&[configured(), permit2.clone()]);

        let resolved_eip3009 = resolve_payment_requirement(&configured(), &issued).unwrap();
        let resolved_permit2 = resolve_payment_requirement(&permit2, &issued).unwrap();

        assert_eq!(resolved_eip3009.asset_transfer_method(), "eip3009");
        assert_eq!(resolved_permit2.asset_transfer_method(), "permit2");
    }

    #[test]
    fn keeps_solana_addresses_case_sensitive() {
        let solana = X402PaymentRequirement {
            network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1".to_string(),
            asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU".to_string(),
            pay_to: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin".to_string(),
            ..configured()
        };
        let issued = issued(std::slice::from_ref(&solana));
        let mut lowercased = solana.clone();
        lowercased.pay_to = solana.pay_to.to_lowercase();

        assert_eq!(issued[0].pay_to, solana.pay_to);
        assert_eq!(issued[0].asset, solana.asset);
        assert!(resolve_payment_requirement(&solana, &issued).is_ok());
        assert_eq!(resolve_payment_requirement(&lowercased, &issued).unwrap_err(), NOT_ISSUED);
    }

    #[test]
    fn rejects_accepted_naming_another_recipient() {
        let accepted = requirement("exact", ATTACKER, "1000000");

        let error = resolve_payment_requirement(&accepted, &issued(&[configured()])).unwrap_err();

        assert_eq!(error, NOT_ISSUED);
    }

    #[test]
    fn rejects_exact_amount_other_than_configured() {
        for amount in ["1", "999999", "1000001", "not-a-number", ""] {
            let accepted = requirement("exact", MERCHANT, amount);
            assert_eq!(
                resolve_payment_requirement(&accepted, &issued(&[configured()])).unwrap_err(),
                NOT_ISSUED,
                "amount {amount}"
            );
        }
    }

    #[test]
    fn upto_requires_the_configured_amount() {
        let issued = issued(&[requirement("upto", MERCHANT, "1000000")]);

        let resolved = resolve_payment_requirement(&requirement("upto", MERCHANT, "1000000"), &issued);

        assert_eq!(resolved.unwrap().amount, "1000000");
        for amount in ["999999", "1000001"] {
            assert_eq!(
                resolve_payment_requirement(&requirement("upto", MERCHANT, amount), &issued).unwrap_err(),
                NOT_ISSUED,
                "amount {amount}"
            );
        }
    }

    #[test]
    fn rejects_accepted_with_another_scheme_network_or_asset() {
        let mut other_scheme = configured();
        other_scheme.scheme = "upto".to_string();
        let mut other_network = configured();
        other_network.network = "eip155:8453".to_string();
        let mut other_asset = configured();
        other_asset.asset = ATTACKER.to_string();
        let mut unknown_scheme = configured();
        unknown_scheme.scheme = "stream".to_string();
        let issued = issued(&[configured(), unknown_scheme.clone()]);

        for accepted in [other_scheme, other_network, other_asset, unknown_scheme] {
            assert_eq!(resolve_payment_requirement(&accepted, &issued).unwrap_err(), NOT_ISSUED);
        }
    }

    #[test]
    fn rejects_any_accepted_when_no_requirement_is_issued() {
        assert_eq!(resolve_payment_requirement(&configured(), &[]).unwrap_err(), NOT_ISSUED);
    }

    #[test]
    fn selects_the_requirement_matching_the_offered_recipient() {
        let issued = issued(&[requirement("exact", ATTACKER, "5"), configured()]);

        let resolved = resolve_payment_requirement(&configured(), &issued).unwrap();

        assert_eq!(resolved.pay_to, MERCHANT.to_lowercase());
        assert_eq!(resolved.amount, "1000000");
    }

    #[test]
    fn reads_the_payment_signature_from_the_named_header_only() {
        let mut headers = HeaderMap::new();
        headers.insert("x-payment", "signed".parse().unwrap());
        assert_eq!(extract_payment_signature(&headers, "x-payment").as_deref(), Some("signed"));
        assert_eq!(extract_payment_signature(&headers, "payment-signature"), None);
    }
}
