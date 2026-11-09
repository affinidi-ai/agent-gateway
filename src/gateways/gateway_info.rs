//! The summary an agent-pay gateway gives with `gateway-info`: that it is a
//! payment gateway, and what the payment surfaces it exposes to this gateway
//! accept. Parsed leniently like the payment manifest, so a newer peer never
//! breaks it, except that the role must say `payment`.

use serde::{Deserialize, Serialize};

pub const PAYMENT_ROLE: &str = "payment";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewayInfo {
    pub info_version: String,
    pub role: String,
    pub protocols: Vec<String>,
    pub payment_methods: Vec<PaymentMethodSummary>,
    pub payable_count: usize,
    pub units: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PaymentMethodSummary {
    pub protocol: String,
    /// `onChain` or `settled`.
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settles_via: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayInfoError {
    /// The peer could not be reached or did not answer in time.
    Unavailable(String),
    /// The peer answered but is not a payment gateway, refused, or sent something unusable.
    Rejected(String),
}

impl std::fmt::Display for GatewayInfoError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(f, "payment gateway unavailable: {reason}"),
            Self::Rejected(reason) => write!(f, "payment gateway not verified: {reason}"),
        }
    }
}

/// Parses a `gateway-info-response` body: `{"info": {...}}`,
/// `{"info": null}` or `{"error": "...", "info": null}`.
pub fn parse_gateway_info_response(body: &serde_json::Value) -> Result<GatewayInfo, GatewayInfoError> {
    if let Some(error) = body
        .get("error")
        .filter(|error| !error.is_null())
    {
        let reason = error
            .as_str()
            .map(|reason| crate::a2a::clip_for_log(reason).to_string())
            .unwrap_or_else(|| "unspecified error".to_string());
        return Err(GatewayInfoError::Rejected(reason));
    }
    let info: GatewayInfo = match body.get("info") {
        None | Some(serde_json::Value::Null) => {
            return Err(GatewayInfoError::Rejected("the gateway is not a payment gateway".to_string()));
        }
        Some(info) => serde_json::from_value(info.clone())
            .map_err(|error| GatewayInfoError::Rejected(format!("malformed gateway info: {error}")))?,
    };
    if info.role != PAYMENT_ROLE {
        return Err(GatewayInfoError::Rejected("the gateway is not a payment gateway".to_string()));
    }
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_payment_gateway_summary_is_parsed_and_unknown_fields_ignored() {
        let info = parse_gateway_info_response(&json!({"info": {
            "info_version": "1",
            "role": "payment",
            "protocols": ["mpp", "x402"],
            "payment_methods": [
                {"protocol": "mpp", "kind": "settled", "provider": "google_pay", "settles_via": "stripe"},
                {"protocol": "x402", "kind": "onChain", "network": "eip155:8453", "future": true},
            ],
            "payable_count": 2,
            "units": ["USD"],
            "newer_field": {},
        }}))
        .unwrap();
        assert_eq!(info.protocols, vec!["mpp", "x402"]);
        assert_eq!(info.payable_count, 2);
        assert_eq!(
            info.payment_methods[0]
                .provider
                .as_deref(),
            Some("google_pay")
        );
        assert_eq!(
            info.payment_methods[0]
                .settles_via
                .as_deref(),
            Some("stripe")
        );
        assert_eq!(
            info.payment_methods[1]
                .network
                .as_deref(),
            Some("eip155:8453")
        );
    }

    #[test]
    fn a_gateway_with_nothing_on_offer_is_still_a_payment_gateway() {
        let info = parse_gateway_info_response(&json!({"info": {"role": "payment", "payable_count": 0}})).unwrap();
        assert_eq!(info.payable_count, 0);
        assert!(info.protocols.is_empty());
    }

    #[test]
    fn anything_but_a_payment_role_is_rejected() {
        for body in
            [json!({"info": null}), json!({}), json!({"info": {"role": "peer"}}), json!({"info": {"payable_count": 1}})]
        {
            assert_eq!(
                parse_gateway_info_response(&body),
                Err(GatewayInfoError::Rejected("the gateway is not a payment gateway".to_string())),
                "{body}"
            );
        }
    }

    #[test]
    fn a_refusal_or_a_malformed_summary_is_rejected() {
        assert_eq!(
            parse_gateway_info_response(&json!({"error": "connection point exposure unavailable", "info": null})),
            Err(GatewayInfoError::Rejected("connection point exposure unavailable".to_string()))
        );
        assert!(matches!(
            parse_gateway_info_response(&json!({"info": {"role": "payment", "payable_count": "many"}})),
            Err(GatewayInfoError::Rejected(reason)) if reason.starts_with("malformed gateway info")
        ));
    }
}
