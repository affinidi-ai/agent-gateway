//! MPP auto-pay for gateway-to-gateway (fabric://) forwarding
//!
//! When `mpp_auto_pay` is true on a channel with a `fabric://` target,
//! GW1 intercepts 402 responses from GW2, fulfils the MPP challenge using
//! wallets/Stripe PMs from the x402-proxy config, and returns an
//! `Authorization: Payment <credential>` header for the retry.

use std::collections::HashMap;

use anyhow::{Context, Result, anyhow};
use tracing::info;

use crate::mpp::challenge::{base64url_decode_nopad, base64url_encode_nopad};
use crate::mpp::payment_challenge::{ParsedChallenge, parse_www_authenticate_headers, sign_mpp_payment};
use crate::mpp::types::{MppChallengeEcho, MppCredential};
use crate::secrets::SecretsStore;
use crate::x402::proxy_config::{StripePaymentMethodConfig, X402ProxyConfig};

/// Result of attempting to auto-pay a 402 from a downstream gateway.
pub struct AutoPayResult {
    /// The `Authorization` header value: `Payment <base64url-credential>`
    pub authorization_header: String,
    /// Which payment method was used
    pub method: String,
}

/// Attempt to fulfil an MPP 402 challenge from a downstream gateway.
///
/// Parses `WWW-Authenticate: Payment` challenges from the response headers,
/// selects a wallet or Stripe PM, signs the payment proof, and returns
/// the `Authorization: Payment <credential>` header value for the retry.
///
/// # Arguments
/// * `response_headers` — headers from the 402 response (key→value map as stored in DIDComm ForwardResponse)
/// * `max_amount` — optional safety limit on the payment amount
/// * `secrets_store` — for loading private keys
pub async fn auto_pay_402(
    response_headers: &HashMap<String, serde_json::Value>,
    max_amount: Option<&str>,
    secrets_store: &dyn SecretsStore,
) -> Result<AutoPayResult> {
    // Load wallet/network config from global cache
    let config = crate::x402::proxy_config_cache::get_x402_proxy_config()
        .await
        .ok_or_else(|| anyhow!("MPP auto-pay: wallet/network config not initialized (x402-proxy)"))?;

    // Extract WWW-Authenticate headers from the response
    let challenges = extract_challenges_from_map(response_headers)?;
    if challenges.is_empty() {
        return Err(anyhow!("MPP auto-pay: no WWW-Authenticate: Payment challenges in 402 response"));
    }

    info!("[mpp_auto_pay] Received {} challenge(s) from downstream gateway", challenges.len());

    // Select best wallet/PM + challenge
    let selection = select_payment(&config, &challenges)?;

    // Validate amount if max_amount configured
    if let Some(max) = max_amount {
        validate_amount(selection.challenge(), max)?;
    }

    // Build credential
    let credential = build_credential(&selection, secrets_store).await?;

    // Encode as Authorization: Payment <base64url>
    let cred_json = serde_json::to_vec(&credential).context("Failed to serialize MPP credential")?;
    let auth_value = format!("Payment {}", base64url_encode_nopad(&cred_json));

    info!(
        "[mpp_auto_pay] Auto-payment prepared: method='{}', auth_header_len={}",
        selection.challenge().method,
        auth_value.len()
    );

    Ok(AutoPayResult {
        authorization_header: auth_value,
        method: selection
            .challenge()
            .method
            .clone(),
    })
}

// ---------------------------------------------------------------------------
// Internal types and helpers
// ---------------------------------------------------------------------------

enum PaymentSelection<'a> {
    Crypto { binding: &'a crate::x402::proxy_config::WalletBinding, challenge: ParsedChallenge },
    Card { stripe_pm: &'a StripePaymentMethodConfig, challenge: ParsedChallenge },
}

impl<'a> PaymentSelection<'a> {
    fn challenge(&self) -> &ParsedChallenge {
        match self {
            Self::Crypto { challenge, .. } | Self::Card { challenge, .. } => challenge,
        }
    }
}

/// Parse `WWW-Authenticate` headers from a DIDComm ForwardResponse headers map.
///
/// In the DIDComm message, headers are stored as `HashMap<String, Value>` with
/// UPPERCASE keys (normalised by GW2). We look for `WWW-AUTHENTICATE` and also
/// check lowercase variants.
fn extract_challenges_from_map(headers: &HashMap<String, serde_json::Value>) -> Result<Vec<ParsedChallenge>> {
    // Build a reqwest HeaderMap so we can reuse parse_www_authenticate_headers
    let mut header_map = reqwest::header::HeaderMap::new();

    for (key, value) in headers {
        let key_upper = key.to_uppercase();
        if key_upper == "WWW-AUTHENTICATE"
            && let Some(val_str) = value.as_str()
            && let Ok(hv) = reqwest::header::HeaderValue::from_str(val_str)
        {
            header_map.append(reqwest::header::WWW_AUTHENTICATE, hv);
        }
    }

    if header_map.is_empty() {
        return Ok(vec![]);
    }

    Ok(parse_www_authenticate_headers(&header_map))
}

/// Select a wallet binding or Stripe PM for the best-matching challenge.
fn select_payment<'a>(
    config: &'a X402ProxyConfig,
    challenges: &[ParsedChallenge],
) -> Result<PaymentSelection<'a>> {
    let mut best_crypto: Option<(
        &'a crate::x402::proxy_config::X402WalletConfig,
        &'a crate::x402::proxy_config::WalletBinding,
        ParsedChallenge,
        i32,
    )> = None;
    let mut best_card: Option<(&'a StripePaymentMethodConfig, ParsedChallenge, i32)> = None;

    for challenge in challenges {
        let request_data = decode_challenge_request(&challenge.request)?;
        let currency = request_data
            .get("currency")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        match challenge.method.as_str() {
            "card" | "stripe" => {
                for spm in &config.stripe_payment_methods {
                    if spm
                        .currencies
                        .iter()
                        .any(|c| c.eq_ignore_ascii_case(currency))
                        && best_card
                            .as_ref()
                            .is_none_or(|(_, _, p)| spm.priority > *p)
                    {
                        best_card = Some((spm, challenge.clone(), spm.priority));
                    }
                }
            }
            _ => {
                let network = request_data
                    .get("network")
                    .and_then(|v| v.as_str());

                for wallet in &config.wallets {
                    for binding in &wallet.bindings {
                        if let Some(net) = network
                            && binding.network != net
                        {
                            continue;
                        }
                        for sym in &binding.symbols {
                            let matches = sym
                                .symbol
                                .eq_ignore_ascii_case(currency)
                                || sym
                                    .token_address
                                    .as_ref()
                                    .is_some_and(|addr| addr.eq_ignore_ascii_case(currency));
                            if matches
                                && best_crypto
                                    .as_ref()
                                    .is_none_or(|(_, _, _, p)| sym.priority > *p)
                            {
                                best_crypto = Some((wallet, binding, challenge.clone(), sym.priority));
                            }
                        }
                    }
                }
            }
        }
    }

    match (best_card, best_crypto) {
        (Some((spm, ch, cp)), Some((_w, b, cc, pp))) => {
            if cp >= pp {
                Ok(PaymentSelection::Card { stripe_pm: spm, challenge: ch })
            } else {
                Ok(PaymentSelection::Crypto { binding: b, challenge: cc })
            }
        }
        (Some((spm, ch, _)), None) => Ok(PaymentSelection::Card { stripe_pm: spm, challenge: ch }),
        (None, Some((_w, b, c, _))) => Ok(PaymentSelection::Crypto { binding: b, challenge: c }),
        (None, None) => Err(anyhow!("MPP auto-pay: no wallet or Stripe PM matches any challenge")),
    }
}

/// Decode the base64url `request` parameter from a challenge.
fn decode_challenge_request(request_b64: &str) -> Result<serde_json::Value> {
    let bytes =
        base64url_decode_nopad(request_b64).map_err(|e| anyhow!("Failed to decode challenge request: {}", e))?;
    serde_json::from_slice(&bytes).map_err(|e| anyhow!("Failed to parse challenge request: {}", e))
}

/// Validate that the challenge amount doesn't exceed the safety limit.
fn validate_amount(
    challenge: &ParsedChallenge,
    max_amount: &str,
) -> Result<()> {
    let request_data = decode_challenge_request(&challenge.request)?;
    let max_f64: f64 = max_amount
        .replace(['$', ',', ' '], "")
        .parse()
        .context("Invalid max amount format")?;

    if let Some(amount_str) = request_data
        .get("amount")
        .and_then(|v| v.as_str())
    {
        let amount: f64 = amount_str
            .replace(['$', ',', ' '], "")
            .parse()
            .with_context(|| format!("Invalid challenge amount: {}", amount_str))?;
        if amount > max_f64 {
            return Err(anyhow!("MPP auto-pay: amount {} exceeds max {}", amount_str, max_amount));
        }
    }
    Ok(())
}

/// Build an MPP credential from the selected payment method.
async fn build_credential(
    selection: &PaymentSelection<'_>,
    secrets_store: &dyn SecretsStore,
) -> Result<MppCredential> {
    let challenge = selection.challenge();

    match selection {
        PaymentSelection::Crypto { binding, .. } => {
            let private_key = binding
                .get_private_key_value(secrets_store)
                .await
                .context("MPP auto-pay: failed to load private key")?;

            let payload = sign_mpp_payment(&private_key, binding, challenge).await?;

            Ok(MppCredential {
                challenge: MppChallengeEcho {
                    id: challenge.id.clone(),
                    realm: challenge.realm.clone(),
                    method: challenge.method.clone(),
                    intent: challenge.intent.clone(),
                    request: challenge.request.clone(),
                    expires: challenge.expires.clone(),
                    digest: challenge.digest.clone(),
                    description: challenge.description.clone(),
                    opaque: challenge.opaque.clone(),
                },
                source: Some(format!("did:pkh:eip155:{}:{}", binding.network, binding.address)),
                payload,
            })
        }
        PaymentSelection::Card { stripe_pm, .. } => {
            let payload = serde_json::json!({
                "type": "card",
                "payment_method": stripe_pm.payment_method_id,
            });

            Ok(MppCredential {
                challenge: MppChallengeEcho {
                    id: challenge.id.clone(),
                    realm: challenge.realm.clone(),
                    method: challenge.method.clone(),
                    intent: challenge.intent.clone(),
                    request: challenge.request.clone(),
                    expires: challenge.expires.clone(),
                    digest: challenge.digest.clone(),
                    description: challenge.description.clone(),
                    opaque: challenge.opaque.clone(),
                },
                source: stripe_pm
                    .label
                    .as_ref()
                    .map(|l| format!("stripe:{}", l)),
                payload,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_challenges_from_map_empty() {
        let headers = HashMap::new();
        let challenges = extract_challenges_from_map(&headers).unwrap();
        assert!(challenges.is_empty());
    }

    #[test]
    fn test_extract_challenges_from_map_with_payment() {
        let mut headers = HashMap::new();
        headers.insert(
            "WWW-AUTHENTICATE".to_string(),
            serde_json::Value::String(
                r#"Payment id="hmac-abc", realm="test.com", method="tempo", intent="charge", request="eyJhbW91bnQiOiIwLjAxIiwiY3VycmVuY3kiOiJ1c2QiLCJyZWNpcGllbnQiOiIweGFiYyJ9""#
                    .to_string(),
            ),
        );

        let challenges = extract_challenges_from_map(&headers).unwrap();
        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].method, "tempo");
        assert_eq!(challenges[0].realm, "test.com");
    }

    #[test]
    fn test_validate_amount_within_limit() {
        let request_json = serde_json::json!({"amount": "0.50", "currency": "usd", "recipient": "0xabc"});
        let request_b64 = base64url_encode_nopad(&serde_json::to_vec(&request_json).unwrap());

        let challenge = ParsedChallenge {
            id: "test".into(),
            realm: "test.com".into(),
            method: "tempo".into(),
            intent: "charge".into(),
            request: request_b64,
            expires: None,
            digest: None,
            description: None,
            opaque: None,
        };

        assert!(validate_amount(&challenge, "1.00").is_ok());
    }

    #[test]
    fn test_validate_amount_exceeds_limit() {
        let request_json = serde_json::json!({"amount": "5.00", "currency": "usd", "recipient": "0xabc"});
        let request_b64 = base64url_encode_nopad(&serde_json::to_vec(&request_json).unwrap());

        let challenge = ParsedChallenge {
            id: "test".into(),
            realm: "test.com".into(),
            method: "tempo".into(),
            intent: "charge".into(),
            request: request_b64,
            expires: None,
            digest: None,
            description: None,
            opaque: None,
        };

        let result = validate_amount(&challenge, "1.00");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("exceeds")
        );
    }

    #[test]
    fn test_select_payment_crypto_match() {
        use crate::x402::proxy_config::*;

        let config = X402ProxyConfig {
            networks: vec![],
            wallets: vec![X402WalletConfig {
                id: "test-wallet".into(),
                name: "Test".into(),
                description: None,
                bindings: vec![WalletBinding {
                    network: "eip155:84532".into(),
                    address: "0xtest".into(),
                    private_key: "0xdeadbeef".into(),
                    symbols: vec![SymbolConfig {
                        symbol: "USDC".into(),
                        priority: 100,
                        token_address: Some("0x036CbD53842c5426634e7929541eC2318f3dCF7e".into()),
                        decimals: Some(6),
                        usd_price: Some(1.0),
                    }],
                }],
            }],
            stripe_payment_methods: vec![],
        };

        let request_json = serde_json::json!({"amount": "0.01", "currency": "0x036CbD53842c5426634e7929541eC2318f3dCF7e", "recipient": "0xabc", "network": "eip155:84532"});
        let request_b64 = base64url_encode_nopad(&serde_json::to_vec(&request_json).unwrap());

        let challenges = vec![ParsedChallenge {
            id: "hmac-test".into(),
            realm: "example.com".into(),
            method: "tempo".into(),
            intent: "charge".into(),
            request: request_b64,
            expires: None,
            digest: None,
            description: None,
            opaque: None,
        }];

        let result = select_payment(&config, &challenges);
        assert!(result.is_ok());
        match result.unwrap() {
            PaymentSelection::Crypto { binding, challenge } => {
                assert_eq!(binding.network, "eip155:84532");
                assert_eq!(challenge.method, "tempo");
            }
            _ => panic!("Expected Crypto selection"),
        }
    }

    #[test]
    fn test_select_payment_card_match() {
        use crate::x402::proxy_config::*;

        let config = X402ProxyConfig {
            networks: vec![],
            wallets: vec![],
            stripe_payment_methods: vec![StripePaymentMethodConfig {
                payment_method_id: "pm_auto_test".into(),
                currencies: vec!["usd".into()],
                priority: 50,
                label: Some("Auto-pay card".into()),
            }],
        };

        let request_json = serde_json::json!({"amount": "1.00", "currency": "usd", "recipient": "acct_123"});
        let request_b64 = base64url_encode_nopad(&serde_json::to_vec(&request_json).unwrap());

        let challenges = vec![ParsedChallenge {
            id: "hmac-test".into(),
            realm: "example.com".into(),
            method: "card".into(),
            intent: "charge".into(),
            request: request_b64,
            expires: None,
            digest: None,
            description: None,
            opaque: None,
        }];

        let result = select_payment(&config, &challenges);
        assert!(result.is_ok());
        match result.unwrap() {
            PaymentSelection::Card { stripe_pm, challenge } => {
                assert_eq!(stripe_pm.payment_method_id, "pm_auto_test");
                assert_eq!(challenge.method, "card");
            }
            _ => panic!("Expected Card selection"),
        }
    }

    #[test]
    fn test_select_payment_no_match() {
        use crate::x402::proxy_config::*;

        let config = X402ProxyConfig {
            networks: vec![],
            wallets: vec![],
            stripe_payment_methods: vec![],
        };

        let request_json = serde_json::json!({"amount": "1.00", "currency": "btc", "recipient": "0xabc"});
        let request_b64 = base64url_encode_nopad(&serde_json::to_vec(&request_json).unwrap());

        let challenges = vec![ParsedChallenge {
            id: "test".into(),
            realm: "test.com".into(),
            method: "tempo".into(),
            intent: "charge".into(),
            request: request_b64,
            expires: None,
            digest: None,
            description: None,
            opaque: None,
        }];

        let result = select_payment(&config, &challenges);
        assert!(result.is_err());
    }
}
