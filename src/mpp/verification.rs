//! MPP credential extraction and verification
//!
//! Handles extraction of `Authorization: Payment <base64url>` credentials from
//! HTTP requests, and verification of the challenge HMAC binding.

use axum::http::HeaderMap;
use base64::Engine;

use super::challenge::{base64url_decode_nopad, base64url_encode_nopad, verify_challenge_id};
use super::types::{MppConfig, MppCredential, MppReceipt};

/// Extract an MPP credential from the `Authorization` header.
///
/// Per the spec, the credential is:
///   `Authorization: Payment <base64url-nopad>`
///
/// Returns `Some(MppCredential)` if the header is present, correctly formatted,
/// and successfully decoded.
pub fn extract_mpp_credential(headers: &HeaderMap) -> Option<MppCredential> {
    let auth_header = headers
        .get("Authorization")
        .or_else(|| headers.get("authorization"))
        .and_then(|v| v.to_str().ok())?;

    // Check for "Payment " prefix (case-sensitive per HTTP auth scheme)
    let credential_b64 = auth_header.strip_prefix("Payment ")?;
    let credential_b64 = credential_b64.trim();

    if credential_b64.is_empty() {
        return None;
    }

    // Decode base64url (no padding)
    let credential_bytes = base64url_decode_nopad(credential_b64).ok()?;

    // Parse JSON
    serde_json::from_slice(&credential_bytes).ok()
}

/// Extract an MPP credential from headers OR MCP tool parameters.
///
/// For MCP `tools/call` requests, the credential may be passed as a
/// `payment_credential` argument. If found there, it is removed from
/// the request body before forwarding.
///
/// # Returns
/// `(Option<MppCredential>, Vec<u8>)` — credential (if found) and possibly
/// modified body bytes.
pub fn extract_mpp_credential_with_mcp(
    headers: &HeaderMap,
    body_bytes: &[u8],
) -> (Option<MppCredential>, Vec<u8>) {
    // 1. Check Authorization header first (standard MPP flow)
    if let Some(credential) = extract_mpp_credential(headers) {
        return (Some(credential), body_bytes.to_vec());
    }

    // 2. Check MCP tool parameters for "payment_credential"
    if let Ok(mut body_json) = serde_json::from_slice::<serde_json::Value>(body_bytes)
        && let Some(method) = body_json
            .get("method")
            .and_then(|m| m.as_str())
        && method == "tools/call"
        && let Some(params) = body_json.get_mut("params")
        && let Some(arguments) = params.get_mut("arguments")
        && let Some(args_obj) = arguments.as_object_mut()
        && let Some(payment_cred) = args_obj.remove("payment_credential")
        && let Some(cred_str) = payment_cred.as_str()
    {
        // Try to decode the credential from b64url
        if let Ok(cred_bytes) = base64url_decode_nopad(cred_str)
            && let Ok(credential) = serde_json::from_slice::<MppCredential>(&cred_bytes)
            && let Ok(modified_body) = serde_json::to_vec(&body_json)
        {
            return (Some(credential), modified_body);
        }
    }

    (None, body_bytes.to_vec())
}

/// Resolve the secret key from config (handles env var references).
fn resolve_secret_key(key: &str) -> Vec<u8> {
    let raw = if let Some(var_name) = key.strip_prefix('$') {
        std::env::var(var_name).unwrap_or_default()
    } else {
        key.to_string()
    };
    base64::engine::general_purpose::STANDARD
        .decode(&raw)
        .unwrap_or_else(|_| raw.into_bytes())
}

/// Verify an MPP credential against the config.
///
/// Steps per the spec:
/// 1. Verify the challenge `id` HMAC binding matches the echoed parameters
/// 2. Check the challenge has not expired
/// 3. Verify the payment method is supported
/// 4. (Future) Verify the payment proof via payment-method-specific logic
///
/// Returns `Ok(())` on success, `Err(error_message)` on failure.
pub fn verify_mpp_credential(
    credential: &MppCredential,
    config: &MppConfig,
) -> Result<(), String> {
    let secret = resolve_secret_key(&config.secret_key);
    let challenge = &credential.challenge;

    // 1. Verify HMAC challenge binding
    let valid = verify_challenge_id(
        &secret,
        &challenge.id,
        &challenge.realm,
        &challenge.method,
        &challenge.intent,
        &challenge.request,
        challenge.expires.as_deref(),
        challenge.digest.as_deref(),
        challenge.opaque.as_deref(),
    )?;

    if !valid {
        return Err("Invalid challenge ID: HMAC binding verification failed".to_string());
    }

    // 2. Check realm matches
    if challenge.realm != config.realm {
        return Err(format!("Realm mismatch: expected '{}', got '{}'", config.realm, challenge.realm));
    }

    // 3. Check expiration
    if let Some(ref expires) = challenge.expires {
        let expires_dt =
            chrono::DateTime::parse_from_rfc3339(expires).map_err(|e| format!("Invalid expires timestamp: {}", e))?;
        if chrono::Utc::now() > expires_dt {
            return Err("Challenge has expired".to_string());
        }
    }

    // 4. Verify the payment method is one we offer
    let method_supported = config
        .payment_methods
        .iter()
        .any(|pm| pm.method == challenge.method && pm.intent == challenge.intent);

    if !method_supported {
        return Err(format!("Unsupported payment method '{}' with intent '{}'", challenge.method, challenge.intent));
    }

    // 5. Verify payment proof — this is payment-method-specific.
    //    For now, we check that the payload is a non-empty JSON object.
    //    Async verification (Stripe API call, on-chain check) happens in
    //    `verify_payment_proof` called separately from `process_payment`.
    if credential.payload.is_null()
        || credential
            .payload
            .as_object()
            .is_some_and(|o| o.is_empty())
    {
        return Err("Empty payment payload".to_string());
    }

    Ok(())
}

/// Perform async payment-method-specific proof verification.
///
/// Called after `verify_mpp_credential` succeeds (HMAC + expiry + method checks pass).
/// For card methods this calls the Stripe API to create+confirm a PaymentIntent.
/// For crypto methods this dispatches to on-chain / signature / passthrough verification.
#[derive(Debug)]
pub struct PaymentProof {
    /// Reference included in the receipt (tx hash, PaymentIntent id, etc.)
    pub reference: String,
    /// The genuinely-unique settlement identifier to enforce single-use on
    /// (Stripe PaymentIntent id, on-chain tx hash, or signature nonce), or
    /// `None` when there is nothing durable to protect (crypto passthrough dev
    /// mode), in which case the caller skips the replay guard.
    pub single_use_key: Option<String>,
}

/// Returns the payment reference on success.
pub async fn verify_payment_proof(
    credential: &MppCredential,
    config: &MppConfig,
) -> Result<PaymentProof, String> {
    let method = &credential.challenge.method;

    match method.as_str() {
        "card" | "stripe" => verify_card_payment(credential, config).await,
        // Crypto methods: dispatch to on-chain / signature / passthrough based on config
        "tempo" | "crypto" | "evm" => {
            let reference = super::onchain::verify_crypto_proof(credential, config).await?;
            // Passthrough performs no real settlement, so its reference is not a
            // durable single-use identifier — skip the replay guard there.
            let single_use_key = match config.crypto_verification_mode {
                super::types::MppVerificationMode::Passthrough => None,
                _ => Some(reference.clone()),
            };
            Ok(PaymentProof { reference, single_use_key })
        }
        other => {
            // No verification path exists for this method, so the payment cannot
            // be attested. Fail closed rather than granting on an unverified
            // payload — an unsupported method MUST be rejected.
            Err(format!("No verification implementation for payment method '{other}'; payment cannot be attested"))
        }
    }
}

/// Verify a card/Stripe payment by creating and confirming a PaymentIntent for
/// the source supplied in the credential — a conformant single-use Shared
/// Payment Token (`spt`, draft-stripe-charge-00) or a legacy reusable Stripe
/// PaymentMethod (`payment_method`, `pm_`).
async fn verify_card_payment(
    credential: &MppCredential,
    config: &MppConfig,
) -> Result<PaymentProof, String> {
    // Extract the Stripe secret key from config
    let stripe_key = config
        .stripe_secret_key
        .as_deref()
        .ok_or("Card payment method configured but no stripe_secret_key in MppConfig")?;

    // Resolve env var reference
    let resolved_key = if let Some(var_name) = stripe_key.strip_prefix('$') {
        std::env::var(var_name)
            .map_err(|_| format!("Environment variable '{}' not set for stripe_secret_key", var_name))?
    } else {
        stripe_key.to_string()
    };

    // Resolve the chargeable source: the conformant single-use Shared Payment
    // Token (`spt`) is preferred; the legacy reusable PaymentMethod (`pm_`) is
    // still accepted for backward compatibility.
    let source = resolve_stripe_source(&credential.payload)?;

    // Decode the challenge request to get amount/currency
    let request_bytes = super::challenge::base64url_decode_nopad(&credential.challenge.request)
        .map_err(|e| format!("Failed to decode challenge request: {}", e))?;
    let request: super::types::MppPaymentRequest =
        serde_json::from_slice(&request_bytes).map_err(|e| format!("Failed to parse challenge request: {}", e))?;

    // Convert amount to Stripe's smallest-unit integer
    let stripe_amount = super::stripe::amount_to_stripe_units(&request.amount, &request.currency)?;

    // Create and confirm the PaymentIntent
    let client = super::stripe::StripeClient::new(&resolved_key);
    let description =
        Some(format!("MPP payment for realm '{}' method '{}'", config.realm, credential.challenge.method));

    // Derive a stable idempotency key from the challenge id so a resubmission of
    // the same credential reuses the original PaymentIntent rather than charging
    // the card a second time.
    let idempotency_key = format!("mpp-{}", credential.challenge.id);

    let pi = client
        .create_and_confirm_payment(
            stripe_amount,
            &request.currency,
            &source,
            description.as_deref(),
            // Use recipient as transfer destination if it looks like a Stripe account
            if request
                .recipient
                .starts_with("acct_")
            {
                Some(request.recipient.as_str())
            } else {
                None
            },
            Some(&idempotency_key),
        )
        .await
        .map_err(|e| e.to_string())?;

    tracing::info!(
        pi_id = %pi.id,
        amount = stripe_amount,
        currency = %request.currency,
        "[mpp] Stripe PaymentIntent succeeded"
    );

    let reference = pi.id;
    Ok(PaymentProof {
        single_use_key: Some(reference.clone()),
        reference,
    })
}

/// Resolve the Stripe charge source from an MPP card/Stripe credential payload.
///
/// Accepts the conformant `draft-stripe-charge-00` single-use Shared Payment
/// Token (`spt`, `spt_`-prefixed) and, for backward compatibility, the legacy
/// reusable Stripe PaymentMethod (`payment_method`, `pm_`-prefixed). The SPT is
/// preferred when both are present. Fails closed when neither is a valid token.
fn resolve_stripe_source(payload: &serde_json::Value) -> Result<super::stripe::StripePaymentSource, String> {
    if let Some(spt) = payload
        .get("spt")
        .and_then(|v| v.as_str())
    {
        if !spt.starts_with("spt_") {
            return Err(format!("Invalid spt format: '{}' (expected Shared Payment Token starting with 'spt_')", spt));
        }
        return Ok(super::stripe::StripePaymentSource::SharedPaymentToken(spt.to_string()));
    }

    if let Some(pm) = payload
        .get("payment_method")
        .and_then(|v| v.as_str())
    {
        if !pm.starts_with("pm_") {
            return Err(format!("Invalid payment_method format: '{}' (expected Stripe PM ID starting with 'pm_')", pm));
        }
        return Ok(super::stripe::StripePaymentSource::PaymentMethod(pm.to_string()));
    }

    Err("Card credential payload must contain a single-use 'spt' (Shared Payment Token) or legacy 'payment_method' (Stripe PM ID)".to_string())
}

/// Build a `Payment-Receipt` header value for a successful payment.
///
/// Returns base64url-encoded JSON per the spec.
pub fn create_mpp_receipt(
    method: &str,
    reference: &str,
) -> Result<String, String> {
    let receipt = MppReceipt {
        status: "success".to_string(),
        method: method.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        reference: reference.to_string(),
    };

    let json = serde_json::to_vec(&receipt).map_err(|e| format!("Failed to serialize receipt: {}", e))?;

    Ok(base64url_encode_nopad(&json))
}

#[cfg(test)]
mod tests {
    use super::super::challenge::compute_challenge_id;
    use super::super::types::*;
    use super::*;
    use axum::http::HeaderMap;

    fn test_config() -> MppConfig {
        MppConfig {
            enabled: true,
            realm: "api.example.com".to_string(),
            secret_key: base64::engine::general_purpose::STANDARD.encode(b"test-secret-key-32bytes-long!!!!"),
            stripe_secret_key: None,
            payment_methods: vec![MppPaymentMethod {
                method: "tempo".to_string(),
                intent: "charge".to_string(),
                currency: "usd".to_string(),
                recipient: "0xrecipient".to_string(),
                amount: "1.00".to_string(),
                network: None,
            }],
            challenge_ttl_seconds: 300,
            mcp_payment_triggers: None,
            a2a_method_filters: None,
            verification_timeout_ms: 10000,
            crypto_verification_mode: MppVerificationMode::default(),
            rpc_endpoints: std::collections::HashMap::new(),
            min_confirmations: 0,
        }
    }

    fn make_valid_credential(config: &MppConfig) -> MppCredential {
        let secret = base64::engine::general_purpose::STANDARD
            .decode(&config.secret_key)
            .unwrap();
        let expires =
            (chrono::Utc::now() + chrono::Duration::seconds(300)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let request_b64 = base64url_encode_nopad(br#"{"amount":"1.00","currency":"usd","recipient":"0xrecipient"}"#);

        let id =
            compute_challenge_id(&secret, &config.realm, "tempo", "charge", &request_b64, Some(&expires), None, None)
                .unwrap();

        MppCredential {
            challenge: MppChallengeEcho {
                id,
                realm: config.realm.clone(),
                method: "tempo".to_string(),
                intent: "charge".to_string(),
                request: request_b64,
                expires: Some(expires),
                digest: None,
                description: None,
                opaque: None,
            },
            source: Some("did:key:z6Mk123".to_string()),
            payload: serde_json::json!({"proof": "0xabc123"}),
        }
    }

    #[test]
    fn test_extract_mpp_credential_from_header() {
        let credential = MppCredential {
            challenge: MppChallengeEcho {
                id: "test-id".to_string(),
                realm: "example.com".to_string(),
                method: "tempo".to_string(),
                intent: "charge".to_string(),
                request: "eyJ0ZXN0IjoxfQ".to_string(),
                expires: None,
                digest: None,
                description: None,
                opaque: None,
            },
            source: None,
            payload: serde_json::json!({"proof": "0x123"}),
        };

        let json = serde_json::to_vec(&credential).unwrap();
        let encoded = base64url_encode_nopad(&json);

        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Payment {}", encoded)
                .parse()
                .unwrap(),
        );

        let extracted = extract_mpp_credential(&headers);
        assert!(extracted.is_some());
        let extracted = extracted.unwrap();
        assert_eq!(extracted.challenge.id, "test-id");
        assert_eq!(extracted.challenge.method, "tempo");
    }

    #[test]
    fn test_extract_mpp_credential_no_header() {
        let headers = HeaderMap::new();
        assert!(extract_mpp_credential(&headers).is_none());
    }

    #[test]
    fn test_extract_mpp_credential_wrong_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            "Bearer abc123"
                .parse()
                .unwrap(),
        );
        assert!(extract_mpp_credential(&headers).is_none());
    }

    #[test]
    fn test_verify_mpp_credential_valid() {
        let config = test_config();
        let credential = make_valid_credential(&config);
        let result = verify_mpp_credential(&credential, &config);
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
    }

    #[test]
    fn test_verify_mpp_credential_wrong_realm() {
        let config = test_config();
        let mut credential = make_valid_credential(&config);
        credential.challenge.realm = "wrong.example.com".to_string();
        let result = verify_mpp_credential(&credential, &config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("HMAC binding")
        );
    }

    #[test]
    fn test_verify_mpp_credential_expired() {
        let config = test_config();
        let mut credential = make_valid_credential(&config);
        // Set expires to the past
        let past =
            (chrono::Utc::now() - chrono::Duration::seconds(60)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        // Recompute challenge id with expired timestamp
        let secret = base64::engine::general_purpose::STANDARD
            .decode(&config.secret_key)
            .unwrap();
        let id = compute_challenge_id(
            &secret,
            &config.realm,
            "tempo",
            "charge",
            &credential.challenge.request,
            Some(&past),
            None,
            None,
        )
        .unwrap();

        credential.challenge.id = id;
        credential.challenge.expires = Some(past);

        let result = verify_mpp_credential(&credential, &config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("expired")
        );
    }

    #[test]
    fn test_verify_mpp_credential_empty_payload() {
        let config = test_config();
        let mut credential = make_valid_credential(&config);
        credential.payload = serde_json::json!({});
        let result = verify_mpp_credential(&credential, &config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Empty payment payload")
        );
    }

    #[test]
    fn test_verify_mpp_credential_unsupported_method() {
        let config = test_config();
        let secret = base64::engine::general_purpose::STANDARD
            .decode(&config.secret_key)
            .unwrap();
        let expires =
            (chrono::Utc::now() + chrono::Duration::seconds(300)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let request_b64 = base64url_encode_nopad(b"{}");

        let id = compute_challenge_id(
            &secret,
            &config.realm,
            "unknown_method",
            "charge",
            &request_b64,
            Some(&expires),
            None,
            None,
        )
        .unwrap();

        let credential = MppCredential {
            challenge: MppChallengeEcho {
                id,
                realm: config.realm.clone(),
                method: "unknown_method".to_string(),
                intent: "charge".to_string(),
                request: request_b64,
                expires: Some(expires),
                digest: None,
                description: None,
                opaque: None,
            },
            source: None,
            payload: serde_json::json!({"proof": "0x123"}),
        };

        let result = verify_mpp_credential(&credential, &config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Unsupported payment method")
        );
    }

    #[test]
    fn test_create_mpp_receipt() {
        let receipt_b64 = create_mpp_receipt("tempo", "0xdeadbeef").unwrap();
        let decoded = base64url_decode_nopad(&receipt_b64).unwrap();
        let receipt: MppReceipt = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(receipt.status, "success");
        assert_eq!(receipt.method, "tempo");
        assert_eq!(receipt.reference, "0xdeadbeef");
        assert!(!receipt.timestamp.is_empty());
    }

    #[tokio::test]
    async fn test_verify_payment_proof_crypto_passthrough() {
        let config = test_config();
        let credential = make_valid_credential(&config);
        // Crypto methods pass through with the proof as reference
        let result = verify_payment_proof(&credential, &config).await;
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
        assert_eq!(result.unwrap().reference, "0xabc123");
    }

    #[tokio::test]
    async fn test_verify_payment_proof_card_no_stripe_key() {
        let mut config = test_config();
        config.stripe_secret_key = None;
        config
            .payment_methods
            .push(MppPaymentMethod {
                method: "card".to_string(),
                intent: "charge".to_string(),
                currency: "usd".to_string(),
                recipient: "acct_test123".to_string(),
                amount: "1.00".to_string(),
                network: None,
            });

        // Build a card credential
        let secret = base64::engine::general_purpose::STANDARD
            .decode(&config.secret_key)
            .unwrap();
        let expires =
            (chrono::Utc::now() + chrono::Duration::seconds(300)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let request_b64 = base64url_encode_nopad(br#"{"amount":"1.00","currency":"usd","recipient":"acct_test123"}"#);
        let id =
            compute_challenge_id(&secret, &config.realm, "card", "charge", &request_b64, Some(&expires), None, None)
                .unwrap();

        let credential = MppCredential {
            challenge: MppChallengeEcho {
                id,
                realm: config.realm.clone(),
                method: "card".to_string(),
                intent: "charge".to_string(),
                request: request_b64,
                expires: Some(expires),
                digest: None,
                description: None,
                opaque: None,
            },
            source: None,
            payload: serde_json::json!({"payment_method": "pm_test123"}),
        };

        let result = verify_payment_proof(&credential, &config).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("stripe_secret_key"),
            "Should error about missing stripe_secret_key"
        );
    }

    #[tokio::test]
    async fn test_verify_payment_proof_card_missing_pm_field() {
        let mut config = test_config();
        config.stripe_secret_key = Some("sk_test_fake".to_string());
        config
            .payment_methods
            .push(MppPaymentMethod {
                method: "card".to_string(),
                intent: "charge".to_string(),
                currency: "usd".to_string(),
                recipient: "acct_test123".to_string(),
                amount: "1.00".to_string(),
                network: None,
            });

        let secret = base64::engine::general_purpose::STANDARD
            .decode(&config.secret_key)
            .unwrap();
        let expires =
            (chrono::Utc::now() + chrono::Duration::seconds(300)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let request_b64 = base64url_encode_nopad(br#"{"amount":"1.00","currency":"usd","recipient":"acct_test123"}"#);
        let id =
            compute_challenge_id(&secret, &config.realm, "card", "charge", &request_b64, Some(&expires), None, None)
                .unwrap();

        // Credential payload WITHOUT payment_method field
        let credential = MppCredential {
            challenge: MppChallengeEcho {
                id,
                realm: config.realm.clone(),
                method: "card".to_string(),
                intent: "charge".to_string(),
                request: request_b64,
                expires: Some(expires),
                digest: None,
                description: None,
                opaque: None,
            },
            source: None,
            payload: serde_json::json!({"some_other_field": "value"}),
        };

        let result = verify_payment_proof(&credential, &config).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("payment_method"),
            "Should error about missing payment_method field"
        );
    }

    #[tokio::test]
    async fn test_verify_payment_proof_card_invalid_pm_format() {
        let mut config = test_config();
        config.stripe_secret_key = Some("sk_test_fake".to_string());
        config
            .payment_methods
            .push(MppPaymentMethod {
                method: "card".to_string(),
                intent: "charge".to_string(),
                currency: "usd".to_string(),
                recipient: "acct_test123".to_string(),
                amount: "1.00".to_string(),
                network: None,
            });

        let secret = base64::engine::general_purpose::STANDARD
            .decode(&config.secret_key)
            .unwrap();
        let expires =
            (chrono::Utc::now() + chrono::Duration::seconds(300)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let request_b64 = base64url_encode_nopad(br#"{"amount":"1.00","currency":"usd","recipient":"acct_test123"}"#);
        let id =
            compute_challenge_id(&secret, &config.realm, "card", "charge", &request_b64, Some(&expires), None, None)
                .unwrap();

        // Credential with INVALID payment_method format (not pm_ prefix)
        let credential = MppCredential {
            challenge: MppChallengeEcho {
                id,
                realm: config.realm.clone(),
                method: "card".to_string(),
                intent: "charge".to_string(),
                request: request_b64,
                expires: Some(expires),
                digest: None,
                description: None,
                opaque: None,
            },
            source: None,
            payload: serde_json::json!({"payment_method": "tok_visa"}),
        };

        let result = verify_payment_proof(&credential, &config).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Invalid payment_method format"),
            "Should error about invalid PM format"
        );
    }

    #[tokio::test]
    async fn test_verify_payment_proof_unknown_method_fails_closed() {
        let mut config = test_config();
        config
            .payment_methods
            .push(MppPaymentMethod {
                method: "lightning".to_string(),
                intent: "charge".to_string(),
                currency: "btc".to_string(),
                recipient: "lnbc1...".to_string(),
                amount: "0.001".to_string(),
                network: None,
            });

        let secret = base64::engine::general_purpose::STANDARD
            .decode(&config.secret_key)
            .unwrap();
        let expires =
            (chrono::Utc::now() + chrono::Duration::seconds(300)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let request_b64 = base64url_encode_nopad(br#"{"amount":"0.001","currency":"btc","recipient":"lnbc1..."}"#);
        let id = compute_challenge_id(
            &secret,
            &config.realm,
            "lightning",
            "charge",
            &request_b64,
            Some(&expires),
            None,
            None,
        )
        .unwrap();

        let credential = MppCredential {
            challenge: MppChallengeEcho {
                id,
                realm: config.realm.clone(),
                method: "lightning".to_string(),
                intent: "charge".to_string(),
                request: request_b64,
                expires: Some(expires),
                digest: None,
                description: None,
                opaque: None,
            },
            source: None,
            payload: serde_json::json!({"reference": "ln_invoice_abc"}),
        };

        // An unsupported payment method has no verification implementation, so
        // it MUST be rejected rather than granted on an unverified payload.
        let result = verify_payment_proof(&credential, &config).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("No verification implementation"),
            "Should fail closed for an unimplemented method"
        );
    }
}
