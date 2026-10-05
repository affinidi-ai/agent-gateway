//! Stripe API client for MPP payment verification
//!
//! Lightweight Stripe API integration using reqwest — no SDK dependency.
//! Supports the Payment Token model: the client supplies a stored
//! `PaymentMethod` ID (`pm_xxx`), and the server creates + confirms a
//! `PaymentIntent` to charge it.
//!
//! Reference: <https://docs.stripe.com/api/payment_intents>

use serde::Deserialize;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Stripe API types (subset we need)
// ---------------------------------------------------------------------------

/// Stripe PaymentIntent — only the fields we care about.
#[derive(Debug, Clone, Deserialize)]
pub struct StripePaymentIntent {
    pub id: String,
    pub status: String,
}

/// Stripe API error envelope.
#[derive(Debug, Deserialize)]
struct StripeErrorResponse {
    error: StripeApiError,
}

#[derive(Debug, Deserialize)]
struct StripeApiError {
    #[serde(rename = "type")]
    error_type: String,
    message: String,
    #[serde(default)]
    code: Option<String>,
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Errors from Stripe operations.
#[derive(Debug)]
pub enum StripeError {
    /// The PaymentIntent could not be created or confirmed.
    PaymentFailed(String),
    /// The PaymentIntent was created but requires additional action (3DS, etc.)
    RequiresAction(String),
    /// Network or serialisation error.
    Network(String),
}

impl std::fmt::Display for StripeError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::PaymentFailed(msg) => write!(f, "Stripe payment failed: {}", msg),
            Self::RequiresAction(msg) => write!(f, "Stripe payment requires action: {}", msg),
            Self::Network(msg) => write!(f, "Stripe network error: {}", msg),
        }
    }
}

impl std::error::Error for StripeError {}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

const STRIPE_API_BASE: &str = "https://api.stripe.com/v1";

/// The chargeable payment source presented in an MPP Stripe credential.
///
/// `draft-stripe-charge-00` carries a single-use Shared Payment Token
/// (`spt_...`); legacy credentials carry a reusable Stripe PaymentMethod
/// (`pm_...`). Each maps to a different Stripe `POST /v1/payment_intents` form
/// field.
pub enum StripePaymentSource {
    /// Reusable Stripe PaymentMethod id (`pm_...`).
    PaymentMethod(String),
    /// Single-use Shared Payment Token (`spt_...`), per draft-stripe-charge-00.
    SharedPaymentToken(String),
}

impl StripePaymentSource {
    /// The Stripe form field + value that charges this source. An SPT is charged
    /// via `payment_method_data[shared_payment_granted_token]`; a PaymentMethod
    /// via `payment_method`.
    fn form_field(&self) -> (&'static str, String) {
        match self {
            Self::PaymentMethod(id) => ("payment_method", id.clone()),
            Self::SharedPaymentToken(spt) => ("payment_method_data[shared_payment_granted_token]", spt.clone()),
        }
    }

    /// A log-safe label identifying the source kind (never the token value).
    fn label(&self) -> &'static str {
        match self {
            Self::PaymentMethod(_) => "payment_method",
            Self::SharedPaymentToken(_) => "shared_payment_token",
        }
    }
}

/// Lightweight Stripe API client.
pub struct StripeClient {
    api_key: String,
    http: reqwest::Client,
}

impl StripeClient {
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_owned(),
            http: reqwest::Client::new(),
        }
    }

    /// Create **and confirm** a PaymentIntent for the given payment source.
    ///
    /// The source is either a reusable Stripe PaymentMethod (`pm_...`) or a
    /// single-use Shared Payment Token (`spt_...`); each maps to its own Stripe
    /// form field.
    ///
    /// `amount` is in the currency's smallest unit (e.g. cents for USD).
    ///
    /// When `idempotency_key` is `Some`, it is sent as Stripe's `Idempotency-Key`
    /// header so a resubmission of the same challenge reuses the original
    /// PaymentIntent instead of charging the card twice.
    pub async fn create_and_confirm_payment(
        &self,
        amount: i64,
        currency: &str,
        source: &StripePaymentSource,
        description: Option<&str>,
        transfer_destination: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> Result<StripePaymentIntent, StripeError> {
        let (source_field, source_value) = source.form_field();
        let mut form: Vec<(&str, String)> = vec![
            ("amount", amount.to_string()),
            ("currency", currency.to_lowercase()),
            (source_field, source_value),
            ("confirm", "true".to_owned()),
            ("capture_method", "automatic".to_owned()),
            ("off_session", "true".to_owned()),
        ];

        if let Some(desc) = description {
            form.push(("description", desc.to_owned()));
        }
        if let Some(dest) = transfer_destination {
            form.push(("transfer_data[destination]", dest.to_owned()));
        }

        debug!(
            amount = amount,
            currency = currency,
            source = source.label(),
            "[stripe] Creating and confirming PaymentIntent"
        );

        let response = self
            .http
            .post(format!("{}/payment_intents", STRIPE_API_BASE))
            .basic_auth(&self.api_key, None::<&str>)
            .form(&form);

        let response = if let Some(key) = idempotency_key {
            response.header("Idempotency-Key", key)
        } else {
            response
        };

        let response = response
            .send()
            .await
            .map_err(|e| StripeError::Network(e.to_string()))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| StripeError::Network(e.to_string()))?;

        if !status.is_success() {
            if let Ok(err_resp) = serde_json::from_str::<StripeErrorResponse>(&body) {
                warn!(
                    error_type = %err_resp.error.error_type,
                    message = %err_resp.error.message,
                    code = ?err_resp.error.code,
                    "[stripe] PaymentIntent creation failed"
                );
                return Err(StripeError::PaymentFailed(err_resp.error.message));
            }
            return Err(StripeError::PaymentFailed(format!("HTTP {}: {}", status, body)));
        }

        let pi: StripePaymentIntent = serde_json::from_str(&body)
            .map_err(|e| StripeError::Network(format!("Failed to parse response: {}", e)))?;

        match pi.status.as_str() {
            "succeeded" => Ok(pi),
            "requires_action" | "requires_confirmation" => {
                Err(StripeError::RequiresAction(format!("PaymentIntent {} status: {}", pi.id, pi.status)))
            }
            other => {
                Err(StripeError::PaymentFailed(format!("PaymentIntent {} has unexpected status: {}", pi.id, other)))
            }
        }
    }
}

/// Parse an MPP amount string (e.g. "0.01") into Stripe's smallest-unit
/// integer for the given currency.
///
/// For currencies with 2 decimal places (USD, EUR, GBP, etc.), "0.01" → 1.
/// For zero-decimal currencies (JPY, KRW), "100" → 100.
pub fn amount_to_stripe_units(
    amount_str: &str,
    currency: &str,
) -> Result<i64, String> {
    let amount: f64 = amount_str
        .parse()
        .map_err(|e| format!("Invalid amount '{}': {}", amount_str, e))?;

    let decimals = stripe_currency_decimals(currency);
    let multiplier = 10_f64.powi(decimals as i32);
    let units = (amount * multiplier).round() as i64;

    if units <= 0 {
        return Err(format!("Amount must be positive, got {} ({})", amount_str, units));
    }

    Ok(units)
}

/// Return the number of decimal places for a currency in Stripe.
/// Zero-decimal currencies: JPY, KRW, VND, etc.
/// Most others are 2 decimals.
fn stripe_currency_decimals(currency: &str) -> u32 {
    match currency
        .to_uppercase()
        .as_str()
    {
        "JPY" | "KRW" | "VND" | "BIF" | "CLP" | "DJF" | "GNF" | "ISK" | "KMF" | "PYG" | "RWF" | "UGX" | "VUV"
        | "XAF" | "XOF" | "XPF" => 0,
        _ => 2,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amount_to_stripe_units_usd() {
        assert_eq!(amount_to_stripe_units("1.00", "usd").unwrap(), 100);
        assert_eq!(amount_to_stripe_units("0.01", "usd").unwrap(), 1);
        assert_eq!(amount_to_stripe_units("10.50", "USD").unwrap(), 1050);
        assert_eq!(amount_to_stripe_units("99.99", "Usd").unwrap(), 9999);
    }

    #[test]
    fn test_amount_to_stripe_units_jpy() {
        assert_eq!(amount_to_stripe_units("100", "jpy").unwrap(), 100);
        assert_eq!(amount_to_stripe_units("1", "JPY").unwrap(), 1);
    }

    #[test]
    fn test_amount_to_stripe_units_eur() {
        assert_eq!(amount_to_stripe_units("5.00", "eur").unwrap(), 500);
    }

    #[test]
    fn test_amount_to_stripe_units_invalid() {
        assert!(amount_to_stripe_units("abc", "usd").is_err());
        assert!(amount_to_stripe_units("-1.00", "usd").is_err());
        assert!(amount_to_stripe_units("0.00", "usd").is_err());
    }

    #[test]
    fn test_stripe_payment_intent_decoder_contract() {
        let minimal = serde_json::from_str::<StripePaymentIntent>(r#"{"id":"pi_123","status":"succeeded"}"#).unwrap();
        assert_eq!(minimal.id, "pi_123");
        assert_eq!(minimal.status, "succeeded");

        let with_extra_fields = serde_json::from_str::<StripePaymentIntent>(
            r#"{"id":"pi_456","status":"requires_action","amount":1050,"currency":"usd","payment_method":"pm_abc","client_secret":"placeholder-value"}"#,
        )
        .unwrap();
        assert_eq!(with_extra_fields.id, "pi_456");
        assert_eq!(with_extra_fields.status, "requires_action");

        let without_amount_currency = serde_json::from_str::<StripePaymentIntent>(
            r#"{"id":"pi_789","status":"processing","payment_method":"pm_def"}"#,
        )
        .unwrap();
        assert_eq!(without_amount_currency.id, "pi_789");
        assert_eq!(without_amount_currency.status, "processing");
    }

    #[test]
    fn test_stripe_error_display() {
        let err = StripeError::PaymentFailed("card declined".into());
        assert_eq!(err.to_string(), "Stripe payment failed: card declined");

        let err = StripeError::RequiresAction("3DS required".into());
        assert_eq!(err.to_string(), "Stripe payment requires action: 3DS required");

        let err = StripeError::Network("timeout".into());
        assert_eq!(err.to_string(), "Stripe network error: timeout");
    }
}
