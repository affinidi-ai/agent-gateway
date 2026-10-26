//! The Payment Manifest an agent-pay gateway publishes for one payment
//! surface: what is being sold, its price, and every way to pay for it.
//!
//! The shape mirrors agent-pay's own manifest and is parsed leniently: unknown
//! fields are ignored and missing ones default, so a newer peer never breaks
//! discovery. `PaymentPoint::detail` stays raw JSON because its shape depends
//! on the payment kind.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PaymentManifest {
    pub version: String,
    pub payable: PayableRef,
    pub amount: Money,
    pub payment_points: Vec<PaymentPoint>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub variants: Vec<VariantSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PayableRef {
    pub id: String,
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surface_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<VariantRef>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct VariantRef {
    pub id: String,
    pub alias: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct VariantSummary {
    pub alias: String,
    pub name: String,
    pub is_default: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<Money>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Money {
    pub amount: String,
    pub unit: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PaymentPoint {
    pub id: String,
    pub label: String,
    /// `x402` or `mpp`.
    pub protocol: String,
    pub credential: String,
    pub detail: serde_json::Value,
}

impl PaymentManifest {
    /// A manifest can back an `agent_pay` policy only when it offers at
    /// least one way to pay.
    pub fn is_payable(&self) -> bool {
        !self.payment_points.is_empty()
    }

    /// Whether any payment point uses the given protocol (`x402` or `mpp`).
    pub fn offers_protocol(
        &self,
        protocol: &str,
    ) -> bool {
        self.payment_points
            .iter()
            .any(|point| {
                point
                    .protocol
                    .eq_ignore_ascii_case(protocol)
            })
    }

    /// Whether MPP is the only way to pay.
    pub fn is_mpp_only(&self) -> bool {
        self.offers_protocol("mpp") && !self.offers_protocol("x402")
    }

    fn point_ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = self
            .payment_points
            .iter()
            .map(|point| point.id.as_str())
            .collect();
        ids.sort_unstable();
        ids
    }

    /// Whether both manifests offer the same thing: the same price, payment
    /// points (matched by id, whatever their order) and variants. The signed
    /// `credential` is new on every fetch and a label changes nothing that is
    /// charged, so neither counts.
    pub fn offers_same_as(
        &self,
        other: &PaymentManifest,
    ) -> bool {
        self.amount == other.amount
            && self.point_terms() == other.point_terms()
            && self.variants_by_alias() == other.variants_by_alias()
    }

    fn point_terms(&self) -> Vec<(&str, &str, &str, &serde_json::Value)> {
        let mut points: Vec<_> = self
            .payment_points
            .iter()
            .map(|point| (point.id.as_str(), point.protocol.as_str(), point.credential.as_str(), &point.detail))
            .collect();
        points.sort_by(|a, b| a.0.cmp(b.0));
        points
    }

    fn variants_by_alias(&self) -> Vec<&VariantSummary> {
        let mut variants: Vec<_> = self.variants.iter().collect();
        variants.sort_by(|a, b| a.alias.cmp(&b.alias));
        variants
    }

    /// Describes how the price or the payment points changed between two
    /// manifests, or `None` when neither did.
    pub fn drift_from(
        &self,
        previous: &PaymentManifest,
    ) -> Option<String> {
        let mut changes = Vec::new();
        if self.amount != previous.amount {
            changes.push(format!(
                "amount {} {} -> {} {}",
                previous.amount.amount, previous.amount.unit, self.amount.amount, self.amount.unit
            ));
        }
        let (before, after) = (previous.point_ids(), self.point_ids());
        if before != after {
            changes.push(format!("payment points [{}] -> [{}]", before.join(", "), after.join(", ")));
        }
        (!changes.is_empty()).then(|| changes.join("; "))
    }
}

/// Why a manifest could not be fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestFetchError {
    /// The peer could not be reached or did not answer in time.
    Unavailable(String),
    /// The peer answered but refused the request or sent something unusable.
    Rejected(String),
}

impl std::fmt::Display for ManifestFetchError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(f, "payment gateway unavailable: {reason}"),
            Self::Rejected(reason) => write!(f, "payment gateway rejected the manifest request: {reason}"),
        }
    }
}

/// Parses a `get-manifest-response` body: `{"manifest": {...} | null}` or
/// `{"error": "...", "manifest": null}`.
pub fn parse_manifest_response(body: &serde_json::Value) -> Result<Option<PaymentManifest>, ManifestFetchError> {
    if let Some(error) = body
        .get("error")
        .filter(|error| !error.is_null())
    {
        let reason = error
            .as_str()
            .map(|reason| crate::a2a::clip_for_log(reason).to_string())
            .unwrap_or_else(|| "unspecified error".to_string());
        return Err(ManifestFetchError::Rejected(reason));
    }
    match body.get("manifest") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(manifest) => serde_json::from_value(manifest.clone())
            .map(Some)
            .map_err(|error| ManifestFetchError::Rejected(format!("malformed manifest: {error}"))),
    }
}

const MAX_PAYMENT_SURFACE_ID_LEN: usize = 256;

/// A payment surface id is the remote surface id, optionally followed by one
/// `$alias` naming a variant.
pub fn is_valid_payment_surface_id(id: &str) -> bool {
    let (base, alias) = match id.split_once('$') {
        Some((base, alias)) => (base, Some(alias)),
        None => (id, None),
    };
    let well_formed = |part: &str| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    id.len() <= MAX_PAYMENT_SURFACE_ID_LEN && well_formed(base) && alias.is_none_or(well_formed)
}

/// What `fetch_payment_manifest` answers for a payment surface in a test, in
/// place of asking a payment gateway over the fabric.
#[cfg(test)]
type TestAnswers = Mutex<HashMap<CacheKey, Result<Option<PaymentManifest>, ManifestFetchError>>>;

#[cfg(test)]
static TEST_ANSWERS: LazyLock<TestAnswers> = LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
pub(crate) fn install_test_answer(
    gateway_id: &str,
    surface_id: &str,
    answer: Result<Option<PaymentManifest>, ManifestFetchError>,
) {
    TEST_ANSWERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert((gateway_id.to_string(), surface_id.to_string()), answer);
}

#[cfg(test)]
pub(crate) fn test_answer(
    gateway_id: &str,
    surface_id: &str,
) -> Option<Result<Option<PaymentManifest>, ManifestFetchError>> {
    TEST_ANSWERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&(gateway_id.to_string(), surface_id.to_string()))
        .cloned()
}

const CACHE_TTL: Duration = Duration::from_secs(60);
/// How many manifests are kept; once full, a fetch is simply not reused.
const MAX_CACHED_MANIFESTS: usize = 1024;

type CacheKey = (String, String);
type CacheEntry = (Instant, PaymentManifest);

static MANIFEST_CACHE: LazyLock<Mutex<HashMap<CacheKey, CacheEntry>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// The payable manifest fetched for `surface_id` on `gateway_id` in the last
/// minute. A missing or unpayable answer is never kept, so fixing the payment
/// surface takes effect on the next fetch.
pub(crate) fn cached_manifest(
    gateway_id: &str,
    surface_id: &str,
) -> Option<PaymentManifest> {
    let cache = MANIFEST_CACHE.lock().ok()?;
    cache
        .get(&(gateway_id.to_string(), surface_id.to_string()))
        .filter(|(fetched_at, _)| fetched_at.elapsed() < CACHE_TTL)
        .map(|(_, manifest)| manifest.clone())
}

pub(crate) fn cache_manifest(
    gateway_id: &str,
    surface_id: &str,
    manifest: PaymentManifest,
) {
    if let Ok(mut cache) = MANIFEST_CACHE.lock() {
        cache.retain(|_, (fetched_at, _)| fetched_at.elapsed() < CACHE_TTL);
        let key = (gateway_id.to_string(), surface_id.to_string());
        if cache.len() < MAX_CACHED_MANIFESTS || cache.contains_key(&key) {
            cache.insert(key, (Instant::now(), manifest));
        }
    }
}

/// The least time between two forced refreshes of one manifest.
const MIN_FORCED_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

static FORCED_REFRESHES: LazyLock<Mutex<HashMap<CacheKey, Instant>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Whether the manifest of `surface_id` on `gateway_id` may be refreshed from
/// the payment gateway now, and notes it if so. A forced refresh asks the
/// payment gateway over the fabric, so each manifest is asked for at most once
/// per [`MIN_FORCED_REFRESH_INTERVAL`] and no more than
/// [`MAX_CACHED_MANIFESTS`] are tracked; past that a manifest that is not
/// tracked is not refreshed.
pub(crate) fn forced_refresh_due(
    gateway_id: &str,
    surface_id: &str,
    now: Instant,
) -> bool {
    let Ok(mut refreshes) = FORCED_REFRESHES.lock() else {
        return false;
    };
    let key = (gateway_id.to_string(), surface_id.to_string());
    let recent = |asked_at: &Instant| now.saturating_duration_since(*asked_at) < MIN_FORCED_REFRESH_INTERVAL;
    if refreshes
        .get(&key)
        .is_some_and(recent)
    {
        return false;
    }
    if refreshes.len() >= MAX_CACHED_MANIFESTS && !refreshes.contains_key(&key) {
        refreshes.retain(|_, asked_at| recent(asked_at));
        if refreshes.len() >= MAX_CACHED_MANIFESTS {
            return false;
        }
    }
    refreshes.insert(key, now);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_manifest_is_force_refreshed_once_per_interval() {
        let gateway = format!("gw-{}", uuid::Uuid::new_v4());
        let now = Instant::now();
        assert!(forced_refresh_due(&gateway, "pay-1", now));
        assert!(!forced_refresh_due(&gateway, "pay-1", now + Duration::from_secs(9)));
        assert!(forced_refresh_due(&gateway, "pay-2", now), "another surface is independent");
        assert!(forced_refresh_due(&gateway, "pay-1", now + MIN_FORCED_REFRESH_INTERVAL));
        assert!(!forced_refresh_due(&gateway, "pay-1", now + MIN_FORCED_REFRESH_INTERVAL));
    }

    fn manifest_json() -> serde_json::Value {
        json!({
            "version": "1",
            "payable": {"id": "pay-1$pro", "name": "Search", "description": "Paid search", "surface_id": "pay-1",
                        "variant": {"id": "v1", "alias": "pro"}},
            "amount": {"amount": "0.01", "unit": "USDC"},
            "payment_points": [
                {"id": "x402:base", "label": "USDC on Base", "protocol": "x402", "credential": "eip3009_signature",
                 "detail": {"kind": "onChain", "scheme": "exact", "network": "base", "pay_to": "0xabc"}},
                {"id": "mpp:stripe:card", "label": "Card", "protocol": "mpp", "credential": "shared_payment_token",
                 "detail": {"kind": "settled", "provider": "stripe", "instrument": {"type": "card"}}}
            ],
            "variants": [{"alias": "pro", "name": "Pro", "is_default": false, "amount": {"amount": "0.05", "unit": "USDC"}}],
            "future_field": {"ignored": true}
        })
    }

    #[test]
    fn a_full_manifest_parses_and_unknown_fields_are_ignored() {
        let manifest = parse_manifest_response(&json!({"manifest": manifest_json()}))
            .unwrap()
            .unwrap();
        assert_eq!(manifest.payable.id, "pay-1$pro");
        assert_eq!(
            manifest
                .payable
                .surface_id
                .as_deref(),
            Some("pay-1")
        );
        assert_eq!(
            manifest
                .payable
                .variant
                .as_ref()
                .map(|v| v.alias.as_str()),
            Some("pro")
        );
        assert_eq!(
            manifest.amount,
            Money {
                amount: "0.01".into(),
                unit: "USDC".into()
            }
        );
        assert_eq!(manifest.payment_points.len(), 2);
        assert_eq!(manifest.payment_points[1].detail["provider"], "stripe");
        assert_eq!(
            manifest.variants[0]
                .amount
                .as_ref()
                .map(|m| m.amount.as_str()),
            Some("0.05")
        );
        assert!(manifest.is_payable());
        assert!(manifest.offers_protocol("mpp"));
        assert!(manifest.offers_protocol("X402"));
        assert!(!manifest.is_mpp_only());
    }

    #[test]
    fn a_sparse_manifest_parses_with_defaults() {
        let manifest = parse_manifest_response(&json!({"manifest": {"payment_points": [{"id": "x402:base"}]}}))
            .unwrap()
            .unwrap();
        assert_eq!(manifest.version, "");
        assert_eq!(manifest.payment_points[0].protocol, "");
        assert!(manifest.is_payable());
        assert!(!manifest.offers_protocol("mpp"));
        assert!(!manifest.is_mpp_only());
    }

    #[test]
    fn a_manifest_with_only_mpp_points_is_mpp_only() {
        let manifest = parse_manifest_response(
            &json!({"manifest": {"payment_points": [{"id": "mpp:stripe:card", "protocol": "mpp"}]}}),
        )
        .unwrap()
        .unwrap();
        assert!(manifest.is_mpp_only());
    }

    #[test]
    fn a_null_or_missing_manifest_is_none() {
        assert_eq!(parse_manifest_response(&json!({"manifest": null})), Ok(None));
        assert_eq!(parse_manifest_response(&json!({})), Ok(None));
    }

    #[test]
    fn a_peer_error_is_rejected() {
        assert_eq!(
            parse_manifest_response(&json!({"error": "channel not exposed", "manifest": null})),
            Err(ManifestFetchError::Rejected("channel not exposed".into()))
        );
    }

    #[test]
    fn a_malformed_manifest_is_rejected() {
        let result = parse_manifest_response(&json!({"manifest": {"payment_points": "not-a-list"}}));
        assert!(
            matches!(result, Err(ManifestFetchError::Rejected(reason)) if reason.starts_with("malformed manifest"))
        );
    }

    #[test]
    fn a_manifest_without_points_is_not_payable() {
        assert!(!PaymentManifest::default().is_payable());
    }

    #[test]
    fn drift_reports_amount_and_point_changes() {
        let before: PaymentManifest = serde_json::from_value(manifest_json()).unwrap();
        assert_eq!(before.drift_from(&before), None);

        let mut after = before.clone();
        after.amount.amount = "0.02".into();
        after.payment_points.pop();
        assert_eq!(
            after
                .drift_from(&before)
                .as_deref(),
            Some("amount 0.01 USDC -> 0.02 USDC; payment points [mpp:stripe:card, x402:base] -> [x402:base]")
        );
    }

    #[test]
    fn drift_ignores_point_order_and_label_changes() {
        let before: PaymentManifest = serde_json::from_value(manifest_json()).unwrap();
        let mut after = before.clone();
        after.payment_points.reverse();
        after.payment_points[0].label = "Renamed".into();
        assert_eq!(after.drift_from(&before), None);
    }

    #[test]
    fn payment_surface_ids_accept_an_optional_alias() {
        assert!(is_valid_payment_surface_id("4f1c2a9e-1b2c-4d5e-8f90-123456789abc"));
        assert!(is_valid_payment_surface_id("pay_surface$pro"));
        assert!(!is_valid_payment_surface_id(""));
        assert!(!is_valid_payment_surface_id("$pro"));
        assert!(!is_valid_payment_surface_id("pay$"));
        assert!(!is_valid_payment_surface_id("pay$pro$extra"));
        assert!(!is_valid_payment_surface_id("pay surface"));
        assert!(!is_valid_payment_surface_id("../etc"));
        assert!(!is_valid_payment_surface_id(&"a".repeat(MAX_PAYMENT_SURFACE_ID_LEN + 1)));
    }

    #[test]
    fn the_cache_returns_fresh_entries_only_for_the_same_key() {
        cache_manifest("gw-cache-test", "pay-1", PaymentManifest::default());
        assert_eq!(cached_manifest("gw-cache-test", "pay-1"), Some(PaymentManifest::default()));
        assert_eq!(cached_manifest("gw-cache-test", "pay-2"), None);
        assert_eq!(cached_manifest("gw-other", "pay-1"), None);
    }

    #[test]
    fn the_cache_stays_bounded() {
        let gateway = format!("gw-bounded-{}", uuid::Uuid::new_v4());
        for i in 0..MAX_CACHED_MANIFESTS + 10 {
            cache_manifest(&gateway, &format!("pay-{i}"), PaymentManifest::default());
        }
        let kept = (0..MAX_CACHED_MANIFESTS + 10)
            .filter(|i| cached_manifest(&gateway, &format!("pay-{i}")).is_some())
            .count();
        assert!(kept <= MAX_CACHED_MANIFESTS, "{kept}");
        assert!(kept > 0);
        assert!(
            MANIFEST_CACHE
                .lock()
                .unwrap()
                .len()
                <= MAX_CACHED_MANIFESTS
        );
    }

    #[test]
    fn a_fresh_credential_does_not_make_a_manifest_differ() {
        let before: PaymentManifest = serde_json::from_value(manifest_json()).unwrap();
        let mut after = before.clone();
        after.credential = Some("eyJhbGciOiJFZERTQSJ9.fresh.signature".into());
        assert_ne!(before, after);
        assert!(before.offers_same_as(&after));
        assert!(after.offers_same_as(&before));
    }

    #[test]
    fn point_order_labels_and_descriptions_do_not_make_a_manifest_differ() {
        let before: PaymentManifest = serde_json::from_value(manifest_json()).unwrap();
        let mut after = before.clone();
        after.payment_points.reverse();
        after.payment_points[0].label = "Renamed".into();
        after.payable.description = "Reworded".into();
        assert!(before.offers_same_as(&after));
    }

    #[test]
    fn a_changed_price_point_or_variant_makes_a_manifest_differ() {
        let before: PaymentManifest = serde_json::from_value(manifest_json()).unwrap();
        let differs = |change: &dyn Fn(&mut PaymentManifest)| {
            let mut after = before.clone();
            change(&mut after);
            !before.offers_same_as(&after) && !after.offers_same_as(&before)
        };
        assert!(differs(&|m| m.amount.amount = "0.02".into()));
        assert!(differs(&|m| m.amount.unit = "USD".into()));
        assert!(differs(&|m| {
            m.payment_points.pop();
        }));
        assert!(differs(&|m| m.payment_points[0].protocol = "mpp".into()));
        assert!(differs(&|m| m.payment_points[0].credential = "permit2_signature".into()));
        assert!(differs(&|m| m.payment_points[0].detail["network"] = "base-sepolia".into()));
        assert!(differs(&|m| m.variants[0].amount = None));
        assert!(differs(&|m| m.variants.clear()));
    }
}
