//! Shared runtime health status and diagnostics for DIDComm connections.
//!
//! Both gateway connection points (`src/gateways/connection_points`) and trust
//! registry connections (`src/trust_registries`) maintain long-lived DIDComm
//! links to mediators and need the same vocabulary for representing a broken
//! connection: a listener-level state, a stable machine-readable error code,
//! and a diagnostics object (why it failed, when it was last healthy, when it
//! will retry). Those types live here so both sides reuse one definition rather
//! than duplicating it.
//!
//! This module is the data model only. Populating it from the reconnect
//! scheduler (proposal section C) and composing it with workflow status
//! (section F) are handled by the consumers. Until the scheduler is wired, the
//! helpers carry `#[allow(dead_code)]`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Listener-level runtime state of a DIDComm connection.
///
/// `Reconnecting` is an internal state used between retry attempts; the API
/// layer collapses it to `failed` for the UI (see proposal §"Canonical
/// status"). Serialized lowercase (`connected` / `reconnecting` / `failed`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionStatus {
    Connected,
    Reconnecting,
    Failed,
}

/// Stable, machine-readable classification of a connection failure.
///
/// The serialized form is the SCREAMING_SNAKE_CASE string the dashboard and
/// alerting key off (e.g. `MEDIATOR_UNREACHABLE`). Rego/UI logic must branch on
/// this code, never on the free-text `error_message` / `original_error`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConnectionErrorCode {
    /// The mediator host could not be reached (DNS, refused, timed out).
    MediatorUnreachable,
    /// The mediator DID could not be resolved to a usable document/endpoint.
    MediatorDidResolutionFailed,
    /// Registering our profile with the mediator failed.
    ProfileRegistrationFailed,
    /// Authentication with the mediator failed.
    AuthenticationFailed,
    /// Key-agreement / signing material is incompatible (e.g. curve mismatch),
    /// typically after a mediator update.
    CryptoMismatch,
    /// An established WebSocket stream broke while receiving.
    WsStreamBroken,
    /// The partner gateway is unavailable: deactivated, it removed its
    /// connection point on its side, or it changed policy so our connection
    /// point can no longer reach it. Our mediator link may still be connected;
    /// the specific cause is carried in `original_error`.
    PeerGatewayUnavailable,
    /// Unclassified failure — see `original_error` for detail.
    Unknown,
}

impl ConnectionErrorCode {
    /// Operator-friendly, display-safe one-liner for this error code.
    ///
    /// This is the default `error_message`; the raw underlying error is kept
    /// separately in `original_error` for diagnostics.
    pub fn message(&self) -> &'static str {
        match self {
            Self::MediatorUnreachable => "Mediator is unreachable",
            Self::MediatorDidResolutionFailed => "Could not resolve the mediator DID",
            Self::ProfileRegistrationFailed => "Failed to register with the mediator",
            Self::AuthenticationFailed => "Authentication with the mediator failed",
            Self::CryptoMismatch => "Mediator cryptography is incompatible",
            Self::WsStreamBroken => "The mediator connection dropped",
            Self::PeerGatewayUnavailable => "The partner gateway is unavailable",
            Self::Unknown => "Connection failed",
        }
    }
}

/// Reconnect schedule: exponential backoff to a cap, then a fixed cadence at
/// the cap.
///
/// `backoff_seconds(n)` for the n-th consecutive failure (`n >= 1`) returns
/// `initial * multiplier^(n-1)`, clamped to `[initial, max]`. Once the product
/// reaches `max` it stays there, which is exactly the requested
/// exponential-then-fixed behaviour (e.g. 30s → 60s → … → 1800s, then every
/// 1800s).
#[derive(Clone, Copy, Debug)]
pub struct ReconnectPolicy {
    pub initial_backoff_seconds: u64,
    pub max_backoff_seconds: u64,
    pub backoff_multiplier: f64,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            initial_backoff_seconds: 30,
            max_backoff_seconds: 1800,
            backoff_multiplier: 2.0,
        }
    }
}

impl ReconnectPolicy {
    /// Backoff delay in seconds for the `consecutive_failures`-th failure.
    ///
    /// Bounded to `[initial, max]`. A non-increasing multiplier (`<= 1.0` or
    /// non-finite) degrades to a constant `initial` delay.
    pub fn backoff_seconds(
        &self,
        consecutive_failures: u64,
    ) -> u64 {
        let initial = self
            .initial_backoff_seconds
            .max(1);
        let max = self
            .max_backoff_seconds
            .max(initial);
        if consecutive_failures <= 1 {
            return initial;
        }
        if !self
            .backoff_multiplier
            .is_finite()
            || self.backoff_multiplier <= 1.0
        {
            return initial;
        }
        let mut delay = initial as f64;
        for _ in 1..consecutive_failures {
            delay *= self.backoff_multiplier;
            if delay >= max as f64 {
                return max;
            }
        }
        (delay as u64).clamp(initial, max)
    }
}

/// Runtime health + diagnostics for a single DIDComm connection.
///
/// Embedded on the owning record (e.g. `GatewayConnectionPoint`) and surfaced
/// verbatim by the API as `runtime_status`. `Option` fields are omitted from
/// the JSON when absent so a healthy connection serializes compactly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionRuntimeStatus {
    /// Listener-level runtime state. `Reconnecting` is internal; the API layer
    /// collapses it to `failed` for the UI.
    pub status: ConnectionStatus,

    /// Stable failure classification. `None` while healthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<ConnectionErrorCode>,

    /// Operator-friendly, sanitized failure reason. `None` while healthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,

    /// Raw underlying error, for diagnostics only (shown behind a details
    /// expander, never as the primary badge text). `None` while healthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_error: Option<String>,

    /// When the current failure streak started. `None` while healthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_failed_at: Option<DateTime<Utc>>,

    /// When the most recent failure occurred. `None` while healthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failed_at: Option<DateTime<Utc>>,

    /// When the connection was last healthy. `None` if it has never connected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_active_at: Option<DateTime<Utc>>,

    /// When the next automatic retry is scheduled. `None` when no retry is
    /// scheduled (healthy, or non-retryable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_retry_at: Option<DateTime<Utc>>,

    /// Number of consecutive failed attempts since the last healthy state.
    #[serde(default)]
    pub consecutive_failures: u64,

    /// Current backoff delay in seconds. `None` while healthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_backoff_seconds: Option<u64>,
}

impl Default for ConnectionRuntimeStatus {
    /// A freshly-created connection that has not connected yet: `Reconnecting`,
    /// no failure recorded, no prior active time.
    fn default() -> Self {
        Self {
            status: ConnectionStatus::Reconnecting,
            error_code: None,
            error_message: None,
            original_error: None,
            first_failed_at: None,
            last_failed_at: None,
            last_active_at: None,
            next_retry_at: None,
            consecutive_failures: 0,
            current_backoff_seconds: None,
        }
    }
}

impl ConnectionRuntimeStatus {
    /// Mark the connection healthy at `now`, clearing all failure diagnostics.
    pub fn mark_active(
        &mut self,
        now: DateTime<Utc>,
    ) {
        self.status = ConnectionStatus::Connected;
        self.error_code = None;
        self.error_message = None;
        self.original_error = None;
        self.first_failed_at = None;
        self.last_failed_at = None;
        self.next_retry_at = None;
        self.consecutive_failures = 0;
        self.current_backoff_seconds = None;
        self.last_active_at = Some(now);
    }

    /// Record a failure at `now` with the given classification and messages.
    ///
    /// Preserves `first_failed_at` across a streak and increments
    /// `consecutive_failures`. Scheduling the next retry (`next_retry_at` /
    /// `current_backoff_seconds`) is the responsibility of the reconnect policy
    /// (section C); this method only captures the failure facts.
    pub fn record_failure(
        &mut self,
        now: DateTime<Utc>,
        code: ConnectionErrorCode,
        error_message: impl Into<String>,
        original_error: impl Into<String>,
    ) {
        self.status = ConnectionStatus::Failed;
        self.error_code = Some(code);
        self.error_message = Some(error_message.into());
        self.original_error = Some(original_error.into());
        if self.first_failed_at.is_none() {
            self.first_failed_at = Some(now);
        }
        self.last_failed_at = Some(now);
        self.consecutive_failures = self
            .consecutive_failures
            .saturating_add(1);
    }

    /// Set `current_backoff_seconds` / `next_retry_at` from the reconnect
    /// policy, based on the current `consecutive_failures`. Call after
    /// [`Self::record_failure`].
    pub fn schedule_retry(
        &mut self,
        now: DateTime<Utc>,
        policy: &ReconnectPolicy,
    ) {
        let backoff = policy.backoff_seconds(
            self.consecutive_failures
                .max(1),
        );
        self.current_backoff_seconds = Some(backoff);
        self.next_retry_at = Some(now + chrono::Duration::seconds(backoff as i64));
    }
}

/// Classify a raw DIDComm/transport error string into a stable
/// [`ConnectionErrorCode`].
///
/// Matching is case-insensitive and ordered most-specific first, because a
/// single error string can contain several signals (e.g. a curve mismatch
/// surfaced during authentication contains both "authenticat" and the crypto
/// phrase — we want `CryptoMismatch`).
///
/// This is best-effort classification only. The full raw error is always kept
/// verbatim in `original_error`, so an imperfect match never loses signal.
pub fn classify_error(raw: &str) -> ConnectionErrorCode {
    let text = raw.to_ascii_lowercase();

    let contains_any = |needles: &[&str]| {
        needles
            .iter()
            .any(|n| text.contains(n))
    };

    if contains_any(&["no common key-agreement curve", "key-agreement", "key agreement", "curve"]) {
        return ConnectionErrorCode::CryptoMismatch;
    }
    if contains_any(&[
        "forwarding.abandoned",
        "forwarding abandoned",
        "no response received",
        "recipient",
        "policy",
        "denied",
        "acl",
        "not allowed",
        "forbidden",
    ]) {
        return ConnectionErrorCode::PeerGatewayUnavailable;
    }
    if contains_any(&["authenticat"]) {
        return ConnectionErrorCode::AuthenticationFailed;
    }
    if contains_any(&["register profile", "profile registration", "register_profile"]) {
        return ConnectionErrorCode::ProfileRegistrationFailed;
    }
    if contains_any(&["resolve", "resolution"]) && text.contains("did") {
        return ConnectionErrorCode::MediatorDidResolutionFailed;
    }
    if contains_any(&["websocket", "ws ", "stream", "connection closed", "connection reset"]) {
        return ConnectionErrorCode::WsStreamBroken;
    }
    if contains_any(&[
        "unreachable",
        "connection refused",
        "timed out",
        "timeout",
        "dns",
        "no route to host",
        "network is unreachable",
    ]) {
        return ConnectionErrorCode::MediatorUnreachable;
    }

    ConnectionErrorCode::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_serializes_to_stable_screaming_snake_strings() {
        let cases = [
            (ConnectionErrorCode::MediatorUnreachable, "\"MEDIATOR_UNREACHABLE\""),
            (ConnectionErrorCode::MediatorDidResolutionFailed, "\"MEDIATOR_DID_RESOLUTION_FAILED\""),
            (ConnectionErrorCode::ProfileRegistrationFailed, "\"PROFILE_REGISTRATION_FAILED\""),
            (ConnectionErrorCode::AuthenticationFailed, "\"AUTHENTICATION_FAILED\""),
            (ConnectionErrorCode::CryptoMismatch, "\"CRYPTO_MISMATCH\""),
            (ConnectionErrorCode::WsStreamBroken, "\"WS_STREAM_BROKEN\""),
            (ConnectionErrorCode::PeerGatewayUnavailable, "\"PEER_GATEWAY_UNAVAILABLE\""),
            (ConnectionErrorCode::Unknown, "\"UNKNOWN\""),
        ];
        for (code, expected) in cases {
            assert_eq!(serde_json::to_string(&code).unwrap(), expected, "unexpected wire form for {code:?}");
        }
    }

    #[test]
    fn healthy_status_omits_optional_fields_on_the_wire() {
        let mut status = ConnectionRuntimeStatus::default();
        status.mark_active(Utc::now());

        let value = serde_json::to_value(&status).unwrap();
        let obj = value.as_object().unwrap();

        assert_eq!(
            obj.get("status")
                .and_then(|v| v.as_str()),
            Some("connected")
        );
        assert!(obj.contains_key("last_active_at"));
        assert_eq!(
            obj.get("consecutive_failures")
                .and_then(|v| v.as_u64()),
            Some(0)
        );
        for absent in [
            "error_code",
            "error_message",
            "original_error",
            "first_failed_at",
            "last_failed_at",
            "next_retry_at",
            "current_backoff_seconds",
        ] {
            assert!(!obj.contains_key(absent), "{absent} must be omitted when healthy");
        }
    }

    #[test]
    fn record_failure_preserves_first_failed_at_and_counts_streak() {
        let t0 = Utc::now();
        let t1 = t0 + chrono::Duration::seconds(30);
        let mut status = ConnectionRuntimeStatus::default();

        status.record_failure(
            t0,
            ConnectionErrorCode::MediatorUnreachable,
            "Connection to mediator timed out",
            "raw-0",
        );
        status.record_failure(
            t1,
            ConnectionErrorCode::MediatorUnreachable,
            "Connection to mediator timed out",
            "raw-1",
        );

        assert_eq!(status.first_failed_at, Some(t0));
        assert_eq!(status.last_failed_at, Some(t1));
        assert_eq!(status.consecutive_failures, 2);
        assert_eq!(status.error_code, Some(ConnectionErrorCode::MediatorUnreachable));
        assert!(matches!(status.status, ConnectionStatus::Failed));
    }

    #[test]
    fn mark_active_clears_failure_diagnostics() {
        let mut status = ConnectionRuntimeStatus::default();
        status.record_failure(Utc::now(), ConnectionErrorCode::AuthenticationFailed, "auth failed", "raw");

        status.mark_active(Utc::now());

        assert!(status.error_code.is_none());
        assert!(status.error_message.is_none());
        assert!(
            status
                .first_failed_at
                .is_none()
        );
        assert_eq!(status.consecutive_failures, 0);
        assert!(
            status
                .last_active_at
                .is_some()
        );
        assert!(matches!(status.status, ConnectionStatus::Connected));
    }

    #[test]
    fn classify_crypto_mismatch_wins_over_authentication() {
        let raw = "DID (did:web:xxx): Attempt #1. Error authenticating: \
                   DIDComm('no common key-agreement curve: sender offers [K256], recipient offers [X25519, P256]')";
        assert_eq!(classify_error(raw), ConnectionErrorCode::CryptoMismatch);
    }

    #[test]
    fn classify_maps_common_transport_and_peer_errors() {
        assert_eq!(classify_error("Connection refused (os error 61)"), ConnectionErrorCode::MediatorUnreachable);
        assert_eq!(classify_error("request timed out after 5s"), ConnectionErrorCode::MediatorUnreachable);
        assert_eq!(classify_error("Error authenticating with mediator"), ConnectionErrorCode::AuthenticationFailed);
        assert_eq!(
            classify_error("Failed to resolve DID document for did:web:mediator"),
            ConnectionErrorCode::MediatorDidResolutionFailed
        );
        assert_eq!(
            classify_error("e.p.me.res.forwarding.abandoned: no response received"),
            ConnectionErrorCode::PeerGatewayUnavailable
        );
        assert_eq!(classify_error("message delivery denied by policy"), ConnectionErrorCode::PeerGatewayUnavailable);
        assert_eq!(classify_error("WebSocket connection closed unexpectedly"), ConnectionErrorCode::WsStreamBroken);
        assert_eq!(classify_error("something entirely unexpected"), ConnectionErrorCode::Unknown);
    }

    #[test]
    fn backoff_grows_exponentially_then_caps() {
        let policy = ReconnectPolicy {
            initial_backoff_seconds: 30,
            max_backoff_seconds: 1800,
            backoff_multiplier: 2.0,
        };
        // 30 -> 60 -> 120 -> 240 -> 480 -> 960 -> 1800 (capped) and stays there.
        assert_eq!(policy.backoff_seconds(0), 30, "zero treated as first attempt");
        assert_eq!(policy.backoff_seconds(1), 30);
        assert_eq!(policy.backoff_seconds(2), 60);
        assert_eq!(policy.backoff_seconds(3), 120);
        assert_eq!(policy.backoff_seconds(4), 240);
        assert_eq!(policy.backoff_seconds(5), 480);
        assert_eq!(policy.backoff_seconds(6), 960);
        assert_eq!(policy.backoff_seconds(7), 1800, "reaches cap");
        assert_eq!(policy.backoff_seconds(50), 1800, "stays at cap = fixed cadence");
    }

    #[test]
    fn backoff_multiplier_of_one_is_constant() {
        let policy = ReconnectPolicy {
            initial_backoff_seconds: 30,
            max_backoff_seconds: 1800,
            backoff_multiplier: 1.0,
        };
        assert_eq!(policy.backoff_seconds(1), 30);
        assert_eq!(policy.backoff_seconds(10), 30);
    }

    #[test]
    fn schedule_retry_sets_backoff_and_next_retry_at() {
        let policy = ReconnectPolicy::default();
        let now = Utc::now();
        let mut status = ConnectionRuntimeStatus::default();

        status.record_failure(now, ConnectionErrorCode::MediatorUnreachable, "unreachable", "raw");
        status.record_failure(now, ConnectionErrorCode::MediatorUnreachable, "unreachable", "raw");
        status.schedule_retry(now, &policy);

        // consecutive_failures == 2 -> 60s backoff.
        assert_eq!(status.current_backoff_seconds, Some(60));
        assert_eq!(status.next_retry_at, Some(now + chrono::Duration::seconds(60)));
    }

    #[test]
    fn error_code_message_is_display_safe_for_every_variant() {
        for code in [
            ConnectionErrorCode::MediatorUnreachable,
            ConnectionErrorCode::MediatorDidResolutionFailed,
            ConnectionErrorCode::ProfileRegistrationFailed,
            ConnectionErrorCode::AuthenticationFailed,
            ConnectionErrorCode::CryptoMismatch,
            ConnectionErrorCode::WsStreamBroken,
            ConnectionErrorCode::PeerGatewayUnavailable,
            ConnectionErrorCode::Unknown,
        ] {
            assert!(!code.message().is_empty(), "{code:?} must have a message");
        }
    }
}
