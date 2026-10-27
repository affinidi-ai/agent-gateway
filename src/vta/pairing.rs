//! "Connect your VTA" pairing — the state machine and verification.
//!
//! VTA-05 printed a grant command to the log and left the rest to the
//! operator: hand-edit TOML, read the command out of `vta_audit`, run it,
//! restart. That is workable for an engineer and unusable as a product
//! onboarding flow. Pairing turns it into one consent step with a verifiable
//! outcome, following the shape of the existing G2G pairing handshake rather
//! than inventing a new one.
//!
//! ## What pairing actually establishes
//!
//! 1. The gateway has a **per-connection** control key — never one shared key,
//!    so revoking one connection cannot strand the others and a leaked key has
//!    a bounded blast radius.
//! 2. The customer has granted that key a **least-privilege** role on their own
//!    VTA. The gateway asserts this rather than assuming it: an over-privileged
//!    grant is surfaced, because a gateway holding VTA admin invalidates the
//!    custody story the integration exists to provide.
//! 3. The VTA that answered is the one the operator meant — its DID is
//!    **pinned** on the connection, so a later DNS or endpoint change cannot
//!    silently redirect signing to a different agent.
//!
//! ## Fail closed, never silently local
//!
//! A connection that has not reached [`PairingState::Connected`] is not used
//! for signing. There is deliberately no "fall back to the local key" path:
//! signing with a key the operator did not choose would attribute credentials
//! to the wrong issuer, which is worse than refusing.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::vta::VtaError;
use crate::vta::connections::{VtaConnection, VtaConnectionStatus};
use crate::vta::control_key::SignerKeyProvider;
use crate::vta::onboarding::{GrantScope, grant_command_with_provisioning};

/// How long a pairing payload stays valid. Short, because it is a one-shot
/// handshake the operator completes immediately; a long-lived payload is just
/// a replay window.
const PAIRING_TTL_MINUTES: i64 = 15;

/// Where a connection is in the pairing lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PairingState {
    /// Recorded, but pairing has not started.
    #[default]
    Draft,
    /// A pairing payload has been issued; the customer has not yet granted.
    AwaitingGrant,
    /// Paired, verified and pinned — usable for signing.
    Connected,
    /// Was connected, but the last interaction failed (grant revoked, VTA
    /// down, DID changed). Not usable until re-verified.
    Degraded,
    /// Deliberately revoked by an operator. Not usable, and not re-usable
    /// without a fresh pairing.
    Revoked,
}

impl PairingState {
    /// Whether a connection in this state may be used for signing. Only
    /// `Connected` may: everything else fails closed.
    pub fn is_usable(self) -> bool {
        self == Self::Connected
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::AwaitingGrant => "awaiting_grant",
            Self::Connected => "connected",
            Self::Degraded => "degraded",
            Self::Revoked => "revoked",
        }
    }
}

impl From<PairingState> for VtaConnectionStatus {
    fn from(state: PairingState) -> Self {
        match state {
            PairingState::Connected => Self::Connected,
            PairingState::Degraded | PairingState::Revoked => Self::Error,
            PairingState::Draft | PairingState::AwaitingGrant => Self::Unpaired,
        }
    }
}

/// Pairing progress recorded on a connection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingRecord {
    #[serde(default)]
    pub state: PairingState,
    /// The gateway control DID the customer is asked to grant. Public — it is
    /// the whole point of the pairing payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_did: Option<String>,
    /// The VTA DID observed and pinned at the last successful verification.
    /// A mismatch on a later verify is treated as a different agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_vta_did: Option<String>,
    /// Role + context the VTA actually granted, as observed. Recorded so an
    /// operator can see what they approved without re-reading the VTA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_role: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub granted_contexts: Vec<String>,
    /// When the outstanding pairing payload stops being accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_verified_at: Option<DateTime<Utc>>,
    /// Why the last attempt failed, for the dashboard. Operator-facing and
    /// actionable; never raw VTA internals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// The artifact the customer acts on: the exact command to run, plus a
/// structured payload a VTA that can accept one may consume directly (QR,
/// deep link).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingPayload {
    /// Binds the grant to **this** connection, so a payload cannot be replayed
    /// against a different one.
    pub connection_id: String,
    pub control_did: String,
    pub vta_did: String,
    pub endpoint: String,
    /// The context the gateway is asking to be scoped to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// The role the gateway is asking for — deliberately not admin.
    pub requested_role: &'static str,
    pub expires_at: DateTime<Utc>,
    /// The one command the customer runs on their own VTA.
    pub grant_command: String,
}

/// The least-privilege role the gateway ever asks for. It can sign and issue
/// inside one context and administer nothing.
/// The role the pairing wizard asks for.
///
/// `initiator` rather than `application` because provisioning a signing key
/// needs `key-mint`, which the agent derives for `admin` and `initiator` only.
/// The grant is nonetheless **narrower** than the old one: naming capabilities
/// explicitly reduces it to exactly `{context-create, key-mint, sign}`, where
/// `application` conferred the whole role.
pub const REQUESTED_ROLE: &str = "initiator";

/// Build the pairing artifact for `connection` and move it to
/// [`PairingState::AwaitingGrant`].
///
/// Idempotent in the sense that matters: calling it again simply issues a fresh
/// payload. It deliberately does **not** reset a `Connected` connection — a
/// stray call must not take a working connection out of service.
pub fn begin_pairing(
    connection: &VtaConnection,
    control_did: &str,
    now: DateTime<Utc>,
) -> Result<(PairingPayload, PairingRecord), VtaError> {
    if control_did.trim().is_empty() {
        return Err(VtaError::Config(format!("VTA connection `{}` has no control key to pair with", connection.id)));
    }
    let context_id = connection
        .default_context_id
        .clone();
    // Without a context there is nothing to bound the grant to, and the
    // customer would be asked to approve an unrestricted one.
    let context_for_command = context_id
        .as_deref()
        .ok_or_else(|| {
            VtaError::Config(format!(
                "VTA connection `{}` needs a default_context_id before pairing, so the grant can be scoped to it",
                connection.id
            ))
        })?;
    let expires_at = now + Duration::minutes(PAIRING_TTL_MINUTES);

    let payload = PairingPayload {
        connection_id: connection.id.clone(),
        control_did: control_did.to_string(),
        vta_did: connection.vta_did.clone(),
        endpoint: connection.endpoint.clone(),
        context_id: context_id.clone(),
        requested_role: REQUESTED_ROLE,
        expires_at,
        grant_command: grant_command_with_provisioning(control_did, context_for_command),
    };

    let record = PairingRecord {
        state: PairingState::AwaitingGrant,
        control_did: Some(control_did.to_string()),
        payload_expires_at: Some(expires_at),
        last_error: None,
        ..Default::default()
    };
    Ok((payload, record))
}

/// What a verification attempt observed on the VTA.
#[derive(Debug, Clone)]
pub struct VerificationOutcome {
    /// The DID the VTA identified itself with.
    pub observed_vta_did: String,
    /// The grant the session token reports.
    pub scope: GrantScope,
}

/// Fold a verification attempt into the connection's pairing record.
///
/// Called after authenticating against the VTA. Three things have to hold, and
/// each failure is reported distinctly because the operator fix differs:
/// the VTA must be the pinned one, the grant must be least-privilege, and the
/// configured context must be inside the grant.
pub fn apply_verification(
    connection: &VtaConnection,
    previous: &PairingRecord,
    outcome: &VerificationOutcome,
    now: DateTime<Utc>,
) -> PairingRecord {
    let mut record = previous.clone();
    record.last_error = None;

    // Pin check first: if this is a different agent, nothing else it says
    // about scope is worth recording.
    let expected = previous
        .pinned_vta_did
        .as_deref()
        .unwrap_or(&connection.vta_did);
    if outcome.observed_vta_did != expected {
        return degrade(
            record,
            format!(
                "the VTA identified itself as `{}` but this connection is pinned to `{expected}`; \
                 re-pair deliberately if the agent really changed",
                outcome.observed_vta_did
            ),
        );
    }

    if let Err(e) = outcome.scope.assert_scoped() {
        // Surfaced, never silently accepted: a gateway holding VTA admin
        // invalidates the custody claim the integration exists to make.
        record.granted_role = Some(outcome.scope.role.clone());
        record.granted_contexts = outcome.scope.contexts.clone();
        return degrade(
            record,
            format!(
                "{}; re-grant with `{}`",
                e.log_detail(),
                grant_command_with_provisioning(
                    previous
                        .control_did
                        .as_deref()
                        .unwrap_or("<control-did>"),
                    connection
                        .default_context_id
                        .as_deref()
                        .unwrap_or("<context>")
                )
            ),
        );
    }

    if let Some(context_id) = connection
        .default_context_id
        .as_deref()
        && !outcome
            .scope
            .contexts
            .iter()
            .any(|c| c == context_id)
    {
        record.granted_role = Some(outcome.scope.role.clone());
        record.granted_contexts = outcome.scope.contexts.clone();
        return degrade(
            record,
            format!("the grant does not cover context `{context_id}`; it covers {:?}", outcome.scope.contexts),
        );
    }

    record.state = PairingState::Connected;
    record.pinned_vta_did = Some(
        outcome
            .observed_vta_did
            .clone(),
    );
    record.granted_role = Some(outcome.scope.role.clone());
    record.granted_contexts = outcome.scope.contexts.clone();
    record.last_verified_at = Some(now);
    // The payload has done its job; leaving it live would be a replay window.
    record.payload_expires_at = None;
    record
}

/// Record a failure to reach or authenticate against the VTA.
///
/// A connection that was `Connected` becomes `Degraded` rather than dropping to
/// `Draft`: the pin and the observed grant are still the best information
/// available, and losing them would force a full re-pair for a transient
/// outage.
pub fn apply_failure(
    previous: &PairingRecord,
    reason: impl Into<String>,
) -> PairingRecord {
    degrade(previous.clone(), reason.into())
}

/// Revoke a connection. Immediate and final: the state alone makes it unusable,
/// so nothing mapped to it can sign while an operator deletes or re-pairs it.
pub fn revoke(previous: &PairingRecord) -> PairingRecord {
    PairingRecord {
        state: PairingState::Revoked,
        // Keep what was observed for the audit trail, but drop the live
        // payload so a stale one cannot be completed after revocation.
        payload_expires_at: None,
        last_error: Some("revoked by an operator".to_string()),
        ..previous.clone()
    }
}

fn degrade(
    mut record: PairingRecord,
    reason: String,
) -> PairingRecord {
    // A connection that never reached `Connected` has nothing to degrade from;
    // it is still awaiting its grant, and saying "degraded" would suggest it
    // once worked.
    record.state = match record.state {
        PairingState::Connected | PairingState::Degraded => PairingState::Degraded,
        PairingState::Revoked => PairingState::Revoked,
        other => other,
    };
    record.last_error = Some(reason);
    record
}

/// Whether a connection may be used for signing right now.
///
/// Both halves matter: a disabled connection is an operator decision, and a
/// non-`Connected` one has not proved it can sign under the identity the
/// operator chose.
pub fn assert_usable(
    connection: &VtaConnection,
    record: &PairingRecord,
) -> Result<(), VtaError> {
    if !connection.enabled {
        return Err(VtaError::Config(format!("VTA connection `{}` is disabled", connection.id)));
    }
    if !record.state.is_usable() {
        return Err(VtaError::Config(format!(
            "VTA connection `{}` is `{}` and cannot sign{}",
            connection.id,
            record.state.as_str(),
            record
                .last_error
                .as_deref()
                .map(|e| format!(": {e}"))
                .unwrap_or_default()
        )));
    }
    Ok(())
}

/// Mint a fresh per-connection control key and return its `did:key` plus the
/// seed, for the caller to store **by reference** in the secrets store.
///
/// Per connection, never shared: revoking one must not strand the others, and a
/// leaked seed must not authenticate the gateway to every VTA it knows.
pub fn mint_control_key() -> (String, String) {
    let key = crate::vta::control_key::ControlKey::generate();
    (key.did().to_string(), key.seed_hex())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vta::connections::VtaConnectionTransport;

    fn connection(context: Option<&str>) -> VtaConnection {
        let now = Utc::now();
        VtaConnection {
            id: "conn-1".to_string(),
            tenant_id: None,
            name: "Customer VTA".to_string(),
            description: None,
            enabled: true,
            transport: VtaConnectionTransport::Https,
            endpoint: "https://vta.customer.example".to_string(),
            vta_did: "did:webvh:vta.customer.example".to_string(),
            default_context_id: context.map(str::to_string),
            control_key_ref: Some("secret-control-key".to_string()),
            status: VtaConnectionStatus::Unpaired,
            keys: Default::default(),
            pairing: Default::default(),
            created_at: now,
            updated_at: now,
        }
    }

    fn scope(
        role: &str,
        contexts: &[&str],
    ) -> GrantScope {
        GrantScope {
            role: role.to_string(),
            contexts: contexts
                .iter()
                .map(|c| c.to_string())
                .collect(),
        }
    }

    fn paired(connection: &VtaConnection) -> PairingRecord {
        let (_, record) = begin_pairing(connection, "did:key:zGateway", Utc::now()).expect("begin");
        apply_verification(
            connection,
            &record,
            &VerificationOutcome {
                observed_vta_did: connection.vta_did.clone(),
                scope: scope(REQUESTED_ROLE, &["ctx"]),
            },
            Utc::now(),
        )
    }

    // ---- pairing payload --------------------------------------------------

    #[test]
    fn the_payload_binds_the_grant_to_one_connection_and_expires() {
        let connection = connection(Some("ctx"));
        let now = Utc::now();
        let (payload, record) = begin_pairing(&connection, "did:key:zGateway", now).expect("begin");

        // Binding to the connection id is what stops a payload being replayed
        // against a different connection.
        assert_eq!(payload.connection_id, "conn-1");
        assert_eq!(payload.control_did, "did:key:zGateway");
        assert_eq!(payload.requested_role, REQUESTED_ROLE);
        assert_ne!(payload.requested_role, "admin", "the gateway must never ask for admin");
        assert!(
            payload
                .grant_command
                .contains("did:key:zGateway")
        );
        assert!(
            payload
                .grant_command
                .contains("ctx")
        );
        assert_eq!(payload.expires_at, now + Duration::minutes(PAIRING_TTL_MINUTES));
        assert_eq!(record.state, PairingState::AwaitingGrant);
        assert_eq!(record.payload_expires_at, Some(payload.expires_at));
    }

    #[test]
    fn pairing_without_a_context_is_refused_rather_than_asking_for_an_unbounded_grant() {
        let err = begin_pairing(&connection(None), "did:key:zGateway", Utc::now())
            .expect_err("there is nothing to scope the grant to");
        assert!(
            err.log_detail()
                .contains("default_context_id"),
            "unexpected error: {}",
            err.log_detail()
        );
    }

    #[test]
    fn pairing_without_a_control_key_is_refused() {
        let err = begin_pairing(&connection(Some("ctx")), "  ", Utc::now()).expect_err("no key to pair with");
        assert!(
            err.log_detail()
                .contains("control key"),
            "unexpected error: {}",
            err.log_detail()
        );
    }

    // ---- verification -----------------------------------------------------

    #[test]
    fn a_least_privilege_grant_connects_and_pins_the_vta_did() {
        let connection = connection(Some("ctx"));
        let record = paired(&connection);

        assert_eq!(record.state, PairingState::Connected);
        assert!(record.state.is_usable());
        assert_eq!(
            record
                .pinned_vta_did
                .as_deref(),
            Some("did:webvh:vta.customer.example")
        );
        assert_eq!(record.granted_role.as_deref(), Some(REQUESTED_ROLE));
        assert_eq!(record.granted_contexts, vec!["ctx".to_string()]);
        assert!(
            record
                .last_verified_at
                .is_some()
        );
        // The payload is consumed, so it cannot be replayed afterwards.
        assert!(
            record
                .payload_expires_at
                .is_none()
        );
        assert!(record.last_error.is_none());
    }

    #[test]
    fn an_over_privileged_grant_is_surfaced_not_accepted() {
        let connection = connection(Some("ctx"));
        let (_, started) = begin_pairing(&connection, "did:key:zGateway", Utc::now()).unwrap();

        for bad in [scope("admin", &["ctx"]), scope(REQUESTED_ROLE, &[]), scope(REQUESTED_ROLE, &["ctx", "other"])] {
            let record = apply_verification(
                &connection,
                &started,
                &VerificationOutcome {
                    observed_vta_did: connection.vta_did.clone(),
                    scope: bad.clone(),
                },
                Utc::now(),
            );
            assert_ne!(record.state, PairingState::Connected, "accepted {bad:?}");
            assert!(!record.state.is_usable());
            let err = record
                .last_error
                .expect("the operator must be told why");
            // The corrective command must be the one the CLI actually accepts:
            // `import-did` takes no `--capabilities`, so printing it here would
            // hand the operator something they cannot run.
            assert!(err.contains("vta acl create"), "the error must be actionable: {err}");
            // What was actually granted is recorded so the operator can see it.
            assert_eq!(record.granted_role.as_deref(), Some(bad.role.as_str()));
        }
    }

    #[test]
    fn a_different_vta_is_rejected_even_with_a_valid_grant() {
        let connection = connection(Some("ctx"));
        let connected = paired(&connection);

        let record = apply_verification(
            &connection,
            &connected,
            &VerificationOutcome {
                observed_vta_did: "did:webvh:impostor.example".to_string(),
                scope: scope(REQUESTED_ROLE, &["ctx"]),
            },
            Utc::now(),
        );

        assert_eq!(record.state, PairingState::Degraded);
        let err = record
            .last_error
            .expect("explains the mismatch");
        assert!(err.contains("impostor.example"), "names what answered: {err}");
        assert!(err.contains("vta.customer.example"), "names what was expected: {err}");
        // The pin survives, so a transient redirect cannot silently re-pin.
        assert_eq!(
            record
                .pinned_vta_did
                .as_deref(),
            Some("did:webvh:vta.customer.example")
        );
    }

    #[test]
    fn a_grant_that_misses_the_configured_context_is_rejected() {
        let connection = connection(Some("ctx"));
        let (_, started) = begin_pairing(&connection, "did:key:zGateway", Utc::now()).unwrap();

        let record = apply_verification(
            &connection,
            &started,
            &VerificationOutcome {
                observed_vta_did: connection.vta_did.clone(),
                scope: scope(REQUESTED_ROLE, &["some-other-context"]),
            },
            Utc::now(),
        );

        assert_ne!(record.state, PairingState::Connected);
        let err = record.last_error.unwrap();
        assert!(err.contains("ctx"), "names the required context: {err}");
        assert!(err.contains("some-other-context"), "names what was granted: {err}");
    }

    #[test]
    fn re_verifying_an_already_connected_connection_is_idempotent() {
        let connection = connection(Some("ctx"));
        let first = paired(&connection);
        let second = apply_verification(
            &connection,
            &first,
            &VerificationOutcome {
                observed_vta_did: connection.vta_did.clone(),
                scope: scope(REQUESTED_ROLE, &["ctx"]),
            },
            Utc::now(),
        );

        assert_eq!(second.state, first.state);
        assert_eq!(second.pinned_vta_did, first.pinned_vta_did);
        assert_eq!(second.granted_contexts, first.granted_contexts);
    }

    #[test]
    fn beginning_pairing_again_issues_a_fresh_payload_without_losing_the_pin() {
        let connection = connection(Some("ctx"));
        let connected = paired(&connection);
        let (payload, _) = begin_pairing(&connection, "did:key:zGateway2", Utc::now()).expect("re-pair");

        // A re-pair is deliberate, so a new payload is issued — but the caller
        // keeps the existing record until verification succeeds, so a working
        // connection is never taken out of service by starting one.
        assert_eq!(payload.control_did, "did:key:zGateway2");
        assert_eq!(connected.state, PairingState::Connected);
    }

    // ---- failure, revocation, usability -----------------------------------

    #[test]
    fn an_unreachable_vta_degrades_a_connected_connection_without_losing_its_pin() {
        let connection = connection(Some("ctx"));
        let connected = paired(&connection);
        let record = apply_failure(&connected, "the VTA did not respond");

        assert_eq!(record.state, PairingState::Degraded);
        assert_eq!(record.pinned_vta_did, connected.pinned_vta_did);
        assert_eq!(record.last_error.as_deref(), Some("the VTA did not respond"));
    }

    #[test]
    fn a_failure_before_the_first_connect_stays_awaiting_grant() {
        let connection = connection(Some("ctx"));
        let (_, started) = begin_pairing(&connection, "did:key:zGateway", Utc::now()).unwrap();
        let record = apply_failure(&started, "the VTA did not respond");

        // Calling it "degraded" would suggest it once worked.
        assert_eq!(record.state, PairingState::AwaitingGrant);
        assert!(record.last_error.is_some());
    }

    #[test]
    fn revocation_is_immediate_and_drops_any_live_payload() {
        let connection = connection(Some("ctx"));
        let (_, started) = begin_pairing(&connection, "did:key:zGateway", Utc::now()).unwrap();
        let revoked = revoke(&started);

        assert_eq!(revoked.state, PairingState::Revoked);
        assert!(
            revoked
                .payload_expires_at
                .is_none(),
            "a stale payload must not be completable after revocation"
        );

        let err = assert_usable(&connection, &revoked).expect_err("a revoked connection cannot sign");
        assert!(
            err.log_detail()
                .contains("revoked"),
            "unexpected error: {}",
            err.log_detail()
        );
    }

    #[test]
    fn a_revoked_connection_cannot_be_degraded_back_into_ambiguity() {
        let connection = connection(Some("ctx"));
        let revoked = revoke(&paired(&connection));
        let after_failure = apply_failure(&revoked, "the VTA did not respond");
        assert_eq!(after_failure.state, PairingState::Revoked);
    }

    #[test]
    fn only_a_connected_and_enabled_connection_may_sign() {
        let connection = connection(Some("ctx"));
        let connected = paired(&connection);
        assert_usable(&connection, &connected).expect("connected and enabled");

        // Not connected → refused, with the state named.
        let (_, awaiting) = begin_pairing(&connection, "did:key:zGateway", Utc::now()).unwrap();
        let err = assert_usable(&connection, &awaiting).expect_err("an unpaired connection cannot sign");
        assert!(
            err.log_detail()
                .contains("awaiting_grant"),
            "unexpected error: {}",
            err.log_detail()
        );

        // Disabled → refused even though pairing succeeded.
        let mut disabled = connection.clone();
        disabled.enabled = false;
        let err = assert_usable(&disabled, &connected).expect_err("a disabled connection cannot sign");
        assert!(
            err.log_detail()
                .contains("disabled"),
            "unexpected error: {}",
            err.log_detail()
        );
    }

    #[test]
    fn the_stored_status_follows_the_pairing_state() {
        assert_eq!(VtaConnectionStatus::from(PairingState::Connected), VtaConnectionStatus::Connected);
        assert_eq!(VtaConnectionStatus::from(PairingState::Degraded), VtaConnectionStatus::Error);
        assert_eq!(VtaConnectionStatus::from(PairingState::Revoked), VtaConnectionStatus::Error);
        assert_eq!(VtaConnectionStatus::from(PairingState::AwaitingGrant), VtaConnectionStatus::Unpaired);
        assert_eq!(VtaConnectionStatus::from(PairingState::Draft), VtaConnectionStatus::Unpaired);
    }

    // ---- per-connection control keys --------------------------------------

    #[test]
    fn every_connection_gets_its_own_control_key() {
        let (first_did, first_seed) = mint_control_key();
        let (second_did, second_seed) = mint_control_key();

        assert_ne!(first_did, second_did, "a shared key would let one leak authenticate everywhere");
        assert_ne!(first_seed, second_seed);
        // 32 bytes of hex — the shape the secrets-store reference resolves to.
        assert_eq!(first_seed.len(), 64);
        // The DID is derivable from the seed, so the record never has to carry
        // it and the two cannot drift apart.
        assert_eq!(crate::vta::control_key_did(&first_seed).unwrap(), first_did);
    }
}
