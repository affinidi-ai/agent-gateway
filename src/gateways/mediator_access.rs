//! The pause of a pairing that waits until its mediator admits the DIDs it minted.
//!
//! A mediator that only admits known DIDs refuses each new DID until its
//! administrator adds it. Creating a Connection Point and adding a gateway can
//! therefore stop right after minting their DIDs, show them, and continue when the
//! operator says so. Continuing authenticates every DID first and stops at the
//! first one the mediator still refuses.

use std::sync::Arc;

use affinidi_messaging_sdk::errors::ATMError;
use affinidi_tdk_common::secrets_resolver::secrets::Secret;
use axum::{Json, http::StatusCode, response::IntoResponse};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::gateways::connection_points::first_call_retry::refused_until_admitted;

/// How long a paused pairing lasts when its invitation names no expiry.
pub const DEFAULT_INVITATION_LIFETIME: chrono::Duration = chrono::Duration::days(7);

/// What a DID is for in the pairing.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DidRole {
    /// The inviter's Connection Point, which receives connection-setup.
    ConnectionPoint,
    /// The acceptor's handshake DID, which receives connection-accepted.
    Temporary,
    /// The DID the paired gateway is reached at once the pairing completes.
    Permanent,
}

impl DidRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionPoint => "connection_point",
            Self::Temporary => "temporary",
            Self::Permanent => "permanent",
        }
    }
}

/// One DID the mediator must admit before the pairing can continue.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AwaitedDid {
    pub role: DidRole,
    pub did: String,
    pub mediator_did: String,
}

/// What a paused pairing waits for: its DIDs and the mediator that must admit
/// them, until the invitation expires.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MediatorAccess {
    pub mediator_did: String,
    /// The stored mediator's name, else its DID.
    pub mediator_name: String,
    pub dids: Vec<AwaitedDid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Why continuing a paused pairing did not go ahead.
#[derive(Debug)]
pub enum ContinueError {
    /// The mediator still refuses this DID.
    Refused(AwaitedDid),
    Failed(StatusCode, String),
}

impl From<(StatusCode, String)> for ContinueError {
    fn from((status, message): (StatusCode, String)) -> Self {
        Self::Failed(status, message)
    }
}

impl IntoResponse for ContinueError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Refused(awaited) => (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "code": "mediator_access_refused",
                    "role": awaited.role.as_str(),
                    "did": awaited.did,
                    "mediator_did": awaited.mediator_did,
                    "message": "The mediator still refuses this DID. Ask its administrator to add it, then continue.",
                })),
            )
                .into_response(),
            Self::Failed(status, message) => (status, message).into_response(),
        }
    }
}

enum Admission {
    Admitted,
    Refused,
}

fn classify(result: Result<(), ATMError>) -> Result<Admission, String> {
    match result {
        Ok(()) => Ok(Admission::Admitted),
        Err(error) if refused_until_admitted(&error) => Ok(Admission::Refused),
        Err(error) => Err(error.to_string()),
    }
}

/// Authenticates `awaited.did` on its mediator over the live stream, which the
/// mediator's replies arrive on, and reads its own account. A mediator that does
/// not admit the DID refuses the authentication, so the stream does not open.
async fn admission(
    awaited: &AwaitedDid,
    secrets: Vec<Secret>,
    mediator_document: Option<serde_json::Value>,
) -> Result<Admission, String> {
    #[cfg(test)]
    if let Some(admitted) =
        crate::gateways::connection_points::test_mediator::admits(&awaited.mediator_did, &awaited.did)
    {
        return Ok(if admitted {
            Admission::Admitted
        } else {
            Admission::Refused
        });
    }

    let client = crate::comm::didcomm::client::DIDCommClient::new_with_mediator_document(
        awaited.did.clone(),
        secrets,
        Some(awaited.mediator_did.clone()),
        mediator_document,
        Some(format!("mediator-access-{}", uuid::Uuid::new_v4())),
    )
    .await?;
    let atm = client.atm();
    let checked = async {
        let profile = atm
            .profile_add(client.profile(), true)
            .await?;
        atm.trust_tasks()
            .account_get(&profile, None)
            .await
            .map(|_| ())
    }
    .await;
    atm.graceful_shutdown().await;
    classify(checked)
}

/// Fails with [`ContinueError::Refused`] while the mediator refuses `awaited`.
pub async fn require_admitted(
    awaited: &AwaitedDid,
    secrets: Vec<Secret>,
    mediator_document: Option<serde_json::Value>,
) -> Result<(), ContinueError> {
    match admission(awaited, secrets, mediator_document).await {
        Ok(Admission::Admitted) => Ok(()),
        Ok(Admission::Refused) => {
            tracing::info!(did = %awaited.did, role = awaited.role.as_str(), "The mediator does not admit this DID yet");
            Err(ContinueError::Refused(awaited.clone()))
        }
        Err(error) => Err(ContinueError::Failed(
            StatusCode::BAD_GATEWAY,
            format!("Could not check whether the mediator admits {}: {error}", awaited.did),
        )),
    }
}

/// Serialises the continuation of one paused pairing, so two requests cannot both
/// open its invitation or send its connection-setup.
pub async fn lock(key: &str) -> tokio::sync::OwnedMutexGuard<()> {
    static LOCKS: std::sync::LazyLock<dashmap::DashMap<String, Arc<tokio::sync::Mutex<()>>>> =
        std::sync::LazyLock::new(dashmap::DashMap::new);
    let lock = LOCKS
        .entry(key.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    lock.lock_owned().await
}

/// When an accepted invitation stops being usable: its `expires_time`, else
/// [`DEFAULT_INVITATION_LIFETIME`] from `now`.
pub fn invitation_expiry(
    expires_time: Option<u64>,
    now: DateTime<Utc>,
) -> DateTime<Utc> {
    expires_time
        .and_then(|secs| i64::try_from(secs).ok())
        .and_then(|secs| DateTime::from_timestamp(secs, 0))
        .unwrap_or(now + DEFAULT_INVITATION_LIFETIME)
}

/// The name the dashboard shows for a mediator: its stored record's, else its DID.
pub async fn mediator_name<M: crate::mediators::MediatorStore>(
    mediator_store: &M,
    mediator_did: &str,
) -> String {
    mediator_store
        .list_all()
        .await
        .ok()
        .and_then(|mediators| {
            mediators
                .into_iter()
                .find(|mediator| mediator.did == mediator_did)
                .map(|mediator| mediator.name)
        })
        .unwrap_or_else(|| mediator_did.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status_error(status: u16) -> ATMError {
        ATMError::HttpStatus(Box::new(affinidi_messaging_sdk::errors::HttpStatusError::new("account get", status)))
    }

    fn awaited() -> AwaitedDid {
        AwaitedDid {
            role: DidRole::Permanent,
            did: "did:peer:2.permanent".to_string(),
            mediator_did: "did:web:mediator.example".to_string(),
        }
    }

    #[test]
    fn a_403_or_an_acl_denial_is_a_refusal() {
        assert!(matches!(classify(Err(status_error(403))), Ok(Admission::Refused)));
        assert!(matches!(classify(Err(ATMError::ACLDenied("blocked".into()))), Ok(Admission::Refused)));
        assert!(matches!(classify(Ok(())), Ok(Admission::Admitted)));
    }

    #[test]
    fn other_failures_are_not_a_refusal() {
        for status in [401, 404, 500, 503] {
            assert!(classify(Err(status_error(status))).is_err(), "{status}");
        }
    }

    #[tokio::test]
    async fn a_refusal_answers_409_naming_the_refused_did() {
        let response = ContinueError::Refused(awaited()).into_response();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], "mediator_access_refused");
        assert_eq!(body["role"], "permanent");
        assert_eq!(body["did"], "did:peer:2.permanent");
        assert_eq!(body["mediator_did"], "did:web:mediator.example");
    }

    #[tokio::test]
    async fn a_mediator_that_refuses_the_did_keeps_the_pause() {
        let mediator = "did:web:refusing.mediator-access.example";
        crate::gateways::connection_points::test_mediator::install(mediator, Err("unused".to_string()));
        let mut refused = awaited();
        refused.mediator_did = mediator.to_string();
        refused.did = format!("did:peer:2.{}", uuid::Uuid::new_v4());
        crate::gateways::connection_points::test_mediator::refuse(&refused.did);

        let outcome = require_admitted(&refused, Vec::new(), None).await;
        assert!(matches!(outcome, Err(ContinueError::Refused(ref did)) if *did == refused));

        crate::gateways::connection_points::test_mediator::admit(&refused.did);
        assert!(
            require_admitted(&refused, Vec::new(), None)
                .await
                .is_ok()
        );
    }

    #[test]
    fn an_invitation_expires_at_its_expires_time() {
        let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        assert_eq!(invitation_expiry(Some(1_800_086_400), now), DateTime::from_timestamp(1_800_086_400, 0).unwrap());
    }

    #[test]
    fn an_invitation_without_expiry_lasts_seven_days() {
        let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        assert_eq!(invitation_expiry(None, now), now + chrono::Duration::days(7));
    }
}
