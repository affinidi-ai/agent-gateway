//! Rotating the control key of a connection the operator added, keeping its
//! `did:webvh`.
//!
//! The DID and the grant on the trust agent do not change; only the key inside
//! the published DID document does. Three steps, each saved on the connection
//! record before the side effect that follows it, so a crash is resumed from the
//! record and never repeated or lost:
//!
//! 1. **Introduce**: the new key joins the document beside the old one. A trust
//!    agent re-reads a cached document that does not define the key a proof
//!    names, so it accepts the new key at once.
//! 2. **Switch**: the connection's one cached client moves to the new key and
//!    signs in with it. The old key stays published until this works.
//! 3. **Retire**: the old key leaves the document and its secret is deleted.
//!
//! A new key the trust agent refuses is retried until `give_up_at` (a trust agent
//! behind a remote resolver can lag) and then rolled back: the old key is the
//! only one left, signing never stopped, and nothing falls back to local signing.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;

use super::auth_did::{ConnectionDidPublisher, introduce_key, keep_only_key, next_key_fragment};
use super::connections::{ControlKeyRotation, RotationPhase, VtaConnection, VtaConnectionStorage};
use super::control_key::{ControlKey, SignerKeyProvider};
use super::error::VtaError;
use super::registry::ConnectionClients;
use crate::secrets::{CreateSecretRequest, SecretsStore};

/// Time, so the retry waits do not need a real clock in tests.
#[async_trait]
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
    async fn sleep(
        &self,
        duration: Duration,
    );
}

pub struct SystemClock;

#[async_trait]
impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }

    async fn sleep(
        &self,
        duration: Duration,
    ) {
        tokio::time::sleep(duration).await;
    }
}

/// How a rotation stands, as the API reports it. Holds no secret reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RotationView {
    pub connection_id: String,
    pub control_did: String,
    /// `None` once finished.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<RotationPhase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub give_up_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_verification_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_verification_method: Option<String>,
    pub verification_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_key_rotated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

pub fn view_of(connection: &VtaConnection) -> RotationView {
    let state = &connection.control_key_state;
    let rotation = state.rotation.as_ref();
    RotationView {
        connection_id: connection.id.clone(),
        control_did: connection
            .control_did
            .clone()
            .unwrap_or_default(),
        phase: rotation.map(|r| r.phase),
        started_at: rotation.map(|r| r.started_at),
        give_up_at: rotation.map(|r| r.give_up_at),
        previous_verification_method: rotation.map(|r| {
            r.previous_verification_method
                .clone()
        }),
        next_verification_method: rotation.map(|r| {
            r.next_verification_method
                .clone()
        }),
        verification_method: state
            .verification_method
            .clone()
            .unwrap_or_else(|| "#key-1".to_string()),
        control_key_rotated_at: state.rotated_at,
        last_error: state.last_error.clone(),
    }
}

/// Why a rotation could not start.
#[derive(Debug)]
pub enum StartError {
    NotFound,
    /// The bundled record rotates through `POST /v1/vta/control-key/rotate`.
    Bundled,
    /// Disabled, or not paired: nothing to rotate yet.
    NotUsable(String),
    /// The connection authenticates as a `did:key`, whose identifier is its key.
    NotWebvh,
    /// A rotation is already under way; carries its view.
    InProgress(Box<RotationView>),
    /// Another call is working on this connection right now.
    Busy,
    Failed(VtaError),
}

/// Why a rotation could not be cancelled.
#[derive(Debug)]
pub enum CancelError {
    NotFound,
    NothingToCancel,
    /// The gateway already signs in with the new key.
    TooLate,
    Failed(VtaError),
}

/// How a drive ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    NothingToDo,
    Finished,
    /// The trust agent refused the new key until the deadline; the old key is back.
    RolledBack,
    /// Another call is already driving this connection.
    Busy,
}

/// A rotation that is stuck: it stays under way and the operator can cancel it.
#[derive(Debug)]
pub struct Stalled(pub String);

type RunningSet = Arc<Mutex<HashSet<String>>>;

/// Marks a connection as being worked on, until dropped.
struct Running {
    set: RunningSet,
    id: String,
}

impl Running {
    fn begin(
        set: &RunningSet,
        id: &str,
    ) -> Option<Self> {
        set.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id.to_string())
            .then(|| Self {
                set: Arc::clone(set),
                id: id.to_string(),
            })
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.set
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.id);
    }
}

fn backoff(attempts: u32) -> Duration {
    Duration::from_secs(
        10u64
            .saturating_mul(
                1 << attempts
                    .saturating_sub(1)
                    .min(3),
            )
            .min(60),
    )
}

fn fragment_of(verification_method: &str) -> &str {
    verification_method
        .rsplit_once('#')
        .map(|(_, f)| f)
        .unwrap_or(verification_method)
}

pub struct ConnectionKeyRotator {
    store: Arc<dyn VtaConnectionStorage>,
    secrets: Arc<dyn SecretsStore>,
    publisher: ConnectionDidPublisher,
    clients: Arc<dyn ConnectionClients>,
    clock: Arc<dyn Clock>,
    switch_timeout: Duration,
    running: RunningSet,
}

impl ConnectionKeyRotator {
    pub fn new(
        store: Arc<dyn VtaConnectionStorage>,
        secrets: Arc<dyn SecretsStore>,
        publisher: ConnectionDidPublisher,
        clients: Arc<dyn ConnectionClients>,
        clock: Arc<dyn Clock>,
        switch_timeout: Duration,
    ) -> Self {
        Self {
            store,
            secrets,
            publisher,
            clients,
            clock,
            switch_timeout,
            running: Arc::default(),
        }
    }

    async fn load(
        &self,
        id: &str,
    ) -> Result<Option<VtaConnection>, VtaError> {
        self.store
            .get(id)
            .await
            .map_err(|e| VtaError::Config(format!("VTA connection lookup failed: {e}")))
    }

    async fn save(
        &self,
        connection: VtaConnection,
    ) -> Result<(), VtaError> {
        self.store
            .update(connection)
            .await
            .map(|_| ())
            .map_err(|e| VtaError::Config(format!("VTA connection could not be saved: {e}")))
    }

    async fn seed_of(
        &self,
        secret_ref: &str,
    ) -> Result<[u8; 32], VtaError> {
        let secret = self
            .secrets
            .get_by_secret_id(secret_ref)
            .await
            .map_err(|e| VtaError::Config(format!("control key lookup failed: {e}")))?
            .ok_or_else(|| VtaError::Config(format!("control key `{secret_ref}` was not found")))?;
        super::decode_hex_seed(secret.value.trim())
    }

    async fn plain_key(
        &self,
        secret_ref: &str,
    ) -> Result<ControlKey, VtaError> {
        Ok(ControlKey::from_seed(
            self.seed_of(secret_ref)
                .await?,
        ))
    }

    async fn provider(
        &self,
        secret_ref: &str,
        did: &str,
        verification_method: &str,
    ) -> Result<Arc<dyn SignerKeyProvider>, VtaError> {
        Ok(Arc::new(
            self.plain_key(secret_ref)
                .await?
                .with_stable_did(did.to_string(), Some(verification_method.to_string()))?,
        ))
    }

    async fn delete_secret(
        &self,
        secret_ref: &str,
    ) {
        match self
            .secrets
            .get_by_secret_id(secret_ref)
            .await
        {
            Ok(Some(secret)) => {
                if let Err(e) = self
                    .secrets
                    .delete(&secret.id)
                    .await
                {
                    tracing::warn!(target: "vta_audit", error = %e, "could not delete a retired control key");
                }
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(target: "vta_audit", error = %e, "could not look up a retired control key"),
        }
    }

    /// Check the connection can be rotated and store the new key. Nothing is
    /// published yet; call [`drive`](Self::drive) to carry it out.
    pub async fn start(
        &self,
        id: &str,
        user: Option<&str>,
    ) -> Result<RotationView, StartError> {
        let _running = Running::begin(&self.running, id).ok_or(StartError::Busy)?;
        let mut connection = self
            .load(id)
            .await
            .map_err(StartError::Failed)?
            .ok_or(StartError::NotFound)?;
        if connection.is_bootstrap() {
            return Err(StartError::Bundled);
        }
        if let Some(rotation) = &connection
            .control_key_state
            .rotation
        {
            let _ = rotation;
            return Err(StartError::InProgress(Box::new(view_of(&connection))));
        }
        let Some(did) = connection
            .control_did
            .clone()
            .filter(|d| d.starts_with("did:webvh:"))
        else {
            return Err(StartError::NotWebvh);
        };
        if !connection.enabled {
            return Err(StartError::NotUsable("the connection is disabled".to_string()));
        }
        if connection.pairing.state != crate::vta::pairing::PairingState::Connected {
            return Err(StartError::NotUsable("the connection is not paired and connected".to_string()));
        }
        let key_ref = connection
            .control_key_ref
            .clone()
            .ok_or_else(|| StartError::NotUsable("the connection has no control key".to_string()))?;

        let dir = self
            .publisher
            .dir(id)
            .map_err(StartError::Failed)?;
        let raw = crate::storage::did_artifacts::read_did_log_raw(&dir)
            .await
            .map_err(|e| StartError::Failed(VtaError::Config(format!("read the auth DID log: {e}"))))?
            .ok_or_else(|| StartError::Failed(VtaError::Config("the connection's DID is not published".to_string())))?;
        let next_fragment = next_key_fragment(&raw);
        let previous_vm = connection
            .control_key_state
            .verification_method
            .clone()
            .unwrap_or_else(|| "#key-1".to_string());
        let next_key = ControlKey::generate();
        let next_key_ref = format!("vta-control-key-{id}-{next_fragment}");
        self.secrets
            .create(CreateSecretRequest {
                tenant_id: connection.tenant_id.clone(),
                name: format!("VTA control key ({id}, {next_fragment})"),
                secret_id: next_key_ref.clone(),
                description: Some(format!("Ed25519 control-key seed for the next key of {did}.")),
                value: next_key.seed_hex(),
                secret_type: "General".to_string(),
                tags: vec!["vta".to_string()],
            })
            .await
            .map_err(|e| {
                StartError::Failed(VtaError::Config(format!("the new control key could not be stored: {e}")))
            })?;

        let now = self.clock.now();
        connection
            .control_key_state
            .last_error = None;
        connection
            .control_key_state
            .rotation = Some(ControlKeyRotation {
            phase: RotationPhase::Prepared,
            next_key_ref,
            next_verification_method: format!("#{next_fragment}"),
            previous_key_ref: key_ref,
            previous_verification_method: previous_vm,
            started_at: now,
            give_up_at: now
                + chrono::Duration::from_std(self.switch_timeout).unwrap_or_else(|_| chrono::Duration::seconds(330)),
            attempts: 0,
        });
        self.save(connection.clone())
            .await
            .map_err(StartError::Failed)?;
        tracing::info!(
            target: "vta_audit",
            event = "vta_connection_control_key_rotation_started",
            connection_id = %id,
            control_did = %did,
            user_id = user.unwrap_or(""),
            "started rotating a connection's control key",
        );
        Ok(view_of(&connection))
    }

    /// Carry a rotation through every remaining phase.
    pub async fn drive(
        &self,
        id: &str,
    ) -> Result<Outcome, Stalled> {
        let Some(_running) = Running::begin(&self.running, id) else {
            return Ok(Outcome::Busy);
        };
        loop {
            let connection = match self.load(id).await {
                Ok(Some(connection)) => connection,
                Ok(None) => return Ok(Outcome::NothingToDo),
                Err(e) => return Err(Stalled(e.log_detail().to_string())),
            };
            let Some(rotation) = connection
                .control_key_state
                .rotation
                .clone()
            else {
                return Ok(Outcome::NothingToDo);
            };
            let step = match rotation.phase {
                RotationPhase::Prepared => self
                    .introduce(connection, rotation)
                    .await
                    .map(|_| None),
                RotationPhase::Introduced => {
                    self.switch(connection, rotation)
                        .await
                }
                RotationPhase::Switched => {
                    return self
                        .finish(connection, rotation)
                        .await
                        .map(|_| Outcome::Finished)
                        .map_err(|e| Stalled(e.log_detail().to_string()));
                }
            };
            match step {
                Ok(None) => {}
                Ok(Some(Step::Wait(wait))) => self.clock.sleep(wait).await,
                Ok(Some(Step::RolledBack)) => return Ok(Outcome::RolledBack),
                Err(e) => return Err(Stalled(e.log_detail().to_string())),
            }
        }
    }

    async fn introduce(
        &self,
        mut connection: VtaConnection,
        mut rotation: ControlKeyRotation,
    ) -> Result<(), VtaError> {
        let did = connection
            .control_did
            .clone()
            .unwrap_or_default();
        let current = self
            .plain_key(&rotation.previous_key_ref)
            .await?;
        let next = self
            .plain_key(&rotation.next_key_ref)
            .await?;
        let dir = self
            .publisher
            .dir(&connection.id)?;
        introduce_key(
            &dir,
            &did,
            &current,
            fragment_of(&rotation.next_verification_method),
            &next.public_key_multibase(),
        )
        .await?;
        rotation.phase = RotationPhase::Introduced;
        connection
            .control_key_state
            .rotation = Some(rotation);
        self.save(connection).await
    }

    async fn switch(
        &self,
        mut connection: VtaConnection,
        mut rotation: ControlKeyRotation,
    ) -> Result<Option<Step>, VtaError> {
        let id = connection.id.clone();
        let did = connection
            .control_did
            .clone()
            .unwrap_or_default();
        let new = self
            .provider(&rotation.next_key_ref, &did, &rotation.next_verification_method)
            .await?;
        match self
            .clients
            .switch_key(&id, new)
            .await
        {
            Ok(()) => {
                connection.control_key_ref = Some(rotation.next_key_ref.clone());
                connection
                    .control_key_state
                    .verification_method = Some(
                    rotation
                        .next_verification_method
                        .clone(),
                );
                rotation.phase = RotationPhase::Switched;
                connection
                    .control_key_state
                    .rotation = Some(rotation);
                self.save(connection).await?;
                Ok(None)
            }
            Err(error) => {
                let old = self
                    .provider(&rotation.previous_key_ref, &did, &rotation.previous_verification_method)
                    .await?;
                if let Err(e) = self
                    .clients
                    .switch_key(&id, old)
                    .await
                {
                    tracing::warn!(
                        target: "vta_audit",
                        connection_id = %id,
                        error = %e,
                        "could not put the previous control key back after a refused rotation",
                    );
                }
                rotation.attempts += 1;
                let refused =
                    matches!(&error, VtaError::Http { status: 401 | 403 | 422, .. }) && !error.is_superseded();
                let reason = if refused {
                    "the trust agent did not accept the new key".to_string()
                } else {
                    format!("the trust agent could not be reached: {error}")
                };
                connection
                    .control_key_state
                    .last_error = Some(reason.clone());
                let past_deadline = self.clock.now() >= rotation.give_up_at;
                tracing::warn!(
                    target: "vta_audit",
                    event = "vta_connection_control_key_rotation_retrying",
                    connection_id = %id,
                    attempts = rotation.attempts,
                    reason = %reason,
                    "the new control key did not sign in",
                );
                if past_deadline && refused {
                    connection
                        .control_key_state
                        .rotation = Some(rotation);
                    return self
                        .roll_back(connection)
                        .await
                        .map(|_| Some(Step::RolledBack));
                }
                if past_deadline {
                    connection
                        .control_key_state
                        .rotation = Some(rotation);
                    self.save(connection).await?;
                    return Err(VtaError::Config(reason));
                }
                let wait = backoff(rotation.attempts).max(
                    error
                        .retry_after()
                        .unwrap_or_default(),
                );
                connection
                    .control_key_state
                    .rotation = Some(rotation);
                self.save(connection).await?;
                Ok(Some(Step::Wait(wait)))
            }
        }
    }

    async fn roll_back(
        &self,
        mut connection: VtaConnection,
    ) -> Result<(), VtaError> {
        let Some(rotation) = connection
            .control_key_state
            .rotation
            .take()
        else {
            return Ok(());
        };
        let did = connection
            .control_did
            .clone()
            .unwrap_or_default();
        let old = self
            .plain_key(&rotation.previous_key_ref)
            .await?;
        let dir = self
            .publisher
            .dir(&connection.id)?;
        keep_only_key(&dir, &did, &old, fragment_of(&rotation.previous_verification_method)).await?;
        let reason = connection
            .control_key_state
            .last_error
            .clone()
            .unwrap_or_else(|| "the rotation was rolled back".to_string());
        connection
            .control_key_state
            .last_error = Some(format!("{reason}; the previous key is still in use"));
        self.save(connection.clone())
            .await?;
        self.delete_secret(&rotation.next_key_ref)
            .await;
        tracing::warn!(
            target: "vta_audit",
            event = "vta_connection_control_key_rotation_rolled_back",
            connection_id = %connection.id,
            control_did = %did,
            "a control-key rotation was rolled back; the previous key is in use",
        );
        Ok(())
    }

    async fn finish(
        &self,
        mut connection: VtaConnection,
        rotation: ControlKeyRotation,
    ) -> Result<(), VtaError> {
        let did = connection
            .control_did
            .clone()
            .unwrap_or_default();
        let new = self
            .plain_key(&rotation.next_key_ref)
            .await?;
        let dir = self
            .publisher
            .dir(&connection.id)?;
        keep_only_key(&dir, &did, &new, fragment_of(&rotation.next_verification_method)).await?;
        connection
            .control_key_state
            .rotation = None;
        connection
            .control_key_state
            .rotated_at = Some(self.clock.now());
        connection
            .control_key_state
            .last_error = None;
        self.save(connection.clone())
            .await?;
        self.delete_secret(&rotation.previous_key_ref)
            .await;
        tracing::info!(
            target: "vta_audit",
            event = "vta_connection_control_key_rotation_finished",
            connection_id = %connection.id,
            control_did = %did,
            previous_verification_method = %rotation.previous_verification_method,
            verification_method = %rotation.next_verification_method,
            "a connection's control key was rotated",
        );
        Ok(())
    }

    /// Stop a rotation that has not switched yet and put the old key back.
    pub async fn cancel(
        &self,
        id: &str,
    ) -> Result<RotationView, CancelError> {
        let _running = Running::begin(&self.running, id).ok_or(CancelError::NothingToCancel)?;
        let mut connection = self
            .load(id)
            .await
            .map_err(CancelError::Failed)?
            .ok_or(CancelError::NotFound)?;
        let Some(rotation) = connection
            .control_key_state
            .rotation
            .clone()
        else {
            return Err(CancelError::NothingToCancel);
        };
        match rotation.phase {
            RotationPhase::Switched => return Err(CancelError::TooLate),
            RotationPhase::Prepared => {
                connection
                    .control_key_state
                    .rotation = None;
                self.save(connection.clone())
                    .await
                    .map_err(CancelError::Failed)?;
                self.delete_secret(&rotation.next_key_ref)
                    .await;
            }
            RotationPhase::Introduced => {
                connection
                    .control_key_state
                    .last_error = Some("the rotation was cancelled".to_string());
                self.roll_back(connection.clone())
                    .await
                    .map_err(CancelError::Failed)?;
                connection = self
                    .load(id)
                    .await
                    .map_err(CancelError::Failed)?
                    .ok_or(CancelError::NotFound)?;
            }
        }
        tracing::info!(
            target: "vta_audit",
            event = "vta_connection_control_key_rotation_cancelled",
            connection_id = %id,
            "a control-key rotation was cancelled",
        );
        Ok(view_of(&connection))
    }

    /// Resume every rotation a restart interrupted.
    pub async fn resume_all(self: &Arc<Self>) {
        let Ok(connections) = self.store.list().await else {
            return;
        };
        for connection in connections {
            if connection
                .control_key_state
                .rotation
                .is_some()
            {
                let rotator = Arc::clone(self);
                let id = connection.id.clone();
                tokio::spawn(async move {
                    if let Err(Stalled(reason)) = rotator.drive(&id).await {
                        tracing::warn!(target: "vta_audit", connection_id = %id, reason = %reason, "a control-key rotation could not be resumed");
                    }
                });
            }
        }
    }
}

enum Step {
    Wait(Duration),
    RolledBack,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::{Secret, SecretListItem, UpdateSecretRequest};
    use crate::vta::auth_did::{declared_keys, ensure_connection_auth_did};
    use crate::vta::connections::{VtaConnectionStatus, VtaConnectionTransport};
    use crate::vta::pairing::PairingState;

    const ID: &str = "conn-r";

    struct FakeStore(Mutex<std::collections::HashMap<String, VtaConnection>>);

    #[async_trait]
    impl VtaConnectionStorage for FakeStore {
        async fn create(
            &self,
            connection: VtaConnection,
        ) -> anyhow::Result<VtaConnection> {
            self.0
                .lock()
                .unwrap()
                .insert(connection.id.clone(), connection.clone());
            Ok(connection)
        }

        async fn get(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<VtaConnection>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .get(id)
                .cloned())
        }

        async fn list(&self) -> anyhow::Result<Vec<VtaConnection>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .values()
                .cloned()
                .collect())
        }

        async fn update(
            &self,
            connection: VtaConnection,
        ) -> anyhow::Result<VtaConnection> {
            self.0
                .lock()
                .unwrap()
                .insert(connection.id.clone(), connection.clone());
            Ok(connection)
        }

        async fn delete(
            &self,
            id: &str,
        ) -> anyhow::Result<()> {
            self.0
                .lock()
                .unwrap()
                .remove(id);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeSecrets(Mutex<std::collections::HashMap<String, (String, String)>>);

    impl FakeSecrets {
        fn ids(&self) -> Vec<String> {
            let mut ids: Vec<String> = self
                .0
                .lock()
                .unwrap()
                .keys()
                .cloned()
                .collect();
            ids.sort();
            ids
        }
    }

    fn secret(
        secret_id: &str,
        id: &str,
        value: &str,
    ) -> Secret {
        let now = Utc::now();
        Secret {
            id: id.to_string(),
            tenant_id: None,
            name: secret_id.to_string(),
            secret_id: secret_id.to_string(),
            description: None,
            value: value.to_string(),
            secret_type: "General".to_string(),
            tags: vec![],
            created_at: now,
            updated_at: now,
        }
    }

    #[async_trait]
    impl SecretsStore for FakeSecrets {
        async fn create(
            &self,
            request: CreateSecretRequest,
        ) -> anyhow::Result<Secret> {
            let mut all = self.0.lock().unwrap();
            anyhow::ensure!(!all.contains_key(&request.secret_id), "exists");
            all.insert(request.secret_id.clone(), (format!("internal-{}", request.secret_id), request.value.clone()));
            Ok(secret(&request.secret_id, &format!("internal-{}", request.secret_id), &request.value))
        }

        async fn get(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<Secret>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .iter()
                .find(|(_, (internal, _))| internal == id)
                .map(|(sid, (internal, value))| secret(sid, internal, value)))
        }

        async fn get_by_secret_id(
            &self,
            secret_id: &str,
        ) -> anyhow::Result<Option<Secret>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .get(secret_id)
                .map(|(internal, value)| secret(secret_id, internal, value)))
        }

        async fn list_all(&self) -> anyhow::Result<Vec<SecretListItem>> {
            Ok(vec![])
        }

        async fn update(
            &self,
            _id: &str,
            _request: UpdateSecretRequest,
        ) -> anyhow::Result<Secret> {
            anyhow::bail!("unused")
        }

        async fn delete(
            &self,
            id: &str,
        ) -> anyhow::Result<()> {
            self.0
                .lock()
                .unwrap()
                .retain(|_, (internal, _)| internal != id);
            Ok(())
        }

        async fn find_by_tag(
            &self,
            _tag: &str,
        ) -> anyhow::Result<Vec<SecretListItem>> {
            Ok(vec![])
        }
    }

    /// Accepts a sign-in only as a verification method it was told about, as a
    /// trust agent that has resolved the published document would.
    struct FakeClients {
        accepted: Mutex<Vec<String>>,
        switches: Mutex<Vec<String>>,
        transport_failures: Mutex<u32>,
    }

    impl FakeClients {
        fn new(accepted: &[&str]) -> Arc<Self> {
            Arc::new(Self {
                accepted: Mutex::new(
                    accepted
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                ),
                switches: Mutex::new(vec![]),
                transport_failures: Mutex::new(0),
            })
        }

        fn switches(&self) -> Vec<String> {
            self.switches
                .lock()
                .unwrap()
                .clone()
        }
    }

    #[async_trait]
    impl ConnectionClients for FakeClients {
        async fn switch_key(
            &self,
            _id: &str,
            key: Arc<dyn SignerKeyProvider>,
        ) -> Result<(), VtaError> {
            let vm = key
                .verification_method()
                .rsplit('#')
                .next()
                .unwrap_or_default()
                .to_string();
            self.switches
                .lock()
                .unwrap()
                .push(vm.clone());
            {
                let mut failures = self
                    .transport_failures
                    .lock()
                    .unwrap();
                if *failures > 0 {
                    *failures -= 1;
                    return Err(VtaError::Transport("down".to_string()));
                }
            }
            if self
                .accepted
                .lock()
                .unwrap()
                .contains(&vm)
            {
                Ok(())
            } else {
                Err(VtaError::Http {
                    status: 422,
                    body: r#"{"payload":{"code":"proofInvalid"}}"#.to_string(),
                })
            }
        }
    }

    struct FakeClock(Mutex<DateTime<Utc>>);

    #[async_trait]
    impl Clock for FakeClock {
        fn now(&self) -> DateTime<Utc> {
            *self.0.lock().unwrap()
        }

        async fn sleep(
            &self,
            duration: Duration,
        ) {
            let mut now = self.0.lock().unwrap();
            *now += chrono::Duration::from_std(duration).unwrap();
        }
    }

    struct Fixture {
        storage: tempfile::TempDir,
        store: Arc<FakeStore>,
        secrets: Arc<FakeSecrets>,
        clients: Arc<FakeClients>,
        clock: Arc<FakeClock>,
        rotator: Arc<ConnectionKeyRotator>,
        did: String,
        old: ControlKey,
    }

    async fn fixture(accepted: &[&str]) -> Fixture {
        let storage = tempfile::tempdir().unwrap();
        let old = ControlKey::from_seed([61u8; 32]);
        let did = ensure_connection_auth_did(storage.path(), "example.com", ID, &old)
            .await
            .unwrap();
        let secrets = Arc::new(FakeSecrets::default());
        secrets
            .create(CreateSecretRequest {
                tenant_id: None,
                name: "key".to_string(),
                secret_id: format!("vta-control-key-{ID}"),
                description: None,
                value: old.seed_hex(),
                secret_type: "General".to_string(),
                tags: vec![],
            })
            .await
            .unwrap();
        let now = Utc::now();
        let mut pairing = crate::vta::pairing::PairingRecord::default();
        pairing.state = PairingState::Connected;
        let connection = VtaConnection {
            id: ID.to_string(),
            tenant_id: None,
            name: "Custom".to_string(),
            description: None,
            enabled: true,
            transport: VtaConnectionTransport::Https,
            endpoint: "http://127.0.0.1:3000".to_string(),
            vta_did: "did:webvh:vta.example".to_string(),
            default_context_id: Some("custom".to_string()),
            control_key_ref: Some(format!("vta-control-key-{ID}")),
            control_did: Some(did.clone()),
            control_key_state: Default::default(),
            status: VtaConnectionStatus::Connected,
            keys: Default::default(),
            pairing,
            created_at: now,
            updated_at: now,
        };
        let store = Arc::new(FakeStore(Mutex::new(Default::default())));
        store
            .create(connection)
            .await
            .unwrap();
        let clients = FakeClients::new(accepted);
        let clock = Arc::new(FakeClock(Mutex::new(now)));
        let rotator = Arc::new(ConnectionKeyRotator::new(
            store.clone(),
            secrets.clone(),
            ConnectionDidPublisher::new(storage.path().to_path_buf(), "example.com".to_string()),
            clients.clone(),
            clock.clone(),
            Duration::from_secs(330),
        ));
        Fixture {
            storage,
            store,
            secrets,
            clients,
            clock,
            rotator,
            did,
            old,
        }
    }

    impl Fixture {
        async fn record(&self) -> VtaConnection {
            self.store
                .get(ID)
                .await
                .unwrap()
                .unwrap()
        }

        async fn log(&self) -> String {
            let dir = crate::vta::auth_did::connection_auth_did_dir(self.storage.path(), ID).unwrap();
            crate::storage::did_artifacts::read_did_log_raw(&dir)
                .await
                .unwrap()
                .unwrap()
        }
    }

    #[tokio::test]
    async fn a_rotation_moves_to_a_new_key_without_changing_the_did() {
        let f = fixture(&["key-1", "key-2"]).await;

        f.rotator
            .start(ID, Some("ada"))
            .await
            .expect("start");
        let outcome = f
            .rotator
            .drive(ID)
            .await
            .expect("drive");

        assert_eq!(outcome, Outcome::Finished);
        let record = f.record().await;
        assert_eq!(record.control_did.as_deref(), Some(f.did.as_str()), "the DID is the one that was granted");
        assert_eq!(
            record
                .control_key_state
                .verification_method
                .as_deref(),
            Some("#key-2")
        );
        assert!(
            record
                .control_key_state
                .rotation
                .is_none()
        );
        assert!(
            record
                .control_key_state
                .rotated_at
                .is_some()
        );
        assert_eq!(
            record
                .control_key_ref
                .as_deref(),
            Some("vta-control-key-conn-r-key-2")
        );
        let keys = declared_keys(&f.log().await);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].fragment, "key-2");
        assert_ne!(keys[0].multibase, f.old.public_key_multibase());
        assert_eq!(f.clients.switches(), vec!["key-2".to_string()], "signed in once, as the new key");
        assert_eq!(f.secrets.ids(), vec!["vta-control-key-conn-r-key-2".to_string()], "the old seed is gone");
    }

    #[tokio::test]
    async fn the_new_secret_holds_the_key_the_document_declares() {
        let f = fixture(&["key-1", "key-2"]).await;
        f.rotator
            .start(ID, None)
            .await
            .unwrap();
        f.rotator
            .drive(ID)
            .await
            .unwrap();

        let stored = f
            .secrets
            .get_by_secret_id("vta-control-key-conn-r-key-2")
            .await
            .unwrap()
            .unwrap();
        let key = ControlKey::from_seed(crate::vta::decode_hex_seed(stored.value.trim()).unwrap());
        assert_eq!(declared_keys(&f.log().await)[0].multibase, key.public_key_multibase());
    }

    #[tokio::test]
    async fn a_refused_new_key_is_retried_and_then_rolled_back_with_the_old_key_in_use() {
        let f = fixture(&["key-1"]).await;

        f.rotator
            .start(ID, None)
            .await
            .unwrap();
        let outcome = f
            .rotator
            .drive(ID)
            .await
            .expect("drive");

        assert_eq!(outcome, Outcome::RolledBack);
        let record = f.record().await;
        assert!(
            record
                .control_key_state
                .rotation
                .is_none()
        );
        assert_eq!(
            record
                .control_key_ref
                .as_deref(),
            Some("vta-control-key-conn-r"),
            "still the old key"
        );
        assert_eq!(
            record
                .control_key_state
                .verification_method,
            None
        );
        assert!(
            record
                .control_key_state
                .last_error
                .as_deref()
                .unwrap()
                .contains("previous key is still in use")
        );
        let keys = declared_keys(&f.log().await);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].fragment, "key-1", "only the old key is published again");
        assert_eq!(f.secrets.ids(), vec!["vta-control-key-conn-r".to_string()], "the new seed was deleted");
        let switches = f.clients.switches();
        assert!(
            switches
                .iter()
                .filter(|vm| *vm == "key-2")
                .count()
                > 1,
            "retried before giving up: {switches:?}"
        );
        assert_eq!(
            switches
                .last()
                .map(String::as_str),
            Some("key-1"),
            "the client is back on the old key"
        );
    }

    #[tokio::test]
    async fn transient_errors_are_retried_and_the_rotation_then_succeeds() {
        let f = fixture(&["key-1", "key-2"]).await;
        *f.clients
            .transport_failures
            .lock()
            .unwrap() = 2;

        f.rotator
            .start(ID, None)
            .await
            .unwrap();
        let outcome = f
            .rotator
            .drive(ID)
            .await
            .expect("drive");

        assert_eq!(outcome, Outcome::Finished);
        assert_eq!(
            f.record()
                .await
                .control_key_state
                .verification_method
                .as_deref(),
            Some("#key-2")
        );
    }

    #[tokio::test]
    async fn an_unreachable_trust_agent_past_the_deadline_leaves_the_rotation_under_way_for_the_operator() {
        let f = fixture(&["key-1", "key-2"]).await;
        *f.clients
            .transport_failures
            .lock()
            .unwrap() = 1000;

        f.rotator
            .start(ID, None)
            .await
            .unwrap();
        let stalled = f
            .rotator
            .drive(ID)
            .await
            .expect_err("stalled");

        assert!(
            stalled
                .0
                .contains("could not be reached"),
            "{}",
            stalled.0
        );
        let record = f.record().await;
        let rotation = record
            .control_key_state
            .rotation
            .expect("still under way");
        assert_eq!(rotation.phase, RotationPhase::Introduced);
        assert!(rotation.attempts > 1);
        assert_eq!(declared_keys(&f.log().await).len(), 2, "both keys stay published");
    }

    #[tokio::test]
    async fn a_crash_after_each_phase_is_resumed_and_finishes_once() {
        for crash_after in ["prepared", "introduced", "switched"] {
            let f = fixture(&["key-1", "key-2"]).await;
            f.rotator
                .start(ID, None)
                .await
                .unwrap();
            let mut record = f.record().await;
            let mut rotation = record
                .control_key_state
                .rotation
                .clone()
                .unwrap();
            if crash_after != "prepared" {
                let current = ControlKey::from_seed(f.old.seed_bytes());
                let next_stored = f
                    .secrets
                    .get_by_secret_id(&rotation.next_key_ref)
                    .await
                    .unwrap()
                    .unwrap();
                let next = ControlKey::from_seed(crate::vta::decode_hex_seed(next_stored.value.trim()).unwrap());
                let dir = crate::vta::auth_did::connection_auth_did_dir(f.storage.path(), ID).unwrap();
                introduce_key(&dir, &f.did, &current, "key-2", &next.public_key_multibase())
                    .await
                    .unwrap();
                rotation.phase = RotationPhase::Introduced;
            }
            if crash_after == "switched" {
                record.control_key_ref = Some(rotation.next_key_ref.clone());
                record
                    .control_key_state
                    .verification_method = Some("#key-2".to_string());
                rotation.phase = RotationPhase::Switched;
            }
            record
                .control_key_state
                .rotation = Some(rotation);
            f.store
                .update(record)
                .await
                .unwrap();

            let outcome = f
                .rotator
                .drive(ID)
                .await
                .expect("resumed");

            assert_eq!(outcome, Outcome::Finished, "after {crash_after}");
            let record = f.record().await;
            assert!(
                record
                    .control_key_state
                    .rotation
                    .is_none(),
                "after {crash_after}"
            );
            let keys = declared_keys(&f.log().await);
            assert_eq!(keys.len(), 1, "after {crash_after}");
            assert_eq!(keys[0].fragment, "key-2");
            assert_eq!(f.log().await.lines().count(), 3, "birth, one introduce, one retire, after {crash_after}");
            assert_eq!(f.secrets.ids(), vec!["vta-control-key-conn-r-key-2".to_string()], "after {crash_after}");
        }
    }

    #[tokio::test]
    async fn resume_all_finishes_a_rotation_a_restart_interrupted() {
        let f = fixture(&["key-1", "key-2"]).await;
        f.rotator
            .start(ID, None)
            .await
            .unwrap();

        f.rotator.resume_all().await;
        for _ in 0..100 {
            if f.record()
                .await
                .control_key_state
                .rotation
                .is_none()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        assert!(
            f.record()
                .await
                .control_key_state
                .rotated_at
                .is_some()
        );
    }

    #[tokio::test]
    async fn cancelling_before_the_switch_puts_the_old_key_back() {
        let f = fixture(&["key-1", "key-2"]).await;
        f.rotator
            .start(ID, None)
            .await
            .unwrap();
        // introduce only
        let mut record = f.record().await;
        let rotation = record
            .control_key_state
            .rotation
            .clone()
            .unwrap();
        let next_stored = f
            .secrets
            .get_by_secret_id(&rotation.next_key_ref)
            .await
            .unwrap()
            .unwrap();
        let next = ControlKey::from_seed(crate::vta::decode_hex_seed(next_stored.value.trim()).unwrap());
        let dir = crate::vta::auth_did::connection_auth_did_dir(f.storage.path(), ID).unwrap();
        introduce_key(&dir, &f.did, &ControlKey::from_seed(f.old.seed_bytes()), "key-2", &next.public_key_multibase())
            .await
            .unwrap();
        record
            .control_key_state
            .rotation = Some(ControlKeyRotation {
            phase: RotationPhase::Introduced,
            ..rotation
        });
        f.store
            .update(record)
            .await
            .unwrap();

        let view = f
            .rotator
            .cancel(ID)
            .await
            .expect("cancelled");

        assert_eq!(view.phase, None);
        assert_eq!(declared_keys(&f.log().await)[0].fragment, "key-1");
        assert_eq!(f.secrets.ids(), vec!["vta-control-key-conn-r".to_string()]);
        assert_eq!(
            f.record()
                .await
                .control_key_ref
                .as_deref(),
            Some("vta-control-key-conn-r")
        );
    }

    #[tokio::test]
    async fn cancelling_after_the_switch_is_too_late_and_with_nothing_under_way_is_refused() {
        let f = fixture(&["key-1", "key-2"]).await;
        assert!(matches!(f.rotator.cancel(ID).await, Err(CancelError::NothingToCancel)));

        f.rotator
            .start(ID, None)
            .await
            .unwrap();
        let mut record = f.record().await;
        let mut rotation = record
            .control_key_state
            .rotation
            .clone()
            .unwrap();
        rotation.phase = RotationPhase::Switched;
        record
            .control_key_state
            .rotation = Some(rotation);
        f.store
            .update(record)
            .await
            .unwrap();

        assert!(matches!(f.rotator.cancel(ID).await, Err(CancelError::TooLate)));
    }

    #[tokio::test]
    async fn a_second_rotation_while_one_is_under_way_is_refused() {
        let f = fixture(&["key-1", "key-2"]).await;
        f.rotator
            .start(ID, None)
            .await
            .unwrap();

        let err = f
            .rotator
            .start(ID, None)
            .await
            .expect_err("in progress");

        assert!(matches!(&err, StartError::InProgress(view) if view.phase == Some(RotationPhase::Prepared)), "{err:?}");
    }

    #[tokio::test]
    async fn connections_that_cannot_rotate_say_why() {
        let f = fixture(&["key-1"]).await;
        let mut record = f.record().await;

        record.control_did = Some("did:key:z6MkPlain".to_string());
        f.store
            .update(record.clone())
            .await
            .unwrap();
        assert!(matches!(
            f.rotator
                .start(ID, None)
                .await,
            Err(StartError::NotWebvh)
        ));

        record.control_did = Some(f.did.clone());
        record.enabled = false;
        f.store
            .update(record.clone())
            .await
            .unwrap();
        assert!(matches!(
            f.rotator
                .start(ID, None)
                .await,
            Err(StartError::NotUsable(_))
        ));

        record.enabled = true;
        record.pairing.state = PairingState::AwaitingGrant;
        f.store
            .update(record.clone())
            .await
            .unwrap();
        assert!(matches!(
            f.rotator
                .start(ID, None)
                .await,
            Err(StartError::NotUsable(_))
        ));

        assert!(matches!(
            f.rotator
                .start("missing", None)
                .await,
            Err(StartError::NotFound)
        ));

        let mut bundled = record.clone();
        bundled.id = crate::vta::connections::BOOTSTRAP_CONNECTION_ID.to_string();
        f.store
            .create(bundled)
            .await
            .unwrap();
        assert!(matches!(
            f.rotator
                .start(crate::vta::connections::BOOTSTRAP_CONNECTION_ID, None)
                .await,
            Err(StartError::Bundled)
        ));
    }

    #[tokio::test]
    async fn the_view_never_carries_a_secret_reference() {
        let f = fixture(&["key-1", "key-2"]).await;
        let view = f
            .rotator
            .start(ID, None)
            .await
            .unwrap();

        let json = serde_json::to_string(&view).unwrap();

        assert!(!json.contains("vta-control-key"), "{json}");
        assert_eq!(
            view.next_verification_method
                .as_deref(),
            Some("#key-2")
        );
        assert_eq!(
            view.previous_verification_method
                .as_deref(),
            Some("#key-1")
        );
    }

    #[tokio::test]
    async fn the_next_rotation_numbers_the_key_after_the_last_one() {
        let f = fixture(&["key-1", "key-2", "key-3"]).await;
        f.rotator
            .start(ID, None)
            .await
            .unwrap();
        f.rotator
            .drive(ID)
            .await
            .unwrap();

        let view = f
            .rotator
            .start(ID, None)
            .await
            .expect("second rotation");
        f.rotator
            .drive(ID)
            .await
            .unwrap();

        assert_eq!(
            view.previous_verification_method
                .as_deref(),
            Some("#key-2")
        );
        assert_eq!(
            view.next_verification_method
                .as_deref(),
            Some("#key-3")
        );
        assert_eq!(
            f.record()
                .await
                .control_key_state
                .verification_method
                .as_deref(),
            Some("#key-3")
        );
        assert_eq!(f.secrets.ids(), vec!["vta-control-key-conn-r-key-3".to_string()]);
    }

    #[test]
    fn the_wait_between_tries_doubles_and_stops_at_a_minute() {
        assert_eq!(backoff(1), Duration::from_secs(10));
        assert_eq!(backoff(2), Duration::from_secs(20));
        assert_eq!(backoff(3), Duration::from_secs(40));
        assert_eq!(backoff(4), Duration::from_secs(60));
        assert_eq!(backoff(40), Duration::from_secs(60));
    }

    #[test]
    fn an_old_record_without_the_new_field_loads_unchanged() {
        let json = serde_json::json!({
            "id": "c", "name": "n", "enabled": true, "endpoint": "http://x", "vta_did": "did:webvh:v",
            "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"
        });
        let connection: VtaConnection = serde_json::from_value(json).unwrap();
        assert!(
            connection
                .control_key_state
                .is_default()
        );
        assert!(
            !serde_json::to_string(&connection)
                .unwrap()
                .contains("control_key_state")
        );
    }
}
