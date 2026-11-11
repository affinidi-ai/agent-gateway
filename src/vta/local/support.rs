use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use async_trait::async_trait;
use vta_audit::AuditSink;
use vta_sdk::protocols::audit_management::list::AuditLogEntry;
use vti_common::error::AppError;
use vti_common::seed_store::SeedStore;
use zeroize::Zeroize;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The seed the VTA store derives its imported-secret wrapping key from. It is
/// random per process and never persisted, because the store it protects is
/// rebuilt from the gateway's own key files on every start.
pub struct EphemeralSeedStore(Mutex<Option<Vec<u8>>>);

impl EphemeralSeedStore {
    pub fn random() -> Self {
        Self(Mutex::new(Some(rand::random::<[u8; 32]>().to_vec())))
    }
}

impl Drop for EphemeralSeedStore {
    fn drop(&mut self) {
        if let Ok(mut seed) = self.0.lock()
            && let Some(bytes) = seed.as_mut()
        {
            bytes.zeroize();
        }
    }
}

impl SeedStore for EphemeralSeedStore {
    fn get(&self) -> BoxFuture<'_, Result<Option<Vec<u8>>, AppError>> {
        let seed = self
            .0
            .lock()
            .map(|s| s.clone())
            .map_err(|_| AppError::Internal("the local signing seed lock is poisoned".to_string()));
        Box::pin(async move { seed })
    }

    fn set(
        &self,
        secret: &[u8],
    ) -> BoxFuture<'_, Result<(), AppError>> {
        let stored = self
            .0
            .lock()
            .map(|mut s| *s = Some(secret.to_vec()))
            .map_err(|_| AppError::Internal("the local signing seed lock is poisoned".to_string()));
        Box::pin(async move { stored })
    }

    fn set_persists_across_restart(&self) -> bool {
        false
    }
}

/// Reports what the VTA library records about a signature to the gateway's own
/// log. It carries identifiers only, never a payload or a key.
pub struct TracingAuditSink;

#[async_trait]
impl AuditSink for TracingAuditSink {
    async fn record(
        &self,
        entry: &AuditLogEntry,
    ) -> Result<(), AppError> {
        tracing::debug!(
            target: "vta_local",
            action = %entry.action,
            actor = %entry.actor,
            resource = entry.resource.as_deref().unwrap_or_default(),
            outcome = %entry.outcome,
            "local signing event",
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_seed_is_random_per_store_and_does_not_persist_across_a_restart() {
        let first = EphemeralSeedStore::random();
        let second = EphemeralSeedStore::random();
        let a = first
            .get()
            .await
            .expect("get")
            .expect("a seed");
        let b = second
            .get()
            .await
            .expect("get")
            .expect("a seed");
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
        assert!(!first.set_persists_across_restart());
    }

    #[tokio::test]
    async fn a_stored_seed_replaces_the_random_one() {
        let store = EphemeralSeedStore::random();
        store
            .set(&[7u8; 32])
            .await
            .expect("set");
        assert_eq!(
            store
                .get()
                .await
                .expect("get"),
            Some(vec![7u8; 32])
        );
    }

    #[tokio::test]
    async fn the_audit_sink_accepts_an_entry() {
        let entry = AuditLogEntry {
            id: "1".to_string(),
            timestamp: 0,
            action: "keys.sign-jws".to_string(),
            actor: "local:agent-gateway".to_string(),
            resource: Some("k".to_string()),
            outcome: "success".to_string(),
            channel: Some("local".to_string()),
            context_id: None,
            detail: None,
        };
        TracingAuditSink
            .record(&entry)
            .await
            .expect("recorded");
    }
}
