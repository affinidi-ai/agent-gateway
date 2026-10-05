//! Wakeup notifier for vault-population events.
//!
//! When the gateway is waiting for a user to complete an OAuth flow (typically
//! because an in-flight MCP tool call elicited consent and is parked), we need
//! to unblock the parked task the instant the OAuth callback writes a token
//! into the vault.
//!
//! The notifier maps a composite vault key
//! `(agent_did, user_identity_hash, credential_provider_id)` to a
//! [`tokio::sync::Notify`]. Callers `await` `wait_for(...)`, the OAuth
//! callback handler calls `notify(...)` after a successful `vault_store.store`,
//! and any number of parked tasks for the same key wake up at once.
//!
//! The notifier is intentionally fire-and-forget: it carries no data. After
//! waking, the caller re-runs the normal vault lookup, which is the source of
//! truth.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

#[derive(Debug, Default)]
pub struct VaultPopulationNotifier {
    inner: Mutex<HashMap<String, Arc<Notify>>>,
}

impl VaultPopulationNotifier {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(
        agent_did: &str,
        user_identity_hash: &str,
        credential_provider_id: &str,
    ) -> String {
        format!("{}\u{1f}{}\u{1f}{}", agent_did, user_identity_hash, credential_provider_id)
    }

    /// Obtain (or create) the [`Notify`] for a key. Caller `.notified().await`s
    /// on the returned handle. Drop the Arc when no longer interested — the
    /// notifier itself retains an entry until cleared (entries are cheap).
    #[allow(dead_code)] // used by the race-aware elicitation wait path
    pub async fn subscribe(
        &self,
        agent_did: &str,
        user_identity_hash: &str,
        credential_provider_id: &str,
    ) -> Arc<Notify> {
        let k = Self::key(agent_did, user_identity_hash, credential_provider_id);
        let mut guard = self.inner.lock().await;
        guard
            .entry(k)
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    /// Wake every parked task currently subscribed to this key. Safe to call
    /// even if no one is waiting.
    pub async fn notify(
        &self,
        agent_did: &str,
        user_identity_hash: &str,
        credential_provider_id: &str,
    ) {
        let k = Self::key(agent_did, user_identity_hash, credential_provider_id);
        let guard = self.inner.lock().await;
        if let Some(n) = guard.get(&k) {
            n.notify_waiters();
        }
    }
}

pub type SharedVaultPopulationNotifier = Arc<VaultPopulationNotifier>;

static GLOBAL_VAULT_POPULATION_NOTIFIER: std::sync::OnceLock<SharedVaultPopulationNotifier> =
    std::sync::OnceLock::new();

/// Process-wide vault-population notifier. Used by:
///   - `oauth_callback` (writer side) to wake parked tasks after a successful
///     `vault_store.store`
///   - `credential_delegation::resolve_delegation_credentials` (waiter side)
///     when running in `ConsentMode::Elicit`
///
/// Mirrors the OnceLock singleton pattern used by `mcp::elicitation`.
pub fn global_vault_population_notifier() -> &'static SharedVaultPopulationNotifier {
    GLOBAL_VAULT_POPULATION_NOTIFIER.get_or_init(|| Arc::new(VaultPopulationNotifier::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn subscribe_and_notify_wakes_one_waiter() {
        let n = Arc::new(VaultPopulationNotifier::new());
        let handle = n
            .subscribe("did:agent", "userhash", "github")
            .await;

        let n2 = n.clone();
        let waiter = tokio::spawn(async move {
            handle.notified().await;
            "woke"
        });

        // Give the spawned task a moment to park
        tokio::task::yield_now().await;
        n2.notify("did:agent", "userhash", "github")
            .await;

        let result = timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter never woke")
            .unwrap();
        assert_eq!(result, "woke");
    }

    #[tokio::test]
    async fn notify_with_no_waiters_is_noop() {
        let n = VaultPopulationNotifier::new();
        n.notify("did:agent", "userhash", "github")
            .await;
    }

    #[tokio::test]
    async fn keys_are_isolated() {
        let n = Arc::new(VaultPopulationNotifier::new());
        let h1 = n
            .subscribe("did:a", "u", "p1")
            .await;
        let h2 = n
            .subscribe("did:a", "u", "p2")
            .await;

        let woke1 = Arc::new(tokio::sync::Mutex::new(false));
        let woke2 = Arc::new(tokio::sync::Mutex::new(false));

        let w1 = woke1.clone();
        let t1 = tokio::spawn(async move {
            h1.notified().await;
            *w1.lock().await = true;
        });
        let w2 = woke2.clone();
        let _t2 = tokio::spawn(async move {
            h2.notified().await;
            *w2.lock().await = true;
        });
        tokio::task::yield_now().await;

        n.notify("did:a", "u", "p1")
            .await;
        timeout(Duration::from_secs(1), t1)
            .await
            .unwrap()
            .unwrap();
        assert!(*woke1.lock().await);
        assert!(!*woke2.lock().await);
    }
}
