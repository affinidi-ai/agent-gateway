//! Keeps post-login return targets on the gateway, so the SAML `RelayState` carries only a short
//! one-time key. The HTTP-Redirect binding caps `RelayState` at 80 bytes, see
//! [SAML 2.0 Bindings, section 3.4.3](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf).

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::service::AUTHN_REQUEST_TTL;

/// Caps memory held by return targets whose sign-in never came back.
const MAX_PENDING_RETURN_TARGETS: usize = 1000;

/// The `RelayState` limit of the HTTP-Redirect binding.
#[cfg(test)]
pub(super) const MAX_RELAY_STATE_BYTES: usize = 80;

struct PendingReturnTarget {
    target: String,
    expires_at: DateTime<Utc>,
}

#[derive(Default)]
pub(crate) struct ReturnTargetStore {
    entries: Mutex<HashMap<String, PendingReturnTarget>>,
}

impl ReturnTargetStore {
    /// Returns the key to send as `RelayState`: 32 hex characters. Expired targets are purged
    /// first, and `None` is returned when the store is still full.
    pub(crate) fn insert(
        &self,
        target: &str,
        now: DateTime<Utc>,
    ) -> Option<String> {
        let mut entries = self.lock();
        entries.retain(|_, pending| pending.expires_at > now);
        if entries.len() >= MAX_PENDING_RETURN_TARGETS {
            return None;
        }
        let key = Uuid::new_v4()
            .simple()
            .to_string();
        entries.insert(
            key.clone(),
            PendingReturnTarget {
                target: target.to_string(),
                expires_at: now + AUTHN_REQUEST_TTL,
            },
        );
        Some(key)
    }

    /// Removes the key, so it works once, and returns its target unless it has expired.
    pub(crate) fn take(
        &self,
        key: &str,
        now: DateTime<Utc>,
    ) -> Option<String> {
        let pending = self.lock().remove(key)?;
        (pending.expires_at > now).then_some(pending.target)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, PendingReturnTarget>> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: &str = "/api/auth/cli/authorize?port=52111&state=st&challenge=ch";

    #[test]
    fn key_is_url_safe_and_fits_the_redirect_binding_limit() {
        let store = ReturnTargetStore::default();

        let key = store
            .insert(TARGET, Utc::now())
            .unwrap();

        assert!(key.len() <= MAX_RELAY_STATE_BYTES);
        assert_eq!(urlencoding::encode(&key), key);
    }

    #[test]
    fn take_returns_the_stored_target() {
        let store = ReturnTargetStore::default();
        let now = Utc::now();
        let key = store
            .insert(TARGET, now)
            .unwrap();

        assert_eq!(
            store
                .take(&key, now)
                .as_deref(),
            Some(TARGET)
        );
    }

    #[test]
    fn a_key_works_only_once() {
        let store = ReturnTargetStore::default();
        let now = Utc::now();
        let key = store
            .insert(TARGET, now)
            .unwrap();

        assert!(
            store
                .take(&key, now)
                .is_some()
        );
        assert!(
            store
                .take(&key, now)
                .is_none()
        );
    }

    #[test]
    fn an_expired_key_returns_nothing() {
        let store = ReturnTargetStore::default();
        let now = Utc::now();
        let key = store
            .insert(TARGET, now)
            .unwrap();

        assert!(
            store
                .take(&key, now + AUTHN_REQUEST_TTL)
                .is_none()
        );
    }

    #[test]
    fn an_unknown_key_returns_nothing() {
        let store = ReturnTargetStore::default();
        store
            .insert(TARGET, Utc::now())
            .unwrap();

        assert!(
            store
                .take("0123456789abcdef0123456789abcdef", Utc::now())
                .is_none()
        );
    }

    #[test]
    fn insert_refuses_new_targets_at_the_cap() {
        let store = ReturnTargetStore::default();
        let now = Utc::now();
        for _ in 0..MAX_PENDING_RETURN_TARGETS {
            store
                .insert(TARGET, now)
                .unwrap();
        }

        assert!(
            store
                .insert(TARGET, now)
                .is_none()
        );
        assert_eq!(store.lock().len(), MAX_PENDING_RETURN_TARGETS);
    }

    #[test]
    fn insert_purges_expired_targets_before_checking_the_cap() {
        let store = ReturnTargetStore::default();
        let now = Utc::now();
        for _ in 0..MAX_PENDING_RETURN_TARGETS {
            store
                .insert(TARGET, now)
                .unwrap();
        }

        let later = now + AUTHN_REQUEST_TTL;
        assert!(
            store
                .insert(TARGET, later)
                .is_some()
        );
        assert_eq!(store.lock().len(), 1);
    }
}
