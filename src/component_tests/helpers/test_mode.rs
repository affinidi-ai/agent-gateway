//! Process-environment seam for tests that must reach loopback http endpoints.
//!
//! The production validators read `AG_TEST_MODE` together with
//! `AG_BDD_EGRESS_ALLOWLIST` (guarded egress, origin or exact entries) and
//! `AG_BDD_OAUTH_ENDPOINT_ALLOWLIST` (OAuth endpoint validation, exact entries).
//! This guard sets them for one test, serialises against every other test that
//! mutates `AG_TEST_MODE`, and restores the previous values on drop.

use std::sync::MutexGuard;

use super::mock_auth_server::MockAuthServer;

const TEST_MODE: &str = "AG_TEST_MODE";
const EGRESS_ALLOWLIST: &str = "AG_BDD_EGRESS_ALLOWLIST";
const OAUTH_ALLOWLIST: &str = "AG_BDD_OAUTH_ENDPOINT_ALLOWLIST";

pub(crate) struct TestModeEnv {
    lock: Option<MutexGuard<'static, bool>>,
    saved: Vec<(&'static str, Option<String>)>,
}

impl TestModeEnv {
    pub(crate) fn enabled(
        egress_allowlist: &str,
        oauth_allowlist: &str,
    ) -> Self {
        Self::with(Some("true"), Some(egress_allowlist), Some(oauth_allowlist))
    }

    pub(crate) fn enabled_for(server: &MockAuthServer) -> Self {
        Self::enabled(&server.egress_allowlist(), &server.oauth_endpoint_allowlist())
    }

    pub(crate) fn with(
        test_mode: Option<&str>,
        egress_allowlist: Option<&str>,
        oauth_allowlist: Option<&str>,
    ) -> Self {
        Self::with_lock(Self::lock(), test_mode, egress_allowlist, oauth_allowlist)
    }

    pub(crate) fn lock() -> MutexGuard<'static, bool> {
        crate::auth::test_auth::tests::TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn with_lock(
        lock: MutexGuard<'static, bool>,
        test_mode: Option<&str>,
        egress_allowlist: Option<&str>,
        oauth_allowlist: Option<&str>,
    ) -> Self {
        let vars = [(TEST_MODE, test_mode), (EGRESS_ALLOWLIST, egress_allowlist), (OAUTH_ALLOWLIST, oauth_allowlist)];
        let saved = vars
            .iter()
            .map(|(name, _)| (*name, std::env::var(name).ok()))
            .collect();
        for (name, value) in vars {
            set_or_remove(name, value);
        }
        Self { lock: Some(lock), saved }
    }
}

impl TestModeEnv {
    pub(crate) fn restore(mut self) -> MutexGuard<'static, bool> {
        self.restore_saved();
        self.lock
            .take()
            .expect("lock held until restore")
    }

    fn restore_saved(&mut self) {
        for (name, value) in self.saved.drain(..) {
            set_or_remove(name, value.as_deref());
        }
    }
}

impl Drop for TestModeEnv {
    fn drop(&mut self) {
        self.restore_saved();
    }
}

fn set_or_remove(
    name: &str,
    value: Option<&str>,
) {
    // The environment is process-global; every writer holds TEST_LOCK.
    unsafe {
        match value {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }
}
