//! Storage module for configuration and settings persistence
//!
//! This module provides various storage backends for configuration and settings,
//! including DynamoDB, filesystem, and caching mechanisms.

use std::sync::Arc;
use tokio::sync::OnceCell;

pub mod config_cache;
pub mod config_store;
pub mod did_artifacts;
#[cfg(feature = "didwebvh")]
pub mod did_logs;
#[cfg(feature = "didwebvh")]
pub mod did_logs_file;
pub mod dynamodb_generic_repository;
pub mod dynamodb_store;
pub mod filesystem;
pub mod integration_handlers;
pub mod integration_trigger_handlers;
pub mod integrations;
pub mod settings_store;

// Re-export main types for convenience
pub use config_cache::ConfigCache;
pub use config_store::ConfigurationStore;
#[cfg(feature = "didwebvh")]
pub use did_logs::DidLogStorage;
#[cfg(feature = "didwebvh")]
pub use did_logs_file::FileDidLogStorage;
pub use dynamodb_store::DynamoDbConfigStore;
pub use filesystem::StorageBackend;
pub use integrations::{Integration, IntegrationStorage};
pub use settings_store::SettingsStore;
pub use settings_store::UserSettingsStore;

// Global integration storage instance
static INTEGRATION_STORAGE: OnceCell<Arc<IntegrationStorage>> = OnceCell::const_new();

/// Initialize the global integration storage
pub async fn init_integration_storage(storage: Arc<IntegrationStorage>) {
    INTEGRATION_STORAGE
        .set(storage)
        .ok();
}

/// Get the global integration storage instance
pub fn get_integration_storage() -> Option<Arc<IntegrationStorage>> {
    INTEGRATION_STORAGE
        .get()
        .cloned()
}

// Global settings storage path
static SETTINGS_STORAGE_PATH: OnceCell<String> = OnceCell::const_new();

// Global integration triggers storage path
static INTEGRATION_TRIGGERS_STORAGE_PATH: OnceCell<String> = OnceCell::const_new();

// Global gateways storage path
static GATEWAYS_STORAGE_PATH: OnceCell<String> = OnceCell::const_new();

// Global identity hash pepper file path
static IDENTITY_HASH_PEPPER_PATH: OnceCell<String> = OnceCell::const_new();

/// Initialize the global settings storage path
pub fn init_settings_storage_path(path: String) {
    SETTINGS_STORAGE_PATH
        .set(path)
        .ok();
}

/// Get the global settings storage path
#[allow(dead_code)]
pub fn get_settings_storage_path() -> Option<String> {
    SETTINGS_STORAGE_PATH
        .get()
        .cloned()
}

/// Initialize the global integration triggers storage path
pub fn init_integration_triggers_storage_path(path: String) {
    INTEGRATION_TRIGGERS_STORAGE_PATH
        .set(path)
        .ok();
}

/// Get the global integration triggers storage path
pub fn get_integration_triggers_storage_path() -> Option<String> {
    INTEGRATION_TRIGGERS_STORAGE_PATH
        .get()
        .cloned()
}

/// Initialize the global gateways storage path
pub fn init_gateways_storage_path(path: String) {
    GATEWAYS_STORAGE_PATH
        .set(path)
        .ok();
}

/// Get the global gateways storage path
pub fn get_gateways_storage_path() -> Option<String> {
    GATEWAYS_STORAGE_PATH
        .get()
        .cloned()
}

/// Initialize the global identity hash pepper file path
pub fn init_identity_hash_pepper_path(path: String) {
    IDENTITY_HASH_PEPPER_PATH
        .set(path)
        .ok();
}

/// Reject any storage ID that could escape the storage directory.
///
/// A valid ID is exactly one normal path component — no separators, no `.` or `..`,
/// no null bytes.  Call this before constructing any filesystem path from an
/// externally-supplied identifier (HTTP path params, JSON fields, etc.).
pub fn validate_storage_id(id: &str) -> anyhow::Result<()> {
    use std::path::{Component, Path};
    let path = Path::new(id);
    let mut components = path.components();
    match components.next() {
        Some(Component::Normal(_)) => {}
        _ => anyhow::bail!("invalid storage id: path traversal or empty id rejected"),
    }
    if components.next().is_some() {
        anyhow::bail!("invalid storage id: path traversal or empty id rejected");
    }
    Ok(())
}

/// Confirm that `candidate` resolves to a path inside `storage_dir`.
///
/// Confirm that `candidate` is inside `storage_dir`.
///
/// Rejects any path that contains a `..` component — that is sufficient to
/// prevent directory traversal without requiring OS canonicalization (which
/// breaks on platforms where the temp dir is a symlink, e.g. macOS
/// `/var` → `/private/var`).  Then performs a lexical `starts_with` check;
/// Rust's `Path::starts_with` compares component-by-component so there is no
/// string-prefix false-positive risk.
pub fn assert_within_storage_dir(
    storage_dir: &std::path::Path,
    candidate: &std::path::Path,
) -> anyhow::Result<()> {
    use std::path::Component;
    if candidate
        .components()
        .any(|c| c == Component::ParentDir)
    {
        anyhow::bail!("path resolves outside the storage directory");
    }
    if !candidate.starts_with(storage_dir) {
        anyhow::bail!("path resolves outside the storage directory");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{assert_within_storage_dir, validate_storage_id};
    use tempfile::TempDir;

    // ============================================================================
    // validate_storage_id tests
    // ============================================================================

    #[test]
    fn test_validate_storage_id_accepts_normal_ids() {
        assert!(validate_storage_id("abc123").is_ok());
        assert!(validate_storage_id("some-uuid-1234-abcd").is_ok());
        assert!(validate_storage_id("secret_name").is_ok());
        assert!(validate_storage_id("a").is_ok());
    }

    #[test]
    fn test_validate_storage_id_rejects_traversal_sequences() {
        assert!(validate_storage_id("../../etc/passwd").is_err());
        assert!(validate_storage_id("../foo").is_err());
        assert!(validate_storage_id("foo/bar").is_err());
        assert!(validate_storage_id("..").is_err());
        assert!(validate_storage_id(".").is_err());
        assert!(validate_storage_id("").is_err());
        assert!(validate_storage_id("/etc/passwd").is_err());
        assert!(validate_storage_id("./local").is_err());
    }

    // ============================================================================
    // assert_within_storage_dir tests
    // ============================================================================

    #[test]
    fn test_assert_within_storage_dir_accepts_child() {
        let dir = TempDir::new().unwrap();
        let child = dir.path().join("agent-1");
        assert!(assert_within_storage_dir(dir.path(), &child).is_ok());
    }

    #[test]
    fn test_assert_within_storage_dir_accepts_existing_child() {
        let dir = TempDir::new().unwrap();
        let child = dir.path().join("agent-1");
        std::fs::create_dir_all(&child).unwrap();
        assert!(assert_within_storage_dir(dir.path(), &child).is_ok());
    }

    #[test]
    fn test_assert_within_storage_dir_accepts_storage_dir_itself() {
        let dir = TempDir::new().unwrap();
        assert!(assert_within_storage_dir(dir.path(), dir.path()).is_ok());
    }

    #[test]
    fn test_assert_within_storage_dir_rejects_parent() {
        let dir = TempDir::new().unwrap();
        let parent = dir.path().parent().unwrap();
        let result = assert_within_storage_dir(dir.path(), parent);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("outside the storage directory")
        );
    }

    #[test]
    fn test_assert_within_storage_dir_rejects_sibling() {
        let dir = TempDir::new().unwrap();
        // Build a sibling path without creating it — canonicalize falls back to raw path
        let sibling = dir
            .path()
            .parent()
            .unwrap()
            .join("sibling-dir-that-does-not-exist");
        let result = assert_within_storage_dir(dir.path(), &sibling);
        assert!(result.is_err());
    }

    #[test]
    fn test_assert_within_storage_dir_rejects_traversal_path() {
        let dir = TempDir::new().unwrap();
        // Simulate what would happen if a traversal ID slipped through:
        // storage_dir.join("../../etc") resolves outside storage_dir
        let traversal = dir.path().join("../../etc");
        let result = assert_within_storage_dir(dir.path(), &traversal);
        assert!(result.is_err());
    }

    #[test]
    fn test_assert_within_storage_dir_accepts_nonexistent_child_via_symlinked_root() {
        // No canonicalization is performed, so this test simply verifies that
        // a non-existent child (built via join) is accepted and a traversal is
        // rejected — without any OS symlink resolution.
        let dir = TempDir::new().unwrap();

        // Non-existent child: accepted because it starts_with storage_dir and has no `..`.
        let child = dir
            .path()
            .join("new-agent-not-yet-created");
        assert!(assert_within_storage_dir(dir.path(), &child).is_ok());

        // Traversal via `..`: rejected because ParentDir component is present.
        let traversal = dir
            .path()
            .join("../../escape");
        assert!(assert_within_storage_dir(dir.path(), &traversal).is_err());
    }
}
