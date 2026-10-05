//! Process-global encryption service shared by non-field consumers.
//!
//! Whole-file encryption is applied at the storage layer; this module owns the
//! single `EncryptionService` used by the remaining direct callers (OAuth state
//! sealing and portable-backup decryption) plus the boot-time init entrypoint.

use once_cell::sync::Lazy;
use std::sync::RwLock;
use tracing::{debug, warn};

use super::EncryptionService;

/// Global encryption config, initialized once at startup.
static GLOBAL_ENCRYPTION_CONFIG: Lazy<RwLock<Option<crate::config::EncryptionConfig>>> =
    Lazy::new(|| RwLock::new(None));

/// Global encryption service, initialized once at startup.
static GLOBAL_ENCRYPTION_SERVICE: Lazy<RwLock<Option<EncryptionService>>> = Lazy::new(|| RwLock::new(None));

// Test-only isolation. In production `init_global_encryption` writes the process-wide
// `GLOBAL_ENCRYPTION_*` slots below and every consumer reads them. Under `cargo test`,
// cases run concurrently on shared threads, so a process-wide global would let one test's
// config clobber another's. These thread-locals give each test thread its own
// config/service; `get_global_encryption_*` prefer them when set and otherwise fall back to
// the real global.
#[cfg(test)]
thread_local! {
    static TEST_ENCRYPTION_CONFIG: std::cell::RefCell<Option<crate::config::EncryptionConfig>> = const { std::cell::RefCell::new(None) };
    static TEST_ENCRYPTION_SERVICE: std::cell::RefCell<Option<EncryptionService>> = const { std::cell::RefCell::new(None) };
}

/// Initialize the global encryption service.
///
/// Constructs the `EncryptionService` internally from the given config via
/// `init_encryption_service`. Must be called before any consumer reads it.
pub fn init_global_encryption(config: crate::config::EncryptionConfig) -> anyhow::Result<()> {
    #[cfg(test)]
    {
        let encryption_service = crate::encryption::init::init_encryption_service(&config)?;
        TEST_ENCRYPTION_CONFIG.with(|global_config| {
            *global_config.borrow_mut() = Some(config);
        });
        TEST_ENCRYPTION_SERVICE.with(|global_encryption_service| {
            *global_encryption_service.borrow_mut() = Some(encryption_service);
        });

        debug!("Thread-local test encryption config and service initialized");
        Ok(())
    }

    #[cfg(not(test))]
    {
        let mut global_config = GLOBAL_ENCRYPTION_CONFIG
            .write()
            .unwrap();
        *global_config = Some(config.clone());

        let encryption_service = crate::encryption::init::init_encryption_service(&config)?;
        let mut global_encryption_service = GLOBAL_ENCRYPTION_SERVICE
            .write()
            .unwrap();
        *global_encryption_service = Some(encryption_service);

        debug!("Global encryption config and encryption service initialized");
        Ok(())
    }
}

/// Inject a prebuilt config + `EncryptionService` into the thread-local test
/// slots, bypassing `init_encryption_service`. Lets tests exercise the global
/// service with a mock-KMS-backed service. Sets the current thread's slots only.
#[cfg(test)]
pub(crate) fn set_test_encryption(
    config: crate::config::EncryptionConfig,
    service: EncryptionService,
) {
    TEST_ENCRYPTION_CONFIG.with(|c| *c.borrow_mut() = Some(config));
    TEST_ENCRYPTION_SERVICE.with(|s| *s.borrow_mut() = Some(service));
}

/// Get the global encryption config if set.
fn get_global_encryption_config() -> Option<crate::config::EncryptionConfig> {
    #[cfg(test)]
    {
        if let Some(config) = TEST_ENCRYPTION_CONFIG.with(|global_config| global_config.borrow().clone()) {
            return Some(config);
        }
    }

    GLOBAL_ENCRYPTION_CONFIG
        .read()
        .unwrap()
        .clone()
}

/// Get the global encryption service (internal).
fn get_global_encryption_service() -> Option<EncryptionService> {
    #[cfg(test)]
    {
        if let Some(service) = TEST_ENCRYPTION_SERVICE.with(|global_service| {
            global_service
                .borrow()
                .clone()
        }) {
            return Some(service);
        }
    }

    GLOBAL_ENCRYPTION_SERVICE
        .read()
        .unwrap()
        .clone()
}

/// Get the global encryption service for direct encrypt/decrypt operations.
pub fn get_encryption_service() -> Option<EncryptionService> {
    get_global_encryption_service()
}

/// True when encryption-at-rest is *configured* (`enabled`), regardless of the
/// active mode. A portable backup decrypts stored `ENC[...]` values in this case,
/// so the archive can hold plaintext key material.
pub fn is_field_encryption_configured() -> bool {
    get_global_encryption_config()
        .map(|cfg| cfg.enabled)
        .unwrap_or(false)
}

/// Build a service capable of **decrypting** existing `ENC[...]` values for a
/// portable backup export.
///
/// When encryption-at-rest is enabled the live global service is returned. When
/// disabled the global service is a pass-through that returns ciphertext
/// unchanged, so a one-off service is built from the configured key source
/// instead — disabling encryption stops *new* writes from being encrypted, but
/// must not blind the export to key material already stored as `ENC[...]`.
/// Returns `None` when no usable key source is configured; the caller then leaves
/// values verbatim.
pub fn build_backup_decryption_service() -> Option<EncryptionService> {
    let config = get_global_encryption_config()?;

    if config.enabled {
        return get_global_encryption_service();
    }

    let decrypt_config = crate::config::EncryptionConfig { enabled: true, ..config };
    match crate::encryption::init::init_encryption_service(&decrypt_config) {
        Ok(service) => Some(service),
        Err(e) => {
            warn!(
                "Backup: could not build a decryption service from the configured key source; \
                 ENC[...] values will be exported verbatim (non-portable): {}",
                e
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_backup_decryption_service_decrypts_when_at_rest_disabled() {
        // A value encrypted while encryption-at-rest was enabled.
        unsafe {
            std::env::set_var("GLOBAL_BACKUP_MEK", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        }
        let writer = EncryptionService::new(crate::encryption::KeySource::Environment {
            var_name: "GLOBAL_BACKUP_MEK".to_string(),
        })
        .unwrap();
        let ciphertext = writer
            .encrypt_field("s3cr3t")
            .unwrap();
        assert!(ciphertext.starts_with("ENC["));

        // Encryption-at-rest is now disabled, but the key source is still configured.
        let config = crate::config::EncryptionConfig {
            enabled: false,
            key_env_var: "GLOBAL_BACKUP_MEK".to_string(),
            ..Default::default()
        };
        set_test_encryption(config, EncryptionService::disabled());

        // The live global service is a pass-through and cannot decrypt...
        assert_eq!(
            get_encryption_service()
                .unwrap()
                .decrypt_field(&ciphertext)
                .unwrap(),
            ciphertext,
            "disabled global service must be a pass-through"
        );

        // ...but the backup decryption service, built from the key source, does.
        let service = build_backup_decryption_service().expect("decryption service from key source");
        assert_eq!(
            service
                .decrypt_field(&ciphertext)
                .unwrap(),
            "s3cr3t"
        );

        unsafe { std::env::remove_var("GLOBAL_BACKUP_MEK") };
    }
}
