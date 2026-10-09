//! Bootstrap configuration implementation

use super::types::*;
use std::path::{Path, PathBuf};

fn resolve_storage_path_from(
    config_dir: &Path,
    path: &str,
) -> String {
    let path = PathBuf::from(path);
    if !path.is_relative() {
        return path
            .to_string_lossy()
            .into_owned();
    }
    let joined = config_dir.join(path);
    joined
        .canonicalize()
        .unwrap_or_else(|_| {
            let mut resolved = PathBuf::new();
            for component in joined.components() {
                match component {
                    std::path::Component::ParentDir => {
                        resolved.pop();
                    }
                    _ => resolved.push(component),
                }
            }
            resolved
        })
        .to_string_lossy()
        .into_owned()
}

impl BootstrapConfig {
    /// Load bootstrap configuration from a TOML file
    pub fn from_file(path: &PathBuf) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;

        let mut config: BootstrapConfig = toml::from_str(&contents)?;

        // Resolve config file paths relative to the config file directory
        if let Some(config_dir) = path.parent() {
            // Resolve all config file paths
            if PathBuf::from(&config.config_files.gateway).is_relative() {
                config.config_files.gateway = config_dir
                    .join(&config.config_files.gateway)
                    .to_string_lossy()
                    .to_string();
            }
            if PathBuf::from(&config.config_files.metrics).is_relative() {
                let resolved = config_dir.join(&config.config_files.metrics);

                config.config_files.metrics = resolved
                    .to_string_lossy()
                    .to_string();
            }
            if PathBuf::from(&config.config_files.rbac).is_relative() {
                config.config_files.rbac = config_dir
                    .join(&config.config_files.rbac)
                    .to_string_lossy()
                    .to_string();
            }
            if PathBuf::from(&config.config_files.limits).is_relative() {
                config.config_files.limits = config_dir
                    .join(&config.config_files.limits)
                    .to_string_lossy()
                    .to_string();
            }
            if PathBuf::from(&config.config_files.saml).is_relative() {
                config.config_files.saml = config_dir
                    .join(&config.config_files.saml)
                    .to_string_lossy()
                    .to_string();
            }
            if PathBuf::from(&config.config_files.x402).is_relative() {
                config.config_files.x402 = config_dir
                    .join(&config.config_files.x402)
                    .to_string_lossy()
                    .to_string();
            }
            if PathBuf::from(&config.config_files.x402_proxy).is_relative() {
                config.config_files.x402_proxy = config_dir
                    .join(&config.config_files.x402_proxy)
                    .to_string_lossy()
                    .to_string();
            }

            // Resolve TLS certificate paths
            if config
                .tls
                .cert_path
                .is_relative()
            {
                config.tls.cert_path = config_dir.join(&config.tls.cert_path);
            }
            if config
                .tls
                .key_path
                .is_relative()
            {
                config.tls.key_path = config_dir.join(&config.tls.key_path);
            }

            // Resolve all storage paths relative to config directory
            let resolve_storage_path = |path: &str| resolve_storage_path_from(config_dir, path);

            config
                .storage_paths
                .config_cache = resolve_storage_path(
                &config
                    .storage_paths
                    .config_cache,
            );
            config.storage_paths.settings = resolve_storage_path(&config.storage_paths.settings);
            config
                .storage_paths
                .notifications = resolve_storage_path(
                &config
                    .storage_paths
                    .notifications,
            );
            config
                .storage_paths
                .notification_templates = resolve_storage_path(
                &config
                    .storage_paths
                    .notification_templates,
            );
            config
                .storage_paths
                .connection_points = resolve_storage_path(
                &config
                    .storage_paths
                    .connection_points,
            );
            config.storage_paths.secrets = resolve_storage_path(&config.storage_paths.secrets);
            config.storage_paths.apikeys = resolve_storage_path(&config.storage_paths.apikeys);
            config
                .storage_paths
                .certificates = resolve_storage_path(
                &config
                    .storage_paths
                    .certificates,
            );
            config
                .storage_paths
                .mcp_proxies = resolve_storage_path(
                &config
                    .storage_paths
                    .mcp_proxies,
            );
            config
                .storage_paths
                .a2a_proxies = resolve_storage_path(
                &config
                    .storage_paths
                    .a2a_proxies,
            );
            config
                .storage_paths
                .integrations = resolve_storage_path(
                &config
                    .storage_paths
                    .integrations,
            );
            config
                .storage_paths
                .integration_triggers = resolve_storage_path(
                &config
                    .storage_paths
                    .integration_triggers,
            );
            config.storage_paths.webhooks = resolve_storage_path(&config.storage_paths.webhooks);
            config.storage_paths.vc_keys = resolve_storage_path(&config.storage_paths.vc_keys);
            config.storage_paths.metrics = resolve_storage_path(&config.storage_paths.metrics);
            config.storage_paths.passkeys = resolve_storage_path(&config.storage_paths.passkeys);
            config.storage_paths.terms = resolve_storage_path(&config.storage_paths.terms);
            config.storage_paths.avatars = resolve_storage_path(&config.storage_paths.avatars);
            config
                .storage_paths
                .identities = resolve_storage_path(
                &config
                    .storage_paths
                    .identities,
            );
            config.storage_paths.gateways = resolve_storage_path(&config.storage_paths.gateways);
            config.storage_paths.mediators = resolve_storage_path(&config.storage_paths.mediators);
            config
                .storage_paths
                .trust_registries = resolve_storage_path(
                &config
                    .storage_paths
                    .trust_registries,
            );
            config.storage_paths.messages = resolve_storage_path(&config.storage_paths.messages);
            config
                .storage_paths
                .x402_transactions = resolve_storage_path(
                &config
                    .storage_paths
                    .x402_transactions,
            );
            config
                .storage_paths
                .mpp_transactions = resolve_storage_path(
                &config
                    .storage_paths
                    .mpp_transactions,
            );
            config.storage_paths.sessions = resolve_storage_path(&config.storage_paths.sessions);
            config
                .storage_paths
                .system_metrics = resolve_storage_path(
                &config
                    .storage_paths
                    .system_metrics,
            );
            config
                .storage_paths
                .agent_surfaces = resolve_storage_path(
                &config
                    .storage_paths
                    .agent_surfaces,
            );
            config
                .storage_paths
                .agent_surface_templates = resolve_storage_path(
                &config
                    .storage_paths
                    .agent_surface_templates,
            );
            config
                .storage_paths
                .identity_hash_pepper = resolve_storage_path(
                &config
                    .storage_paths
                    .identity_hash_pepper,
            );

            // Resolve DID cache storage path using the same resolve_storage_path function
            config.did_cache.storage_path = resolve_storage_path(&config.did_cache.storage_path);

            // Resolve log directory if present using the same resolve_storage_path function
            if let Some(ref log_dir) = config.logging.log_directory {
                config.logging.log_directory = Some(resolve_storage_path(log_dir));
            }

            // Remember the directory the config was loaded from so
            // downstream services can resolve sibling resource folders
            // (e.g. the agent surface template seeder).
            config.config_dir = Some(config_dir.to_path_buf());
        }

        // Deprecation WARN for the legacy `[storage_paths].departments` key
        // (accepted via `#[serde(alias = "departments")]`). Serde alias is
        // silent, so operators would never see the rename request otherwise.
        if raw_config_mentions_legacy_departments_storage_key(&contents) {
            tracing::warn!(
                config_file = %path.display(),
                "`[storage_paths].departments` is deprecated — rename the key to `issuers`. Legacy key still honoured for backward compatibility."
            );
        }

        // Auto-migrate the default legacy storage folder when the effective
        // issuers path resolves to the built-in default `_storage/issuers` and
        // that folder does not exist yet but `_storage/departments` does.
        // Operator-customised paths (either explicit `issuers = "…"` or the
        // legacy `departments = "…"`) are never auto-moved. Skipped when no
        // config directory was resolved (e.g. path had no parent) — the
        // migration is only meaningful anchored to a base directory.
        if let Some(base_dir) = config.config_dir.as_deref() {
            try_migrate_legacy_issuers_storage_folder(base_dir, &config.storage_paths.issuers);
        }

        // Initialise the process-global Q3 resource-name toggle now that the
        // bootstrap config is loaded. First call wins; safe under reload.
        crate::trust_registries::q3_resource_config::init(
            config
                .trust_registry
                .q3_resource_name
                .clone(),
        );

        Ok(config)
    }

    /// Validate the bootstrap configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        match self
            .channel_config_source
            .as_str()
        {
            "dynamodb" => {
                if self.dynamodb_table.is_none() {
                    anyhow::bail!("dynamodb_table must be specified when channel_config_source is 'dynamodb'");
                }
            }
            "file" => {
                // File-based config doesn't need additional validation here
            }
            "local" => {
                // Local config doesn't need additional validation here
            }
            other => {
                anyhow::bail!("Invalid channel_config_source '{}'. Must be 'dynamodb', 'file', or 'local'", other);
            }
        }

        // Validate A2A config (version, expires vs timeout, inflight limits, etc.)
        self.a2a
            .validate()
            .map_err(|e| anyhow::anyhow!("Invalid [a2a] config: {e}"))?;

        // Install the operator-configured advertised version now that it is known
        // to be supported, so the cards the gateway generates reflect it.
        crate::a2a::version::init_advertised_version(&self.a2a.default_version);

        if self
            .a2a
            .validate_messages
            .is_some()
        {
            tracing::warn!(
                "[a2a] validate_messages is deprecated: validation is set per A2A surface \
                 (access_point.a2a.validation). It is only applied to A2A surfaces loaded without their own \
                 settings, as \"off\" when false and \"envelope\" otherwise. Remove it from the config file."
            );
        }

        if let Some(continuations) = &self.mcp.continuations {
            continuations
                .validate()
                .map_err(|error| anyhow::anyhow!("Invalid [mcp.continuations] config: {error}"))?;
        }

        // Validate TLS certificate paths
        if !self.tls.cert_path.exists() {
            anyhow::bail!("TLS certificate file not found: {:?}", self.tls.cert_path);
        }

        if !self.tls.key_path.exists() {
            anyhow::bail!("TLS key file not found: {:?}", self.tls.key_path);
        }

        Ok(())
    }
}

/// Return true when the raw TOML config text mentions the legacy
/// `[storage_paths].departments` key (case-sensitive). Cheap substring scan
/// of the section — enough to surface a deprecation WARN without a full
/// TOML re-parse.
fn raw_config_mentions_legacy_departments_storage_key(raw: &str) -> bool {
    let Some(section_start) = raw.find("[storage_paths]") else {
        return false;
    };
    // Bound the search to the next section header (`\n[`) to avoid false
    // positives from unrelated `departments = "…"` lines elsewhere.
    let section_body = &raw[section_start..];
    let section_end = section_body[15..]
        .find("\n[")
        .map(|off| off + 15)
        .unwrap_or(section_body.len());
    let scope = &section_body[..section_end];
    scope.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with("departments") && trimmed.contains('=')
    })
}

/// Atomically rename `<base_dir>/_storage/departments` → `<base_dir>/_storage/issuers`
/// on boot when the operator has not customised the issuer storage path and the
/// legacy default folder is the only one present. Falls back to a copy-then-delete
/// on `EXDEV` (cross-filesystem `rename(2)`). Errors are logged and do not abort
/// startup.
///
/// `base_dir` is the config-file directory (`config.config_dir`) so all paths
/// are resolved to absolute locations without depending on the process CWD.
/// Tests can therefore pass a `tempdir` directly instead of mutating the
/// process-global CWD via `std::env::set_current_dir`.
fn try_migrate_legacy_issuers_storage_folder(
    base_dir: &std::path::Path,
    effective_issuers_path: &str,
) {
    // `storage_paths.issuers` is not run through `resolve_storage_path`, so
    // for a default config it stays as the raw serde default sentinel. Any
    // other value — including a resolved absolute form of the default —
    // means the operator (or the legacy `departments` alias) set the key
    // and owns the migration.
    if effective_issuers_path != ISSUERS_STORAGE_PATH_DEFAULT {
        return;
    }

    let legacy = base_dir
        .join("_storage")
        .join("departments");
    let canonical = base_dir
        .join("_storage")
        .join("issuers");

    if canonical.exists() || !legacy.exists() {
        return;
    }

    match std::fs::rename(&legacy, &canonical) {
        Ok(()) => {
            tracing::info!(
                from = %legacy.display(),
                to = %canonical.display(),
                "Migrated legacy storage folder to canonical location (`department` → `issuer` concept rename). No operator action required."
            );
        }
        Err(err) if err.raw_os_error() == Some(libc::EXDEV) => {
            tracing::error!(
                from = %legacy.display(),
                to = %canonical.display(),
                error = %err,
                "Cannot atomically rename storage folder (EXDEV — different filesystems). Falling back to copy-then-delete. This may leave the legacy folder behind on failure; verify and remove manually if needed."
            );
            if let Err(copy_err) = copy_directory_recursive(&legacy, &canonical) {
                tracing::error!(
                    from = %legacy.display(),
                    to = %canonical.display(),
                    error = %copy_err,
                    "Cross-filesystem storage migration failed. Falling back to reading from the legacy path is NOT supported — the operator must resolve manually (`mv _storage/departments _storage/issuers`) and restart."
                );
            } else if let Err(rm_err) = std::fs::remove_dir_all(&legacy) {
                tracing::warn!(
                    from = %legacy.display(),
                    error = %rm_err,
                    "Migrated storage folder contents but failed to remove the legacy directory. The gateway will read from the canonical path; safe to delete the legacy folder manually."
                );
            } else {
                tracing::info!(
                    from = %legacy.display(),
                    to = %canonical.display(),
                    "Migrated legacy storage folder to canonical location via copy-then-delete."
                );
            }
        }
        Err(err) => {
            tracing::error!(
                from = %legacy.display(),
                to = %canonical.display(),
                error = %err,
                "Failed to migrate legacy storage folder. Continue anyway — the gateway will run against an empty issuer store. Resolve manually (`mv _storage/departments _storage/issuers`) and restart."
            );
        }
    }
}

fn copy_directory_recursive(
    src: &std::path::Path,
    dst: &std::path::Path,
) -> std::io::Result<()> {
    if !dst.exists() {
        std::fs::create_dir_all(dst)?;
    }
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_directory_recursive(&src_path, &dst_path)?;
        } else if file_type.is_file() {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod migration_tests {
    use super::*;

    #[test]
    fn terms_storage_path_resolves_relative_to_the_config_directory() {
        let config_dir = Path::new("/opt/affinidi/config");

        assert_eq!(resolve_storage_path_from(config_dir, "../_storage/terms"), "/opt/affinidi/_storage/terms");
    }

    #[test]
    fn legacy_departments_key_detected_in_storage_paths_section() {
        let toml = r#"
[storage_paths]
config_cache = "/tmp/cache"
departments = "/tmp/dept"
authorities = "/tmp/auth"

[tls]
cert_path = "certs/cert.pem"
"#;
        assert!(raw_config_mentions_legacy_departments_storage_key(toml));
    }

    #[test]
    fn legacy_departments_key_not_falsely_detected_outside_storage_paths() {
        let toml = r#"
[other]
departments = "outside"

[tls]
cert_path = "certs/cert.pem"
"#;
        assert!(!raw_config_mentions_legacy_departments_storage_key(toml));
    }

    #[test]
    fn canonical_issuers_key_alone_is_not_flagged() {
        let toml = r#"
[storage_paths]
issuers = "/tmp/issuers"

[tls]
cert_path = "certs/cert.pem"
"#;
        assert!(!raw_config_mentions_legacy_departments_storage_key(toml));
    }

    #[test]
    fn unknown_top_level_key_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
backup_encryption_key = "unused"
unknown_section = "unsupported"

[tls]
cert_path = "cert.pem"
key_path = "key.pem"
"#,
        )
        .unwrap();

        let config = BootstrapConfig::from_file(&path).expect("unknown top-level keys are ignored");
        assert_eq!(config.backup_encryption_key, "unused");
    }

    #[test]
    fn shipped_example_is_valid_bootstrap_config() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/examples/config.example.toml");
        BootstrapConfig::from_file(&path).expect("shipped bootstrap example must parse");
    }

    #[test]
    fn migration_no_op_when_operator_customised_path() {
        // The tempdir is the base — no CWD mutation, so this test is safe
        // to run concurrently with the rest of the suite.
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        std::fs::create_dir_all(base.join("_storage/departments")).unwrap();
        std::fs::write(base.join("_storage/departments/dummy.txt"), "x").unwrap();

        // Operator customised the issuers path to a non-default value:
        try_migrate_legacy_issuers_storage_folder(base, "/tmp/custom/issuers");

        // Legacy dir untouched because operator customised the path.
        assert!(
            base.join("_storage/departments/dummy.txt")
                .exists()
        );
        assert!(
            !base
                .join("_storage/issuers")
                .exists()
        );
    }

    #[test]
    fn migration_renames_legacy_folder_to_canonical_when_effective_path_is_default() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();

        // Seed the legacy folder with a top-level file and a nested file so
        // the assertion covers both the shallow rename and any future switch
        // to the copy-then-delete walker.
        let legacy = base
            .join("_storage")
            .join("departments");
        std::fs::create_dir_all(legacy.join("nested")).unwrap();
        std::fs::write(legacy.join("issuer-a.json"), r#"{"id":"a"}"#).unwrap();
        std::fs::write(
            legacy
                .join("nested")
                .join("child.json"),
            r#"{"id":"b"}"#,
        )
        .unwrap();

        // The real caller passes `config.storage_paths.issuers`, which is
        // the raw serde default sentinel (`ISSUERS_STORAGE_PATH_DEFAULT`)
        // for an unset key — `storage_paths.issuers` is not resolved to an
        // absolute path. Feed the same value so this test exercises the
        // real production code path.
        try_migrate_legacy_issuers_storage_folder(base, ISSUERS_STORAGE_PATH_DEFAULT);

        let canonical = base
            .join("_storage")
            .join("issuers");
        assert!(!legacy.exists(), "legacy folder should be gone after migration");
        assert!(canonical.exists(), "canonical folder should exist after migration");
        assert_eq!(std::fs::read_to_string(canonical.join("issuer-a.json")).unwrap(), r#"{"id":"a"}"#);
        assert_eq!(
            std::fs::read_to_string(
                canonical
                    .join("nested")
                    .join("child.json")
            )
            .unwrap(),
            r#"{"id":"b"}"#
        );
    }
}
