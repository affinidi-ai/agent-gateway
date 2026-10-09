#![recursion_limit = "256"]
#![allow(clippy::too_many_arguments)]

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use anyhow::{Context, Result};
use clap::Parser;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use tracing::{Level, error, info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;

mod config;
mod metrics;

// Refactored modular structure
mod a2a;
mod a2a_proxies;
mod access_tokens;
mod agents_api;
mod ap2; // AP2 protocol (Agent-to-Agent Plus)
mod api_keys; // API Key Provider for A2A authentication
mod auth;
mod auth_manager;
mod authorities; // Local record book of external authority DIDs (trust anchors)
mod backup_restore; // Backup and restore logic for _storage
mod certificates; // Certificate management (TLS/SSL certificates)
mod comm;
mod credential_providers; // OAuth credential provider CRUD management
mod delegation_vault; // Delegation vault — encrypted OAuth tokens + consent flow
mod didauth; // DID Authentication for channels
mod egress; // DNS-pinning, redirect-revalidating SSRF egress guard primitive
mod encryption; // Encryption at rest for local storage
mod export; // Storage export with PII redaction and public-key encryption
mod gateways;
mod http_client; // Shared reqwest client factory (timeout + redirect policy defaults)
mod identity;
mod integrations;
mod issuers; // Issuer management with auto-generated did:web / did:webvh DIDs (was: departments)
mod jwt_bearer; // JWT Bearer token authentication
mod mcp; // Model Context Protocol support
mod mcp_proxies;
mod mediators;
mod messages;
mod mpp; // MPP (Machine Payments Protocol) — IETF draft-httpauth-payment-00
mod observability;
mod payment_credentials; // Payment dispute-evidence Verifiable Credentials
mod policies;
mod protocols; // Protocol-agnostic utilities (multi-protocol support)
mod proxy;
mod rbac;
mod secrets;
mod server;
mod source_auth; // Unified source authentication (JWT Bearer, API Key, DID Auth, mTLS)
mod state;
mod storage;
mod sts; // Security Token Service — RFC 8693 token exchange + ID-JAG
mod surface_context; // Shared context types for OPA policy evaluation
mod surface_templates; // Reusable surface item bundles (builtin + user)
mod surfaces; // Agent Surface configuration CRUD (replaces channels)
mod tenancy; // Management API tenant context and ownership helpers
mod terms;
mod trust_registries;
mod trust_registry_verification; // Trust Registry client and validation
mod url_validation; // SSRF protection for user-supplied URLs
mod vault_identity; // Vault identity generation for API keys and certificates
mod x402; // x402 protocol (HTTP Native Payments Protocol)

#[cfg(test)]
mod component_tests;

use config::{BootstrapConfig, GatewayConfig};
use storage::{ConfigCache, ConfigurationStore, DynamoDbConfigStore};

/// A2A Protocol Intercepting Proxy
///
/// An HTTPS proxy server for the Agent2Agent (A2A) protocol that intercepts
/// and forwards requests between clients and A2A agents.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to bootstrap configuration file (TOML format)
    /// This file specifies the DynamoDB table or other config source
    #[arg(short, long, value_name = "FILE", default_value = "config.toml")]
    config: PathBuf,

    /// Path to TLS certificate file (overrides config file)
    #[arg(long, env = "agent_gateway_CERT")]
    cert: Option<PathBuf>,

    /// Path to TLS private key file (overrides config file)
    #[arg(long, env = "agent_gateway_KEY")]
    key: Option<PathBuf>,

    /// Generate a default bootstrap configuration file
    #[arg(long)]
    generate_bootstrap: bool,

    // Base folder
    #[arg(long, default_value = "")]
    base_folder: String,

    // Use cors origins
    #[arg(long, default_value = "")]
    cors_origins: String,

    /// Export storage with PII redaction, encrypted with recipient's Ed25519 public key
    #[arg(long, value_name = "OUTPUT_FILE")]
    export_storage: Option<PathBuf>,

    /// Decrypt a previously exported storage archive
    #[arg(long, value_name = "INPUT_FILE")]
    decrypt_export: Option<PathBuf>,

    /// Output path (used with --decrypt-export, defaults to export.zip)
    #[arg(long, value_name = "OUTPUT_FILE", default_value = "export.zip")]
    output: PathBuf,
}

fn main() -> Result<()> {
    // ssi-json-ld's recursive expansion (json-ld-expansion) overflows the
    // default 2 MiB Tokio worker stack on macOS for typical agent-identity
    // VPs. Give every Tokio-managed thread (workers + blocking pool) 8 MiB.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(8 * 1024 * 1024)
        .build()?
        .block_on(async_main())
}

async fn async_main() -> Result<()> {
    // Note: Can't log here yet - logging not initialized

    // Initialize rustls crypto provider (ring backend)
    // This must be done before any TLS operations
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install rustls crypto provider"))?;

    // Initialize dashboard start time
    observability::init_start_time();

    // Install SIGUSR1/SIGUSR2 dispositions before any async work so a signal
    // arriving before spawn_signal_handlers() runs is queued, not fatal.
    crate::server::mode::install_signal_handlers();

    let args = Args::parse();

    // Generate default bootstrap config if requested
    if args.generate_bootstrap {
        generate_default_bootstrap(&args.base_folder, &args.cors_origins)?;
        return Ok(());
    }

    // Decrypt a previously exported storage archive (no config needed)
    if let Some(input_path) = &args.decrypt_export {
        export::decrypt_export(input_path, &args.output)?;
        return Ok(());
    }

    // Load bootstrap configuration
    let config_path = std::env::current_dir()?.join(&args.config);
    let bootstrap_config = BootstrapConfig::from_file(&config_path)
        .with_context(|| format!("Failed to load bootstrap config from {:?}", config_path))?;

    // Apply the boot-time mode from config; signals arriving before this are already queued.
    crate::server::mode::set_server_mode(bootstrap_config.server_mode);
    if crate::server::mode::is_standby() {
        tracing::info!("server_mode=standby: /api/v1/health will report 503 until promotion with SIGUSR1");
    }

    // Configure shared-storage cache tailing before any store is constructed. `0`
    // (default) leaves single-node deployments free of periodic disk polling.
    crate::storage::filesystem::set_cache_refresh_interval_secs(bootstrap_config.cache_refresh_interval_secs);
    if bootstrap_config.cache_refresh_interval_secs > 0 {
        tracing::info!(
            "cache_refresh_interval_secs={}: cached stores will tail shared storage for cross-node changes",
            bootstrap_config.cache_refresh_interval_secs
        );
    }

    println!("DEBUG: Loaded bootstrap config from {:?}", config_path);
    println!(
        "DEBUG:   config_cache_path: {}",
        bootstrap_config
            .storage_paths
            .config_cache
    );
    println!(
        "DEBUG:   settings_storage_path: {}",
        bootstrap_config
            .storage_paths
            .settings
    );
    println!(
        "DEBUG:   metrics_config_path: {}",
        bootstrap_config
            .config_files
            .metrics
    );

    // Export storage with PII redaction (needs config for storage paths)
    if let Some(output_path) = &args.export_storage {
        let storage_root = export::resolve_storage_root(
            &bootstrap_config
                .storage_paths
                .agent_surfaces,
            &args.base_folder,
        );
        export::export_storage(&storage_root, output_path)?;
        return Ok(());
    }

    // Check for a staged backup (backup.agbak / legacy backup.tgwbak) and perform restore if present
    {
        let storage_root = export::resolve_storage_root(
            &bootstrap_config
                .storage_paths
                .agent_surfaces,
            &args.base_folder,
        );
        let backup_restore_dir = if bootstrap_config
            .storage_paths
            .backup_restore
            .starts_with('/')
            || args.base_folder.is_empty()
        {
            std::path::PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .backup_restore,
            )
        } else {
            std::path::PathBuf::from(&args.base_folder).join(
                &bootstrap_config
                    .storage_paths
                    .backup_restore,
            )
        };
        let restore_domain = bootstrap_config
            .load_network_config()
            .context("Failed to load did.domain for backup restore")?
            .did
            .domain;
        // The backup encryption key is REQUIRED. Resolve it once here (fail closed) so
        // startup aborts with a clear error when it is unset or unresolvable. When a
        // restore is staged, record the configuration failure before aborting.
        let backup_key =
            match backup_restore::encryption::resolve_backup_key(&bootstrap_config.backup_encryption_key).await {
                Ok(key) => key,
                Err(error) => {
                    backup_restore::record_startup_restore_key_unavailable(&backup_restore_dir, &restore_domain);
                    return Err(error).context("backup_encryption_key is required");
                }
            };

        if backup_restore::check_and_restore_backup(
            &storage_root,
            &backup_restore_dir,
            &backup_key,
            bootstrap_config
                .legacy_backup_encryption_keys
                .as_deref(),
            &restore_domain,
        ) {
            // Restore was performed — exit so Docker/supervisor restarts us
            std::process::exit(1);
        }

        // Legacy-key configuration remains fail-closed when no restore is staged.
        backup_restore::encryption::resolve_legacy_backup_keys(
            bootstrap_config
                .legacy_backup_encryption_keys
                .as_deref(),
        )
        .context("legacy_backup_encryption_keys is invalid")?;
    }

    bootstrap_config
        .validate()
        .context("Bootstrap configuration validation failed")?;

    let config = load_configuration(&bootstrap_config)
        .await
        .context("Failed to load configuration")?;

    // Initialize encryption at rest BEFORE logging. The OTLP exporter may be
    // configured with an auth header whose value lives in the secrets store,
    // and the store can only decrypt values once encryption is initialized.
    // Logs here use eprintln! because the tracing subscriber is not installed
    // until init_logging below.
    let encryption = bootstrap_config
        .encryption
        .clone();
    eprintln!("Setting up encryption configuration...");
    if encryption.enabled {
        eprintln!("Initializing encryption at rest (key_source={:?})", encryption.key_source);
        if encryption.key_source == config::KeySourceConfig::Local {
            eprintln!("WARNING: key_source=local performs NO encryption - development only");
        }
    } else {
        eprintln!("Encryption at rest is DISABLED - data will be stored unencrypted");
    }

    // Initialize global encryption service for the remaining direct consumers
    // (OAuth state sealing, portable-backup decryption).
    encryption::global::init_global_encryption(encryption.clone())
        .context("Failed to initialize encryption service")?;

    // Initialize global encryption config for all storage operations
    storage::filesystem::init_global_encryption(encryption.clone())
        .context("Failed to initialize storage encryption")?;

    // Boot migration: decrypt any residual field-level ENC[...] values left by an
    // earlier build to plaintext, before any store is loaded into a model. Whole-file
    // encryption re-wraps them on the next save.
    {
        let storage_root = export::resolve_storage_root(
            &bootstrap_config
                .storage_paths
                .agent_surfaces,
            &args.base_folder,
        );
        encryption::migration::migrate_field_encrypted_values(&storage_root, &encryption);
    }

    // Boot preflight: refuse to start if any persisted value uses an envelope version
    // incompatible with the active key_source (e.g. a local-MEK value under aws_kms, or vice-versa),
    // rather than limping into partial unreadability. Covers whole-file encryption
    // (`.json.enc`, which stores an `ENC[...]` string).
    let encryption_preflight_version = if encryption.enabled {
        let storage_root = export::resolve_storage_root(
            &bootstrap_config
                .storage_paths
                .agent_surfaces,
            &args.base_folder,
        );
        let active_version = encryption::preflight::active_envelope_version(encryption.key_source);
        encryption::preflight::check_envelope_versions(&storage_root, active_version)
            .context("Encryption backend preflight failed — refusing to start")?;
        Some(active_version)
    } else {
        None
    };

    // Post-restore re-encryption marker: if a portable backup was just restored, its
    // records are on disk as plaintext `.json`. The whole-file storage layer re-encrypts
    // each to `.json.enc` on next save; this observes and clears the restore marker.
    {
        let backup_restore_dir = if args.base_folder.is_empty() {
            std::path::PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .backup_restore,
            )
        } else {
            std::path::PathBuf::from(&args.base_folder).join(
                &bootstrap_config
                    .storage_paths
                    .backup_restore,
            )
        };
        tokio::task::block_in_place(|| {
            backup_restore::reencrypt::maybe_run_post_restore_reencrypt(&backup_restore_dir, &encryption);
        });
    }

    if !encryption.enabled {
        eprintln!("⚠ Encryption at rest is DISABLED - sensitive data will be stored in plain text");
    }

    // Resolve the optional OTLP exporter auth header from the secrets store
    // (requires encryption to be initialized, above).
    let otlp_auth_header = resolve_startup_otlp_auth(&bootstrap_config)
        .await
        .context("Failed to resolve OTLP exporter authentication")?;

    // Initialize logging
    // before this point consider using println
    let _guard: Option<WorkerGuard> = init_logging(&config, &bootstrap_config, otlp_auth_header)?;

    // Load resource-limit configuration into the process-global. Placed after
    // logging init so a missing/misconfigured path is visible. A missing or
    // malformed file leaves every dimension unconstrained (limit 1_000_000).
    crate::config::init_global_limits(crate::config::load_limits_config(
        &bootstrap_config
            .config_files
            .limits,
    ));

    // Emit boot status that was determined before logging was available, so it
    // lands in the persisted log rather than only on stderr.
    if let Some(active_version) = encryption_preflight_version {
        info!("✓ Encryption backend preflight passed (envelope version {active_version})");
    }
    if encryption.enabled {
        info!("✓ Encryption at rest ENABLED - whole-file storage encryption active");
    }

    // Initialize variable patterns from config for runtime use
    crate::storage::integration_trigger_handlers::set_variable_pattern(
        config
            .integration
            .variable_pattern
            .clone(),
    );
    crate::integrations::runtime_variables::set_variable_patterns(
        config
            .integration
            .variable_pattern
            .clone(),
        config
            .integration
            .custom_variable_prefix
            .clone(),
    );

    info!("Initialized variable patterns from config");

    // Boot the predefined Trust Check queries catalogue.
    let _ = crate::trust_registry_verification::predefined_queries::builtin_catalogue();
    info!("Initialized predefined Trust Check queries catalogue");

    // Override TLS paths with command line arguments if provided
    // Priority: command line args > bootstrap config
    let mut config = config;
    if let Some(cert) = args.cert {
        info!("Using TLS certificate from command line: {:?}", cert);
        config.tls.cert_path = cert;
    }

    if let Some(key) = args.key {
        info!("Using TLS key from command line: {:?}", key);
        config.tls.key_path = key;
    }

    // NOW load and cache x402 configuration (after logging is initialized)
    match bootstrap_config.load_x402_config() {
        Ok(x402_config) => {
            x402::set_x402_config(x402_config).await;
        }
        Err(e) => {
            warn!("Failed to load x402 configuration: {}", e);
            warn!("Payment verification may fail - x402 config not loaded");
        }
    }

    // Also cache x402 metadata (network/token information)
    match bootstrap_config.load_x402_metadata() {
        Ok(x402_metadata) => {
            x402::set_x402_metadata(x402_metadata).await;
        }
        Err(e) => {
            warn!("Failed to load x402 metadata: {}", e);
            warn!("Token symbols and decimals will not be available");
        }
    }

    // Load and cache X402 Proxy configuration (wallet/network config for fabric auto-pay)
    match crate::x402::proxy_config::load_x402_proxy_config(&bootstrap_config) {
        Ok(x402_proxy_config) => {
            crate::x402::proxy_config_cache::set_x402_proxy_config(x402_proxy_config).await;
        }
        Err(e) => {
            warn!("Failed to load X402 Proxy configuration: {}", e);
            warn!("Fabric auto-pay may not function - config not loaded");
        }
    }

    // Initialize gateway facilitator service for DIDComm-based payment verification
    x402::init_gateway_facilitator_service().await;
    info!("Gateway facilitator service initialized - ready for ATM infrastructure");

    // NOW load surfaces (after logging is initialized so errors are logged)
    // Only for "local" configuration source
    if bootstrap_config.channel_config_source == "local" {
        info!("Loading surfaces from local storage (after logging initialized)");
        match load_surfaces(&bootstrap_config).await {
            Ok(channels) => {
                info!("Successfully loaded {} surface(s)", channels.len());
                config.surfaces = channels;
            }
            Err(e) => {
                error!("Failed to load surfaces: {}", e);
                return Err(e.context("Failed to load surfaces from local storage"));
            }
        }
    }

    // Print ASCII art banner (always to terminal and logs)
    println!();
    println!("     _     __  __ _       _     _ _   _____               _     _____     _          _            ");
    println!("    / \\   / _|/ _(_)_ __ (_) __| (_) |_   _| __ _   _ ___| |_  |  ___|_ _| |__  _ __(_) ___       ");
    println!("   / _ \\ | |_| |_| | '_ \\| |/ _` | |   | || '__| | | / __| __| | |_ / _` | '_ \\| '__| |/ __|      ");
    println!("  / ___ \\|  _|  _| | | | | | (_| | |   | || |  | |_| \\__ \\ |_  |  _| (_| | |_) | |  | | (__       ");
    println!(
        " /_/ _ \\_\\_| |_| |_|_| |_|_|\\__,_|_|_  |_||_|   \\__,_|___/\\__|_|_|  \\__,_|_.__/|_|  |_|\\___|      "
    );
    println!("    / \\   __ _  ___ _ __ | |_  |_   _| __ _   _ ___| |_   / ___| __ _| |_ _____      ____ _ _   _ ");
    println!(
        "   / _ \\ / _` |/ _ \\ '_ \\| __|   | || '__| | | / __| __| | |  _ / _` | __/ _ \\ \\ /\\ / / _` | | | |"
    );
    println!("  / ___ \\ (_| |  __/ | | | |_    | || |  | |_| \\__ \\ |_  | |_| | (_| | ||  __|\\ V  V / (_| | |_| |");
    println!(
        " /_/   \\_\\__, |\\___|_| |_|\\__|   |_||_|   \\__,_|___/\\__|  \\____|\\__,_|\\__\\___| \\_/\\_/ \\__,_|\\__, |"
    );
    println!("         |___/                                                                              |___/ ");
    println!();

    println!("Starting Affinidi Trust Fabric Gateway");
    println!("Configuration: {}", config_path.display());

    info!("");
    info!("     _     __  __ _       _     _ _   _____               _     _____     _          _            ");
    info!("    / \\   / _|/ _(_)_ __ (_) __| (_) |_   _| __ _   _ ___| |_  |  ___|_ _| |__  _ __(_) ___       ");
    info!("   / _ \\ | |_| |_| | '_ \\| |/ _` | |   | || '__| | | / __| __| | |_ / _` | '_ \\| '__| |/ __|      ");
    info!("  / ___ \\|  _|  _| | | | | | (_| | |   | || |  | |_| \\__ \\ |_  |  _| (_| | |_) | |  | | (__       ");
    info!(" /_/ _ \\_\\_| |_| |_|_| |_|_|\\__,_|_|_  |_||_|   \\__,_|___/\\__|_|_|  \\__,_|_.__/|_|  |_|\\___|      ");
    info!("    / \\   __ _  ___ _ __ | |_  |_   _| __ _   _ ___| |_   / ___| __ _| |_ _____      ____ _ _   _ ");
    info!("   / _ \\ / _` |/ _ \\ '_ \\| __|   | || '__| | | / __| __| | |  _ / _` | __/ _ \\ \\ /\\ / / _` | | | |");
    info!("  / ___ \\ (_| |  __/ | | | |_    | || |  | |_| \\__ \\ |_  | |_| | (_| | ||  __|\\ V  V / (_| | |_| |");
    info!(
        " /_/   \\_\\__, |\\___|_| |_|\\__|   |_||_|   \\__,_|___/\\__|  \\____|\\__,_|\\__\\___| \\_/\\_/ \\__,_|\\__, |"
    );
    info!("         |___/                                                                              |___/ ");
    info!("");

    info!("Starting Affinidi Trust Fabric Gateway");
    info!("Configuration: {}", config_path.display());

    log_startup_configs(&bootstrap_config, &config);

    let active_count = config
        .surfaces
        .iter()
        .filter(|s| s.status == crate::config::agent_surface::SurfaceStatus::Active)
        .count();
    let disabled_count = config
        .surfaces
        .iter()
        .filter(|s| s.status == crate::config::agent_surface::SurfaceStatus::Disabled)
        .count();
    info!("Configured {} channel(s) ({} active, {} disabled)", config.surfaces.len(), active_count, disabled_count);
    for surface in config
        .surfaces
        .iter()
        .filter(|s| s.status == crate::config::agent_surface::SurfaceStatus::Active)
    {
        info!("  Channel '{}': {} -> {}", surface.name, surface.listen_address(), surface.target_endpoint());
    }

    // Validate configuration
    config
        .validate()
        .context("Configuration validation failed")?;

    // ── (Future) one-shot agent-identity `#key-2` migration — trigger point ──
    //
    // NOT implemented. This is only the place it would hook in; the work must
    // live inside `server::run_axum_proxy`'s orchestrator, where the identity
    // store (`base_path()` + `find_by_hash`) and the VC issuer actually exist —
    // `async_main` has neither yet.
    //
    // What caused the need:
    //   Agent-identity `did:webvh` birth logs (`{identities}/{uuid}/did.jsonl`)
    //   minted *before* the Multikey fix publish only `#key-1` (JsonWebKey2020).
    //   Agent VPs are signed under `#key-2` (`vp_issuer::DEFAULT_SIGNING_KEY_ID`,
    //   an Ed25519 Multikey). So when a *receiving* gateway resolves such a DID
    //   over `fabric`, it cannot find `#key-2` and verification fails with
    //   "could not find resource …#key-2" — the caller is marked unverified and
    //   its real DID never crosses the hop. (Same root cause produces a `404`
    //   when a record still resolves via `find_by_hash` but its `did.jsonl` was
    //   removed.)
    //
    // Why it is usually NOT needed:
    //   Every identity minted *after* the fix already carries `#key-2`, and a
    //   fresh or wiped `_storage/identities` never holds a stale log. Only a
    //   persistent store carried across the fix boundary is affected — i.e. an
    //   in-place prod/staging upgrade where wiping real, registered identities
    //   is not acceptable. Dev environments simply wipe the folder.
    //
    // What an implementation must do:
    //   scan each agent-identity `did.jsonl`, detect a missing / `key-1`-only
    //   log, re-mint through the `issue_or_get_credential` create path, and
    //   re-register the new DID in the trust registry. Note the DID necessarily
    //   changes (the SCID is content-derived from the birth entry), so TR
    //   re-registration is mandatory. Must be idempotent and run once per
    //   stale identity.

    // Run the Axum-based server (identity API is initialized inside if enabled)
    let result = server::run_axum_proxy(config.clone(), bootstrap_config.clone()).await;

    // Shutdown OpenTelemetry gracefully (check metrics.json config)
    // We reload to check if it was actually enabled
    if let Ok(metrics_cfg) = config::load_metrics_config(
        &bootstrap_config
            .config_files
            .metrics,
    ) && metrics_cfg
        .opentelemetry
        .enabled
    {
        info!("Shutting down OpenTelemetry");
        observability::shutdown_otel();
    }

    result
}

/// Load configuration from the specified source with fallback to last-known-good config
/// Channels are loaded from DynamoDB, while TLS, A2A, and logging configs come from bootstrap
async fn load_configuration(bootstrap: &BootstrapConfig) -> Result<GatewayConfig> {
    eprintln!("🔍 [CONFIG-LOAD] load_configuration called");
    eprintln!("🔍 [CONFIG-LOAD] channel_config_source = '{}'", bootstrap.channel_config_source);
    eprintln!(
        "🔍 [CONFIG-LOAD] agent surface storage path = '{}'",
        bootstrap
            .storage_paths
            .agent_surfaces
    );

    // Initialize config cache
    let config_cache = ConfigCache::new(
        &bootstrap
            .storage_paths
            .config_cache,
    );

    match bootstrap
        .channel_config_source
        .as_str()
    {
        "dynamodb" => {
            let table_name = bootstrap
                .dynamodb_table
                .as_ref()
                .context("DynamoDB table name not specified")?;

            info!("Loading channels from DynamoDB table: {}", table_name);

            // Try to load from DynamoDB first
            let dynamodb_result = async {
                let store = DynamoDbConfigStore::new(
                    table_name.clone(),
                    bootstrap.aws_region.clone(),
                    bootstrap.aws_profile.clone(),
                )
                .await?;

                // Load only channels from DynamoDB
                let mut config = store.load_config().await?;

                // Use TLS, A2A, logging, and extension inspection configs from bootstrap
                config.tls = bootstrap.tls.clone();
                config.a2a = bootstrap.a2a.clone();
                // Logging base (level, json, log_directory) comes from config.toml;
                // redaction rules come from gateway.json and are merged in below.
                let gw_redaction = config
                    .logging
                    .redaction
                    .clone();
                config.logging = bootstrap.logging.clone();
                config.logging.redaction = gw_redaction;
                config.extension_inspection = bootstrap
                    .extension_inspection
                    .clone();
                Ok::<GatewayConfig, anyhow::Error>(config)
            }
            .await;

            match dynamodb_result {
                Ok(mut config) => {
                    info!("Successfully loaded configuration from DynamoDB");

                    // Load x402 headers from x402.json
                    config.x402_headers = match bootstrap.load_x402_headers() {
                        Ok(headers) => headers,
                        Err(e) => {
                            warn!("Failed to load x402 headers from x402.json: {}, using defaults", e);
                            config::types::X402Headers::default()
                        }
                    };

                    // Load and cache full x402 configuration (including facilitator private keys)
                    // This prevents repeated disk I/O during payment verification
                    match bootstrap.load_x402_config() {
                        Ok(x402_config) => {
                            x402::set_x402_config(x402_config).await;
                            info!("x402 configuration loaded and cached successfully");
                        }
                        Err(e) => {
                            warn!("Failed to load x402 configuration: {}. Payment verification may fail.", e);
                        }
                    }

                    // Also cache x402 metadata (network/token information)
                    match bootstrap.load_x402_metadata() {
                        Ok(x402_metadata) => {
                            x402::set_x402_metadata(x402_metadata).await;
                            info!("x402 metadata loaded and cached successfully");
                        }
                        Err(e) => {
                            warn!("Failed to load x402 metadata: {}. Token symbols may not be available.", e);
                        }
                    }

                    // Save successful configuration to cache
                    if let Err(cache_error) = config_cache
                        .save(&config, "dynamodb")
                        .await
                    {
                        error!("Failed to cache configuration: {}", cache_error);
                        // Don't fail startup just because caching failed
                    }

                    Ok(config)
                }
                Err(dynamodb_error) => {
                    error!("Failed to load configuration from DynamoDB: {}", dynamodb_error);

                    // Try to load from cache as fallback
                    if config_cache.exists().await {
                        info!("Attempting to load last-known-good configuration from cache");

                        match config_cache.load().await {
                            Ok(cached) => {
                                warn!(
                                    "Using cached configuration from {} (cached at {})",
                                    cached.source, cached.cached_at
                                );

                                // Update bootstrap-specific configs even for cached config
                                let mut config = cached.config;
                                config.tls = bootstrap.tls.clone();
                                config.a2a = bootstrap.a2a.clone();
                                let gw_redaction = config
                                    .logging
                                    .redaction
                                    .clone();
                                config.logging = bootstrap.logging.clone();
                                config.logging.redaction = gw_redaction;
                                config.extension_inspection = bootstrap
                                    .extension_inspection
                                    .clone();

                                // Load x402 headers from x402.json
                                config.x402_headers = match bootstrap.load_x402_headers() {
                                    Ok(headers) => headers,
                                    Err(e) => {
                                        warn!("Failed to load x402 headers from x402.json: {}, using defaults", e);
                                        config::types::X402Headers::default()
                                    }
                                };

                                // Load and cache full x402 configuration (including facilitator private keys)
                                match bootstrap.load_x402_config() {
                                    Ok(x402_config) => {
                                        x402::set_x402_config(x402_config).await;
                                        info!("x402 configuration loaded and cached successfully");
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Failed to load x402 configuration: {}. Payment verification may fail.",
                                            e
                                        );
                                    }
                                }

                                // Also cache x402 metadata (network/token information)
                                match bootstrap.load_x402_metadata() {
                                    Ok(x402_metadata) => {
                                        x402::set_x402_metadata(x402_metadata).await;
                                        info!("x402 metadata loaded and cached successfully");
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Failed to load x402 metadata: {}. Token symbols may not be available.",
                                            e
                                        );
                                    }
                                }

                                Ok(config)
                            }
                            Err(cache_error) => {
                                error!("Failed to load cached configuration: {}", cache_error);
                                Err(dynamodb_error.context("DynamoDB load failed and no valid cache available"))
                            }
                        }
                    } else {
                        error!("No cached configuration available for fallback");
                        Err(dynamodb_error.context("DynamoDB load failed and no cache exists"))
                    }
                }
            }
        }
        "local" => {
            eprintln!("🔍 [CONFIG-LOAD] Taking LOCAL branch");
            eprintln!("[V8]");
            eprintln!("🔍 [CONFIG-LOAD] Deferring channel loading until after logging is initialized");

            // Load network config to get integration configuration
            let network_config_path = &bootstrap.config_files.gateway;
            let network_config = config::NetworkConfig::load_from_file(network_config_path)
                .context("Failed to load network config for integration configuration")?;

            // Create configuration with EMPTY channels (will be loaded after logging is initialized)
            // Logging base (level, json, log_directory) comes from config.toml;
            // redaction rules come from gateway.json.
            let mut logging = bootstrap.logging.clone();
            if let Some(gw_logging) = &network_config.logging {
                logging.redaction = gw_logging.redaction.clone();
            }

            let mut config = GatewayConfig {
                surfaces: Vec::new(), // Empty for now
                tls: bootstrap.tls.clone(),
                a2a: bootstrap.a2a.clone(),
                mcp: bootstrap.mcp.clone(),
                logging,
                extension_inspection: bootstrap
                    .extension_inspection
                    .clone(),
                integration: network_config.integration,
                facilitator_mode: network_config
                    .facilitator_mode
                    .unwrap_or_default(),
                x402_headers: config::types::X402Headers::default(), // Will be loaded next
            };

            // Load x402 headers from x402.json
            config.x402_headers = match bootstrap.load_x402_headers() {
                Ok(headers) => headers,
                Err(e) => {
                    warn!("Failed to load x402 headers from x402.json: {}, using defaults", e);
                    config::types::X402Headers::default()
                }
            };

            // NOTE: x402 config cache population moved to main() after logging is initialized
            // This ensures log messages appear in the log file

            info!("Local configuration loaded successfully");
            Ok(config)
        }
        other => {
            anyhow::bail!("Unsupported configuration source: {}", other)
        }
    }
}

fn log_startup_configs(
    bootstrap_config: &BootstrapConfig,
    gateway_config: &GatewayConfig,
) {
    info!("Startup bootstrap config:\n{:#?}", bootstrap_config);
    info!("Startup effective gateway config:\n{:#?}", gateway_config);
}

/// Load surfaces from storage (called AFTER logging is initialized)
async fn load_surfaces(bootstrap: &BootstrapConfig) -> Result<Vec<crate::config::agent_surface::AgentSurface>> {
    info!(
        "🔍 [SURFACE-LOAD] Loading surfaces from: {}",
        bootstrap
            .storage_paths
            .agent_surfaces
    );

    let store = surfaces::FileSystemAgentSurfaceStore::new(PathBuf::from(
        &bootstrap
            .storage_paths
            .agent_surfaces,
    ))
    .await?;

    let mut channels = surfaces::AgentSurfaceStore::list_all(&store)
        .await
        .context("Failed to load surfaces from storage")?;

    // list_all iterates a hash-map cache, so its order is non-deterministic;
    // sort so duplicate-route precedence stays stable across restarts.
    channels.sort_by(|a, b| {
        a.surface_id
            .cmp(&b.surface_id)
    });

    let network_config = bootstrap
        .load_network_config()
        .context("Failed to load network config for duplicate-route detection")?;
    disable_duplicate_route_surfaces(&store, &mut channels, &network_config).await?;
    surfaces::strip_unsupported_header_metadata_mappings(&store, &mut channels).await?;
    surfaces::carry_over_a2a_settings(&store, &mut channels, surfaces::RetiredA2aSwitches::read(bootstrap).await)
        .await?;

    info!("✅ Loaded {} surface(s) from local storage", channels.len());

    Ok(channels)
}

/// Auto-disable surfaces whose access-point `(port, route)` claim duplicates
/// an earlier-loaded active surface, persisting the new status to storage.
///
/// Duplicates can only reach disk by bypassing the API (hand-edited files,
/// restores); refusing to boot over them would lock the operator out of the
/// very UI needed to resolve the conflict. Instead the first copy in
/// `surface_id` order — the one runtime routing would serve — stays active
/// deterministically across restarts, later copies are
/// disabled and show up as such in the UI, and `ProxyConfig::validate`'s
/// duplicate check (which ignores disabled surfaces) then passes. Re-enabling
/// a disabled copy goes through full save-time validation, so the conflict
/// cannot be reintroduced silently.
///
/// Claims are keyed by **resolved listener port** (the orchestrator's
/// `channels_by_port` grouping uses the same unrestricted `map_url_to_port`
/// resolver), so different address strings that alias the same listener are
/// still duplicates. Addresses that resolve to no listener fall back to the
/// raw string, which still catches literal copies.
async fn disable_duplicate_route_surfaces(
    store: &surfaces::FileSystemAgentSurfaceStore,
    channels: &mut [crate::config::agent_surface::AgentSurface],
    network_config: &config::NetworkConfig,
) -> Result<()> {
    let mut seen_route_port_combos = std::collections::HashSet::new();
    for surface in channels.iter_mut() {
        if surface.status == crate::config::agent_surface::SurfaceStatus::Disabled {
            continue;
        }
        let listen_address = surface.listen_address();
        let route = surface.route();
        let listener = match network_config.map_url_to_port(listen_address) {
            Some(port) => format!("port {}", port),
            None => format!("address '{}'", listen_address),
        };
        let normalized_route = if route.starts_with('/') {
            route.to_string()
        } else {
            format!("/{}", route)
        };
        let combo = format!("{}:{}", listener, normalized_route);
        if !seen_route_port_combos.insert(combo.clone()) {
            error!(
                surface = %surface.name,
                surface_id = %surface.surface_id,
                combo = %combo,
                "Duplicate access-point route+port found in storage — auto-disabling this surface so the gateway can boot; \
                 resolve the conflict and re-enable it via the UI or API"
            );
            surface.status = crate::config::agent_surface::SurfaceStatus::Disabled;
            surfaces::AgentSurfaceStore::save(store, surface)
                .await
                .with_context(|| {
                    format!("Failed to persist auto-disable for duplicated surface '{}'", surface.surface_id)
                })?;
        }
    }
    Ok(())
}

/// Resolve the optional OTLP exporter auth header from the secrets store.
///
/// Returns `Ok(None)` when OpenTelemetry is disabled, the metrics config cannot
/// be loaded, or no auth is configured. Returns an error (fail-fast) when auth
/// is configured but the referenced secret cannot be read, so the gateway does
/// not silently export telemetry unauthenticated.
async fn resolve_startup_otlp_auth(bootstrap_config: &config::BootstrapConfig) -> Result<Option<(String, String)>> {
    let metrics_config = match config::load_metrics_config(
        &bootstrap_config
            .config_files
            .metrics,
    ) {
        Ok(cfg) => cfg,
        Err(_) => return Ok(None),
    };

    if !metrics_config
        .opentelemetry
        .enabled
    {
        return Ok(None);
    }

    let Some(auth) = metrics_config
        .opentelemetry
        .auth
        .as_ref()
    else {
        return Ok(None);
    };

    let backend = match bootstrap_config
        .secrets_backend
        .as_str()
    {
        "aws" => secrets::SecretsBackend::Aws,
        _ => secrets::SecretsBackend::Filesystem,
    };
    let store = secrets::create_secrets_store(
        backend,
        Some(
            bootstrap_config
                .storage_paths
                .secrets
                .clone(),
        ),
    )
    .await
    .context("Failed to initialize secrets store for OTLP auth resolution")?;

    let header = config::metrics_config::resolve_otel_auth_header(auth, &store).await?;
    Ok(Some(header))
}

/// Initialize the logging subsystem
fn init_logging(
    config: &GatewayConfig,
    bootstrap_config: &config::BootstrapConfig,
    otlp_auth_header: Option<(String, String)>,
) -> Result<Option<WorkerGuard>> {
    let mut guard = None;

    let max_level = match Level::from_str(config.logging.level.as_str()) {
        Ok(level) => level,
        Err(e) => anyhow::bail!("Cannot parse log level: {}", e),
    };

    // Build the log redactor from gateway.json config (compiled once, shared via Arc)
    let redactor = observability::LogRedactor::from_config(&config.logging.redaction);
    // Capture the redactor for hot-reload up front, even if OpenTelemetry starts
    // disabled, so a later enable-via-reload applies the configured span
    // redaction instead of the default (which would leak matched values).
    observability::set_reload_redactor(redactor.clone());
    if !redactor.is_empty() {
        eprintln!(
            "✅ Log redaction enabled with {} rule(s)",
            config
                .logging
                .redaction
                .rules
                .len()
        );
    }

    // Load metrics configuration from metrics.json
    let metrics_config = match config::load_metrics_config(
        &bootstrap_config
            .config_files
            .metrics,
    ) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!(
                "⚠️  Failed to load metrics config from {}: {}",
                bootstrap_config
                    .config_files
                    .metrics,
                e
            );
            eprintln!("⚠️  Continuing with OpenTelemetry disabled");
            // Create default config with everything disabled
            config::MetricsConfig {
                opentelemetry: config::OpenTelemetryConfig {
                    enabled: false,
                    endpoint: "http://localhost:4317".to_string(),
                    protocol: config::metrics_config::OtlpProtocol::default(),
                    auth: None,
                    service_name: env!("CARGO_PKG_NAME").to_string(),
                    environment: "development".to_string(),
                    traces: config::metrics_config::TracesConfig {
                        enabled: false,
                        sample_rate: 1.0,
                        target_crates: vec!["agent_gateway".to_string()],
                        record_caller_identity: false,
                    },
                    metrics: config::MetricsExportConfig {
                        enabled: false,
                        export_interval_seconds: 60,
                        batch_max_queue_size: None,
                        batch_scheduled_delay_ms: None,
                        batch_max_export_size: None,
                    },
                    logs: config::metrics_config::LogsConfig { enabled: false },
                },
                cloudwatch: config::metrics_config::CloudWatchMetricConfig {
                    enabled: false,
                    region: Some("us-east-1".to_string()),
                    namespace: "AgentGateway".to_string(),
                    dimensions: None,
                },
                retention: config::RetentionConfig::default(),
                advanced: config::AdvancedConfig::default(),
            }
        }
    };

    // Wire the opt-in caller-identity span attribute toggle (default off).
    observability::set_record_caller_identity(
        metrics_config
            .opentelemetry
            .traces
            .record_caller_identity,
    );

    // Initialize OpenTelemetry providers if enabled. The trace + log layers are
    // installed as reloadable layers below, so a config save can swap them in
    // place without restarting the process.
    let otel_trace_provider = if metrics_config
        .opentelemetry
        .enabled
    {
        let mut otel_config = observability::OtelConfig::from(&metrics_config.opentelemetry);
        otel_config.auth_header = otlp_auth_header;

        let tracer_provider = match observability::init_tracer(&otel_config, redactor.clone()) {
            Ok(provider) => Some(provider),
            Err(e) => {
                eprintln!("⚠️  Failed to initialize OpenTelemetry tracer: {}", e);
                None
            }
        };

        if let Err(e) = observability::init_metrics(&otel_config) {
            eprintln!("⚠️  Failed to initialize OpenTelemetry metrics: {}", e);
        }

        if metrics_config
            .opentelemetry
            .logs
            .enabled
            && let Err(e) = observability::init_logs(&otel_config)
        {
            eprintln!("⚠️  Failed to initialize OpenTelemetry logs: {}", e);
        }

        tracer_provider
    } else {
        None
    };

    // Build the initial reloadable OTEL layers (real when enabled, else no-op)
    // and install them first in the subscriber so they can be hot-swapped by a
    // later config save via `observability::reload_otel`.
    let initial_trace_layer = match &otel_trace_provider {
        Some(provider) => observability::build_trace_layer_boxed(
            provider,
            &metrics_config
                .opentelemetry
                .service_name,
        ),
        None => observability::noop_layer_boxed(),
    };
    let initial_log_layer = match observability::get_logger_provider() {
        Some(provider) => observability::build_log_layer_boxed(provider),
        None => observability::noop_layer_boxed(),
    };

    // Assemble the subscriber from a single vec of boxed layers so every logging
    // mode shares one code path and the OTEL layers stay swappable.
    let mut layers: Vec<observability::BoxedLayer> = vec![
        observability::install_trace_reload(
            initial_trace_layer,
            metrics_config
                .opentelemetry
                .traces
                .target_crates
                .clone(),
        ),
        observability::install_log_reload(initial_log_layer, max_level),
        observability::WebSocketLogLayer::new().boxed(),
    ];

    if config.logging.json {
        if let Some(log_dir) = &config.logging.log_directory {
            let (none_blocking, worker_guard) = tracing_appender::non_blocking(tracing_appender::rolling::never(
                Path::new(log_dir),
                "agent-gateway.log",
            ));
            guard = Some(worker_guard);

            layers.push(
                tracing_subscriber::fmt::Layer::new()
                    .json()
                    .flatten_event(false)
                    .with_writer(
                        observability::RedactingMakeWriter::new(none_blocking, redactor.clone())
                            .with_max_level(max_level),
                    )
                    .with_ansi(false)
                    .with_target(false)
                    .with_span_events(FmtSpan::NONE)
                    .with_span_list(false)
                    .boxed(),
            );
        }

        layers.push(
            tracing_subscriber::fmt::Layer::new()
                .json()
                .flatten_event(false)
                .with_writer(
                    observability::RedactingMakeWriter::new(io::stderr, redactor.clone()).with_max_level(max_level),
                )
                .with_ansi(true)
                .with_target(false)
                .with_span_events(FmtSpan::NONE)
                .with_span_list(false)
                .boxed(),
        );
    } else {
        if let Some(log_dir) = &config.logging.log_directory {
            let (none_blocking, worker_guard) = tracing_appender::non_blocking(tracing_appender::rolling::never(
                Path::new(log_dir),
                "agent-gateway.log",
            ));
            guard = Some(worker_guard);

            layers.push(
                tracing_subscriber::fmt::Layer::new()
                    .event_format(observability::SimpleFormat)
                    .with_writer(
                        observability::RedactingMakeWriter::new(none_blocking, redactor.clone())
                            .with_max_level(max_level),
                    )
                    .with_ansi(false)
                    .boxed(),
            );
        }

        layers.push(
            tracing_subscriber::fmt::Layer::new()
                .event_format(observability::SimpleFormat)
                .with_writer(
                    observability::RedactingMakeWriter::new(io::stderr, redactor.clone()).with_max_level(max_level),
                )
                .with_ansi(true)
                .boxed(),
        );
    }

    tracing_subscriber::registry()
        .with(layers)
        .init();

    Ok(guard)
}

/// Generate a default bootstrap configuration file
fn generate_default_bootstrap(
    base_folder: &str,
    cors_origins: &str,
) -> Result<()> {
    let toml_str = render_default_bootstrap_toml(base_folder, cors_origins)?;

    println!("# Affinidi Fabric Affinidi Trust Fabric Gateway Bootstrap Configuration File\n");
    println!("# This file contains local configuration (TLS, A2A, logging)");
    println!("# and specifies where to load channels from (DynamoDB)\n");
    println!("{}", toml_str);

    println!("\n# Save this to config.toml and run:");
    println!("# agent-gateway --config config.toml");

    Ok(())
}

fn render_default_bootstrap_toml(
    base_folder: &str,
    cors_origins: &str,
) -> Result<String> {
    let base_folder_prefix = if base_folder.is_empty() {
        "".to_string()
    } else if base_folder.ends_with('/') {
        base_folder.to_string()
    } else {
        format!("{}/", base_folder)
    };
    let logging = config::LoggingConfig {
        log_directory: Some(format!("{}_storage/logs", base_folder_prefix)),
        ..config::LoggingConfig::default()
    };
    let did_cache = config::types::DIDCacheBootstrapConfig {
        storage_path: format!("{}_storage/did_cache", base_folder_prefix),
        ..config::types::DIDCacheBootstrapConfig::default()
    };
    // CORS origins are now configured in network_config.cors (handled separately)
    let _ = cors_origins; // Suppress unused variable warning

    let config = BootstrapConfig {
        channel_config_source: "local".to_string(),
        dynamodb_table: Some("trust-proxy-configuration".to_string()),
        aws_region: None,
        aws_profile: None,
        encryption: config::EncryptionConfig::default(),
        tls: config::TlsConfig {
            cert_path: PathBuf::from(format!("{}certs/cert.pem", base_folder_prefix)),
            key_path: PathBuf::from(format!("{}certs/key.pem", base_folder_prefix)),
            verify_upstream: true,
            client_auth: Default::default(),
        },
        a2a: config::A2aConfig::default(),
        mcp: config::McpConfig::default(),
        oob_connection: config::OobConnectionConfig::default(),
        reconnect_policy: config::ReconnectPolicyConfig::default(),
        logging,
        extension_inspection: config::ExtensionInspectionConfig::default(),
        config_files: config::types::ConfigFilePaths {
            // let's keep configs relative to config.tom
            gateway: "gateway.json".to_string(),
            metrics: "metrics.json".to_string(),
            rbac: "rbac.json".to_string(),
            limits: "limits.json".to_string(),
            saml: "saml.json".to_string(),
            x402: "x402.json".to_string(),
            x402_proxy: "x402-proxy.json".to_string(),
            test_endpoints: "config/test-endpoints.json".to_string(),
            agent_surface_templates_dir: "agent_surface_templates".to_string(),
        },
        storage_paths: config::StoragePaths {
            config_cache: format!("{}_storage/cache", base_folder_prefix),
            settings: format!("{}_storage/settings", base_folder_prefix),
            notifications: format!("{}_storage/notifications", base_folder_prefix),
            notification_templates: format!("{}_storage/notifications/templates", base_folder_prefix),
            connection_points: format!("{}_storage/connection_points", base_folder_prefix),
            secrets: format!("{}_storage/secrets", base_folder_prefix),
            apikeys: format!("{}_storage/apikeys", base_folder_prefix),
            certificates: format!("{}_storage/certificates", base_folder_prefix),
            mcp_proxies: format!("{}_storage/mcp_proxies", base_folder_prefix),
            a2a_proxies: format!("{}_storage/a2a_proxies", base_folder_prefix),
            integrations: format!("{}_storage/integrations/definitions", base_folder_prefix),
            integration_triggers: format!("{}_storage/integrations/triggers", base_folder_prefix),
            webhooks: format!("{}_storage/webhooks", base_folder_prefix),
            vc_keys: format!("{}_storage/vc_keys", base_folder_prefix),
            metrics: format!("{}_storage/metrics", base_folder_prefix),
            passkeys: format!("{}_storage/passkeys", base_folder_prefix),
            terms: format!("{}_storage/terms", base_folder_prefix),
            avatars: format!("{}_storage/avatars", base_folder_prefix),
            identities: format!("{}_storage/identities", base_folder_prefix),
            gateways: format!("{}_storage/gateways", base_folder_prefix),
            mediators: format!("{}_storage/mediators", base_folder_prefix),
            trust_registries: format!("{}_storage/trust_registries", base_folder_prefix),
            messages: format!("{}_storage/messages", base_folder_prefix),
            x402_transactions: format!("{}_storage/x402_transactions", base_folder_prefix),
            mpp_transactions: format!("{}_storage/mpp_transactions", base_folder_prefix),
            sessions: format!("{}_storage/sessions", base_folder_prefix),
            system_metrics: format!("{}_storage/system_metrics", base_folder_prefix),
            policy_definitions: format!("{}_storage/policy_definitions", base_folder_prefix),
            global_policies: format!("{}_storage/global_policies", base_folder_prefix),
            issuers: format!("{}_storage/issuers", base_folder_prefix),
            authorities: format!("{}_storage/authorities", base_folder_prefix),
            credential_providers: format!("{}_storage/credential_providers", base_folder_prefix),
            delegation_vault: format!("{}_storage/delegation_vault", base_folder_prefix),
            agent_surfaces: format!("{}_storage/agent_surfaces", base_folder_prefix),
            agent_surface_templates: format!("{}_storage/agent_surface_templates", base_folder_prefix),
            backup_restore: format!("{}_backup_restore", base_folder_prefix),
            identity_hash_pepper: format!("{}_storage/identity_hash_pepper", base_folder_prefix),
        },
        secrets_backend: "filesystem".to_string(),
        rbac: crate::rbac::RbacConfig::default(),
        did_cache,
        metrics_cache_ttl_seconds: 1,
        websocket_require_auth: true,
        session_timeout_minutes: 20,
        websocket_broadcast_buffer: 500,
        metrics_retention_minutes: 360,
        metrics_cache_ttl_seconds_legacy: 1,
        auth_mode: crate::auth::AuthMode::default(),
        // The backup key is required at runtime; generated configs reference an env var
        // (nothing secret committed). Local dev supplies it via the Makefile / config-certs.
        backup_encryption_key: "env://AG_BACKUP_ENCRYPTION_KEY".to_string(),
        legacy_backup_encryption_keys: None,
        trust_registry: Default::default(),
        tenancy: Default::default(),
        config_dir: None,
        server_mode: crate::server::mode::ServerMode::default(),
        cache_refresh_interval_secs: 0,
    };
    let toml_str = toml::to_string_pretty(&config)?;
    Ok(toml_str)
}

#[cfg(test)]
mod bootstrap_render_tests {
    use super::render_default_bootstrap_toml;

    #[test]
    fn generated_bootstrap_omits_optional_mcp_and_fabric_stream_settings() {
        let toml = render_default_bootstrap_toml("", "").expect("bootstrap toml should render");

        assert!(toml.contains("\n[a2a]\n"));
        assert!(toml.contains("\n[mcp]\n"));
        for key in ["fabric_stream_max_envelope_bytes", "continuations", "mcp_issuer", "mcp_replay"] {
            assert!(!toml.contains(key), "generated bootstrap must not contain {key}");
        }
        let config: crate::config::BootstrapConfig = toml::from_str(&toml).expect("generated bootstrap must parse");
        assert_eq!(config.a2a.validate(), Ok(()));
    }
}

#[cfg(test)]
mod duplicate_route_surface_tests {
    use super::*;
    use crate::config::agent_surface::{AgentSurface, SurfaceStatus};

    fn network_config() -> config::NetworkConfig {
        serde_json::from_value(serde_json::json!({
            "did": { "domain": "test.local" },
            "webauthn": { "rp_id": "localhost", "external_origin": "https://localhost" },
            "integration": { "types": [], "categories": [] },
            "listeners": [],
            "routes": {},
        }))
        .expect("test network config should deserialize")
    }

    fn surface(
        id: &str,
        route: &str,
    ) -> AgentSurface {
        serde_json::from_value(serde_json::json!({
            "surface_id": id,
            "name": id,
            "access_point": {"listen_address": "0.0.0.0:8443", "route": route, "protocol": "a2a"},
            "target": {"endpoint": "http://upstream"}
        }))
        .expect("test surface should deserialize")
    }

    async fn test_store(dir: &std::path::Path) -> surfaces::FileSystemAgentSurfaceStore {
        surfaces::FileSystemAgentSurfaceStore::new(dir.to_path_buf())
            .await
            .expect("test store should initialize")
    }

    #[tokio::test]
    async fn test_disable_duplicate_route_surfaces_later_copy_disabled_and_persisted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let mut channels = vec![surface("s-a", "/api"), surface("s-b", "/api")];

        disable_duplicate_route_surfaces(&store, &mut channels, &network_config())
            .await
            .expect("dedup should succeed");

        assert_eq!(channels[0].status, SurfaceStatus::Active);
        assert_eq!(channels[1].status, SurfaceStatus::Disabled);

        let persisted = surfaces::AgentSurfaceStore::get(&store, "s-b")
            .await
            .expect("get should succeed");
        match persisted {
            Some(s) => assert_eq!(s.status, SurfaceStatus::Disabled),
            None => panic!("auto-disabled surface 's-b' must be persisted to the store"),
        }
    }

    #[tokio::test]
    async fn test_disable_duplicate_route_surfaces_sorted_order_is_deterministic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        // Reverse insertion order; the sort in load_surfaces must make
        // the lowest surface_id win regardless.
        let mut channels = vec![surface("s-b", "/api"), surface("s-a", "/api")];
        channels.sort_by(|a, b| {
            a.surface_id
                .cmp(&b.surface_id)
        });

        disable_duplicate_route_surfaces(&store, &mut channels, &network_config())
            .await
            .expect("dedup should succeed");

        assert_eq!(channels[0].surface_id, "s-a");
        assert_eq!(channels[0].status, SurfaceStatus::Active);
        assert_eq!(channels[1].surface_id, "s-b");
        assert_eq!(channels[1].status, SurfaceStatus::Disabled);
    }

    #[tokio::test]
    async fn test_disable_duplicate_route_surfaces_distinct_routes_unchanged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let mut channels = vec![surface("s-a", "/api"), surface("s-b", "/other")];

        disable_duplicate_route_surfaces(&store, &mut channels, &network_config())
            .await
            .expect("dedup should succeed");

        assert!(
            channels
                .iter()
                .all(|s| s.status == SurfaceStatus::Active),
            "distinct routes must not be disabled"
        );
    }

    #[tokio::test]
    async fn test_disable_duplicate_route_surfaces_disabled_surface_claims_no_route() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let mut disabled = surface("s-a", "/api");
        disabled.status = SurfaceStatus::Disabled;
        let mut channels = vec![disabled, surface("s-b", "/api")];

        disable_duplicate_route_surfaces(&store, &mut channels, &network_config())
            .await
            .expect("dedup should succeed");

        assert_eq!(channels[0].status, SurfaceStatus::Disabled);
        assert_eq!(channels[1].status, SurfaceStatus::Active, "an already-disabled surface must not claim the route");
    }
}
