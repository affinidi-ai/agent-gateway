//! The management API router built by `create_identity_api_router` over temporary storage, so a
//! test can send requests to the router the gateway serves rather than to a hand-assembled copy.
//!
//! Every store whose presence decides whether a group of routes is mounted is wired. The SAML
//! state, the secrets store, the trust registry listener manager and worker, the MCP replay
//! cache and several optional fields of the identity and dashboard states are `None`. Of those
//! only the SAML state changes which routes exist; the others change what the handlers find.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use axum::Router;
use chrono::Utc;
use serde_json::json;
use tempfile::TempDir;

use crate::access_tokens::store::hash_secret;
use crate::access_tokens::{AccessToken, FsAccessTokenStore, generate_token};
use crate::auth::AuthState;
use crate::auth::storage::UserData;
use crate::auth::types::{UserRole, UserStatus};
use crate::auth_manager::middleware::RbacGuard;
use crate::config::{BootstrapConfig, GatewayConfig, NetworkConfig};
use crate::integrations::FileSystemNotificationStore;
use crate::integrations::definitions::{DefinitionStores, definition_stores, init_definition_stores};
use crate::rbac::RbacConfig;
use crate::terms::TermsManager;

const BOOTSTRAP_TOML: &str = r#"
backup_encryption_key = "unused"

[tls]
cert_path = "cert.pem"
key_path = "key.pem"

[logging]
log_directory = "logs"
"#;

const TEST_MODE: &str = "AG_TEST_MODE";

/// Whether the calling test should build its router in this process. `AG_TEST_MODE` from a
/// developer's shell would mount the debug-only test sign-in route, so the test then runs again
/// in a child process without it, and this answers false once that run has passed.
pub(crate) fn runs_without_test_mode() -> bool {
    std::env::var_os(TEST_MODE).is_none()
        || crate::a2a::version::run_isolated_from_other_tests_with_env(&[], &[TEST_MODE])
}

pub(crate) struct ManagementApi {
    pub(crate) router: Router,
    pub(crate) log_directory: PathBuf,
    auth: Option<Arc<AuthState>>,
    access_tokens: Arc<FsAccessTokenStore>,
    _storage: TempDir,
    _issuer_storage: TempDir,
    _listener_issuer_storage: TempDir,
}

impl ManagementApi {
    /// The router behind a passkey auth backend whose permission map is `rbac`. Build it only
    /// where [`runs_without_test_mode`] holds, so the debug-only test sign-in route is absent.
    pub(crate) async fn with_auth_backend(rbac: RbacConfig) -> Self {
        assert!(
            std::env::var_os(TEST_MODE).is_none(),
            "{TEST_MODE} is set; start the test with runs_without_test_mode"
        );
        Self::build(rbac, true).await
    }

    /// The router as built when neither a passkey nor a SAML backend is configured.
    pub(crate) async fn without_auth_backend() -> Self {
        Self::build(RbacConfig::default(), false).await
    }

    /// A session for a new approved user with `role`.
    pub(crate) async fn session(
        &self,
        role: UserRole,
    ) -> String {
        let auth = self.auth_state();
        let user_id = self.approved_user(role).await;
        auth.session_manager
            .create_session(user_id.clone(), user_id)
            .await
    }

    /// The secret of an access token held by a new approved user with `role` and limited to
    /// `scopes`.
    pub(crate) async fn access_token(
        &self,
        role: UserRole,
        scopes: &[&str],
    ) -> String {
        let user_id = self.approved_user(role).await;
        let (id, secret) = generate_token();
        self.access_tokens
            .create(AccessToken {
                id,
                name: "management api token".to_string(),
                description: String::new(),
                token_hash: hash_secret(&secret),
                user_id: user_id.clone(),
                scopes: scopes
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                resource_pattern: None,
                required_headers: Vec::new(),
                created_by: user_id,
                parent_token_id: None,
                delegation_depth: 0,
                created_at: Utc::now(),
                last_used_at: None,
                expires_at: None,
                revoked_at: None,
                rotation_generation: 0,
                rotated_at: None,
                rotated_by: None,
            })
            .await
            .expect("access token");
        secret
    }

    fn auth_state(&self) -> &Arc<AuthState> {
        self.auth
            .as_ref()
            .expect("the router was built with an auth backend")
    }

    async fn approved_user(
        &self,
        role: UserRole,
    ) -> String {
        let user_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();
        self.auth_state()
            .storage
            .save_user(&UserData {
                user_id: user_id.clone(),
                username: user_id.clone(),
                passkeys: Vec::new(),
                role,
                status: UserStatus::Approved,
                is_primary: false,
                first_name: None,
                last_name: None,
                email: None,
                department: None,
                job_title: None,
                avatar_path: None,
                created_at: now,
                updated_at: now,
                last_logged_in: None,
                saml_id: None,
            })
            .await
            .expect("save user");
        user_id
    }

    async fn build(
        rbac: RbacConfig,
        with_auth_backend: bool,
    ) -> Self {
        super::ensure_rustls();
        ensure_integration_definition_stores().await;
        let storage = tempfile::tempdir().expect("tempdir");
        let root = storage.path();
        let config_directory = root.join("config");
        std::fs::create_dir_all(&config_directory).expect("config directory");
        let config_path = config_directory.join("config.toml");
        std::fs::write(&config_path, BOOTSTRAP_TOML).expect("bootstrap config");
        let bootstrap = Arc::new(BootstrapConfig::from_file(&config_path).expect("bootstrap"));
        let paths = bootstrap
            .storage_paths
            .clone();
        let log_directory = PathBuf::from(
            bootstrap
                .logging
                .log_directory
                .clone()
                .expect("log directory"),
        );
        std::fs::create_dir_all(&log_directory).expect("log directory");

        let config = Arc::new(GatewayConfig::default_config());
        let network_config: Arc<NetworkConfig> = Arc::new(
            serde_json::from_value(json!({
                "did": { "domain": "test.local" },
                "webauthn": { "rp_id": "localhost", "external_origin": "https://localhost" },
                "integration": { "types": [], "categories": [] },
                "listeners": [],
                "routes": {},
            }))
            .expect("network config"),
        );
        let rbac = Arc::new(rbac);
        let terms_manager = Arc::new(TermsManager::disabled());
        let (vc_issuer, issuer_storage) = crate::identity::test_helpers::test_vc_issuer().await;
        let vc_issuer = Arc::new(vc_issuer);
        let ws_state = Arc::new(crate::server::WsState::new(16));
        let settings_store = Arc::new(crate::storage::SettingsStore::new(&paths.settings));
        let metrics_store = Arc::new(crate::metrics::MetricsStore::new(100));
        let channel_manager = Arc::new(crate::proxy::SurfaceTaskManager::new(
            config.clone(),
            bootstrap.clone(),
            Arc::new(crate::storage::ConfigCache::new(root.join("config_cache"))),
            None,
            None,
            None,
            settings_store.clone(),
            Arc::new(crate::didauth::DidAuthSessionStore::new()),
        ));
        let auth = if with_auth_backend {
            Some(Arc::new(
                AuthState::new(
                    "localhost".to_string(),
                    url::Url::parse("https://localhost").expect("origin"),
                    paths.passkeys.clone(),
                    paths.avatars.clone(),
                    20,
                    paths.sessions.clone(),
                    terms_manager.clone(),
                )
                .await
                .expect("auth state"),
            ))
        } else {
            None
        };
        let rbac_guard = auth
            .as_ref()
            .map(|auth| RbacGuard::new(auth.storage.clone(), rbac.clone()));
        let notification_store = Arc::new(
            FileSystemNotificationStore::new(
                (&paths.notifications).into(),
                (&paths.notification_templates).into(),
                None,
            )
            .await
            .expect("notification store"),
        );
        let access_tokens = Arc::new(
            FsAccessTokenStore::new(root.join("access_tokens"))
                .await
                .expect("access token store"),
        );

        let gateway_store = Arc::new(
            crate::gateways::FileSystemGatewayStore::new(root.join("gateways"), None)
                .await
                .expect("gateway store"),
        );
        let mediator_store = Arc::new(
            crate::mediators::FileSystemMediatorStore::new(root.join("mediators"))
                .await
                .expect("mediator store"),
        );
        let trust_registry_store = Arc::new(
            crate::trust_registries::FileSystemTrustRegistryStore::new(root.join("trust_registries"))
                .await
                .expect("trust registry store"),
        );
        let mcp_proxy_store = Arc::new(
            crate::mcp_proxies::FileSystemMcpProxyStore::new(root.join("mcp_proxies"))
                .await
                .expect("mcp proxy store"),
        );
        let a2a_proxy_store = Arc::new(
            crate::a2a_proxies::FileSystemA2aProxyStore::new(root.join("a2a_proxies"))
                .await
                .expect("a2a proxy store"),
        );
        let connection_point_store = Arc::new(
            crate::gateways::FileSystemConnectionPointStore::new(root.join("connection_points"))
                .await
                .expect("connection point store"),
        );
        let message_store = Arc::new(
            crate::gateways::MessageStore::new(root.join("messages"))
                .await
                .expect("message store"),
        );
        let (listener_manager, listener_issuer_storage) =
            crate::gateways::test_helpers::test_listener_manager(&root.join("listener")).await;
        let issuer_store = Arc::new(
            crate::issuers::FileSystemIssuerStore::new(root.join("issuers"))
                .await
                .expect("issuer store"),
        );
        let authority_store = Arc::new(
            crate::authorities::FileSystemAuthorityStore::new(root.join("authorities"))
                .await
                .expect("authority store"),
        );
        let jwt_verification_strategy_store: Arc<dyn crate::jwt_bearer::JwtVerificationStrategyStorage> = Arc::new(
            crate::jwt_bearer::storage::FileSystemJwtVerificationStrategyStore::new(root.join("jwt_strategies"))
                .await
                .expect("jwt verification strategy store"),
        );
        let sts_client_store: Arc<dyn crate::sts::store::StsClientStorage> = Arc::new(
            crate::sts::store::FileSystemStsClientStore::new(root.join("sts_clients"))
                .await
                .expect("sts client store"),
        );
        let x402_admin_router = crate::x402::admin_api::create_admin_router(rbac_guard.clone())
            .with_state(crate::x402::admin_api::AdminApiState { transaction_store: None });
        let mpp_admin_router = crate::mpp::admin_api::create_mpp_admin_router()
            .with_state(crate::mpp::admin_api::MppAdminApiState { transaction_store: None });

        let state = crate::identity::IdentityApiState {
            vc_issuer: vc_issuer.clone(),
            config: config.clone(),
            network_config: network_config.clone(),
            ws_state: ws_state.clone(),
            settings_store: settings_store.clone(),
            user_settings_store: Arc::new(crate::storage::UserSettingsStore::new(&paths.settings)),
            metrics_store: metrics_store.clone(),
            channel_manager: channel_manager.clone(),
            tls_acceptor: tls_acceptor_without_certificates(),
            client: reqwest::Client::new(),
            bootstrap_config: bootstrap.clone(),
            rbac_config: rbac,
            task_monitor: None,
            onboarding_sessions: Arc::new(crate::identity::handlers::OnboardingSessionManager::new()),
            policy_manager: Arc::new(crate::policies::SurfacePolicyManager::new()),
            gateway_policy_manager: None,
            notification_store: Some(notification_store.clone()),
            policy_definition_store: None,
            global_policy_store: None,
            global_policy_manager: None,
            agent_surface_store: None,
            gateway_store: None,
            connection_point_store: None,
            mediator_store: None,
            issuer_store: None,
            trust_registry_store: None,
            authority_store: None,
            mcp_proxy_store: None,
            a2a_proxy_store: None,
            secrets_store: None,
            certificate_store: None,
            jwt_verification_strategy_store: None,
            credential_provider_store: None,
            delegation_vault_store: None,
            sts_client_store: None,
            resolved_surface_cache: Arc::new(crate::surfaces::ResolvedSurfaceCache::new()),
            surface_reload_lock: Arc::new(tokio::sync::Mutex::new(())),
            surface_template_store: None,
            event_hook: None,
            mediator_directory: None,
            #[cfg(feature = "didwebvh")]
            didwebvh_identity_store: Some(Arc::new(
                crate::identity::didwebvh::identity_manager::FileSystemDidWebVhIdentityStore::new(
                    root.join("didwebvh_identities"),
                )
                .await
                .expect("did:webvh identity store"),
            )),
            #[cfg(feature = "didwebvh")]
            didwebvh_log_storage: Some(Arc::new(crate::storage::did_logs_file::FileDidLogStorage::new(
                root.join("didwebvh_logs"),
            ))),
            #[cfg(feature = "didwebvh")]
            didwebvh_base_url: Some("https://test.local".to_string()),
        };
        let dashboard_state = crate::observability::DashboardState {
            config,
            network_config,
            identity_store: Arc::new(crate::identity::test_helpers::MockIdentityStore::new()),
            metrics_store: metrics_store.clone(),
            vc_issuer,
            ws_state,
            task_monitor: None,
            channel_manager,
            connection_point_listener_manager: None,
            mcp_proxy_store: None,
            mcp_server_manager: None,
            notification_store: Some(notification_store.clone()),
            auth_state: auth.clone(),
            trust_registry_listener_manager: None,
            system_metrics_store: None,
            agent_surface_store: None,
        };
        let router = crate::identity::create_identity_api_router(
            state,
            dashboard_state,
            auth.clone(),
            None,
            Some(gateway_store),
            Some(mediator_store),
            Some(trust_registry_store),
            None,
            None,
            Some(mcp_proxy_store),
            Some(a2a_proxy_store),
            Arc::new(crate::mcp_proxies::handlers::McpServerManager::new()),
            None,
            Some(connection_point_store),
            Some(notification_store),
            Some(Arc::new(listener_manager)),
            Some(message_store),
            Arc::new(
                crate::gateways::PendingConnectionStore::new(root.join("pending_connections"))
                    .await
                    .expect("pending connection store"),
            ),
            Some(jwt_verification_strategy_store),
            Some(Arc::new(crate::jwt_bearer::JwksClient::new())),
            Some(issuer_store),
            Some(authority_store),
            Some(x402_admin_router),
            Some(mpp_admin_router),
            Some(metrics_store),
            Some(sts_client_store),
            None,
            terms_manager,
            Some(access_tokens.clone()),
        );

        Self {
            router,
            log_directory,
            auth,
            access_tokens,
            _storage: storage,
            _issuer_storage: issuer_storage,
            _listener_issuer_storage: listener_issuer_storage,
        }
    }
}

fn tls_acceptor_without_certificates() -> tokio_rustls::TlsAcceptor {
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

/// The integrations API is mounted only once the process-wide definition stores are set,
/// which the gateway does at startup. They are set here, so the router always carries those
/// routes, over a temporary folder that is kept on purpose: the stores live as long as the test
/// process, so the folder stays in the system temporary directory after it exits.
async fn ensure_integration_definition_stores() {
    static STORAGE: OnceLock<PathBuf> = OnceLock::new();
    if definition_stores().is_some() {
        return;
    }
    let root = STORAGE.get_or_init(|| {
        tempfile::tempdir()
            .expect("tempdir")
            .keep()
    });
    let stores = DefinitionStores::open(&root.join("endpoints"), &root.join("event_sets"), &root.join("integrations"))
        .await
        .expect("integration definition stores");
    init_definition_stores(Arc::new(stores));
}
