use axum::{
    Extension, Router,
    http::{HeaderValue, request::Parts as RequestParts},
    middleware,
    routing::{delete, get, patch, post, put},
};
use hyper::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::{debug, error, info};

use crate::identity::handlers;
use crate::identity::state::IdentityApiState;
use crate::metrics::MetricsStore;
use std::sync::Arc;

/// 308 Permanent Redirect handler for legacy `/v1/departments*` admin routes.
/// Rewrites the path prefix `/v1/departments` → `/v1/issuers` (and the migration
/// admin path `/v1/admin/departments/…` → `/v1/admin/issuers/…`), preserves any
/// query string, and logs a deprecation WARN per hit so operators can migrate
/// their API clients to the canonical `/v1/issuers*` URLs.
async fn legacy_v1_department_308_handler(
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let path = uri.path();
    let new_path = if let Some(rest) = path.strip_prefix("/v1/admin/departments") {
        format!("/v1/admin/issuers{}", rest)
    } else if let Some(rest) = path.strip_prefix("/v1/departments") {
        format!("/v1/issuers{}", rest)
    } else {
        path.to_string()
    };
    let location = match uri.query() {
        Some(q) => format!("{}?{}", new_path, q),
        None => new_path.clone(),
    };
    tracing::warn!(
        legacy_path = %path,
        new_path = %new_path,
        "Legacy /v1/departments* route accessed; redirecting (308 Permanent Redirect) to /v1/issuers*. Please update API clients."
    );
    axum::response::Redirect::permanent(&location).into_response()
}

/// 308 Permanent Redirect handler for legacy `/departments/{id}/did.{json,jsonl}`
/// DID resolution routes. Rewrites the path prefix `/departments/` →
/// `/issuers/`, preserves query string, and logs a deprecation WARN. Note the
/// small risk that a strict `did:{web,webvh}` resolver refusing HTTP 3xx
/// redirects could fail to resolve legacy `did:…:departments:{uuid}` DIDs; the
/// vast majority of resolvers (Node fetch, Rust reqwest, Go http.Client, Python
/// requests) follow 3xx by default.
async fn legacy_department_did_308_handler(
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let path = uri.path();
    let new_path = if let Some(rest) = path.strip_prefix("/departments/") {
        format!("/issuers/{}", rest)
    } else {
        path.to_string()
    };
    let location = match uri.query() {
        Some(q) => format!("{}?{}", new_path, q),
        None => new_path.clone(),
    };
    tracing::warn!(
        legacy_path = %path,
        new_path = %new_path,
        "Legacy /departments/{{id}}/did.* DID resolution route accessed; redirecting (308) to /issuers/{{id}}/did.*. Existing did:…:departments:{{uuid}} DIDs continue to resolve when the fetcher follows HTTP 3xx redirects."
    );
    axum::response::Redirect::permanent(&location).into_response()
}

/// Create the identity API router with all routes configured
/// A2A-proxy management routes for a deployment with **no auth backend**.
///
/// `create`/`update` set the proxy `base_url`, an egress target the dispatch
/// layer trusts with the tenant credential, so on a no-auth deploy they are
/// intentionally **not** mounted — an unauthenticated caller must not be able to
/// set `base_url`. A POST/PUT therefore returns 405; read and delete stay
/// available. When an auth backend is present these routes are RBAC-gated
/// instead (see the `A2aProxiesEdit` branch in `create_identity_api_router`).
fn build_a2a_proxy_router_unauthenticated(
    store: std::sync::Arc<crate::a2a_proxies::FileSystemA2aProxyStore>,
    secrets_store: Option<std::sync::Arc<dyn crate::secrets::SecretsStore>>,
) -> Router {
    Router::new()
        .route(
            "/v1/a2a-proxies",
            get(crate::a2a_proxies::handlers::list_a2a_proxies::<crate::a2a_proxies::FileSystemA2aProxyStore>),
        )
        .route(
            "/v1/a2a-proxies/{id}",
            get(crate::a2a_proxies::handlers::get_a2a_proxy::<crate::a2a_proxies::FileSystemA2aProxyStore>),
        )
        .route(
            "/v1/a2a-proxies/{id}",
            delete(crate::a2a_proxies::handlers::delete_a2a_proxy::<crate::a2a_proxies::FileSystemA2aProxyStore>),
        )
        .layer(Extension(store))
        .layer(Extension(secrets_store))
}

pub fn create_identity_api_router(
    state: IdentityApiState,
    dashboard_state: crate::observability::DashboardState,
    auth_state: Option<std::sync::Arc<crate::auth::AuthState>>,
    saml_state: Option<std::sync::Arc<crate::auth::saml::SamlState>>,
    gateway_store: Option<std::sync::Arc<crate::gateways::FileSystemGatewayStore>>,
    mediator_store: Option<std::sync::Arc<crate::mediators::FileSystemMediatorStore>>,
    trust_registry_store: Option<std::sync::Arc<crate::trust_registries::FileSystemTrustRegistryStore>>,
    trust_registry_listener_manager: Option<std::sync::Arc<crate::trust_registries::TrustRegistryListenerManager>>,
    trust_registry_worker: Option<std::sync::Arc<crate::trust_registries::TrustRegistryWorker>>,
    mcp_proxy_store: Option<std::sync::Arc<crate::mcp_proxies::FileSystemMcpProxyStore>>,
    a2a_proxy_store: Option<std::sync::Arc<crate::a2a_proxies::FileSystemA2aProxyStore>>,
    mcp_server_manager: std::sync::Arc<crate::mcp_proxies::handlers::McpServerManager>,
    secrets_store: Option<std::sync::Arc<dyn crate::secrets::SecretsStore>>,
    connection_point_store: Option<std::sync::Arc<crate::gateways::FileSystemConnectionPointStore>>,
    notification_store: Option<std::sync::Arc<crate::integrations::FileSystemNotificationStore>>,
    listener_manager: Option<std::sync::Arc<crate::gateways::ConnectionPointListenerManager>>,
    message_store: Option<std::sync::Arc<crate::gateways::MessageStore>>,
    pending_connection_store: std::sync::Arc<crate::gateways::PendingConnectionStore>,
    integration_storage: Option<std::sync::Arc<crate::storage::IntegrationStorage>>,
    jwt_verification_strategy_store: Option<std::sync::Arc<dyn crate::jwt_bearer::JwtVerificationStrategyStorage>>,
    jwks_client: Option<std::sync::Arc<crate::jwt_bearer::JwksClient>>,
    issuer_store: Option<std::sync::Arc<crate::issuers::FileSystemIssuerStore>>,
    authority_store: Option<std::sync::Arc<crate::authorities::FileSystemAuthorityStore>>,
    x402_admin_router: Option<Router>,
    mpp_admin_router: Option<Router>,
    metric_store: Option<Arc<MetricsStore>>,
    sts_client_store: Option<std::sync::Arc<dyn crate::sts::store::StsClientStorage>>,
    mcp_replay: Option<std::sync::Arc<crate::sts::replay::McpReplay>>,
    terms_manager: Arc<crate::terms::TermsManager>,
    pat_authenticator: Option<std::sync::Arc<dyn crate::auth_manager::pat::PatAuthenticator>>,
) -> Router {
    // Capture config before moving state into routers
    let avatars_path = state
        .bootstrap_config
        .storage_paths
        .avatars
        .clone();
    {
        let resolved = std::fs::canonicalize(&avatars_path)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|e| format!("<unresolved: {}>", e));
        let cwd = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "?".to_string());
        tracing::info!("[WWW Hosting] avatars dir (path: {} | cwd: {} | resolved: {})", avatars_path, cwd, resolved);
    }

    let rbac_config = state.rbac_config.clone();
    let websocket_require_auth = state
        .bootstrap_config
        .websocket_require_auth;
    let gateway_session_mgr = auth_state
        .as_ref()
        .map(|auth| auth.session_manager.clone())
        .or_else(|| {
            saml_state
                .as_ref()
                .map(|saml| saml.session_manager.clone())
        });
    let gateway_user_storage = auth_state
        .as_ref()
        .map(|auth| auth.storage.clone())
        .or_else(|| {
            saml_state
                .as_ref()
                .map(|saml| saml.storage.clone())
        });

    // Reuse trust registry listener manager for agents-api onboarding
    let agents_api_listener_manager = trust_registry_listener_manager.clone();

    // Create gateway channel cache
    let gateway_channel_cache = std::sync::Arc::new(crate::gateways::GatewaySurfaceCache::new());

    // Create dashboard routes with dashboard state
    let dashboard_router = Router::new()
        .route("/v1/dashboard/stats", get(crate::observability::get_dashboard_stats))
        .route("/v1/dashboard/delta", get(crate::observability::get_dashboard_delta))
        .route("/v1/dashboard/surface/{channel_config_id}/metrics", get(crate::observability::get_surface_metrics))
        .route(
            "/v1/dashboard/surface/{channel_config_id}/ucp-operations",
            get(crate::observability::get_ucp_operation_stats),
        )
        .route("/v1/dashboard/metrics/hierarchical", get(crate::observability::get_hierarchical_metrics))
        .route("/v1/dashboard/system-metrics", get(crate::observability::get_system_metrics));

    // Add WebSocket routes conditionally based on auth requirement
    info!(
        "Setting up WebSocket routes: websocket_require_auth={}, auth_state={}, saml_state={}",
        websocket_require_auth,
        auth_state.is_some(),
        saml_state.is_some()
    );

    let dashboard_router = if websocket_require_auth && (auth_state.is_some() || saml_state.is_some()) {
        // Get session manager from whichever auth mode is active
        let session_mgr = if let Some(auth) = auth_state.as_ref() {
            info!("Using passkey session manager for WebSocket authentication");
            auth.session_manager.clone()
        } else if let Some(saml) = saml_state.as_ref() {
            info!("Using SAML session manager for WebSocket authentication");
            saml.session_manager.clone()
        } else {
            unreachable!("Session manager must exist when auth_state or saml_state is Some");
        };

        info!("WebSocket routes configured with authentication required");
        dashboard_router
            .route("/ws/dashboard", get(crate::server::ws_handler_authenticated))
            .route("/ws", get(crate::server::ws_handler_authenticated))
            .with_state(dashboard_state.clone())
            .layer(Extension(session_mgr))
            .layer(Extension(terms_manager.clone()))
    } else {
        // Use unauthenticated handler for backward compatibility
        info!("WebSocket routes configured without authentication");
        dashboard_router
            .route("/ws/dashboard", get(crate::server::ws_handler))
            .route("/ws", get(crate::server::ws_handler))
            .with_state(dashboard_state.clone())
    };

    // Create identity API routes with identity state.
    //
    // NOTE: routes flagged HIGH-severity (findings H1, H3, H4, H5, H6, H15, H18)
    // are NOT registered here. They are moved to `rbac_identity_router` below so
    // they are gated by `require_feature(<Feature>)` against the per-route RBAC
    // policy. In auth-disabled builds the RBAC router is not built, so those
    // routes return 404 — fail-closed.
    let identity_router = Router::new()
        // DIDComm messaging endpoints
        .route("/didcomm", post(handlers::didcomm_endpoint))
        .route("/didcomm/ws", get(handlers::didcomm_ws_endpoint))
        // Identity credential routes (read-only — issue/retry-registration are RBAC-gated below)
        .route("/v1/identity/did-document", get(handlers::get_did_document))
        .route("/v1/identity/resolve-did", get(handlers::resolve_did_document))
        .route("/v1/identity/resolve-did-document", get(handlers::resolve_did_document_spec))
        // Health check
        .route("/v1/health", get(handlers::health_check))
        .route("/v1/alive", get(handlers::alive_check))
        // Version check
        .route("/v1/version", get(handlers::get_version))
        // Settings routes (GET is open to all; POST/DELETE require admin and are registered below)
        .route("/v1/settings", get(handlers::get_settings))
        // NOTE: storage backup/restore/export and agents-api sign-jwt are admin-only
        // and are registered on the RBAC-gated `auth_manager_router` below, not here.
        // Metrics routes
        .route("/v1/metrics/truncate", post(handlers::truncate_metrics))
        .route("/v1/metrics/prometheus", get(handlers::prometheus_metrics))
        .route("/v1/metrics/otlp-status", get(handlers::get_otlp_status))
        // NOTE: the metrics configuration routes write the OTLP exporter destination and its
        // secret-store-resolved auth header, and the log download returns the whole log
        // directory, so all four are RBAC-gated on `rbac_identity_router` below.
        // Logs routes
        .route("/v1/logs/truncate", post(handlers::truncate_old_logs))
        // NOTE: the VP Audit Log (/v1/audit) can include caller context and VP
        // JWTs, so it is RBAC-gated behind administrator-only `audit.view` on
        // the `rbac_identity_router` below, not registered here.
        // Configuration read routes (reload is RBAC-gated below)
        .route("/v1/config/surface-routing", get(handlers::get_surface_routing_config))
        .route("/v1/config/x402", get(handlers::get_payment_policy))
        .route("/v1/config/networking", get(handlers::get_networking_config))
        // Policy validation (used by surface builder)
        .route("/v1/surfaces/validate-policy", post(handlers::validate_policy))
        // Agent Surface, Surface Template, and policy-definition management routes are RBAC-gated below.
        // NOTE: GET /v1/policy-assignments is RBAC-gated below (Feature::PoliciesView) —
        // it discloses appliance-wide global policy enforcement configuration.
        // Onboarding routes (create-temp-surface and delete-temp-channel are RBAC-gated below)
        .route("/onboard/{uuid}/.well-known/agent-card.json", get(handlers::serve_onboarding_agent_card))
        .route("/onboard/{uuid}/rpc", post(handlers::handle_onboarding_message))
        .route("/onboard/{uuid}/", post(handlers::handle_onboarding_message))
        .route("/onboard/{uuid}", post(handlers::handle_onboarding_message))
        // Agent routes
        .route("/v1/agents", get(handlers::get_agents))
        // Agents API routes (for local agents to onboard and verify JWTs).
        // NOTE: /agents-api/v1/sign-jwt is admin-only and registered on the
        // RBAC-gated `auth_manager_router` below, not here.
        .route("/agents-api/v1/onboard", post(crate::agents_api::handlers::onboard))
        .route("/agents-api/v1/verify-jwt", post(crate::agents_api::handlers::verify_jwt))
        .layer(Extension(agents_api_listener_manager.clone()))
        .with_state(state.clone());

    // Determine auth mode from what was actually passed to this function
    // If saml_state is Some, we're in SAML mode
    // If auth_state is Some, we're in Passkey mode
    let auth_mode = if saml_state.is_some() {
        crate::auth::AuthMode::Saml
    } else {
        crate::auth::AuthMode::Passkey
    };

    // Create auth routes based on authentication mode
    // Returns: (router, storage_for_manager, session_manager_for_manager)
    let (auth_router, passkey_storage_for_manager, session_manager_for_manager) = match auth_mode {
        crate::auth::AuthMode::Passkey => {
            if let Some(auth_state_arc) = auth_state.clone() {
                let storage = auth_state_arc.storage.clone();
                let session_mgr = auth_state_arc
                    .session_manager
                    .clone();
                #[cfg(debug_assertions)]
                let test_support_router = {
                    let test_auth_config = crate::auth::test_auth::TestAuthConfig::from_env();
                    if test_auth_config.enabled {
                        Router::new()
                            .route("/internal/test-support/auth/login", post(crate::auth::test_auth::test_login))
                            .with_state(std::sync::Arc::new(crate::auth::test_auth::TestAuthState::new(
                                storage.clone(),
                                session_mgr.clone(),
                                terms_manager.clone(),
                                test_auth_config,
                            )))
                    } else {
                        Router::new()
                    }
                };
                #[cfg(not(debug_assertions))]
                let test_support_router = Router::new();

                let router = Router::new()
                    // Auth mode endpoint (unauthenticated)
                    .route("/v1/auth/mode", get(crate::auth::mode_handler::get_auth_mode))
                    .layer(Extension(auth_mode.clone()))
                    .merge(
                        Router::new()
                            .route("/auth/register/start", post(crate::auth::handlers::register_start))
                            .route("/auth/register/finish", post(crate::auth::handlers::register_finish))
                            .route("/auth/login/start", post(crate::auth::handlers::login_start))
                            .route("/auth/login/finish", post(crate::auth::handlers::login_finish))
                            .route("/auth/check", get(crate::auth::handlers::check_auth))
                            .route("/auth/logout", post(crate::auth::handlers::logout))
                            .layer(Extension(metric_store.clone()))
                            .with_state(auth_state_arc.clone()),
                    )
                    .merge(test_support_router);

                (router, Some(storage), Some(session_mgr))
            } else {
                error!("Passkey mode enabled but no auth state available");
                (
                    Router::new()
                        .route("/v1/auth/mode", get(crate::auth::mode_handler::get_auth_mode))
                        .layer(Extension(auth_mode.clone())),
                    None,
                    None,
                )
            }
        }
        crate::auth::AuthMode::Saml => {
            // Add SAML routes if saml_state is available
            if let Some(saml_state_arc) = saml_state {
                let session_mgr = saml_state_arc
                    .session_manager
                    .clone();
                let storage = saml_state_arc.storage.clone();

                let router = Router::new()
                    // Auth mode endpoint (unauthenticated)
                    .route("/v1/auth/mode", get(crate::auth::mode_handler::get_auth_mode))
                    .layer(Extension(auth_mode.clone()))
                    .merge(
                        Router::new()
                            .route("/saml/login", get(crate::auth::saml::saml_login))
                            .route("/saml/acs", post(crate::auth::saml::saml_acs))
                            .route("/saml/metadata", get(crate::auth::saml::saml_metadata))
                            .route("/saml/logout", post(crate::auth::saml::saml_logout))
                            .layer(Extension(metric_store.clone()))
                            .with_state(saml_state_arc.clone()),
                    )
                    .merge(
                        Router::new()
                            .route("/auth/check", get(crate::auth::saml::saml_check_auth))
                            .route("/auth/logout", post(crate::auth::saml::saml_logout_generic))
                            .layer(Extension(session_mgr.clone()))
                            .layer(Extension(terms_manager.clone())),
                    );
                info!("SAML routes registered (login, acs, metadata, logout, check)");

                // Return storage and session manager for auth_manager_router setup
                (router, Some(storage), Some(session_mgr))
            } else {
                error!("SAML mode enabled but no SAML state available");
                (
                    Router::new()
                        .route("/v1/auth/mode", get(crate::auth::mode_handler::get_auth_mode))
                        .layer(Extension(auth_mode.clone())),
                    None,
                    None,
                )
            }
        }
    };

    // Create auth manager routes if passkey storage and session manager are available
    // This works for both Passkey and SAML modes since they both use PasskeyStorage
    let auth_manager_router = if let (Some(storage), Some(sess_mgr)) =
        (passkey_storage_for_manager.as_ref(), session_manager_for_manager.as_ref())
    {
        let mut router = Router::new();

        // Add user management routes with session auth middleware.
        // These handlers are auth-mode-agnostic — they need PasskeyStorage,
        // RbacConfig, and MetricsStore (all available in both Passkey and SAML
        // modes), not the Passkey-specific AuthState.
        router = router.merge(
            Router::new()
                .route("/v1/users", get(crate::auth_manager::handlers::list_users))
                .route("/v1/users/{user_id}", get(crate::auth_manager::handlers::get_user))
                .route("/v1/users/{user_id}", put(crate::auth_manager::handlers::update_user))
                .route("/v1/users/{user_id}", delete(crate::auth_manager::handlers::delete_user))
                .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
                .layer(Extension(sess_mgr.clone()))
                .layer(Extension(storage.clone()))
                .layer(Extension(notification_store.clone()))
                .layer(Extension(rbac_config.clone()))
                .layer(Extension(metric_store.clone())),
        );

        // Add profile and permissions routes with session auth middleware
        router = router.merge(
            Router::new()
                .route("/v1/profile", get(crate::auth_manager::handlers::get_profile))
                .route("/v1/profile", put(crate::auth_manager::handlers::update_profile))
                .route("/v1/profile/avatar", post(crate::auth_manager::handlers::upload_avatar))
                .route("/v1/permissions", get(crate::auth_manager::permissions::get_permissions))
                .route("/v1/token-info", get(crate::auth_manager::permissions::get_token_info))
                .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
                .layer(Extension(sess_mgr.clone()))
                .layer(Extension(storage.clone()))
                .layer(Extension(rbac_config.clone())),
        );

        // Add unauthenticated permissions endpoint for registration flow
        router = router.merge(
            Router::new()
                .route("/v1/permissions/public", get(crate::auth_manager::permissions::get_permissions_optional))
                .layer(Extension(storage.clone()))
                .layer(Extension(rbac_config.clone())),
        );

        // Add per-user settings routes with session auth middleware
        router = router.merge(
            Router::new()
                .route("/v1/user-settings", get(handlers::get_user_settings))
                .route("/v1/user-settings", post(handlers::update_user_settings))
                .route("/v1/user-settings", delete(handlers::reset_user_settings))
                .route("/v1/user-settings/overrides", get(handlers::get_user_settings_overrides))
                .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
                .layer(Extension(sess_mgr.clone()))
                .layer(Extension(storage.clone()))
                .with_state(state.clone()),
        );

        // Add admin-protected system settings write routes (POST/DELETE /v1/settings)
        router = router.merge(
            Router::new()
                .route("/v1/settings", post(handlers::update_settings))
                .route("/v1/settings", delete(handlers::reset_settings))
                .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
                .layer(Extension(sess_mgr.clone()))
                .layer(Extension(storage.clone()))
                .layer(Extension(rbac_config.clone()))
                .with_state(state.clone()),
        );

        // Add admin-only full-storage and key-signing routes (relocated from
        // `identity_router` so they are RBAC-gated like the settings writes above).
        // Each handler enforces `storage.admin`/`settings.edit` (administrator-only).
        // Mounting them here means they are fail-closed: when no auth backend is
        // configured this router is not built and the routes return 404 instead of
        // being reachable by any session.
        router = router.merge(
            Router::new()
                .route("/v1/admin/backup-storage", post(crate::backup_restore::backup_storage))
                .route(
                    "/v1/admin/restore-storage",
                    post(crate::backup_restore::restore_storage)
                        .layer(axum::extract::DefaultBodyLimit::max(512 * 1024 * 1024)), // 512 MB
                )
                .route("/v1/debug/export-storage", post(handlers::export_storage))
                .route("/agents-api/v1/sign-jwt", post(crate::agents_api::handlers::sign_jwt))
                .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
                .layer(Extension(sess_mgr.clone()))
                .layer(Extension(storage.clone()))
                .layer(Extension(rbac_config.clone()))
                .with_state(state.clone()),
        );

        info!(
            "Auth manager routes registered (users, profile, permissions) for {} mode",
            if auth_mode == crate::auth::AuthMode::Saml {
                "SAML"
            } else {
                "Passkey"
            }
        );

        router
    } else {
        Router::new()
    };

    let terms_router = {
        let public = Router::new()
            .route("/v1/terms/applicable", get(crate::terms::handlers::applicable))
            .route("/v1/terms/provider-health", get(crate::terms::handlers::provider_health));
        let protected = if let (Some(storage), Some(session_manager)) =
            (passkey_storage_for_manager.as_ref(), session_manager_for_manager.as_ref())
        {
            use crate::auth_manager::middleware::require_feature;
            use crate::rbac::Feature;
            let rbac = rbac_config.clone();
            Router::new()
                .route("/v1/terms/status", get(crate::terms::handlers::status))
                .route("/v1/terms/acceptances", post(crate::terms::handlers::accept))
                .route(
                    "/v1/terms",
                    get(crate::terms::handlers::definitions).layer(require_feature(
                        storage.clone(),
                        rbac.clone(),
                        Feature::TermsView,
                    )),
                )
                .route(
                    "/v1/terms/customer/draft",
                    put(crate::terms::handlers::save_draft).layer(require_feature(
                        storage.clone(),
                        rbac.clone(),
                        Feature::TermsEdit,
                    )),
                )
                .route(
                    "/v1/terms/customer/publish",
                    post(crate::terms::handlers::publish).layer(require_feature(
                        storage.clone(),
                        rbac.clone(),
                        Feature::TermsEdit,
                    )),
                )
                .route(
                    "/v1/terms/customer/deactivate",
                    post(crate::terms::handlers::deactivate).layer(require_feature(
                        storage.clone(),
                        rbac,
                        Feature::TermsEdit,
                    )),
                )
                .layer(Extension(session_manager.clone()))
        } else {
            Router::new()
        };
        public
            .merge(protected)
            .layer(Extension(terms_manager.clone()))
    };

    // Create RBAC-gated identity routes (relocated from `identity_router`).
    //
    // These cover findings H1, H3, H4, H5, H6, H15, H18 — every mutating route
    // listed here is wrapped with `require_feature(<Feature>)` so unauthorised
    // callers are rejected with 403 before the handler runs. In auth-disabled
    // builds this router is empty, so the routes 404 (fail-closed).
    let rbac_identity_router = if let Some(storage) = passkey_storage_for_manager.as_ref() {
        use crate::auth_manager::middleware::require_feature;
        use crate::rbac::Feature;
        let s = storage.clone();
        let r = rbac_config.clone();
        Router::new()
            // H18 — credentials issuance
            .route(
                "/v1/identity/issue",
                post(handlers::issue_credential).layer(require_feature(s.clone(), r.clone(), Feature::IdentityIssue)),
            )
            // H5 — config reload (reads disk and reapplies)
            .route(
                "/v1/config/reload",
                post(handlers::reload_configuration).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::ConfigReload,
                )),
            )
            .route(
                "/v1/config/reload/{config_id}",
                post(handlers::reload_single_channel).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::ConfigReload,
                )),
            )
            // VP Audit Log read — the response can include caller context and VP
            // JWTs, so it is gated behind the administrator-only audit evidence
            // permission rather than the broader application-log permission.
            .route(
                "/v1/audit",
                get(handlers::audit_log::get_audit_log).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::AuditView,
                )),
            )
            .route(
                "/v1/limits",
                get(handlers::list_limits).layer(require_feature(s.clone(), r.clone(), Feature::MetricsView)),
            )
            // Observability configuration — writes the OTLP exporter destination and
            // resolves its auth header from the secret store.
            .route(
                "/v1/metrics/config",
                get(handlers::get_metrics_config).layer(require_feature(s.clone(), r.clone(), Feature::SettingsEdit)),
            )
            .route(
                "/v1/metrics/config",
                put(handlers::update_metrics_config).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::SettingsEdit,
                )),
            )
            .route(
                "/v1/metrics/test-connection",
                post(handlers::test_otlp_connection).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::SettingsEdit,
                )),
            )
            // Server logs routinely carry tokens, request detail and PII.
            .route(
                "/v1/logs/download",
                get(handlers::download_logs).layer(require_feature(s.clone(), r.clone(), Feature::AuditView)),
            )
            // H1 / H16 — surface mutations (H16 collapses into H1 because the
            // channel-policy update is reached via the surface PUT/DELETE)
            .route(
                "/v1/surfaces",
                get(handlers::list_surfaces).layer(require_feature(s.clone(), r.clone(), Feature::SurfacesView)),
            )
            .route(
                "/v1/surfaces",
                post(handlers::create_surface).layer(require_feature(s.clone(), r.clone(), Feature::SurfacesEdit)),
            )
            .route(
                "/v1/surfaces/{surface_id}",
                get(handlers::get_surface).layer(require_feature(s.clone(), r.clone(), Feature::SurfacesView)),
            )
            .route(
                "/v1/surfaces/{surface_id}",
                put(handlers::update_surface).layer(require_feature(s.clone(), r.clone(), Feature::SurfacesEdit)),
            )
            .route(
                "/v1/surfaces/{surface_id}",
                patch(handlers::surfaces::patch_surface).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::SurfacesEdit,
                )),
            )
            .route(
                "/v1/surfaces/{surface_id}",
                delete(handlers::delete_surface).layer(require_feature(s.clone(), r.clone(), Feature::SurfacesDelete)),
            )
            // H1 — surface variants
            .route(
                "/v1/surfaces/{surface_id}/variants",
                post(handlers::create_variant).layer(require_feature(s.clone(), r.clone(), Feature::SurfacesEdit)),
            )
            .route(
                "/v1/surfaces/{surface_id}/variants/{variant_id}",
                put(handlers::update_variant).layer(require_feature(s.clone(), r.clone(), Feature::SurfacesEdit)),
            )
            .route(
                "/v1/surfaces/{surface_id}/variants/{variant_id}",
                patch(handlers::surfaces::patch_variant).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::SurfacesEdit,
                )),
            )
            .route(
                "/v1/surfaces/{surface_id}/variants/{variant_id}",
                delete(handlers::delete_variant).layer(require_feature(s.clone(), r.clone(), Feature::SurfacesDelete)),
            )
            .route(
                "/v1/surfaces/{surface_id}/variants/{variant_id}/promote-to-default",
                post(handlers::promote_variant_to_default).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::SurfacesEdit,
                )),
            )
            .route(
                "/v1/surfaces/{surface_id}/variants/{alias}/resolved",
                get(handlers::get_resolved_variant).layer(require_feature(s.clone(), r.clone(), Feature::SurfacesView)),
            )
            .route(
                "/v1/surface-templates",
                get(crate::surface_templates::handlers::list_templates).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::SurfacesView,
                )),
            )
            .route(
                "/v1/surface-templates",
                post(crate::surface_templates::handlers::create_template).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::SurfacesEdit,
                )),
            )
            .route(
                "/v1/surface-templates/import",
                post(crate::surface_templates::handlers::import_template).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::SurfacesEdit,
                )),
            )
            .route(
                "/v1/surface-templates/{template_id}",
                get(crate::surface_templates::handlers::get_template).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::SurfacesView,
                )),
            )
            .route(
                "/v1/surface-templates/{template_id}",
                put(crate::surface_templates::handlers::update_template).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::SurfacesEdit,
                )),
            )
            .route(
                "/v1/surface-templates/{template_id}",
                delete(crate::surface_templates::handlers::delete_template).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::SurfacesDelete,
                )),
            )
            .route(
                "/v1/surface-templates/{template_id}/export",
                get(crate::surface_templates::handlers::export_template).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::SurfacesView,
                )),
            )
            // H4 — OPA policy definitions
            .route(
                "/v1/policy-definitions",
                get(handlers::list_policy_definitions).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::PoliciesView,
                )),
            )
            .route(
                "/v1/policy-definitions/{policy_id}",
                get(handlers::get_policy_definition).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::PoliciesView,
                )),
            )
            .route(
                "/v1/policy-definitions/{policy_id}/versions",
                get(handlers::list_policy_versions).layer(require_feature(s.clone(), r.clone(), Feature::PoliciesView)),
            )
            .route(
                "/v1/policy-definitions/{policy_id}/impact",
                get(handlers::policy_definition_impact).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::PoliciesView,
                )),
            )
            .route(
                "/v1/policy-definitions",
                post(handlers::create_policy_definition).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::PoliciesEdit,
                )),
            )
            .route(
                "/v1/policy-definitions/{policy_id}",
                put(handlers::update_policy_definition).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::PoliciesEdit,
                )),
            )
            .route(
                "/v1/policy-definitions/{policy_id}",
                delete(handlers::delete_policy_definition).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::PoliciesDelete,
                )),
            )
            .route(
                "/v1/policy-definitions/{policy_id}/simulate",
                post(handlers::simulate_policy_definition).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::PoliciesEdit,
                )),
            )
            .route(
                "/v1/policy-assignments",
                get(handlers::get_policy_assignments).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::PoliciesView,
                )),
            )
            .route(
                "/v1/policy-assignments",
                put(handlers::update_policy_assignments).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::PoliciesEdit,
                )),
            )
            .route(
                "/v1/tenant-ownership/{kind}/{id}/impact",
                get(handlers::tenant_ownership::ownership_impact).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::TenantOwnershipManage,
                )),
            )
            .route(
                "/v1/tenant-ownership/{kind}/{id}",
                put(handlers::tenant_ownership::reassign_ownership).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::TenantOwnershipManage,
                )),
            )
            // H6 — onboarding surface lifecycle
            .route(
                "/v1/onboard/create-temp-surface",
                post(handlers::create_temp_onboard_surface).layer(require_feature(
                    s.clone(),
                    r.clone(),
                    Feature::SurfacesEdit,
                )),
            )
            .route(
                "/v1/onboard/delete-temp-channel/{config_id}",
                delete(handlers::delete_temp_onboard_channel).layer(require_feature(s, r, Feature::SurfacesDelete)),
            )
            .layer(Extension(agents_api_listener_manager.clone()))
            .with_state(state.clone())
    } else {
        Router::new()
    };

    // Capture clones for the STS router before these Options are consumed by the
    // OIDC provider router below. The STS token endpoint reuses the same JWT
    // verification strategies to verify subject-token / ID-JAG assertions.
    let sts_jwks_client = jwks_client.clone();
    let sts_strategy_store = jwt_verification_strategy_store.clone();
    let sts_vc_issuer = state.vc_issuer.clone();
    let sts_secrets_store = secrets_store.clone();
    let sts_gateway_policy_manager = state
        .gateway_policy_manager
        .clone();
    let sts_trust_registry_listener_manager = trust_registry_listener_manager.clone();

    // Create JWT verification strategy management routes (admin-only)
    let oidc_provider_router = if let (Some(store), Some(storage), Some(sess_mgr)) =
        (jwt_verification_strategy_store, passkey_storage_for_manager.as_ref(), session_manager_for_manager.as_ref())
    {
        let state: crate::jwt_bearer::handlers::JwtVerificationStrategyState = store;
        info!("JWT verification strategy management routes registered");
        let router = crate::jwt_bearer::router::create_jwt_verification_strategies_router(state)
            .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
            .layer(Extension(sess_mgr.clone()))
            .layer(Extension(storage.clone()))
            .layer(Extension(rbac_config.clone()));
        // Attach the JwksClient Extension when available so the validate-jwks-uri handler can use it.
        if let Some(client) = jwks_client {
            router.layer(Extension(client))
        } else {
            router
        }
    } else {
        Router::new()
    };

    // Which tenant owns each MCP resource: read by STS minting, STS client
    // saves and MCP Proxy saves, so they all apply the same rule.
    let resource_owners = std::sync::Arc::new(crate::sts::resource_owners::ApplianceResourceOwners::new(
        state
            .agent_surface_store
            .clone()
            .map(|store| store as Arc<dyn crate::surfaces::AgentSurfaceStore>),
        state
            .mcp_proxy_store
            .clone()
            .map(|store| store as Arc<dyn crate::mcp_proxies::McpProxyStore>),
        state.network_config.clone(),
    ));

    // STS managed-connection (client) admin routes — administrator-gated.
    let sts_admin_router = if let (Some(store), Some(storage), Some(sess_mgr)) =
        (sts_client_store.clone(), passkey_storage_for_manager.as_ref(), session_manager_for_manager.as_ref())
    {
        info!("STS client management routes registered");
        crate::sts::admin::create_sts_client_router(store, secrets_store.clone(), resource_owners.clone())
            .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
            .layer(Extension(sess_mgr.clone()))
            .layer(Extension(storage.clone()))
            .layer(Extension(rbac_config.clone()))
    } else {
        Router::new()
    };

    let integration_storage_for_gateways = integration_storage.clone();

    // Create gateway routes if store is provided
    let gateway_router = if let Some(ref store) = gateway_store {
        // H2 / H8 — RBAC gate for mutating gateway routes.
        // When passkey storage is not configured (auth-disabled build) the
        // gate is a no-op; otherwise non-admin callers are rejected with 403.
        use crate::auth_manager::middleware::require_feature;
        use crate::rbac::Feature;
        let storage_opt = passkey_storage_for_manager.clone();
        let rbac = rbac_config.clone();
        let gate = |mr: axum::routing::MethodRouter, feat: Feature| -> axum::routing::MethodRouter {
            if let Some(s) = storage_opt.as_ref() {
                mr.layer(require_feature(s.clone(), rbac.clone(), feat))
            } else {
                mr.layer(axum::middleware::from_fn(crate::auth_manager::middleware::deny_unguarded_request))
            }
        };

        let mut router = Router::new()
            .route(
                "/v1/gateway/config",
                gate(get(crate::gateways::handlers::get_gateway_config), Feature::SettingsView),
            )
            .route(
                "/v1/gateways",
                gate(
                    get(crate::gateways::handlers::list_gateways::<crate::gateways::FileSystemGatewayStore>),
                    Feature::GatewaysView,
                ),
            )
            .route(
                "/v1/gateways",
                gate(
                    post(crate::gateways::handlers::create_gateway::<crate::gateways::FileSystemGatewayStore>),
                    Feature::GatewaysEdit,
                ),
            )
            .route(
                "/v1/gateways/connect-via-oob",
                gate(
                    post(
                        crate::gateways::handlers::connect_via_oob::<
                            crate::gateways::FileSystemGatewayStore,
                            crate::gateways::FileSystemConnectionPointStore,
                            crate::mediators::FileSystemMediatorStore,
                        >,
                    ),
                    Feature::GatewaysEdit,
                ),
            )
            .route(
                "/v1/gateways/{id}",
                gate(
                    get(crate::gateways::handlers::get_gateway::<crate::gateways::FileSystemGatewayStore>),
                    Feature::GatewaysView,
                ),
            )
            .route(
                "/v1/gateways/{id}",
                gate(
                    put(crate::gateways::handlers::update_gateway::<crate::gateways::FileSystemGatewayStore>),
                    Feature::GatewaysEdit,
                ),
            )
            .route(
                "/v1/gateways/{id}/integrations",
                gate(
                    get(crate::integrations::gateway_integrations_handlers::get_gateway_integrations),
                    Feature::GatewaysView,
                ),
            )
            .route(
                "/v1/gateways/{id}/integrations",
                gate(
                    put(crate::integrations::gateway_integrations_handlers::update_gateway_integrations),
                    Feature::GatewaysEdit,
                ),
            )
            .route(
                "/v1/gateways/{id}/policy",
                gate(
                    get(crate::gateways::handlers::get_gateway_policy::<crate::gateways::FileSystemGatewayStore>),
                    Feature::GatewaysView,
                ),
            )
            .route(
                "/v1/gateways/{id}/policy",
                gate(
                    put(crate::gateways::handlers::update_gateway_policy::<crate::gateways::FileSystemGatewayStore>),
                    Feature::GatewaysEdit,
                ),
            )
            .layer(Extension(store.clone()))
            .layer(Extension(state.vc_issuer.clone()))
            .layer(Extension(state.bootstrap_config.clone()))
            .layer(Extension(state.network_config.clone()))
            .layer(Extension(pending_connection_store.clone()))
            .layer(Extension(notification_store.clone()))
            .layer(Extension(
                state
                    .gateway_policy_manager
                    .clone(),
            ))
            .layer(Extension(
                state
                    .policy_definition_store
                    .clone(),
            ))
            .layer(Extension(
                state
                    .agent_surface_store
                    .clone(),
            ))
            .layer(Extension(integration_storage_for_gateways));

        // Add listener manager + surface cache for gateway discovery routes
        if let Some(ref listener_mgr) = listener_manager {
            router = router.layer(Extension(listener_mgr.clone()));
            router = router.layer(Extension(gateway_channel_cache.clone()));
        }

        // Add connection point store if available (needed for OOB connections and delete)
        if let Some(cp_store) = &connection_point_store {
            router = router.layer(Extension(cp_store.clone()));
        }
        // Also expose it as an Option so read handlers (e.g. list_gateways status
        // derivation) can extract it even when connection points are unconfigured.
        router = router.layer(Extension(connection_point_store.clone()));

        // Add mediator store if available (needed for OOB connections)
        if let Some(med_store) = &mediator_store {
            router = router.layer(Extension(med_store.clone()));
        }

        if let (Some(sess_mgr), Some(user_storage)) = (gateway_session_mgr.as_ref(), gateway_user_storage.as_ref()) {
            router = router
                .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
                .layer(Extension(sess_mgr.clone()))
                .layer(Extension(user_storage.clone()))
                .layer(Extension(rbac_config.clone()));
        }

        // Add didwebvh log storage and identity store for OOB connections that use did:webvh
        #[cfg(feature = "didwebvh")]
        {
            router = router
                .layer(Extension(
                    state
                        .didwebvh_log_storage
                        .clone(),
                ))
                .layer(Extension(
                    state
                        .didwebvh_identity_store
                        .clone(),
                ));
        }

        // Add ping route only if we have listener manager
        if let Some(listener_mgr) = &listener_manager {
            router =
                router
                    .route(
                        "/v1/gateways/{id}/ping",
                        gate(
                            post(crate::gateways::handlers::ping_gateway::<crate::gateways::FileSystemGatewayStore>),
                            Feature::GatewaysEdit,
                        ),
                    )
                    .route(
                        "/v1/gateways/{id}/issuer",
                        gate(
                            post(
                                crate::gateways::handlers::request_gateway_issuer::<
                                    crate::gateways::FileSystemGatewayStore,
                                >,
                            )
                            .delete(
                                crate::gateways::handlers::forget_gateway_issuer::<
                                    crate::gateways::FileSystemGatewayStore,
                                >,
                            ),
                            Feature::GatewaysEdit,
                        ),
                    )
                    .route(
                        "/v1/gateways/{id}/trusted-issuers",
                        gate(
                            post(
                                crate::gateways::handlers::add_trusted_issuer::<
                                    crate::gateways::FileSystemGatewayStore,
                                >,
                            ),
                            Feature::GatewaysEdit,
                        ),
                    )
                    .route(
                        "/v1/gateways/{id}/trusted-issuers/{issuer_did}",
                        gate(
                            axum::routing::delete(
                                crate::gateways::handlers::remove_trusted_issuer::<
                                    crate::gateways::FileSystemGatewayStore,
                                >,
                            ),
                            Feature::GatewaysEdit,
                        ),
                    )
                    .route(
                        "/v1/gateways/{id}/surfaces",
                        gate(
                            get(crate::gateways::handlers::get_gateway_surfaces::<
                                crate::gateways::FileSystemGatewayStore,
                            >),
                            Feature::GatewaysView,
                        ),
                    )
                    .route(
                        "/v1/gateways/payment-providers",
                        gate(
                            get(crate::gateways::handlers::list_payment_gateways::<
                                crate::gateways::FileSystemGatewayStore,
                            >),
                            Feature::GatewaysView,
                        ),
                    )
                    .route(
                        "/v1/gateways/{id}/exposed-surfaces",
                        gate(
                            put(crate::gateways::handlers::update_gateway_exposed_surfaces::<
                                crate::gateways::FileSystemGatewayStore,
                            >),
                            Feature::GatewaysEdit,
                        ),
                    )
                    .route(
                        "/v1/gateways/refresh-surfaces",
                        gate(
                            post(
                                crate::gateways::handlers::refresh_gateway_surfaces_cache::<
                                    crate::gateways::FileSystemGatewayStore,
                                >,
                            ),
                            Feature::GatewaysEdit,
                        ),
                    )
                    .layer(Extension(store.clone()))
                    .layer(Extension(Some(listener_mgr.clone())))
                    .layer(Extension(gateway_channel_cache.clone()))
                    .layer(Extension(state.bootstrap_config.clone()))
                    .layer(Extension(
                        state
                            .agent_surface_store
                            .clone(),
                    ));
        }

        // Add approve route only if we have listener manager, connection point store, and mediator store
        if let (Some(listener_mgr), Some(cp_store), Some(med_store)) =
            (&listener_manager, &connection_point_store, &mediator_store)
        {
            router = router
                .route(
                    "/v1/gateways/{id}/approve",
                    gate(
                        post(
                            crate::gateways::approve::approve_gateway::<
                                crate::gateways::FileSystemGatewayStore,
                                crate::gateways::FileSystemConnectionPointStore,
                                crate::mediators::FileSystemMediatorStore,
                            >,
                        ),
                        Feature::GatewaysEdit,
                    ),
                )
                .layer(Extension(store.clone()))
                .layer(Extension(cp_store.clone()))
                .layer(Extension(med_store.clone()))
                .layer(Extension(state.vc_issuer.clone()))
                .layer(Extension(state.bootstrap_config.clone()))
                .layer(Extension(state.network_config.clone()))
                .layer(Extension(pending_connection_store.clone()))
                .layer(Extension(Some(listener_mgr.clone())));

            #[cfg(feature = "didwebvh")]
            {
                router = router
                    .layer(Extension(
                        state
                            .didwebvh_log_storage
                            .clone(),
                    ))
                    .layer(Extension(
                        state
                            .didwebvh_identity_store
                            .clone(),
                    ));
            }
        }

        // Add delete route only if we have connection point store and listener manager
        if let (Some(cp_store), Some(listener_mgr)) = (&connection_point_store, &listener_manager) {
            let mut delete_router = Router::new()
                .route(
                    "/v1/gateways/{id}",
                    gate(
                        delete(
                            crate::gateways::handlers::delete_gateway::<
                                crate::gateways::FileSystemGatewayStore,
                                crate::gateways::FileSystemConnectionPointStore,
                            >,
                        ),
                        Feature::GatewaysDelete,
                    ),
                )
                .layer(Extension(store.clone()))
                .layer(Extension(cp_store.clone()))
                .layer(Extension(listener_mgr.clone()))
                .layer(Extension(notification_store.clone()));

            if let (Some(sess_mgr), Some(user_storage)) = (gateway_session_mgr.as_ref(), gateway_user_storage.as_ref())
            {
                delete_router = delete_router
                    .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
                    .layer(Extension(sess_mgr.clone()))
                    .layer(Extension(user_storage.clone()))
                    .layer(Extension(rbac_config.clone()));
            }

            router = router.merge(delete_router);
        }

        router
    } else {
        Router::new()
    };

    // Clone Arc references before moving them into connection_point_router tuple
    // These clones will be used for the mediator router layers
    let connection_point_store_for_mediator = connection_point_store.clone();
    let listener_manager_for_mediator = listener_manager.clone();
    let integration_storage_for_connection_points = integration_storage.clone();
    let surface_store_for_connection_points = state
        .agent_surface_store
        .clone();

    // Create connection point routes if gateway, connection point, and mediator stores are provided
    let connection_point_router =
        if let (Some(pub_store), Some(gw_store), Some(med_store), Some(listener_mgr), Some(msg_store)) =
            (connection_point_store, gateway_store, mediator_store.clone(), listener_manager, message_store)
        {
            let storage_opt = passkey_storage_for_manager.clone();
            let rbac = rbac_config.clone();
            let gate =
                |route: axum::routing::MethodRouter, feature: crate::rbac::Feature| -> axum::routing::MethodRouter {
                    if let Some(storage) = storage_opt.as_ref() {
                        route.layer(crate::auth_manager::middleware::require_feature(
                            storage.clone(),
                            rbac.clone(),
                            feature,
                        ))
                    } else {
                        route
                    }
                };
            let router = Router::new()
                // DID web endpoint for connection points (standard did:web resolution path)
                .route(
                    "/connection-points/{cp_id}/did.json",
                    get(crate::gateways::connection_points::handlers::serve_connection_point_did_document::<
                        crate::gateways::FileSystemConnectionPointStore,
                    >),
                )
                // did:webvh log endpoint for connection points
                .route(
                    "/connection-points/{cp_id}/did.jsonl",
                    get(crate::gateways::connection_points::handlers::serve_connection_point_did_jsonl::<
                        crate::gateways::FileSystemConnectionPointStore,
                    >),
                )
                // Also support .well-known variant for compatibility
                .route(
                    "/.well-known/connection-points/{cp_id}/did.json",
                    get(crate::gateways::connection_points::handlers::serve_connection_point_did_document::<
                        crate::gateways::FileSystemConnectionPointStore,
                    >),
                )
                // did:webvh log endpoint (.well-known variant)
                .route(
                    "/.well-known/connection-points/{cp_id}/did.jsonl",
                    get(crate::gateways::connection_points::handlers::serve_connection_point_did_jsonl::<
                        crate::gateways::FileSystemConnectionPointStore,
                    >),
                )
                .route(
                    "/v1/connection-points",
                    gate(
                        get(crate::gateways::connection_points::handlers::list_connection_points::<
                            crate::gateways::FileSystemConnectionPointStore,
                        >),
                        crate::rbac::Feature::GatewaysView,
                    ),
                )
                .route(
                    "/v1/connection-points",
                    gate(
                        post(
                            crate::gateways::connection_points::handlers::create_connection_point::<
                                crate::gateways::FileSystemConnectionPointStore,
                                crate::gateways::FileSystemGatewayStore,
                                crate::mediators::FileSystemMediatorStore,
                            >,
                        ),
                        crate::rbac::Feature::GatewaysEdit,
                    ),
                )
                .route(
                    "/v1/connection-points/{id}",
                    gate(
                        get(crate::gateways::connection_points::handlers::get_connection_point::<
                            crate::gateways::FileSystemConnectionPointStore,
                        >),
                        crate::rbac::Feature::GatewaysView,
                    ),
                )
                .route(
                    "/v1/connection-points/{id}",
                    gate(
                        put(crate::gateways::connection_points::handlers::update_connection_point::<
                            crate::gateways::FileSystemConnectionPointStore,
                        >),
                        crate::rbac::Feature::GatewaysEdit,
                    ),
                )
                .route(
                    "/v1/connection-points/{id}",
                    gate(
                        delete(
                            crate::gateways::connection_points::handlers::delete_connection_point::<
                                crate::gateways::FileSystemConnectionPointStore,
                            >,
                        ),
                        crate::rbac::Feature::GatewaysDelete,
                    ),
                )
                .route(
                    "/v1/connection-points/{id}/use",
                    gate(
                        post(
                            crate::gateways::connection_points::handlers::use_connection_point::<
                                crate::gateways::FileSystemConnectionPointStore,
                            >,
                        ),
                        crate::rbac::Feature::GatewaysEdit,
                    ),
                )
                .route(
                    "/v1/connection-points/{id}/exposed-surfaces",
                    gate(
                        put(crate::gateways::connection_points::handlers::update_connection_point_exposed_channels::<
                            crate::gateways::FileSystemConnectionPointStore,
                        >),
                        crate::rbac::Feature::GatewaysEdit,
                    ),
                )
                .route(
                    "/v1/connection-points/{id}/messages",
                    gate(
                        get(crate::gateways::connection_points::handlers::get_connection_point_messages),
                        crate::rbac::Feature::GatewaysView,
                    ),
                )
                .route(
                    "/v1/connection-points/{id}/messages/{message_id}",
                    gate(
                        get(crate::gateways::connection_points::handlers::get_connection_point_message),
                        crate::rbac::Feature::GatewaysView,
                    ),
                )
                .route(
                    "/v1/connection-points/{id}/messages/{message_id}/read",
                    gate(
                        post(crate::gateways::connection_points::handlers::mark_message_read),
                        crate::rbac::Feature::GatewaysEdit,
                    ),
                )
                .route(
                    "/v1/connection-points/{id}/messages/{message_id}",
                    gate(
                        delete(crate::gateways::connection_points::handlers::delete_message),
                        crate::rbac::Feature::GatewaysEdit,
                    ),
                )
                .route(
                    "/v1/connection-points/{id}/messages/unread-count",
                    gate(
                        get(crate::gateways::connection_points::handlers::get_unread_message_count),
                        crate::rbac::Feature::GatewaysView,
                    ),
                )
                .route(
                    "/v1/connection-points/{id}/metrics",
                    gate(
                        get(crate::gateways::connection_points::handlers::get_connection_point_metrics),
                        crate::rbac::Feature::GatewaysView,
                    ),
                )
                .route(
                    "/v1/connection-points/{id}/reconnect",
                    gate(
                        post(
                            crate::gateways::connection_points::handlers::reconnect_connection_point::<
                                crate::gateways::FileSystemConnectionPointStore,
                                crate::mediators::FileSystemMediatorStore,
                            >,
                        ),
                        crate::rbac::Feature::GatewaysEdit,
                    ),
                )
                .route(
                    "/v1/gateways/{gateway_id}/connection-points",
                    gate(
                        get(crate::gateways::connection_points::handlers::list_gateway_connection_points::<
                            crate::gateways::FileSystemConnectionPointStore,
                        >),
                        crate::rbac::Feature::GatewaysView,
                    ),
                )
                .layer(Extension(pub_store))
                .layer(Extension(gw_store))
                .layer(Extension(med_store))
                .layer(Extension(state.vc_issuer.clone()))
                .layer(Extension(state.config.clone()))
                .layer(Extension(state.bootstrap_config.clone()))
                .layer(Extension(state.network_config.clone()))
                .layer(Extension(listener_mgr))
                .layer(Extension(msg_store))
                .layer(Extension(integration_storage_for_connection_points))
                .layer(Extension(surface_store_for_connection_points))
                .layer(Extension(notification_store.clone()));

            #[cfg(feature = "didwebvh")]
            let router = router
                .layer(Extension(
                    state
                        .didwebvh_log_storage
                        .clone(),
                ))
                .layer(Extension(
                    state
                        .didwebvh_identity_store
                        .clone(),
                ));

            router
        } else {
            Router::new()
        };

    let management_gate = |route: axum::routing::MethodRouter,
                           feature: crate::rbac::Feature|
     -> axum::routing::MethodRouter {
        if let Some(storage) = passkey_storage_for_manager.as_ref() {
            route.layer(crate::auth_manager::middleware::require_feature(storage.clone(), rbac_config.clone(), feature))
        } else {
            route
        }
    };

    // Create mediator routes if store is provided
    let mediator_router = if let Some(store) = mediator_store {
        Router::new()
            .route(
                "/v1/mediators",
                management_gate(
                    get(crate::mediators::handlers::list_mediators::<crate::mediators::FileSystemMediatorStore>),
                    crate::rbac::Feature::MediatorsView,
                ),
            )
            .route(
                "/v1/mediators",
                management_gate(
                    post(crate::mediators::handlers::create_mediator::<crate::mediators::FileSystemMediatorStore>),
                    crate::rbac::Feature::MediatorsEdit,
                ),
            )
            .route(
                "/v1/mediators/compatible",
                management_gate(
                    get(crate::mediators::handlers::list_compatible_mediators::<
                        crate::mediators::FileSystemMediatorStore,
                    >),
                    crate::rbac::Feature::MediatorsView,
                ),
            )
            .route(
                "/v1/mediators/check-auth",
                management_gate(
                    post(crate::mediators::handlers::check_auth_compatibility),
                    crate::rbac::Feature::MediatorsEdit,
                ),
            )
            .route(
                "/v1/mediators/{id}",
                management_gate(
                    get(crate::mediators::handlers::get_mediator::<crate::mediators::FileSystemMediatorStore>),
                    crate::rbac::Feature::MediatorsView,
                ),
            )
            .route(
                "/v1/mediators/{id}",
                management_gate(
                    put(crate::mediators::handlers::update_mediator::<crate::mediators::FileSystemMediatorStore>),
                    crate::rbac::Feature::MediatorsEdit,
                ),
            )
            .route(
                "/v1/mediators/{id}",
                management_gate(
                    delete(crate::mediators::handlers::delete_mediator::<crate::mediators::FileSystemMediatorStore>),
                    crate::rbac::Feature::MediatorsDelete,
                ),
            )
            .route(
                "/v1/mediators/{id}/trust-ping",
                management_gate(
                    post(crate::mediators::handlers::trust_ping_mediator::<crate::mediators::FileSystemMediatorStore>),
                    crate::rbac::Feature::MediatorsEdit,
                ),
            )
            .layer(Extension(store))
            .layer(Extension(state.vc_issuer.clone()))
            .layer(Extension(notification_store.clone()))
            .layer(Extension(connection_point_store_for_mediator.clone()))
            .layer(Extension(listener_manager_for_mediator.clone()))
    } else {
        Router::new()
    };

    // Reuse the agents-api TR listener manager for issuer trust registry registration
    let issuer_tr_listener_manager = agents_api_listener_manager;

    // Create issuer routes if store is provided. Legacy `/v1/departments*`
    // paths are still registered below on `legacy_department_router` where
    // they return `308 Permanent Redirect` to their `/v1/issuers*`
    // counterparts (with a deprecation WARN logged per hit).
    let issuer_router = if let Some(store) = issuer_store {
        let mut r = Router::new()
            .route(
                "/v1/issuers",
                management_gate(
                    get(crate::issuers::handlers::list_issuers::<crate::issuers::FileSystemIssuerStore>),
                    crate::rbac::Feature::IssuersView,
                ),
            )
            .route(
                "/v1/issuers",
                management_gate(
                    post(crate::issuers::handlers::create_issuer::<crate::issuers::FileSystemIssuerStore>),
                    crate::rbac::Feature::IssuersEdit,
                ),
            )
            .route(
                "/v1/issuers/{id}",
                management_gate(
                    get(crate::issuers::handlers::get_issuer::<crate::issuers::FileSystemIssuerStore>),
                    crate::rbac::Feature::IssuersView,
                ),
            )
            .route(
                "/v1/issuers/{id}",
                management_gate(
                    put(crate::issuers::handlers::update_issuer::<crate::issuers::FileSystemIssuerStore>),
                    crate::rbac::Feature::IssuersEdit,
                ),
            )
            .route(
                "/v1/issuers/{id}",
                management_gate(
                    delete(crate::issuers::handlers::delete_issuer::<crate::issuers::FileSystemIssuerStore>),
                    crate::rbac::Feature::IssuersDelete,
                ),
            )
            .route(
                "/v1/issuers/{id}/register-trust-registry",
                management_gate(
                    post(
                        crate::issuers::handlers::retry_issuer_tr_registration::<crate::issuers::FileSystemIssuerStore>,
                    ),
                    crate::rbac::Feature::IssuersEdit,
                ),
            );

        // Migration endpoint — only available when didwebvh feature is enabled
        #[cfg(feature = "didwebvh")]
        {
            r = r.route(
                "/v1/admin/issuers/migrate-to-webvh",
                management_gate(
                    post(crate::issuers::handlers::migrate_issuers_to_webvh::<crate::issuers::FileSystemIssuerStore>),
                    crate::rbac::Feature::IssuersEdit,
                ),
            );
        }

        r.layer(Extension(store))
            .layer(Extension(state.vc_issuer.clone()))
            .layer(Extension(state.bootstrap_config.clone()))
            .layer(Extension(issuer_tr_listener_manager))
            .layer(Extension(
                state
                    .didwebvh_log_storage
                    .clone(),
            ))
    } else {
        Router::new()
    };

    // Legacy `/v1/departments*` routes — deprecated aliases for `/v1/issuers*`.
    // Every hit returns `308 Permanent Redirect` to the canonical `/v1/issuers*`
    // path (preserving `{id}` substitution and query string) and logs one WARN
    // per hit so operators can migrate their API clients.
    let legacy_department_router = {
        use axum::routing::{MethodRouter, any};
        fn legacy() -> MethodRouter {
            any(legacy_v1_department_308_handler)
        }
        Router::new()
            .route("/v1/departments", legacy())
            .route("/v1/departments/{id}", legacy())
            .route("/v1/departments/{id}/register-trust-registry", legacy())
            .route("/v1/admin/departments/migrate-to-webvh", legacy())
    };

    // Create authority routes if store is provided
    let authority_router = if let Some(store) = authority_store {
        Router::new()
            .route(
                "/v1/authorities",
                management_gate(
                    get(crate::authorities::handlers::list_authorities::<crate::authorities::FileSystemAuthorityStore>),
                    crate::rbac::Feature::AuthoritiesView,
                ),
            )
            .route(
                "/v1/authorities",
                management_gate(
                    post(
                        crate::authorities::handlers::create_authority::<crate::authorities::FileSystemAuthorityStore>,
                    ),
                    crate::rbac::Feature::AuthoritiesEdit,
                ),
            )
            .route(
                "/v1/authorities/{id}",
                management_gate(
                    get(crate::authorities::handlers::get_authority::<crate::authorities::FileSystemAuthorityStore>),
                    crate::rbac::Feature::AuthoritiesView,
                ),
            )
            .route(
                "/v1/authorities/{id}",
                management_gate(
                    put(crate::authorities::handlers::update_authority::<crate::authorities::FileSystemAuthorityStore>),
                    crate::rbac::Feature::AuthoritiesEdit,
                ),
            )
            .route(
                "/v1/authorities/{id}",
                management_gate(
                    delete(
                        crate::authorities::handlers::delete_authority::<crate::authorities::FileSystemAuthorityStore>,
                    ),
                    crate::rbac::Feature::AuthoritiesDelete,
                ),
            )
            .layer(Extension(store))
    } else {
        Router::new()
    };

    // Create MCP Proxy routes if store is provided
    let mcp_proxy_router = if let Some(store) = mcp_proxy_store {
        Router::new()
            .route(
                "/v1/mcp-proxies",
                management_gate(
                    get(crate::mcp_proxies::handlers::list_mcp_proxies::<crate::mcp_proxies::FileSystemMcpProxyStore>),
                    crate::rbac::Feature::McpProxiesView,
                ),
            )
            .route(
                "/v1/mcp-proxies",
                management_gate(
                    post(crate::mcp_proxies::handlers::create_mcp_proxy::<crate::mcp_proxies::FileSystemMcpProxyStore>),
                    crate::rbac::Feature::McpProxiesEdit,
                ),
            )
            .route(
                "/v1/mcp-proxies/validate",
                management_gate(
                    post(crate::mcp_proxies::handlers::validate_openapi_spec),
                    crate::rbac::Feature::McpProxiesEdit,
                ),
            )
            .route(
                "/v1/mcp-proxies/{id}",
                management_gate(
                    get(crate::mcp_proxies::handlers::get_mcp_proxy::<crate::mcp_proxies::FileSystemMcpProxyStore>),
                    crate::rbac::Feature::McpProxiesView,
                ),
            )
            .route(
                "/v1/mcp-proxies/{id}",
                management_gate(
                    put(crate::mcp_proxies::handlers::update_mcp_proxy::<crate::mcp_proxies::FileSystemMcpProxyStore>),
                    crate::rbac::Feature::McpProxiesEdit,
                ),
            )
            .route(
                "/v1/mcp-proxies/{id}",
                management_gate(
                    delete(
                        crate::mcp_proxies::handlers::delete_mcp_proxy::<crate::mcp_proxies::FileSystemMcpProxyStore>,
                    ),
                    crate::rbac::Feature::McpProxiesDelete,
                ),
            )
            .route(
                "/v1/mcp-proxies/discover-tools",
                management_gate(
                    management_gate(
                        post(
                            crate::mcp_proxies::handlers::discover_mcp_tools::<
                                crate::mcp_proxies::FileSystemMcpProxyStore,
                            >,
                        ),
                        crate::rbac::Feature::SecretsView,
                    ),
                    crate::rbac::Feature::McpProxiesEdit,
                ),
            )
            .layer(Extension(store))
            .layer(Extension(mcp_server_manager))
            .layer(Extension(secrets_store.clone()))
            .layer(Extension(notification_store.clone()))
            .layer(Extension(resource_owners.clone()))
    } else {
        Router::new()
    };

    // Create A2A Proxy routes if store is provided
    let a2a_proxy_router = if let Some(store) = a2a_proxy_store {
        if let Some(auth_storage) = passkey_storage_for_manager.as_ref() {
            use crate::auth_manager::middleware::require_feature;
            use crate::rbac::Feature;
            let s = auth_storage.clone();
            let r = rbac_config.clone();
            Router::new()
                .route(
                    "/v1/a2a-proxies",
                    get(crate::a2a_proxies::handlers::list_a2a_proxies::<crate::a2a_proxies::FileSystemA2aProxyStore>)
                        .layer(require_feature(s.clone(), r.clone(), Feature::A2aProxiesView)),
                )
                .route(
                    "/v1/a2a-proxies",
                    post(crate::a2a_proxies::handlers::create_a2a_proxy::<crate::a2a_proxies::FileSystemA2aProxyStore>)
                        .layer(require_feature(s.clone(), r.clone(), Feature::A2aProxiesEdit)),
                )
                .route(
                    "/v1/a2a-proxies/{id}",
                    get(crate::a2a_proxies::handlers::get_a2a_proxy::<crate::a2a_proxies::FileSystemA2aProxyStore>)
                        .layer(require_feature(s.clone(), r.clone(), Feature::A2aProxiesView)),
                )
                .route(
                    "/v1/a2a-proxies/{id}",
                    put(crate::a2a_proxies::handlers::update_a2a_proxy::<crate::a2a_proxies::FileSystemA2aProxyStore>)
                        .layer(require_feature(s.clone(), r.clone(), Feature::A2aProxiesEdit)),
                )
                .route(
                    "/v1/a2a-proxies/{id}",
                    delete(
                        crate::a2a_proxies::handlers::delete_a2a_proxy::<crate::a2a_proxies::FileSystemA2aProxyStore>,
                    )
                    .layer(require_feature(s, r, Feature::A2aProxiesDelete)),
                )
                .layer(Extension(store))
                .layer(Extension(secrets_store.clone()))
        } else {
            build_a2a_proxy_router_unauthenticated(store, secrets_store.clone())
        }
    } else {
        Router::new()
    };

    // Create integration routes if storage is provided
    let integration_router = match integration_storage {
        Some(storage) => crate::storage::integration_handlers::integration_router(
            storage,
            passkey_storage_for_manager
                .as_ref()
                .map(|auth_storage| {
                    crate::auth_manager::middleware::RbacGuard::new(auth_storage.clone(), rbac_config.clone())
                }),
            state.config.clone(),
            state.bootstrap_config.clone(),
        ),
        None => Router::new(),
    };

    // Create user integrations routes
    let user_integrations_router = {
        use crate::auth_manager::middleware::require_feature;
        use crate::rbac::Feature;
        let storage_opt = passkey_storage_for_manager.clone();
        let rbac = rbac_config.clone();
        let gate = |route: axum::routing::MethodRouter, feature: Feature| -> axum::routing::MethodRouter {
            if let Some(auth_storage) = storage_opt.as_ref() {
                route.layer(require_feature(auth_storage.clone(), rbac.clone(), feature))
            } else {
                route
            }
        };
        Router::new()
            .route(
                "/v1/users/integrations",
                gate(
                    get(crate::integrations::user_integrations_handlers::get_user_integrations),
                    Feature::IntegrationsView,
                ),
            )
            .route(
                "/v1/users/integrations",
                gate(
                    put(crate::integrations::user_integrations_handlers::update_user_integrations),
                    Feature::IntegrationsEdit,
                ),
            )
            .layer(Extension(state.bootstrap_config.clone()))
    };

    // Create identity integrations routes
    let identity_integrations_router = {
        use crate::auth_manager::middleware::require_feature;
        use crate::rbac::Feature;
        let storage_opt = passkey_storage_for_manager.clone();
        let rbac = rbac_config.clone();
        let gate = |mr: axum::routing::MethodRouter, feat: Feature| -> axum::routing::MethodRouter {
            if let Some(s) = storage_opt.as_ref() {
                mr.layer(require_feature(s.clone(), rbac.clone(), feat))
            } else {
                mr.layer(axum::middleware::from_fn(crate::auth_manager::middleware::deny_unguarded_request))
            }
        };
        Router::new()
            .route(
                "/v1/identities/integrations",
                gate(
                    get(crate::integrations::identity_integrations_handlers::get_identity_integrations),
                    Feature::IntegrationsView,
                ),
            )
            .route(
                "/v1/identities/integrations",
                gate(
                    put(crate::integrations::identity_integrations_handlers::update_identity_integrations),
                    Feature::IntegrationsEdit,
                ),
            )
            .layer(Extension(state.bootstrap_config.clone()))
    };

    // Create trust registry routes if store is provided
    let trust_registry_router = if let Some(store) = trust_registry_store {
        use crate::auth_manager::middleware::require_feature;
        use crate::rbac::Feature;
        let storage_opt = passkey_storage_for_manager.clone();
        let rbac = rbac_config.clone();
        let gate = |mr: axum::routing::MethodRouter, feat: Feature| -> axum::routing::MethodRouter {
            if let Some(s) = storage_opt.as_ref() {
                mr.layer(require_feature(s.clone(), rbac.clone(), feat))
            } else {
                mr.layer(axum::middleware::from_fn(crate::auth_manager::middleware::deny_unguarded_request))
            }
        };
        let tr_listener_manager = trust_registry_listener_manager;

        let router = Router::new()
            .route(
                "/trust-registries/{tr_id}/did.json",
                get(crate::trust_registries::handlers::serve_trust_registry_did_document::<
                    crate::trust_registries::FileSystemTrustRegistryStore,
                >),
            )
            .route(
                "/.well-known/trust-registries/{tr_id}/did.json",
                get(crate::trust_registries::handlers::serve_trust_registry_did_document::<
                    crate::trust_registries::FileSystemTrustRegistryStore,
                >),
            );

        #[cfg(feature = "didwebvh")]
        let router = router.route(
            "/trust-registries/{tr_id}/did.jsonl",
            get(crate::trust_registries::handlers::serve_trust_registry_did_jsonl::<
                crate::trust_registries::FileSystemTrustRegistryStore,
            >),
        );

        #[cfg(feature = "didwebvh")]
        let router = router.route(
            "/trust-registries/{tr_id}/did-witness.json",
            get(crate::trust_registries::handlers::serve_trust_registry_did_witness::<
                crate::trust_registries::FileSystemTrustRegistryStore,
            >),
        );

        let mut router = router
            .route(
                "/v1/trust-registries",
                gate(
                    get(crate::trust_registries::handlers::list_trust_registries::<
                        crate::trust_registries::FileSystemTrustRegistryStore,
                    >),
                    Feature::TrustRegistriesView,
                ),
            )
            .route(
                "/v1/trust-registries",
                gate(
                    post(
                        crate::trust_registries::handlers::create_trust_registry::<
                            crate::trust_registries::FileSystemTrustRegistryStore,
                        >,
                    ),
                    Feature::TrustRegistriesEdit,
                ),
            )
            .route(
                "/v1/trust-registries/{id}",
                gate(
                    get(crate::trust_registries::handlers::get_trust_registry::<
                        crate::trust_registries::FileSystemTrustRegistryStore,
                    >),
                    Feature::TrustRegistriesView,
                ),
            )
            .route(
                "/v1/trust-registries/{id}",
                gate(
                    put(crate::trust_registries::handlers::update_trust_registry::<
                        crate::trust_registries::FileSystemTrustRegistryStore,
                    >),
                    Feature::TrustRegistriesEdit,
                ),
            )
            .route(
                "/v1/trust-registries/{id}",
                gate(
                    delete(
                        crate::trust_registries::handlers::delete_trust_registry::<
                            crate::trust_registries::FileSystemTrustRegistryStore,
                        >,
                    ),
                    Feature::TrustRegistriesDelete,
                ),
            )
            .route(
                "/v1/trust-registries/{id}/list-records",
                gate(
                    post(
                        crate::trust_registries::handlers::list_trust_registry_records::<
                            crate::trust_registries::FileSystemTrustRegistryStore,
                        >,
                    ),
                    Feature::TrustRegistriesView,
                ),
            )
            .route(
                "/v1/trust-registries/{id}/reconnect",
                gate(
                    post(
                        crate::trust_registries::handlers::reconnect_trust_registry::<
                            crate::trust_registries::FileSystemTrustRegistryStore,
                        >,
                    ),
                    Feature::TrustRegistriesEdit,
                ),
            )
            .route("/v1/trust-check/predefined-queries", get(handlers::list_predefined_trust_check_queries))
            .layer(Extension(notification_store.clone()))
            .layer(Extension(store))
            .layer(Extension(state.bootstrap_config.clone()))
            .layer(Extension(Some(
                dashboard_state
                    .ws_state
                    .clone(),
            )));

        if let Some(listener_mgr) = tr_listener_manager {
            router = router.layer(Extension(listener_mgr));
        }

        if let Some(w) = trust_registry_worker {
            router = router.layer(Extension(w));
        }

        router
    } else {
        Router::new()
    };

    // Create notification routes if store is provided
    let notification_router = if let Some(store) = notification_store {
        let router =
            Router::new()
                .route(
                    "/v1/notifications",
                    get(crate::integrations::handlers::list_notifications::<
                        crate::integrations::FileSystemNotificationStore,
                    >),
                )
                .route(
                    "/v1/notifications",
                    post(
                        crate::integrations::handlers::create_notification::<
                            crate::integrations::FileSystemNotificationStore,
                        >,
                    ),
                )
                .route(
                    "/v1/notifications/{id}",
                    get(crate::integrations::handlers::get_notification::<
                        crate::integrations::FileSystemNotificationStore,
                    >),
                )
                .route(
                    "/v1/notifications/{id}",
                    put(crate::integrations::handlers::update_notification::<
                        crate::integrations::FileSystemNotificationStore,
                    >),
                )
                .route(
                    "/v1/notifications/{id}",
                    delete(
                        crate::integrations::handlers::delete_notification::<
                            crate::integrations::FileSystemNotificationStore,
                        >,
                    ),
                )
                .route(
                    "/v1/notifications/unread/count",
                    get(crate::integrations::handlers::get_unread_count::<
                        crate::integrations::FileSystemNotificationStore,
                    >),
                )
                .route(
                    "/v1/notifications/user-welcome-template",
                    get(crate::integrations::handlers::get_user_welcome_template::<
                        crate::integrations::FileSystemNotificationStore,
                    >),
                )
                .route(
                    "/v1/notifications/user-welcome-template",
                    put(crate::integrations::handlers::set_user_welcome_template::<
                        crate::integrations::FileSystemNotificationStore,
                    >),
                )
                .route(
                    "/v1/notifications/send-welcome",
                    post(
                        crate::integrations::handlers::send_user_welcome::<
                            crate::integrations::FileSystemNotificationStore,
                        >,
                    ),
                )
                .layer(Extension(store));

        // Add session manager if available (works for both Passkey and SAML modes)
        if let Some(sess_mgr) = &session_manager_for_manager {
            router.layer(Extension(sess_mgr.clone()))
        } else {
            router
        }
    } else {
        Router::new()
    };

    let cors_origins = state
        .network_config
        .cors
        .clone();
    let origins = cors_origins
        .into_iter()
        .map(|origin| {
            origin
                .parse::<HeaderValue>()
                .unwrap()
        })
        .collect::<Vec<HeaderValue>>();

    // Merge the routers - API routes first to ensure they match before fallback
    let didwebvh_router = create_didwebvh_router(
        state.clone(),
        passkey_storage_for_manager
            .as_ref()
            .map(|storage| (storage.clone(), rbac_config.clone())),
    );

    // Build the session manager extension for global auth middleware
    let session_mgr_for_global_auth: Option<std::sync::Arc<crate::auth::session::SessionManager>> =
        session_manager_for_manager.clone();

    // Build the STS (RFC 8693 token exchange + ID-JAG) sub-router. Client
    // managed-connections are empty until the dashboard store lands in a later
    // phase; the endpoints, discovery, and JWKS are live and client-authenticated
    // (exempt from dashboard session auth via the `/oauth2/` public-path prefix).
    let sts_router = crate::sts::handlers::build_sts_router(
        sts_vc_issuer,
        sts_jwks_client,
        sts_strategy_store,
        sts_client_store,
        sts_secrets_store,
        sts_gateway_policy_manager,
        sts_trust_registry_listener_manager,
        resource_owners.clone(),
        crate::sts::handlers::StsConfig {
            // Advertise absolute RFC 8414 discovery URLs under the gateway's
            // configured public origin (inbound `external_urls`) rather than the
            // request `Host`, which behind a terminating HTTP proxy/tunnel is the
            // internal `127.0.0.1:PORT`. Falls back to request-derived when unset.
            public_base_url: state
                .network_config
                .get_inbound_external_urls()
                .into_iter()
                .next(),
            replay_backend: state
                .network_config
                .sts
                .replay_protection
                .backend
                .clone(),
            throttle: state
                .network_config
                .sts
                .token_endpoint_throttle
                .clone(),
            mcp_issuer: state
                .network_config
                .sts
                .mcp_issuer
                .clone(),
            mcp_replay,
            ..crate::sts::handlers::StsConfig::default()
        },
    );

    let mut app = Router::new()
        .merge(didwebvh_router)
        .merge(gateway_router)
        .merge(connection_point_router)
        .merge(mediator_router)
        .merge(issuer_router)
        .merge(legacy_department_router)
        .merge(authority_router)
        .merge(mcp_proxy_router)
        .merge(a2a_proxy_router)
        .merge(integration_router)
        .merge(user_integrations_router)
        .merge(identity_integrations_router)
        .merge(trust_registry_router)
        .merge(notification_router)
        .merge(auth_manager_router)
        .merge(terms_router)
        .merge(rbac_identity_router)
        .merge(oidc_provider_router)
        .merge(sts_admin_router)
        .merge(identity_router)
        .merge(sts_router)
        .merge(auth_router)
        .merge(dashboard_router)
        .layer(axum::middleware::from_fn(crate::observability::trace_http_request));

    // Mount the x402 admin API inside the identity router so it inherits the
    // same global `require_session_auth` layer. Routes become
    // `/api/admin/x402/...` once the identity router is nested at `/api`.
    if let Some(admin_router) = x402_admin_router {
        info!("Merging x402 Admin API router at /admin/x402 (protected by global session auth + payments.view)");
        let admin_router = match passkey_storage_for_manager.as_ref() {
            Some(storage) => admin_router.layer(crate::auth_manager::middleware::require_feature(
                storage.clone(),
                rbac_config.clone(),
                crate::rbac::Feature::PaymentsView,
            )),
            None => {
                admin_router.layer(axum::middleware::from_fn(crate::auth_manager::middleware::deny_unguarded_request))
            }
        };
        app = app.nest("/admin", admin_router);
    }

    // Mount the MPP admin API the same way; routes become `/api/admin/mpp/...`.
    // Also gated on `payments.view` — these routes expose full MPP transaction
    // records (payer, amount, method), which the dashboard already restricts by
    // permission, so the backend must enforce it too rather than relying on
    // session auth alone.
    if let Some(admin_router) = mpp_admin_router {
        info!("Merging MPP Admin API router at /admin/mpp (protected by global session auth + payments.view)");
        let admin_router = match passkey_storage_for_manager.as_ref() {
            Some(storage) => admin_router.layer(crate::auth_manager::middleware::require_feature(
                storage.clone(),
                rbac_config.clone(),
                crate::rbac::Feature::PaymentsView,
            )),
            None => {
                admin_router.layer(axum::middleware::from_fn(crate::auth_manager::middleware::deny_unguarded_request))
            }
        };
        app = app.nest("/admin", admin_router);
    }

    // Apply global session auth middleware when a session manager is available
    if let Some(sess_mgr) = session_mgr_for_global_auth {
        info!("Global session auth middleware enabled for all protected API routes");
        let guard_state = crate::auth_manager::middleware::AuthGuardState::new(
            sess_mgr,
            passkey_storage_for_manager.clone(),
            terms_manager,
        )
        .with_pat_authenticator(pat_authenticator)
        .with_trusted_tenant_header(
            state
                .bootstrap_config
                .tenancy
                .trusted_tenant_header
                .clone()
                .map(std::sync::Arc::new),
        );
        app = app.layer(axum::middleware::from_fn_with_state(
            guard_state,
            crate::auth_manager::middleware::require_session_auth,
        ));
    } else {
        info!("No session manager available - global session auth middleware NOT enabled");
    }

    let app = app
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("frame-ancestors 'none'"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ));

    app.layer(
        CorsLayer::new()
            .allow_methods(Any)
            .allow_origin(AllowOrigin::async_predicate(
                |origin: HeaderValue, _request_parts: &RequestParts| async move {
                    if origins.is_empty() {
                        // Do not allow any origins if none are configured.
                        // This will only work for the same origin, i.e. hosted directly from the AG.
                        return false;
                    }
                    debug!("Checking CORS origin: {:?} against allowed origins: {:?}", origin, origins);
                    origins.contains(&origin)
                },
            ))
            .allow_headers([AUTHORIZATION, CONTENT_TYPE]),
    )
    // Serve avatar files with proper MIME types and cache control
    .nest_service(
        "/avatars",
        Router::new()
            .fallback_service(
                ServeDir::new(avatars_path)
                    .precompressed_gzip()
                    .precompressed_br(),
            )
            .layer(SetResponseHeaderLayer::if_not_present(
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            )),
    )
}

/// Create a separate router for DID resolution routes at root level
/// These routes need to be at the root level for did:web resolution
pub fn create_did_router(
    state: IdentityApiState,
    issuer_store: Option<std::sync::Arc<crate::issuers::FileSystemIssuerStore>>,
    trust_registry_store: Option<std::sync::Arc<crate::trust_registries::FileSystemTrustRegistryStore>>,
) -> Router {
    let router = Router::new()
        .route("/.well-known/did.json", get(handlers::serve_gateway_did_document))
        // Spec-required path: did:webvh:SCID:host → https://host/.well-known/did/did.jsonl
        .route("/.well-known/did/did.jsonl", get(handlers::serve_gateway_did_jsonl))
        // Legacy path kept for backwards compatibility
        .route("/.well-known/did.jsonl", get(handlers::serve_gateway_did_jsonl))
        // Empty witness-proofs document — the did:webvh resolver fetches this
        // alongside did.jsonl; without a route it falls through to the SPA.
        .route("/.well-known/did-witness.json", get(handlers::serve_gateway_did_witness))
        .route("/surface/{surface_id}/did.json", get(handlers::serve_agent_did_document))
        .route("/surface/{surface_id}/did.jsonl", get(handlers::serve_surface_did_jsonl))
        .route("/surface/{surface_id}/did-witness.json", get(handlers::serve_surface_did_witness));

    // NOTE: Root-level /{*path} catch-all for spec-standard DID-to-HTTPS URLs
    // is NOT added here — it would intercept all requests (static assets, API, etc.)
    // and break the SPA. Instead, DID catch-all is wired as a fallback wrapper
    // in proxy/server.rs, so it only fires when no other route matches.

    // Save bootstrap_config before state is moved into .with_state()
    let issuer_bootstrap_config = state.bootstrap_config.clone();
    let tr_bootstrap_config = state.bootstrap_config.clone();
    #[cfg(feature = "didwebvh")]
    let tr_log_storage = state
        .didwebvh_log_storage
        .clone();

    let mut router = router
        .layer(Extension(state.vc_issuer.clone()))
        .layer(Extension(state.bootstrap_config.clone()))
        .layer(Extension(state.network_config.clone()))
        .with_state(state);

    // Issuer DID document endpoint (unauthenticated — did:web resolution).
    // Legacy `/departments/{id}/did.{json,jsonl}` paths return 308 to their
    // `/issuers/{id}/did.*` counterparts so existing published DIDs shaped
    // `did:{web,webvh}:{domain}:departments:{uuid}` continue to resolve.
    if let Some(store) = issuer_store {
        router = router.merge(
            Router::new()
                .route(
                    "/issuers/{id}/did.json",
                    get(crate::issuers::handlers::serve_issuer_did_document::<crate::issuers::FileSystemIssuerStore>),
                )
                .route(
                    "/issuers/{id}/did.jsonl",
                    get(crate::issuers::handlers::serve_issuer_did_jsonl::<crate::issuers::FileSystemIssuerStore>),
                )
                // Legacy paths — 308 redirects with deprecation WARN
                .route("/departments/{id}/did.json", axum::routing::any(legacy_department_did_308_handler))
                .route("/departments/{id}/did.jsonl", axum::routing::any(legacy_department_did_308_handler))
                .layer(Extension(store))
                .layer(Extension(issuer_bootstrap_config)),
        );
    }

    // Trust registry DID resolution endpoints (unauthenticated — did:web/did:webvh resolution)
    if let Some(tr_store) = trust_registry_store {
        let tr_router = Router::new().route(
            "/trust-registries/{tr_id}/did.json",
            get(crate::trust_registries::handlers::serve_trust_registry_did_document::<
                crate::trust_registries::FileSystemTrustRegistryStore,
            >),
        );

        #[cfg(feature = "didwebvh")]
        let tr_router = tr_router.route(
            "/trust-registries/{tr_id}/did.jsonl",
            get(crate::trust_registries::handlers::serve_trust_registry_did_jsonl::<
                crate::trust_registries::FileSystemTrustRegistryStore,
            >),
        );

        #[cfg(feature = "didwebvh")]
        let tr_router = tr_router.route(
            "/trust-registries/{tr_id}/did-witness.json",
            get(crate::trust_registries::handlers::serve_trust_registry_did_witness::<
                crate::trust_registries::FileSystemTrustRegistryStore,
            >),
        );

        let mut tr_router = tr_router
            .layer(Extension(tr_store))
            .layer(Extension(tr_bootstrap_config));

        #[cfg(feature = "didwebvh")]
        if let Some(log_storage) = tr_log_storage {
            tr_router = tr_router.layer(Extension(log_storage));
        }

        router = router.merge(tr_router);
    }

    router
}

#[cfg(feature = "didwebvh")]
pub fn create_didwebvh_router(
    state: IdentityApiState,
    rbac: Option<(Arc<crate::auth::storage::PasskeyStorage>, Arc<crate::rbac::RbacConfig>)>,
) -> Router {
    use crate::identity::didwebvh::DidWebVhApiState;
    use tracing::info;

    // Create DID:webvh API state if available
    if let (Some(identity_store), Some(log_storage), Some(base_url)) = (
        state
            .didwebvh_identity_store
            .clone(),
        state
            .didwebvh_log_storage
            .clone(),
        state
            .didwebvh_base_url
            .clone(),
    ) {
        let didwebvh_state = DidWebVhApiState {
            identity_store,
            log_storage,
            base_url,
        };

        info!("✓ DID:webvh API routes registered at /v1/identities");

        // Identity management reads and writes the DID key material and can transfer
        // or deactivate any identity, so the whole group is gated. DID resolution
        // below stays public: it serves the published DID document.
        let management = Router::new()
            .route("/v1/identities", post(crate::identity::didwebvh::create_identity))
            .route("/v1/identities", get(crate::identity::didwebvh::list_identities))
            .route("/v1/identities/{id}", get(crate::identity::didwebvh::get_identity))
            .route("/v1/identities/{id}", delete(crate::identity::didwebvh::delete_identity))
            .route("/v1/identities/{id}/update", post(crate::identity::didwebvh::update_identity))
            .route("/v1/identities/{id}/rotate-keys", post(crate::identity::didwebvh::rotate_keys))
            .route("/v1/identities/{id}/transfer", post(crate::identity::didwebvh::transfer_ownership))
            .route("/v1/identities/{id}/history", get(crate::identity::didwebvh::get_identity_history))
            .route("/v1/identities/{id}/policy", put(crate::identity::didwebvh::update_policy_config))
            .route("/v1/identities/{id}/policy", get(crate::identity::didwebvh::get_policy_config));

        let management = match rbac {
            Some((storage, rbac_config)) => management.layer(crate::auth_manager::middleware::require_feature(
                storage,
                rbac_config,
                crate::rbac::Feature::IdentityIssue,
            )),
            None => {
                management.layer(axum::middleware::from_fn(crate::auth_manager::middleware::deny_unguarded_request))
            }
        };

        management
            .route("/v1/resolve", get(crate::identity::didwebvh::resolve_did))
            .route("/v1/verify/{did}", post(crate::identity::didwebvh::verify_identity))
            .route("/dids/{*path}", get(crate::identity::didwebvh::serve_did_log))
            .with_state(didwebvh_state)
    } else {
        tracing::debug!("DID:webvh API routes NOT registered - stores not available");
        Router::new()
    }
}

#[cfg(not(feature = "didwebvh"))]
pub fn create_didwebvh_router(
    _state: IdentityApiState,
    _rbac: Option<(Arc<crate::auth::storage::PasskeyStorage>, Arc<crate::rbac::RbacConfig>)>,
) -> Router {
    Router::new()
}

/// Create a separate router for onboarding routes only
/// These routes need to be at the root level (/) for external client access
pub fn create_onboarding_router(state: IdentityApiState) -> Router {
    Router::new()
        .route("/onboard/{uuid}/.well-known/agent-card.json", get(handlers::serve_onboarding_agent_card))
        .route("/onboard/{uuid}/rpc", post(handlers::handle_onboarding_message))
        .route("/onboard/{uuid}/", post(handlers::handle_onboarding_message))
        .route("/onboard/{uuid}", post(handlers::handle_onboarding_message))
        .with_state(state)
}

#[cfg(test)]
mod a2a_proxy_gating_tests {
    use super::build_a2a_proxy_router_unauthenticated;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn store() -> std::sync::Arc<crate::a2a_proxies::FileSystemA2aProxyStore> {
        let dir = tempfile::tempdir().expect("tempdir");
        std::sync::Arc::new(
            crate::a2a_proxies::FileSystemA2aProxyStore::new(dir.path().to_path_buf())
                .await
                .expect("build a2a proxy store"),
        )
    }

    #[tokio::test]
    async fn no_auth_backend_refuses_create_and_update_but_allows_read() {
        let router = build_a2a_proxy_router_unauthenticated(store().await, None);

        // create (POST) is not mounted → 405, so an unauthenticated caller cannot set base_url.
        let create = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/a2a-proxies")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::METHOD_NOT_ALLOWED, "create must be refused with no auth backend");

        // update (PUT) is not mounted → 405.
        let update = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/a2a-proxies/some-id")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(update.status(), StatusCode::METHOD_NOT_ALLOWED, "update must be refused with no auth backend");

        // read (GET list) stays available.
        let list = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/a2a-proxies")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list.status(), StatusCode::OK, "list must remain available");
    }
}
