use crate::auth::session::{SessionManager, TermsSessionGate};
use crate::auth::session_cookie;
use crate::auth::storage::PasskeyStorage;
use crate::auth::types::UserStatus;
use axum::{
    Extension, Json,
    extract::{Request, State},
    http::{Method, StatusCode, header::SET_COOKIE},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Paths that are exempt from session authentication.
/// These include auth flows, health checks, protocol endpoints, and public resources.
const PUBLIC_EXACT_PATHS: &[&str] =
    &["/v1/terms/applicable", "/api/v1/terms/applicable", "/v1/terms/provider-health", "/api/v1/terms/provider-health"];
const CONSENT_PENDING_PATHS: &[&str] = &[
    "/v1/terms/applicable",
    "/api/v1/terms/applicable",
    "/v1/terms/status",
    "/api/v1/terms/status",
    "/v1/terms/acceptances",
    "/api/v1/terms/acceptances",
    "/auth/check",
    "/api/auth/check",
    "/auth/logout",
    "/api/auth/logout",
    "/saml/logout",
    "/api/saml/logout",
];

/// Paths where a personal access token only inspects itself, so its resource-scope
/// headers are not evaluated. Token authentication and revocation still apply.
const TOKEN_SELF_INSPECTION_PATHS: &[&str] = &["/v1/token-info", "/api/v1/token-info"];

const PUBLIC_PATH_PREFIXES: &[&str] = &[
    "/auth/",                    // Passkey auth flows
    "/saml/",                    // SAML auth flows
    "/internal/test-support/",   // Internal UI-test auth bootstrap
    "/v1/auth/",                 // Auth mode endpoint
    "/v1/alive",                 // Liveness check
    "/v1/health",                // Readiness check
    "/v1/version",               // Version check
    "/v1/permissions/public",    // Public permissions for registration
    "/v1/metrics/prometheus",    // Prometheus scraping
    "/didcomm",                  // DIDComm protocol endpoints
    "/onboard/",                 // Agent onboarding (external access)
    "/agents-api/v1/verify-jwt", // JWT verification is read-only and safe to expose
    "/agents-api/v1/onboard",    // Agent onboarding (self-registration)
    "/.well-known/",             // DID resolution / well-known
    "/connection-points/",       // DID web resolution for connection points
    "/dids/",                    // DID:webvh log serving
    "/ws",                       // WebSocket (has its own auth handling)
    "/api/ws",                   // WebSocket when nested under /api prefix
    "/avatars/",                 // Static avatar files
    "/surface/",                 // DID web resolution for channels (did.json)
    "/v1/identity/resolve-did",  // DID document resolution (public, like /.well-known/)
    "/v1/resolve",               // DID:webvh resolution (public — no auth required for DID lookup)
    "/api/v1/resolve",           // Same, when identity API is nested under /api prefix
    "/oauth2/",                  // STS token exchange + JWKS (client-authenticated, not session)
    "/api/oauth2/",              // Same, when identity API is nested under /api prefix
];

/// Returns true if the given path is considered public and should bypass session auth.
fn is_public_path(path: &str) -> bool {
    PUBLIC_EXACT_PATHS.contains(&path)
        || PUBLIC_PATH_PREFIXES
            .iter()
            .any(|prefix| path.starts_with(prefix))
}

/// Extract session token from the request's Authorization header or cookies.
/// Priority: Authorization Bearer header > `session_token` cookie.
fn extract_session_token(request: &Request) -> Option<String> {
    extract_session_token_from_headers(request.headers())
}

/// Public helper: extract session token from request headers only.
/// Priority: Authorization Bearer header > `session_token` cookie.
///
/// Tokens are deliberately never read from the URL query string: a token in the
/// URL leaks into access logs, `Referer` headers, browser history, and proxy
/// caches. Callers must supply the token via the `Authorization` header or the
/// HttpOnly `session_token` cookie.
pub fn extract_session_token_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    // 1. Try Authorization header first (preferred — avoids token leaking into logs/URLs)
    if let Some(auth_header) = headers.get(axum::http::header::AUTHORIZATION)
        && let Ok(auth_str) = auth_header.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        let token = token.trim();
        if !token.is_empty() {
            return Some(token.to_string());
        }
    }

    // 2. Fall back to cookie (SAML mode sets HttpOnly session_token cookie)
    if let Some(cookie_header) = headers.get(axum::http::header::COOKIE)
        && let Ok(cookie_str) = cookie_header.to_str()
    {
        for cookie in cookie_str.split(';') {
            let parts: Vec<&str> = cookie
                .trim()
                .splitn(2, '=')
                .collect();
            if parts.len() == 2 && parts[0] == "session_token" && !parts[1].is_empty() {
                return Some(parts[1].to_string());
            }
        }
    }

    None
}

/// Combined state required by the global session-auth middleware.
///
/// Holds the session manager (for token validation) and, when available,
/// the passkey/user storage so the middleware can additionally reject
/// requests whose underlying user account has been disabled or removed.
/// The storage is optional to keep test wiring and minimal deployments
/// simple — when `None`, the status check is skipped.
#[derive(Clone)]
pub struct AuthGuardState {
    pub session_manager: Arc<SessionManager>,
    pub user_storage: Option<Arc<PasskeyStorage>>,
    pub pat_authenticator: Option<Arc<dyn crate::auth_manager::pat::PatAuthenticator>>,
    pub terms_manager: Arc<crate::terms::TermsManager>,
    /// Trusted-edge tenant-header assertion. `None` (default) means a broad
    /// PAT tenant selector fails closed at auth time.
    pub trusted_tenant_header: Option<Arc<crate::tenancy::TrustedTenantHeader>>,
}

/// Marker inserted by `require_session_auth` after a successful validation
/// so downstream middlewares (`extract_user_id`) can short-circuit and avoid
/// re-running `validate_session` (which also writes to disk) plus the user
/// status lookup on every authenticated request. The wrapped id is the
/// authenticated user id, readable by handlers for attribution.
#[derive(Clone)]
pub struct AuthGuardOk(pub String);

impl AuthGuardState {
    pub fn new(
        session_manager: Arc<SessionManager>,
        user_storage: Option<Arc<PasskeyStorage>>,
        terms_manager: Arc<crate::terms::TermsManager>,
    ) -> Self {
        Self {
            session_manager,
            user_storage,
            pat_authenticator: None,
            terms_manager,
            trusted_tenant_header: None,
        }
    }

    pub fn with_pat_authenticator(
        mut self,
        authenticator: Option<Arc<dyn crate::auth_manager::pat::PatAuthenticator>>,
    ) -> Self {
        self.pat_authenticator = authenticator;
        self
    }

    /// Configure the trusted-edge tenant-header assertion. When set, a broad
    /// PAT tenant selector for that header is honored; otherwise it fails
    /// closed at auth time.
    pub fn with_trusted_tenant_header(
        mut self,
        trusted_tenant_header: Option<Arc<crate::tenancy::TrustedTenantHeader>>,
    ) -> Self {
        self.trusted_tenant_header = trusted_tenant_header;
        self
    }
}

fn terms_required_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(crate::terms::TermsErrorBody {
            code: "TERMS_ACCEPTANCE_REQUIRED".to_string(),
            required_terms: None,
        }),
    )
        .into_response()
}

/// Global middleware that requires a valid session for all non-public API routes.
/// Public paths (auth flows, health, DIDComm, onboarding, etc.) are exempt.
/// Must be applied via `axum::middleware::from_fn_with_state(AuthGuardState, require_session_auth)`.
#[allow(clippy::result_large_err)] // FIXME: Response is not an error
pub async fn require_session_auth(
    State(state): State<AuthGuardState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    let path = request
        .uri()
        .path()
        .to_string();

    let supplied_session_token = extract_session_token(&request);

    if is_public_path(&path) {
        debug!("require_session_auth: public path {}, skipping auth", path);
        return Ok(next.run(request).await);
    }

    let session_token = match supplied_session_token {
        Some(token) => token,
        None => {
            warn!("require_session_auth: no session_token for protected path {}", path);
            return Err(StatusCode::UNAUTHORIZED.into_response());
        }
    };

    if let Some(session) = state
        .session_manager
        .validate_session_record(&session_token)
        .await
    {
        let user_id = session.user_id.clone();
        if let Some(storage) = state.user_storage.as_ref()
            && !user_is_approved(storage, &user_id).await
        {
            warn!("require_session_auth: session valid but user_id={} is not Approved — rejecting {}", user_id, path);
            return Err(StatusCode::UNAUTHORIZED.into_response());
        }

        if session.terms_gate == TermsSessionGate::ConsentPending && !CONSENT_PENDING_PATHS.contains(&path.as_str()) {
            let status = state
                .terms_manager
                .status(&user_id, crate::terms::AcceptanceContext::Login)
                .await
                .map_err(IntoResponse::into_response)?;
            if status.consent_required {
                return Err(terms_required_response());
            }
        }

        let mut request = request;
        request
            .extensions_mut()
            .insert(AuthGuardOk(user_id));
        if let Some(storage) = state.user_storage.clone() {
            request
                .extensions_mut()
                .insert(storage);
        }
        let mut response = next.run(request).await;
        if let Ok(value) = session_cookie::build_session_cookie(
            &session_token,
            state
                .session_manager
                .timeout_seconds(),
        )
        .parse()
        {
            response
                .headers_mut()
                .append(SET_COOKIE, value);
        }
        return Ok(response);
    }

    if let Some(authenticator) = state
        .pat_authenticator
        .as_ref()
        && let Some(principal) = authenticator
            .authenticate(&session_token)
            .await
    {
        if let Some(storage) = state.user_storage.as_ref()
            && !user_is_approved(storage, &principal.user_id).await
        {
            warn!(
                "require_session_auth: access token valid but bound user_id={} is not Approved — rejecting {}",
                principal.user_id, path
            );
            return Err(StatusCode::UNAUTHORIZED.into_response());
        }

        let status = state
            .terms_manager
            .status(&principal.user_id, crate::terms::AcceptanceContext::Login)
            .await
            .map_err(IntoResponse::into_response)?;
        if status.consent_required {
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "code": "TERMS_ACCEPTANCE_REQUIRED",
                    "message": "Sign in to Agent Gateway as this access token's owner, accept the required Terms and Conditions, then retry."
                })),
            ).into_response());
        }

        let resource_scoped = principal
            .resource_scope
            .is_some();
        let scope_evaluation = match principal
            .resource_scope
            .as_ref()
        {
            Some(scope) if !TOKEN_SELF_INSPECTION_PATHS.contains(&path.as_str()) => {
                match scope.evaluate(request.headers()) {
                    Ok(scope) => scope,
                    Err(rejection) => {
                        warn!(
                            token_id = %principal.token_id,
                            path = %path,
                            reason = %rejection.message(),
                            "Access-token resource scope rejected request"
                        );
                        return Err(StatusCode::FORBIDDEN.into_response());
                    }
                }
            }
            _ => crate::auth_manager::resource_scope::ScopeEvaluation { pattern: None, tenant_id: None },
        };

        // Fail closed for an already-issued broad (multi-valued) tenant selector
        // unless a trusted, edge-authenticated proxy owns the header. A broad
        // selector lets the bearer pick the tenant per request; header presence
        // alone is not trust. An exact selector is always permitted — its
        // anchored regex admits only one value.
        if let Some(selector) = principal
            .resource_scope
            .as_ref()
            .and_then(|scope| scope.tenant_selector())
            && !crate::tenancy::header_derived_tenant_permitted(
                selector,
                state
                    .trusted_tenant_header
                    .as_deref(),
            )
        {
            warn!(
                token_id = %principal.token_id,
                path = %path,
                header = %selector.header_name,
                "PAT tenant selector is broad and no trusted edge is configured — failing closed"
            );
            return Err(StatusCode::FORBIDDEN.into_response());
        }

        if let Some(tenant_id) = scope_evaluation
            .tenant_id
            .as_deref()
            && crate::tenancy::validate_tenant_id(tenant_id).is_err()
        {
            return Err(StatusCode::FORBIDDEN.into_response());
        }

        let tenant_context = scope_evaluation
            .tenant_id
            .as_ref()
            .map(|tenant_id| crate::tenancy::PatTenantContext {
                token_id: principal.token_id.clone(),
                tenant_id: tenant_id.clone(),
            });

        if let Some(regex) = scope_evaluation
            .pattern
            .as_ref()
        {
            use crate::auth_manager::pat::{PathScope, classify_resource_path};

            let is_read = matches!(*request.method(), Method::GET | Method::HEAD | Method::OPTIONS);
            match classify_resource_path(&path) {
                PathScope::EnforceId { kind, id }
                    if !crate::tenancy::scope_allows_resource(
                        Some(&crate::auth_manager::pat::PatResourceScope(regex.clone())),
                        tenant_context.as_ref(),
                        kind,
                        &id,
                    ) =>
                {
                    return Err(if is_read {
                        StatusCode::NOT_FOUND.into_response()
                    } else {
                        StatusCode::FORBIDDEN.into_response()
                    });
                }
                PathScope::Unscoped if !is_read => return Err(StatusCode::FORBIDDEN.into_response()),
                PathScope::DenyScoped => {
                    return Err(if is_read {
                        StatusCode::NOT_FOUND.into_response()
                    } else {
                        StatusCode::FORBIDDEN.into_response()
                    });
                }
                _ => {}
            }
        }

        let mut request = request;
        request
            .extensions_mut()
            .insert(AuthGuardOk(principal.user_id));
        request
            .extensions_mut()
            .insert(crate::auth_manager::pat::PatContext(principal.scopes));
        request
            .extensions_mut()
            .insert(crate::auth_manager::pat::PatDelegationContext {
                token_id: principal.token_id,
                delegation_depth: principal.delegation_depth,
                resource_scoped,
            });
        if let Some(tenant_context) = tenant_context {
            request
                .extensions_mut()
                .insert(tenant_context);
        }
        if let Some(regex) = scope_evaluation.pattern {
            request
                .extensions_mut()
                .insert(crate::auth_manager::pat::PatResourceScope(regex));
        }
        if let Some(storage) = state.user_storage.clone() {
            request
                .extensions_mut()
                .insert(storage);
        }
        return Ok(next.run(request).await);
    }

    warn!("require_session_auth: invalid/expired session for {}", path);
    Err(StatusCode::UNAUTHORIZED.into_response())
}

/// Middleware that extracts user_id from session token and adds it as an Extension.
///
/// Fast path: if `require_session_auth` has already validated the request and
/// stored an `AuthGuardOk` marker in the extensions, reuse that user_id and skip
/// the (otherwise duplicated) session_manager + user_storage round-trip.
pub async fn extract_user_id(
    Extension(session_manager): Extension<Arc<SessionManager>>,
    Extension(user_storage): Extension<Arc<PasskeyStorage>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let user_id = if let Some(AuthGuardOk(id)) = request
        .extensions()
        .get::<AuthGuardOk>()
    {
        id.clone()
    } else {
        // Extract session token using the shared helper (header > query param > cookie)
        let session_token = extract_session_token(&request).ok_or(StatusCode::UNAUTHORIZED)?;

        debug!("extract_user_id Validating session token: {}...", &session_token[..session_token.len().min(8)]);
        let (_username, user_id) = session_manager
            .validate_session(&session_token)
            .await
            .ok_or(StatusCode::UNAUTHORIZED)?;

        // Defense-in-depth: reject if user is no longer Approved.
        if !user_is_approved(&user_storage, &user_id).await {
            warn!("extract_user_id: session valid but user_id={} is not Approved", user_id);
            return Err(StatusCode::UNAUTHORIZED);
        }
        user_id
    };

    info!("extract_user_id OK");
    request
        .extensions_mut()
        .insert(user_id);

    Ok(next.run(request).await)
}

/// Returns true when the user record exists and has `UserStatus::Approved`.
/// Any other state (New, Disabled, missing, or storage error) is treated
/// as not approved — the safer choice for an auth gate.
pub(crate) async fn user_is_approved(
    storage: &PasskeyStorage,
    user_id: &str,
) -> bool {
    match storage
        .load_user_by_id(user_id)
        .await
    {
        Ok(Some(u)) => u.status == UserStatus::Approved,
        Ok(None) => {
            warn!("user_is_approved: user_id={} not found in storage", user_id);
            false
        }
        Err(e) => {
            warn!("user_is_approved: failed to load user_id={}: {}", user_id, e);
            false
        }
    }
}

/// Build a route-level layer that enforces RBAC against a specific `Feature`.
///
/// Designed to be applied via `.route_layer(require_feature(...))` so a single
/// route can be gated without changing the handler signature. The layer reads
/// the `AuthGuardOk` marker set by the global `require_session_auth`, loads
/// the user's role from `PasskeyStorage`, and consults `RbacConfig`.
///
/// Fail-closed contract:
///   - missing `AuthGuardOk` (e.g. global session guard not applied)  → 401
///   - storage load error                                              → 500
///   - user not found / role not permitted                             → 403
///
/// This is the bulk-gating tool for the HIGH-severity mutating endpoints
/// (findings H1–H18 except H17).
/// Shared state captured by `require_feature` so it can be threaded through
/// `from_fn_with_state` (which requires `Clone + Send + Sync + 'static`).
#[derive(Clone)]
pub struct FeatureGuard {
    pub storage: Arc<PasskeyStorage>,
    pub rbac_config: Arc<crate::rbac::RbacConfig>,
    pub feature: crate::rbac::Feature,
}

/// Route-level RBAC middleware that enforces `Feature` permission before the
/// handler runs.
///
/// Mount-time: pass into `MethodRouter::layer(...)`. Returns 401 when the
/// request lacks the `AuthGuardOk` marker (global session guard not applied),
/// 403 when the caller lacks the feature, 500 on storage error.
///
/// This is the bulk-gating tool for the HIGH-severity mutating endpoints
/// (findings H1–H18 except H17).
pub fn require_feature(
    storage: Arc<PasskeyStorage>,
    rbac_config: Arc<crate::rbac::RbacConfig>,
    feature: crate::rbac::Feature,
) -> FeatureGuardLayer {
    axum::middleware::from_fn_with_state(FeatureGuard { storage, rbac_config, feature }, feature_guard_middleware)
}

/// Concrete return type of `require_feature`. Aliased to silence
/// `clippy::type_complexity` and to give callers a stable name.
pub type FeatureGuardLayer = axum::middleware::FromFnLayer<
    fn(
        State<FeatureGuard>,
        Request,
        Next,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>>,
    FeatureGuard,
    (State<FeatureGuard>, Request),
>;

fn feature_guard_middleware(
    State(guard): State<FeatureGuard>,
    request: Request,
    next: Next,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>> {
    Box::pin(async move {
        let user_id = match request
            .extensions()
            .get::<AuthGuardOk>()
        {
            Some(AuthGuardOk(id)) => id.clone(),
            None => {
                warn!(feature = ?guard.feature, "require_feature: no AuthGuardOk on request — global session guard not applied");
                return Err(StatusCode::UNAUTHORIZED);
            }
        };
        match guard
            .storage
            .load_user_by_id(&user_id)
            .await
        {
            Ok(Some(user)) => {
                if !guard
                    .rbac_config
                    .has_permission(&user.role, &guard.feature)
                {
                    warn!(
                        user_id = %user_id,
                        role = ?user.role,
                        feature = ?guard.feature,
                        "require_feature: RBAC rejected — insufficient permissions"
                    );
                    return Err(StatusCode::FORBIDDEN);
                }
            }
            Ok(None) => {
                warn!(user_id = %user_id, feature = ?guard.feature, "require_feature: user not found");
                return Err(StatusCode::FORBIDDEN);
            }
            Err(e) => {
                warn!(user_id = %user_id, feature = ?guard.feature, error = %e, "require_feature: failed to load user");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }

        if !pat_scope_allows(
            request
                .extensions()
                .get::<crate::auth_manager::pat::PatContext>(),
            &guard.feature,
        ) {
            warn!(feature = ?guard.feature, "require_feature: access-token scope excludes permission");
            return Err(StatusCode::FORBIDDEN);
        }
        Ok(next.run(request).await)
    })
}

/// An access token restricted to explicit scopes allows only those scopes;
/// a session or an unrestricted token defers to the caller's role.
pub(crate) fn pat_scope_allows(
    pat: Option<&crate::auth_manager::pat::PatContext>,
    feature: &crate::rbac::Feature,
) -> bool {
    match pat {
        Some(crate::auth_manager::pat::PatContext(Some(scopes))) => scopes
            .iter()
            .any(|scope| scope == feature.as_str()),
        _ => true,
    }
}

/// Packaged storage + RBAC config so router factories can accept a single
/// `Option<RbacGuard>` and conditionally gate mutating routes. Built once
/// at orchestrator wiring time, cloned per route via `.gate(...)`.
#[derive(Clone)]
pub struct RbacGuard {
    pub storage: Arc<PasskeyStorage>,
    pub rbac_config: Arc<crate::rbac::RbacConfig>,
}

impl RbacGuard {
    pub fn new(
        storage: Arc<PasskeyStorage>,
        rbac_config: Arc<crate::rbac::RbacConfig>,
    ) -> Self {
        Self { storage, rbac_config }
    }

    /// Wrap a `MethodRouter` with a `require_feature` layer. The handler
    /// signature is unchanged; per-route gating keeps reads ungated.
    pub fn gate<S>(
        &self,
        mr: axum::routing::MethodRouter<S>,
        feature: crate::rbac::Feature,
    ) -> axum::routing::MethodRouter<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        mr.layer(require_feature(self.storage.clone(), self.rbac_config.clone(), feature))
    }

    /// Whether the authenticated user holds `feature`, honouring the scopes of
    /// the access token the request used. An unknown user holds nothing.
    pub async fn allows(
        &self,
        user_id: &str,
        pat: Option<&crate::auth_manager::pat::PatContext>,
        feature: crate::rbac::Feature,
    ) -> anyhow::Result<bool> {
        let Some(user) = self
            .storage
            .load_user_by_id(user_id)
            .await?
        else {
            return Ok(false);
        };
        Ok(self
            .rbac_config
            .has_permission(&user.role, &feature)
            && pat_scope_allows(pat, &feature))
    }
}

/// Refuses every request to a protected route that was mounted without an RBAC
/// guard. Without a guard there is no principal to authorise, so serving the
/// route would be an unauthenticated grant.
pub(crate) async fn deny_unguarded_request(
    request: Request,
    _next: Next,
) -> Response {
    warn!(
        path = %request.uri().path(),
        "Denying request to a protected route that was mounted without an RBAC guard"
    );
    (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "forbidden"}))).into_response()
}

/// Gates a `MethodRouter` on `feature` when an `RbacGuard` is supplied, and
/// denies every request when it is `None`.
pub fn maybe_gate<S>(
    guard: Option<&RbacGuard>,
    mr: axum::routing::MethodRouter<S>,
    feature: crate::rbac::Feature,
) -> axum::routing::MethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    match guard {
        Some(g) => g.gate(mr, feature),
        None => {
            // No guard means no way to authorise, so the protected route must not serve.
            mr.layer(axum::middleware::from_fn(deny_unguarded_request))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, routing::get};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tower::ServiceExt;

    /// Dummy handler that returns 200 OK — used to verify middleware behaviour.
    async fn ok_handler() -> &'static str {
        "ok"
    }

    /// Build a minimal router with `require_session_auth` applied globally.
    fn test_app(session_manager: Arc<crate::auth::session::SessionManager>) -> Router {
        Router::new()
            // Protected routes (representative sample)
            .route("/v1/settings", get(ok_handler))
            .route("/v1/surfaces", get(ok_handler))
            .route("/v1/config/reload", get(ok_handler))
            .route("/v1/config/surface-routing", get(ok_handler))
            .route("/v1/config/x402", get(ok_handler))
            .route("/v1/dashboard/stats", get(ok_handler))
            .route("/v1/dashboard/delta", get(ok_handler))
            .route("/v1/dashboard/surface/ch1/ucp-operations", get(ok_handler))
            .route("/v1/dashboard/surface/ch1/metrics", get(ok_handler))
            .route("/v1/gateways", get(ok_handler))
            .route("/v1/gateways/123", get(ok_handler))
            .route("/v1/gateways/refresh-surfaces", get(ok_handler))
            .route("/v1/mcp-proxies", get(ok_handler))
            .route("/v1/mcp-proxies/123", get(ok_handler))
            .route("/v1/integrations", get(ok_handler))
            .route("/v1/integrations/config", get(ok_handler))
            .route("/v1/connection-points/123/messages", get(ok_handler))
            .route("/v1/mediators", get(ok_handler))
            .route("/v1/departments", get(ok_handler))
            .route("/v1/issuers", get(ok_handler))
            .route("/v1/trust-registries", get(ok_handler))
            .route("/v1/notifications", get(ok_handler))
            .route("/v1/users", get(ok_handler))
            .route("/v1/users/u1", get(ok_handler))
            .route("/v1/profile", get(ok_handler))
            .route("/v1/permissions", get(ok_handler))
            .route("/v1/token-info", get(ok_handler))
            .route("/v1/identities", get(ok_handler))
            .route("/v1/identities/id1/policy", get(ok_handler))
            .route("/v1/secrets", get(ok_handler))
            .route("/v1/apikeys", get(ok_handler))
            .route("/v1/certificates", get(ok_handler))
            .route("/v1/identity/resolve-did", get(ok_handler))
            .route("/v1/metrics/config", get(ok_handler))
            .route("/v1/agents", get(ok_handler))
            .route("/v1/onboard/create-temp-surface", get(ok_handler))
            .route("/v1/gateway/config", get(ok_handler))
            .route("/agents-api/v1/sign-jwt", get(ok_handler))
            // Public routes
            .route("/auth/register/start", get(ok_handler))
            .route("/auth/login/start", get(ok_handler))
            .route("/auth/check", get(ok_handler))
            .route("/auth/logout", get(ok_handler))
            .route("/auth/cli/authorize", get(ok_handler))
            .route("/auth/cli/consent", get(ok_handler))
            .route("/auth/cli/exchange", get(ok_handler))
            .route("/saml/login", get(ok_handler))
            .route("/saml/acs", get(ok_handler))
            .route("/saml/metadata", get(ok_handler))
            .route("/v1/auth/mode", get(ok_handler))
            .route("/v1/terms/provider-health", get(ok_handler))
            .route("/v1/health", get(ok_handler))
            .route("/v1/version", get(ok_handler))
            .route("/v1/permissions/public", get(ok_handler))
            .route("/v1/metrics/prometheus", get(ok_handler))
            .route("/didcomm", get(ok_handler))
            .route("/didcomm/ws", get(ok_handler))
            .route("/internal/test-support/auth/login", get(ok_handler))
            .route("/onboard/uuid1/rpc", get(ok_handler))
            .route("/agents-api/v1/onboard", get(ok_handler))
            .route("/agents-api/v1/verify-jwt", get(ok_handler))
            .route("/.well-known/did.json", get(ok_handler))
            .route("/connection-points/cp1/did.json", get(ok_handler))
            .route("/dids/something", get(ok_handler))
            .route("/avatars/user.png", get(ok_handler))
            .route("/surface/ch1/did.json", get(ok_handler))
            .layer(axum::middleware::from_fn_with_state(
                AuthGuardState::new(session_manager, None, std::sync::Arc::new(crate::terms::TermsManager::disabled())),
                require_session_auth,
            ))
    }

    /// Helper: send a GET request to the given path (no session token).
    async fn get_status(
        app: &Router,
        path: &str,
    ) -> u16 {
        let req = axum::http::Request::builder()
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let resp = app
            .clone()
            .oneshot(req)
            .await
            .unwrap();
        resp.status().as_u16()
    }

    /// Helper: send a GET request with a session_token query parameter.
    async fn get_status_with_token(
        app: &Router,
        path: &str,
        token: &str,
    ) -> u16 {
        let sep = if path.contains('?') {
            "&"
        } else {
            "?"
        };
        let uri = format!("{}{sep}session_token={token}", path);
        let req = axum::http::Request::builder()
            .uri(&uri)
            .body(Body::empty())
            .unwrap();
        let resp = app
            .clone()
            .oneshot(req)
            .await
            .unwrap();
        resp.status().as_u16()
    }

    /// Helper: send a GET request with an Authorization Bearer header.
    async fn get_status_with_bearer(
        app: &Router,
        path: &str,
        token: &str,
    ) -> u16 {
        let req = axum::http::Request::builder()
            .uri(path)
            .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app
            .clone()
            .oneshot(req)
            .await
            .unwrap();
        resp.status().as_u16()
    }

    async fn feature_guard_app(scopes: Vec<String>) -> Router {
        let temp = tempdir().unwrap();
        let storage = Arc::new(
            crate::auth::storage::PasskeyStorage::new(
                temp.path()
                    .join("users")
                    .to_string_lossy()
                    .into_owned(),
                temp.path()
                    .join("avatars")
                    .to_string_lossy()
                    .into_owned(),
            )
            .await
            .unwrap(),
        );
        let now = chrono::Utc::now();
        storage
            .save_user(&crate::auth::storage::UserData {
                user_id: "admin".into(),
                username: "admin".into(),
                passkeys: Vec::new(),
                role: crate::auth::types::UserRole::Administrator,
                status: crate::auth::types::UserStatus::Approved,
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
            .unwrap();

        Router::new()
            .route(
                "/v1/mediators",
                get(ok_handler).layer(require_feature(
                    storage,
                    Arc::new(crate::rbac::RbacConfig::default()),
                    crate::rbac::Feature::MediatorsView,
                )),
            )
            .layer(Extension(crate::auth_manager::pat::PatContext(Some(scopes))))
            .layer(Extension(AuthGuardOk("admin".into())))
    }

    #[tokio::test]
    async fn management_route_guard_intersects_pat_scope_with_user_role() {
        let denied = feature_guard_app(vec!["surfaces.view".into()]).await;
        let allowed = feature_guard_app(vec!["mediators.view".into()]).await;

        assert_eq!(get_status(&denied, "/v1/mediators").await, StatusCode::FORBIDDEN.as_u16());
        assert_eq!(get_status(&allowed, "/v1/mediators").await, StatusCode::OK.as_u16());
    }

    #[tokio::test]
    async fn rbac_guard_allows_combines_role_access_token_scope_and_known_user() {
        use crate::auth_manager::pat::PatContext;
        use crate::rbac::Feature;

        let mut user = mk_user_data("member", "member", UserStatus::Approved);
        user.role = UserRole::User;
        let (storage, _tmp) = make_storage_with_user(user).await;
        let guard = RbacGuard::new(storage, Arc::new(crate::rbac::RbacConfig::default()));
        let scoped = |scopes: &[&str]| {
            PatContext(Some(
                scopes
                    .iter()
                    .map(|scope| scope.to_string())
                    .collect(),
            ))
        };

        assert!(
            guard
                .allows("member", None, Feature::IntegrationsView)
                .await
                .unwrap()
        );
        assert!(
            !guard
                .allows("member", None, Feature::AuditView)
                .await
                .unwrap(),
            "a role below the required one is refused"
        );
        assert!(
            guard
                .allows("member", Some(&PatContext(None)), Feature::IntegrationsView)
                .await
                .unwrap(),
            "an unrestricted token defers to the role"
        );
        assert!(
            !guard
                .allows("member", Some(&scoped(&["surfaces.view"])), Feature::IntegrationsView)
                .await
                .unwrap(),
            "a scoped token refuses permissions outside its scopes"
        );
        assert!(
            guard
                .allows("member", Some(&scoped(&["integrations.view"])), Feature::IntegrationsView)
                .await
                .unwrap()
        );
        assert!(
            !guard
                .allows("ghost", None, Feature::IntegrationsView)
                .await
                .unwrap(),
            "an unknown user holds nothing"
        );
    }

    // ── Protected endpoints must return 401 without a session token ──

    #[tokio::test]
    async fn protected_endpoints_return_401_without_token() {
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let app = test_app(sess_mgr);

        let protected_paths = [
            "/v1/settings",
            "/v1/surfaces",
            "/v1/config/reload",
            "/v1/config/surface-routing",
            "/v1/config/x402",
            "/v1/dashboard/stats",
            "/v1/dashboard/delta",
            "/v1/dashboard/surface/ch1/ucp-operations",
            "/v1/dashboard/surface/ch1/metrics",
            "/v1/gateways",
            "/v1/gateways/123",
            "/v1/gateways/refresh-surfaces",
            "/v1/mcp-proxies",
            "/v1/mcp-proxies/123",
            "/v1/integrations",
            "/v1/integrations/config",
            "/v1/connection-points/123/messages",
            "/v1/mediators",
            "/v1/departments",
            "/v1/issuers",
            "/v1/trust-registries",
            "/v1/notifications",
            "/v1/users",
            "/v1/users/u1",
            "/v1/profile",
            "/v1/permissions",
            "/v1/token-info",
            "/v1/identities",
            "/v1/identities/id1/policy",
            "/v1/secrets",
            "/v1/apikeys",
            "/v1/certificates",
            "/v1/metrics/config",
            "/v1/agents",
            "/v1/onboard/create-temp-surface",
            "/v1/gateway/config",
            "/agents-api/v1/sign-jwt",
        ];

        for path in &protected_paths {
            let status = get_status(&app, path).await;
            assert_eq!(status, 401, "Expected 401 for protected path {path} without token, got {status}");
        }
    }

    // ── Protected endpoints must return 401 with an invalid token ──

    #[tokio::test]
    async fn protected_endpoints_return_401_with_invalid_token() {
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let app = test_app(sess_mgr);

        let sample_paths = [
            "/v1/settings",
            "/v1/dashboard/delta",
            "/v1/dashboard/surface/ch1/ucp-operations",
            "/v1/integrations/config",
            "/v1/secrets",
        ];

        for path in &sample_paths {
            let status = get_status_with_token(&app, path, "bogus-token-xyz").await;
            assert_eq!(status, 401, "Expected 401 for {path} with invalid token, got {status}");
        }
    }

    // ── A token supplied only via the URL query string must be rejected ──
    // Tokens in the URL leak into access logs, Referer headers, browser
    // history, and proxy caches, so the query-string path is not honoured even
    // when the token is otherwise valid. Tokens must arrive via the
    // Authorization header or the HttpOnly session_token cookie.

    #[tokio::test]
    async fn protected_endpoints_reject_valid_token_in_query_param() {
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let token = sess_mgr
            .create_session("test-user".into(), "user-001".into())
            .await;
        let app = test_app(sess_mgr);

        let sample_paths = [
            "/v1/settings",
            "/v1/dashboard/delta",
            "/v1/dashboard/surface/ch1/ucp-operations",
            "/v1/integrations/config",
            "/v1/secrets",
            "/v1/gateways",
            "/v1/surfaces",
        ];

        for path in &sample_paths {
            let status = get_status_with_token(&app, path, &token).await;
            assert_eq!(
                status, 401,
                "Expected 401 for {path} with valid token supplied only via query param, got {status}"
            );
        }
    }

    // ── Public endpoints must return 200 without any token ──

    #[tokio::test]
    async fn public_endpoints_return_200_without_token() {
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let app = test_app(sess_mgr);

        let public_paths = [
            "/auth/register/start",
            "/auth/login/start",
            "/auth/check",
            "/auth/logout",
            "/auth/cli/authorize",
            "/auth/cli/consent",
            "/auth/cli/exchange",
            "/saml/login",
            "/saml/acs",
            "/saml/metadata",
            "/v1/auth/mode",
            "/v1/terms/provider-health",
            "/v1/health",
            "/v1/version",
            "/v1/permissions/public",
            "/v1/metrics/prometheus",
            "/didcomm",
            "/didcomm/ws",
            "/internal/test-support/auth/login",
            "/onboard/uuid1/rpc",
            "/agents-api/v1/onboard",
            "/agents-api/v1/verify-jwt",
            "/.well-known/did.json",
            "/connection-points/cp1/did.json",
            "/dids/something",
            "/avatars/user.png",
            "/surface/ch1/did.json",
        ];

        for path in &public_paths {
            let status = get_status(&app, path).await;
            assert_eq!(status, 200, "Expected 200 for public path {path} without token, got {status}");
        }
    }

    // ── Session token via cookie should also work ──

    #[tokio::test]
    async fn protected_endpoint_accepts_session_cookie() {
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let token = sess_mgr
            .create_session("test-user".into(), "user-001".into())
            .await;
        let app = test_app(sess_mgr);

        let req = axum::http::Request::builder()
            .uri("/v1/settings")
            .header(axum::http::header::COOKIE, format!("session_token={token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app
            .clone()
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "Cookie-based session should be accepted");
    }

    // ── Session token via Authorization Bearer header should work ──

    #[tokio::test]
    async fn protected_endpoint_accepts_authorization_bearer() {
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let token = sess_mgr
            .create_session("test-user".into(), "user-001".into())
            .await;
        let app = test_app(sess_mgr);

        let sample_paths = ["/v1/settings", "/v1/dashboard/delta", "/v1/gateways", "/v1/surfaces"];

        for path in &sample_paths {
            let status = get_status_with_bearer(&app, path, &token).await;
            assert_eq!(status, 200, "Expected 200 for {path} with Bearer token, got {status}");
        }
    }

    #[tokio::test]
    async fn protected_endpoint_rejects_invalid_bearer_token() {
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let app = test_app(sess_mgr);

        let status = get_status_with_bearer(&app, "/v1/settings", "bogus-token").await;
        assert_eq!(status, 401, "Expected 401 for invalid Bearer token");
    }

    // ── status-aware session validation (defense in depth) ──
    // The middleware must reject a request whose session is technically
    // valid but whose underlying user account is no longer Approved
    // (disabled, deleted, or pending re-approval).

    use crate::auth::storage::{PasskeyStorage, UserData};
    use crate::auth::types::{UserRole, UserStatus};

    async fn make_storage_with_user(user: UserData) -> (Arc<PasskeyStorage>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage_path = tmp
            .path()
            .join("passkeys")
            .to_string_lossy()
            .to_string();
        let avatars_path = tmp
            .path()
            .join("avatars")
            .to_string_lossy()
            .to_string();
        let storage = PasskeyStorage::new(storage_path, avatars_path)
            .await
            .expect("storage init");
        storage
            .save_user(&user)
            .await
            .expect("save user");
        (Arc::new(storage), tmp)
    }

    fn mk_user_data(
        user_id: &str,
        username: &str,
        status: UserStatus,
    ) -> UserData {
        let now = chrono::Utc::now();
        UserData {
            user_id: user_id.to_string(),
            username: username.to_string(),
            passkeys: Vec::new(),
            role: UserRole::User,
            status,
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
        }
    }

    /// Build a router whose `require_session_auth` is wired with both a
    /// session manager and a user storage (the production configuration).
    fn test_app_with_storage(
        session_manager: Arc<crate::auth::session::SessionManager>,
        user_storage: Arc<PasskeyStorage>,
    ) -> Router {
        Router::new()
            .route("/v1/settings", get(ok_handler))
            .layer(axum::middleware::from_fn_with_state(
                AuthGuardState::new(
                    session_manager,
                    Some(user_storage),
                    std::sync::Arc::new(crate::terms::TermsManager::disabled()),
                ),
                require_session_auth,
            ))
    }

    #[tokio::test]
    async fn require_session_auth_rejects_disabled_user() {
        let user = mk_user_data("user-disabled-1", "alice", UserStatus::Disabled);
        let (storage, _tmp) = make_storage_with_user(user).await;

        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let token = sess_mgr
            .create_session("alice".into(), "user-disabled-1".into())
            .await;

        let app = test_app_with_storage(sess_mgr, storage);
        let status = get_status_with_bearer(&app, "/v1/settings", &token).await;
        assert_eq!(status, 401, "Disabled user must be rejected even with valid session token");
    }

    #[tokio::test]
    async fn require_session_auth_rejects_new_user() {
        let user = mk_user_data("user-new-1", "bob", UserStatus::New);
        let (storage, _tmp) = make_storage_with_user(user).await;

        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let token = sess_mgr
            .create_session("bob".into(), "user-new-1".into())
            .await;

        let app = test_app_with_storage(sess_mgr, storage);
        let status = get_status_with_bearer(&app, "/v1/settings", &token).await;
        assert_eq!(status, 401, "New (pending) user must be rejected");
    }

    #[tokio::test]
    async fn require_session_auth_rejects_missing_user() {
        // Token exists but no UserData was saved — covers the
        // "user deleted while session still cached" race.
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(
            PasskeyStorage::new(
                tmp.path()
                    .join("passkeys")
                    .to_string_lossy()
                    .to_string(),
                tmp.path()
                    .join("avatars")
                    .to_string_lossy()
                    .to_string(),
            )
            .await
            .expect("storage init"),
        );

        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let token = sess_mgr
            .create_session("ghost".into(), "user-missing-1".into())
            .await;

        let app = test_app_with_storage(sess_mgr, storage);
        let status = get_status_with_bearer(&app, "/v1/settings", &token).await;
        assert_eq!(status, 401, "Session for non-existent user must be rejected");
    }

    #[tokio::test]
    async fn require_session_auth_accepts_approved_user() {
        let user = mk_user_data("user-ok-1", "carol", UserStatus::Approved);
        let (storage, _tmp) = make_storage_with_user(user).await;

        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let token = sess_mgr
            .create_session("carol".into(), "user-ok-1".into())
            .await;

        let app = test_app_with_storage(sess_mgr, storage);
        let status = get_status_with_bearer(&app, "/v1/settings", &token).await;
        assert_eq!(status, 200, "Approved user with valid session must pass");
    }

    struct TermsTestPat;

    #[async_trait::async_trait]
    impl crate::auth_manager::pat::PatAuthenticator for TermsTestPat {
        async fn authenticate(
            &self,
            token: &str,
        ) -> Option<crate::auth_manager::pat::PatPrincipal> {
            (token == "terms-test-pat").then(|| crate::auth_manager::pat::PatPrincipal {
                user_id: "user-1".to_string(),
                scopes: None,
                token_id: "test-token".to_string(),
                delegation_depth: 0,
                resource_scope: None,
            })
        }
    }

    fn terms_test_app(
        sessions: Arc<SessionManager>,
        manager: Arc<crate::terms::TermsManager>,
    ) -> Router {
        Router::new()
            .route("/v1/settings", get(ok_handler))
            .route("/auth/login/start", get(ok_handler))
            .route("/saml/acs", get(ok_handler))
            .route("/v1/terms/status", get(ok_handler))
            .layer(axum::middleware::from_fn_with_state(
                AuthGuardState::new(sessions, None, manager).with_pat_authenticator(Some(Arc::new(TermsTestPat))),
                require_session_auth,
            ))
    }

    #[tokio::test]
    async fn terms_outage_preserves_allowed_sessions_and_public_routes() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path()
                .join("acceptances"),
            b"not a directory",
        )
        .unwrap();
        let manager = Arc::new(
            crate::terms::TermsManager::open(true, "appliance".into(), temp.path().into(), None)
                .await
                .unwrap(),
        );
        let sessions = Arc::new(SessionManager::new());
        let app = terms_test_app(sessions.clone(), manager);
        for (gate, expected) in [
            (TermsSessionGate::AllowedAtLogin, 200),
            (TermsSessionGate::LegacyAllowed, 200),
            (TermsSessionGate::ConsentPending, 503),
        ] {
            let token = sessions
                .create_session_with_terms_gate("alice".into(), "user-1".into(), gate)
                .await;
            assert_eq!(get_status_with_bearer(&app, "/v1/settings", &token).await, expected);
            for path in ["/auth/login/start", "/saml/acs", "/v1/terms/status"] {
                assert_eq!(get_status_with_bearer(&app, path, &token).await, 200);
            }
        }
        assert_eq!(get_status_with_bearer(&app, "/v1/settings", "terms-test-pat").await, 503);
        assert_eq!(get_status_with_bearer(&app, "/v1/settings", "invalid").await, 401);
    }

    #[tokio::test]
    async fn human_pat_requires_acceptance_and_reconsent_but_disabled_terms_do_not() {
        use crate::terms::*;
        let temp = tempfile::tempdir().unwrap();
        for (enabled, version, expected) in [(false, "1", 200), (true, "1", 403), (true, "2", 403)] {
            let manager = Arc::new(
                TermsManager::open(
                    enabled,
                    "appliance".into(),
                    temp.path().into(),
                    Some(TermsVersion {
                        terms_type: TermsType::Affinidi,
                        document_id: AFFINIDI_TERMS_DOCUMENT_ID.into(),
                        version_id: version.into(),
                        version: version.into(),
                        title: "Terms".into(),
                        url: "https://example.com/terms".into(),
                        requires_reconsent: true,
                        published_at: chrono::Utc::now(),
                        published_by: None,
                    }),
                )
                .await
                .unwrap(),
            );
            let app = terms_test_app(Arc::new(SessionManager::new()), manager.clone());
            assert_eq!(get_status_with_bearer(&app, "/v1/settings", "terms-test-pat").await, expected);
            if enabled {
                let response = app
                    .clone()
                    .oneshot(
                        axum::http::Request::builder()
                            .uri("/v1/settings")
                            .header(axum::http::header::AUTHORIZATION, "Bearer terms-test-pat")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::FORBIDDEN);
                let body = response
                    .into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes();
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                    serde_json::json!({
                        "code": "TERMS_ACCEPTANCE_REQUIRED",
                        "message": "Sign in to Agent Gateway as this access token's owner, accept the required Terms and Conditions, then retry."
                    })
                );
                manager
                    .accept(
                        "user-1",
                        AcceptanceContext::Login,
                        AcceptTermsRequest {
                            accepted_terms: vec![AcceptedTermsVersion {
                                terms_type: TermsType::Affinidi,
                                version_id: version.into(),
                                accepted: true,
                            }],
                        },
                    )
                    .await
                    .unwrap();
                assert_eq!(get_status_with_bearer(&app, "/v1/settings", "terms-test-pat").await, 200);
            }
        }
    }

    #[tokio::test]
    async fn consent_pending_session_is_limited_to_terms_routes() {
        let temp = tempfile::tempdir().unwrap();
        let manager = Arc::new(
            crate::terms::TermsManager::open(
                true,
                "did:web:gateway.example".to_string(),
                temp.path().join("terms"),
                Some(crate::terms::TermsVersion {
                    terms_type: crate::terms::TermsType::Affinidi,
                    document_id: crate::terms::AFFINIDI_TERMS_DOCUMENT_ID.to_string(),
                    version_id: "terms-v1".to_string(),
                    version: "1".to_string(),
                    title: "Terms".to_string(),
                    url: "https://example.com/terms".to_string(),
                    requires_reconsent: true,
                    published_at: chrono::Utc::now(),
                    published_by: None,
                }),
            )
            .await
            .unwrap(),
        );
        let sessions = Arc::new(crate::auth::session::SessionManager::new());
        let token = sessions
            .create_session_with_terms_gate("alice".to_string(), "user-1".to_string(), TermsSessionGate::ConsentPending)
            .await;
        let app = Router::new()
            .route("/v1/settings", get(ok_handler))
            .route("/v1/terms/status", get(ok_handler))
            .route("/auth/login/start", get(ok_handler))
            .route("/auth/check", get(ok_handler))
            .route("/auth/logout", get(ok_handler))
            .layer(axum::middleware::from_fn_with_state(
                AuthGuardState::new(sessions, None, manager),
                require_session_auth,
            ));

        let blocked = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/settings")
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
        let body = blocked
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&body).unwrap()["code"], "TERMS_ACCEPTANCE_REQUIRED");
        assert_eq!(get_status_with_bearer(&app, "/v1/terms/status", &token).await, 200);
        assert_eq!(get_status_with_bearer(&app, "/auth/check", &token).await, 200);
        assert_eq!(get_status_with_bearer(&app, "/auth/logout", &token).await, 200);
        assert_eq!(get_status_with_bearer(&app, "/auth/login/start", &token).await, 200);
    }
}
