//! WebSocket support for real-time dashboard updates

use axum::{
    Extension,
    extract::{
        Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{
        HeaderMap, StatusCode,
        header::{AUTHORIZATION, ORIGIN},
    },
    response::{IntoResponse, Response},
};
use futures::{sink::SinkExt, stream::StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, error, info, warn};

use crate::observability::loggable;

/// WebSocket update message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsUpdate {
    /// New identity was created
    IdentityCreated { identity: serde_json::Value },
    /// Identity was updated (e.g., last_used timestamp)
    IdentityUpdated { identity: serde_json::Value },
    /// Metrics were updated
    MetricsUpdated { metrics: serde_json::Value },
    /// New log entry
    LogEntry { entry: String },
    /// Agent payload captured for a channel
    PayloadCaptured {
        channel: String,
        config_id: String,
        payload: serde_json::Value,
        response_payload: Option<serde_json::Value>,
        outbound_request: Box<Option<serde_json::Value>>,
        inbound_response: Box<Option<serde_json::Value>>,
        timestamp: String,
        validation_status: String,
        validation_error: Option<String>,
        derived_schema: Box<serde_json::Value>,
        /// The surface variant of the request the payload belongs to, as its
        /// audit records name it. `None` outside a surface request.
        #[serde(skip_serializing_if = "Option::is_none")]
        surface_variant: Option<String>,
    },
    /// Temporary channel expired and was deleted
    ChannelExpired { config_id: String, channel_name: String },
    /// Onboarding attempt received
    OnboardingAttempt { session_id: String, payload: serde_json::Value, timestamp: String },
    /// Full dashboard refresh needed
    RefreshDashboard,
    /// Pre-computed dashboard delta pushed from server.
    /// Holds a pre-serialized JSON string wrapped in Arc so broadcast
    /// clones are cheap (pointer copy instead of deep-cloning the payload).
    #[serde(skip)]
    DashboardDelta { json: Arc<String> },
}

/// WebSocket state shared across connections
#[derive(Clone)]
pub struct WsState {
    tx: broadcast::Sender<WsUpdate>,
}

impl WsState {
    /// Create a new WebSocket state with a broadcast channel
    ///
    /// # Arguments
    /// * `buffer_size` - Capacity of the broadcast channel (default: 500)
    pub fn new(buffer_size: usize) -> Self {
        // Configurable buffer size to handle high-traffic scenarios
        // Prevents message drops during payload capture bursts
        let (tx, _rx) = broadcast::channel(buffer_size);
        Self { tx }
    }

    /// Broadcast an update to all connected WebSocket clients
    pub fn broadcast(
        &self,
        update: WsUpdate,
    ) {
        let _ = self.tx.send(update);
    }

    /// Get a receiver for updates
    pub fn subscribe(&self) -> broadcast::Receiver<WsUpdate> {
        self.tx.subscribe()
    }

    /// Number of active WebSocket subscribers
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

/// Per-connection subscription controlling which delta sections to receive.
/// When `sections` is empty, all sections are forwarded (backward compatible).
struct WsSubscription {
    sections: HashSet<String>,
}

impl WsSubscription {
    fn new() -> Self {
        Self { sections: HashSet::new() }
    }

    /// Returns true if the client is interested in `section`.
    /// An empty set means "all sections".
    fn wants(
        &self,
        section: &str,
    ) -> bool {
        self.sections.is_empty()
            || self
                .sections
                .contains(section)
    }

    /// Returns true when no filtering is needed (all sections wanted).
    fn wants_all(&self) -> bool {
        self.sections.is_empty()
    }
}

/// Filter a pre-serialized dashboard_delta JSON to only include the
/// sections the client subscribed to and may read: the `logs` section needs
/// `logs.view` (`logs_allowed`).  Returns `None` if the filtered delta would
/// have zero change sections (nothing to send).
fn filter_delta_json(
    json: &str,
    sub: &WsSubscription,
    logs_allowed: bool,
) -> Option<String> {
    let mut value: serde_json::Value = serde_json::from_str(json).ok()?;
    let changes = value
        .get_mut("delta")?
        .get_mut("changes")?
        .as_object_mut()?;

    changes.retain(|key, _| sub.wants(key) && (logs_allowed || key != "logs"));

    if changes.is_empty() {
        return None; // Nothing left after filtering
    }

    serde_json::to_string(&value).ok()
}

/// The dashboard delta to send one connection: the broadcast unchanged when
/// the connection wants every section and may read log lines, otherwise
/// [`filter_delta_json`]'s result.
fn delta_for_connection(
    json: &str,
    sub: &WsSubscription,
    logs_allowed: bool,
) -> Option<String> {
    if sub.wants_all() && logs_allowed {
        return Some(json.to_owned());
    }
    filter_delta_json(json, sub, logs_allowed)
}

/// Whether a connection may receive `update`: log lines need `logs.view`.
fn admits(
    update: &WsUpdate,
    logs_allowed: bool,
) -> bool {
    logs_allowed || !matches!(update, WsUpdate::LogEntry { .. })
}

/// The user and session a connection serves and the guard that decides what
/// it may read. Its permissions are checked when it connects and again on
/// each keep-alive ping, so a role change or an ended session reaches an open
/// socket.
struct WsCaller {
    guard: crate::auth_manager::middleware::RbacGuard,
    user_id: String,
    sessions: Arc<crate::auth::SessionManager>,
    session_token: String,
}

impl WsCaller {
    /// Whether `caller` may receive log lines: its session is still live and
    /// its user holds `logs.view`. A connection without a known user or an
    /// RBAC guard may not.
    async fn logs_allowed(caller: Option<&Self>) -> bool {
        let Some(caller) = caller else {
            return false;
        };
        caller
            .sessions
            .is_live(&caller.session_token)
            .await
            && caller
                .guard
                .allows(&caller.user_id, None, &crate::rbac::Feature::LogsView)
                .await
    }
}

/// Message sent by a client to configure its subscription.
#[derive(Deserialize)]
struct SubscribeMessage {
    /// Delta sections the client wants.  Empty or absent = all.
    #[serde(default)]
    sections: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionTokenSource {
    AuthorizationHeader,
    Cookie,
    QueryParameter,
}

impl SessionTokenSource {
    fn requires_origin(self) -> bool {
        matches!(self, Self::Cookie)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationHeader => "authorization_header",
            Self::Cookie => "session_cookie",
            Self::QueryParameter => "query_parameter",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct SessionToken {
    token: String,
    source: SessionTokenSource,
}

impl std::fmt::Debug for SessionToken {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        formatter
            .debug_struct("SessionToken")
            .field("token", &loggable::secret(&self.token))
            .field("source", &self.source)
            .finish()
    }
}

/// WebSocket handler (unauthenticated - for backward compatibility). Its
/// clients know no user, so they never receive log lines.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<crate::observability::DashboardState>,
) -> impl IntoResponse {
    let ws_state = state.ws_state.clone();
    ws.on_upgrade(move |socket| handle_socket(socket, ws_state, None, None))
}

/// Authenticated WebSocket handler - requires valid session
#[allow(clippy::result_large_err)] // FIXME: Response is not an error
pub async fn ws_handler_authenticated(
    ws: WebSocketUpgrade,
    State(state): State<crate::observability::DashboardState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    Extension(session_mgr): Extension<Arc<crate::auth::SessionManager>>,
    Extension(terms_manager): Extension<Arc<crate::terms::TermsManager>>,
    rbac_guard: Option<Extension<crate::auth_manager::middleware::RbacGuard>>,
) -> Result<Response, Response> {
    debug!("WebSocket connection attempt received");

    let session_token = extract_session_token(&headers, &params).ok_or_else(|| {
        warn!("WebSocket auth failed: missing session token");
        (StatusCode::UNAUTHORIZED, "Missing session token".to_string()).into_response()
    })?;

    if session_token.source == SessionTokenSource::QueryParameter {
        warn!("Rejected WebSocket query-string token authentication attempt");
        return Err((
            StatusCode::BAD_REQUEST,
            "Query-string token authentication is not supported for WebSocket connections".to_string(),
        )
            .into_response());
    }

    let allowed_origins = build_allowed_websocket_origins(state.network_config.as_ref());
    validate_websocket_origin(&headers, &allowed_origins, session_token.source).map_err(IntoResponse::into_response)?;

    let session = session_mgr
        .validate_session_record(&session_token.token)
        .await
        .ok_or_else(|| {
            warn!("WebSocket auth failed: invalid or expired session via {}", session_token.source.as_str());
            (StatusCode::UNAUTHORIZED, "Invalid or expired session".to_string()).into_response()
        })?;
    verify_websocket_terms(&session, &terms_manager).await?;
    let user_id = session.user_id;

    info!("WebSocket connection authenticated for user_id: {} via {}", user_id, session_token.source.as_str());

    let caller = rbac_guard.map(|Extension(guard)| WsCaller {
        guard,
        user_id: user_id.clone(),
        sessions: session_mgr.clone(),
        session_token: session_token.token.clone(),
    });

    // Upgrade connection
    let ws_state = state.ws_state.clone();
    Ok(ws
        .on_upgrade(move |socket| handle_socket(socket, ws_state, Some(user_id), caller))
        .into_response())
}

#[allow(clippy::result_large_err)] // FIXME: Response is not an error
async fn verify_websocket_terms(
    session: &crate::auth::session::Session,
    manager: &crate::terms::TermsManager,
) -> Result<(), Response> {
    if session.terms_gate != crate::auth::session::TermsSessionGate::ConsentPending {
        return Ok(());
    }
    let status = manager
        .status(&session.user_id, crate::terms::AcceptanceContext::Login)
        .await
        .map_err(IntoResponse::into_response)?;
    if session.terms_gate == crate::auth::session::TermsSessionGate::ConsentPending && status.consent_required {
        return Err((
            StatusCode::FORBIDDEN,
            axum::Json(crate::terms::TermsErrorBody {
                code: "TERMS_ACCEPTANCE_REQUIRED".to_string(),
                required_terms: None,
            }),
        )
            .into_response());
    }
    Ok(())
}

/// Extract session token from Authorization header, rejected query parameters, or cookies.
/// Priority: Authorization Bearer header > rejected `token` query param > `__Host-session_token` cookie.
fn extract_session_token(
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> Option<SessionToken> {
    if let Some(auth_header) = headers.get(AUTHORIZATION)
        && let Ok(auth_str) = auth_header.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        let token = token.trim();
        if !token.is_empty() {
            return Some(SessionToken {
                token: token.to_string(),
                source: SessionTokenSource::AuthorizationHeader,
            });
        }
    }

    if let Some(token) = params.get("token") {
        let token = token.trim();
        if !token.is_empty() {
            return Some(SessionToken {
                token: token.to_string(),
                source: SessionTokenSource::QueryParameter,
            });
        }
    }

    crate::auth::session_cookie::session_cookie_value(headers).map(|token| SessionToken {
        token: token.to_string(),
        source: SessionTokenSource::Cookie,
    })
}

fn build_allowed_websocket_origins(network_config: &crate::config::NetworkConfig) -> HashSet<String> {
    let mut allowed_origins = HashSet::new();

    for origin in &network_config.cors {
        if let Some(origin) = normalize_origin(origin) {
            allowed_origins.insert(origin);
        }
    }

    if let Some(origin) = normalize_origin(
        &network_config
            .webauthn
            .external_origin,
    ) {
        allowed_origins.insert(origin);
    }

    allowed_origins
}

fn validate_websocket_origin(
    headers: &HeaderMap,
    allowed_origins: &HashSet<String>,
    token_source: SessionTokenSource,
) -> Result<(), (StatusCode, String)> {
    let origin = headers
        .get(ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if token_source.requires_origin() && origin.is_none() {
        warn!("Rejected WebSocket cookie-auth request without Origin header");
        return Err((StatusCode::FORBIDDEN, "Missing Origin header".to_string()));
    }

    let Some(origin) = origin else {
        return Ok(());
    };

    let origin = normalize_origin(origin).ok_or_else(|| {
        warn!("Rejected WebSocket request with invalid Origin header");
        (StatusCode::FORBIDDEN, "Invalid Origin header".to_string())
    })?;

    if allowed_origins.contains(&origin) {
        return Ok(());
    }

    warn!("Rejected WebSocket request from non-allowlisted origin: {}", origin);
    Err((StatusCode::FORBIDDEN, "Origin not allowed".to_string()))
}

fn normalize_origin(origin: &str) -> Option<String> {
    let parsed = url::Url::parse(origin).ok()?;
    match parsed.origin() {
        url::Origin::Opaque(_) => None,
        origin => Some(origin.ascii_serialization()),
    }
}

/// Handle a WebSocket connection
async fn handle_socket(
    socket: WebSocket,
    state: Arc<WsState>,
    user_id: Option<String>,
    caller: Option<WsCaller>,
) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.subscribe();

    // Per-connection subscription – shared between send & recv tasks.
    let subscription = Arc::new(RwLock::new(WsSubscription::new()));

    // Send initial connection confirmation
    if let Err(e) = sender
        .send(Message::Text(
            serde_json::json!({
                "type": "connected",
                "message": "WebSocket connection established"
            })
            .to_string()
            .into(),
        ))
        .await
    {
        error!("Failed to send connection confirmation: {}", e);
        return;
    }

    if let Some(ref user_id) = user_id {
        debug!("WebSocket client connected (user_id: {})", user_id);
    } else {
        debug!("WebSocket client connected (unauthenticated)");
    }

    // Spawn a task to handle outgoing messages and keep-alive pings
    let send_sub = Arc::clone(&subscription);
    let mut send_task = tokio::spawn(async move {
        let mut ping_interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut logs_allowed = WsCaller::logs_allowed(caller.as_ref()).await;

        loop {
            tokio::select! {
                // Handle broadcast updates
                update_result = rx.recv() => {
                    match update_result {
                        Ok(update) => {
                            if !admits(&update, logs_allowed) {
                                continue;
                            }
                            // DashboardDelta is already serialized; apply per-client
                            // section filtering before forwarding.
                            let msg = match &update {
                                WsUpdate::DashboardDelta { json } => {
                                    let sub = send_sub.read().await;
                                    match delta_for_connection(json, &sub, logs_allowed) {
                                        Some(delta) => Message::Text(delta.into()),
                                        None => continue, // Nothing left after filtering
                                    }
                                }
                                other => match serde_json::to_string(other) {
                                    Ok(json) => Message::Text(json.into()),
                                    Err(e) => {
                                        error!("Failed to serialize update: {}", e);
                                        continue;
                                    }
                                },
                            };

                            if sender.send(msg).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break, // Channel closed
                    }
                }
                // Send periodic pings to keep connection alive
                _ = ping_interval.tick() => {
                    logs_allowed = WsCaller::logs_allowed(caller.as_ref()).await;
                    if sender.send(Message::Ping("ping".into())).await.is_err() {
                        break;
                    }
                    debug!("Sent WebSocket ping");
                }
            }
        }
    });

    // Handle incoming messages from client (ping/pong, close, and subscribe)
    let recv_sub = Arc::clone(&subscription);
    let recv_user_id = user_id.clone();
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Text(text) => {
                    // Try to parse as a subscribe command
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                        if value
                            .get("type")
                            .and_then(|t| t.as_str())
                            == Some("subscribe")
                        {
                            if let Ok(sub_msg) = serde_json::from_value::<SubscribeMessage>(value) {
                                let sections: HashSet<String> = sub_msg
                                    .sections
                                    .into_iter()
                                    .collect();
                                let label = if sections.is_empty() {
                                    "all".to_string()
                                } else {
                                    sections
                                        .iter()
                                        .cloned()
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                };
                                debug!(
                                    "WebSocket client {} subscribed to: [{}]",
                                    recv_user_id
                                        .as_deref()
                                        .unwrap_or("anon"),
                                    label,
                                );
                                recv_sub
                                    .write()
                                    .await
                                    .sections = sections;
                            } else {
                                info!(
                                    "WebSocket client {} sent subscribe but failed to parse sections",
                                    recv_user_id
                                        .as_deref()
                                        .unwrap_or("anon"),
                                );
                            }
                        } else {
                            debug!("Received non-subscribe text message ({} bytes)", text.len());
                        }
                    } else {
                        debug!("Received unparseable text message ({} bytes)", text.len());
                    }
                }
                Message::Ping(_) => {
                    debug!("Received WebSocket ping, responding with pong");
                }
                Message::Pong(_) => {
                    debug!("Received WebSocket pong");
                }
                Message::Close(_) => {
                    debug!("Client closed connection");
                    break;
                }
                _ => {}
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };

    if let Some(ref user_id) = user_id {
        debug!("WebSocket client disconnected (user_id: {})", user_id);
    } else {
        debug!("WebSocket client disconnected");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SessionTokenSource, build_allowed_websocket_origins, extract_session_token, normalize_origin,
        validate_websocket_origin, verify_websocket_terms,
    };
    use axum::body::to_bytes;
    use axum::http::{
        HeaderMap, HeaderValue,
        header::{AUTHORIZATION, COOKIE, ORIGIN},
    };
    use chrono::Utc;
    use std::collections::{HashMap, HashSet};
    use tempfile::TempDir;

    fn session(terms_gate: crate::auth::session::TermsSessionGate) -> crate::auth::session::Session {
        crate::auth::session::Session {
            token_hash: crate::storage::filesystem::token_storage_id("token"),
            username: "user".to_string(),
            user_id: "user-1".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            terms_gate,
        }
    }

    #[tokio::test]
    async fn websocket_terms_gate_blocks_only_pending_sessions() {
        let directory = TempDir::new().unwrap();
        let manager = crate::terms::TermsManager::open(
            true,
            "did:web:gateway.example".to_string(),
            directory.path().to_path_buf(),
            Some(crate::terms::TermsVersion {
                terms_type: crate::terms::TermsType::Affinidi,
                document_id: crate::terms::AFFINIDI_TERMS_DOCUMENT_ID.to_string(),
                version_id: "v1".to_string(),
                version: "1".to_string(),
                title: "Affinidi Terms".to_string(),
                url: "https://example.com/terms".to_string(),
                requires_reconsent: true,
                published_at: Utc::now(),
                published_by: None,
            }),
        )
        .await
        .unwrap();

        let response =
            verify_websocket_terms(&session(crate::auth::session::TermsSessionGate::ConsentPending), &manager)
                .await
                .unwrap_err();
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
        assert!(
            verify_websocket_terms(&session(crate::auth::session::TermsSessionGate::AllowedAtLogin), &manager,)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn websocket_terms_gate_returns_stable_operational_failure_and_recovers() {
        let directory = TempDir::new().unwrap();
        let acceptance_dir = directory
            .path()
            .join("acceptances");
        tokio::fs::create_dir_all(&acceptance_dir)
            .await
            .unwrap();
        let corrupt_path = acceptance_dir.join("broken.json");
        tokio::fs::write(&corrupt_path, b"not json")
            .await
            .unwrap();
        let manager = crate::terms::TermsManager::open(
            true,
            "did:web:gateway.example".to_string(),
            directory.path().to_path_buf(),
            None,
        )
        .await
        .unwrap();

        for gate in [
            crate::auth::session::TermsSessionGate::AllowedAtLogin,
            crate::auth::session::TermsSessionGate::LegacyAllowed,
        ] {
            assert!(
                verify_websocket_terms(&session(gate), &manager)
                    .await
                    .is_ok()
            );
        }
        let response =
            verify_websocket_terms(&session(crate::auth::session::TermsSessionGate::ConsentPending), &manager)
                .await
                .unwrap_err();
        assert_eq!(response.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"code": "TERMS_OPERATIONAL_FAILURE"})
        );

        tokio::fs::remove_file(corrupt_path)
            .await
            .unwrap();
        assert!(
            verify_websocket_terms(&session(crate::auth::session::TermsSessionGate::ConsentPending), &manager,)
                .await
                .is_ok()
        );
    }

    #[test]
    fn test_extract_session_token_prefers_authorization_header() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer bearer-token"));
        headers.insert(COOKIE, HeaderValue::from_static("__Host-session_token=cookie-token"));
        let params = HashMap::from([(String::from("token"), String::from("query-token"))]);

        let token = extract_session_token(&headers, &params).expect("token should be extracted");

        assert_eq!(token.token, "bearer-token");
        assert_eq!(token.source, SessionTokenSource::AuthorizationHeader);
    }

    #[test]
    fn test_extract_session_token_marks_query_parameter_source() {
        let headers = HeaderMap::new();
        let params = HashMap::from([(String::from("token"), String::from("query-token"))]);

        let token = extract_session_token(&headers, &params).expect("token should be extracted");

        assert_eq!(token.token, "query-token");
        assert_eq!(token.source, SessionTokenSource::QueryParameter);
    }

    #[test]
    fn test_extract_session_token_uses_cookie_when_present() {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_static("__Host-session_token=cookie-token"));

        let token = extract_session_token(&headers, &HashMap::new()).expect("token should be extracted");

        assert_eq!(token.token, "cookie-token");
        assert_eq!(token.source, SessionTokenSource::Cookie);
    }

    #[test]
    fn test_extract_session_token_ignores_the_unprefixed_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_static("session_token=cookie-token"));

        assert!(extract_session_token(&headers, &HashMap::new()).is_none());
    }

    #[test]
    fn session_token_debug_shows_only_a_token_prefix() {
        let token = "0f2c9d7e-1b3a-4c5d-8e9f-a0b1c2d3e4f5";
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {token}")).unwrap());
        let session_token = extract_session_token(&headers, &HashMap::new()).expect("token should be extracted");

        let rendered = format!("{session_token:?}");

        assert_eq!(rendered, r#"SessionToken { token: "0f2c9d7e...", source: AuthorizationHeader }"#);
        assert!(!rendered.contains(token), "{rendered}");
    }

    #[test]
    fn test_validate_websocket_origin_rejects_cookie_auth_without_origin() {
        let headers = HeaderMap::new();
        let err = validate_websocket_origin(&headers, &HashSet::new(), SessionTokenSource::Cookie)
            .expect_err("missing origin should be rejected");

        assert_eq!(err.0, axum::http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_validate_websocket_origin_allows_allowlisted_cookie_origin() {
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("https://dashboard.example.com"));
        let allowed = HashSet::from([String::from("https://dashboard.example.com")]);

        let result = validate_websocket_origin(&headers, &allowed, SessionTokenSource::Cookie);

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_websocket_origin_rejects_disallowed_origin() {
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("https://evil.example.com"));
        let allowed = HashSet::from([String::from("https://dashboard.example.com")]);

        let err = validate_websocket_origin(&headers, &allowed, SessionTokenSource::Cookie)
            .expect_err("disallowed origin should be rejected");

        assert_eq!(err.0, axum::http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_validate_websocket_origin_allows_bearer_without_origin() {
        let headers = HeaderMap::new();

        let result = validate_websocket_origin(
            &headers,
            &HashSet::from([String::from("https://dashboard.example.com")]),
            SessionTokenSource::AuthorizationHeader,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_normalize_origin_strips_path_and_keeps_origin_only() {
        let origin = normalize_origin("https://dashboard.example.com/app/index.html").expect("origin should normalize");

        assert_eq!(origin, "https://dashboard.example.com");
    }

    #[test]
    fn test_build_allowed_websocket_origins_includes_cors_and_external_origin() {
        let network_config: crate::config::NetworkConfig = serde_json::from_value(serde_json::json!({
            "did": { "domain": "gateway.example.com" },
            "webauthn": {
                "rp_id": "gateway.example.com",
                "external_origin": "https://gateway.example.com/app"
            },
            "integration": {
                "categories": [],
                "types": []
            },
            "cors": ["https://dashboard.example.com", "https://ops.example.com/path"],
            "listeners": [],
            "routes": {}
        }))
        .expect("network config should deserialize");

        let origins = build_allowed_websocket_origins(&network_config);

        assert!(origins.contains("https://dashboard.example.com"));
        assert!(origins.contains("https://ops.example.com"));
        assert!(origins.contains("https://gateway.example.com"));
    }

    const DELTA_WITH_LOGS: &str = r#"{"type":"dashboard_delta","delta":{"timestamp":1,"changes":{"metrics":{"x":1},"logs":{"new_entries":[{"message":"secret line"}]}}}}"#;

    fn changes_of(json: &str) -> serde_json::Map<String, serde_json::Value> {
        serde_json::from_str::<serde_json::Value>(json).unwrap()["delta"]["changes"]
            .as_object()
            .unwrap()
            .clone()
    }

    fn subscribed_to(sections: &[&str]) -> super::WsSubscription {
        let mut sub = super::WsSubscription::new();
        sub.sections = sections
            .iter()
            .map(|section| section.to_string())
            .collect();
        sub
    }

    #[test]
    fn a_client_without_logs_view_never_gets_the_log_section() {
        let filtered = super::delta_for_connection(DELTA_WITH_LOGS, &subscribed_to(&[]), false).unwrap();

        let changes = changes_of(&filtered);
        assert_eq!(
            changes
                .keys()
                .collect::<Vec<_>>(),
            vec!["metrics"]
        );
        assert!(!filtered.contains("secret line"), "{filtered}");
    }

    #[test]
    fn a_client_with_logs_view_gets_the_delta_unchanged() {
        let delta = super::delta_for_connection(DELTA_WITH_LOGS, &subscribed_to(&[]), true).unwrap();

        assert_eq!(delta, DELTA_WITH_LOGS);
    }

    #[test]
    fn a_delta_holding_only_logs_is_sent_only_to_a_client_with_logs_view() {
        let logs_only = subscribed_to(&["logs"]);

        assert_eq!(super::delta_for_connection(DELTA_WITH_LOGS, &logs_only, false), None);
        let allowed = super::delta_for_connection(DELTA_WITH_LOGS, &logs_only, true).unwrap();
        assert_eq!(
            changes_of(&allowed)
                .keys()
                .collect::<Vec<_>>(),
            vec!["logs"]
        );
    }

    #[test]
    fn log_entry_updates_reach_only_clients_with_logs_view() {
        let entry = super::WsUpdate::LogEntry {
            entry: "secret line".to_string(),
        };

        assert!(!super::admits(&entry, false));
        assert!(super::admits(&entry, true));
        assert!(super::admits(&super::WsUpdate::RefreshDashboard, false));
    }

    async fn guard_with_user(
        dir: &TempDir,
        role: crate::auth::types::UserRole,
    ) -> crate::auth_manager::middleware::RbacGuard {
        let storage = crate::auth::storage::PasskeyStorage::new(
            dir.path()
                .join("users")
                .to_string_lossy()
                .into_owned(),
            dir.path()
                .join("avatars")
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap();
        storage
            .save_user(&user_data(role, crate::auth::types::UserStatus::Approved))
            .await
            .unwrap();
        let mut rbac = crate::rbac::RbacConfig::default();
        rbac.permissions
            .insert("logs.view".to_string(), "poweruser".to_string());
        crate::auth_manager::middleware::RbacGuard::new(std::sync::Arc::new(storage), std::sync::Arc::new(rbac))
    }

    fn user_data(
        role: crate::auth::types::UserRole,
        status: crate::auth::types::UserStatus,
    ) -> crate::auth::storage::UserData {
        let now = Utc::now();
        crate::auth::storage::UserData {
            user_id: "user-1".to_string(),
            username: "user".to_string(),
            passkeys: Vec::new(),
            role,
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

    async fn caller_for(
        guard: crate::auth_manager::middleware::RbacGuard,
        user_id: &str,
    ) -> super::WsCaller {
        let sessions = std::sync::Arc::new(crate::auth::SessionManager::new());
        let session_token = sessions
            .create_session("user".to_string(), user_id.to_string())
            .await;
        super::WsCaller {
            guard,
            user_id: user_id.to_string(),
            sessions,
            session_token,
        }
    }

    #[tokio::test]
    async fn a_connection_may_read_logs_only_when_its_user_holds_logs_view() {
        let dir = TempDir::new().unwrap();
        let power_user =
            caller_for(guard_with_user(&dir, crate::auth::types::UserRole::PowerUser).await, "user-1").await;
        assert!(super::WsCaller::logs_allowed(Some(&power_user)).await);

        let dir = TempDir::new().unwrap();
        let user = caller_for(guard_with_user(&dir, crate::auth::types::UserRole::User).await, "user-1").await;
        assert!(!super::WsCaller::logs_allowed(Some(&user)).await);

        let unknown = caller_for(power_user.guard.clone(), "someone-else").await;
        assert!(!super::WsCaller::logs_allowed(Some(&unknown)).await);
        assert!(!super::WsCaller::logs_allowed(None).await);
    }

    #[tokio::test]
    async fn a_later_check_refuses_logs_after_the_user_loses_logs_view_or_approval() {
        use crate::auth::types::{UserRole, UserStatus};

        for (role, status) in [(UserRole::User, UserStatus::Approved), (UserRole::PowerUser, UserStatus::Disabled)] {
            let dir = TempDir::new().unwrap();
            let caller = caller_for(guard_with_user(&dir, UserRole::PowerUser).await, "user-1").await;
            assert!(super::WsCaller::logs_allowed(Some(&caller)).await);

            caller
                .guard
                .storage
                .save_user(&user_data(role, status))
                .await
                .unwrap();

            assert!(!super::WsCaller::logs_allowed(Some(&caller)).await);
        }
    }

    #[tokio::test]
    async fn a_later_check_refuses_logs_after_the_session_ends() {
        let dir = TempDir::new().unwrap();
        let caller = caller_for(guard_with_user(&dir, crate::auth::types::UserRole::PowerUser).await, "user-1").await;
        assert!(super::WsCaller::logs_allowed(Some(&caller)).await);

        caller
            .sessions
            .remove_sessions_for_user("user-1")
            .await;

        assert!(!super::WsCaller::logs_allowed(Some(&caller)).await);
    }
}
