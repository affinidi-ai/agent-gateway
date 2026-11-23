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
use crate::policies::input_capture::QueuedCapture;

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
    /// A policy evaluation on a surface whose policy input a connection listens to: its
    /// input, credentials masked, and its outcome. Sent only to the connections listening
    /// to that surface, while their user holds `surfaces.edit` and `policies.edit`.
    PolicyInputCaptured {
        config_id: String,
        timestamp: String,
        /// `gateway`, `surface` or `appliance`.
        plane: String,
        /// The key of the evaluated policy engine.
        engine: String,
        /// The evaluated policy slot in words, such as `inbound` or `transit <alias>`.
        slot: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        transit_point: Option<String>,
        /// The policy definitions the slot evaluated.
        policies: Vec<crate::policies::input_capture::CapturedPolicy>,
        /// The policy, by id, that denied, when the slot evaluates a set of several.
        #[serde(skip_serializing_if = "Option::is_none")]
        decided_by: Option<String>,
        input: Box<serde_json::Value>,
        /// `allow`, `deny` or `error`.
        decision: String,
        /// The deny reason, or the evaluation error.
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
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
        mut update: WsUpdate,
    ) {
        // Identity frames reach every dashboard session whatever its role, so no producer may put
        // a private key in one, now or later.
        if let WsUpdate::IdentityCreated { identity } | WsUpdate::IdentityUpdated { identity } = &mut update {
            strip_private_keys(identity);
        }
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
    /// The surfaces whose policy input this connection listens to.
    policy_input: HashMap<String, crate::policies::input_capture::Listening>,
    /// Where this connection's listens send their captures.
    captures: crate::policies::input_capture::CaptureSender,
    /// The user of the connection, named in the records of its listens.
    user_id: String,
}

/// A connection's subscription is dropped however the connection ends, so every listen still
/// open when it closes is recorded as ended because the connection closed. A gateway restart or
/// crash may end listens without a stop record.
impl Drop for WsSubscription {
    fn drop(&mut self) {
        let mut open: Vec<String> = self
            .policy_input
            .drain()
            .map(|(surface_id, _)| surface_id)
            .collect();
        if open.is_empty() {
            return;
        }
        open.sort();
        for surface_id in &open {
            crate::audit::policy_input_captures::stopped(
                &self.user_id,
                surface_id,
                crate::delegation_vault::audit::PolicyInputCaptureStop::ConnectionClosed,
            );
        }
        info!(
            user_id = %self.user_id,
            surfaces = open.len(),
            "Stopped listening to policy input: the connection closed"
        );
    }
}

/// Why a listen was refused or ended: the connection's session has ended.
const SESSION_ENDED: &str = "your dashboard session has ended; sign in again";

/// Why a listen was refused: the connection has no dashboard sign-in.
const NO_SIGN_IN: &str = "policy input capture needs dashboard sign-in";

/// Why a listen was refused or ended: the user lacks a permission listening needs.
const PERMISSION_MISSING: &str = "needs surfaces.edit and policies.edit";

/// Why a listen was refused or ended: the `policy_input_capture` feature flag is off.
const TURNED_OFF: &str = "policy input capture is turned off";

/// Why a connection may not listen to policy input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenRefusal {
    NoSignIn,
    SessionEnded,
    TurnedOff,
    PermissionMissing,
}

impl ListenRefusal {
    /// What the client is told.
    fn message(self) -> &'static str {
        match self {
            Self::NoSignIn => NO_SIGN_IN,
            Self::SessionEnded => SESSION_ENDED,
            Self::TurnedOff => TURNED_OFF,
            Self::PermissionMissing => PERMISSION_MISSING,
        }
    }

    /// Why a listen this refusal ends is recorded as stopped. A connection without a
    /// sign-in never starts a listen, so `NoSignIn` ends none.
    fn stop(self) -> crate::delegation_vault::audit::PolicyInputCaptureStop {
        use crate::delegation_vault::audit::PolicyInputCaptureStop;
        match self {
            Self::NoSignIn | Self::SessionEnded => PolicyInputCaptureStop::SessionEnded,
            Self::TurnedOff => PolicyInputCaptureStop::TurnedOff,
            Self::PermissionMissing => PolicyInputCaptureStop::PermissionMissing,
        }
    }
}

/// The most surfaces one connection may listen to the policy input of at once.
const MAX_POLICY_INPUT_SURFACES: usize = 10;

/// How many answers to a client's listen requests may wait to be sent before the
/// connection stops reading the client's messages.
const MAX_PENDING_ANSWERS: usize = 32;

/// The longest surface id a policy input listen message may name.
const MAX_SURFACE_ID_LEN: usize = 256;

/// How many captures may wait to be sent to one connection. Captures that find its
/// queue full are dropped for that connection only.
const MAX_PENDING_CAPTURES: usize = 64;

/// How long one message may wait for a client to read it before the connection is closed.
/// A client that stops reading would otherwise hold back the keep-alive access recheck.
const SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How often a connection rechecks its access and pings the client.
const KEEP_ALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

impl WsSubscription {
    fn new(captures: crate::policies::input_capture::CaptureSender) -> Self {
        Self {
            sections: HashSet::new(),
            policy_input: HashMap::new(),
            captures,
            user_id: String::new(),
        }
    }

    /// This subscription, for the connection of `user_id`.
    fn for_user(
        mut self,
        user_id: &str,
    ) -> Self {
        self.user_id = user_id.to_string();
        self
    }

    /// Whether this connection listens to the policy input of `surface_id`.
    fn listens_to(
        &self,
        surface_id: &str,
    ) -> bool {
        self.policy_input
            .contains_key(surface_id)
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

/// Whether a connection may receive the broadcast `update`: log lines need `logs.view`,
/// and captured policy input goes only to its listeners, never through the broadcast.
fn admits(
    update: &WsUpdate,
    logs_allowed: bool,
) -> bool {
    match update {
        WsUpdate::LogEntry { .. } => logs_allowed,
        WsUpdate::PolicyInputCaptured { .. } => false,
        _ => true,
    }
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
        Self::allowed(caller, &[crate::rbac::Feature::LogsView]).await
    }

    /// Why `caller` may not listen to policy input: it has no dashboard sign-in, its
    /// session has ended, policy input capture is turned off, or its user lacks a
    /// permission. `None` when it may listen.
    async fn policy_input_refusal(caller: Option<&Self>) -> Option<ListenRefusal> {
        let Some(live) = caller else {
            return Some(ListenRefusal::NoSignIn);
        };
        if !live
            .sessions
            .is_live(&live.session_token)
            .await
        {
            return Some(ListenRefusal::SessionEnded);
        }
        if !crate::policies::input_capture::capture_turned_on() {
            return Some(ListenRefusal::TurnedOff);
        }
        if live
            .holds(&[crate::rbac::Feature::SurfacesEdit, crate::rbac::Feature::PoliciesEdit])
            .await
        {
            None
        } else {
            Some(ListenRefusal::PermissionMissing)
        }
    }

    /// Whether `caller` may receive captured policy input: its session is still live
    /// and its user holds `surfaces.edit` and `policies.edit`.
    #[cfg(test)]
    async fn policy_input_allowed(caller: Option<&Self>) -> bool {
        Self::policy_input_refusal(caller)
            .await
            .is_none()
    }

    async fn allowed(
        caller: Option<&Self>,
        features: &[crate::rbac::Feature],
    ) -> bool {
        let Some(caller) = caller else {
            return false;
        };
        caller
            .sessions
            .is_live(&caller.session_token)
            .await
            && caller.holds(features).await
    }

    /// Whether this caller's user holds every one of `features`.
    async fn holds(
        &self,
        features: &[crate::rbac::Feature],
    ) -> bool {
        for feature in features {
            if !self
                .guard
                .allows(&self.user_id, None, feature)
                .await
            {
                return false;
            }
        }
        true
    }
}

/// A client's request to start or stop listening to a surface's policy input.
#[derive(Deserialize)]
struct PolicyInputListenMessage {
    surface_id: String,
}

/// The answer to a [`PolicyInputListenMessage`]: whether the connection now listens to the
/// surface's policy input, and why not when it was refused.
fn policy_input_listen_answer(
    surface_id: &str,
    listening: bool,
    error: Option<&str>,
) -> String {
    let mut answer = serde_json::json!({
        "type": "policy_input_capture",
        "surface_id": surface_id,
        "listening": listening,
    });
    if let Some(error) = error {
        answer["error"] = serde_json::json!(error);
    }
    answer.to_string()
}

/// Whether a listen message's `surface_id` can name a surface: not empty, at most
/// [`MAX_SURFACE_ID_LEN`] bytes and free of control, bidi and zero-width characters, so it
/// cannot forge a log line or display as another id.
fn is_valid_surface_id(surface_id: &str) -> bool {
    !surface_id.is_empty()
        && surface_id.len() <= MAX_SURFACE_ID_LEN
        && !surface_id.chars().any(|c| {
            c.is_control()
                || matches!(
                    c,
                    '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
                )
        })
}

/// The answer to a listen message without a valid surface id: a refused listen says why,
/// and a stop, which leaves nothing listening, carries no `error`.
fn invalid_surface_id_answer(start: bool) -> String {
    policy_input_listen_answer("", false, start.then_some("invalid surface id"))
}

/// The user id of `caller`, empty for a connection without one.
fn user_of(caller: Option<&WsCaller>) -> &str {
    caller
        .map(|caller| caller.user_id.as_str())
        .unwrap_or_default()
}

/// Start or stop listening to a surface's policy input for `subscription`, answering the
/// client. Listening needs policy input capture turned on, `surfaces.edit` and
/// `policies.edit`. A listen that starts or stops is recorded with its user and surface.
async fn listen_to_policy_input(
    subscription: &RwLock<WsSubscription>,
    caller: Option<&WsCaller>,
    message: PolicyInputListenMessage,
    start: bool,
) -> String {
    let surface_id = message.surface_id;
    if !is_valid_surface_id(&surface_id) {
        return invalid_surface_id_answer(start);
    }
    if !start {
        let stopped = subscription
            .write()
            .await
            .policy_input
            .remove(&surface_id)
            .is_some();
        if stopped {
            info!(surface_id = %surface_id, "Stopped listening to policy input");
            crate::audit::policy_input_captures::stopped(
                user_of(caller),
                &surface_id,
                crate::delegation_vault::audit::PolicyInputCaptureStop::Stopped,
            );
        }
        return policy_input_listen_answer(&surface_id, false, None);
    }
    if let Some(refusal) = WsCaller::policy_input_refusal(caller).await {
        return policy_input_listen_answer(&surface_id, false, Some(refusal.message()));
    }
    let mut subscription = subscription.write().await;
    if let Some(refusal) = WsCaller::policy_input_refusal(caller).await {
        return policy_input_listen_answer(&surface_id, false, Some(refusal.message()));
    }
    if !subscription.listens_to(&surface_id) {
        if subscription
            .policy_input
            .len()
            >= MAX_POLICY_INPUT_SURFACES
        {
            return policy_input_listen_answer(
                &surface_id,
                false,
                Some("listening to too many surfaces on this connection"),
            );
        }
        let listening = crate::policies::input_capture::listen(&surface_id, subscription.captures.clone());
        subscription
            .policy_input
            .insert(surface_id.clone(), listening);
        info!(surface_id = %surface_id, user_id = user_of(caller), "Listening to policy input");
        crate::audit::policy_input_captures::started(user_of(caller), &surface_id);
    }
    policy_input_listen_answer(&surface_id, true, None)
}

/// Stop every listen of `subscription`, recording each as ended for `reason`. Returns the
/// surfaces whose listens stopped.
async fn stop_policy_input(
    subscription: &RwLock<WsSubscription>,
    caller: Option<&WsCaller>,
    reason: crate::delegation_vault::audit::PolicyInputCaptureStop,
) -> Vec<String> {
    let mut stopped: Vec<String> = subscription
        .write()
        .await
        .policy_input
        .drain()
        .map(|(surface_id, _)| surface_id)
        .collect();
    stopped.sort();
    for surface_id in &stopped {
        crate::audit::policy_input_captures::stopped(user_of(caller), surface_id, reason);
    }
    stopped
}

/// Check again whether `caller` may listen to policy input. When it may not, every
/// listen of `subscription` stops, and the answers telling the client so are returned.
async fn recheck_policy_input(
    subscription: &RwLock<WsSubscription>,
    caller: Option<&WsCaller>,
) -> (bool, Vec<String>) {
    let Some(refusal) = WsCaller::policy_input_refusal(caller).await else {
        return (true, Vec::new());
    };
    let stopped = stop_policy_input(subscription, caller, refusal.stop()).await;
    if !stopped.is_empty() {
        info!(
            user_id = user_of(caller),
            surfaces = stopped.len(),
            reason = refusal.message(),
            "Stopped listening to policy input: the user may no longer listen"
        );
    }
    let answers = stopped
        .iter()
        .map(|surface_id| policy_input_listen_answer(surface_id, false, Some(refusal.message())))
        .collect();
    (false, answers)
}

/// The keep-alive recheck of policy input listening: when `caller` may no longer listen,
/// every listen stops and the captures already queued in `captures` are discarded, so
/// none reaches the client. A connection without listens skips the recheck. Returns the
/// answers telling the client which listens stopped.
async fn recheck_at_keep_alive(
    subscription: &RwLock<WsSubscription>,
    caller: Option<&WsCaller>,
    captures: &mut tokio::sync::mpsc::Receiver<QueuedCapture>,
) -> Vec<String> {
    if subscription
        .read()
        .await
        .policy_input
        .is_empty()
    {
        return Vec::new();
    }
    let (allowed, stopped) = recheck_policy_input(subscription, caller).await;
    if !allowed {
        while captures.try_recv().is_ok() {}
    }
    stopped
}

/// Send `message` to the client. Returns false when the connection should end: the
/// client is gone, or it has not read the message within [`SEND_TIMEOUT`].
async fn deliver<S>(
    sender: &mut S,
    message: Message,
) -> bool
where
    S: futures::Sink<Message> + Unpin,
{
    match tokio::time::timeout(SEND_TIMEOUT, sender.send(message)).await {
        Ok(sent) => sent.is_ok(),
        Err(_) => {
            debug!("WebSocket client stopped reading; closing the connection");
            false
        }
    }
}

/// Remove every private-key member from `value`, at any depth.
fn strip_private_keys(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            object.remove("private_key");
            object.remove("private_key_jwk");
            object
                .values_mut()
                .for_each(strip_private_keys);
        }
        serde_json::Value::Array(items) => items
            .iter_mut()
            .for_each(strip_private_keys),
        _ => {}
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

/// Whether a connection keeps reading the update channel after `error`: one that fell
/// behind skips the updates it missed and is told to refresh its dashboard at the next
/// keep-alive, and only a closed channel ends it.
fn keeps_reading(error: &broadcast::error::RecvError) -> bool {
    matches!(error, broadcast::error::RecvError::Lagged(_))
}

/// What the send loop picked to send next, apart from the keep-alive tick.
enum Outgoing {
    Update(Box<WsUpdate>),
    Missed(broadcast::error::RecvError),
    Answer(String),
    Capture(QueuedCapture),
}

/// Send the connection's broadcast updates, answers and policy input captures to the
/// client, and at each `ping_interval` tick recheck its access, send one
/// `refresh_dashboard` if it fell behind the update channel since the last tick, and
/// ping it. Returns when the client is gone or stops reading, or the update channel closes.
async fn send_loop<S>(
    mut sender: S,
    mut rx: broadcast::Receiver<WsUpdate>,
    mut answer_rx: tokio::sync::mpsc::Receiver<String>,
    mut capture_rx: tokio::sync::mpsc::Receiver<QueuedCapture>,
    send_sub: &RwLock<WsSubscription>,
    caller: Option<&WsCaller>,
    mut ping_interval: tokio::time::Interval,
) where
    S: futures::Sink<Message> + Unpin,
{
    let mut logs_allowed = WsCaller::logs_allowed(caller).await;
    let mut refresh_pending = false;

    'send: loop {
        let outgoing = tokio::select! {
            // A due keep-alive recheck runs before any queued capture is sent; the
            // other queues share the rest fairly, so a busy broadcast starves none.
            biased;
            _ = ping_interval.tick() => {
                logs_allowed = WsCaller::logs_allowed(caller).await;
                let stopped = recheck_at_keep_alive(send_sub, caller, &mut capture_rx).await;
                for answer in stopped {
                    if !deliver(&mut sender, Message::Text(answer.into())).await {
                        break 'send;
                    }
                }
                if refresh_pending {
                    refresh_pending = false;
                    match serde_json::to_string(&WsUpdate::RefreshDashboard) {
                        Ok(refresh) => {
                            if !deliver(&mut sender, Message::Text(refresh.into())).await {
                                break;
                            }
                        }
                        Err(e) => error!("Failed to serialize update: {}", e),
                    }
                }
                if !deliver(&mut sender, Message::Ping("ping".into())).await {
                    break;
                }
                debug!("Sent WebSocket ping");
                continue;
            }
            outgoing = async {
                tokio::select! {
                    update = rx.recv() => match update {
                        Ok(update) => Outgoing::Update(Box::new(update)),
                        Err(error) => Outgoing::Missed(error),
                    },
                    Some(answer) = answer_rx.recv() => Outgoing::Answer(answer),
                    Some(capture) = capture_rx.recv() => Outgoing::Capture(capture),
                }
            } => outgoing,
        };

        let msg = match outgoing {
            Outgoing::Update(update) => {
                if !admits(&update, logs_allowed) {
                    continue;
                }
                // DashboardDelta is already serialized; apply per-client
                // section filtering before forwarding.
                match update.as_ref() {
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
                }
            }
            Outgoing::Missed(error) if keeps_reading(&error) => {
                debug!("WebSocket client fell behind the update channel: {}", error);
                refresh_pending = true;
                continue;
            }
            Outgoing::Missed(_) => break,
            Outgoing::Answer(answer) => Message::Text(answer.into()),
            Outgoing::Capture(capture) => {
                let held = send_sub
                    .read()
                    .await
                    .policy_input
                    .get(&capture.surface_id)
                    .is_some_and(|listening| listening.id() == capture.listen);
                if !held {
                    continue;
                }
                Message::Text(capture.update.as_ref().into())
            }
        };
        if !deliver(&mut sender, msg).await {
            break;
        }
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
    let rx = state.subscribe();

    // Per-connection subscription – shared between send & recv tasks.
    // Captured policy input of the surfaces this connection listens to, sent by the send task.
    let (capture_tx, capture_rx) = tokio::sync::mpsc::channel::<QueuedCapture>(MAX_PENDING_CAPTURES);
    let subscription = Arc::new(RwLock::new(WsSubscription::new(capture_tx).for_user(user_of(caller.as_ref()))));
    let caller = Arc::new(caller);
    // Answers to the client's own requests, sent by the send task.
    // Bounded, so a client that stops reading its socket is no longer read from either.
    let (answer_tx, answer_rx) = tokio::sync::mpsc::channel::<String>(MAX_PENDING_ANSWERS);

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
    let send_caller = Arc::clone(&caller);
    let mut send_task = tokio::spawn(async move {
        let mut ping_interval = tokio::time::interval(KEEP_ALIVE_INTERVAL);
        ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        send_loop(sender, rx, answer_rx, capture_rx, &send_sub, (*send_caller).as_ref(), ping_interval).await;
    });

    // Handle incoming messages from client (ping/pong, close, and subscribe)
    let recv_sub = Arc::clone(&subscription);
    let recv_user_id = user_id.clone();
    let recv_caller = Arc::clone(&caller);
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Text(text) => {
                    // Try to parse as a subscribe command
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                        let message_type = value
                            .get("type")
                            .and_then(|t| t.as_str())
                            .map(str::to_string);
                        if let Some(start @ ("capture_policy_input" | "stop_capturing_policy_input")) =
                            message_type.as_deref()
                        {
                            let answer = match serde_json::from_value::<PolicyInputListenMessage>(value) {
                                Ok(message) => {
                                    listen_to_policy_input(
                                        &recv_sub,
                                        (*recv_caller).as_ref(),
                                        message,
                                        start == "capture_policy_input",
                                    )
                                    .await
                                }
                                Err(_) => invalid_surface_id_answer(start == "capture_policy_input"),
                            };
                            if answer_tx
                                .send(answer)
                                .await
                                .is_err()
                            {
                                break;
                            }
                        } else if message_type.as_deref() == Some("subscribe") {
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

    #[test]
    fn an_identity_frame_never_carries_a_private_key_whoever_produced_it() {
        let ws = super::WsState::new(4);
        let mut updates = ws.subscribe();

        ws.broadcast(super::WsUpdate::IdentityUpdated {
            identity: serde_json::json!({
                "did": "did:example:agent",
                "private_key": { "kty": "OKP", "d": "secret" },
                "nested": [{ "private_key_jwk": { "d": "secret" }, "kept": 1 }],
                "identity_fields": { "d": "a caller field that happens to be named d" },
            }),
        });

        let super::WsUpdate::IdentityUpdated { identity } = updates.try_recv().unwrap() else {
            panic!("expected an identity update");
        };
        assert_eq!(
            identity,
            serde_json::json!({
                "did": "did:example:agent",
                "nested": [{ "kept": 1 }],
                "identity_fields": { "d": "a caller field that happens to be named d" },
            })
        );
    }

    #[test]
    fn frames_that_are_not_identities_are_passed_on_as_they_are() {
        let ws = super::WsState::new(4);
        let mut updates = ws.subscribe();
        let metrics = serde_json::json!({ "private_key": "not an identity frame" });

        ws.broadcast(super::WsUpdate::MetricsUpdated { metrics: metrics.clone() });

        let super::WsUpdate::MetricsUpdated { metrics: received } = updates.try_recv().unwrap() else {
            panic!("expected a metrics update");
        };
        assert_eq!(received, metrics);
    }
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
        let mut sub = super::WsSubscription::new(tokio::sync::mpsc::channel(1).0);
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

    #[test]
    fn captured_policy_input_never_goes_through_the_broadcast() {
        let captured = super::WsUpdate::PolicyInputCaptured {
            config_id: "alpha".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            plane: "surface".to_string(),
            engine: "alpha".to_string(),
            slot: "target".to_string(),
            transit_point: None,
            policies: Vec::new(),
            decided_by: None,
            input: Box::new(serde_json::json!({ "a2a": { "text": "hello" } })),
            decision: "allow".to_string(),
            reason: None,
            surface_variant: None,
        };

        assert!(!super::admits(&captured, true));
    }

    #[tokio::test]
    async fn a_connection_that_falls_behind_keeps_reading_and_only_a_closed_channel_ends_it() {
        let (tx, mut rx) = tokio::sync::broadcast::channel::<u8>(1);
        tx.send(1).unwrap();
        tx.send(2).unwrap();

        let lagged = rx.recv().await.unwrap_err();
        assert!(matches!(lagged, tokio::sync::broadcast::error::RecvError::Lagged(1)));
        assert!(super::keeps_reading(&lagged));
        assert_eq!(rx.recv().await.unwrap(), 2);

        drop(tx);
        let closed = rx.recv().await.unwrap_err();
        assert!(!super::keeps_reading(&closed));
    }

    #[tokio::test]
    async fn a_connection_may_read_policy_input_only_when_its_user_may_edit_surfaces_and_policies() {
        use crate::auth::types::UserRole;

        let dir = TempDir::new().unwrap();
        let admin = caller_for(guard_with_user(&dir, UserRole::Administrator).await, "user-1").await;
        assert!(super::WsCaller::policy_input_allowed(Some(&admin)).await);

        let dir = TempDir::new().unwrap();
        let user = caller_for(guard_with_user(&dir, UserRole::User).await, "user-1").await;
        assert!(!super::WsCaller::policy_input_allowed(Some(&user)).await);

        admin
            .sessions
            .remove_sessions_for_user("user-1")
            .await;
        assert!(!super::WsCaller::policy_input_allowed(Some(&admin)).await);
        assert!(!super::WsCaller::policy_input_allowed(None).await);
    }

    #[tokio::test]
    async fn a_connection_whose_user_holds_only_one_of_surfaces_edit_and_policies_edit_reads_no_policy_input() {
        use crate::auth::types::UserRole;

        for (granted, allowed) in [
            (&["surfaces.edit"][..], false),
            (&["policies.edit"][..], false),
            (&["surfaces.edit", "policies.edit"][..], true),
        ] {
            let dir = TempDir::new().unwrap();
            let guard = guard_with_user_and_permissions(&dir, UserRole::PowerUser, granted).await;
            let poweruser = caller_for(guard, "user-1").await;
            assert_eq!(super::WsCaller::policy_input_allowed(Some(&poweruser)).await, allowed, "{granted:?}");
        }
    }

    fn subscription() -> tokio::sync::RwLock<super::WsSubscription> {
        tokio::sync::RwLock::new(super::WsSubscription::new(tokio::sync::mpsc::channel(1).0))
    }

    fn listen_message(surface_id: &str) -> super::PolicyInputListenMessage {
        super::PolicyInputListenMessage {
            surface_id: surface_id.to_string(),
        }
    }

    fn answer(text: String) -> serde_json::Value {
        serde_json::from_str(&text).unwrap()
    }

    #[tokio::test]
    async fn a_connection_captures_a_surface_while_it_listens_and_stops_when_it_stops_or_closes() {
        use crate::auth::types::UserRole;
        use crate::policies::input_capture::is_captured;

        let dir = TempDir::new().unwrap();
        let admin = caller_for(guard_with_user(&dir, UserRole::Administrator).await, "user-1").await;
        let subscription = subscription();

        let started =
            answer(super::listen_to_policy_input(&subscription, Some(&admin), listen_message("ws-listen"), true).await);
        assert_eq!(started["type"], "policy_input_capture");
        assert_eq!(started["surface_id"], "ws-listen");
        assert_eq!(started["listening"], true);
        assert!(is_captured("ws-listen"));
        assert!(
            subscription
                .read()
                .await
                .listens_to("ws-listen")
        );

        let stopped = answer(
            super::listen_to_policy_input(&subscription, Some(&admin), listen_message("ws-listen"), false).await,
        );
        assert_eq!(stopped["listening"], false);
        assert!(!is_captured("ws-listen"));

        super::listen_to_policy_input(&subscription, Some(&admin), listen_message("ws-closed"), true).await;
        assert!(is_captured("ws-closed"));
        drop(subscription);
        assert!(!is_captured("ws-closed"));
    }

    #[tokio::test]
    async fn a_capture_is_queued_only_for_the_connection_that_listens_to_its_surface() {
        use crate::auth::types::UserRole;
        use crate::policies::input_capture::{begin, received_captures};

        let dir = TempDir::new().unwrap();
        let admin = caller_for(guard_with_user(&dir, UserRole::Administrator).await, "user-1").await;
        let (listener_tx, mut listener_rx) = tokio::sync::mpsc::channel(8);
        let listener = tokio::sync::RwLock::new(super::WsSubscription::new(listener_tx));
        let (bystander_tx, mut bystander_rx) = tokio::sync::mpsc::channel(8);
        let bystander = tokio::sync::RwLock::new(super::WsSubscription::new(bystander_tx));
        super::listen_to_policy_input(&listener, Some(&admin), listen_message("ws-queued"), true).await;
        super::listen_to_policy_input(&bystander, Some(&admin), listen_message("ws-queued-other"), true).await;

        begin("surface", "ws-queued", &serde_json::json!({ "channel": { "config_id": "ws-queued" } }), Vec::new)
            .unwrap()
            .finish(Ok((true, None)));

        let captures = received_captures(&mut listener_rx);
        assert_eq!(captures.len(), 1, "{captures:?}");
        assert_eq!(captures[0]["config_id"], "ws-queued");
        assert!(received_captures(&mut bystander_rx).is_empty());
    }

    #[tokio::test]
    async fn a_listener_keeps_listening_while_it_may_and_is_stopped_and_told_once_it_loses_a_permission() {
        use crate::auth::types::{UserRole, UserStatus};
        use crate::policies::input_capture::is_captured;

        for (role, status) in [(UserRole::User, UserStatus::Approved), (UserRole::Administrator, UserStatus::Disabled)]
        {
            let dir = TempDir::new().unwrap();
            let caller = caller_for(guard_with_user(&dir, UserRole::Administrator).await, "user-1").await;
            let subscription = subscription();
            super::listen_to_policy_input(&subscription, Some(&caller), listen_message("ws-revoked-a"), true).await;
            super::listen_to_policy_input(&subscription, Some(&caller), listen_message("ws-revoked-b"), true).await;

            let (allowed, answers) = super::recheck_policy_input(&subscription, Some(&caller)).await;
            assert!(allowed);
            assert!(answers.is_empty());
            assert!(is_captured("ws-revoked-a"));

            caller
                .guard
                .storage
                .save_user(&user_data(role, status))
                .await
                .unwrap();
            let (allowed, answers) = super::recheck_policy_input(&subscription, Some(&caller)).await;

            assert!(!allowed);
            let mut answers: Vec<serde_json::Value> = answers
                .into_iter()
                .map(answer)
                .collect();
            answers.sort_by_key(|answer| answer["surface_id"].to_string());
            assert_eq!(answers.len(), 2, "{answers:?}");
            for (answer, surface_id) in answers
                .iter()
                .zip(["ws-revoked-a", "ws-revoked-b"])
            {
                assert_eq!(answer["surface_id"], surface_id);
                assert_eq!(answer["listening"], false);
                assert_eq!(answer["error"], "needs surfaces.edit and policies.edit");
            }
            assert!(
                subscription
                    .read()
                    .await
                    .policy_input
                    .is_empty()
            );
            assert!(!is_captured("ws-revoked-a"));
            assert!(!is_captured("ws-revoked-b"));
        }
    }

    #[tokio::test]
    async fn a_listener_whose_session_ends_is_stopped_at_the_next_check() {
        use crate::policies::input_capture::is_captured;

        let dir = TempDir::new().unwrap();
        let caller =
            caller_for(guard_with_user(&dir, crate::auth::types::UserRole::Administrator).await, "user-1").await;
        let subscription = subscription();
        super::listen_to_policy_input(&subscription, Some(&caller), listen_message("ws-session-ended"), true).await;

        caller
            .sessions
            .remove_sessions_for_user("user-1")
            .await;
        let (allowed, answers) = super::recheck_policy_input(&subscription, Some(&caller)).await;

        assert!(!allowed);
        assert_eq!(answers.len(), 1);
        assert_eq!(answer(answers[0].clone())["error"], super::SESSION_ENDED);
        assert!(!is_captured("ws-session-ended"));
    }

    #[tokio::test]
    async fn a_listen_is_refused_while_policy_input_capture_is_turned_off() {
        use crate::policies::input_capture::{is_captured, set_turned_on_in_this_thread};

        let dir = TempDir::new().unwrap();
        let admin =
            caller_for(guard_with_user(&dir, crate::auth::types::UserRole::Administrator).await, "user-1").await;
        let subscription = subscription();
        set_turned_on_in_this_thread(false);

        let refused =
            answer(super::listen_to_policy_input(&subscription, Some(&admin), listen_message("ws-off"), true).await);

        set_turned_on_in_this_thread(true);
        assert_eq!(refused["listening"], false);
        assert_eq!(refused["error"], "policy input capture is turned off");
        assert!(!is_captured("ws-off"));
    }

    #[tokio::test]
    async fn listening_stops_at_the_next_check_once_policy_input_capture_is_turned_off() {
        use crate::policies::input_capture::{is_captured, set_turned_on_in_this_thread};

        let dir = TempDir::new().unwrap();
        let admin =
            caller_for(guard_with_user(&dir, crate::auth::types::UserRole::Administrator).await, "user-1").await;
        let subscription = subscription();
        super::listen_to_policy_input(&subscription, Some(&admin), listen_message("ws-turned-off"), true).await;
        set_turned_on_in_this_thread(false);

        let (allowed, answers) = super::recheck_policy_input(&subscription, Some(&admin)).await;

        set_turned_on_in_this_thread(true);
        assert!(!allowed);
        assert_eq!(answers.len(), 1);
        let stopped = answer(answers[0].clone());
        assert_eq!(stopped["surface_id"], "ws-turned-off");
        assert_eq!(stopped["listening"], false);
        assert_eq!(stopped["error"], "policy input capture is turned off");
        assert!(!is_captured("ws-turned-off"));
    }

    /// The `policy_input_capture_started` and `policy_input_capture_stopped` records `records`
    /// holds, as (category, surface id, actor id, reason).
    fn capture_records(
        records: &[crate::delegation_vault::audit::DelegationAuditEvent]
    ) -> Vec<(String, String, String, Option<String>)> {
        records
            .iter()
            .filter_map(|record| {
                let category = crate::delegation_vault::audit::action_category(&record.event);
                let stored = serde_json::to_value(&record.event).ok()?;
                let details = stored.get(category)?;
                Some((
                    category.to_string(),
                    record
                        .surface_id
                        .clone()
                        .unwrap_or_default(),
                    details["actor"]["id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    details["reason"]
                        .as_str()
                        .map(str::to_string),
                ))
            })
            .filter(|(category, ..)| category.starts_with("policy_input_capture_"))
            .collect()
    }

    fn record(
        category: &str,
        surface_id: &str,
        reason: Option<&str>,
    ) -> (String, String, String, Option<String>) {
        (category.to_string(), surface_id.to_string(), "user-1".to_string(), reason.map(str::to_string))
    }

    #[tokio::test]
    async fn starting_and_stopping_a_listen_records_who_listened_to_which_surface() {
        use crate::audit::producer::capture;

        let dir = TempDir::new().unwrap();
        let admin =
            caller_for(guard_with_user(&dir, crate::auth::types::UserRole::Administrator).await, "user-1").await;
        let subscription = subscription();

        let ((), records) = capture(async {
            super::listen_to_policy_input(&subscription, Some(&admin), listen_message("ws-audited"), true).await;
            super::listen_to_policy_input(&subscription, Some(&admin), listen_message("ws-audited"), true).await;
            super::listen_to_policy_input(&subscription, Some(&admin), listen_message("ws-audited"), false).await;
            super::listen_to_policy_input(&subscription, Some(&admin), listen_message("ws-audited"), false).await;
        })
        .await;

        assert_eq!(
            capture_records(&records),
            [
                record("policy_input_capture_started", "ws-audited", None),
                record("policy_input_capture_stopped", "ws-audited", Some("stopped")),
            ]
        );
    }

    #[tokio::test]
    async fn a_refused_listen_records_nothing() {
        use crate::audit::producer::capture;
        use crate::policies::input_capture::set_turned_on_in_this_thread;

        let dir = TempDir::new().unwrap();
        let user = caller_for(guard_with_user(&dir, crate::auth::types::UserRole::User).await, "user-1").await;
        let dir = TempDir::new().unwrap();
        let admin =
            caller_for(guard_with_user(&dir, crate::auth::types::UserRole::Administrator).await, "user-1").await;
        let subscription = subscription();

        let ((), records) = capture(async {
            super::listen_to_policy_input(&subscription, Some(&user), listen_message("ws-refused-audit"), true).await;
            set_turned_on_in_this_thread(false);
            super::listen_to_policy_input(&subscription, Some(&admin), listen_message("ws-refused-audit"), true).await;
            set_turned_on_in_this_thread(true);
        })
        .await;

        assert!(capture_records(&records).is_empty(), "{records:?}");
    }

    #[tokio::test]
    async fn a_listen_ended_by_a_check_or_a_closed_connection_records_why() {
        use crate::audit::producer::capture;
        use crate::auth::types::{UserRole, UserStatus};
        use crate::policies::input_capture::set_turned_on_in_this_thread;

        let dir = TempDir::new().unwrap();
        let admin = caller_for(guard_with_user(&dir, UserRole::Administrator).await, "user-1").await;
        let subscription = subscription();
        let ((), records) = capture(async {
            super::listen_to_policy_input(&subscription, Some(&admin), listen_message("ws-ended-off"), true).await;
            set_turned_on_in_this_thread(false);
            super::recheck_policy_input(&subscription, Some(&admin)).await;
            set_turned_on_in_this_thread(true);

            let closing = tokio::sync::RwLock::new(
                super::WsSubscription::new(tokio::sync::mpsc::channel(1).0).for_user("user-1"),
            );
            super::listen_to_policy_input(&closing, Some(&admin), listen_message("ws-ended-closed"), true).await;
            drop(closing);

            super::listen_to_policy_input(&subscription, Some(&admin), listen_message("ws-ended-role"), true).await;
            admin
                .guard
                .storage
                .save_user(&user_data(UserRole::User, UserStatus::Approved))
                .await
                .unwrap();
            super::recheck_policy_input(&subscription, Some(&admin)).await;
        })
        .await;
        let dir = TempDir::new().unwrap();
        let other = caller_for(guard_with_user(&dir, UserRole::Administrator).await, "user-1").await;
        let other_subscription = self::subscription();
        let ((), session_records) = capture(async {
            super::listen_to_policy_input(&other_subscription, Some(&other), listen_message("ws-ended-session"), true)
                .await;
            other
                .sessions
                .remove_sessions_for_user("user-1")
                .await;
            super::recheck_policy_input(&other_subscription, Some(&other)).await;
        })
        .await;

        assert_eq!(
            capture_records(&records),
            [
                record("policy_input_capture_started", "ws-ended-off", None),
                record("policy_input_capture_stopped", "ws-ended-off", Some("turned_off")),
                record("policy_input_capture_started", "ws-ended-closed", None),
                record("policy_input_capture_stopped", "ws-ended-closed", Some("connection_closed")),
                record("policy_input_capture_started", "ws-ended-role", None),
                record("policy_input_capture_stopped", "ws-ended-role", Some("permission_missing")),
            ]
        );
        assert_eq!(
            capture_records(&session_records),
            [
                record("policy_input_capture_started", "ws-ended-session", None),
                record("policy_input_capture_stopped", "ws-ended-session", Some("session_ended")),
            ]
        );
    }

    #[tokio::test]
    async fn captures_queued_before_access_is_lost_are_discarded_at_the_keep_alive_recheck() {
        use crate::policies::input_capture::begin;

        let dir = TempDir::new().unwrap();
        let caller =
            caller_for(guard_with_user(&dir, crate::auth::types::UserRole::Administrator).await, "user-1").await;
        let (captures_tx, mut captures) = tokio::sync::mpsc::channel(8);
        let subscription = tokio::sync::RwLock::new(super::WsSubscription::new(captures_tx));
        super::listen_to_policy_input(&subscription, Some(&caller), listen_message("ws-drained"), true).await;
        let capture = || {
            begin("surface", "ws-drained", &serde_json::json!({ "channel": { "config_id": "ws-drained" } }), Vec::new)
                .unwrap()
                .finish(Ok((true, None)));
        };

        capture();
        let stopped = super::recheck_at_keep_alive(&subscription, Some(&caller), &mut captures).await;
        assert!(stopped.is_empty());
        assert!(captures.try_recv().is_ok(), "a capture queued while the caller may listen is kept");

        capture();
        capture();
        caller
            .sessions
            .remove_sessions_for_user("user-1")
            .await;
        let stopped = super::recheck_at_keep_alive(&subscription, Some(&caller), &mut captures).await;

        assert_eq!(stopped.len(), 1);
        assert_eq!(answer(stopped[0].clone())["error"], super::SESSION_ENDED);
        assert!(captures.try_recv().is_err(), "no queued capture is left to send");
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_stops_reading_is_given_up_on_after_the_send_timeout() {
        use axum::extract::ws::Message;

        let (mut reading, mut read) = futures::channel::mpsc::channel::<Message>(1);
        assert!(super::deliver(&mut reading, Message::Ping("one".into())).await);
        read.try_recv().unwrap();
        assert!(super::deliver(&mut reading, Message::Ping("two".into())).await);

        let (mut stalled, _never_read) = futures::channel::mpsc::channel::<Message>(0);
        let started = tokio::time::Instant::now();
        assert!(!super::deliver(&mut stalled, Message::Ping("stuck".into())).await);
        assert_eq!(started.elapsed(), super::SEND_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stop_answer_the_client_does_not_read_at_a_keep_alive_check_ends_the_connection_without_a_ping() {
        use axum::extract::ws::Message;

        let dir = TempDir::new().unwrap();
        let caller =
            caller_for(guard_with_user(&dir, crate::auth::types::UserRole::Administrator).await, "user-1").await;
        let (captures_tx, captures) = tokio::sync::mpsc::channel(8);
        let subscription = tokio::sync::RwLock::new(super::WsSubscription::new(captures_tx));
        super::listen_to_policy_input(&subscription, Some(&caller), listen_message("ws-stalled-stop"), true).await;
        caller
            .sessions
            .remove_sessions_for_user("user-1")
            .await;
        let (updates_tx, updates) = tokio::sync::broadcast::channel(8);
        let (answers_tx, answers) = tokio::sync::mpsc::channel(8);
        let (stalled, mut never_read) = futures::channel::mpsc::channel::<Message>(0);

        let started = tokio::time::Instant::now();
        let ping_interval = tokio::time::interval(super::KEEP_ALIVE_INTERVAL);
        super::send_loop(stalled, updates, answers, captures, &subscription, Some(&caller), ping_interval).await;

        assert_eq!(started.elapsed(), super::SEND_TIMEOUT);
        let Ok(Message::Text(stop)) = never_read.try_recv() else {
            panic!("the stop answer is the one message sent");
        };
        assert_eq!(answer(stop.to_string())["error"], super::SESSION_ENDED);
        assert!(never_read.try_recv().is_err(), "no ping follows the stop answer");
        drop((updates_tx, answers_tx));
    }

    /// What `sent` received, in order: each text message as JSON, and each ping as `"ping"`.
    fn sent_messages(mut sent: futures::channel::mpsc::Receiver<axum::extract::ws::Message>) -> Vec<serde_json::Value> {
        use axum::extract::ws::Message;

        let mut messages = Vec::new();
        while let Ok(message) = sent.try_recv() {
            messages.push(match message {
                Message::Text(text) => serde_json::from_str(text.as_str()).unwrap(),
                Message::Ping(_) => serde_json::json!("ping"),
                other => panic!("unexpected message {other:?}"),
            });
        }
        messages
    }

    /// Run the send loop over `captures` until it has nothing left to send, with no
    /// broadcast updates or answers, and return what it sent.
    async fn sent_until_idle(
        captures: tokio::sync::mpsc::Receiver<crate::policies::input_capture::QueuedCapture>,
        subscription: &tokio::sync::RwLock<super::WsSubscription>,
        caller: &super::WsCaller,
    ) -> Vec<serde_json::Value> {
        let (_updates_tx, updates) = tokio::sync::broadcast::channel(1);
        let (_answers_tx, answers) = tokio::sync::mpsc::channel(1);
        let (sink, sent) = futures::channel::mpsc::channel(64);
        let ping_interval = tokio::time::interval(super::KEEP_ALIVE_INTERVAL);
        let looping = super::send_loop(sink, updates, answers, captures, subscription, Some(caller), ping_interval);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), looping)
                .await
                .is_err()
        );
        sent_messages(sent)
    }

    fn capture_on(
        surface_id: &str,
        allow: bool,
    ) {
        if let Some(capture) = crate::policies::input_capture::begin(
            "surface",
            surface_id,
            &serde_json::json!({ "channel": { "config_id": surface_id } }),
            Vec::new,
        ) {
            capture.finish(Ok((allow, None)));
        }
    }

    #[tokio::test]
    async fn queued_answers_and_a_queued_capture_are_sent_before_a_busy_broadcast_drains() {
        const UPDATES: usize = 500;
        let dir = TempDir::new().unwrap();
        let caller =
            caller_for(guard_with_user(&dir, crate::auth::types::UserRole::Administrator).await, "user-1").await;
        let (captures_tx, captures) = tokio::sync::mpsc::channel(8);
        let subscription = tokio::sync::RwLock::new(super::WsSubscription::new(captures_tx));
        super::listen_to_policy_input(&subscription, Some(&caller), listen_message("ws-busy"), true).await;
        capture_on("ws-busy", true);
        let (updates_tx, updates) = tokio::sync::broadcast::channel(UPDATES);
        for _ in 0..UPDATES {
            updates_tx
                .send(super::WsUpdate::RefreshDashboard)
                .unwrap();
        }
        drop(updates_tx);
        let (answers_tx, answers) = tokio::sync::mpsc::channel(super::MAX_PENDING_ANSWERS);
        for n in 0..super::MAX_PENDING_ANSWERS {
            answers_tx
                .try_send(serde_json::json!({ "type": "answer", "n": n }).to_string())
                .unwrap();
        }
        let (sink, sent) = futures::channel::mpsc::channel(UPDATES + super::MAX_PENDING_ANSWERS + 8);
        let ping_interval = tokio::time::interval(super::KEEP_ALIVE_INTERVAL);

        super::send_loop(sink, updates, answers, captures, &subscription, Some(&caller), ping_interval).await;

        let sent = sent_messages(sent);
        let of_type = |messages: &[serde_json::Value], kind: &str| {
            messages
                .iter()
                .filter(|message| message["type"] == kind)
                .count()
        };
        assert_eq!(of_type(&sent, "refresh_dashboard"), UPDATES);
        let last_update = sent
            .iter()
            .rposition(|message| message["type"] == "refresh_dashboard")
            .unwrap();
        let before_drained = &sent[..last_update];
        assert_eq!(of_type(before_drained, "answer"), super::MAX_PENDING_ANSWERS);
        assert_eq!(of_type(before_drained, "policy_input_captured"), 1);
        drop(answers_tx);
    }

    #[tokio::test(start_paused = true)]
    async fn a_due_recheck_that_revokes_access_runs_before_a_queued_capture_is_sent() {
        for run in 0..32 {
            let surface_id = format!("ws-recheck-first-{run}");
            let dir = TempDir::new().unwrap();
            let caller =
                caller_for(guard_with_user(&dir, crate::auth::types::UserRole::Administrator).await, "user-1").await;
            let (captures_tx, captures) = tokio::sync::mpsc::channel(8);
            let subscription = tokio::sync::RwLock::new(super::WsSubscription::new(captures_tx));
            super::listen_to_policy_input(&subscription, Some(&caller), listen_message(&surface_id), true).await;
            capture_on(&surface_id, true);
            caller
                .sessions
                .remove_sessions_for_user("user-1")
                .await;
            let (_, updates) = tokio::sync::broadcast::channel::<super::WsUpdate>(1);
            let (_, answers) = tokio::sync::mpsc::channel(1);
            let (sink, sent) = futures::channel::mpsc::channel(8);
            let mut ping_interval = tokio::time::interval(super::KEEP_ALIVE_INTERVAL);
            ping_interval.tick().await;
            tokio::time::advance(super::KEEP_ALIVE_INTERVAL).await;

            super::send_loop(sink, updates, answers, captures, &subscription, Some(&caller), ping_interval).await;

            let sent = sent_messages(sent);
            assert_eq!(sent.len(), 2, "run {run}: {sent:?}");
            assert_eq!(sent[0]["surface_id"], surface_id.as_str());
            assert_eq!(sent[0]["error"], super::SESSION_ENDED);
            assert_eq!(sent[1], "ping");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn captures_and_a_skipped_notice_queued_before_a_stop_are_not_sent() {
        let dir = TempDir::new().unwrap();
        let caller =
            caller_for(guard_with_user(&dir, crate::auth::types::UserRole::Administrator).await, "user-1").await;
        let (captures_tx, mut captures) = tokio::sync::mpsc::channel(2);
        let subscription = tokio::sync::RwLock::new(super::WsSubscription::new(captures_tx));
        super::listen_to_policy_input(&subscription, Some(&caller), listen_message("ws-stopped-queue"), true).await;
        for _ in 0..3 {
            capture_on("ws-stopped-queue", true);
        }
        captures.try_recv().unwrap();
        capture_on("ws-stopped-queue", true);
        assert_eq!(captures.len(), 2, "a capture and a skipped notice are queued before the stop");
        super::listen_to_policy_input(&subscription, Some(&caller), listen_message("ws-stopped-queue"), false).await;

        let sent = sent_until_idle(captures, &subscription, &caller).await;

        assert_eq!(sent, vec![serde_json::json!("ping")]);
    }

    #[tokio::test(start_paused = true)]
    async fn after_a_stop_and_a_new_listen_only_the_new_listens_captures_are_sent() {
        let dir = TempDir::new().unwrap();
        let caller =
            caller_for(guard_with_user(&dir, crate::auth::types::UserRole::Administrator).await, "user-1").await;
        let (captures_tx, captures) = tokio::sync::mpsc::channel(8);
        let subscription = tokio::sync::RwLock::new(super::WsSubscription::new(captures_tx));
        super::listen_to_policy_input(&subscription, Some(&caller), listen_message("ws-restarted"), true).await;
        capture_on("ws-restarted", true);
        super::listen_to_policy_input(&subscription, Some(&caller), listen_message("ws-restarted"), false).await;
        super::listen_to_policy_input(&subscription, Some(&caller), listen_message("ws-restarted"), true).await;
        capture_on("ws-restarted", false);

        let sent = sent_until_idle(captures, &subscription, &caller).await;

        assert_eq!(sent.len(), 2, "{sent:?}");
        assert_eq!(sent[0], "ping");
        assert_eq!(sent[1]["config_id"], "ws-restarted");
        assert_eq!(sent[1]["decision"], "deny");
    }

    #[tokio::test(start_paused = true)]
    async fn stopping_one_surface_still_sends_the_queued_captures_of_another() {
        let dir = TempDir::new().unwrap();
        let caller =
            caller_for(guard_with_user(&dir, crate::auth::types::UserRole::Administrator).await, "user-1").await;
        let (captures_tx, captures) = tokio::sync::mpsc::channel(8);
        let subscription = tokio::sync::RwLock::new(super::WsSubscription::new(captures_tx));
        super::listen_to_policy_input(&subscription, Some(&caller), listen_message("ws-stopped-s"), true).await;
        super::listen_to_policy_input(&subscription, Some(&caller), listen_message("ws-kept-t"), true).await;
        capture_on("ws-stopped-s", true);
        capture_on("ws-kept-t", true);
        super::listen_to_policy_input(&subscription, Some(&caller), listen_message("ws-stopped-s"), false).await;

        let sent = sent_until_idle(captures, &subscription, &caller).await;

        assert_eq!(sent.len(), 2, "{sent:?}");
        assert_eq!(sent[0], "ping");
        assert_eq!(sent[1]["type"], "policy_input_captured");
        assert_eq!(sent[1]["config_id"], "ws-kept-t");
    }

    fn channel_expired() -> super::WsUpdate {
        super::WsUpdate::ChannelExpired {
            config_id: "ws-lag".to_string(),
            channel_name: "lag".to_string(),
        }
    }

    /// Run the send loop of a connection without a caller over `updates` while `producing`
    /// runs, for at most `run_for`. Returns whether the loop ended by itself, and the type
    /// of each message it sent, with a ping as `"ping"`.
    async fn kinds_sent_over(
        updates: tokio::sync::broadcast::Receiver<super::WsUpdate>,
        producing: impl std::future::Future<Output = ()>,
        run_for: std::time::Duration,
    ) -> (bool, Vec<String>) {
        let (captures_tx, captures) = tokio::sync::mpsc::channel(1);
        let subscription = tokio::sync::RwLock::new(super::WsSubscription::new(captures_tx));
        let (_answers_tx, answers) = tokio::sync::mpsc::channel(1);
        let (sink, sent) = futures::channel::mpsc::channel(64);
        let ping_interval = tokio::time::interval(super::KEEP_ALIVE_INTERVAL);
        let looping = super::send_loop(sink, updates, answers, captures, &subscription, None, ping_interval);
        let (_, ran) = tokio::join!(producing, tokio::time::timeout(run_for, looping));
        let kinds = sent_messages(sent)
            .into_iter()
            .map(|message| match message.as_str() {
                Some(ping) => ping.to_string(),
                None => message["type"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            })
            .collect();
        (ran.is_ok(), kinds)
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_that_falls_behind_several_times_is_told_once_to_refresh_at_its_next_keep_alive() {
        let (updates_tx, updates) = tokio::sync::broadcast::channel(1);
        let producing = async {
            for _ in 0..3 {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                for _ in 0..3 {
                    updates_tx
                        .send(channel_expired())
                        .unwrap();
                }
            }
        };

        let (ended, sent) =
            kinds_sent_over(updates, producing, super::KEEP_ALIVE_INTERVAL * 2 + std::time::Duration::from_secs(1))
                .await;

        assert!(!ended, "falling behind does not end the connection");
        assert_eq!(
            sent,
            ["ping", "channel_expired", "channel_expired", "channel_expired", "refresh_dashboard", "ping", "ping"]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_that_keeps_up_is_not_told_to_refresh() {
        let (updates_tx, updates) = tokio::sync::broadcast::channel(8);
        let producing = async {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            for _ in 0..3 {
                updates_tx
                    .send(channel_expired())
                    .unwrap();
            }
        };

        let (ended, sent) =
            kinds_sent_over(updates, producing, super::KEEP_ALIVE_INTERVAL + std::time::Duration::from_secs(1)).await;

        assert!(!ended);
        assert_eq!(sent, ["ping", "channel_expired", "channel_expired", "channel_expired", "ping"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_closed_update_channel_ends_a_connection_that_fell_behind() {
        let (updates_tx, updates) = tokio::sync::broadcast::channel(1);
        for _ in 0..3 {
            updates_tx
                .send(channel_expired())
                .unwrap();
        }
        drop(updates_tx);

        let (ended, sent) =
            kinds_sent_over(updates, async {}, super::KEEP_ALIVE_INTERVAL + std::time::Duration::from_secs(1)).await;

        assert!(ended, "a closed update channel ends the loop");
        assert_eq!(sent, ["ping", "channel_expired"]);
    }

    #[tokio::test]
    async fn a_connection_without_both_permissions_or_a_valid_surface_id_cannot_listen() {
        use crate::auth::types::UserRole;
        use crate::policies::input_capture::is_captured;

        let dir = TempDir::new().unwrap();
        let user = caller_for(guard_with_user(&dir, UserRole::User).await, "user-1").await;
        let subscription = subscription();

        let refused =
            answer(super::listen_to_policy_input(&subscription, Some(&user), listen_message("ws-refused"), true).await);
        assert_eq!(refused["listening"], false);
        assert_eq!(refused["error"], "needs surfaces.edit and policies.edit");
        assert!(!is_captured("ws-refused"));

        let anonymous =
            answer(super::listen_to_policy_input(&subscription, None, listen_message("ws-anonymous"), true).await);
        assert_eq!(anonymous["listening"], false);
        assert_eq!(anonymous["error"], "policy input capture needs dashboard sign-in");
        assert!(!is_captured("ws-anonymous"));

        let dir = TempDir::new().unwrap();
        let admin = caller_for(guard_with_user(&dir, UserRole::Administrator).await, "user-1").await;
        let empty = answer(super::listen_to_policy_input(&subscription, Some(&admin), listen_message(""), true).await);
        assert_eq!(empty["error"], "invalid surface id");
        let long_id = "s".repeat(super::MAX_SURFACE_ID_LEN + 1);
        let long =
            answer(super::listen_to_policy_input(&subscription, Some(&admin), listen_message(&long_id), true).await);
        assert_eq!(long["error"], "invalid surface id");
        assert!(!is_captured(&long_id));
        for forged in ["alpha\nINFO forged line", "alpha\r", "al\u{1b}[31mpha"] {
            let refused =
                answer(super::listen_to_policy_input(&subscription, Some(&admin), listen_message(forged), true).await);
            assert_eq!(refused["listening"], false, "{forged:?}");
            assert_eq!(refused["error"], "invalid surface id", "{forged:?}");
            assert!(!is_captured(forged), "{forged:?}");
        }
    }

    #[test]
    fn a_surface_id_with_a_bidi_or_zero_width_character_is_invalid() {
        assert!(super::is_valid_surface_id("surface-1_ok"));
        for forged in ["alpha\u{202e}ahpla", "al\u{200b}pha", "alpha\u{2066}", "\u{feff}alpha"] {
            assert!(!super::is_valid_surface_id(forged), "{forged:?}");
        }
    }

    #[tokio::test]
    async fn a_start_waiting_for_the_subscription_is_refused_when_the_session_ends_meanwhile() {
        use crate::audit::producer::capture;
        use crate::policies::input_capture::is_captured;

        let dir = TempDir::new().unwrap();
        let admin =
            caller_for(guard_with_user(&dir, crate::auth::types::UserRole::Administrator).await, "user-1").await;
        let subscription = subscription();

        let (refused, records) = capture(async {
            let held = subscription.write().await;
            let starting =
                super::listen_to_policy_input(&subscription, Some(&admin), listen_message("ws-late-start"), true);
            tokio::pin!(starting);
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(200), &mut starting)
                    .await
                    .is_err(),
                "the start waits for the subscription"
            );
            admin
                .sessions
                .remove_sessions_for_user("user-1")
                .await;
            drop(held);
            answer(starting.await)
        })
        .await;

        assert_eq!(refused["listening"], false);
        assert_eq!(refused["error"], super::SESSION_ENDED);
        assert!(!is_captured("ws-late-start"));
        assert!(capture_records(&records).is_empty(), "{records:?}");
    }

    #[tokio::test]
    async fn a_stop_naming_no_valid_surface_is_answered_without_an_error() {
        use crate::auth::types::UserRole;

        let dir = TempDir::new().unwrap();
        let admin = caller_for(guard_with_user(&dir, UserRole::Administrator).await, "user-1").await;
        let subscription = subscription();

        for surface_id in ["", "alpha\nforged"] {
            let stopped = answer(
                super::listen_to_policy_input(&subscription, Some(&admin), listen_message(surface_id), false).await,
            );
            assert_eq!(stopped["type"], "policy_input_capture");
            assert_eq!(stopped["listening"], false);
            assert!(stopped.get("error").is_none(), "{stopped}");
        }
        assert!(
            super::invalid_surface_id_answer(false)
                .find("error")
                .is_none()
        );
        assert_eq!(answer(super::invalid_surface_id_answer(true))["error"], "invalid surface id");
    }

    #[tokio::test]
    async fn a_connection_listens_to_at_most_the_maximum_number_of_surfaces() {
        use crate::auth::types::UserRole;

        let dir = TempDir::new().unwrap();
        let admin = caller_for(guard_with_user(&dir, UserRole::Administrator).await, "user-1").await;
        let subscription = subscription();
        for i in 0..super::MAX_POLICY_INPUT_SURFACES {
            let started = answer(
                super::listen_to_policy_input(
                    &subscription,
                    Some(&admin),
                    listen_message(&format!("ws-max-{i}")),
                    true,
                )
                .await,
            );
            assert_eq!(started["listening"], true);
        }

        let over = answer(
            super::listen_to_policy_input(&subscription, Some(&admin), listen_message("ws-max-over"), true).await,
        );

        assert_eq!(over["listening"], false);
        assert!(!crate::policies::input_capture::is_captured("ws-max-over"));
    }

    async fn guard_with_user(
        dir: &TempDir,
        role: crate::auth::types::UserRole,
    ) -> crate::auth_manager::middleware::RbacGuard {
        guard_with_user_and_permissions(dir, role, &["logs.view"]).await
    }

    /// A guard for a user with `role`, where `poweruser` may use each feature in `poweruser_features`.
    async fn guard_with_user_and_permissions(
        dir: &TempDir,
        role: crate::auth::types::UserRole,
        poweruser_features: &[&str],
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
        for feature in poweruser_features {
            rbac.permissions
                .insert(feature.to_string(), "poweruser".to_string());
        }
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
