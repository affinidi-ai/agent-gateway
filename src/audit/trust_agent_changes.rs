//! Security records of trust agent changes and of refused signing changes: who changed a trust
//! agent connection or a key the gateway signs or signs in with, and who was refused. Each is
//! appended to the [`security_chain`] before the request is answered, logged on the
//! `security_audit` target (refusals at warn) and handed to the audit sinks that select it.
//! Records name ids only, never key material, a grant, a request body or an error text.

use axum::extract::{MatchedPath, Request};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use serde::Serialize;

use crate::audit::context::current_actor;
use crate::audit::events::{
    Actor, ControlKeyRotationOutcome, SecurityRefusalReason, SigningOwnerKind, TrustAgentAction,
};
use crate::audit::policy_refusals::untrusted_id;
use crate::audit::security_chain::{self, ChainLink, LOG_TARGET};
use crate::delegation_vault::audit::{
    DelegationAuditAction, SigningChangeRefusalDetails, TrustAgentChangeDetails, audit_event, emit,
};
use crate::vta::connections::VtaConnection;

/// Marks a `404` answered for a connection the caller may not see, so its refusal is recorded;
/// a `404` for a connection that does not exist is not one.
#[derive(Debug, Clone, Copy)]
pub struct HiddenConnection;

/// Marks a response whose outcome the handler already recorded, so its status is not taken
/// for a refusal.
#[derive(Debug, Clone, Copy)]
pub struct OutcomeRecorded;

/// Whether the caller acknowledged that stopping a connection stops what signs through it.
#[derive(Debug, Clone, Copy, Default)]
pub struct Acknowledged {
    pub signing_users: bool,
    pub stranded_agents: bool,
}

/// A record by `actor` with every other field unset.
pub fn details(actor: Actor) -> TrustAgentChangeDetails {
    TrustAgentChangeDetails {
        actor,
        recorded_at: chrono::Utc::now().to_rfc3339(),
        connection_id: None,
        tenant_id: None,
        action: None,
        status: None,
        reason: None,
        previous_enabled: None,
        enabled: None,
        previous_state: None,
        state: None,
        previous_key_id: None,
        key_id: None,
        outcome: None,
        previous_control_did: None,
        control_did: None,
        acknowledge_signing_users: None,
        acknowledge_stranded_agents: None,
        chain: None,
    }
}

/// The actor of the management request being served, or the gateway outside one.
pub fn actor() -> Actor {
    current_actor().unwrap_or_else(Actor::system)
}

fn about(connection: &VtaConnection) -> TrustAgentChangeDetails {
    let mut record = details(actor());
    record.connection_id = Some(connection.id.clone());
    record.tenant_id = connection.tenant_id.clone();
    record
}

fn acknowledged(
    mut record: TrustAgentChangeDetails,
    acknowledged: Acknowledged,
) -> TrustAgentChangeDetails {
    record.acknowledge_signing_users = Some(acknowledged.signing_users);
    record.acknowledge_stranded_agents = Some(acknowledged.stranded_agents);
    record
}

fn state(connection: &VtaConnection) -> String {
    connection
        .pairing
        .state
        .as_str()
        .to_string()
}

/// A record whose chain link is set once it is appended.
trait Linked: Serialize {
    fn link(&mut self) -> &mut Option<ChainLink>;
}

impl Linked for TrustAgentChangeDetails {
    fn link(&mut self) -> &mut Option<ChainLink> {
        &mut self.chain
    }
}

impl Linked for SigningChangeRefusalDetails {
    fn link(&mut self) -> &mut Option<ChainLink> {
        &mut self.chain
    }
}

/// Appends `record` to the security chain, logs it and hands it to the audit sinks that select
/// `category`. The chain hash covers the record as delivered, less `seq`, `prev_hash` and
/// `record_hash`.
fn write<T: Linked>(
    category: &'static str,
    mut record: T,
    tenant_id: Option<String>,
    refusal: bool,
    wrap: fn(Box<T>) -> DelegationAuditAction,
) {
    *record.link() = None;
    let content = serde_json::to_value(&record).unwrap_or_default();
    let link = security_chain::append(category, &content);
    let seq = link
        .as_ref()
        .map(|link| link.seq);
    let record_hash = link
        .as_ref()
        .map(|link| link.record_hash.clone());
    if refusal {
        tracing::warn!(target: LOG_TARGET, event = category, seq, record_hash, record = %content, "Security record");
    } else {
        tracing::info!(target: LOG_TARGET, event = category, seq, record_hash, record = %content, "Security record");
    }
    *record.link() = link;
    let action = wrap(Box::new(record));
    emit(category, move || {
        let mut event = audit_event(action, None, None, None, None);
        event.tenant_id = tenant_id;
        event
    });
}

fn change(
    category: &'static str,
    record: TrustAgentChangeDetails,
    wrap: fn(Box<TrustAgentChangeDetails>) -> DelegationAuditAction,
) {
    let tenant_id = record.tenant_id.clone();
    write(category, record, tenant_id, false, wrap);
}

pub fn connection_created(connection: &VtaConnection) {
    let mut record = about(connection);
    record.enabled = Some(connection.enabled);
    change("trust_agent_connection_created", record, DelegationAuditAction::TrustAgentConnectionCreated);
}

/// `acknowledgement` is recorded when the update disabled the connection.
pub fn connection_updated(
    previous: &VtaConnection,
    updated: &VtaConnection,
    acknowledgement: Acknowledged,
) {
    let mut record = about(updated);
    record.previous_enabled = Some(previous.enabled);
    record.enabled = Some(updated.enabled);
    if previous.enabled && !updated.enabled {
        record = acknowledged(record, acknowledgement);
    }
    change("trust_agent_connection_updated", record, DelegationAuditAction::TrustAgentConnectionUpdated);
}

pub fn connection_deleted(
    connection: &VtaConnection,
    acknowledgement: Acknowledged,
) {
    let mut record = acknowledged(about(connection), acknowledgement);
    record.previous_state = Some(state(connection));
    change("trust_agent_connection_deleted", record, DelegationAuditAction::TrustAgentConnectionDeleted);
}

pub fn pairing_started(
    previous: &VtaConnection,
    current: &VtaConnection,
) {
    let mut record = about(current);
    record.previous_state = Some(state(previous));
    record.state = Some(state(current));
    change("trust_agent_pairing_started", record, DelegationAuditAction::TrustAgentPairingStarted);
}

/// The state a verification stored, connected or not.
pub fn connection_verified(
    previous_state: &str,
    verified: &VtaConnection,
) {
    let mut record = about(verified);
    record.previous_state = Some(previous_state.to_string());
    record.state = Some(state(verified));
    change("trust_agent_connection_verified", record, DelegationAuditAction::TrustAgentConnectionVerified);
}

pub fn connection_revoked(
    previous_state: &str,
    revoked: &VtaConnection,
    acknowledgement: Acknowledged,
) {
    let mut record = acknowledged(about(revoked), acknowledgement);
    record.previous_state = Some(previous_state.to_string());
    record.state = Some(state(revoked));
    change("trust_agent_connection_revoked", record, DelegationAuditAction::TrustAgentConnectionRevoked);
}

pub fn signing_key_provisioned(
    connection: &VtaConnection,
    previous_key_id: Option<String>,
    key_id: &str,
) {
    let mut record = about(connection);
    record.previous_key_id = previous_key_id;
    record.key_id = Some(key_id.to_string());
    change("trust_agent_signing_key_provisioned", record, DelegationAuditAction::TrustAgentSigningKeyProvisioned);
}

pub fn signing_key_rotated(
    connection: &VtaConnection,
    previous_key_id: Option<String>,
    key_id: &str,
) {
    let mut record = about(connection);
    record.previous_key_id = previous_key_id;
    record.key_id = Some(key_id.to_string());
    change("trust_agent_signing_key_rotated", record, DelegationAuditAction::TrustAgentSigningKeyRotated);
}

/// The DIDs a control key rotation moved between: public identifiers, never keys.
#[derive(Debug, Clone, Default)]
pub struct ControlDids {
    pub previous: Option<String>,
    pub current: Option<String>,
}

/// A control key rotation by `actor`: of `connection`, or of the `[vta]` block when `None`.
pub fn control_key_rotated(
    actor: Actor,
    connection: Option<(&str, Option<&str>)>,
    outcome: ControlKeyRotationOutcome,
    dids: ControlDids,
) {
    let mut record = details(actor);
    if let Some((id, tenant_id)) = connection {
        record.connection_id = Some(id.to_string());
        record.tenant_id = tenant_id.map(str::to_string);
    }
    record.outcome = Some(outcome);
    record.previous_control_did = dids.previous;
    record.control_did = dids.current;
    change("trust_agent_control_key_rotated", record, DelegationAuditAction::TrustAgentControlKeyRotated);
}

/// The trust agent change a `method` request to the route registered at `matched` makes, if
/// any. `matched` may carry the prefix the router is nested at.
pub fn action_of_route(
    method: &Method,
    matched: &str,
) -> Option<TrustAgentAction> {
    use TrustAgentAction as A;
    const ROUTES: [(&str, &str, TrustAgentAction); 11] = [
        ("POST", "/v1/vta/connections", A::CreateConnection),
        ("PUT", "/v1/vta/connections/{id}", A::UpdateConnection),
        ("DELETE", "/v1/vta/connections/{id}", A::DeleteConnection),
        ("POST", "/v1/vta/connections/{id}/pair", A::PairConnection),
        ("POST", "/v1/vta/connections/{id}/verify", A::VerifyConnection),
        ("POST", "/v1/vta/connections/{id}/revoke", A::RevokeConnection),
        ("POST", "/v1/vta/connections/{id}/rotate", A::RotateSigningKey),
        ("POST", "/v1/vta/connections/{id}/keys", A::ProvisionSigningKey),
        ("POST", "/v1/vta/connections/{id}/control-key/rotate", A::RotateControlKey),
        ("POST", "/v1/vta/connections/{id}/control-key/rotate/cancel", A::CancelControlKeyRotation),
        ("POST", "/v1/vta/control-key/rotate", A::RotateControlKey),
    ];
    ROUTES
        .into_iter()
        .find(|(route_method, path, _)| method.as_str() == *route_method && matched.ends_with(path))
        .map(|(_, _, action)| action)
}

/// The connection id a request path names, bounded and kept to id characters.
fn connection_id_of(path: &str) -> Option<String> {
    let mut segments = path.split('/');
    segments.find(|segment| *segment == "connections")?;
    segments
        .next()
        .filter(|id| !id.is_empty())
        .map(untrusted_id)
}

/// The reason a refusal with `status` is recorded under. A `404` is one only for a connection
/// the caller may not see.
fn refusal_reason(
    status: StatusCode,
    hidden: bool,
) -> Option<SecurityRefusalReason> {
    match status {
        StatusCode::UNAUTHORIZED => Some(SecurityRefusalReason::Unauthenticated),
        StatusCode::FORBIDDEN => Some(SecurityRefusalReason::Forbidden),
        StatusCode::CONFLICT => Some(SecurityRefusalReason::Conflict),
        StatusCode::NOT_FOUND if hidden => Some(SecurityRefusalReason::NotVisible),
        _ => None,
    }
}

/// Records `trust_agent_change_refused` for `action` refused with `status`.
pub fn change_refused(
    action: TrustAgentAction,
    path: &str,
    status: StatusCode,
    hidden: bool,
    actor: Actor,
) {
    let Some(reason) = refusal_reason(status, hidden) else {
        return;
    };
    let mut record = details(actor);
    record.connection_id = connection_id_of(path);
    record.action = Some(action);
    record.status = Some(status.as_u16());
    record.reason = Some(reason);
    write("trust_agent_change_refused", record, None, true, DelegationAuditAction::TrustAgentChangeRefused);
}

/// Records `request`'s refusal with `status` when it attempted a trust agent change, for a
/// refusal made before the route's own layers ran, as authentication does.
pub fn record_refused(
    request: &Request,
    status: StatusCode,
    actor: Actor,
) {
    let Some(action) = request
        .extensions()
        .get::<MatchedPath>()
        .and_then(|matched| action_of_route(request.method(), matched.as_str()))
    else {
        return;
    };
    change_refused(action, request.uri().path(), status, false, actor);
}

/// Route layer of the trust agent routes: records each refused change, unless the handler
/// marked the response [`OutcomeRecorded`].
pub async fn record_refusals(
    request: Request,
    next: Next,
) -> Response {
    let action = request
        .extensions()
        .get::<MatchedPath>()
        .and_then(|matched| action_of_route(request.method(), matched.as_str()));
    let path = request
        .uri()
        .path()
        .to_string();
    let response = next.run(request).await;
    if let Some(action) = action
        && response
            .extensions()
            .get::<OutcomeRecorded>()
            .is_none()
    {
        let hidden = response
            .extensions()
            .get::<HiddenConnection>()
            .is_some();
        change_refused(action, &path, response.status(), hidden, actor());
    }
    response
}

/// Records `signing_change_refused`: a save of `owner` (by id, when it has one) that changed a
/// signing choice was refused with `403`.
pub fn signing_change_refused(
    owner: SigningOwnerKind,
    owner_id: Option<&str>,
) {
    let record = SigningChangeRefusalDetails {
        actor: actor(),
        recorded_at: chrono::Utc::now().to_rfc3339(),
        owner,
        owner_id: owner_id
            .filter(|id| !id.is_empty())
            .map(untrusted_id),
        status: StatusCode::FORBIDDEN.as_u16(),
        chain: None,
    };
    write("signing_change_refused", record, None, true, DelegationAuditAction::SigningChangeRefused);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::context::in_management_request;
    use crate::audit::hash_chain::Chained;
    use crate::audit::producer::capture;
    use crate::audit::security_chain::SecurityRecord;
    use crate::delegation_vault::audit::action_category;
    use axum::Router;
    use axum::body::Body;
    use axum::response::IntoResponse;
    use axum::routing::{post, put};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    fn connection(tenant_id: Option<&str>) -> VtaConnection {
        serde_json::from_value(json!({
            "id": "c-1",
            "tenant_id": tenant_id,
            "name": "Trust agent",
            "enabled": true,
            "endpoint": "https://vta.example",
            "vta_did": "did:web:vta.example",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }))
        .unwrap()
    }

    fn stored(record: &crate::delegation_vault::audit::DelegationAuditEvent) -> (&'static str, Value) {
        let category = action_category(&record.event);
        (category, serde_json::to_value(&record.event).unwrap()[category].clone())
    }

    /// The record as delivered verifies against its own link: its hash covers it, less the
    /// chain fields.
    fn assert_linked(
        category: &str,
        record: &Value,
    ) {
        let mut content = record.clone();
        let object = content
            .as_object_mut()
            .unwrap();
        let link: ChainLink = serde_json::from_value(json!({
            "seq": object.remove("seq").expect("seq"),
            "prev_hash": object.remove("prev_hash").expect("prev_hash"),
            "record_hash": object.remove("record_hash").expect("record_hash"),
        }))
        .unwrap();
        let chained = SecurityRecord {
            link: link.clone(),
            category: category.to_string(),
            record: content,
        };
        assert_eq!(chained.compute_hash(), link.record_hash, "{category}");
    }

    #[tokio::test]
    async fn each_change_is_recorded_with_its_actor_its_connection_and_a_chain_link() {
        let before = connection(Some("t-1"));
        let mut after = before.clone();
        after.enabled = false;
        let ((), records) = capture(in_management_request(Actor::user("u-1"), async {
            connection_created(&before);
            connection_updated(
                &before,
                &after,
                Acknowledged {
                    signing_users: true,
                    stranded_agents: false,
                },
            );
            pairing_started(&before, &after);
            connection_verified("pending", &after);
            connection_revoked("connected", &after, Acknowledged::default());
            signing_key_provisioned(&after, None, "gateway-jwt-1");
            signing_key_rotated(&after, Some("gateway-jwt-1".to_string()), "key-2");
            connection_deleted(&after, Acknowledged::default());
        }))
        .await;
        let categories: Vec<&str> = records
            .iter()
            .map(|record| action_category(&record.event))
            .collect();
        assert_eq!(
            categories,
            [
                "trust_agent_connection_created",
                "trust_agent_connection_updated",
                "trust_agent_pairing_started",
                "trust_agent_connection_verified",
                "trust_agent_connection_revoked",
                "trust_agent_signing_key_provisioned",
                "trust_agent_signing_key_rotated",
                "trust_agent_connection_deleted",
            ]
        );
        for record in &records {
            assert!(record.event.is_vp_audit());
            assert_eq!(record.tenant_id.as_deref(), Some("t-1"));
            let (category, details) = stored(record);
            assert_eq!(details["actor"], json!({ "kind": "user", "id": "u-1" }), "{category}");
            assert_eq!(details["connection_id"], "c-1", "{category}");
            assert_linked(category, &details);
        }
        let (_, updated) = stored(&records[1]);
        assert_eq!(updated["previous_enabled"], true);
        assert_eq!(updated["enabled"], false);
        assert_eq!(updated["acknowledge_signing_users"], true);
        assert_eq!(updated["acknowledge_stranded_agents"], false);
        let (_, verified) = stored(&records[3]);
        assert_eq!(verified["previous_state"], "pending");
        assert!(verified["state"].is_string());
        let (_, rotated) = stored(&records[6]);
        assert_eq!(rotated["previous_key_id"], "gateway-jwt-1");
        assert_eq!(rotated["key_id"], "key-2");
    }

    #[tokio::test]
    async fn an_update_that_does_not_disable_records_no_acknowledgement() {
        let before = connection(None);
        let ((), records) = capture(in_management_request(Actor::user("u-1"), async {
            connection_updated(&before, &before, Acknowledged::default());
        }))
        .await;
        let (_, updated) = stored(&records[0]);
        assert!(
            updated
                .get("acknowledge_signing_users")
                .is_none()
        );
        assert!(
            updated
                .get("tenant_id")
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_control_key_rotation_names_its_outcome_and_dids_only() {
        let ((), records) = capture(async {
            control_key_rotated(
                Actor::user("u-1"),
                None,
                ControlKeyRotationOutcome::Rotated,
                ControlDids {
                    previous: Some("did:key:z6Mkold".to_string()),
                    current: Some("did:key:z6Mknew".to_string()),
                },
            );
            control_key_rotated(
                Actor::user("u-1"),
                Some(("c-1", None)),
                ControlKeyRotationOutcome::RolledBack,
                ControlDids::default(),
            );
        })
        .await;
        let (_, appliance) = stored(&records[0]);
        assert!(
            appliance
                .get("connection_id")
                .is_none()
        );
        assert_eq!(appliance["outcome"], "rotated");
        assert_eq!(appliance["previous_control_did"], "did:key:z6Mkold");
        let (category, connection) = stored(&records[1]);
        assert_eq!(connection["connection_id"], "c-1");
        assert_eq!(connection["outcome"], "rolled_back");
        assert_linked(category, &connection);
    }

    #[test]
    fn each_trust_agent_write_route_names_its_action_and_reads_name_none() {
        use TrustAgentAction as A;
        for (method, route, action) in [
            (Method::POST, "/api/v1/vta/connections", Some(A::CreateConnection)),
            (Method::PUT, "/v1/vta/connections/{id}", Some(A::UpdateConnection)),
            (Method::DELETE, "/v1/vta/connections/{id}", Some(A::DeleteConnection)),
            (Method::POST, "/v1/vta/connections/{id}/pair", Some(A::PairConnection)),
            (Method::POST, "/v1/vta/connections/{id}/verify", Some(A::VerifyConnection)),
            (Method::POST, "/v1/vta/connections/{id}/revoke", Some(A::RevokeConnection)),
            (Method::POST, "/v1/vta/connections/{id}/rotate", Some(A::RotateSigningKey)),
            (Method::POST, "/v1/vta/connections/{id}/keys", Some(A::ProvisionSigningKey)),
            (Method::POST, "/v1/vta/connections/{id}/control-key/rotate", Some(A::RotateControlKey)),
            (Method::POST, "/v1/vta/connections/{id}/control-key/rotate/cancel", Some(A::CancelControlKeyRotation)),
            (Method::POST, "/v1/vta/control-key/rotate", Some(A::RotateControlKey)),
            (Method::GET, "/v1/vta/connections", None),
            (Method::GET, "/v1/vta/connections/{id}", None),
            (Method::GET, "/v1/vta/connections/{id}/status", None),
            (Method::GET, "/v1/key-management/inventory", None),
        ] {
            assert_eq!(action_of_route(&method, route), action, "{method} {route}");
        }
    }

    #[test]
    fn the_connection_id_is_read_from_the_path_bounded() {
        assert_eq!(connection_id_of("/api/v1/vta/connections/c-1/revoke").as_deref(), Some("c-1"));
        assert_eq!(connection_id_of("/v1/vta/connections"), None);
        assert_eq!(connection_id_of("/v1/vta/control-key/rotate"), None);
        assert_eq!(connection_id_of("/v1/vta/connections/a%0Ab<x>").as_deref(), Some("a_0Ab_x_"));
        assert_eq!(
            connection_id_of(&format!("/v1/vta/connections/{}", "a".repeat(300)))
                .unwrap()
                .len(),
            128
        );
    }

    #[test]
    fn only_authorization_and_conflict_refusals_are_recorded() {
        for (status, hidden, expected) in [
            (StatusCode::UNAUTHORIZED, false, Some(SecurityRefusalReason::Unauthenticated)),
            (StatusCode::FORBIDDEN, false, Some(SecurityRefusalReason::Forbidden)),
            (StatusCode::CONFLICT, false, Some(SecurityRefusalReason::Conflict)),
            (StatusCode::NOT_FOUND, true, Some(SecurityRefusalReason::NotVisible)),
            (StatusCode::NOT_FOUND, false, None),
            (StatusCode::OK, false, None),
            (StatusCode::BAD_REQUEST, false, None),
            (StatusCode::BAD_GATEWAY, false, None),
        ] {
            assert_eq!(refusal_reason(status, hidden), expected, "{status} {hidden}");
        }
    }

    async fn answer(status: StatusCode) -> Response {
        status.into_response()
    }

    async fn send(
        app: &Router,
        method: Method,
        uri: &str,
    ) -> StatusCode {
        app.clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn the_route_layer_records_refusals_and_skips_outcomes_and_reads() {
        let app = Router::new()
            .route("/v1/vta/connections/{id}/revoke", post(|| answer(StatusCode::FORBIDDEN)))
            .route(
                "/v1/vta/connections/{id}",
                put(|| async {
                    let mut response = StatusCode::NOT_FOUND.into_response();
                    response
                        .extensions_mut()
                        .insert(HiddenConnection);
                    response
                })
                .delete(|| answer(StatusCode::NOT_FOUND))
                .get(|| answer(StatusCode::FORBIDDEN)),
            )
            .route(
                "/v1/vta/connections/{id}/verify",
                post(|| async {
                    let mut response = StatusCode::CONFLICT.into_response();
                    response
                        .extensions_mut()
                        .insert(OutcomeRecorded);
                    response
                }),
            )
            .route("/v1/vta/control-key/rotate", post(|| answer(StatusCode::OK)))
            .route_layer(axum::middleware::from_fn(record_refusals));

        let ((), records) = capture(in_management_request(Actor::pat("tok-1", "u-1"), async {
            assert_eq!(send(&app, Method::POST, "/v1/vta/connections/c-1/revoke").await, StatusCode::FORBIDDEN);
            assert_eq!(send(&app, Method::PUT, "/v1/vta/connections/c-2").await, StatusCode::NOT_FOUND);
            assert_eq!(send(&app, Method::DELETE, "/v1/vta/connections/c-3").await, StatusCode::NOT_FOUND);
            assert_eq!(send(&app, Method::GET, "/v1/vta/connections/c-4").await, StatusCode::FORBIDDEN);
            assert_eq!(send(&app, Method::POST, "/v1/vta/connections/c-5/verify").await, StatusCode::CONFLICT);
            assert_eq!(send(&app, Method::POST, "/v1/vta/control-key/rotate").await, StatusCode::OK);
        }))
        .await;

        assert_eq!(records.len(), 2, "{records:?}");
        let (category, revoke) = stored(&records[0]);
        assert_eq!(category, "trust_agent_change_refused");
        assert_eq!(revoke["action"], "revoke_connection");
        assert_eq!(revoke["connection_id"], "c-1");
        assert_eq!(revoke["status"], 403);
        assert_eq!(revoke["reason"], "forbidden");
        assert_eq!(revoke["actor"], json!({ "kind": "pat", "id": "tok-1", "user_id": "u-1" }));
        assert_linked(category, &revoke);
        let (_, hidden) = stored(&records[1]);
        assert_eq!(hidden["action"], "update_connection");
        assert_eq!(hidden["connection_id"], "c-2");
        assert_eq!(hidden["status"], 404);
        assert_eq!(hidden["reason"], "not_visible");
    }

    #[tokio::test]
    async fn a_refused_signing_change_names_its_owner() {
        let ((), records) = capture(in_management_request(Actor::user("u-2"), async {
            signing_change_refused(SigningOwnerKind::Issuer, Some("issuer-1"));
            signing_change_refused(SigningOwnerKind::GatewayDefault, None);
            signing_change_refused(SigningOwnerKind::Surface, Some(""));
        }))
        .await;
        assert_eq!(records.len(), 3);
        let (category, issuer) = stored(&records[0]);
        assert_eq!(category, "signing_change_refused");
        assert_eq!(issuer["owner"], "issuer");
        assert_eq!(issuer["owner_id"], "issuer-1");
        assert_eq!(issuer["status"], 403);
        assert_eq!(issuer["actor"], json!({ "kind": "user", "id": "u-2" }));
        assert_linked(category, &issuer);
        let (_, default) = stored(&records[1]);
        assert_eq!(default["owner"], "gateway_default");
        assert!(
            default
                .get("owner_id")
                .is_none()
        );
        let (_, new_surface) = stored(&records[2]);
        assert!(
            new_surface
                .get("owner_id")
                .is_none()
        );
    }
}
