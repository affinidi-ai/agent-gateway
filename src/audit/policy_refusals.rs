//! Records refused attempts to change a policy or where one applies. The
//! attempt is read from the route and the request path only, never from the
//! body or from the error it got.

use axum::Router;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::MethodRouter;

use crate::audit::context::current_actor;
use crate::audit::events::{
    Actor, PolicyChangeAction, PolicyChangeSource, PolicyField, PolicyTargetKind, RefusalReason,
};
use crate::audit::policy_changes;
use crate::delegation_vault::audit::{DelegationAuditAction, PolicyChangeDetails, PolicyTarget};

/// A route that changes a policy or where one applies. Each is registered
/// with [`PolicyWriteRoutes::policy_write`], so its path is named once, here,
/// and every refusal of it is recorded: by its own layers or handler, and by
/// authentication before it ([`record_refused`]).
///
/// `PUT /v1/gateways/{id}` is not one: it edits a gateway's name, description
/// and status, never its policy. `DELETE /v1/gateways/{id}` is not one either,
/// though deleting a gateway drops its policies: a refused delete cannot be
/// called a policy change without reading the stored gateway, so its refusals
/// are not recorded. A successful delete records each policy it detaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyWrite {
    CreateDefinition,
    UpdateDefinition,
    DeleteDefinition,
    /// Reassigning a resource's tenant: a policy change for a definition only.
    ReassignOwner,
    /// Replacing the appliance-wide assignments.
    Assignments,
    /// Replacing a gateway's policy.
    GatewayPolicy,
}

impl PolicyWrite {
    pub const ALL: [Self; 6] = [
        Self::CreateDefinition,
        Self::UpdateDefinition,
        Self::DeleteDefinition,
        Self::ReassignOwner,
        Self::Assignments,
        Self::GatewayPolicy,
    ];

    pub fn method(self) -> Method {
        match self {
            Self::CreateDefinition => Method::POST,
            Self::DeleteDefinition => Method::DELETE,
            Self::UpdateDefinition | Self::ReassignOwner | Self::Assignments | Self::GatewayPolicy => Method::PUT,
        }
    }

    /// The route's path, as registered.
    pub fn path(self) -> &'static str {
        match self {
            Self::CreateDefinition => "/v1/policy-definitions",
            Self::UpdateDefinition | Self::DeleteDefinition => "/v1/policy-definitions/{policy_id}",
            Self::ReassignOwner => "/v1/tenant-ownership/{kind}/{id}",
            Self::Assignments => "/v1/policy-assignments",
            Self::GatewayPolicy => "/v1/gateways/{id}/policy",
        }
    }

    /// The write a `method` request to the route registered at `matched`
    /// makes, if any. `matched` may carry the prefix the router is nested at.
    fn of_route(
        method: &Method,
        matched: &str,
    ) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|write| write.method() == method && matched.ends_with(write.path()))
    }

    /// The value of the route parameter `name` in `path`, a request path of
    /// this route.
    fn param<'a>(
        self,
        path: &'a str,
        name: &str,
    ) -> Option<&'a str> {
        self.path()
            .rsplit('/')
            .zip(
                path.trim_end_matches('/')
                    .rsplit('/'),
            )
            .find(|(part, _)| {
                part.strip_prefix('{')
                    .and_then(|part| part.strip_suffix('}'))
                    == Some(name)
            })
            .map(|(_, value)| value)
    }

    /// The change a request to `path` attempts, or `None` when it changes no
    /// policy. Writes that replace a whole set of attachments (appliance-wide
    /// assignments, a gateway's policy) attempt `policy_attached`.
    fn attempt(
        self,
        path: &str,
    ) -> Option<Attempt> {
        let id = |name| {
            self.param(path, name)
                .map(untrusted_id)
        };
        let on_definition = |action, name, changed| Attempt {
            action,
            policy_definition_id: id(name),
            target: None,
            changed,
        };
        let attached_at = |kind, id: Option<String>| Attempt {
            action: PolicyChangeAction::PolicyAttached,
            policy_definition_id: None,
            target: Some(PolicyTarget { kind, id, name: None }),
            changed: Vec::new(),
        };
        match self {
            Self::CreateDefinition => Some(Attempt {
                action: PolicyChangeAction::PolicyCreated,
                policy_definition_id: None,
                target: None,
                changed: Vec::new(),
            }),
            Self::UpdateDefinition => Some(on_definition(PolicyChangeAction::PolicyUpdated, "policy_id", Vec::new())),
            Self::DeleteDefinition => Some(on_definition(PolicyChangeAction::PolicyDeleted, "policy_id", Vec::new())),
            Self::ReassignOwner => (self.param(path, "kind") == Some("policy-definitions"))
                .then(|| on_definition(PolicyChangeAction::PolicyUpdated, "id", vec![PolicyField::Owner])),
            Self::Assignments => Some(attached_at(PolicyTargetKind::Appliance, None)),
            Self::GatewayPolicy => Some(attached_at(PolicyTargetKind::Gateway, id("id"))),
        }
    }

    /// Records `policy_change_refused` when `status` refuses the change a
    /// request to `path` attempted.
    fn record(
        self,
        path: &str,
        status: StatusCode,
        actor: Actor,
    ) {
        let (Some(attempt), Some(reason)) = (self.attempt(path), reason(status)) else {
            return;
        };
        let mut change = PolicyChangeDetails::new(actor, PolicyChangeSource::Api);
        change.policy_definition_id = attempt.policy_definition_id;
        change.target = attempt.target;
        change.changed = attempt.changed;
        change.action = Some(attempt.action);
        change.status = Some(status.as_u16());
        change.reason = Some(reason);
        policy_changes::write(DelegationAuditAction::PolicyChangeRefused(Box::new(change)));
    }
}

/// Registers policy write routes on a router.
pub trait PolicyWriteRoutes<S> {
    /// Registers `endpoint` at `write`'s path, recording each refusal of it,
    /// including one by a layer `endpoint` already carries.
    fn policy_write(
        self,
        write: PolicyWrite,
        endpoint: MethodRouter<S>,
    ) -> Self;
}

impl<S: Clone + Send + Sync + 'static> PolicyWriteRoutes<S> for Router<S> {
    fn policy_write(
        self,
        write: PolicyWrite,
        endpoint: MethodRouter<S>,
    ) -> Self {
        self.route(write.path(), endpoint.layer(axum::middleware::from_fn_with_state(write, record_refusals)))
    }
}

/// What a request to a policy write route attempted.
#[derive(Debug, Clone, PartialEq)]
pub struct Attempt {
    pub action: PolicyChangeAction,
    pub policy_definition_id: Option<String>,
    pub target: Option<PolicyTarget>,
    pub changed: Vec<PolicyField>,
}

/// The reason a refusal with `status` is recorded under, or `None` for a
/// status that is not a refusal of the change.
pub fn reason(status: StatusCode) -> Option<RefusalReason> {
    match status {
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => Some(RefusalReason::Invalid),
        StatusCode::FORBIDDEN => Some(RefusalReason::Forbidden),
        StatusCode::NOT_FOUND => Some(RefusalReason::NotFound),
        StatusCode::CONFLICT => Some(RefusalReason::Conflict),
        _ => None,
    }
}

/// Records `policy_change_refused` when `status` refuses `request` to a
/// policy write route before the route's own layers ran, as authentication
/// does. Routing has matched the request by then, so the route is known.
pub fn record_refused(
    request: &Request,
    status: StatusCode,
    actor: Actor,
) {
    let Some(write) = request
        .extensions()
        .get::<MatchedPath>()
        .and_then(|matched| PolicyWrite::of_route(request.method(), matched.as_str()))
    else {
        return;
    };
    write.record(request.uri().path(), status, actor);
}

/// Route layer of a policy write: records each refused attempt, including a
/// refusal by a layer it wraps.
async fn record_refusals(
    State(write): State<PolicyWrite>,
    request: Request,
    next: Next,
) -> Response {
    let path = request
        .uri()
        .path()
        .to_string();
    let response = next.run(request).await;
    write.record(&path, response.status(), current_actor().unwrap_or_else(Actor::system));
    response
}

/// An id read from a request path, kept to the characters ids use and to a
/// bounded length, as the path is untrusted.
fn untrusted_id(id: &str) -> String {
    id.chars()
        .take(MAX_ID_CHARS)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

const MAX_ID_CHARS: usize = 128;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::context::in_management_request;
    use crate::audit::producer::capture;
    use axum::body::Body;
    use axum::routing::{MethodFilter, on};
    use tower::ServiceExt;

    fn target(
        kind: PolicyTargetKind,
        id: Option<&str>,
    ) -> Option<PolicyTarget> {
        Some(PolicyTarget {
            kind,
            id: id.map(str::to_string),
            name: None,
        })
    }

    fn definition(
        action: PolicyChangeAction,
        id: Option<&str>,
        changed: Vec<PolicyField>,
    ) -> Attempt {
        Attempt {
            action,
            policy_definition_id: id.map(str::to_string),
            target: None,
            changed,
        }
    }

    /// Each write, a request path of its route, and the change it attempts.
    fn writes() -> Vec<(PolicyWrite, &'static str, Attempt)> {
        let attached = |kind, id| Attempt {
            action: PolicyChangeAction::PolicyAttached,
            policy_definition_id: None,
            target: target(kind, id),
            changed: vec![],
        };
        vec![
            (
                PolicyWrite::CreateDefinition,
                "/v1/policy-definitions",
                definition(PolicyChangeAction::PolicyCreated, None, vec![]),
            ),
            (
                PolicyWrite::UpdateDefinition,
                "/v1/policy-definitions/deny-pii",
                definition(PolicyChangeAction::PolicyUpdated, Some("deny-pii"), vec![]),
            ),
            (
                PolicyWrite::DeleteDefinition,
                "/v1/policy-definitions/deny-pii",
                definition(PolicyChangeAction::PolicyDeleted, Some("deny-pii"), vec![]),
            ),
            (
                PolicyWrite::ReassignOwner,
                "/v1/tenant-ownership/policy-definitions/deny-pii",
                definition(PolicyChangeAction::PolicyUpdated, Some("deny-pii"), vec![PolicyField::Owner]),
            ),
            (PolicyWrite::Assignments, "/v1/policy-assignments", attached(PolicyTargetKind::Appliance, None)),
            (PolicyWrite::GatewayPolicy, "/v1/gateways/gw-1/policy", attached(PolicyTargetKind::Gateway, Some("gw-1"))),
        ]
    }

    #[test]
    fn every_write_is_listed_once() {
        let listed: Vec<PolicyWrite> = writes()
            .into_iter()
            .map(|(write, _, _)| write)
            .collect();
        assert_eq!(listed, PolicyWrite::ALL);
    }

    #[test]
    fn each_policy_write_route_names_the_change_it_attempts() {
        for (write, path, attempt) in writes() {
            assert_eq!(write.attempt(path), Some(attempt), "{write:?}");
        }
    }

    #[test]
    fn reassigning_anything_but_a_definition_attempts_no_policy_change() {
        assert_eq!(PolicyWrite::ReassignOwner.attempt("/v1/tenant-ownership/surfaces/s-1"), None);
    }

    #[test]
    fn a_write_is_found_from_its_route_under_any_prefix_and_only_for_its_method() {
        assert_eq!(
            PolicyWrite::of_route(&Method::PUT, "/api/v1/policy-definitions/{policy_id}"),
            Some(PolicyWrite::UpdateDefinition)
        );
        assert_eq!(
            PolicyWrite::of_route(&Method::DELETE, "/v1/policy-definitions/{policy_id}"),
            Some(PolicyWrite::DeleteDefinition)
        );
        for (method, route) in [
            (Method::GET, "/v1/policy-definitions/{policy_id}"),
            (Method::POST, "/v1/policy-definitions/{policy_id}/simulate"),
            (Method::PUT, "/v1/gateways/{id}"),
        ] {
            assert_eq!(PolicyWrite::of_route(&method, route), None, "{method} {route}");
        }
    }

    #[test]
    fn an_id_from_the_path_is_bounded_and_keeps_only_id_characters() {
        let long = "a".repeat(300);
        let attempt = PolicyWrite::DeleteDefinition
            .attempt(&format!("/v1/policy-definitions/{long}"))
            .unwrap();
        assert_eq!(
            attempt
                .policy_definition_id
                .unwrap()
                .len(),
            128
        );

        let attempt = PolicyWrite::DeleteDefinition
            .attempt("/v1/policy-definitions/deny%0Apii<script>")
            .unwrap();
        assert_eq!(
            attempt
                .policy_definition_id
                .as_deref(),
            Some("deny_0Apii_script_")
        );
    }

    #[test]
    fn only_client_refusals_are_recorded_and_each_has_its_reason() {
        for (status, expected) in [
            (StatusCode::BAD_REQUEST, Some(RefusalReason::Invalid)),
            (StatusCode::UNPROCESSABLE_ENTITY, Some(RefusalReason::Invalid)),
            (StatusCode::FORBIDDEN, Some(RefusalReason::Forbidden)),
            (StatusCode::NOT_FOUND, Some(RefusalReason::NotFound)),
            (StatusCode::CONFLICT, Some(RefusalReason::Conflict)),
            (StatusCode::OK, None),
            (StatusCode::CREATED, None),
            (StatusCode::UNAUTHORIZED, None),
            (StatusCode::INTERNAL_SERVER_ERROR, None),
        ] {
            assert_eq!(reason(status), expected, "{status}");
        }
    }

    async fn accept() -> StatusCode {
        StatusCode::OK
    }

    /// Stands in for `require_feature` refusing the caller's role.
    async fn forbid(
        _request: Request,
        _next: Next,
    ) -> Response {
        axum::response::IntoResponse::into_response(StatusCode::FORBIDDEN)
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
    async fn a_role_refusal_of_each_write_route_is_recorded_with_its_actor() {
        for (write, path, attempt) in writes() {
            let endpoint =
                on(MethodFilter::try_from(write.method()).unwrap(), accept).layer(axum::middleware::from_fn(forbid));
            let app = Router::new().nest("/api", Router::new().policy_write(write, endpoint));

            let (status, records) = capture(in_management_request(Actor::user("u-1"), async {
                send(&app, write.method(), &format!("/api{path}")).await
            }))
            .await;

            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(records.len(), 1, "{write:?}");
            assert!(
                records[0]
                    .request_id
                    .is_some()
            );
            let DelegationAuditAction::PolicyChangeRefused(change) = &records[0].event else {
                panic!("{write:?}: {:?}", records[0].event);
            };
            assert_eq!(change.action, Some(attempt.action), "{write:?}");
            assert_eq!(change.policy_definition_id, attempt.policy_definition_id, "{write:?}");
            assert_eq!(change.target, attempt.target, "{write:?}");
            assert_eq!(change.actor, Actor::user("u-1"));
            assert_eq!(change.status, Some(403));
            assert_eq!(change.reason, Some(RefusalReason::Forbidden));
        }
    }

    #[tokio::test]
    async fn the_route_layer_records_a_refused_change_and_nothing_else() {
        let app = Router::new()
            .policy_write(
                PolicyWrite::UpdateDefinition,
                axum::routing::put(accept).layer(axum::middleware::from_fn(forbid)),
            )
            .policy_write(PolicyWrite::DeleteDefinition, axum::routing::delete(accept));

        let ((), records) = capture(in_management_request(Actor::user("u-1"), async {
            assert_eq!(send(&app, Method::PUT, "/v1/policy-definitions/deny-pii").await, StatusCode::FORBIDDEN);
            assert_eq!(send(&app, Method::DELETE, "/v1/policy-definitions/deny-pii").await, StatusCode::OK);
        }))
        .await;

        assert_eq!(records.len(), 1);
        let json = serde_json::to_value(&records[0].event).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"policy_change_refused": {
                "policy_definition_id": "deny-pii",
                "actor": { "kind": "user", "id": "u-1" },
                "source": "api",
                "action": "policy_updated",
                "status": 403,
                "reason": "forbidden",
            }})
        );
    }
}
