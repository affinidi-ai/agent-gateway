//! Records refused attempts to change a policy or where one applies. The
//! attempt is read from the request's method and path only, never from its
//! body or from the error it got.

use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

use crate::audit::context::current_actor;
use crate::audit::events::{
    Actor, PolicyChangeAction, PolicyChangeSource, PolicyField, PolicyTargetKind, RefusalReason,
};
use crate::audit::policy_changes;
use crate::delegation_vault::audit::{DelegationAuditAction, PolicyChangeDetails, PolicyTarget};

/// What a request to a policy write route attempted.
#[derive(Debug, Clone, PartialEq)]
pub struct Attempt {
    pub action: PolicyChangeAction,
    pub policy_definition_id: Option<String>,
    pub target: Option<PolicyTarget>,
    pub changed: Vec<PolicyField>,
}

/// The policy change a `method` request to `path` attempts, or `None` when
/// the route changes no policy. Routes that replace a whole set of
/// attachments (appliance-wide assignments, a gateway's policy) attempt
/// `policy_attached`.
pub fn attempted(
    method: &Method,
    path: &str,
) -> Option<Attempt> {
    let api = &path[path.find("/v1/")?..];
    let segments: Vec<&str> = api
        .trim_end_matches('/')
        .split('/')
        .skip(2)
        .collect();
    let on_definition = |action, id: &str, changed| Attempt {
        action,
        policy_definition_id: Some(untrusted_id(id)),
        target: None,
        changed,
    };
    let attached_at = |kind, id: Option<&str>| Attempt {
        action: PolicyChangeAction::PolicyAttached,
        policy_definition_id: None,
        target: Some(PolicyTarget {
            kind,
            id: id.map(untrusted_id),
            name: None,
        }),
        changed: Vec::new(),
    };
    match (method, segments.as_slice()) {
        (&Method::POST, ["policy-definitions"]) => Some(Attempt {
            action: PolicyChangeAction::PolicyCreated,
            policy_definition_id: None,
            target: None,
            changed: Vec::new(),
        }),
        (&Method::PUT, ["policy-definitions", id]) => {
            Some(on_definition(PolicyChangeAction::PolicyUpdated, id, Vec::new()))
        }
        (&Method::DELETE, ["policy-definitions", id]) => {
            Some(on_definition(PolicyChangeAction::PolicyDeleted, id, Vec::new()))
        }
        (&Method::PUT, ["tenant-ownership", "policy-definitions", id]) => {
            Some(on_definition(PolicyChangeAction::PolicyUpdated, id, vec![PolicyField::Owner]))
        }
        (&Method::PUT, ["policy-assignments"]) => Some(attached_at(PolicyTargetKind::Appliance, None)),
        (&Method::PUT, ["gateways", id, "policy"]) => Some(attached_at(PolicyTargetKind::Gateway, Some(id))),
        _ => None,
    }
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

/// Records `policy_change_refused` when `status` refuses a policy change the
/// `method` request to `path` attempted.
pub fn record_refused(
    method: &Method,
    path: &str,
    status: StatusCode,
    actor: Actor,
) {
    let (Some(attempt), Some(reason)) = (attempted(method, path), reason(status)) else {
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

/// Route layer for the policy write routes: records each refused attempt,
/// including a refusal by a layer it wraps.
pub async fn record_refused_policy_changes(
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request
        .uri()
        .path()
        .to_string();
    let response = next.run(request).await;
    record_refused(&method, &path, response.status(), current_actor().unwrap_or_else(Actor::system));
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
    use axum::Router;
    use axum::body::Body;
    use axum::routing::put;
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

    #[test]
    fn each_policy_write_route_names_the_change_it_attempts() {
        let attempt = |method: Method, path: &str| attempted(&method, path);
        let definition = |action, id: Option<&str>, changed: Vec<PolicyField>| {
            Some(Attempt {
                action,
                policy_definition_id: id.map(str::to_string),
                target: None,
                changed,
            })
        };

        assert_eq!(
            attempt(Method::POST, "/v1/policy-definitions"),
            definition(PolicyChangeAction::PolicyCreated, None, vec![])
        );
        assert_eq!(
            attempt(Method::PUT, "/v1/policy-definitions/deny-pii"),
            definition(PolicyChangeAction::PolicyUpdated, Some("deny-pii"), vec![])
        );
        assert_eq!(
            attempt(Method::DELETE, "/admin/v1/policy-definitions/deny-pii"),
            definition(PolicyChangeAction::PolicyDeleted, Some("deny-pii"), vec![])
        );
        assert_eq!(
            attempt(Method::PUT, "/v1/tenant-ownership/policy-definitions/deny-pii"),
            definition(PolicyChangeAction::PolicyUpdated, Some("deny-pii"), vec![PolicyField::Owner])
        );
        assert_eq!(
            attempt(Method::PUT, "/v1/policy-assignments"),
            Some(Attempt {
                action: PolicyChangeAction::PolicyAttached,
                policy_definition_id: None,
                target: target(PolicyTargetKind::Appliance, None),
                changed: vec![],
            })
        );
        assert_eq!(
            attempt(Method::PUT, "/v1/gateways/gw-1/policy"),
            Some(Attempt {
                action: PolicyChangeAction::PolicyAttached,
                policy_definition_id: None,
                target: target(PolicyTargetKind::Gateway, Some("gw-1")),
                changed: vec![],
            })
        );
    }

    #[test]
    fn reads_simulations_and_other_routes_attempt_no_change() {
        for (method, path) in [
            (Method::GET, "/v1/policy-definitions/deny-pii"),
            (Method::POST, "/v1/policy-definitions/deny-pii/simulate"),
            (Method::PUT, "/v1/tenant-ownership/surfaces/s-1"),
            (Method::PUT, "/v1/gateways/gw-1"),
            (Method::PUT, "/v1/policy-definitions"),
        ] {
            assert_eq!(attempted(&method, path), None, "{method} {path}");
        }
    }

    #[test]
    fn an_id_from_the_path_is_bounded_and_keeps_only_id_characters() {
        let long = "a".repeat(300);
        let attempt = attempted(&Method::DELETE, &format!("/v1/policy-definitions/{long}")).unwrap();
        assert_eq!(
            attempt
                .policy_definition_id
                .unwrap()
                .len(),
            128
        );

        let attempt = attempted(&Method::DELETE, "/v1/policy-definitions/deny%0Apii<script>").unwrap();
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

    async fn refuse() -> StatusCode {
        StatusCode::FORBIDDEN
    }

    async fn accept() -> StatusCode {
        StatusCode::OK
    }

    #[tokio::test]
    async fn the_route_layer_records_a_refused_change_with_its_actor_and_nothing_else() {
        let app = Router::new()
            .route("/v1/policy-definitions/{policy_id}", put(refuse).delete(accept))
            .layer(axum::middleware::from_fn(record_refused_policy_changes));
        let send = |method: Method| {
            app.clone().oneshot(
                axum::http::Request::builder()
                    .method(method)
                    .uri("/v1/policy-definitions/deny-pii")
                    .body(Body::empty())
                    .unwrap(),
            )
        };

        let ((), records) = capture(in_management_request(Actor::user("u-1"), async {
            assert_eq!(
                send(Method::PUT)
                    .await
                    .unwrap()
                    .status(),
                StatusCode::FORBIDDEN
            );
            assert_eq!(
                send(Method::DELETE)
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
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
