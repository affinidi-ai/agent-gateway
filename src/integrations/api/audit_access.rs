//! Changes that decide where Governance Audit records go need `audit.view` as well as the
//! route's `integrations.*` permission: an event set holding audit events, an integration whose
//! event set holds them, and an endpoint such an integration delivers to.

use std::convert::Infallible;

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;

use super::{ApiError, DefinitionStores, integrations_using, internal_error};
use crate::auth_manager::middleware::{AuthGuardOk, RbacGuard};
use crate::auth_manager::pat::PatContext;
use crate::rbac::Feature;

const REFUSED: &str = "Audit events need the audit.view permission";

/// The caller of a request, to check `audit.view` when a change touches audit events.
pub struct AuditAccess {
    guard: Option<RbacGuard>,
    user_id: Option<String>,
    pat: Option<PatContext>,
}

impl<S: Send + Sync> FromRequestParts<S> for AuditAccess {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self {
            guard: parts
                .extensions
                .get::<RbacGuard>()
                .cloned(),
            user_id: parts
                .extensions
                .get::<AuthGuardOk>()
                .map(|AuthGuardOk(user_id)| user_id.clone()),
            pat: parts
                .extensions
                .get::<PatContext>()
                .cloned(),
        })
    }
}

impl AuditAccess {
    /// Refuses with 403 unless the caller holds `audit.view`; without a guard or a caller
    /// there is no one to authorise, so it refuses too.
    pub async fn require(&self) -> Result<(), ApiError> {
        let (Some(guard), Some(user_id)) = (&self.guard, &self.user_id) else {
            return Err(refused());
        };
        match guard
            .allows(user_id, self.pat.as_ref(), Feature::AuditView)
            .await
        {
            Ok(true) => Ok(()),
            Ok(false) => Err(refused()),
            Err(error) => Err(internal_error("check permissions", error)),
        }
    }

    /// [`AuditAccess::require`] when `touches_audit` holds.
    pub async fn require_if(
        &self,
        touches_audit: bool,
    ) -> Result<(), ApiError> {
        if touches_audit {
            self.require().await
        } else {
            Ok(())
        }
    }

    /// [`AuditAccess::require`] when an integration delivering audit events uses the endpoint
    /// `endpoint_id`, so changing it changes where audit records go.
    pub async fn require_for_endpoint(
        &self,
        stores: &DefinitionStores,
        endpoint_id: &str,
    ) -> Result<(), ApiError> {
        let users = integrations_using(stores, |integration| integration.endpoint_id == endpoint_id).await?;
        for integration in users {
            if event_set_holds_audit(stores, &integration.event_set_id).await? {
                return self.require().await;
            }
        }
        Ok(())
    }
}

/// Whether `events` names any audit event.
pub fn holds_audit_events(events: &[String]) -> bool {
    events
        .iter()
        .any(|event| event.starts_with("audit."))
}

/// Whether the stored event set `event_set_id` holds audit events; false when it does not exist.
pub async fn event_set_holds_audit(
    stores: &DefinitionStores,
    event_set_id: &str,
) -> Result<bool, ApiError> {
    if uuid::Uuid::parse_str(event_set_id).is_err() {
        return Ok(false);
    }
    Ok(stores
        .event_sets
        .find(event_set_id)
        .await
        .map_err(|error| internal_error("load the event set", error))?
        .is_some_and(|event_set| holds_audit_events(&event_set.events)))
}

fn refused() -> ApiError {
    (StatusCode::FORBIDDEN, REFUSED.to_string())
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use serde_json::{Value as JsonValue, json};

    use super::super::test_support::*;
    use super::REFUSED;
    use crate::integrations::definitions::{Endpoint, EndpointType, EventSet, Integration};

    struct Seeded {
        endpoint: Endpoint,
        gateways: EventSet,
        audit: EventSet,
        on_audit: Integration,
    }

    /// A webhook endpoint at a public IP literal (no DNS), a gateway event set, an audit event
    /// set, and an integration delivering the audit set to the endpoint.
    async fn seeded(f: &Fixture) -> Seeded {
        let endpoint = Endpoint::new(
            "SIEM".to_string(),
            String::new(),
            EndpointType::Webhook,
            json!({"url": "https://93.184.215.14/hook"}),
        );
        let gateways =
            EventSet::new("Gateways".to_string(), String::new(), vec!["gateway.created".to_string()]).expect("set");
        let audit = EventSet::new(
            "Governance".to_string(),
            String::new(),
            vec!["gateway.created".to_string(), "audit.policy_decision".to_string()],
        )
        .expect("set");
        let on_audit =
            Integration::new("SIEM".to_string(), String::new(), endpoint.id.clone(), audit.id.clone(), json!({}));
        f.stores
            .endpoints
            .save(&endpoint)
            .await
            .expect("endpoint");
        for set in [&gateways, &audit] {
            f.stores
                .event_sets
                .save(set)
                .await
                .expect("event set");
        }
        f.stores
            .integrations
            .save(&on_audit)
            .await
            .expect("integration");
        Seeded {
            endpoint,
            gateways,
            audit,
            on_audit,
        }
    }

    fn event_set(events: &[&str]) -> JsonValue {
        json!({"name": "Set", "events": events})
    }

    fn integration(
        endpoint: &Endpoint,
        event_set: &EventSet,
    ) -> JsonValue {
        json!({"name": "Forward", "endpoint_id": endpoint.id, "event_set_id": event_set.id, "content": {}})
    }

    fn webhook() -> JsonValue {
        json!({"name": "SIEM", "configuration": {"url": "https://93.184.215.14/other"}, "status": "active"})
    }

    fn refused(response: (StatusCode, JsonValue)) -> bool {
        response == (StatusCode::FORBIDDEN, json!(REFUSED))
    }

    #[tokio::test]
    async fn without_audit_events_integrations_edit_is_enough() {
        let f = Fixture::new().await;
        let s = seeded(&f).await;
        let unused = Endpoint::new(
            "Ops".to_string(),
            String::new(),
            EndpointType::Webhook,
            json!({"url": "https://93.184.215.14/ops"}),
        );
        f.stores
            .endpoints
            .save(&unused)
            .await
            .expect("endpoint");

        let (set, _) = f
            .call(EDITOR, "POST", "/v1/integrations/event-sets", Some(event_set(&["gateway.created"])))
            .await;
        let (created, _) = f
            .call(EDITOR, "POST", "/v1/integrations", Some(integration(&s.endpoint, &s.gateways)))
            .await;
        let (endpoint, _) = f
            .call(EDITOR, "PUT", &format!("/v1/integrations/endpoints/{}", unused.id), Some(webhook()))
            .await;

        assert_eq!((set, created, endpoint), (StatusCode::CREATED, StatusCode::CREATED, StatusCode::OK));
    }

    #[tokio::test]
    async fn an_event_set_with_audit_events_needs_audit_view() {
        let f = Fixture::new().await;
        let s = seeded(&f).await;
        let audit = event_set(&["gateway.created", "audit.policy_decision"]);
        let gateways = event_set(&["gateway.created"]);

        assert!(refused(
            f.call(EDITOR, "POST", "/v1/integrations/event-sets", Some(audit.clone()))
                .await
        ));
        let gateway_set = format!("/v1/integrations/event-sets/{}", s.gateways.id);
        assert!(refused(
            f.call(EDITOR, "PUT", &gateway_set, Some(audit.clone()))
                .await
        ));
        let audit_set = format!("/v1/integrations/event-sets/{}", s.audit.id);
        assert!(refused(
            f.call(EDITOR, "PUT", &audit_set, Some(gateways))
                .await
        ));

        let (created, _) = f
            .call(ADMIN, "POST", "/v1/integrations/event-sets", Some(audit.clone()))
            .await;
        let (updated, _) = f
            .call(ADMIN, "PUT", &audit_set, Some(audit))
            .await;
        assert_eq!((created, updated), (StatusCode::CREATED, StatusCode::OK));
    }

    #[tokio::test]
    async fn deleting_an_event_set_with_audit_events_needs_audit_view() {
        let f = Fixture::new().await;
        let unused =
            EventSet::new("Unused".to_string(), String::new(), vec!["audit.policy_decision".to_string()]).expect("set");
        f.stores
            .event_sets
            .save(&unused)
            .await
            .expect("event set");
        let path = format!("/v1/integrations/event-sets/{}", unused.id);

        assert!(refused(
            f.call(EDITOR, "DELETE", &path, None)
                .await
        ));
        assert_eq!(
            f.call(ADMIN, "DELETE", &path, None)
                .await
                .0,
            StatusCode::NO_CONTENT
        );
    }

    #[tokio::test]
    async fn an_integration_receiving_audit_events_needs_audit_view() {
        let f = Fixture::new().await;
        let s = seeded(&f).await;
        let on_gateways = Integration::new(
            "Alerts".to_string(),
            String::new(),
            s.endpoint.id.clone(),
            s.gateways.id.clone(),
            json!({}),
        );
        f.stores
            .integrations
            .save(&on_gateways)
            .await
            .expect("integration");
        let audit_path = format!("/v1/integrations/{}", s.on_audit.id);

        assert!(refused(
            f.call(EDITOR, "POST", "/v1/integrations", Some(integration(&s.endpoint, &s.audit)))
                .await
        ));
        assert!(refused(
            f.call(EDITOR, "PUT", &audit_path, Some(integration(&s.endpoint, &s.gateways)))
                .await
        ));
        assert!(refused(
            f.call(
                EDITOR,
                "PUT",
                &format!("/v1/integrations/{}", on_gateways.id),
                Some(integration(&s.endpoint, &s.audit))
            )
            .await
        ));
        assert!(refused(
            f.call(EDITOR, "DELETE", &audit_path, None)
                .await
        ));

        let (created, _) = f
            .call(ADMIN, "POST", "/v1/integrations", Some(integration(&s.endpoint, &s.audit)))
            .await;
        let (deleted, _) = f
            .call(ADMIN, "DELETE", &audit_path, None)
            .await;
        assert_eq!((created, deleted), (StatusCode::CREATED, StatusCode::NO_CONTENT));
    }

    #[tokio::test]
    async fn an_endpoint_receiving_audit_records_needs_audit_view() {
        let f = Fixture::new().await;
        let s = seeded(&f).await;
        let path = format!("/v1/integrations/endpoints/{}", s.endpoint.id);

        assert!(refused(
            f.call(EDITOR, "PUT", &path, Some(webhook()))
                .await
        ));
        assert!(refused(
            f.call(EDITOR, "DELETE", &path, None)
                .await
        ));
        assert_eq!(
            f.call(ADMIN, "PUT", &path, Some(webhook()))
                .await
                .0,
            StatusCode::OK
        );
    }
}
