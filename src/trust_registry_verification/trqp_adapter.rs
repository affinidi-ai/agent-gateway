//! Production [`TrqpClient`] adapter over
//! [`crate::trust_registries::communication::TrustRegistryListenerManager`].
//!
//! Resolves a configured `trust_registry_id` to its established
//! DIDComm connection, builds a [`TrqpQueryRequest`] for the requested
//! query family, dispatches via the listener manager, and normalises the
//! response into a [`TrqpOutcome`]. Maps the listener's
//! [`TrustRegistryError`] taxonomy onto [`TrqpClientError`]:
//!
//! - `NotFound` / `NoConnection` / `StaleConnection` / `ConnectionError`
//!   → [`TrqpClientError::Unreachable`] (no live transport to the registry).
//! - `SendError` → [`TrqpClientError::QueryFailed`] (transport delivered an
//!   exchange but the send leg itself failed).
//! - `ProblemReport` → [`TrqpClientError::ProblemReport`] (registry replied
//!   with a DIDComm problem-report carrying its own code).
//! - `ParseError` → [`TrqpClientError::ParseError`] (response was delivered
//!   but could not be parsed into the expected TRQP shape).
//! - `Timeout` → [`TrqpClientError::QueryFailed`]. When an element sets
//!   `timeout_secs = Some(n)`, the executor wraps `client.query(...)` in an
//!   outer `tokio::time::timeout(n)` and maps elapse to its own
//!   `QUERY_TIMEOUT` audit code (with `message = "exceeded {n}s budget"`).
//!   When `timeout_secs` is `None`, the only bound is the listener's own
//!   transport timeout, and a transport-level elapse surfaces through this
//!   branch instead.
//!
//! Keeping the three failure shapes distinct preserves the spec's
//! clean-denied vs error partition: a registry that signals "not
//! recognised" via a problem-report is observable separately from a
//! schema/version drift (parse error) and a low-level transport error.

use std::sync::Arc;

use async_trait::async_trait;

use crate::trust_registries::TrustRegistryListenerManager;
use crate::trust_registries::communication::TrustRegistryError;
use crate::trust_registries::types::TrqpQueryRequest;
use crate::trust_registry_verification::trust_check_element::{TrqpQueryParams, TrqpQueryType};
use crate::trust_registry_verification::trust_check_executor::{TrqpClient, TrqpClientError, TrqpOutcome};

/// Wire-level default `action` applied to a recognition query when the
/// element omits it or supplies a blank string. The `TrqpQueryRequest`
/// shape sends all four fields regardless of query family; without a
/// default, an under-specified recognition element would dispatch with
/// `action=""` and never match a stored 4-tuple record. A future
/// custom-query mode will let the dashboard surface this explicitly.
pub(crate) const RECOGNITION_DEFAULT_ACTION: &str = "is";

/// Wire-level default `resource` applied to a recognition query when
/// the element omits it or supplies a blank string. See
/// [`RECOGNITION_DEFAULT_ACTION`].
pub(crate) const RECOGNITION_DEFAULT_RESOURCE: &str = "ownedAgent";

/// Build the `TrqpQueryRequest` dispatched to a registry, applying
/// query-family-specific defaults for `action` and `resource`.
///
/// For [`TrqpQueryType::Recognition`], a missing or empty `action` /
/// `resource` falls through to the [`RECOGNITION_DEFAULT_ACTION`] /
/// [`RECOGNITION_DEFAULT_RESOURCE`] constants. For
/// [`TrqpQueryType::Authorization`] the element's values are sent
/// verbatim — the spec requires both fields, so silently defaulting
/// would mask config errors.
fn build_request(
    query_type: TrqpQueryType,
    params: &TrqpQueryParams,
) -> TrqpQueryRequest {
    let (default_action, default_resource) = match query_type {
        TrqpQueryType::Recognition => (RECOGNITION_DEFAULT_ACTION, RECOGNITION_DEFAULT_RESOURCE),
        TrqpQueryType::Authorization => ("", ""),
    };
    let action = params
        .action
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(default_action)
        .to_string();
    let resource = params
        .resource
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(default_resource)
        .to_string();
    TrqpQueryRequest {
        authority_id: params.authority_id.clone(),
        entity_id: params.entity_id.clone(),
        action,
        resource,
    }
}

/// Adapter that fronts a `TrustRegistryListenerManager` as a [`TrqpClient`].
pub struct TrqpListenerClient {
    manager: Arc<TrustRegistryListenerManager>,
}

impl TrqpListenerClient {
    pub fn new(manager: Arc<TrustRegistryListenerManager>) -> Self {
        Self { manager }
    }
}

#[async_trait]
impl TrqpClient for TrqpListenerClient {
    async fn query(
        &self,
        registry_id: &str,
        query_type: TrqpQueryType,
        params: &TrqpQueryParams,
    ) -> Result<TrqpOutcome, TrqpClientError> {
        let connection = self
            .manager
            .get_connection_clone(registry_id)
            .await
            .ok_or_else(|| {
                TrqpClientError::Unreachable(format!("no active trust registry connection for id '{}'", registry_id))
            })?;

        let registry_did = connection
            .main_did
            .clone()
            .unwrap_or_else(|| {
                connection
                    .registry_did
                    .clone()
            });

        let request = build_request(query_type, params);

        match query_type {
            TrqpQueryType::Authorization => self
                .manager
                .query_authorization(&registry_did, &request)
                .await
                .map(map_authorization_outcome)
                .map_err(map_error),
            TrqpQueryType::Recognition => self
                .manager
                .query_recognition(&registry_did, &request)
                .await
                .map(map_recognition_outcome)
                .map_err(map_error),
        }
    }
}

/// Message stamped on `TrqpOutcome::Denied.detail` when the registry
/// returned an empty JSON object (`{}`) — the no-matching-record
/// shape emitted by some registries.
const EMPTY_BODY_DETAIL: &str = "Registry returned empty response body \u{2014} no matching trust record";

fn map_recognition_outcome(maybe_resp: Option<crate::trust_registries::types::TrqpRecognitionResponse>) -> TrqpOutcome {
    match maybe_resp {
        None => TrqpOutcome::Denied {
            detail: EMPTY_BODY_DETAIL.to_string(),
        },
        Some(resp) if resp.recognized => TrqpOutcome::Allowed,
        Some(_) => TrqpOutcome::Denied {
            detail: "Registry answered `recognized: false`".to_string(),
        },
    }
}

fn map_authorization_outcome(
    maybe_resp: Option<crate::trust_registries::types::TrqpAuthorizationResponse>
) -> TrqpOutcome {
    match maybe_resp {
        None => TrqpOutcome::Denied {
            detail: EMPTY_BODY_DETAIL.to_string(),
        },
        Some(resp) if resp.authorized => TrqpOutcome::Allowed,
        Some(_) => TrqpOutcome::Denied {
            detail: "Registry answered `authorized: false`".to_string(),
        },
    }
}

fn map_error(err: TrustRegistryError) -> TrqpClientError {
    match err {
        TrustRegistryError::NotFound(msg)
        | TrustRegistryError::NoConnection(msg)
        | TrustRegistryError::StaleConnection(msg)
        | TrustRegistryError::ConnectionError(msg) => TrqpClientError::Unreachable(msg),
        TrustRegistryError::SendError(msg) | TrustRegistryError::Timeout(msg) => TrqpClientError::QueryFailed(msg),
        TrustRegistryError::ParseError(msg) => TrqpClientError::ParseError(msg),
        TrustRegistryError::ProblemReport(code, message) => TrqpClientError::ProblemReport { code, message },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_error_partitions_connection_failures_as_unreachable() {
        assert!(matches!(map_error(TrustRegistryError::NotFound("x".into())), TrqpClientError::Unreachable(_)));
        assert!(matches!(map_error(TrustRegistryError::NoConnection("x".into())), TrqpClientError::Unreachable(_)));
        assert!(matches!(map_error(TrustRegistryError::StaleConnection("x".into())), TrqpClientError::Unreachable(_)));
        assert!(matches!(map_error(TrustRegistryError::ConnectionError("x".into())), TrqpClientError::Unreachable(_)));
    }

    #[test]
    fn map_error_partitions_transport_failures_as_query_failed() {
        assert!(matches!(map_error(TrustRegistryError::SendError("x".into())), TrqpClientError::QueryFailed(_)));
        assert!(matches!(map_error(TrustRegistryError::Timeout("x".into())), TrqpClientError::QueryFailed(_)));
    }

    #[test]
    fn map_error_routes_parse_error_to_its_own_variant() {
        match map_error(TrustRegistryError::ParseError("bad json".into())) {
            TrqpClientError::ParseError(msg) => assert_eq!(msg, "bad json"),
            other => panic!("expected ParseError, got {:?}", other),
        }
    }

    #[test]
    fn map_error_routes_problem_report_to_its_own_variant_preserving_code_and_message() {
        match map_error(TrustRegistryError::ProblemReport("e.p2.encryption".into(), "boom".into())) {
            TrqpClientError::ProblemReport { code, message } => {
                assert_eq!(code, "e.p2.encryption");
                assert_eq!(message, "boom");
            }
            other => panic!("expected ProblemReport, got {:?}", other),
        }
    }

    fn params(
        authority: &str,
        entity: &str,
        action: Option<&str>,
        resource: Option<&str>,
    ) -> TrqpQueryParams {
        TrqpQueryParams {
            authority_id: authority.to_string(),
            entity_id: entity.to_string(),
            action: action.map(str::to_string),
            resource: resource.map(str::to_string),
        }
    }

    #[test]
    fn build_request_applies_recognition_defaults_when_action_and_resource_are_absent() {
        let p = params("did:a", "did:e", None, None);
        let req = build_request(TrqpQueryType::Recognition, &p);
        assert_eq!(req.authority_id, "did:a");
        assert_eq!(req.entity_id, "did:e");
        assert_eq!(req.action, RECOGNITION_DEFAULT_ACTION);
        assert_eq!(req.resource, RECOGNITION_DEFAULT_RESOURCE);
    }

    #[test]
    fn build_request_applies_recognition_defaults_when_action_and_resource_are_blank_strings() {
        let p = params("did:a", "did:e", Some(""), Some(""));
        let req = build_request(TrqpQueryType::Recognition, &p);
        assert_eq!(req.action, RECOGNITION_DEFAULT_ACTION);
        assert_eq!(req.resource, RECOGNITION_DEFAULT_RESOURCE);
    }

    #[test]
    fn build_request_honours_explicit_recognition_action_and_resource() {
        let p = params("did:a", "did:e", Some("perform"), Some("thing"));
        let req = build_request(TrqpQueryType::Recognition, &p);
        assert_eq!(req.action, "perform");
        assert_eq!(req.resource, "thing");
    }

    #[test]
    fn build_request_does_not_apply_recognition_defaults_for_authorization() {
        let p = params("did:a", "did:e", None, None);
        let req = build_request(TrqpQueryType::Authorization, &p);
        assert_eq!(req.action, "", "authorization must send element's value verbatim, even when blank");
        assert_eq!(req.resource, "");
    }

    #[test]
    fn build_request_honours_explicit_authorization_action_and_resource() {
        let p = params("did:a", "did:e", Some("transfer"), Some("account"));
        let req = build_request(TrqpQueryType::Authorization, &p);
        assert_eq!(req.action, "transfer");
        assert_eq!(req.resource, "account");
    }

    // --- outcome mappers: empty-body sentinel, explicit false, allow ---

    fn recognition(recognized: bool) -> crate::trust_registries::types::TrqpRecognitionResponse {
        crate::trust_registries::types::TrqpRecognitionResponse {
            recognized,
            authority_id: None,
            entity_id: None,
            action: None,
            resource: None,
            context: None,
            record_type: None,
            time_requested: None,
            time_evaluated: None,
            message: None,
        }
    }

    fn authorization(authorized: bool) -> crate::trust_registries::types::TrqpAuthorizationResponse {
        crate::trust_registries::types::TrqpAuthorizationResponse {
            authorized,
            authority_id: None,
            entity_id: None,
            action: None,
            resource: None,
            context: None,
            record_type: None,
            time_requested: None,
            time_evaluated: None,
            message: None,
        }
    }

    #[test]
    fn recognition_outcome_maps_recognized_true_to_allowed() {
        assert!(matches!(map_recognition_outcome(Some(recognition(true))), TrqpOutcome::Allowed));
    }

    #[test]
    fn recognition_outcome_maps_recognized_false_to_denied_with_verbatim_detail() {
        match map_recognition_outcome(Some(recognition(false))) {
            TrqpOutcome::Denied { detail } => assert_eq!(detail, "Registry answered `recognized: false`"),
            other => panic!("expected Denied, got {:?}", other),
        }
    }

    #[test]
    fn recognition_outcome_maps_empty_body_to_denied_with_empty_body_detail() {
        match map_recognition_outcome(None) {
            TrqpOutcome::Denied { detail } => {
                assert_eq!(detail, EMPTY_BODY_DETAIL);
                assert!(detail.contains("empty response body"), "detail must name the workaround: {}", detail);
            }
            other => panic!("expected Denied, got {:?}", other),
        }
    }

    #[test]
    fn authorization_outcome_maps_authorized_true_to_allowed() {
        assert!(matches!(map_authorization_outcome(Some(authorization(true))), TrqpOutcome::Allowed));
    }

    #[test]
    fn authorization_outcome_maps_authorized_false_to_denied_with_verbatim_detail() {
        match map_authorization_outcome(Some(authorization(false))) {
            TrqpOutcome::Denied { detail } => assert_eq!(detail, "Registry answered `authorized: false`"),
            other => panic!("expected Denied, got {:?}", other),
        }
    }

    #[test]
    fn authorization_outcome_maps_empty_body_to_denied_with_empty_body_detail() {
        match map_authorization_outcome(None) {
            TrqpOutcome::Denied { detail } => assert_eq!(detail, EMPTY_BODY_DETAIL),
            other => panic!("expected Denied, got {:?}", other),
        }
    }
}
