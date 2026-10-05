//! Trust Check executor — resolves [`TrqpQueryParams`] templates against the
//! request context and fans an ordered list of [`TrustCheckElement`]s out to
//! a pluggable [`TrqpClient`] in parallel, producing a `Vec<TrustCheckResult>`
//! that preserves input ordering for OPA consumption.
//!
//! Eeach element either
//! succeeds (`ok = true`), cleanly denies (`ok = false`, `error = None`), or
//! fails the stage (`ok = false`, `error = Some(_)`). One audit event +
//! Prometheus sample is emitted per element from inside [`execute_list`] —
//! the call site does not need to instrument anything.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::future::join_all;
use serde_json::Value;
use thiserror::Error;
use tokio::time::timeout;

use crate::observability::trust_check_audit::{TrustCheckAuditEvent, record_trust_check};
use crate::trust_registry_verification::template::{self, TemplateError};
use crate::trust_registry_verification::trqp_adapter::{RECOGNITION_DEFAULT_ACTION, RECOGNITION_DEFAULT_RESOURCE};
use crate::trust_registry_verification::trust_check_element::{
    TrqpQueryParams, TrqpQueryType, TrustCheckElement, TrustCheckError, TrustCheckLeg, TrustCheckResult,
};

/// Stage failure code: outbound TRQP transport could not be established
/// (registry not found, no DIDComm connection, stale connection, …).
pub const TRUST_REGISTRY_UNREACHABLE: &str = "TRUST_REGISTRY_UNREACHABLE";

/// Stage failure code: TRQP transport delivered a request/response but the
/// exchange itself failed in a way the adapter could not classify further
/// (e.g. low-level send error). Spec-explicit problem-report and parse-error
/// cases use the more specific codes below.
pub const QUERY_FAILED: &str = "QUERY_FAILED";

/// Stage failure code: registry responded with a DIDComm problem report. The
/// embedded code is preserved in the `error.message` so Rego policies can
/// branch on the registry-level reason without the adapter taking a position
/// on which codes mean "clean denial" vs "transport error".
pub const TRUST_REGISTRY_PROBLEM_REPORT: &str = "TRUST_REGISTRY_PROBLEM_REPORT";

/// Stage failure code: registry response was delivered but could not be
/// parsed into the expected TRQP shape. Distinct from `QUERY_FAILED` so a
/// schema/version drift on the registry side is observable independently
/// from a transport failure.
pub const TRUST_REGISTRY_PARSE_ERROR: &str = "TRUST_REGISTRY_PARSE_ERROR";

/// Stage failure code: the per-element `timeout_secs` override budget
/// elapsed before a response was received. Only emitted when the element
/// carries an explicit `Some(n)` timeout — elements that defer to the
/// trust-registry transport's own timeout instead surface their failure
/// via `TrqpClientError::QueryFailed` → [`QUERY_FAILED`].
pub const QUERY_TIMEOUT: &str = "QUERY_TIMEOUT";

/// Stage failure code: a `{{path}}` in the configured query could not be
/// resolved against the request context. No network call was attempted.
pub const TEMPLATE_RESOLUTION_FAILED: &str = "TEMPLATE_RESOLUTION_FAILED";

/// Stage failure code: the target's agent card could not be fetched and
/// Trust Check drove the card-fetch (i.e. the legacy
/// `trust_registry_verification` block is disabled or absent). The stage
/// synthesizes one result per configured element with this code, one
/// audit event per synthesized result, and returns `Ok(())` so OPA
/// remains authoritative on how to react.
///
/// Results carrying this code omit `authority_id` / `entity_id` from
/// the wire (see [`TrustCheckResult`]) since the raw template strings
/// aren't useful to an operator when the pipeline never got as far as
/// building the context they'd resolve against.
pub const AGENT_CARD_UNAVAILABLE: &str = "AGENT_CARD_UNAVAILABLE";

/// Stage failure code: the target's agent card **was** fetched, but does
/// not carry a usable `TRUST_REGISTRY_EXTENSION` metadata block — i.e.
/// `target_agent_context.provider_did` and/or `trust_registry_did` are
/// absent. Any Trust Check query template referencing
/// `input.agent.provider_did` / `input.agent.trust_registry_did` therefore
/// has nothing to resolve against. Distinct from
/// [`AGENT_CARD_UNAVAILABLE`] (card fetch itself failed) and from
/// [`TEMPLATE_RESOLUTION_FAILED`] (a genuine template-authoring bug on a
/// path unrelated to the TR extension).
///
/// Emitted only by the outbound target-leg pre-check in `step_trust_check`;
/// like `AGENT_CARD_UNAVAILABLE`, no TRQP call fires and results carrying
/// this code omit `authority_id` / `entity_id` from the wire.
pub const TRUST_REGISTRY_METADATA_UNAVAILABLE: &str = "TRUST_REGISTRY_METADATA_UNAVAILABLE";

/// Stage failure code: the target's agent card **was** fetched, but the
/// agent-identity credential it carries could not be cryptographically
/// verified — its `agent-identity-credential/v1` Verifiable Presentation
/// fails proof/expiry verification, or no `VCIssuer` is configured to
/// verify it. The VP **is present**; it just cannot be trusted. When the
/// card carries no such VP at all, the distinct
/// [`TARGET_AGENT_IDENTITY_UNAVAILABLE`] code is used instead. Because the
/// target's identity cannot be established, the whole target leg is
/// untrustworthy: the stage synthesizes one result per configured element
/// with this code (mirroring [`AGENT_CARD_UNAVAILABLE`]), one audit event
/// per synthesized result, clears `input.agent.did` so the unverified DID
/// never reaches OPA, and returns `Ok(())` so OPA remains authoritative on
/// how to react.
///
/// Emitted only by the outbound target-leg seam when the surface has a
/// non-empty target `trust_check_list` (i.e. Trust Check is active); the
/// legacy TR-only path never runs this verification. No TRQP call fires and
/// results carrying this code omit `authority_id` / `entity_id` from the
/// wire.
pub const IDENTITY_VP_VERIFICATION_FAILED: &str = "IDENTITY_VP_VERIFICATION_FAILED";

/// Stage failure code: the target's agent card was fetched, but it carries
/// **no** `agent-identity-credential/v1` Verifiable Presentation at all, so
/// the target's identity was never asserted — distinct from
/// [`IDENTITY_VP_VERIFICATION_FAILED`], which means a VP *was* present but
/// could not be cryptographically verified. Because the target's identity
/// cannot be established, the whole target leg is untrustworthy: the stage
/// synthesizes one result per configured element with this code (mirroring
/// [`AGENT_CARD_UNAVAILABLE`]), one audit event per synthesized result,
/// clears `input.agent.did` so no unverified DID reaches OPA, and returns
/// `Ok(())` so OPA remains authoritative on how to react.
///
/// Emitted only by the outbound target-leg seam when the surface has a
/// non-empty target `trust_check_list` (i.e. Trust Check is active). No TRQP
/// call fires and results carrying this code omit `authority_id` /
/// `entity_id` from the wire.
pub const TARGET_AGENT_IDENTITY_UNAVAILABLE: &str = "TARGET_AGENT_IDENTITY_UNAVAILABLE";

/// Stage failure code: a recognition query returned a negative verdict.
/// Fires when the registry either answers spec-compliantly with
/// `{ recognized: false, ... }` or (workaround for registries that emit
/// the no-matching-record shape) returns a literal empty body `{}`.
/// The `error.message` distinguishes the two paths for diagnostic
/// purposes; Rego rules should key off the code.
pub const NOT_RECOGNIZED: &str = "NOT_RECOGNIZED";

/// Stage failure code: an authorization query returned a negative
/// verdict. See [`NOT_RECOGNIZED`] for the symmetric contract.
pub const NOT_AUTHORIZED: &str = "NOT_AUTHORIZED";

/// Verdict returned by a TRQP query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrqpOutcome {
    Allowed,
    /// Registry answered with a clear negative verdict. `detail` is
    /// surfaced as the audit event's `error.message` and distinguishes
    /// the two negative paths (spec-compliant `false` vs empty-body
    /// workaround). The mapping from `Denied` to `NOT_RECOGNIZED` /
    /// `NOT_AUTHORIZED` happens in the executor, driven by the element's
    /// [`TrqpQueryType`].
    Denied {
        detail: String,
    },
}

/// Transport / protocol error categories surfaced by a [`TrqpClient`].
/// The adapter translates the underlying
/// [`crate::trust_registries::communication::TrustRegistryError`] into one
/// of these variants; the executor maps each to its own audit `error_code`
/// so the operator can distinguish them in logs/policies.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TrqpClientError {
    /// Outbound TRQP transport could not be established.
    #[error("trust registry unreachable: {0}")]
    Unreachable(String),
    /// Transport delivered the exchange but it failed end-to-end in a way
    /// that doesn't fit a more specific bucket (e.g. send error).
    #[error("trqp query failed: {0}")]
    QueryFailed(String),
    /// Registry responded with a DIDComm problem report. `code` is the
    /// problem-report code; `message` is the registry-supplied description.
    #[error("trqp problem report [{code}]: {message}")]
    ProblemReport { code: String, message: String },
    /// Registry response was delivered but could not be parsed.
    #[error("trqp parse error: {0}")]
    ParseError(String),
}

/// Pluggable TRQP transport. The executor owns this trait (Dependency
/// Inversion) so the production adapter (MR-3) and unit-test doubles share
/// one contract.
#[async_trait]
pub trait TrqpClient: Send + Sync {
    async fn query(
        &self,
        registry_id: &str,
        query_type: TrqpQueryType,
        params: &TrqpQueryParams,
    ) -> Result<TrqpOutcome, TrqpClientError>;
}

/// Per-request resolution context. Today it carries just the OPA-shaped
/// `input.*` value; the struct is the seam for forward-compatible additions
/// (gateway DID, leg-specific overrides, …).
#[derive(Debug, Clone, Copy)]
pub struct ExecutionContext<'a> {
    pub input: &'a Value,
}

/// Resolve templates and dispatch every element in `elements` concurrently,
/// returning one [`TrustCheckResult`] per input element in the same order.
///
/// Audit + Prometheus sampling fire once per element from inside this
/// function — the caller installs nothing.
pub async fn execute_list<C: TrqpClient + ?Sized>(
    surface_id: &str,
    leg: TrustCheckLeg,
    elements: &[TrustCheckElement],
    ctx: &ExecutionContext<'_>,
    client: &C,
) -> Vec<TrustCheckResult> {
    let surface_id = surface_id.to_string();
    let futures = elements
        .iter()
        .map(|elem| execute_one(surface_id.clone(), leg, elem, ctx, client));
    join_all(futures).await
}

async fn execute_one<C: TrqpClient + ?Sized>(
    surface_id: String,
    leg: TrustCheckLeg,
    elem: &TrustCheckElement,
    ctx: &ExecutionContext<'_>,
    client: &C,
) -> TrustCheckResult {
    let resolved = match resolve_params(&elem.query, ctx.input) {
        Ok(params) => params,
        Err(err) => {
            let detail = err.to_string();
            let result = stage_failure(elem, TEMPLATE_RESOLUTION_FAILED, detail.clone());
            record_trust_check(TrustCheckAuditEvent {
                surface_id: &surface_id,
                leg,
                element_id: &elem.id,
                element_name: elem.name.as_deref(),
                authority_id: Some(&elem.query.authority_id),
                entity_id: Some(&elem.query.entity_id),
                trust_registry_id: &elem.trust_registry_id,
                query_type: elem.query_type,
                ok: false,
                error_code: Some(TEMPLATE_RESOLUTION_FAILED),
                error_detail: Some(&detail),
                latency_ms: 0,
            });
            return result;
        }
    };

    let started = Instant::now();
    let outcome = match elem.timeout_secs {
        Some(secs) => {
            let budget = Duration::from_secs(secs as u64);
            timeout(budget, client.query(&elem.trust_registry_id, elem.query_type, &resolved))
                .await
                .map_err(|_| secs)
        }
        None => Ok(client
            .query(&elem.trust_registry_id, elem.query_type, &resolved)
            .await),
    };
    let latency_ms = started
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;

    let (result, error_code): (TrustCheckResult, Option<&'static str>) = match outcome {
        Ok(Ok(TrqpOutcome::Allowed)) => (
            TrustCheckResult {
                id: elem.id.clone(),
                trust_registry_id: elem.trust_registry_id.clone(),
                query_type: elem.query_type,
                ok: true,
                error: None,
                name: elem.name.clone(),
                authority_id: Some(resolved.authority_id.clone()),
                entity_id: Some(resolved.entity_id.clone()),
                action: effective_action(elem.query_type, resolved.action.as_deref()),
                resource: effective_resource(elem.query_type, resolved.resource.as_deref()),
                query_resolved: true,
            },
            None,
        ),
        Ok(Ok(TrqpOutcome::Denied { detail })) => {
            let code = match elem.query_type {
                TrqpQueryType::Recognition => NOT_RECOGNIZED,
                TrqpQueryType::Authorization => NOT_AUTHORIZED,
            };
            (resolved_failure(elem, &resolved, code, detail), Some(code))
        }
        Ok(Err(TrqpClientError::Unreachable(detail))) => {
            (resolved_failure(elem, &resolved, TRUST_REGISTRY_UNREACHABLE, detail), Some(TRUST_REGISTRY_UNREACHABLE))
        }
        Ok(Err(TrqpClientError::QueryFailed(detail))) => {
            (resolved_failure(elem, &resolved, QUERY_FAILED, detail), Some(QUERY_FAILED))
        }
        Ok(Err(TrqpClientError::ProblemReport { code, message })) => (
            resolved_failure(elem, &resolved, TRUST_REGISTRY_PROBLEM_REPORT, format!("[{}] {}", code, message)),
            Some(TRUST_REGISTRY_PROBLEM_REPORT),
        ),
        Ok(Err(TrqpClientError::ParseError(detail))) => {
            (resolved_failure(elem, &resolved, TRUST_REGISTRY_PARSE_ERROR, detail), Some(TRUST_REGISTRY_PARSE_ERROR))
        }
        Err(secs) => (
            resolved_failure(elem, &resolved, QUERY_TIMEOUT, format!("exceeded {}s budget", secs)),
            Some(QUERY_TIMEOUT),
        ),
    };

    let error_detail = result
        .error
        .as_ref()
        .map(|e| e.message.as_str());
    record_trust_check(TrustCheckAuditEvent {
        surface_id: &surface_id,
        leg,
        element_id: &elem.id,
        element_name: elem.name.as_deref(),
        authority_id: Some(&resolved.authority_id),
        entity_id: Some(&resolved.entity_id),
        trust_registry_id: &elem.trust_registry_id,
        query_type: elem.query_type,
        ok: result.ok,
        error_code,
        error_detail,
        latency_ms,
    });
    result
}

fn resolve_params(
    params: &TrqpQueryParams,
    input: &Value,
) -> Result<TrqpQueryParams, TemplateError> {
    let authority_id = template::resolve(&params.authority_id, input)?;
    let entity_id = template::resolve(&params.entity_id, input)?;
    let action = match &params.action {
        Some(t) => Some(template::resolve(t, input)?),
        None => None,
    };
    let resource = match &params.resource {
        Some(t) => Some(template::resolve(t, input)?),
        None => None,
    };
    Ok(TrqpQueryParams {
        authority_id,
        entity_id,
        action,
        resource,
    })
}

fn stage_failure(
    elem: &TrustCheckElement,
    code: &'static str,
    message: String,
) -> TrustCheckResult {
    synthesize_failure(elem, code, message)
}

/// Build a stage-failure result for one element using the **resolved**
/// query values. Used by the executor's post-dispatch error arms so the
/// evaluated `authority_id`/`entity_id`/`action`/`resource` still reach
/// OPA even on a transport / registry / timeout failure.
fn resolved_failure(
    elem: &TrustCheckElement,
    resolved: &TrqpQueryParams,
    code: &'static str,
    message: String,
) -> TrustCheckResult {
    TrustCheckResult {
        id: elem.id.clone(),
        trust_registry_id: elem.trust_registry_id.clone(),
        query_type: elem.query_type,
        ok: false,
        error: Some(TrustCheckError {
            code: code.to_string(),
            message,
        }),
        name: elem.name.clone(),
        authority_id: Some(resolved.authority_id.clone()),
        entity_id: Some(resolved.entity_id.clone()),
        action: effective_action(elem.query_type, resolved.action.as_deref()),
        resource: effective_resource(elem.query_type, resolved.resource.as_deref()),
        query_resolved: true,
    }
}

/// Build a stage-failure [`TrustCheckResult`] for one element without running
/// the per-element TRQP call. Used by pipeline stages that must synthesize
/// results outside [`execute_list`] — the outbound target-leg pre-check uses
/// this to emit [`AGENT_CARD_UNAVAILABLE`] (card fetch failed) and
/// [`TRUST_REGISTRY_METADATA_UNAVAILABLE`] (card fetched but the TR metadata
/// extension is missing / incomplete) results while preserving positional
/// identity parity (`id`, `trust_registry_id`, `query_type`, `name`) with the
/// source element so Rego rules that address by `id` and audit consumers that
/// key on element identity stay stable.
///
/// `authority_id` / `entity_id` are omitted (`None`) when `code` is one of
/// the two "unavailable" codes above — the raw template strings would be
/// noise, not signal, on those paths and the wire simply drops them. For any
/// other code (e.g. [`TEMPLATE_RESOLUTION_FAILED`]) the raw template strings
/// from `elem.query.*` are still surfaced so a policy authoring bug remains
/// visible in the failing result.
///
/// `action` / `resource` are always populated from the element's raw
/// template strings (recognition wire defaults still apply); they are
/// operator-set literals, not template-derived, and remain meaningful on
/// every error path. `query_resolved` is set to `false` since template
/// substitution either failed or was never attempted by the time this
/// function is reached.
pub fn synthesize_failure(
    elem: &TrustCheckElement,
    code: &'static str,
    message: String,
) -> TrustCheckResult {
    let omit_ids = code_omits_ids(code);
    TrustCheckResult {
        id: elem.id.clone(),
        trust_registry_id: elem.trust_registry_id.clone(),
        query_type: elem.query_type,
        ok: false,
        error: Some(TrustCheckError {
            code: code.to_string(),
            message,
        }),
        name: elem.name.clone(),
        authority_id: if omit_ids {
            None
        } else {
            Some(
                elem.query
                    .authority_id
                    .clone(),
            )
        },
        entity_id: if omit_ids {
            None
        } else {
            Some(elem.query.entity_id.clone())
        },
        action: effective_action(elem.query_type, elem.query.action.as_deref()),
        resource: effective_resource(elem.query_type, elem.query.resource.as_deref()),
        query_resolved: false,
    }
}

/// True when `code` is one of the target-leg pre-dispatch codes whose
/// synthesized results deliberately omit `authority_id` / `entity_id`
/// from the wire (see [`synthesize_failure`]).
pub(crate) fn code_omits_ids(code: &str) -> bool {
    matches!(
        code,
        AGENT_CARD_UNAVAILABLE
            | TRUST_REGISTRY_METADATA_UNAVAILABLE
            | IDENTITY_VP_VERIFICATION_FAILED
            | TARGET_AGENT_IDENTITY_UNAVAILABLE
    )
}

/// A deferred trust-check failure: the wire error code plus the fixed
/// `error.message` to stamp on every synthesized per-element result.
#[derive(Clone, Debug)]
pub struct TrustCheckIdentityVerificationFailure {
    /// Wire error code (e.g. [`IDENTITY_VP_VERIFICATION_FAILED`] or
    /// [`TARGET_AGENT_IDENTITY_UNAVAILABLE`]).
    pub code: &'static str,
    /// Fixed wire `error.message` on each synthesized result.
    pub detail: &'static str,
}

/// The value published on `TrustCheckResult.action` for a given
/// query family and operator-set value. Recognition queries with no
/// operator-set value (or a blank one) fall through to the wire
/// default [`RECOGNITION_DEFAULT_ACTION`] so a Rego rule reads the
/// same tuple the registry saw. Authorization queries pass through
/// verbatim (the spec requires both fields — a blank/missing value is
/// a config issue and should surface as-is instead of being silently
/// defaulted).
fn effective_action(
    query_type: TrqpQueryType,
    action: Option<&str>,
) -> String {
    let raw = action.unwrap_or("");
    if query_type == TrqpQueryType::Recognition && raw.is_empty() {
        return RECOGNITION_DEFAULT_ACTION.to_string();
    }
    raw.to_string()
}

/// The value published on `TrustCheckResult.resource`. See
/// [`effective_action`] — recognition default is
/// [`RECOGNITION_DEFAULT_RESOURCE`].
fn effective_resource(
    query_type: TrqpQueryType,
    resource: Option<&str>,
) -> String {
    let raw = resource.unwrap_or("");
    if query_type == TrqpQueryType::Recognition && raw.is_empty() {
        return RECOGNITION_DEFAULT_RESOURCE.to_string();
    }
    raw.to_string()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;
    use tokio::sync::Mutex;
    use tokio::time::{Duration, sleep};

    use super::*;

    /// Per-call response programmed by index in input order.
    enum Programmed {
        Outcome(TrqpOutcome),
        Error(TrqpClientError),
        Delay(Duration, TrqpOutcome),
    }

    struct MockClient {
        responses: Mutex<Vec<Programmed>>,
        call_order: Arc<Mutex<Vec<String>>>,
        dispatched: AtomicUsize,
    }

    impl MockClient {
        fn new(responses: Vec<Programmed>) -> Self {
            Self {
                responses: Mutex::new(responses),
                call_order: Arc::new(Mutex::new(Vec::new())),
                dispatched: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl TrqpClient for MockClient {
        async fn query(
            &self,
            registry_id: &str,
            _query_type: TrqpQueryType,
            _params: &TrqpQueryParams,
        ) -> Result<TrqpOutcome, TrqpClientError> {
            let idx = self
                .dispatched
                .fetch_add(1, Ordering::SeqCst);
            self.call_order
                .lock()
                .await
                .push(registry_id.to_string());
            let programmed = {
                let mut responses = self.responses.lock().await;
                std::mem::replace(
                    &mut responses[idx],
                    Programmed::Outcome(TrqpOutcome::Denied { detail: String::new() }),
                )
            };
            match programmed {
                Programmed::Outcome(o) => Ok(o),
                Programmed::Error(e) => Err(e),
                Programmed::Delay(d, o) => {
                    sleep(d).await;
                    Ok(o)
                }
            }
        }
    }

    fn elem(
        id: &str,
        registry: &str,
        timeout_secs: Option<u32>,
    ) -> TrustCheckElement {
        TrustCheckElement {
            id: id.to_string(),
            trust_registry_id: registry.to_string(),
            query_type: TrqpQueryType::Recognition,
            query: TrqpQueryParams {
                authority_id: "{{input.caller.gateway.did}}".to_string(),
                entity_id: "{{input.caller.did}}".to_string(),
                action: None,
                resource: None,
            },
            timeout_secs,
            name: None,
        }
    }

    fn ctx() -> Value {
        json!({
            "input": {
                "caller": {
                    "did": "did:web:caller",
                    "gateway": { "did": "did:web:caller-gateway" }
                }
            }
        })
    }

    #[tokio::test]
    async fn allowed_outcome_maps_to_ok_true() {
        let elements = vec![elem("e1", "tr-a", Some(5))];
        let client = MockClient::new(vec![Programmed::Outcome(TrqpOutcome::Allowed)]);
        let input = ctx();
        let results =
            execute_list("surf", TrustCheckLeg::Caller, &elements, &ExecutionContext { input: &input }, &client).await;
        assert_eq!(results.len(), 1);
        assert!(results[0].ok);
        assert!(results[0].error.is_none());
    }

    #[tokio::test]
    async fn denied_recognition_maps_to_not_recognized_with_detail() {
        let elements = vec![elem("e1", "tr-a", Some(5))];
        let client = MockClient::new(vec![Programmed::Outcome(TrqpOutcome::Denied {
            detail: "Registry answered `recognized: false`".to_string(),
        })]);
        let input = ctx();
        let results =
            execute_list("surf", TrustCheckLeg::Caller, &elements, &ExecutionContext { input: &input }, &client).await;
        assert!(!results[0].ok);
        let err = results[0]
            .error
            .as_ref()
            .expect("denied recognition now carries an error code");
        assert_eq!(err.code, NOT_RECOGNIZED);
        assert_eq!(err.message, "Registry answered `recognized: false`");
    }

    #[tokio::test]
    async fn denied_authorization_maps_to_not_authorized_with_detail() {
        let mut e = elem("e1", "tr-a", Some(5));
        e.query_type = TrqpQueryType::Authorization;
        let elements = vec![e];
        let client = MockClient::new(vec![Programmed::Outcome(TrqpOutcome::Denied {
            detail: "Registry returned empty response body \u{2014} no matching trust record".to_string(),
        })]);
        let input = ctx();
        let results =
            execute_list("surf", TrustCheckLeg::Caller, &elements, &ExecutionContext { input: &input }, &client).await;
        assert!(!results[0].ok);
        let err = results[0]
            .error
            .as_ref()
            .expect("denied authorization now carries an error code");
        assert_eq!(err.code, NOT_AUTHORIZED);
        assert!(
            err.message
                .contains("empty response body"),
            "detail must be surfaced verbatim: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn unreachable_maps_to_trust_registry_unreachable() {
        let elements = vec![elem("e1", "tr-a", Some(5))];
        let client =
            MockClient::new(vec![Programmed::Error(TrqpClientError::Unreachable("no connection".to_string()))]);
        let input = ctx();
        let results =
            execute_list("surf", TrustCheckLeg::Caller, &elements, &ExecutionContext { input: &input }, &client).await;
        let err = results[0]
            .error
            .as_ref()
            .expect("error expected");
        assert_eq!(err.code, TRUST_REGISTRY_UNREACHABLE);
    }

    #[tokio::test]
    async fn query_failed_maps_to_query_failed_code() {
        let elements = vec![elem("e1", "tr-a", Some(5))];
        let client = MockClient::new(vec![Programmed::Error(TrqpClientError::QueryFailed("send failed".to_string()))]);
        let input = ctx();
        let results =
            execute_list("surf", TrustCheckLeg::Caller, &elements, &ExecutionContext { input: &input }, &client).await;
        let err = results[0]
            .error
            .as_ref()
            .expect("error expected");
        assert_eq!(err.code, QUERY_FAILED);
    }

    #[tokio::test]
    async fn problem_report_maps_to_dedicated_code_and_preserves_registry_code_in_message() {
        let elements = vec![elem("e1", "tr-a", Some(5))];
        let client = MockClient::new(vec![Programmed::Error(TrqpClientError::ProblemReport {
            code: "e.p2.encryption".to_string(),
            message: "decryption failed".to_string(),
        })]);
        let input = ctx();
        let results =
            execute_list("surf", TrustCheckLeg::Caller, &elements, &ExecutionContext { input: &input }, &client).await;
        let err = results[0]
            .error
            .as_ref()
            .expect("error expected");
        assert_eq!(err.code, TRUST_REGISTRY_PROBLEM_REPORT);
        assert!(
            err.message
                .contains("e.p2.encryption"),
            "registry code preserved in message: {}",
            err.message
        );
        assert!(
            err.message
                .contains("decryption failed")
        );
    }

    #[tokio::test]
    async fn parse_error_maps_to_dedicated_code() {
        let elements = vec![elem("e1", "tr-a", Some(5))];
        let client = MockClient::new(vec![Programmed::Error(TrqpClientError::ParseError("bad json".to_string()))]);
        let input = ctx();
        let results =
            execute_list("surf", TrustCheckLeg::Caller, &elements, &ExecutionContext { input: &input }, &client).await;
        let err = results[0]
            .error
            .as_ref()
            .expect("error expected");
        assert_eq!(err.code, TRUST_REGISTRY_PARSE_ERROR);
        assert_eq!(err.message, "bad json");
    }

    #[tokio::test]
    async fn elapsed_budget_maps_to_query_timeout() {
        let elements = vec![elem("slow", "tr-a", Some(1))];
        let client = MockClient::new(vec![Programmed::Delay(Duration::from_millis(1500), TrqpOutcome::Allowed)]);
        let input = ctx();
        let results =
            execute_list("surf", TrustCheckLeg::Caller, &elements, &ExecutionContext { input: &input }, &client).await;
        let err = results[0]
            .error
            .as_ref()
            .expect("error expected");
        assert_eq!(err.code, QUERY_TIMEOUT);
    }

    #[tokio::test]
    async fn template_failure_short_circuits_before_dispatch() {
        let mut e = elem("e1", "tr-a", Some(5));
        e.query.authority_id = "{{input.missing.field}}".to_string();
        let client = MockClient::new(vec![Programmed::Outcome(TrqpOutcome::Allowed)]);
        let input = ctx();
        let results =
            execute_list("surf", TrustCheckLeg::Caller, &[e], &ExecutionContext { input: &input }, &client).await;
        let err = results[0]
            .error
            .as_ref()
            .expect("error expected");
        assert_eq!(err.code, TEMPLATE_RESOLUTION_FAILED);
        assert_eq!(
            client
                .dispatched
                .load(Ordering::SeqCst),
            0,
            "no TRQP call fires when template fails"
        );
    }

    #[tokio::test]
    async fn results_preserve_input_order_under_concurrent_completion() {
        let elements =
            vec![elem("first", "tr-1", Some(5)), elem("second", "tr-2", Some(5)), elem("third", "tr-3", Some(5))];
        let client = MockClient::new(vec![
            Programmed::Delay(Duration::from_millis(120), TrqpOutcome::Allowed),
            Programmed::Outcome(TrqpOutcome::Allowed),
            Programmed::Delay(Duration::from_millis(60), TrqpOutcome::Allowed),
        ]);
        let input = ctx();
        let results =
            execute_list("surf", TrustCheckLeg::Caller, &elements, &ExecutionContext { input: &input }, &client).await;
        let registries: Vec<&str> = results
            .iter()
            .map(|r| r.trust_registry_id.as_str())
            .collect();
        assert_eq!(registries, vec!["tr-1", "tr-2", "tr-3"]);
    }

    #[tokio::test]
    async fn slow_element_does_not_block_siblings() {
        let elements = vec![elem("slow", "tr-slow", Some(1)), elem("fast", "tr-fast", Some(5))];
        let client = MockClient::new(vec![
            Programmed::Delay(Duration::from_millis(1500), TrqpOutcome::Allowed),
            Programmed::Outcome(TrqpOutcome::Allowed),
        ]);
        let input = ctx();
        let started = std::time::Instant::now();
        let results =
            execute_list("surf", TrustCheckLeg::Caller, &elements, &ExecutionContext { input: &input }, &client).await;
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_millis(2500), "fast element waited on slow element: elapsed = {:?}", elapsed);
        assert_eq!(
            results[0]
                .error
                .as_ref()
                .unwrap()
                .code,
            QUERY_TIMEOUT
        );
        assert!(results[1].ok);
    }

    fn elem_with_action_resource(
        id: &str,
        registry: &str,
    ) -> TrustCheckElement {
        TrustCheckElement {
            id: id.to_string(),
            trust_registry_id: registry.to_string(),
            query_type: TrqpQueryType::Authorization,
            query: TrqpQueryParams {
                authority_id: "{{input.caller.gateway.did}}".to_string(),
                entity_id: "{{input.caller.did}}".to_string(),
                action: Some("invoke".to_string()),
                resource: Some("tool:payments.transfer".to_string()),
            },
            timeout_secs: Some(5),
            name: None,
        }
    }

    #[tokio::test]
    async fn evaluated_fields_populated_on_success() {
        let elements = vec![elem_with_action_resource("e1", "tr-a")];
        let client = MockClient::new(vec![Programmed::Outcome(TrqpOutcome::Allowed)]);
        let input = ctx();
        let results =
            execute_list("surf", TrustCheckLeg::Caller, &elements, &ExecutionContext { input: &input }, &client).await;
        assert!(results[0].ok);
        assert!(results[0].query_resolved, "success arm must set query_resolved = true");
        assert_eq!(
            results[0]
                .authority_id
                .as_deref(),
            Some("did:web:caller-gateway")
        );
        assert_eq!(
            results[0]
                .entity_id
                .as_deref(),
            Some("did:web:caller")
        );
        assert_eq!(results[0].action, "invoke");
        assert_eq!(results[0].resource, "tool:payments.transfer");
    }

    #[tokio::test]
    async fn evaluated_fields_populated_on_deny() {
        let elements = vec![elem_with_action_resource("e1", "tr-a")];
        let client = MockClient::new(vec![Programmed::Outcome(TrqpOutcome::Denied { detail: "denied".to_string() })]);
        let input = ctx();
        let results =
            execute_list("surf", TrustCheckLeg::Caller, &elements, &ExecutionContext { input: &input }, &client).await;
        assert!(!results[0].ok);
        assert_eq!(
            results[0]
                .error
                .as_ref()
                .unwrap()
                .code,
            NOT_AUTHORIZED
        );
        assert!(results[0].query_resolved, "clean deny still has resolved query");
        assert_eq!(
            results[0]
                .authority_id
                .as_deref(),
            Some("did:web:caller-gateway")
        );
        assert_eq!(
            results[0]
                .entity_id
                .as_deref(),
            Some("did:web:caller")
        );
        assert_eq!(results[0].action, "invoke");
        assert_eq!(results[0].resource, "tool:payments.transfer");
    }

    #[tokio::test]
    async fn evaluated_fields_populated_on_transport_error() {
        let elements = vec![elem_with_action_resource("e1", "tr-a")];
        let client =
            MockClient::new(vec![Programmed::Error(TrqpClientError::Unreachable("no connection".to_string()))]);
        let input = ctx();
        let results =
            execute_list("surf", TrustCheckLeg::Caller, &elements, &ExecutionContext { input: &input }, &client).await;
        assert!(!results[0].ok);
        assert_eq!(
            results[0]
                .error
                .as_ref()
                .unwrap()
                .code,
            TRUST_REGISTRY_UNREACHABLE
        );
        assert!(results[0].query_resolved, "transport error still has resolved query");
        assert_eq!(
            results[0]
                .authority_id
                .as_deref(),
            Some("did:web:caller-gateway")
        );
        assert_eq!(results[0].action, "invoke");
        assert_eq!(results[0].resource, "tool:payments.transfer");
    }

    #[tokio::test]
    async fn evaluated_fields_raw_on_template_failure() {
        // Template references a path that isn't in the context → resolve_params
        // short-circuits with TEMPLATE_RESOLUTION_FAILED before any TRQP call.
        let mut e = elem_with_action_resource("e1", "tr-a");
        e.query.entity_id = "{{input.does.not.exist}}".to_string();
        let elements = vec![e];
        let client = MockClient::new(vec![Programmed::Outcome(TrqpOutcome::Allowed)]);
        let input = ctx();
        let results =
            execute_list("surf", TrustCheckLeg::Caller, &elements, &ExecutionContext { input: &input }, &client).await;
        assert!(!results[0].ok);
        assert_eq!(
            results[0]
                .error
                .as_ref()
                .unwrap()
                .code,
            TEMPLATE_RESOLUTION_FAILED
        );
        assert!(!results[0].query_resolved, "template failure must set query_resolved = false");
        // Raw template strings (verbatim from elem.query) reach OPA so a
        // policy can still assert on action/resource on the failure path.
        assert_eq!(
            results[0]
                .authority_id
                .as_deref(),
            Some("{{input.caller.gateway.did}}")
        );
        assert_eq!(
            results[0]
                .entity_id
                .as_deref(),
            Some("{{input.does.not.exist}}")
        );
        assert_eq!(results[0].action, "invoke");
        assert_eq!(results[0].resource, "tool:payments.transfer");
    }

    #[test]
    fn synthesize_failure_omits_ids_for_agent_card_unavailable() {
        // The two "unavailable" pre-check codes emitted by the outbound
        // target-leg pipeline drop authority_id / entity_id entirely so
        // the wire (and audit) doesn't show noisy raw template strings.
        let elem = elem_with_action_resource("e1", "tr-a");
        let result = synthesize_failure(&elem, AGENT_CARD_UNAVAILABLE, "card unavailable".to_string());
        assert!(!result.ok);
        assert_eq!(
            result
                .error
                .as_ref()
                .unwrap()
                .code,
            AGENT_CARD_UNAVAILABLE
        );
        assert!(!result.query_resolved);
        assert!(result.authority_id.is_none(), "AGENT_CARD_UNAVAILABLE must omit authority_id");
        assert!(result.entity_id.is_none(), "AGENT_CARD_UNAVAILABLE must omit entity_id");
        // action / resource stay populated — they are operator literals
        // (or recognition defaults), not template-derived.
        assert_eq!(result.action, "invoke");
        assert_eq!(result.resource, "tool:payments.transfer");
    }

    #[test]
    fn synthesize_failure_omits_ids_for_trust_registry_metadata_unavailable() {
        let elem = elem_with_action_resource("e1", "tr-a");
        let result = synthesize_failure(
            &elem,
            TRUST_REGISTRY_METADATA_UNAVAILABLE,
            "target agent card is missing the trust registry metadata extension".to_string(),
        );
        assert!(!result.ok);
        assert_eq!(
            result
                .error
                .as_ref()
                .unwrap()
                .code,
            TRUST_REGISTRY_METADATA_UNAVAILABLE
        );
        assert!(!result.query_resolved);
        assert!(result.authority_id.is_none());
        assert!(result.entity_id.is_none());
        assert_eq!(result.action, "invoke");
        assert_eq!(result.resource, "tool:payments.transfer");
    }

    #[test]
    fn synthesize_failure_omits_ids_for_identity_vp_verification_failed() {
        assert!(code_omits_ids(IDENTITY_VP_VERIFICATION_FAILED));
        let elem = elem_with_action_resource("e1", "tr-a");
        let result = synthesize_failure(
            &elem,
            IDENTITY_VP_VERIFICATION_FAILED,
            "target agent identity credential could not be verified".to_string(),
        );
        assert!(!result.ok);
        assert_eq!(
            result
                .error
                .as_ref()
                .unwrap()
                .code,
            IDENTITY_VP_VERIFICATION_FAILED
        );
        assert!(!result.query_resolved);
        assert!(result.authority_id.is_none());
        assert!(result.entity_id.is_none());
        assert_eq!(result.action, "invoke");
        assert_eq!(result.resource, "tool:payments.transfer");
    }

    #[test]
    fn synthesize_failure_omits_ids_for_target_agent_identity_unavailable() {
        assert!(code_omits_ids(TARGET_AGENT_IDENTITY_UNAVAILABLE));
        let elem = elem_with_action_resource("e1", "tr-a");
        let result = synthesize_failure(
            &elem,
            TARGET_AGENT_IDENTITY_UNAVAILABLE,
            "target agent card carries no agent-identity-credential".to_string(),
        );
        assert!(!result.ok);
        assert_eq!(
            result
                .error
                .as_ref()
                .unwrap()
                .code,
            TARGET_AGENT_IDENTITY_UNAVAILABLE
        );
        assert!(!result.query_resolved);
        assert!(result.authority_id.is_none());
        assert!(result.entity_id.is_none());
        assert_eq!(result.action, "invoke");
        assert_eq!(result.resource, "tool:payments.transfer");
    }

    #[test]
    fn synthesize_failure_keeps_raw_templates_for_other_codes() {
        // Every other synthesized-failure path (e.g. TEMPLATE_RESOLUTION_FAILED
        // when synthesized outside the executor) keeps the raw template
        // strings so operators can see the offending path in the result.
        let elem = elem_with_action_resource("e1", "tr-a");
        let result = synthesize_failure(&elem, TEMPLATE_RESOLUTION_FAILED, "boom".to_string());
        assert_eq!(
            result.authority_id.as_deref(),
            Some("{{input.caller.gateway.did}}"),
            "non-unavailable codes must surface the raw template"
        );
        assert_eq!(result.entity_id.as_deref(), Some("{{input.caller.did}}"));
    }

    #[test]
    fn synthesize_failure_serializes_to_omit_absent_ids() {
        // Wire-shape guard: `authority_id` / `entity_id` disappear from the
        // JSON entirely on the two "unavailable" codes so the operator sees
        // no template noise, and stay present as strings on every other path.
        let elem = elem_with_action_resource("e1", "tr-a");
        let unavailable = synthesize_failure(&elem, AGENT_CARD_UNAVAILABLE, "gone".to_string());
        let json = serde_json::to_value(&unavailable).unwrap();
        assert!(
            json.get("authority_id")
                .is_none(),
            "authority_id must be omitted from JSON on AGENT_CARD_UNAVAILABLE"
        );
        assert!(
            json.get("entity_id")
                .is_none(),
            "entity_id must be omitted from JSON on AGENT_CARD_UNAVAILABLE"
        );
        let template_fail = synthesize_failure(&elem, TEMPLATE_RESOLUTION_FAILED, "boom".to_string());
        let json = serde_json::to_value(&template_fail).unwrap();
        assert!(
            json.get("authority_id")
                .is_some(),
            "authority_id must round-trip on TEMPLATE_RESOLUTION_FAILED"
        );
        assert!(
            json.get("entity_id")
                .is_some()
        );
    }

    fn elem_recognition_without_action_resource(
        id: &str,
        registry: &str,
    ) -> TrustCheckElement {
        TrustCheckElement {
            id: id.to_string(),
            trust_registry_id: registry.to_string(),
            query_type: TrqpQueryType::Recognition,
            query: TrqpQueryParams {
                authority_id: "{{input.caller.gateway.did}}".to_string(),
                entity_id: "{{input.caller.did}}".to_string(),
                action: None,
                resource: None,
            },
            timeout_secs: Some(5),
            name: None,
        }
    }

    #[tokio::test]
    async fn recognition_result_fills_wire_defaults_when_element_omits_action_and_resource() {
        // A recognition element with no operator-set action/resource
        // publishes the wire defaults on the result so Rego reads the
        // same tuple the registry actually saw. Covers the success arm.
        let elements = vec![elem_recognition_without_action_resource("e-rec", "tr-a")];
        let client = MockClient::new(vec![Programmed::Outcome(TrqpOutcome::Allowed)]);
        let input = ctx();
        let results =
            execute_list("surf", TrustCheckLeg::Caller, &elements, &ExecutionContext { input: &input }, &client).await;
        assert!(results[0].ok);
        assert_eq!(results[0].action, "is", "recognition default action must reach OPA");
        assert_eq!(results[0].resource, "ownedAgent", "recognition default resource must reach OPA");
    }

    #[test]
    fn recognition_synthesize_failure_fills_wire_defaults() {
        // The synthesize_failure path (raw templates, query_resolved=false)
        // still fills recognition defaults so a Rego rule reading
        // r.action on an AGENT_CARD_UNAVAILABLE recognition result
        // sees "is" instead of an empty string.
        let elem = elem_recognition_without_action_resource("e-rec", "tr-a");
        let result = synthesize_failure(&elem, AGENT_CARD_UNAVAILABLE, "card unavailable".to_string());
        assert!(!result.query_resolved);
        assert_eq!(result.action, "is");
        assert_eq!(result.resource, "ownedAgent");
    }

    #[test]
    fn effective_action_preserves_custom_recognition_value() {
        // Custom recognition action/resource passes through unchanged;
        // defaults only kick in for None or blank.
        assert_eq!(effective_action(TrqpQueryType::Recognition, Some("custom-verb")), "custom-verb");
        assert_eq!(effective_resource(TrqpQueryType::Recognition, Some("custom-thing")), "custom-thing");
        assert_eq!(effective_action(TrqpQueryType::Recognition, None), "is");
        assert_eq!(effective_action(TrqpQueryType::Recognition, Some("")), "is");
        assert_eq!(effective_resource(TrqpQueryType::Recognition, None), "ownedAgent");
        assert_eq!(effective_resource(TrqpQueryType::Recognition, Some("")), "ownedAgent");
    }

    #[test]
    fn effective_action_does_not_default_for_authorization() {
        // Authorization queries require both fields per spec; a blank or
        // missing value stays blank so a config error surfaces on the
        // wire instead of being silently masked.
        assert_eq!(effective_action(TrqpQueryType::Authorization, None), "");
        assert_eq!(effective_action(TrqpQueryType::Authorization, Some("")), "");
        assert_eq!(effective_action(TrqpQueryType::Authorization, Some("invoke")), "invoke");
        assert_eq!(effective_resource(TrqpQueryType::Authorization, None), "");
        assert_eq!(effective_resource(TrqpQueryType::Authorization, Some("tool:x")), "tool:x");
    }
}
