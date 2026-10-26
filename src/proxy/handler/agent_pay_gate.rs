//! The payment gate for surfaces with an `agent_pay` payment policy.
//!
//! This gateway decides *whether* a request is chargeable (the policy's MCP
//! tool triggers, A2A method filters or `require_all`); agent-pay *takes* the
//! payment. A request is read once into an [`Intake`], which also removes its
//! payment credential. Just before the request is forwarded, a chargeable one
//! sends a small payment request — never the caller's payload — to the policy's
//! payment surface over the fabric, and the gate's answer either lets the
//! request through with a receipt or becomes the caller's response. A free
//! request makes no fabric hop.

mod consumed;
mod streamed;

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use serde_json::{Map, Value, json};

use crate::config::ChannelProtocol;
use crate::config::agent_surface::{AgentPayPolicy, AgentSurface};
use crate::mcp::continuations::protected::ContinuationPayment;
use crate::proxy::fabric_forward::{FabricForwardError, FabricForwardResponse};
use crate::surface_context::{McpContext, PaymentContext};
use crate::x402::PaymentDelegationDecision;

/// The x402 credential header, spelled exactly as agent-pay matches it.
const X402_CREDENTIAL_HEADER: &str = "PAYMENT-SIGNATURE";
const MCP_CREDENTIAL_META: &str = "org.paymentauth/credential";
const RECEIPT_META: &str = "org.paymentauth/receipt";
const RECEIPT_VC_FINGERPRINT_HEADER: &str = "payment-receipt-vc-fingerprint";
/// The members of an A2A 1.0 `SendMessageResponse` or `StreamResponse` that
/// wrap the object a result is made of. The wrapper itself defines no
/// `metadata`; the object inside does.
const A2A_RESULT_WRAPPERS: [&str; 4] = ["message", "task", "statusUpdate", "artifactUpdate"];
const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;
const MAX_PRINCIPAL_HOPS: usize = 16;
const MAX_RESOURCE_CHARS: usize = 256;
const MAX_PATH_CHARS: usize = 2048;
const MAX_VARIANT_CHARS: usize = 64;
const MAX_RECEIPT_BODY_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_BREAKER_FAILURES: u32 = 5;
const DEFAULT_BREAKER_OPEN_FOR: Duration = Duration::from_secs(30);
const AUTHORIZATION_HEADER: &str = "payment-authorization";
const CAPTURE_DEADLINE_HEADER: &str = "payment-capture-deadline";
const MAX_AUTHORIZATION_CHARS: usize = 256;
/// How long held funds stay capturable when agent-pay names no deadline.
const DEFAULT_CAPTURE_WINDOW: chrono::Duration = chrono::Duration::minutes(15);
/// The bounds a capture deadline agent-pay names is held to.
const MIN_CAPTURE_WINDOW: chrono::Duration = chrono::Duration::minutes(1);
const MAX_CAPTURE_WINDOW: chrono::Duration = chrono::Duration::days(7);
/// The reason a void names for a request whose Target did not deliver.
const NOT_DELIVERED: &str = "not_delivered";
/// The least the gate waits for agent-pay: the deadline it hands on is in whole
/// seconds, at least one, so a shorter wait would outlive the caller's.
const MIN_PAYMENT_WAIT: Duration = Duration::from_secs(1);
/// Why a credential that already paid for a forwarded request is refused.
const ALREADY_USED: &str = "payment_already_used";
/// Why a retry of a payment whose outcome is not known is asked for.
const UNCONFIRMED: &str = "payment_unconfirmed";
/// Why a request is asked to be retried while its payment is being made.
const IN_PROGRESS: &str = "payment_in_progress";
/// Seconds a caller is told to wait before it retries a payment whose outcome is
/// not known.
const UNCONFIRMED_RETRY_AFTER_SECS: u64 = 2;
/// How long agent-pay answers the same credential, request and idempotency key
/// with the payment it already took, in seconds: the window in which retrying
/// is safe, because it cannot be charged twice.
const REPLAY_WINDOW_SECS: u64 = 120;

/// The payment rail a credential or receipt belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Rail {
    X402,
    Mpp,
}

impl Rail {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::X402 => "x402",
            Self::Mpp => "mpp",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "x402" => Some(Self::X402),
            "mpp" => Some(Self::Mpp),
            _ => None,
        }
    }

    /// The caller-facing receipt header for this rail.
    fn receipt_header(self) -> HeaderName {
        match self {
            Self::X402 => HeaderName::from_static("payment-response"),
            Self::Mpp => HeaderName::from_static("payment-receipt"),
        }
    }

    fn audit(self) -> crate::delegation_vault::audit::PaymentRail {
        match self {
            Self::X402 => crate::delegation_vault::audit::PaymentRail::X402,
            Self::Mpp => crate::delegation_vault::audit::PaymentRail::Mpp,
        }
    }

    fn ledger(self) -> crate::payments_ledger::LedgerRail {
        match self {
            Self::X402 => crate::payments_ledger::LedgerRail::X402,
            Self::Mpp => crate::payments_ledger::LedgerRail::Mpp,
        }
    }
}

/// A payment credential the caller presented. Never logged.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Credential {
    rail: Rail,
    value: String,
}

impl std::fmt::Debug for Credential {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        formatter
            .debug_struct("Credential")
            .field("rail", &self.rail)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Credential {
    /// The header agent-pay reads this credential from.
    fn wire_header(&self) -> (String, String) {
        match self.rail {
            Rail::X402 => (X402_CREDENTIAL_HEADER.to_string(), self.value.clone()),
            Rail::Mpp => ("authorization".to_string(), format!("Payment {}", self.value)),
        }
    }
}

fn usable_credential(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= MAX_CREDENTIAL_BYTES && HeaderValue::from_str(value).is_ok())
        .then(|| value.to_string())
}

fn mpp_token(value: &str) -> Option<String> {
    let value = usable_credential(value)?;
    let decoded = crate::mpp::challenge::base64url_decode_nopad(&value).ok()?;
    serde_json::from_slice::<crate::mpp::types::MppCredential>(&decoded)
        .ok()
        .map(|_| value)
}

/// The token of an `Authorization: Payment <token>` value. HTTP authentication
/// schemes are case-insensitive, and so is the match.
fn payment_token(value: &[u8]) -> Option<&[u8]> {
    let end = value
        .iter()
        .position(|byte| *byte == b' ')?;
    value[..end]
        .eq_ignore_ascii_case(b"Payment")
        .then(|| &value[end + 1..])
}

/// Where a JSON-RPC request can carry `_meta["org.paymentauth/credential"]`:
/// the message root (generic JSON-RPC), `params._meta` (MCP), `params.metadata`
/// and `params.message.metadata` (A2A).
fn credential_holders(message: &Value) -> impl Iterator<Item = &Value> {
    let params = message.get("params");
    [
        message.get("_meta"),
        params.and_then(|params| params.get("_meta")),
        params.and_then(|params| params.get("metadata")),
        params
            .and_then(|params| params.get("message"))
            .and_then(|message| message.get("metadata")),
    ]
    .into_iter()
    .flatten()
}

fn meta_credential(holder: &Value) -> Option<String> {
    match holder.get(MCP_CREDENTIAL_META)? {
        Value::String(token) => mpp_token(token),
        object @ Value::Object(_) => serde_json::to_vec(object)
            .ok()
            .map(|bytes| crate::mpp::challenge::base64url_encode_nopad(&bytes))
            .and_then(|token| usable_credential(&token)),
        _ => None,
    }
}

/// The credential in a JSON-RPC request body: an MCP `tools/call`'s
/// `payment_signature` / `payment_credential` arguments, or
/// `_meta["org.paymentauth/credential"]` in any of [`credential_holders`] on any
/// method. A batch's is the first of its messages'.
fn body_credential(message: &Value) -> Option<Credential> {
    match message {
        Value::Array(messages) => messages
            .iter()
            .find_map(body_credential),
        _ => message_credential(message),
    }
}

fn message_credential(message: &Value) -> Option<Credential> {
    let arguments = (message
        .get("method")
        .and_then(Value::as_str)
        == Some("tools/call"))
    .then(|| {
        message
            .get("params")
            .and_then(|params| params.get("arguments"))
    })
    .flatten();
    if let Some(value) = arguments
        .and_then(|arguments| arguments.get("payment_signature"))
        .and_then(Value::as_str)
        .and_then(usable_credential)
    {
        return Some(Credential { rail: Rail::X402, value });
    }
    arguments
        .and_then(|arguments| arguments.get("payment_credential"))
        .and_then(Value::as_str)
        .and_then(mpp_token)
        .or_else(|| credential_holders(message).find_map(meta_credential))
        .map(|value| Credential { rail: Rail::Mpp, value })
}

/// The payment credential on a request: the `PAYMENT-SIGNATURE` header (or the
/// gateway's configured x402 header), `Authorization: Payment …`, or the
/// request body's (see [`body_credential`]). Headers win over the body.
fn extract_credential(
    headers: &HeaderMap,
    signature_header: &str,
    message: Option<&Value>,
) -> Option<Credential> {
    let x402_header = [X402_CREDENTIAL_HEADER, signature_header]
        .into_iter()
        .find_map(|name| crate::x402::extract_payment_signature(headers, name))
        .and_then(|value| usable_credential(&value));
    if let Some(value) = x402_header {
        return Some(Credential { rail: Rail::X402, value });
    }
    if let Some(value) = headers
        .get_all(axum::http::header::AUTHORIZATION)
        .iter()
        .filter_map(|value| payment_token(value.as_bytes()))
        .filter_map(|token| std::str::from_utf8(token).ok())
        .find_map(mpp_token)
    {
        return Some(Credential { rail: Rail::Mpp, value });
    }
    message.and_then(body_credential)
}

/// Removes the payment credential from `owner`'s `field` object (`_meta` or
/// `metadata`), dropping that object when the removal leaves it empty.
fn remove_meta_credential(
    owner: &mut Value,
    field: &str,
) -> bool {
    let Some(owner) = owner.as_object_mut() else { return false };
    let Some(holder) = owner
        .get_mut(field)
        .and_then(Value::as_object_mut)
    else {
        return false;
    };
    if holder
        .remove(MCP_CREDENTIAL_META)
        .is_none()
    {
        return false;
    }
    if holder.is_empty() {
        owner.remove(field);
    }
    true
}

fn remove_params_metadata(params: &mut Value) -> bool {
    let mut removed = remove_meta_credential(params, "_meta");
    removed |= remove_meta_credential(params, "metadata");
    if let Some(message) = params.get_mut("message") {
        removed |= remove_meta_credential(message, "metadata");
    }
    removed
}

/// Removes every payment credential an MCP `tools/call` can carry in its
/// params, so none reaches the Target. Returns whether anything was removed.
pub(crate) fn remove_mcp_credentials(params: Option<&mut Value>) -> bool {
    let Some(params) = params else { return false };
    let mut removed = super::surface_payment::remove_payment_argument(Some(params), "payment_signature");
    removed |= super::surface_payment::remove_payment_argument(Some(params), "payment_credential");
    removed | remove_params_metadata(params)
}

/// Removes every payment credential a JSON-RPC request body can carry, from
/// every message of a batch.
fn remove_body_credentials(message: &mut Value) -> bool {
    if let Value::Array(messages) = message {
        return messages
            .iter_mut()
            .fold(false, |removed, message| remove_body_credentials(message) | removed);
    }
    let is_tool_call = message
        .get("method")
        .and_then(Value::as_str)
        == Some("tools/call");
    let mut removed = remove_meta_credential(message, "_meta");
    if let Some(params) = message.get_mut("params") {
        removed |= if is_tool_call {
            remove_mcp_credentials(Some(params))
        } else {
            remove_params_metadata(params)
        };
    }
    removed
}

/// Removes every payment credential header, so none reaches the Target.
fn strip_credential_headers(
    headers: &mut HeaderMap,
    signature_header: &str,
) {
    headers.remove(X402_CREDENTIAL_HEADER);
    if let Ok(name) = HeaderName::from_bytes(signature_header.as_bytes()) {
        headers.remove(name);
    }
    if headers
        .get_all(axum::http::header::AUTHORIZATION)
        .iter()
        .any(|value| payment_token(value.as_bytes()).is_some())
    {
        let kept: Vec<HeaderValue> = headers
            .get_all(axum::http::header::AUTHORIZATION)
            .iter()
            .filter(|value| payment_token(value.as_bytes()).is_none())
            .cloned()
            .collect();
        headers.remove(axum::http::header::AUTHORIZATION);
        for value in kept {
            headers.append(axum::http::header::AUTHORIZATION, value);
        }
    }
}

/// The same as [`strip_credential_headers`] for a fabric `headers` object: an
/// array-valued `authorization` keeps the values that are not payment ones.
fn strip_credential_json_headers(
    headers: &mut Map<String, Value>,
    signature_header: &str,
) {
    headers.retain(|name, _| {
        !(name.eq_ignore_ascii_case(X402_CREDENTIAL_HEADER) || name.eq_ignore_ascii_case(signature_header))
    });
    let authorization: Vec<String> = headers
        .keys()
        .filter(|name| name.eq_ignore_ascii_case("authorization"))
        .cloned()
        .collect();
    for name in authorization {
        let Some(value) = headers.get_mut(&name) else { continue };
        match value {
            Value::String(text) if payment_token(text.as_bytes()).is_some() => {
                headers.remove(&name);
            }
            Value::Array(values) => {
                values.retain(|value| {
                    !value
                        .as_str()
                        .is_some_and(|text| payment_token(text.as_bytes()).is_some())
                });
                if values.is_empty() {
                    headers.remove(&name);
                }
            }
            _ => {}
        }
    }
}

/// Whether the policy charges this request. `require_all` charges every
/// request; otherwise MCP `tools/call` requests follow the tool triggers, A2A
/// requests the method filters (a body they cannot be matched against is
/// charged), and every other protocol is always charged. A policy that names no
/// triggers charges the protocol's default operations (see
/// [`AgentPayPolicy::charged_mcp_triggers`] and
/// [`AgentPayPolicy::charged_a2a_filters`]). A JSON-RPC batch is charged, once,
/// when any of its messages is.
pub(crate) fn is_chargeable(
    policy: &AgentPayPolicy,
    protocol: &ChannelProtocol,
    body: &[u8],
    mcp_context: Option<&McpContext>,
) -> bool {
    is_chargeable_parsed(
        policy,
        protocol,
        body.is_empty(),
        serde_json::from_slice(body)
            .ok()
            .as_ref(),
        mcp_context,
    )
}

/// [`is_chargeable`] for a body that is already parsed.
fn is_chargeable_parsed(
    policy: &AgentPayPolicy,
    protocol: &ChannelProtocol,
    body_is_empty: bool,
    parsed: Option<&Value>,
    mcp_context: Option<&McpContext>,
) -> bool {
    if policy.require_all {
        return true;
    }
    match protocol {
        ChannelProtocol::Mcp => {
            let mcp_message_charged = |method: &str, tool_name: Option<&str>| {
                crate::x402::middleware::mcp_tool_requires_payment(
                    Some(
                        policy
                            .charged_mcp_triggers()
                            .as_ref(),
                    ),
                    method,
                    tool_name,
                    "agent_pay",
                )
            };
            let json_message_charged = |json: &Value| {
                mcp_message_charged(
                    &crate::x402::middleware::json_rpc_method(json),
                    crate::x402::middleware::json_rpc_tool_name(json).as_deref(),
                )
            };
            match (mcp_context, parsed) {
                (Some(context), _) => mcp_message_charged(&context.method, context.tool_name.as_deref()),
                (None, Some(Value::Array(messages))) => messages
                    .iter()
                    .any(json_message_charged),
                (None, Some(json)) => json_message_charged(json),
                (None, None) => false,
            }
        }
        ChannelProtocol::A2a | ChannelProtocol::Ap2 => {
            let filters = policy.charged_a2a_filters();
            let message_charged = |parsed: Option<&Value>| {
                crate::x402::middleware::a2a_requires_payment_parsed(
                    Some(filters.as_slice()),
                    None,
                    body_is_empty,
                    parsed,
                    "agent_pay",
                )
            };
            match parsed {
                Some(Value::Array(messages)) => messages
                    .iter()
                    .any(|message| message_charged(Some(message))),
                parsed => message_charged(parsed),
            }
        }
        _ => true,
    }
}

fn protocol_label(protocol: &ChannelProtocol) -> &'static str {
    match protocol {
        ChannelProtocol::Mcp => "mcp",
        ChannelProtocol::A2a | ChannelProtocol::Ap2 => "a2a",
        _ => "http",
    }
}

fn clip(
    value: &str,
    max_chars: usize,
) -> String {
    value
        .chars()
        .take(max_chars)
        .collect()
}

/// What the payment is for: the MCP tool, the A2A method, or the HTTP path
/// (without its query string, which can carry secrets).
fn resource(
    protocol: &ChannelProtocol,
    body: Option<&Value>,
    mcp_context: Option<&McpContext>,
    path: &str,
) -> String {
    let method = body
        .and_then(|body| body.get("method"))
        .and_then(Value::as_str);
    let named = match protocol {
        ChannelProtocol::Mcp => mcp_context
            .and_then(|context| context.tool_name.clone())
            .or_else(|| {
                body.and_then(|body| body.pointer("/params/name"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .or_else(|| method.map(str::to_string)),
        ChannelProtocol::A2a | ChannelProtocol::Ap2 => method.map(str::to_string),
        _ => None,
    };
    clip(
        named
            .as_deref()
            .unwrap_or(path),
        MAX_RESOURCE_CHARS,
    )
}

fn manifest_rail(policy: &AgentPayPolicy) -> Option<Rail> {
    let manifest = policy
        .manifest_snapshot
        .as_ref()?;
    match (manifest.offers_protocol("x402"), manifest.offers_protocol("mpp")) {
        (true, false) => Some(Rail::X402),
        (false, true) => Some(Rail::Mpp),
        _ => None,
    }
}

/// The rail a gate call is reported under, by the audit trail, the ledger, the
/// integration events and `input.payment` alike: the rail of the credential the
/// caller presented, else the only rail the manifest offers.
fn resolved_rail(
    credential_rail: Option<Rail>,
    policy: &AgentPayPolicy,
) -> Option<Rail> {
    credential_rail.or_else(|| manifest_rail(policy))
}

/// The audit trail and the receipt credentials always name a rail, so a call
/// whose rail is not known is recorded as `x402`.
fn audit_rail(rail: Option<Rail>) -> Rail {
    rail.unwrap_or(Rail::X402)
}

fn manifest_price(policy: &AgentPayPolicy) -> (Option<String>, Option<String>) {
    let Some(manifest) = policy
        .manifest_snapshot
        .as_ref()
    else {
        return (None, None);
    };
    let present = |value: &str| (!value.is_empty()).then(|| value.to_string());
    (present(&manifest.amount.amount), present(&manifest.amount.unit))
}

/// How a refusal is shaped for the caller.
#[derive(Clone, Debug, PartialEq)]
enum Shape {
    Http,
    /// A JSON-RPC caller. A caller on the legacy MCP revision is answered with
    /// the payment transport's retired error codes.
    JsonRpc {
        id: Option<Value>,
        legacy_mcp: bool,
    },
}

fn shape(
    message: Option<&Value>,
    protocol: &ChannelProtocol,
    mcp_context: Option<&McpContext>,
) -> Shape {
    match message {
        Some(message)
            if message
                .get("jsonrpc")
                .and_then(Value::as_str)
                == Some("2.0") =>
        {
            Shape::JsonRpc {
                id: message.get("id").cloned(),
                legacy_mcp: *protocol == ChannelProtocol::Mcp
                    && mcp_context.is_none_or(|context| {
                        context
                            .protocol_version
                            .is_none()
                    }),
            }
        }
        _ => Shape::Http,
    }
}

/// A request as the gate is given it.
pub(crate) struct Inbound<'a> {
    pub method: &'a str,
    /// The path and query as received; only the path is ever reported.
    pub path_and_query: &'a str,
    /// The surface variant the request resolved to.
    pub variant: Option<&'a str>,
    pub headers: &'a HeaderMap,
    pub body: &'a Bytes,
    pub mcp_context: Option<&'a McpContext>,
    pub signature_header: &'a str,
}

/// What the gate learned from one request before any payment is taken: whether
/// it is chargeable, the credential it carried, and the request without that
/// credential. The credential leaves the request here, whether or not the
/// request is chargeable, and is held only to pay with.
#[derive(Clone, Debug)]
pub(crate) struct Intake {
    chargeable: bool,
    /// The body is a JSON-RPC batch.
    batch: bool,
    credential: Option<Credential>,
    /// The idempotency key of this credential on this request.
    key: Option<String>,
    shape: Shape,
    protocol: ChannelProtocol,
    resource: String,
    path: String,
    variant: Option<String>,
    request_id: Option<String>,
    signature_header: String,
    message: Option<Value>,
    body: Bytes,
    input: PaymentContext,
}

impl Intake {
    /// Reads a request on `surface`; `None` when the surface has no `agent_pay`
    /// policy and so nothing to charge or to strip.
    pub(crate) fn read(
        surface: &AgentSurface,
        inbound: Inbound<'_>,
    ) -> Option<Self> {
        let policy = surface.agent_pay_policy()?;
        let protocol = surface.channel_protocol();
        let path = inbound
            .path_and_query
            .split(['?', '#'])
            .next()
            .unwrap_or_default();
        let mut message = serde_json::from_slice::<Value>(inbound.body).ok();
        let credential = extract_credential(inbound.headers, inbound.signature_header, message.as_ref());
        let chargeable = !crate::proxy::paths::is_public_request(inbound.method, path)
            && is_chargeable_parsed(policy, &protocol, inbound.body.is_empty(), message.as_ref(), inbound.mcp_context);
        let removed = message
            .as_mut()
            .is_some_and(remove_body_credentials);
        let body = match message.as_ref() {
            Some(message) if removed => serde_json::to_vec(message)
                .map(Bytes::from)
                .unwrap_or_default(),
            _ => inbound.body.clone(),
        };
        let variant = inbound
            .variant
            .map(|variant| clip(variant, MAX_VARIANT_CHARS));
        let key = credential
            .as_ref()
            .map(|credential| {
                idempotency_key(
                    &surface.surface_id,
                    &policy.payment_surface_id,
                    &request_digest(
                        inbound.method,
                        inbound.path_and_query,
                        variant.as_deref(),
                        message.as_ref(),
                        &body,
                    ),
                    credential,
                )
            });
        let (amount, currency) = manifest_price(policy);
        let input = PaymentContext {
            required: chargeable,
            rail: resolved_rail(
                credential
                    .as_ref()
                    .map(|credential| credential.rail),
                policy,
            )
            .map(|rail| rail.as_str().to_string()),
            amount,
            currency,
            response_header: None,
        };
        Some(Self {
            chargeable,
            batch: matches!(message, Some(Value::Array(_))),
            key,
            shape: shape(message.as_ref(), &protocol, inbound.mcp_context),
            resource: resource(&protocol, message.as_ref(), inbound.mcp_context, path),
            path: clip(path, MAX_PATH_CHARS),
            variant,
            request_id: inbound
                .headers
                .get("x-request-id")
                .and_then(|value| value.to_str().ok())
                .filter(|value| !value.is_empty() && value.len() <= 128)
                .map(str::to_string),
            signature_header: inbound
                .signature_header
                .to_string(),
            credential,
            protocol,
            message,
            body,
            input,
        })
    }

    /// The request body without any payment credential: what is forwarded.
    pub(crate) fn body(&self) -> &Bytes {
        &self.body
    }

    /// `input.payment` for policy: whether the request is chargeable, and the
    /// rail and price it would be charged at, when known.
    pub(crate) fn policy_input(&self) -> PaymentContext {
        self.input.clone()
    }

    /// Whether the request is chargeable and carries no credential, so a
    /// continuation round must already hold its payment.
    pub(crate) fn is_unpaid(&self) -> bool {
        self.chargeable && self.credential.is_none()
    }

    /// Removes the payment credentials from the params of a modern MCP message,
    /// so the copy of the request that is dispatched, answered to policy and
    /// logged carries none.
    pub(crate) fn strip_modern(
        &self,
        message: &mut crate::mcp::request_validation::ValidatedModernMessage,
    ) {
        let Some(params) = message.params.as_mut() else { return };
        if message.method == "tools/call" {
            remove_mcp_credentials(Some(params));
        } else {
            remove_params_metadata(params);
        }
    }

    /// Removes the payment credential headers from `headers`.
    pub(crate) fn strip_headers(
        &self,
        headers: &mut HeaderMap,
    ) {
        strip_credential_headers(headers, &self.signature_header);
    }

    /// Removes the payment credential headers from a fabric `headers` object.
    pub(crate) fn strip_json_headers(
        &self,
        headers: &mut Map<String, Value>,
    ) {
        strip_credential_json_headers(headers, &self.signature_header);
    }
}

/// A canonical rendering of `value`: object keys in order, no whitespace.
fn write_canonical(
    value: &Value,
    out: &mut Vec<u8>,
) {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
            out.push(b'{');
            for (index, (key, value)) in entries
                .into_iter()
                .enumerate()
            {
                if index > 0 {
                    out.push(b',');
                }
                // Serializing into a `Vec` cannot fail.
                let _ = serde_json::to_writer(&mut *out, key);
                out.push(b':');
                write_canonical(value, out);
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        scalar => {
            let _ = serde_json::to_writer(&mut *out, scalar);
        }
    }
}

/// What the request asks for, as one hex SHA-256: its method, its path and
/// query as received, its surface variant and its body without any credential.
/// A JSON-RPC body counts only through its `method` and `params`, so a retry
/// under a new JSON-RPC `id` is the same request while a different tool,
/// arguments or path is not.
fn request_digest(
    method: &str,
    path_and_query: &str,
    variant: Option<&str>,
    message: Option<&Value>,
    body: &[u8],
) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    for field in [method, path_and_query, variant.unwrap_or_default()] {
        hasher.update(field.as_bytes());
        hasher.update(b"\n");
    }
    match message.filter(|message| {
        message
            .get("jsonrpc")
            .and_then(Value::as_str)
            == Some("2.0")
    }) {
        Some(message) => {
            let mut canonical = Vec::new();
            canonical.extend_from_slice(b"{\"method\":");
            write_canonical(
                message
                    .get("method")
                    .unwrap_or(&Value::Null),
                &mut canonical,
            );
            canonical.extend_from_slice(b",\"params\":");
            write_canonical(
                message
                    .get("params")
                    .unwrap_or(&Value::Null),
                &mut canonical,
            );
            canonical.push(b'}');
            hasher.update(&canonical);
        }
        None => hasher.update(body),
    }
    format!("{:x}", hasher.finalize())
}

/// The idempotency key agent-pay is given for one credential on one request:
/// stable across a client's retry of that request, different for any other
/// request the same credential is presented with.
fn idempotency_key(
    surface_id: &str,
    payment_surface_id: &str,
    request_digest: &str,
    credential: &Credential,
) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    for part in [surface_id, payment_surface_id, request_digest] {
        hasher.update(part.as_bytes());
        hasher.update(b"\n");
    }
    hasher.update(credential.value.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// A client-supplied principal chain, passed through only when every hop has
/// the shape agent-pay accepts; the gateway never builds one itself.
fn client_principal_chain(body: Option<&Value>) -> Option<Value> {
    let body = body?;
    let supplied = [
        "/params/_meta/org.paymentauth~1payment_context",
        "/params/metadata/org.paymentauth~1payment_context",
        "/params/message/metadata/org.paymentauth~1payment_context",
    ]
    .iter()
    .find_map(|pointer| body.pointer(pointer))?;
    let chain = supplied
        .get("principal_chain")?
        .as_array()?;
    let valid_hop = |hop: &Value| {
        hop.as_object()
            .is_some_and(|hop| {
                hop.get("did")
                    .and_then(Value::as_str)
                    .is_some_and(|did| did.starts_with("did:") && did.len() <= 2048)
                    && hop
                        .iter()
                        .all(|(name, value)| match name.as_str() {
                            "did" => true,
                            "role" | "delegation_vc" | "signature" => value.is_string(),
                            _ => false,
                        })
            })
    };
    (!chain.is_empty() && chain.len() <= MAX_PRINCIPAL_HOPS && chain.iter().all(valid_hop))
        .then(|| Value::Array(chain.clone()))
}

/// Whether a principal chain ends at `agent_did`: the paying agent is its last
/// hop.
fn chain_ends_at(
    chain: &Value,
    agent_did: &str,
) -> bool {
    chain
        .as_array()
        .and_then(|hops| hops.last())
        .and_then(|hop| hop.get("did"))
        .and_then(Value::as_str)
        == Some(agent_did)
}

/// Who is paying, as far as this gateway authenticated them.
#[derive(Clone, Copy, Default)]
pub(crate) struct Caller<'a> {
    pub identity: Option<&'a crate::source_auth::AuthenticatedIdentity>,
    /// The caller's agent DID, only when its identity binding was verified.
    pub verified_agent_did: Option<&'a str>,
}

impl Caller<'_> {
    fn claim(
        &self,
        name: &str,
    ) -> Option<String> {
        self.identity?
            .jwt_claims()?
            .get(name)?
            .as_str()
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    }

    /// The payer recorded in this gateway's audit trail: the verified agent
    /// DID, or a peppered hash of the authenticated principal.
    fn audit_payer(&self) -> Option<String> {
        self.verified_agent_did
            .map(str::to_string)
            .or_else(|| {
                self.identity.map(|identity| {
                    crate::identity::credential_identity::hash_credential(&[(
                        "payer",
                        identity
                            .principal_key()
                            .as_str(),
                    )])
                })
            })
    }
}

/// The peppered hash of an authenticated caller a ledger row records, so only
/// that caller can poll the payment's held case.
pub(crate) fn caller_principal(identity: Option<&crate::source_auth::AuthenticatedIdentity>) -> Option<String> {
    identity.map(|identity| {
        crate::identity::credential_identity::hash_credential(&[(
            "payment-caller",
            identity
                .principal_key()
                .as_str(),
        )])
    })
}

/// The path suffix under a surface's route a caller polls its held payment at.
const CASE_POLL_PATH: &str = "/.well-known/payment-cases/";
const MAX_CASE_ID_CHARS: usize = 128;

/// The case id a `GET` of [`CASE_POLL_PATH`] asks about.
pub(crate) fn polled_case<'p>(
    method: &str,
    path: &'p str,
) -> Option<&'p str> {
    let (_, case_id) = path.rsplit_once(CASE_POLL_PATH)?;
    (method == "GET"
        && !case_id.is_empty()
        && case_id.len() <= MAX_CASE_ID_CHARS
        && case_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    .then_some(case_id)
}

/// Whether a surface charges through agent-pay but authenticates no caller, so
/// its callers cannot poll their held payments: every poll is answered `404`.
pub(crate) fn held_payments_unpollable(surface: &AgentSurface) -> bool {
    surface
        .agent_pay_policy()
        .is_some()
        && surface
            .source_auth()
            .is_none()
}

/// The answer to a caller's poll of its held payment: its outcome, live review
/// state and receipt reference, or `404` for any case that is not the caller's.
pub(crate) async fn case_poll_response(
    surface: &AgentSurface,
    case_id: &str,
    identity: Option<&crate::source_auth::AuthenticatedIdentity>,
) -> Response {
    let principal = caller_principal(identity);
    let mut response =
        match crate::payments_ledger::caller_case(&surface.surface_id, case_id, principal.as_deref()).await {
            Some(case) => (StatusCode::OK, axum::Json(case)).into_response(),
            None => (StatusCode::NOT_FOUND, axum::Json(json!({"error": "Payment case not found"}))).into_response(),
        };
    response
        .headers_mut()
        .insert(axum::http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// A W3C `traceparent` continuing `trace_id` (a UUID, or anything else hashed
/// into a trace id) with a fresh span.
pub(crate) fn traceparent(trace_id: &str) -> String {
    use sha2::{Digest, Sha256};

    let compact: String = trace_id
        .chars()
        .filter(|character| *character != '-')
        .collect::<String>()
        .to_ascii_lowercase();
    let trace = if compact.len() == 32
        && compact
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        && compact != "0".repeat(32)
    {
        compact
    } else {
        hex::encode(&Sha256::digest(trace_id.as_bytes())[..16])
    };
    let span = loop {
        let span = hex::encode(rand::random::<[u8; 8]>());
        if span != "0".repeat(16) {
            break span;
        }
    };
    format!("00-{trace}-{span}-01")
}

/// The top-level `payment_context` of the forward-request.
///
/// A client-supplied principal chain is forwarded only when this gateway
/// verified the caller's agent DID and the chain ends at it, since agent-pay
/// takes the payer from the chain's root and cannot check the caller itself; a
/// caller this gateway did not verify as an agent, however it authenticated,
/// has its chain dropped. With a chain forwarded, the payer has no `did` of its
/// own, and without one it is the verified agent.
fn build_payment_context(
    surface_id: &str,
    policy: &AgentPayPolicy,
    message: Option<&Value>,
    resource: &str,
    caller: &Caller<'_>,
    idempotency_key: Option<&str>,
    thid: &str,
    trace_context: &str,
) -> Value {
    let mut context = Map::new();
    let chain = client_principal_chain(message).filter(|chain| {
        caller
            .verified_agent_did
            .is_some_and(|did| chain_ends_at(chain, did))
    });
    let has_chain = chain.is_some();
    if let Some(chain) = chain {
        context.insert("principal_chain".into(), chain);
    }
    let mut payer = Map::new();
    if !has_chain && let Some(did) = caller.verified_agent_did {
        payer.insert("did".into(), json!(did));
    }
    let mut claims = Map::new();
    for (name, value) in [
        ("iss", caller.claim("iss")),
        ("tid", caller.claim("tid")),
        (
            "oid",
            caller
                .claim("oid")
                .or_else(|| caller.claim("sub")),
        ),
    ] {
        if let Some(value) = value {
            claims.insert(name.into(), json!(value));
        }
    }
    if !claims.is_empty() {
        payer.insert("jwt_claims".into(), Value::Object(claims));
    }
    if policy.share_payer_email
        && let Some(email) = caller.claim("email")
    {
        payer.insert("email".into(), json!(email));
    }
    if !payer.is_empty() {
        context.insert("payer_identity".into(), Value::Object(payer));
    }
    let mut intent = Map::new();
    intent.insert("merchant".into(), json!(surface_id));
    intent.insert("resource_id".into(), json!(resource));
    let (amount, currency) = manifest_price(policy);
    if let Some(amount) = amount {
        intent.insert("amount".into(), json!(amount));
    }
    if let Some(currency) = currency {
        intent.insert("currency".into(), json!(currency));
    }
    context.insert("intent".into(), Value::Object(intent));
    let mut correlation = Map::new();
    if let Some(key) = idempotency_key {
        correlation.insert("idempotency_key".into(), json!(key));
    }
    correlation.insert("thid".into(), json!(thid));
    correlation.insert("trace_context".into(), json!(trace_context));
    context.insert("correlation".into(), Value::Object(correlation));
    Value::Object(context)
}

/// What is sent to agent-pay for one chargeable request.
#[derive(Clone, Debug)]
pub(crate) struct GateWireRequest {
    pub fabric_target: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Value,
    pub payment_context: Value,
    pub timeout: Duration,
    pub trace_id: String,
}

/// Request headers sent to agent-pay: the credential header with the exact
/// casing agent-pay matches, plus `content-type`, `traceparent` and
/// `x-request-id`. Cookies, the caller's source-auth credential and every
/// other header stay behind.
fn gate_headers(
    credential: Option<&Credential>,
    request_id: Option<&str>,
    traceparent: &str,
) -> HashMap<String, String> {
    let mut headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("traceparent".to_string(), traceparent.to_string()),
    ]);
    if let Some(request_id) = request_id {
        headers.insert("x-request-id".to_string(), request_id.to_string());
    }
    if let Some(credential) = credential {
        let (name, value) = credential.wire_header();
        headers.insert(name, value);
    }
    headers
}

/// Sends a payment request to agent-pay.
pub(crate) trait GateTransport: Send + Sync {
    fn send(
        &self,
        request: GateWireRequest,
    ) -> futures::future::BoxFuture<'_, Result<FabricForwardResponse, FabricForwardError>>;

    /// The DID of the payment gateway, for the audit trail.
    fn gateway_did<'a>(
        &'a self,
        gateway_id: &'a str,
    ) -> futures::future::BoxFuture<'a, Option<String>>;
}

/// The production transport: a `forward-request` over the fabric.
pub(crate) struct FabricTransport(
    pub Arc<tokio::sync::RwLock<Option<Arc<crate::gateways::ConnectionPointListenerManager>>>>,
);

impl GateTransport for FabricTransport {
    fn send(
        &self,
        request: GateWireRequest,
    ) -> futures::future::BoxFuture<'_, Result<FabricForwardResponse, FabricForwardError>> {
        Box::pin(async move {
            let body = serde_json::to_vec(&request.body).unwrap_or_default();
            let mut extra_body = Map::new();
            extra_body.insert("payment_context".into(), request.payment_context);
            crate::proxy::fabric_forward::forward_via_fabric(
                &self.0,
                crate::proxy::fabric_forward::FabricForwardRequest {
                    fabric_target: &request.fabric_target,
                    method: &axum::http::Method::POST,
                    path: &request.path,
                    headers: request.headers,
                    body: body.into(),
                    timeout: request.timeout,
                    trace_id: &request.trace_id,
                    log_label: "payment-gate",
                    extra_body: Some(extra_body),
                },
            )
            .await
        })
    }

    fn gateway_did<'a>(
        &'a self,
        gateway_id: &'a str,
    ) -> futures::future::BoxFuture<'a, Option<String>> {
        Box::pin(async move {
            let manager = self.0.read().await.clone()?;
            manager
                .get_gateway_did(gateway_id)
                .await
        })
    }
}

#[cfg(test)]
static TEST_TRANSPORTS: LazyLock<Mutex<HashMap<String, Arc<dyn GateTransport>>>> = LazyLock::new(Default::default);

/// Routes this process's payment requests for `gateway_id` to `transport`.
#[cfg(test)]
pub(crate) fn install_test_transport(
    gateway_id: &str,
    transport: Arc<dyn GateTransport>,
) {
    TEST_TRANSPORTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(gateway_id.to_string(), transport);
}

fn transport_for(
    gateway_id: &str,
    fabric: &Arc<tokio::sync::RwLock<Option<Arc<crate::gateways::ConnectionPointListenerManager>>>>,
) -> Arc<dyn GateTransport> {
    #[cfg(test)]
    if let Some(transport) = TEST_TRANSPORTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(gateway_id)
    {
        return transport.clone();
    }
    let _ = gateway_id;
    Arc::new(FabricTransport(fabric.clone()))
}

#[derive(Default)]
struct BreakerState {
    consecutive_failures: u32,
    open_until: Option<Instant>,
    /// Until when the one call let through after the breaker opened holds it.
    probe_until: Option<Instant>,
}

/// When a payment gateway's breaker opens and for how long, from
/// `payment_gate` in `gateway.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BreakerSettings {
    failures: u32,
    open_for: Duration,
}

static BREAKER_SETTINGS: std::sync::RwLock<BreakerSettings> = std::sync::RwLock::new(BreakerSettings {
    failures: DEFAULT_BREAKER_FAILURES,
    open_for: DEFAULT_BREAKER_OPEN_FOR,
});

fn breaker_settings() -> BreakerSettings {
    *BREAKER_SETTINGS
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Restores the payments this node dispatched a request for from the journal
/// in `dir` and records later dispatches there; returns how many it restored.
pub(crate) fn open_claim_journal(dir: &std::path::Path) -> std::io::Result<usize> {
    consumed::open_journal(dir)
}

/// Sets the breaker thresholds every payment gateway's breaker uses.
pub(crate) fn configure_breaker(config: &crate::config::types::PaymentGateConfig) {
    *BREAKER_SETTINGS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = BreakerSettings {
        failures: config.breaker_failures(),
        open_for: config.breaker_open_for(),
    };
}

/// One circuit breaker per payment gateway: after `breaker_failures`
/// consecutive transport failures it opens for `breaker_open_secs`, answering
/// at once instead of waiting for a timeout.
/// Once that time has passed exactly one call at a time is let through to find
/// out whether the gateway is back, and the others stay refused until it
/// answers: a success closes the breaker, a failure opens it again, and a wait
/// cut short by the caller's deadline gives the next call the probe.
///
/// It is not `crate::policies::CircuitBreaker`: that one records only the
/// success or failure of the call it wraps, but a wait cut short by a caller's
/// own deadline says nothing about agent-pay and must neither open the breaker
/// nor reset its count, and the gate checks the breaker before a call and
/// records after it.
static BREAKERS: LazyLock<Mutex<HashMap<String, BreakerState>>> = LazyLock::new(Default::default);

fn breakers() -> std::sync::MutexGuard<'static, HashMap<String, BreakerState>> {
    BREAKERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// `Ok` when a call to `gateway_id` may be made now, and the seconds to wait
/// when the breaker refuses it. A call let through once the open time has
/// passed is the probe.
fn breaker_admit(
    gateway_id: &str,
    now: Instant,
) -> Result<(), u64> {
    let mut breakers = breakers();
    let Some(state) = breakers.get_mut(gateway_id) else {
        return Ok(());
    };
    let Some(open_until) = state.open_until else {
        return Ok(());
    };
    let remaining = |until: Instant| {
        until
            .checked_duration_since(now)
            .filter(|remaining| !remaining.is_zero())
    };
    if let Some(open_for) = remaining(open_until) {
        return Err(open_for.as_secs().max(1));
    }
    if state
        .probe_until
        .and_then(remaining)
        .is_some()
    {
        return Err(1);
    }
    state.probe_until = Some(now + breaker_settings().open_for);
    Ok(())
}

/// Where one payment gateway's circuit breaker stands, as the admin API shows it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct BreakerSnapshot {
    /// `closed`, `open` (calls are refused), or `half_open` (the open time has
    /// passed and the next call, or the one already let through, decides).
    pub state: &'static str,
    pub consecutive_failures: u32,
    /// Seconds until an open breaker lets a call through again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,
    /// Consecutive failures that open it.
    pub failures_to_open: u32,
    pub open_secs: u64,
}

/// The breaker of `gateway_id` at `now`; `closed` for a gateway never called or
/// whose last call answered.
pub(crate) fn breaker_snapshot(
    gateway_id: &str,
    now: Instant,
) -> BreakerSnapshot {
    let settings = breaker_settings();
    let breakers = breakers();
    let state = breakers.get(gateway_id);
    let consecutive_failures = state.map_or(0, |state| state.consecutive_failures);
    let (state, retry_after_secs) = match state.and_then(|state| state.open_until) {
        None => ("closed", None),
        Some(open_until) => match open_until
            .checked_duration_since(now)
            .filter(|remaining| !remaining.is_zero())
        {
            Some(remaining) => ("open", Some(remaining.as_secs().max(1))),
            None => ("half_open", None),
        },
    };
    BreakerSnapshot {
        state,
        consecutive_failures,
        retry_after_secs,
        failures_to_open: settings.failures,
        open_secs: settings.open_for.as_secs(),
    }
}

/// What a call to the payment gateway says about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransportOutcome {
    /// The gateway answered.
    Reached,
    /// The gateway did not answer within the gate's own timeout, or the
    /// transport failed.
    Failed,
    /// The wait was cut short by the caller's deadline, so the gateway's
    /// silence proves nothing.
    Inconclusive,
}

fn record_transport_result(
    gateway_id: &str,
    outcome: TransportOutcome,
    now: Instant,
) {
    let mut breakers = breakers();
    match outcome {
        TransportOutcome::Inconclusive => {
            if let Some(state) = breakers.get_mut(gateway_id) {
                state.probe_until = None;
            }
        }
        TransportOutcome::Reached => {
            if breakers
                .remove(gateway_id)
                .is_some_and(|state| state.open_until.is_some())
            {
                tracing::info!(payment_gateway_id = %gateway_id, "Payment gate circuit breaker closed");
                crate::metrics::backends::prometheus::track_payment_gate_breaker(gateway_id, "closed");
            }
        }
        TransportOutcome::Failed => {
            let settings = breaker_settings();
            let state = breakers
                .entry(gateway_id.to_string())
                .or_default();
            state.consecutive_failures = state
                .consecutive_failures
                .saturating_add(1);
            state.probe_until = None;
            if state.consecutive_failures >= settings.failures {
                if state.open_until.is_none() {
                    tracing::warn!(
                        payment_gateway_id = %gateway_id,
                        failures = state.consecutive_failures,
                        open_for_secs = settings.open_for.as_secs(),
                        "Payment gate circuit breaker opened"
                    );
                    crate::metrics::backends::prometheus::track_payment_gate_breaker(gateway_id, "open");
                }
                state.open_until = Some(now + settings.open_for);
            }
        }
    }
}

/// A receipt for a paid request.
#[derive(Clone, Debug)]
pub(crate) struct Receipt {
    rail: Rail,
    value: String,
    vc_fingerprint: Option<String>,
    /// The `cache-control` agent-pay set on its paid answer, relayed so a
    /// shared cache does not keep the paid response.
    cache_control: Option<String>,
    /// The claim on the payment's idempotency key, released when the last copy
    /// of the receipt drops before [`Self::commit`].
    claim: Option<Arc<consumed::Claim>>,
    /// Funds agent-pay holds until the Target delivers, captured or voided by
    /// [`Self::settled`] and voided when the last copy drops unsettled.
    authorization: Option<Arc<Authorization>>,
}

/// Funds agent-pay holds for one request: captured once, when the Target
/// delivered, and voided otherwise. The first decision is final, and the
/// capture or void runs as its own task so a caller that goes away cannot
/// cancel it half sent.
#[derive(Debug)]
pub(crate) struct Authorization {
    held: crate::payments_ledger::settlement::HeldPayment,
    /// The authorization receipt continuation evidence carries.
    evidence: String,
    decision: std::sync::OnceLock<crate::payments_ledger::SettleAction>,
    settled: Arc<tokio::sync::OnceCell<crate::payments_ledger::settlement::Settled>>,
    in_flight: Arc<crate::payments_ledger::settlement::InFlight>,
}

impl Authorization {
    fn new(
        held: crate::payments_ledger::settlement::HeldPayment,
        evidence: String,
    ) -> Self {
        Self {
            in_flight: Arc::new(crate::payments_ledger::settlement::InFlight::track(&held.row_id)),
            held,
            evidence,
            decision: std::sync::OnceLock::new(),
            settled: Arc::default(),
        }
    }

    /// Takes the decision, or returns the one already taken.
    fn decide(
        &self,
        delivered: bool,
    ) -> crate::payments_ledger::SettleAction {
        use crate::payments_ledger::SettleAction;

        let action = *self.decision.get_or_init(|| {
            if delivered {
                SettleAction::Capture
            } else {
                SettleAction::Void
            }
        });
        if action == SettleAction::Void {
            void_evidence(&self.evidence);
        }
        action
    }

    fn spawn_settle(
        &self,
        runtime: &tokio::runtime::Handle,
        action: crate::payments_ledger::SettleAction,
    ) -> tokio::task::JoinHandle<crate::payments_ledger::settlement::Settled> {
        let held = self.held.clone();
        let evidence = self.evidence.clone();
        let settled = Arc::clone(&self.settled);
        let in_flight = Arc::clone(&self.in_flight);
        runtime.spawn(async move {
            let _in_flight = in_flight;
            settled
                .get_or_init(|| async {
                    let reason = (action == crate::payments_ledger::SettleAction::Void).then_some(NOT_DELIVERED);
                    let settled = crate::payments_ledger::settlement::settle(&held, action, reason).await;
                    if settled.outcome == crate::payments_ledger::LedgerOutcome::Voided {
                        void_evidence(&evidence);
                    }
                    settled
                })
                .await
                .clone()
        })
    }

    /// Settles by the decision (taken now when none was) and returns it with
    /// what came of it.
    async fn settle(
        &self,
        delivered: bool,
    ) -> (crate::payments_ledger::SettleAction, crate::payments_ledger::settlement::Settled) {
        let action = self.decide(delivered);
        let settled = self
            .spawn_settle(&tokio::runtime::Handle::current(), action)
            .await
            .unwrap_or(crate::payments_ledger::settlement::Settled {
                outcome: crate::payments_ledger::LedgerOutcome::Authorized,
                receipt: None,
            });
        (action, settled)
    }
}

/// How long the receipt of a voided authorization is remembered: the longest an
/// MCP continuation can carry it.
const VOIDED_EVIDENCE_KEPT: Duration = Duration::from_secs(crate::mcp::continuations::MAX_TTL_SECS);

/// Receipts of voided authorizations, by digest, so continuation evidence
/// recorded from one before the void pays for no later round.
static VOIDED_EVIDENCE: LazyLock<Mutex<HashMap<[u8; 32], Instant>>> = LazyLock::new(Default::default);

fn evidence_digest(receipt: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    Sha256::digest(receipt.as_bytes()).into()
}

fn void_evidence(receipt: &str) {
    let now = Instant::now();
    let mut voided = VOIDED_EVIDENCE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    voided.retain(|_, expires| *expires > now);
    voided.insert(evidence_digest(receipt), now + VOIDED_EVIDENCE_KEPT);
}

fn evidence_voided(receipt: &str) -> bool {
    VOIDED_EVIDENCE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&evidence_digest(receipt))
        .is_some_and(|expires| *expires > Instant::now())
}

impl Drop for Authorization {
    fn drop(&mut self) {
        if self.decision.get().is_some() {
            return;
        }
        let action = self.decide(false);
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                self.spawn_settle(&runtime, action);
            }
            Err(_) => tracing::warn!(
                row_id = %self.held.row_id,
                "A held payment was dropped outside a runtime; the reconciler voids it"
            ),
        }
    }
}

/// Funds agent-pay's answer says it holds rather than captured.
#[derive(Clone, Debug, PartialEq, Eq)]
struct HeldFunds {
    authorization_id: String,
    capture_deadline: chrono::DateTime<chrono::Utc>,
}

/// The held funds a paid answer names, `None` for a payment already captured,
/// or why the authorization is unusable.
fn held_funds(headers: &HashMap<String, Vec<String>>) -> Result<Option<HeldFunds>, PaymentDelegationDecision> {
    let Some(authorization_id) = first_header(headers, AUTHORIZATION_HEADER) else {
        return Ok(None);
    };
    let usable = !authorization_id.is_empty()
        && authorization_id.len() <= MAX_AUTHORIZATION_CHARS
        && authorization_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'));
    if !usable {
        return Err(PaymentDelegationDecision::unconfirmed(
            502,
            "payment gateway answered with an unusable payment authorization",
        ));
    }
    let capture_deadline = first_header(headers, CAPTURE_DEADLINE_HEADER)
        .and_then(|deadline| chrono::DateTime::parse_from_rfc3339(deadline).ok())
        .map(|deadline| deadline.with_timezone(&chrono::Utc))
        .unwrap_or_else(|| chrono::Utc::now() + DEFAULT_CAPTURE_WINDOW);
    let now = chrono::Utc::now();
    let capture_deadline = capture_deadline.clamp(now + MIN_CAPTURE_WINDOW, now + MAX_CAPTURE_WINDOW);
    Ok(Some(HeldFunds {
        authorization_id: authorization_id.to_string(),
        capture_deadline,
    }))
}

/// Whether a Target's answer is one the caller receives as success: a `2xx`
/// and, for a JSON-RPC protocol, a body (when it was read) with no error
/// message.
pub(crate) fn delivered(
    protocol: &ChannelProtocol,
    status: StatusCode,
    body: Option<&[u8]>,
) -> bool {
    if !status.is_success() {
        return false;
    }
    if !matches!(protocol, ChannelProtocol::Mcp | ChannelProtocol::A2a | ChannelProtocol::Ap2) {
        return true;
    }
    let Some(body) = body else {
        return true;
    };
    let is_error = |message: &Value| {
        message
            .get("error")
            .is_some_and(|error| !error.is_null())
    };
    let messages: Vec<Value> = match serde_json::from_slice::<Value>(body) {
        Ok(Value::Array(batch)) => batch,
        Ok(message) => vec![message],
        Err(_) => std::str::from_utf8(body)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .filter_map(|data| serde_json::from_str(data.trim_start()).ok())
            .collect(),
    };
    !messages.iter().any(is_error)
}

impl PartialEq for Receipt {
    fn eq(
        &self,
        other: &Self,
    ) -> bool {
        (&self.rail, &self.value, &self.vc_fingerprint, &self.cache_control)
            == (&other.rail, &other.value, &other.vc_fingerprint, &other.cache_control)
    }
}

impl Eq for Receipt {}

impl Receipt {
    /// Records that the request this receipt paid for is being dispatched, so
    /// the credential cannot pay for another. Until then a request that fails
    /// or is cancelled gives the credential back, and the client can retry it
    /// within agent-pay's replay window.
    pub(crate) fn commit(&self) {
        if let Some(claim) = &self.claim {
            claim.commit();
        }
    }

    /// Gives the credential back after [`Self::commit`] when the request failed
    /// before it reached its Target (an open circuit breaker, a refused
    /// connection, a failed send), so the client can retry it within agent-pay's
    /// replay window instead of paying again.
    pub(crate) fn revoke(&self) {
        if let Some(claim) = &self.claim {
            claim.revoke();
        }
    }

    fn header_value(value: &str) -> Option<String> {
        (!value.is_empty() && value.len() <= MAX_CREDENTIAL_BYTES && HeaderValue::from_str(value).is_ok())
            .then(|| value.to_string())
    }

    /// The headers a paid response carries: `PAYMENT-RESPONSE` for an x402
    /// credential, `Payment-Receipt` for MPP, and the gate's `cache-control`.
    pub(crate) fn headers(&self) -> Vec<(HeaderName, HeaderValue)> {
        let mut headers = vec![(
            self.rail.receipt_header(),
            HeaderValue::from_str(&self.value).unwrap_or_else(|_| HeaderValue::from_static("")),
        )];
        if let Some(cache_control) = self
            .cache_control
            .as_deref()
            .and_then(|value| HeaderValue::from_str(value).ok())
        {
            headers.push((axum::http::header::CACHE_CONTROL, cache_control));
        }
        headers
    }

    pub(crate) fn apply(
        &self,
        headers: &mut HeaderMap,
    ) {
        for (name, value) in self.headers() {
            headers.insert(name, value);
        }
    }

    /// The receipt as continuation evidence, so a later round is not charged.
    pub(crate) fn continuation_evidence(&self) -> impl FnOnce(u64, u64) -> ContinuationPayment + '_ {
        move |verified_at, expires_at| ContinuationPayment::AgentPay {
            scheme: self.rail.as_str().to_string(),
            receipt: Some(self.value.clone()),
            vc_fingerprint: self.vc_fingerprint.clone(),
            verified_at,
            expires_at,
        }
    }

    /// Adds the receipt to one JSON-RPC message: MCP `result._meta`, A2A
    /// `metadata` of the message or task the result is (A2A 0.3), or of the
    /// message, task or event a 1.0 result wraps. `false` when the message is
    /// not a JSON-RPC result.
    pub(crate) fn inject_into_message(
        &self,
        protocol: &ChannelProtocol,
        message: &mut Value,
    ) -> bool {
        let field = match protocol {
            ChannelProtocol::Mcp => "_meta",
            ChannelProtocol::A2a | ChannelProtocol::Ap2 => "metadata",
            _ => return false,
        };
        let Some(result) = message
            .get_mut("result")
            .and_then(Value::as_object_mut)
        else {
            return false;
        };
        let holder = match protocol {
            ChannelProtocol::Mcp => result,
            _ => {
                let wrapped = A2A_RESULT_WRAPPERS
                    .into_iter()
                    .find(|key| {
                        result
                            .get(*key)
                            .is_some_and(Value::is_object)
                    });
                match wrapped {
                    Some(key) => {
                        let Some(inner) = result
                            .get_mut(key)
                            .and_then(Value::as_object_mut)
                        else {
                            return false;
                        };
                        inner
                    }
                    None => result,
                }
            }
        };
        let Some(container) = holder
            .entry(field)
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
        else {
            return false;
        };
        container.insert(RECEIPT_META.into(), json!(self.value));
        true
    }

    /// Adds the receipt to a JSON-RPC response body. `None` when the body is not
    /// a JSON-RPC result.
    pub(crate) fn inject_into_json(
        &self,
        protocol: &ChannelProtocol,
        body: &[u8],
    ) -> Option<Vec<u8>> {
        let mut message: Value = serde_json::from_slice(body).ok()?;
        self.inject_into_message(protocol, &mut message)
            .then(|| serde_json::to_vec(&message).ok())
            .flatten()
    }

    /// Adds the receipt to the JSON-RPC results in the `data:` lines of a
    /// buffered event stream. `None` when none carries a result.
    fn inject_into_events(
        &self,
        protocol: &ChannelProtocol,
        events: &str,
    ) -> Option<String> {
        let mut injected = String::with_capacity(events.len() + 128);
        let mut changed = false;
        for (index, line) in events.split('\n').enumerate() {
            if index > 0 {
                injected.push('\n');
            }
            if let Some(data) = line.strip_prefix("data:")
                && let Ok(mut message) = serde_json::from_str::<Value>(data.trim_start())
                && self.inject_into_message(protocol, &mut message)
                && let Ok(encoded) = serde_json::to_string(&message)
            {
                injected.push_str("data: ");
                injected.push_str(&encoded);
                changed = true;
            } else {
                injected.push_str(line);
            }
        }
        changed.then_some(injected)
    }

    /// Adds the receipt to a response: its headers always, and the JSON-RPC
    /// receipt when the body is buffered JSON, or buffered events, of a known
    /// size. A streamed body carries the headers only.
    pub(crate) async fn attach(
        &self,
        protocol: &ChannelProtocol,
        response: Response,
    ) -> Response {
        use axum::body::HttpBody as _;

        let (mut parts, body) = response.into_parts();
        self.apply(&mut parts.headers);
        let content_type = parts
            .headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let is_json = content_type.starts_with("application/json");
        let is_events = content_type.starts_with("text/event-stream");
        let size = body.size_hint().exact();
        if !(is_json || is_events) || size.is_none_or(|size| size as usize > MAX_RECEIPT_BODY_BYTES) {
            return Response::from_parts(parts, body);
        }
        let Ok(bytes) = axum::body::to_bytes(body, MAX_RECEIPT_BODY_BYTES).await else {
            return crate::a2a::create_error_response(StatusCode::BAD_GATEWAY, "Failed to read upstream response");
        };
        let injected = if is_json {
            self.inject_into_json(protocol, &bytes)
        } else {
            std::str::from_utf8(&bytes)
                .ok()
                .and_then(|events| self.inject_into_events(protocol, events))
                .map(String::into_bytes)
        };
        let bytes = match injected {
            Some(injected) => {
                parts
                    .headers
                    .remove(axum::http::header::CONTENT_LENGTH);
                Bytes::from(injected)
            }
            None => bytes,
        };
        Response::from_parts(parts, axum::body::Body::from(bytes))
    }

    /// Captures held funds when the Target `delivered` and voids them otherwise,
    /// and returns the receipt the response carries: the capture's, or this one
    /// when nothing was held or the capture did not answer with one. `None` when
    /// the caller was not charged.
    pub(crate) async fn settled(
        &self,
        delivered: bool,
    ) -> Option<Receipt> {
        use crate::payments_ledger::LedgerOutcome;

        let Some(authorization) = &self.authorization else {
            return Some(self.clone());
        };
        let (action, settled) = authorization
            .settle(delivered)
            .await;
        if action == crate::payments_ledger::SettleAction::Void || settled.outcome == LedgerOutcome::Voided {
            return None;
        }
        let mut receipt = self.clone();
        if let Some(value) = settled
            .receipt
            .as_deref()
            .and_then(Self::header_value)
        {
            receipt.value = value;
        }
        Some(receipt)
    }

    /// Settles held funds by what a Target answered and adds the receipt to the
    /// answer. A buffered body is judged before it is returned and carries the
    /// capture receipt. A successful streamed body is returned at once, with the
    /// authorization receipt in its headers and messages; it is captured when the
    /// stream completes without a JSON-RPC error event, voided when the upstream
    /// stream fails or the client goes away first, and an event stream ends with
    /// a `payment-receipt` event carrying the capture receipt.
    pub(crate) async fn settle_response(
        &self,
        protocol: &ChannelProtocol,
        response: Response,
    ) -> Response {
        use axum::body::HttpBody as _;

        let Some(authorization) = &self.authorization else {
            return self
                .attach(protocol, response)
                .await;
        };
        if response.status().is_success()
            && response
                .body()
                .size_hint()
                .exact()
                .is_none()
        {
            return streamed::settle_when_streamed(self, Arc::clone(authorization), protocol, response);
        }
        let (response, delivered) = Self::judged(protocol, response).await;
        match self.settled(delivered).await {
            Some(receipt) => {
                receipt
                    .attach(protocol, response)
                    .await
            }
            None => response,
        }
    }

    /// Reads a buffered JSON or event-stream body of a known size, so whether
    /// the Target delivered can be told from it as well as from its status.
    async fn judged(
        protocol: &ChannelProtocol,
        response: Response,
    ) -> (Response, bool) {
        use axum::body::HttpBody as _;

        let (parts, body) = response.into_parts();
        let content_type = parts
            .headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let readable = content_type.starts_with("application/json") || content_type.starts_with("text/event-stream");
        let size = body.size_hint().exact();
        if !readable || size.is_none_or(|size| size as usize > MAX_RECEIPT_BODY_BYTES) {
            let delivered = delivered(protocol, parts.status, None);
            return (Response::from_parts(parts, body), delivered);
        }
        match axum::body::to_bytes(body, MAX_RECEIPT_BODY_BYTES).await {
            Ok(bytes) => {
                let delivered = delivered(protocol, parts.status, Some(&bytes));
                (Response::from_parts(parts, axum::body::Body::from(bytes)), delivered)
            }
            Err(_) => {
                (crate::a2a::create_error_response(StatusCode::BAD_GATEWAY, "Failed to read upstream response"), false)
            }
        }
    }

    /// [`Self::attach`] to either side of a handler's result, so a request that
    /// was paid for and then failed still carries its receipt. Held funds are
    /// captured or voided first, by what the Target answered.
    pub(crate) async fn attach_to_result(
        &self,
        protocol: &ChannelProtocol,
        result: Result<Response, Response>,
    ) -> Result<Response, Response> {
        if self.authorization.is_some() {
            return match result {
                Ok(response) => Ok(self
                    .settle_response(protocol, response)
                    .await),
                Err(response) => {
                    self.settled(false).await;
                    Err(response)
                }
            };
        }
        match result {
            Ok(response) => Ok(self
                .attach(protocol, response)
                .await),
            Err(response) => Err(self
                .attach(protocol, response)
                .await),
        }
    }
}

/// A request agent-pay was paid for.
#[derive(Debug)]
pub(crate) struct Paid {
    pub receipt: Receipt,
}

/// The gate's verdict on one request.
#[derive(Debug)]
pub(crate) enum GateOutcome {
    /// Not chargeable: no fabric hop was made.
    Free,
    Paid(Paid),
    /// The caller's response: a challenge, a hold or a refusal.
    Refused(Response),
}

/// The circumstances of one call to the gate.
pub(crate) struct GateCall<'a> {
    pub surface: &'a AgentSurface,
    pub caller: Caller<'a>,
    /// This gateway's own trace id, which its audit trail, ledger and
    /// credentials record.
    pub trace_id: &'a str,
    /// The trace id of the outbound leg: all the payment gateway sees.
    pub egress_trace_id: &'a str,
    /// The caller's deadline, epoch milliseconds.
    pub deadline_ms: Option<u64>,
    pub evidence: Option<&'a ContinuationPayment>,
    pub fabric: &'a Arc<tokio::sync::RwLock<Option<Arc<crate::gateways::ConnectionPointListenerManager>>>>,
    pub via_fabric: bool,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// Rejects a response too large to be a payment gate's answer.
fn oversized(response: &FabricForwardResponse) -> bool {
    let header_bytes: usize = response
        .headers
        .iter()
        .map(|(name, values)| {
            name.len()
                + values
                    .iter()
                    .map(String::len)
                    .sum::<usize>()
        })
        .sum();
    response.body.len() > MAX_RESPONSE_BODY_BYTES || header_bytes > MAX_RESPONSE_HEADER_BYTES
}

fn first_header<'h>(
    headers: &'h HashMap<String, Vec<String>>,
    name: &str,
) -> Option<&'h str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .and_then(|(_, values)| values.first())
        .map(String::as_str)
}

/// The receipt in a paid answer, or why it is unusable.
fn paid_receipt(
    receipt_headers: &HashMap<String, Vec<String>>,
    rail: Rail,
) -> Result<Receipt, PaymentDelegationDecision> {
    let value = first_header(receipt_headers, "payment-receipt")
        .and_then(Receipt::header_value)
        .ok_or_else(|| {
            PaymentDelegationDecision::unconfirmed(502, "payment gateway answered without a usable receipt")
        })?;
    let vc_fingerprint = first_header(receipt_headers, RECEIPT_VC_FINGERPRINT_HEADER)
        .filter(|value| value.len() <= 256)
        .and_then(Receipt::header_value);
    let cache_control = first_header(receipt_headers, "cache-control")
        .filter(|value| value.len() <= 256)
        .and_then(Receipt::header_value);
    Ok(Receipt {
        rail,
        value,
        vc_fingerprint,
        cache_control,
        claim: None,
        authorization: None,
    })
}

/// Fields read from a receipt for the audit trail: an MPP receipt's
/// `reference` / `challengeId` / `method`, or an x402 settlement's transaction
/// hash and network. Receipts are base64 or base64url JSON.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ReceiptFacts {
    pub reference: Option<String>,
    pub challenge_id: Option<String>,
    pub method: Option<String>,
    pub network: Option<String>,
    /// The amount and currency the receipt says were charged.
    pub amount: Option<String>,
    pub currency: Option<String>,
    /// How many decimal places `amount` is in base units of, when the receipt says.
    pub decimals: Option<u32>,
}

pub(crate) fn receipt_facts(receipt: &str) -> ReceiptFacts {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};

    let decoded = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| {
            engine
                .decode(receipt.trim())
                .ok()
        })
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let Some(json) = decoded else {
        return ReceiptFacts::default();
    };
    let text = |names: &[&str]| {
        names
            .iter()
            .find_map(|name| json.get(*name)?.as_str())
            .filter(|value| !value.is_empty())
            .map(|value| clip(value, MAX_RESOURCE_CHARS))
    };
    ReceiptFacts {
        reference: text(&["reference", "transaction", "txHash", "tx_hash"]),
        challenge_id: text(&["challengeId", "challenge_id"]),
        method: text(&["method", "scheme"]),
        network: text(&["network"]),
        amount: json
            .get("amount")
            .and_then(|amount| match amount {
                Value::String(amount) => Some(amount.clone()),
                Value::Number(amount) => Some(amount.to_string()),
                _ => None,
            })
            .filter(|amount| !amount.is_empty() && amount.len() <= 64),
        currency: text(&["currency"]),
        decimals: json
            .get("decimals")
            .and_then(Value::as_u64)
            .and_then(|decimals| u32::try_from(decimals).ok())
            .filter(|decimals| *decimals <= MAX_DECIMALS),
    }
}

/// The ledger and metric outcome of a decision.
fn outcome_label(decision: &PaymentDelegationDecision) -> crate::payments_ledger::LedgerOutcome {
    use crate::payments_ledger::LedgerOutcome;

    match decision {
        PaymentDelegationDecision::Proceed { .. } => LedgerOutcome::Paid,
        PaymentDelegationDecision::Challenge { .. } => LedgerOutcome::Challenge,
        PaymentDelegationDecision::Held { .. } => LedgerOutcome::Held,
        PaymentDelegationDecision::VerificationFailed { .. } | PaymentDelegationDecision::Rejected { .. } => {
            LedgerOutcome::Rejected
        }
        PaymentDelegationDecision::Unconfirmed { .. } | PaymentDelegationDecision::InProgress { .. } => {
            LedgerOutcome::Unconfirmed
        }
        PaymentDelegationDecision::RateLimited { .. } | PaymentDelegationDecision::Deny { .. } => {
            LedgerOutcome::Unavailable
        }
    }
}

fn outcome_str(outcome: crate::payments_ledger::LedgerOutcome) -> &'static str {
    outcome.as_str()
}

fn json_response(
    status: StatusCode,
    body: &Value,
    headers: &[(HeaderName, HeaderValue)],
) -> Response {
    let mut response = (status, axum::Json(body)).into_response();
    for (name, value) in headers {
        response
            .headers_mut()
            .append(name.clone(), value.clone());
    }
    response
        .headers_mut()
        .insert(axum::http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn header_pairs(headers: &HashMap<String, Vec<String>>) -> Vec<(HeaderName, HeaderValue)> {
    headers
        .iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case("cache-control") && !name.eq_ignore_ascii_case("content-type"))
        .flat_map(|(name, values)| {
            values
                .iter()
                .filter_map(move |value| {
                    Some((HeaderName::from_bytes(name.as_bytes()).ok()?, HeaderValue::from_str(value).ok()?))
                })
        })
        .collect()
}

/// MPP challenges parsed from `WWW-Authenticate: Payment` values, in the
/// object form the MCP payment transport carries.
fn mpp_challenges(headers: &HashMap<String, Vec<String>>) -> Vec<Value> {
    let mut map = reqwest::header::HeaderMap::new();
    for (name, values) in headers {
        if name.eq_ignore_ascii_case("www-authenticate") {
            for value in values {
                if let Ok(value) = reqwest::header::HeaderValue::from_str(value) {
                    map.append(reqwest::header::WWW_AUTHENTICATE, value);
                }
            }
        }
    }
    crate::mpp::payment_challenge::parse_www_authenticate_headers(&map)
        .into_iter()
        .map(|challenge| {
            let mut object = json!({
                "id": challenge.id, "realm": challenge.realm, "method": challenge.method,
                "intent": challenge.intent, "request": challenge.request,
            });
            for (name, value) in [
                ("expires", challenge.expires),
                ("digest", challenge.digest),
                ("description", challenge.description),
                ("opaque", challenge.opaque),
            ] {
                if let Some(value) = value {
                    object[name] = json!(value);
                }
            }
            object
        })
        .collect()
}

/// The challenges a JSON-RPC caller pays against: `data.challenges` for MPP,
/// and the x402 requirements as `data.x402` when the gate offered x402.
fn challenge_data(
    headers: &HashMap<String, Vec<String>>,
    body: &[u8],
) -> Value {
    let mut data = json!({"httpStatus": 402, "challenges": mpp_challenges(headers)});
    if first_header(headers, "payment-required").is_some()
        && let Ok(x402) = serde_json::from_slice::<Value>(body)
    {
        data["x402"] = x402;
    }
    data
}

fn retry_after_header(retry_after: Option<&str>) -> Vec<(HeaderName, HeaderValue)> {
    retry_after
        .and_then(|value| HeaderValue::from_str(value).ok())
        .map(|value| vec![(axum::http::header::RETRY_AFTER, value)])
        .unwrap_or_default()
}

/// The caller's response for a decision that is not `Proceed`.
fn render(
    decision: &PaymentDelegationDecision,
    shape: &Shape,
) -> Response {
    use crate::mcp::errors::{application_error_codes, error_codes, payment_transport_error_codes};

    let jsonrpc = |status: StatusCode, code: i32, message: &str, data: Value, headers: &[(HeaderName, HeaderValue)]| {
        let id = match shape {
            Shape::JsonRpc { id, .. } => id.clone(),
            Shape::Http => None,
        };
        json_response(status, &crate::mcp::errors::create_mcp_error_envelope(id, code, message, Some(data)), headers)
    };
    let is_jsonrpc = matches!(shape, Shape::JsonRpc { .. });
    let legacy = matches!(shape, Shape::JsonRpc { legacy_mcp: true, .. });
    let (required, rejected) = if legacy {
        (
            (payment_transport_error_codes::PAYMENT_REQUIRED, "Payment Required"),
            (payment_transport_error_codes::PAYMENT_VERIFICATION_FAILED, "Payment Verification Failed"),
        )
    } else {
        (
            (application_error_codes::PAYMENT_REQUIRED, "Payment required"),
            (application_error_codes::PAYMENT_REJECTED, "Payment rejected"),
        )
    };
    match decision {
        PaymentDelegationDecision::Proceed { .. } => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        PaymentDelegationDecision::Challenge { headers, body, .. } => {
            let relayed = header_pairs(headers);
            if is_jsonrpc {
                return jsonrpc(
                    StatusCode::PAYMENT_REQUIRED,
                    required.0,
                    required.1,
                    challenge_data(headers, body),
                    &relayed,
                );
            }
            let mut response = Response::new(axum::body::Body::from(body.clone()));
            *response.status_mut() = StatusCode::PAYMENT_REQUIRED;
            let content_type = first_header(headers, "content-type")
                .and_then(|value| HeaderValue::from_str(value).ok())
                .unwrap_or(HeaderValue::from_static("application/json"));
            let response_headers = response.headers_mut();
            response_headers.insert(axum::http::header::CONTENT_TYPE, content_type);
            response_headers.insert(axum::http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            for (name, value) in relayed {
                response_headers.append(name, value);
            }
            response
        }
        PaymentDelegationDecision::VerificationFailed { headers, body, reason, detail } => {
            let relayed = header_pairs(headers);
            if is_jsonrpc {
                let mut data = challenge_data(headers, body);
                data["failure"] = json!({"reason": reason, "detail": detail});
                return jsonrpc(StatusCode::PAYMENT_REQUIRED, rejected.0, rejected.1, data, &relayed);
            }
            let mut body = serde_json::from_slice::<Value>(body)
                .ok()
                .filter(Value::is_object)
                .unwrap_or_else(|| json!({"error": reason, "detail": detail}));
            if reason == ALREADY_USED {
                body["error"] = json!(reason);
            }
            json_response(StatusCode::PAYMENT_REQUIRED, &body, &relayed)
        }
        PaymentDelegationDecision::Held { case_id, reason } => {
            if is_jsonrpc {
                return jsonrpc(
                    StatusCode::OK,
                    application_error_codes::PAYMENT_PENDING,
                    "Payment pending review",
                    json!({"httpStatus": 202, "case_id": case_id, "reason": reason}),
                    &[],
                );
            }
            json_response(
                StatusCode::ACCEPTED,
                &json!({"status": "held_for_oversight", "case_id": case_id, "reason": reason}),
                &[],
            )
        }
        PaymentDelegationDecision::Rejected { status, reason } => {
            let status = StatusCode::from_u16(*status).unwrap_or(StatusCode::FORBIDDEN);
            if is_jsonrpc {
                return jsonrpc(
                    status,
                    rejected.0,
                    rejected.1,
                    json!({"httpStatus": status.as_u16(), "failure": {"reason": reason}}),
                    &[],
                );
            }
            json_response(status, &json!({"error": reason}), &[])
        }
        PaymentDelegationDecision::RateLimited { retry_after } => {
            let headers = retry_after_header(retry_after.as_deref());
            if is_jsonrpc {
                return jsonrpc(
                    StatusCode::TOO_MANY_REQUESTS,
                    error_codes::INTERNAL_ERROR,
                    "Payment gateway rate limit reached",
                    json!({"httpStatus": 429, "retryAfter": retry_after}),
                    &headers,
                );
            }
            json_response(StatusCode::TOO_MANY_REQUESTS, &json!({"error": "rate_limited"}), &headers)
        }
        PaymentDelegationDecision::InProgress { retry_after } => {
            let headers = retry_after_header(retry_after.as_deref());
            if is_jsonrpc {
                return jsonrpc(
                    StatusCode::CONFLICT,
                    error_codes::INTERNAL_ERROR,
                    "Payment in progress",
                    json!({"httpStatus": 409, "error": IN_PROGRESS, "retryAfter": retry_after}),
                    &headers,
                );
            }
            json_response(StatusCode::CONFLICT, &json!({"error": IN_PROGRESS, "retry_same_request": true}), &headers)
        }
        PaymentDelegationDecision::Unconfirmed { status, message } => {
            let status = StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY);
            let headers = retry_after_header(Some(&UNCONFIRMED_RETRY_AFTER_SECS.to_string()));
            if is_jsonrpc {
                return jsonrpc(
                    status,
                    error_codes::INTERNAL_ERROR,
                    "Payment not confirmed",
                    json!({
                        "httpStatus": status.as_u16(), "error": UNCONFIRMED, "detail": message,
                        "retryAfter": UNCONFIRMED_RETRY_AFTER_SECS, "replayWindowSecs": REPLAY_WINDOW_SECS,
                    }),
                    &headers,
                );
            }
            json_response(
                status,
                &json!({
                    "error": UNCONFIRMED, "detail": message, "retry_same_request": true,
                    "retry_after": UNCONFIRMED_RETRY_AFTER_SECS, "replay_window_secs": REPLAY_WINDOW_SECS,
                }),
                &headers,
            )
        }
        PaymentDelegationDecision::Deny { status, message } => {
            let status = StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY);
            if is_jsonrpc {
                return jsonrpc(
                    status,
                    error_codes::INTERNAL_ERROR,
                    "Payment unavailable",
                    json!({"httpStatus": status.as_u16(), "error": "payment_unavailable", "detail": message}),
                    &[],
                );
            }
            json_response(status, &json!({"error": "payment_unavailable", "detail": message}), &[])
        }
    }
}

/// A `Deny` carrying `Retry-After`, as an open breaker answers.
fn render_with_retry_after(
    decision: &PaymentDelegationDecision,
    shape: &Shape,
    retry_after: Option<u64>,
) -> Response {
    let mut response = render(decision, shape);
    if let Some(seconds) = retry_after {
        response
            .headers_mut()
            .insert(axum::http::header::RETRY_AFTER, HeaderValue::from(seconds));
    }
    response
}

/// Everything recorded about one gate call.
struct GateRecord<'a> {
    intake: &'a Intake,
    call: &'a GateCall<'a>,
    policy: &'a AgentPayPolicy,
    decision: &'a PaymentDelegationDecision,
    remote_status: Option<u16>,
    receipt: Option<&'a Receipt>,
    gateway_did: Option<String>,
    /// How long agent-pay took, when a request was made to it.
    latency_ms: Option<u64>,
    /// Funds agent-pay holds rather than captured.
    held: Option<&'a HeldFunds>,
}

/// The most decimal places a price is compared at.
const MAX_DECIMALS: u32 = 28;

/// The decimal places of a currency's base unit, for a receipt amount that is
/// a whole number of base units without saying so.
fn base_unit_decimals(currency: &str) -> Option<u32> {
    let currency = currency.to_ascii_uppercase();
    match currency.as_str() {
        "BIF" | "CLP" | "DJF" | "GNF" | "ISK" | "JPY" | "KMF" | "KRW" | "PYG" | "RWF" | "UGX" | "VND" | "VUV"
        | "XAF" | "XOF" | "XPF" => Some(0),
        "BHD" | "IQD" | "JOD" | "KWD" | "LYD" | "OMR" | "TND" => Some(3),
        "USDC" | "USDT" | "PYUSD" | "EURC" => Some(6),
        "ETH" => Some(18),
        _ if currency.len() == 3
            && currency
                .bytes()
                .all(|byte| byte.is_ascii_alphabetic()) =>
        {
            Some(2)
        }
        _ => None,
    }
}

/// Whether a charged amount is the quoted price: compared as numbers, the
/// charged one read in base units when the receipt names its decimals, or when
/// it is a whole number that only matches as base units of its currency.
fn same_amount(
    quoted: &str,
    charged: &str,
    decimals: Option<u32>,
    currency: Option<&str>,
) -> bool {
    use std::str::FromStr;

    let parse = |amount: &str| rust_decimal::Decimal::from_str(amount.trim()).ok();
    let (Some(quoted), Some(charged)) = (parse(quoted), parse(charged)) else {
        return quoted.trim() == charged.trim();
    };
    let in_base_units = |decimals: u32| {
        let mut major = charged;
        major
            .set_scale(
                charged
                    .scale()
                    .checked_add(decimals)?,
            )
            .ok()?;
        Some(major)
    };
    match decimals {
        Some(decimals) => in_base_units(decimals) == Some(quoted),
        None => {
            charged == quoted
                || (charged.fract().is_zero()
                    && currency
                        .and_then(base_unit_decimals)
                        .and_then(in_base_units)
                        == Some(quoted))
        }
    }
}

/// The amount and currency agent-pay charged, from its receipt, falling back to
/// the manifest snapshot; and whether the receipt's price differs from the
/// manifest's in value or currency.
fn charged_price(
    facts: &ReceiptFacts,
    quoted: (Option<String>, Option<String>),
) -> (Option<String>, Option<String>, bool) {
    let (quoted_amount, quoted_currency) = quoted;
    let Some(amount) = facts.amount.clone() else {
        return (quoted_amount, quoted_currency, false);
    };
    let currency = facts
        .currency
        .clone()
        .or_else(|| quoted_currency.clone());
    let amount_differs = quoted_amount
        .as_deref()
        .is_some_and(|quoted| !same_amount(quoted, &amount, facts.decimals, currency.as_deref()));
    let currency_differs = match (&quoted_currency, &facts.currency) {
        (Some(quoted), Some(charged)) => !quoted.eq_ignore_ascii_case(charged),
        _ => false,
    };
    (Some(amount), currency, amount_differs || currency_differs)
}

/// Records one gate call; returns the id of its ledger row.
async fn record(record: GateRecord<'_>) -> String {
    use crate::delegation_vault::audit::{DelegatedPaymentFacts, PaymentEventDetails, PaymentStage};
    use crate::integrations::payment_gate_integration_triggers::{
        PaymentGateEvent, PaymentGateEventFacts, raise_payment_gate_event,
    };
    use crate::payments_ledger::LedgerOutcome;

    let surface = record.call.surface;
    let policy = record.policy;
    let intake = record.intake;
    let trace_id = record.call.trace_id;
    let outcome = match (outcome_label(record.decision), record.held) {
        (LedgerOutcome::Paid, Some(_)) => LedgerOutcome::Authorized,
        (outcome, _) => outcome,
    };
    let id = uuid::Uuid::now_v7().to_string();
    let facts = record
        .receipt
        .map(|receipt| receipt_facts(&receipt.value))
        .unwrap_or_default();
    let quoted = manifest_price(policy);
    let (amount, currency, price_mismatch) = charged_price(&facts, quoted.clone());
    if price_mismatch {
        tracing::warn!(
            surface_id = %surface.surface_id,
            charged = ?amount,
            quoted = ?quoted.0,
            "agent-pay's receipt names a different price than the manifest snapshot"
        );
    }
    let (case_id, error) = match record.decision {
        PaymentDelegationDecision::Held { case_id, .. } => (Some(case_id.clone()), None),
        PaymentDelegationDecision::Rejected { reason, .. } => (None, Some(reason.clone())),
        PaymentDelegationDecision::VerificationFailed { reason, detail, .. } => (
            None,
            Some(match detail {
                Some(detail) => format!("{reason}: {detail}"),
                None => reason.clone(),
            }),
        ),
        PaymentDelegationDecision::RateLimited { .. } => (None, Some("rate_limited".to_string())),
        PaymentDelegationDecision::InProgress { .. } => (None, Some(IN_PROGRESS.to_string())),
        PaymentDelegationDecision::Unconfirmed { message, .. } => (None, Some(format!("{UNCONFIRMED}: {message}"))),
        PaymentDelegationDecision::Deny { message, .. } => (None, Some(message.clone())),
        _ => (None, None),
    };
    let reason = error
        .as_deref()
        .filter(|_| {
            matches!(
                outcome,
                LedgerOutcome::Rejected
                    | LedgerOutcome::Unavailable
                    | LedgerOutcome::Unconfirmed
                    | LedgerOutcome::CaptureFailed
                    | LedgerOutcome::Voided
            )
        })
        .map(crate::payments_ledger::ledger_reason);
    let stage = match outcome {
        LedgerOutcome::Paid => PaymentStage::Verified,
        LedgerOutcome::Authorized => PaymentStage::Authorized,
        LedgerOutcome::Voided => PaymentStage::Voided,
        LedgerOutcome::CaptureFailed => PaymentStage::SettlementFailed,
        LedgerOutcome::Challenge => PaymentStage::ChallengeIssued,
        LedgerOutcome::Held => PaymentStage::Held,
        LedgerOutcome::Unconfirmed => PaymentStage::Unconfirmed,
        LedgerOutcome::Rejected | LedgerOutcome::Unavailable => PaymentStage::Failed,
    };
    let rail = resolved_rail(
        intake
            .credential
            .as_ref()
            .map(|credential| credential.rail),
        policy,
    );
    let payer = record
        .call
        .caller
        .audit_payer();
    let vc = match outcome {
        LedgerOutcome::Paid | LedgerOutcome::Authorized => {
            crate::payment_credentials::issue_access_grant(crate::payment_credentials::AccessGrantInput {
                rail: audit_rail(rail).as_str(),
                trace_id: Some(trace_id.to_string()),
                payment_gateway_id: Some(
                    policy
                        .payment_gateway_id
                        .clone(),
                ),
                payment_surface_id: Some(
                    policy
                        .payment_surface_id
                        .clone(),
                ),
                remote_status: record
                    .remote_status
                    .unwrap_or(200),
            })
            .await
        }
        LedgerOutcome::Rejected => {
            crate::payment_credentials::issue_payment_rejection(crate::payment_credentials::PaymentRejectionInput {
                rail: audit_rail(rail).as_str(),
                payment_id: id.clone(),
                trace_id: Some(trace_id.to_string()),
                method: facts.method.clone(),
                payer: payer.clone(),
                reason: error
                    .clone()
                    .unwrap_or_default(),
            })
            .await
        }
        _ => None,
    };
    crate::delegation_vault::audit::record_payment_event(
        PaymentEventDetails {
            rail: audit_rail(rail).audit(),
            stage,
            transaction_id: id.clone(),
            amount: amount.clone(),
            currency: currency.clone(),
            method: facts.method.clone(),
            payer,
            error,
            delegated: true,
            payment_gateway_id: Some(
                policy
                    .payment_gateway_id
                    .clone(),
            ),
            payment_surface_id: Some(
                policy
                    .payment_surface_id
                    .clone(),
            ),
            remote_status: record.remote_status,
            delegation: Some(Box::new(DelegatedPaymentFacts {
                resource: Some(intake.resource.clone()),
                variant: intake.variant.clone(),
                gateway_did: record.gateway_did,
                case_id: case_id.clone(),
                vc_fingerprint: record
                    .receipt
                    .and_then(|receipt| receipt.vc_fingerprint.clone()),
                idempotency_key: intake.key.clone(),
                receipt_reference: facts.reference.clone(),
                challenge_id: facts.challenge_id,
                network: facts.network.clone(),
                latency_ms: record
                    .latency_ms
                    .unwrap_or_default(),
                authorization_id: record
                    .held
                    .map(|held| held.authorization_id.clone()),
                quoted_amount: quoted
                    .0
                    .clone()
                    .filter(|_| price_mismatch),
                quoted_currency: quoted
                    .1
                    .clone()
                    .filter(|_| price_mismatch),
                price_mismatch,
            })),
        },
        Some(&surface.surface_id),
        Some(&surface.name),
        Some(trace_id),
        record.call.via_fabric,
        vc.as_ref()
            .map(|credential| credential.jwt.as_str()),
    );
    match record.latency_ms {
        Some(latency_ms) => crate::metrics::backends::prometheus::track_payment_gate(
            &surface.surface_id,
            outcome_str(outcome),
            latency_ms,
        ),
        None => {
            crate::metrics::backends::prometheus::track_payment_gate_request(&surface.surface_id, outcome_str(outcome))
        }
    }
    crate::payments_ledger::record(
        crate::payments_ledger::PaymentLedgerRow {
            id: id.clone(),
            created_at: chrono::Utc::now(),
            surface_id: surface.surface_id.clone(),
            variant: intake.variant.clone(),
            payment_gateway_id: policy
                .payment_gateway_id
                .clone(),
            payment_surface_id: policy
                .payment_surface_id
                .clone(),
            outcome,
            rail: rail.map(Rail::ledger),
            amount: amount.clone(),
            currency: currency.clone(),
            resource: Some(intake.resource.clone()),
            case_id: case_id.clone(),
            receipt_reference: facts.reference.clone(),
            vc_fingerprint: record
                .receipt
                .and_then(|receipt| receipt.vc_fingerprint.clone()),
            reason: reason.clone(),
            latency_ms: record
                .latency_ms
                .unwrap_or_default(),
            remote_status: record.remote_status,
            trace_id: Some(trace_id.to_string()),
            price_mismatch,
            quoted_amount: quoted
                .0
                .clone()
                .filter(|_| price_mismatch),
            quoted_currency: quoted
                .1
                .clone()
                .filter(|_| price_mismatch),
            idempotency_key: intake
                .key
                .clone()
                .filter(|_| outcome.is_money()),
            authorization_id: record
                .held
                .map(|held| held.authorization_id.clone()),
            capture_deadline: record
                .held
                .map(|held| held.capture_deadline),
            settle_timeout_ms: record
                .held
                .map(|_| policy.timeout().as_millis() as u64),
            caller_principal: caller_principal(record.call.caller.identity),
            ..crate::payments_ledger::PaymentLedgerRow::new(String::new(), String::new(), String::new(), outcome)
        },
        surface.tenant_id.clone(),
    )
    .await;
    let event = match outcome {
        LedgerOutcome::Paid => PaymentGateEvent::Paid,
        LedgerOutcome::Authorized => PaymentGateEvent::Authorized,
        LedgerOutcome::Voided => PaymentGateEvent::Voided,
        LedgerOutcome::CaptureFailed => PaymentGateEvent::CaptureFailed,
        LedgerOutcome::Challenge => PaymentGateEvent::ChallengeIssued,
        LedgerOutcome::Held => PaymentGateEvent::Held,
        LedgerOutcome::Rejected => PaymentGateEvent::Rejected,
        LedgerOutcome::Unconfirmed => PaymentGateEvent::Unconfirmed,
        LedgerOutcome::Unavailable => PaymentGateEvent::Unavailable,
    };
    let event_facts = PaymentGateEventFacts {
        surface_id: surface.surface_id.clone(),
        variant: intake.variant.clone(),
        payment_gateway_id: policy
            .payment_gateway_id
            .clone(),
        payment_surface_id: policy
            .payment_surface_id
            .clone(),
        resource: Some(intake.resource.clone()),
        rail: rail.map(|rail| rail.as_str().to_string()),
        amount,
        currency,
        case_id,
        remote_status: record.remote_status,
        trace_id: trace_id.to_string(),
        authorization_id: record
            .held
            .map(|held| held.authorization_id.clone()),
        receipt_reference: facts.reference,
        quoted_amount: quoted
            .0
            .filter(|_| price_mismatch),
        quoted_currency: quoted
            .1
            .filter(|_| price_mismatch),
        price_mismatch,
        reason,
    };
    raise_payment_gate_event(event, event_facts);
    crate::observability::note_payment_outcome(outcome.as_str(), Some(&id));
    id
}

/// How often one surface's refused requests are audited and raised as an
/// integration event: every refusal is counted, but a flood of unauthenticated
/// requests must not become a flood of audit records and webhooks.
const LEGACY_REFUSAL_EVENT_EVERY: Duration = Duration::from_secs(60);
const MAX_TRACKED_LEGACY_REFUSALS: usize = 4096;

static LEGACY_REFUSALS: LazyLock<Mutex<HashMap<String, Instant>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Whether the refusal of a request to `surface_id` at `now` is the first in
/// [`LEGACY_REFUSAL_EVENT_EVERY`], and notes it if so. At most
/// [`MAX_TRACKED_LEGACY_REFUSALS`] surfaces are tracked; past that, a surface
/// that is not tracked is always due.
fn refusal_due(
    refused: &mut HashMap<String, Instant>,
    surface_id: &str,
    now: Instant,
) -> bool {
    if refused
        .get(surface_id)
        .is_some_and(|last| now.saturating_duration_since(*last) < LEGACY_REFUSAL_EVENT_EVERY)
    {
        return false;
    }
    if refused.len() >= MAX_TRACKED_LEGACY_REFUSALS && !refused.contains_key(surface_id) {
        refused.retain(|_, last| now.saturating_duration_since(*last) < LEGACY_REFUSAL_EVENT_EVERY);
        if refused.len() >= MAX_TRACKED_LEGACY_REFUSALS {
            return true;
        }
    }
    refused.insert(surface_id.to_string(), now);
    true
}

fn legacy_refusal_due(
    surface_id: &str,
    now: Instant,
) -> bool {
    refusal_due(
        &mut LEGACY_REFUSALS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        surface_id,
        now,
    )
}

/// Records a request refused because the surface still carries an
/// unsupported local x402 or MPP payment policy. The refusal is always counted;
/// the audit event and the integration event are raised once a minute per
/// surface (see [`LEGACY_REFUSAL_EVENT_EVERY`]).
pub(crate) fn record_legacy_refusal(
    surface: &AgentSurface,
    via_fabric: bool,
) {
    use crate::delegation_vault::audit::{PaymentEventDetails, PaymentStage};
    use crate::integrations::payment_gate_integration_triggers::{
        PaymentGateEvent, PaymentGateEventFacts, raise_payment_gate_event,
    };

    crate::metrics::backends::prometheus::track_payment_gate_request(&surface.surface_id, "unavailable");
    crate::observability::note_payment_outcome("unavailable", None);
    if !legacy_refusal_due(&surface.surface_id, Instant::now()) {
        return;
    }
    let rail = if surface.mpp_config().is_some() {
        crate::delegation_vault::audit::PaymentRail::Mpp
    } else {
        crate::delegation_vault::audit::PaymentRail::X402
    };
    let trace_id = crate::observability::policy_audit::current_span_trace_id();
    crate::delegation_vault::audit::record_payment_event(
        PaymentEventDetails {
            rail,
            stage: PaymentStage::Failed,
            transaction_id: uuid::Uuid::new_v4().to_string(),
            amount: None,
            currency: None,
            method: None,
            payer: None,
            error: Some("local_payment_unsupported".to_string()),
            delegated: false,
            payment_gateway_id: None,
            payment_surface_id: None,
            remote_status: None,
            delegation: None,
        },
        Some(&surface.surface_id),
        Some(&surface.name),
        trace_id.as_deref(),
        via_fabric,
        None,
    );
    raise_payment_gate_event(
        PaymentGateEvent::Unavailable,
        PaymentGateEventFacts {
            surface_id: surface.surface_id.clone(),
            trace_id: trace_id.unwrap_or_default(),
            remote_status: Some(503),
            reason: Some("local_payment_unsupported".to_string()),
            ..Default::default()
        },
    );
}

fn continuation_refusal(shape: &Shape) -> Response {
    render(
        &PaymentDelegationDecision::Rejected {
            status: 403,
            reason: "payment_continuation_invalid".to_string(),
        },
        shape,
    )
}

/// The outcome of a continuation round that already holds its payment: the
/// evidence's receipt, or a refusal when the evidence is not agent-pay's, has
/// expired, or is unusable.
fn evidence_outcome(
    intake: &Intake,
    evidence: &ContinuationPayment,
) -> GateOutcome {
    let valid = crate::proxy::credential_delegation::modern::now_secs()
        .ok()
        .is_some_and(|now| evidence.validate(now).is_ok());
    match evidence {
        ContinuationPayment::AgentPay {
            scheme,
            receipt: Some(receipt),
            vc_fingerprint,
            ..
        } if valid && !evidence_voided(receipt) => match Rail::parse(scheme) {
            Some(rail) => GateOutcome::Paid(Paid {
                receipt: Receipt {
                    rail,
                    value: receipt.clone(),
                    vc_fingerprint: vc_fingerprint.clone(),
                    cache_control: Some("no-store".to_string()),
                    claim: None,
                    authorization: None,
                },
            }),
            None => GateOutcome::Refused(continuation_refusal(&intake.shape)),
        },
        _ => GateOutcome::Refused(continuation_refusal(&intake.shape)),
    }
}

/// One request to the payment gateway and what came of it.
struct Exchange {
    decision: PaymentDelegationDecision,
    remote_status: Option<u16>,
    gateway_did: Option<String>,
    retry_after: Option<u64>,
    /// A request went on the wire to agent-pay.
    called: bool,
}

impl Exchange {
    /// A refusal made without a request to agent-pay.
    fn denied(
        status: u16,
        message: impl Into<String>,
    ) -> Self {
        Self::answered(PaymentDelegationDecision::deny(status, message), false)
    }

    fn answered(
        decision: PaymentDelegationDecision,
        called: bool,
    ) -> Self {
        Self {
            decision,
            remote_status: None,
            gateway_did: None,
            retry_after: None,
            called,
        }
    }
}

/// What one call to the payment gateway is made of.
struct Hop<'a> {
    intake: &'a Intake,
    call: &'a GateCall<'a>,
    policy: &'a AgentPayPolicy,
    transport: Arc<dyn GateTransport>,
    gateway_id: String,
}

/// Sends one payment request, with `credential` and its idempotency `key` when
/// the caller is paying, and without when it asks for a fresh challenge. An
/// answer that does not say whether the payment was taken is `Unconfirmed`; the
/// caller turns that into plain unavailability when nothing was presented to pay
/// with.
async fn exchange(
    hop: &Hop<'_>,
    credential: Option<&Credential>,
    key: Option<&str>,
) -> Exchange {
    let fabric_target = match hop.policy.fabric_target() {
        Ok(target) => target,
        Err(reason) => return Exchange::denied(502, reason),
    };
    if let Err(seconds) = breaker_admit(&hop.gateway_id, Instant::now()) {
        return Exchange {
            retry_after: Some(seconds),
            ..Exchange::denied(503, "payment gateway circuit open")
        };
    }
    let mut timeout = hop.policy.timeout();
    let mut shortened = false;
    if let Some(deadline) = hop.call.deadline_ms {
        let remaining = Duration::from_millis(deadline.saturating_sub(now_ms()));
        if remaining < MIN_PAYMENT_WAIT {
            record_transport_result(&hop.gateway_id, TransportOutcome::Inconclusive, Instant::now());
            return Exchange::denied(504, "caller deadline too short for payment");
        }
        if remaining < timeout {
            timeout = remaining;
            shortened = true;
        }
    }
    let traceparent = traceparent(hop.call.egress_trace_id);
    let intake = hop.intake;
    let wire = GateWireRequest {
        fabric_target,
        path: intake.path.clone(),
        headers: gate_headers(credential, intake.request_id.as_deref(), &traceparent),
        body: json!({
            "kind": "payment_request",
            "protocol": protocol_label(&intake.protocol),
            "resource": intake.resource,
            "caller_surface_id": hop.call.surface.surface_id,
        }),
        payment_context: build_payment_context(
            &hop.call.surface.surface_id,
            hop.policy,
            intake.message.as_ref(),
            &intake.resource,
            &hop.call.caller,
            key,
            hop.call.egress_trace_id,
            &traceparent,
        ),
        timeout,
        trace_id: hop
            .call
            .egress_trace_id
            .to_string(),
    };
    let sent = hop.transport.send(wire).await;
    record_transport_result(
        &hop.gateway_id,
        match &sent {
            Ok(_) => TransportOutcome::Reached,
            Err(FabricForwardError::NoResponse(_)) if shortened => TransportOutcome::Inconclusive,
            Err(_) => TransportOutcome::Failed,
        },
        Instant::now(),
    );
    let response = match sent {
        Ok(response) => response,
        Err(FabricForwardError::NoResponse(_)) => {
            return Exchange::answered(
                PaymentDelegationDecision::unconfirmed(504, "payment gateway did not answer in time"),
                true,
            );
        }
        Err(FabricForwardError::UnexpectedResponse(_)) => {
            return Exchange::answered(
                PaymentDelegationDecision::unconfirmed(502, "payment gateway answered with an unexpected message"),
                true,
            );
        }
        Err(error) => {
            tracing::warn!(
                surface_id = %hop.call.surface.surface_id,
                payment_gateway_id = %hop.gateway_id,
                error = %error,
                "Payment gate request failed"
            );
            return Exchange::answered(
                PaymentDelegationDecision::deny(502, "payment gateway unreachable"),
                matches!(error, FabricForwardError::SendFailed(_)),
            );
        }
    };
    let remote_status = Some(response.status);
    let gateway_did = hop
        .transport
        .gateway_did(&hop.gateway_id)
        .await;
    if oversized(&response) {
        return Exchange {
            remote_status,
            gateway_did,
            ..Exchange::answered(
                PaymentDelegationDecision::unconfirmed(502, "payment gateway response too large"),
                true,
            )
        };
    }
    let retry_after = (response.status == 503)
        .then(|| crate::x402::delegate::retry_after(&response.headers))
        .flatten()
        .and_then(|value| value.parse().ok());
    Exchange {
        remote_status,
        gateway_did,
        retry_after,
        ..Exchange::answered(
            crate::x402::map_delegation_response(response.status, response.headers, response.body),
            true,
        )
    }
}

/// A paid request whose gate step was cancelled after agent-pay was asked and
/// before its answer was recorded. Agent-pay may hold or have taken a payment
/// for it, so dropping this records an unconfirmed row under the request's
/// idempotency key, which the reconciler asks agent-pay about and voids when
/// funds are held.
struct Abandoned(Option<crate::payments_ledger::PaymentLedgerRow>, Option<String>);

impl Abandoned {
    fn arm(
        intake: &Intake,
        call: &GateCall<'_>,
        policy: &AgentPayPolicy,
    ) -> Self {
        let row = intake
            .key
            .clone()
            .filter(|_| intake.credential.is_some())
            .map(|key| crate::payments_ledger::PaymentLedgerRow {
                variant: intake.variant.clone(),
                resource: Some(intake.resource.clone()),
                trace_id: Some(call.trace_id.to_string()),
                idempotency_key: Some(key),
                caller_principal: caller_principal(call.caller.identity),
                reason: Some("request_cancelled_before_recorded".to_string()),
                ..crate::payments_ledger::PaymentLedgerRow::new(
                    call.surface
                        .surface_id
                        .clone(),
                    policy
                        .payment_gateway_id
                        .clone(),
                    policy
                        .payment_surface_id
                        .clone(),
                    crate::payments_ledger::LedgerOutcome::Unconfirmed,
                )
            });
        Self(row, call.surface.tenant_id.clone())
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for Abandoned {
    fn drop(&mut self) {
        let Some(row) = self.0.take() else {
            return;
        };
        let tenant_id = self.1.take();
        tracing::warn!(
            surface_id = %row.surface_id,
            "A paid request was cancelled before its payment was recorded; the reconciler settles it"
        );
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(crate::payments_ledger::record(row, tenant_id));
        }
    }
}

/// The refusal of a JSON-RPC batch on a surface that charges: which of its
/// messages is the paid one, and what each would cost, cannot be told.
fn batch_refusal() -> Response {
    crate::a2a::create_jsonrpc_error_response(
        StatusCode::BAD_REQUEST,
        crate::mcp::errors::error_codes::INVALID_REQUEST,
        "JSON-RPC batches are not supported on a surface that charges",
    )
}

/// Puts one request through the gate, just before it is forwarded. A request
/// the gate lets through has paid for exactly one forward: agent-pay may answer
/// the same credential and request as paid again within its replay window, and
/// that answer is refused here with a fresh challenge once a request was
/// dispatched for it. The receipt holds the claim on the payment until
/// [`Receipt::commit`], so a request that fails or is cancelled before that can
/// be retried with the same credential.
pub(crate) async fn charge(
    intake: &Intake,
    call: GateCall<'_>,
) -> GateOutcome {
    let Some(policy) = call
        .surface
        .agent_pay_policy()
    else {
        return GateOutcome::Free;
    };
    if !intake.chargeable {
        return GateOutcome::Free;
    }
    if let Some(evidence) = call.evidence {
        return evidence_outcome(intake, evidence);
    }
    if intake.batch && matches!(intake.protocol, ChannelProtocol::Mcp | ChannelProtocol::A2a | ChannelProtocol::Ap2) {
        return GateOutcome::Refused(batch_refusal());
    }

    let started = Instant::now();
    let gateway_id = policy
        .payment_gateway_id
        .trim()
        .to_string();
    let hop = Hop {
        intake,
        call: &call,
        policy,
        transport: transport_for(&gateway_id, call.fabric),
        gateway_id,
    };
    let mut abandoned = Abandoned::arm(intake, &call, policy);
    let answer = exchange(&hop, intake.credential.as_ref(), intake.key.as_deref()).await;
    let receipt_rail = resolved_rail(
        intake
            .credential
            .as_ref()
            .map(|credential| credential.rail),
        policy,
    )
    .unwrap_or(Rail::X402);
    let mut held = None;
    let (mut decision, mut receipt) = match answer.decision {
        PaymentDelegationDecision::Proceed { mut receipt_headers } => {
            let read = paid_receipt(&receipt_headers, receipt_rail)
                .and_then(|receipt| held_funds(&receipt_headers).map(|funds| (receipt, funds)));
            receipt_headers.retain(|name, _| {
                !name.eq_ignore_ascii_case(AUTHORIZATION_HEADER) && !name.eq_ignore_ascii_case(CAPTURE_DEADLINE_HEADER)
            });
            match read {
                Ok((receipt, funds)) => {
                    held = funds;
                    (PaymentDelegationDecision::Proceed { receipt_headers }, Some(receipt))
                }
                Err(unusable) => (unusable, None),
            }
        }
        other => (other, None),
    };
    let claim = receipt
        .as_ref()
        .and(intake.key.as_deref())
        .map(consumed::claim);
    match claim {
        Some(Ok(claim)) => {
            if let Some(receipt) = receipt.as_mut() {
                receipt.claim = Some(Arc::new(claim));
            }
        }
        Some(Err(consumed::Unclaimable::InFlight)) => {
            tracing::warn!(
                surface_id = %call.surface.surface_id,
                "A payment credential was presented again while a request it paid for is being dispatched"
            );
            decision = PaymentDelegationDecision::InProgress {
                retry_after: Some("1".to_string()),
            };
            receipt = None;
        }
        Some(Err(consumed::Unclaimable::Forwarded)) => {
            tracing::warn!(
                surface_id = %call.surface.surface_id,
                "A payment credential that already paid for a forwarded request was presented again"
            );
            let fresh = exchange(&hop, None, None).await;
            let (headers, body) = match fresh.decision {
                PaymentDelegationDecision::Challenge { headers, body, .. } => (headers, body),
                _ => (HashMap::new(), Vec::new()),
            };
            decision = PaymentDelegationDecision::VerificationFailed {
                headers,
                body,
                reason: ALREADY_USED.to_string(),
                detail: None,
            };
            receipt = None;
        }
        None => {}
    }
    if intake.credential.is_none() {
        decision = decision.without_credential();
    }
    let latency_ms = answer
        .called
        .then(|| started.elapsed().as_millis() as u64);
    let held = held.filter(|_| receipt.is_some());
    let row_id = record(GateRecord {
        intake,
        call: &call,
        policy,
        decision: &decision,
        remote_status: answer.remote_status,
        receipt: receipt.as_ref(),
        gateway_did: answer.gateway_did,
        latency_ms,
        held: held.as_ref(),
    })
    .await;
    abandoned.disarm();
    match receipt {
        Some(mut receipt) => {
            if let Some(held) = held {
                let evidence = receipt.value.clone();
                receipt.authorization = Some(Arc::new(Authorization::new(
                    crate::payments_ledger::settlement::HeldPayment {
                        row_id,
                        payment_gateway_id: hop.gateway_id.clone(),
                        authorization_id: held.authorization_id,
                        wait: policy.timeout(),
                    },
                    evidence,
                )));
            }
            GateOutcome::Paid(Paid { receipt })
        }
        None => {
            tracing::info!(
                surface_id = %call.surface.surface_id,
                outcome = outcome_str(outcome_label(&decision)),
                remote_status = ?answer.remote_status,
                "Payment gate did not authorize the request"
            );
            let retry_after = match decision {
                PaymentDelegationDecision::Unconfirmed { .. } => None,
                _ => answer.retry_after,
            };
            GateOutcome::Refused(render_with_retry_after(&decision, &intake.shape, retry_after))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    type Fabric = Arc<tokio::sync::RwLock<Option<Arc<crate::gateways::ConnectionPointListenerManager>>>>;

    /// A payment gate that answers every request with a fixed response (a
    /// request without a credential with its own, once one is set) and remembers
    /// what it was sent.
    type Answer = Result<(u16, HashMap<String, Vec<String>>, Vec<u8>), &'static str>;

    pub(crate) struct MockGate {
        pub answer: Mutex<Answer>,
        pub challenge: Mutex<Option<Answer>>,
        pub delay: Mutex<Duration>,
        pub calls: AtomicUsize,
        pub requests: Mutex<Vec<GateWireRequest>>,
    }

    fn answer(
        status: u16,
        headers: &[(&str, &str)],
        body: Value,
    ) -> Answer {
        Ok((
            status,
            headers
                .iter()
                .map(|(name, value)| (name.to_string(), vec![value.to_string()]))
                .collect(),
            body.to_string().into_bytes(),
        ))
    }

    impl MockGate {
        fn with_answer(answer: Answer) -> Arc<Self> {
            Arc::new(Self {
                answer: Mutex::new(answer),
                challenge: Mutex::new(None),
                delay: Mutex::new(Duration::ZERO),
                calls: AtomicUsize::new(0),
                requests: Mutex::new(Vec::new()),
            })
        }

        pub(crate) fn answering(
            status: u16,
            headers: &[(&str, &str)],
            body: Value,
        ) -> Arc<Self> {
            Self::with_answer(answer(status, headers, body))
        }

        pub(crate) fn failing(error: &'static str) -> Arc<Self> {
            Self::with_answer(Err(error))
        }

        /// Answers a request without a credential with this challenge.
        pub(crate) fn challenging(
            self: Arc<Self>,
            headers: &[(&str, &str)],
            body: Value,
        ) -> Arc<Self> {
            *self.challenge.lock().unwrap() = Some(answer(402, headers, body));
            self
        }

        pub(crate) fn delayed(
            self: Arc<Self>,
            delay: Duration,
        ) -> Arc<Self> {
            *self.delay.lock().unwrap() = delay;
            self
        }

        pub(crate) fn calls(&self) -> usize {
            self.calls
                .load(Ordering::SeqCst)
        }

        pub(crate) fn last(&self) -> GateWireRequest {
            self.requests
                .lock()
                .unwrap()
                .last()
                .cloned()
                .expect("the payment gate was called")
        }

        fn sent(&self) -> Vec<GateWireRequest> {
            self.requests
                .lock()
                .unwrap()
                .clone()
        }
    }

    impl GateTransport for MockGate {
        fn send(
            &self,
            request: GateWireRequest,
        ) -> futures::future::BoxFuture<'_, Result<FabricForwardResponse, FabricForwardError>> {
            self.calls
                .fetch_add(1, Ordering::SeqCst);
            let credentialed = request
                .headers
                .keys()
                .any(|name| {
                    name.eq_ignore_ascii_case("payment-signature") || name.eq_ignore_ascii_case("authorization")
                });
            self.requests
                .lock()
                .unwrap()
                .push(request);
            let answer = match self
                .challenge
                .lock()
                .unwrap()
                .clone()
            {
                Some(challenge) if !credentialed => challenge,
                _ => self
                    .answer
                    .lock()
                    .unwrap()
                    .clone(),
            };
            let delay = *self.delay.lock().unwrap();
            Box::pin(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                match answer {
                    Ok((status, headers, body)) => Ok(FabricForwardResponse { status, headers, body }),
                    Err("timeout") => Err(FabricForwardError::NoResponse("gw".into())),
                    Err(_) => Err(FabricForwardError::GatewayNotConnected("gw".into())),
                }
            })
        }

        fn gateway_did<'a>(
            &'a self,
            _gateway_id: &'a str,
        ) -> futures::future::BoxFuture<'a, Option<String>> {
            Box::pin(async { Some("did:web:agent-pay.example".to_string()) })
        }
    }

    pub(crate) fn mcp_surface(
        gateway_id: &str,
        policy: Value,
    ) -> AgentSurface {
        let mut policy = policy;
        policy["type"] = json!("agent_pay");
        policy["payment_gateway_id"] = json!(gateway_id);
        policy["payment_surface_id"] = json!("pay-1");
        serde_json::from_value(json!({
            "surface_id": "paid-mcp", "name": "Paid MCP",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "https://target.example/mcp", "payment_policy": policy}
        }))
        .unwrap()
    }

    fn a2a_surface(
        gateway_id: &str,
        policy: Value,
    ) -> AgentSurface {
        let mut policy = policy;
        policy["type"] = json!("agent_pay");
        policy["payment_gateway_id"] = json!(gateway_id);
        policy["payment_surface_id"] = json!("pay-1");
        serde_json::from_value(json!({
            "surface_id": "paid-a2a", "name": "Paid A2A",
            "access_point": {"listen_address": "https://gateway.example", "route": "/a2a", "protocol": "a2a"},
            "target": {"endpoint": "https://target.example/a2a", "payment_policy": policy}
        }))
        .unwrap()
    }

    fn policy(value: Value) -> AgentPayPolicy {
        serde_json::from_value(value).unwrap()
    }

    fn tool_call(
        tool: &str,
        arguments: Value,
    ) -> Vec<u8> {
        serde_json::to_vec(
            &json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}),
        )
        .unwrap()
    }

    fn mpp_token() -> String {
        crate::mpp::challenge::base64url_encode_nopad(
            br#"{"challenge":{"id":"c1","realm":"r","method":"tempo","intent":"charge","request":"e30"},"payload":{"proof":"p"}}"#,
        )
    }

    fn unique(label: &str) -> String {
        format!("{label}-{}", uuid::Uuid::new_v4())
    }

    fn x402_headers(credential: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("payment-signature", HeaderValue::from_str(credential).unwrap());
        headers
    }

    fn no_fabric() -> Fabric {
        Arc::new(tokio::sync::RwLock::new(None))
    }

    struct Read<'a> {
        method: &'a str,
        path_and_query: &'a str,
        variant: Option<&'a str>,
        headers: &'a HeaderMap,
        body: &'a [u8],
        mcp_context: Option<&'a McpContext>,
    }

    fn read_with(
        surface: &AgentSurface,
        request: Read<'_>,
    ) -> Intake {
        Intake::read(
            surface,
            Inbound {
                method: request.method,
                path_and_query: request.path_and_query,
                variant: request.variant,
                headers: request.headers,
                body: &Bytes::copy_from_slice(request.body),
                mcp_context: request.mcp_context,
                signature_header: "PAYMENT-SIGNATURE",
            },
        )
        .expect("an agent_pay surface")
    }

    fn read(
        surface: &AgentSurface,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Intake {
        read_with(
            surface,
            Read {
                method: "POST",
                path_and_query: "/mcp",
                variant: Some("gold"),
                headers,
                body,
                mcp_context: None,
            },
        )
    }

    fn call<'a>(
        surface: &'a AgentSurface,
        fabric: &'a Fabric,
    ) -> GateCall<'a> {
        GateCall {
            surface,
            caller: Caller::default(),
            trace_id: "ingress-trace",
            egress_trace_id: "0af76519-16cd-43dd-8448-eb211c80319c",
            deadline_ms: None,
            evidence: None,
            fabric,
            via_fabric: false,
        }
    }

    /// Charges a request and marks it as dispatched, as a handler does.
    async fn dispatched(
        intake: &Intake,
        call: GateCall<'_>,
    ) -> Receipt {
        let GateOutcome::Paid(paid) = charge(intake, call).await else { panic!("expected a paid request") };
        paid.receipt.commit();
        paid.receipt
    }

    fn paid_gate() -> Arc<MockGate> {
        MockGate::answering(
            200,
            &[
                ("Payment-Receipt", "the-receipt"),
                ("Payment-Receipt-VC-Fingerprint", "fp-1"),
                ("Cache-Control", "no-store"),
            ],
            json!({}),
        )
    }

    async fn body_json(response: Response) -> (StatusCode, HeaderMap, Value) {
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX)
            .await
            .unwrap();
        (parts.status, parts.headers, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    fn payment_events(
        events: &[crate::delegation_vault::audit::DelegationAuditEvent]
    ) -> Vec<(crate::delegation_vault::audit::PaymentEventDetails, Option<String>)> {
        events
            .iter()
            .filter_map(|event| match &event.event {
                crate::delegation_vault::audit::DelegationAuditAction::PaymentEvent(details) => {
                    Some(((**details).clone(), event.trace_id.clone()))
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn mcp_triggers_decide_which_tool_calls_are_chargeable() {
        let matching = policy(json!({"mcp_payment_triggers": {"mode": "match", "patterns": ["^premium_"]}}));
        assert!(is_chargeable(&matching, &ChannelProtocol::Mcp, &tool_call("premium_report", json!({})), None));
        assert!(!is_chargeable(&matching, &ChannelProtocol::Mcp, &tool_call("free_report", json!({})), None));
        let listing = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        assert!(!is_chargeable(&matching, &ChannelProtocol::Mcp, listing, None));
        let listed = |policy: &AgentPayPolicy| is_chargeable(policy, &ChannelProtocol::Mcp, listing, None);
        let called = |policy: &AgentPayPolicy| {
            is_chargeable(policy, &ChannelProtocol::Mcp, &tool_call("any_tool", json!({})), None)
        };
        for unset in [
            json!({}),
            json!({"mcp_payment_triggers": {"mode": "match", "patterns": []}}),
            json!({"mcp_payment_triggers": {"mode": "match", "patterns": ["", "  "]}}),
        ] {
            let unset = policy(unset);
            assert!(called(&unset), "a policy with no trigger configuration charges every tools/call");
            assert!(!listed(&unset), "and nothing else");
        }
        assert!(called(&policy(json!({"mcp_payment_triggers": {"mode": "match", "patterns": ["", "^any_"]}}))));
        assert!(
            !called(&policy(json!({"mcp_payment_triggers": {"mode": "match", "patterns": ["^other_"]}}))),
            "a match with real patterns that match nothing stays as configured"
        );
        assert!(
            !called(&policy(json!({"mcp_payment_triggers": {"mode": "exclude", "patterns": ["^any_"]}}))),
            "an exclusion of the tool stays as configured"
        );
        let context = McpContext {
            method: "tools/call".into(),
            tool_name: Some("premium_x".into()),
            ..Default::default()
        };
        assert!(is_chargeable(&matching, &ChannelProtocol::Mcp, b"", Some(&context)));
        assert!(!is_chargeable(&matching, &ChannelProtocol::Mcp, b"not json", None));
    }

    #[test]
    fn a2a_filters_decide_which_methods_are_chargeable_and_unreadable_bodies_are_charged() {
        let filters = policy(json!({"a2a_method_filters": [{"method": "message/send", "message_patterns": ["buy"]}]}));
        let message = |method: &str, text: &str| {
            serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": method,
                "params": {"message": {"parts": [{"kind": "text", "text": text}]}}}))
            .unwrap()
        };
        assert!(is_chargeable(&filters, &ChannelProtocol::A2a, &message("message/send", "buy now"), None));
        assert!(is_chargeable(&filters, &ChannelProtocol::A2a, &message("SendMessage", "please buy"), None));
        assert!(!is_chargeable(&filters, &ChannelProtocol::A2a, &message("message/send", "hello"), None));
        assert!(!is_chargeable(&filters, &ChannelProtocol::A2a, &message("tasks/get", "buy"), None));
        assert!(is_chargeable(&filters, &ChannelProtocol::A2a, b"not json", None));
        assert!(is_chargeable(&filters, &ChannelProtocol::A2a, br#"[{"method":"message/send"}]"#, None));
        assert!(!is_chargeable(&filters, &ChannelProtocol::A2a, b"", None));
        assert!(is_chargeable(&policy(json!({})), &ChannelProtocol::A2a, b"not json", None));
    }

    #[test]
    fn a_policy_with_no_a2a_filter_charges_message_send_and_stream_and_blank_patterns_are_unset() {
        let message = |method: &str, text: &str| {
            serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": method,
                "params": {"message": {"parts": [{"text": text}]}}}))
            .unwrap()
        };
        let charged = |policy: &AgentPayPolicy, method: &str, text: &str| {
            is_chargeable(policy, &ChannelProtocol::A2a, &message(method, text), None)
        };
        for unset in [json!({}), json!({"a2a_method_filters": []}), json!({"a2a_method_filters": [{"method": " "}]})] {
            let unset = policy(unset);
            for method in ["message/send", "SendMessage", "message/stream", "SendStreamingMessage"] {
                assert!(charged(&unset, method, "hello"), "{method}");
            }
            assert!(!charged(&unset, "tasks/get", "hello"));
            assert!(!charged(&unset, "tasks/cancel", "hello"));
        }
        let blank = policy(json!({"a2a_method_filters": [{"method": "message/send", "message_patterns": ["", " "]}]}));
        assert!(charged(&blank, "message/send", "anything"), "a blank pattern is unset, not a match for nothing");
        assert!(!charged(&blank, "message/stream", "anything"), "an explicit filter names its methods");
        let literal = policy(json!({"a2a_method_filters": [{"method": "message/send", "message_patterns": ["Buy"]}]}));
        assert!(charged(&literal, "message/send", "Buy now"));
        assert!(!charged(&literal, "message/send", "buy now"), "a pattern is case-sensitive");
    }

    #[test]
    fn a_message_pattern_is_text_the_message_contains() {
        let filters =
            policy(json!({"a2a_method_filters": [{"method": "message/send", "message_patterns": ["a.b", "(x"]}]}));
        let message = |text: &str| {
            serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": "message/send",
                "params": {"message": {"parts": [{"kind": "text", "text": text}]}}}))
            .unwrap()
        };
        assert!(is_chargeable(&filters, &ChannelProtocol::A2a, &message("say a.b please"), None));
        assert!(
            !is_chargeable(&filters, &ChannelProtocol::A2a, &message("say axb please"), None),
            ". is not a wildcard"
        );
        assert!(
            is_chargeable(&filters, &ChannelProtocol::A2a, &message("open (x now"), None),
            "an unbalanced paren is text"
        );
    }

    #[test]
    fn require_all_charges_every_request_and_other_protocols_are_always_charged() {
        let all = policy(json!({"require_all": true}));
        for protocol in [ChannelProtocol::Mcp, ChannelProtocol::A2a, ChannelProtocol::DIDComm] {
            assert!(is_chargeable(&all, &protocol, br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#, None));
        }
        assert!(is_chargeable(&policy(json!({})), &ChannelProtocol::DIDComm, b"", None));
    }

    #[test]
    fn a_surface_is_due_a_refusal_event_once_a_minute() {
        let now = Instant::now();
        let surface = unique("legacy-surface");
        assert!(legacy_refusal_due(&surface, now));
        assert!(!legacy_refusal_due(&surface, now + Duration::from_secs(59)));
        assert!(legacy_refusal_due(&unique("other-surface"), now), "another surface has its own interval");
        assert!(legacy_refusal_due(&surface, now + Duration::from_secs(60)));
        assert!(!legacy_refusal_due(&surface, now + Duration::from_secs(61)), "the interval restarts at each event");
    }

    #[test]
    fn the_surfaces_tracked_for_refusal_events_stay_bounded() {
        let now = Instant::now();
        let mut refused = HashMap::new();
        for i in 0..MAX_TRACKED_LEGACY_REFUSALS {
            assert!(refusal_due(&mut refused, &format!("surface-{i}"), now));
        }
        assert_eq!(refused.len(), MAX_TRACKED_LEGACY_REFUSALS);

        assert!(refusal_due(&mut refused, "one-too-many", now), "an untracked surface still gets its event");
        assert_eq!(refused.len(), MAX_TRACKED_LEGACY_REFUSALS, "but is not tracked");
        assert!(!refusal_due(&mut refused, "surface-0", now), "a tracked surface keeps its interval");

        let later = now + LEGACY_REFUSAL_EVENT_EVERY;
        assert!(refusal_due(&mut refused, "one-too-many", later));
        assert_eq!(refused.len(), 1, "entries past their interval are dropped when the cap is reached");
    }

    #[tokio::test]
    async fn every_legacy_refusal_is_counted_but_only_the_first_raises_events() {
        let mut surface = mcp_surface("legacy-counted", json!({}));
        surface.surface_id = unique("legacy-counted");
        let counted = || {
            crate::metrics::backends::prometheus::PAYMENT_GATE_REQUESTS
                .with_label_values(&[surface.surface_id.as_str(), "unavailable"])
                .get()
        };
        for _ in 0..5 {
            record_legacy_refusal(&surface, false);
        }
        assert_eq!(counted(), 5);
        assert!(!legacy_refusal_due(&surface.surface_id, Instant::now()), "the first refusal started the interval");
    }

    #[test]
    fn a_stored_legacy_delegated_policy_naming_no_triggers_still_charges_its_protocol() {
        use crate::storage::filesystem::StorableEntity;

        let loaded = |protocol: &str| {
            let mut stored = json!({
                "surface_id": "s-legacy", "name": "legacy",
                "access_point": {"listen_address": "127.0.0.1:8080", "route": "/legacy", "protocol": protocol},
                "target": {"endpoint": "http://upstream.example", "payment_policy": {
                    "type": "x402", "provider": "agent_pay", "payment_gateway_id": "gw", "payment_surface_id": "pay"
                }}
            });
            AgentSurface::migrate_raw_json(&mut stored).unwrap();
            let surface: AgentSurface = serde_json::from_value(stored).unwrap();
            surface
                .agent_pay_policy()
                .cloned()
                .unwrap()
        };
        let message = |method: &str| {
            serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": {}})).unwrap()
        };

        let mcp = loaded("mcp");
        assert!(is_chargeable(&mcp, &ChannelProtocol::Mcp, &tool_call("any_tool", json!({})), None));
        assert!(!is_chargeable(&mcp, &ChannelProtocol::Mcp, &message("tools/list"), None));

        let a2a = loaded("a2a");
        assert!(is_chargeable(&a2a, &ChannelProtocol::A2a, &message("message/send"), None));
        assert!(is_chargeable(&a2a, &ChannelProtocol::A2a, &message("SendStreamingMessage"), None));
        assert!(!is_chargeable(&a2a, &ChannelProtocol::A2a, &message("tasks/get"), None));

        assert!(is_chargeable(&loaded("didcomm"), &ChannelProtocol::DIDComm, b"{}", None));
    }

    #[test]
    fn credentials_are_found_in_every_supported_location() {
        let mut headers = HeaderMap::new();
        assert_eq!(extract_credential(&headers, "PAYMENT-SIGNATURE", None), None);
        headers.insert("payment-signature", HeaderValue::from_static("x402-proof"));
        let found = extract_credential(&headers, "PAYMENT-SIGNATURE", None).unwrap();
        assert_eq!((found.rail, found.value.as_str()), (Rail::X402, "x402-proof"));

        let mut configured = HeaderMap::new();
        configured.insert("x-payment", HeaderValue::from_static("legacy-proof"));
        assert_eq!(
            extract_credential(&configured, "X-PAYMENT", None)
                .unwrap()
                .value,
            "legacy-proof"
        );

        let mut mpp = HeaderMap::new();
        mpp.insert("authorization", HeaderValue::from_str(&format!("Payment {}", mpp_token())).unwrap());
        let found = extract_credential(&mpp, "PAYMENT-SIGNATURE", None).unwrap();
        assert_eq!((found.rail, found.value), (Rail::Mpp, mpp_token()));
        mpp.insert("authorization", HeaderValue::from_str(&format!("payment {}", mpp_token())).unwrap());
        assert_eq!(
            extract_credential(&mpp, "PAYMENT-SIGNATURE", None)
                .unwrap()
                .value,
            mpp_token(),
            "the auth scheme is matched in any case"
        );
        mpp.insert("authorization", HeaderValue::from_static("Payment not-base64-json"));
        assert_eq!(extract_credential(&mpp, "PAYMENT-SIGNATURE", None), None);
        mpp.insert("authorization", HeaderValue::from_static("Bearer token"));
        assert_eq!(extract_credential(&mpp, "PAYMENT-SIGNATURE", None), None);

        let empty = HeaderMap::new();
        let call = |arguments: Value, meta: Value| {
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "t", "arguments": arguments, "_meta": meta}})
        };
        let found = extract_credential(
            &empty,
            "PAYMENT-SIGNATURE",
            Some(&call(json!({"payment_signature": "sig"}), json!({}))),
        )
        .unwrap();
        assert_eq!((found.rail, found.value.as_str()), (Rail::X402, "sig"));
        let found = extract_credential(
            &empty,
            "PAYMENT-SIGNATURE",
            Some(&call(json!({"payment_credential": mpp_token()}), json!({}))),
        )
        .unwrap();
        assert_eq!((found.rail, found.value), (Rail::Mpp, mpp_token()));
        let found = extract_credential(
            &empty,
            "PAYMENT-SIGNATURE",
            Some(&call(json!({}), json!({"org.paymentauth/credential": mpp_token()}))),
        )
        .unwrap();
        assert_eq!(found.value, mpp_token());
        let object = json!({"challenge": {"id": "c2", "realm": "r", "method": "tempo", "intent": "charge", "request": "e30"}, "payload": {}});
        let found = extract_credential(
            &empty,
            "PAYMENT-SIGNATURE",
            Some(&call(json!({}), json!({"org.paymentauth/credential": object.clone()}))),
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&crate::mpp::challenge::base64url_decode_nopad(&found.value).unwrap())
                .unwrap(),
            object
        );
        assert_eq!(
            extract_credential(
                &headers,
                "PAYMENT-SIGNATURE",
                Some(&call(json!({"payment_signature": "body"}), json!({})))
            )
            .unwrap()
            .value,
            "x402-proof",
            "a header wins over the body"
        );
        assert!(!format!("{found:?}").contains(&found.value), "a credential is never printed");
    }

    #[test]
    fn an_mpp_credential_is_found_wherever_agent_pay_accepts_it() {
        let empty = HeaderMap::new();
        let credential = json!({"challenge": {"id": "c3", "realm": "r", "method": "tempo", "intent": "charge", "request": "e30"}, "payload": {}});
        let key = "org.paymentauth/credential";
        let expected = crate::mpp::challenge::base64url_encode_nopad(&serde_json::to_vec(&credential).unwrap());
        for (label, message) in [
            (
                "root _meta on tools/call",
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "_meta": {key: credential.clone()}, "params": {"name": "t"}}),
            ),
            (
                "root _meta on an A2A message",
                json!({"jsonrpc": "2.0", "id": 1, "method": "message/send", "_meta": {key: credential.clone()}, "params": {"message": {}}}),
            ),
            (
                "params _meta on a resource read",
                json!({"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": "x", "_meta": {key: credential.clone()}}}),
            ),
            (
                "params metadata on A2A",
                json!({"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {"metadata": {key: credential.clone()}, "message": {}}}),
            ),
            (
                "message metadata on A2A",
                json!({"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {"message": {"metadata": {key: credential.clone()}}}}),
            ),
        ] {
            let found = extract_credential(&empty, "PAYMENT-SIGNATURE", Some(&message));
            assert_eq!(found.map(|found| (found.rail, found.value)), Some((Rail::Mpp, expected.clone())), "{label}");
        }
        let listing = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"arguments": {"payment_signature": "sig"}}});
        assert_eq!(
            extract_credential(&empty, "PAYMENT-SIGNATURE", Some(&listing)),
            None,
            "an argument only counts on tools/call"
        );
    }

    #[test]
    fn credentials_are_stripped_from_every_placement_but_nothing_else_is() {
        let key = "org.paymentauth/credential";
        let mut call = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "_meta": {key: "r", "root": 1}, "params": {
            "name": "t", "arguments": {"value": 1, "payment_signature": "s", "payment_credential": "c"},
            "_meta": {key: "m", "progressToken": 3}, "metadata": {key: "a", "keep": true},
            "message": {"metadata": {key: "b"}, "text": "kept"}
        }});
        assert!(remove_body_credentials(&mut call));
        assert_eq!(
            call,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "_meta": {"root": 1}, "params": {
                "name": "t", "arguments": {"value": 1}, "_meta": {"progressToken": 3},
                "metadata": {"keep": true}, "message": {"text": "kept"}
            }})
        );

        let mut listing = json!({"jsonrpc": "2.0", "id": 1, "method": "prompts/get", "params": {
            "name": "p", "arguments": {"payment_signature": "an ordinary prompt argument"}, "_meta": {key: "m"}}});
        assert!(remove_body_credentials(&mut listing));
        assert_eq!(
            listing["params"],
            json!({"name": "p", "arguments": {"payment_signature": "an ordinary prompt argument"}}),
            "only a tools/call argument is a credential"
        );

        let mut untouched =
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "t", "arguments": {}}});
        let before = untouched.clone();
        assert!(!remove_body_credentials(&mut untouched));
        assert_eq!(untouched, before, "a request with no credential is not rewritten, empty arguments included");

        let mut headers = HeaderMap::new();
        headers.insert("payment-signature", HeaderValue::from_static("s"));
        headers.insert("x-payment", HeaderValue::from_static("s"));
        headers.append("authorization", HeaderValue::from_static("PAYMENT abc"));
        headers.append("authorization", HeaderValue::from_static("Bearer keep"));
        headers.insert("x-other", HeaderValue::from_static("kept"));
        strip_credential_headers(&mut headers, "X-PAYMENT");
        assert_eq!(headers.len(), 2);
        assert_eq!(headers["x-other"], "kept");
        assert_eq!(headers["authorization"], "Bearer keep", "only the payment authorization goes");
        let mut bearer = HeaderMap::new();
        bearer.insert("authorization", HeaderValue::from_static("Bearer keep"));
        strip_credential_headers(&mut bearer, "PAYMENT-SIGNATURE");
        assert_eq!(bearer["authorization"], "Bearer keep");

        let mut json_headers = json!({"PAYMENT-SIGNATURE": "s", "Authorization": "payment abc", "accept": "a"})
            .as_object()
            .unwrap()
            .clone();
        strip_credential_json_headers(&mut json_headers, "PAYMENT-SIGNATURE");
        assert_eq!(Value::Object(json_headers), json!({"accept": "a"}));
        let mut array_headers = json!({"authorization": ["Bearer x", "Payment abc"], "x-payment": "s", "accept": "a"})
            .as_object()
            .unwrap()
            .clone();
        strip_credential_json_headers(&mut array_headers, "X-PAYMENT");
        assert_eq!(
            Value::Object(array_headers),
            json!({"authorization": ["Bearer x"], "accept": "a"}),
            "an array-valued authorization loses only its payment values"
        );
        let mut payment_only = json!({"authorization": ["Payment abc", "payment def"], "accept": "a"})
            .as_object()
            .unwrap()
            .clone();
        strip_credential_json_headers(&mut payment_only, "PAYMENT-SIGNATURE");
        assert_eq!(Value::Object(payment_only), json!({"accept": "a"}), "an authorization with none left goes");
        let mut bearer_array = json!({"authorization": ["Bearer x"]})
            .as_object()
            .unwrap()
            .clone();
        strip_credential_json_headers(&mut bearer_array, "PAYMENT-SIGNATURE");
        assert_eq!(Value::Object(bearer_array), json!({"authorization": ["Bearer x"]}));
    }

    #[test]
    fn an_intake_removes_the_credential_even_from_a_request_it_does_not_charge() {
        let surface =
            mcp_surface("gw-intake", json!({"mcp_payment_triggers": {"mode": "match", "patterns": ["^paid_"]}}));
        let credential = unique("proof");
        let free = tool_call("free_tool", json!({"q": 1, "payment_signature": credential}));
        let intake = read(&surface, &x402_headers(&credential), &free);
        assert!(!intake.chargeable);
        assert!(!intake.is_unpaid());
        assert_eq!(
            serde_json::from_slice::<Value>(intake.body()).unwrap()["params"]["arguments"],
            json!({"q": 1}),
            "the credential never reaches the Target on a free request"
        );
        let mut headers = x402_headers(&credential);
        headers.insert("x-keep", HeaderValue::from_static("1"));
        intake.strip_headers(&mut headers);
        assert!(
            headers
                .get("payment-signature")
                .is_none()
        );
        assert_eq!(headers["x-keep"], "1");
        assert!(!format!("{intake:?}").contains(&credential), "an intake never prints the credential");
    }

    #[test]
    fn an_intake_reads_chargeability_credential_and_price_once() {
        let surface = mcp_surface(
            "gw-input",
            json!({"mcp_payment_triggers": {"mode": "all"}, "manifest_snapshot": {
                "amount": {"amount": "5", "unit": "USDC"}, "payment_points": [{"id": "p", "protocol": "mpp"}]
            }}),
        );
        let unpaid = read(&surface, &HeaderMap::new(), &tool_call("t", json!({})));
        assert_eq!(
            serde_json::to_value(unpaid.policy_input()).unwrap(),
            json!({"required": true, "rail": "mpp", "amount": "5", "currency": "USDC"})
        );
        assert!(unpaid.is_unpaid());
        let credential = unique("proof");
        let listing = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let surface = mcp_surface(
            "gw-input",
            json!({"mcp_payment_triggers": {"mode": "match", "patterns": ["^paid_"]}, "manifest_snapshot": {
                "amount": {"amount": "5", "unit": "USDC"}, "payment_points": [{"id": "p", "protocol": "mpp"}]
            }}),
        );
        let free = read(&surface, &x402_headers(&credential), listing);
        assert_eq!(
            serde_json::to_value(free.policy_input()).unwrap(),
            json!({"required": false, "rail": "x402", "amount": "5", "currency": "USDC"}),
            "the rail of a presented credential wins over the manifest's"
        );
        let both = mcp_surface(
            "gw-input",
            json!({"mcp_payment_triggers": {"mode": "all"}, "manifest_snapshot": {
                "payment_points": [{"id": "a", "protocol": "mpp"}, {"id": "b", "protocol": "x402"}]
            }}),
        );
        let ambiguous = read(&both, &HeaderMap::new(), &tool_call("t", json!({})));
        assert_eq!(serde_json::to_value(ambiguous.policy_input()).unwrap(), json!({"required": true}));
        assert!(
            Intake::read(
                &AgentSurface::default(),
                Inbound {
                    method: "POST",
                    path_and_query: "/",
                    variant: None,
                    headers: &HeaderMap::new(),
                    body: &Bytes::new(),
                    mcp_context: None,
                    signature_header: "PAYMENT-SIGNATURE",
                }
            )
            .is_none()
        );
    }

    #[test]
    fn discovery_requests_are_never_chargeable() {
        let surface = a2a_surface("gw-card", json!({"require_all": true}));
        let card = read_with(
            &surface,
            Read {
                method: "GET",
                path_and_query: "/.well-known/agent-card.json",
                variant: None,
                headers: &HeaderMap::new(),
                body: b"",
                mcp_context: None,
            },
        );
        assert!(!card.chargeable);
        assert!(!card.is_unpaid());
        assert_eq!(serde_json::to_value(card.policy_input()).unwrap(), json!({"required": false}));
    }

    #[test]
    fn the_payment_resource_is_the_path_without_its_query() {
        let surface = a2a_surface("gw-resource", json!({"require_all": true}));
        let credential = unique("proof");
        let intake = read_with(
            &surface,
            Read {
                method: "POST",
                path_and_query: "/v1/report?api_key=SECRET&x=1#frag",
                variant: None,
                headers: &x402_headers(&credential),
                body: br#"{"order":1}"#,
                mcp_context: None,
            },
        );
        assert_eq!(intake.resource, "/v1/report");
        assert_eq!(intake.path, "/v1/report");
        let long = format!("/{}", "a".repeat(5000));
        let clipped = read_with(
            &surface,
            Read {
                method: "POST",
                path_and_query: &long,
                variant: None,
                headers: &HeaderMap::new(),
                body: b"",
                mcp_context: None,
            },
        );
        assert_eq!(clipped.path.chars().count(), MAX_PATH_CHARS);
        assert_eq!(
            clipped
                .resource
                .chars()
                .count(),
            MAX_RESOURCE_CHARS
        );
    }

    #[tokio::test]
    async fn the_gate_never_sends_a_query_string_to_agent_pay() {
        let gate = paid_gate();
        install_test_transport("gw-query", gate.clone());
        let surface = a2a_surface("gw-query", json!({"require_all": true}));
        let credential = unique("proof");
        let intake = read_with(
            &surface,
            Read {
                method: "GET",
                path_and_query: "/v1/report?api_key=SECRET",
                variant: None,
                headers: &x402_headers(&credential),
                body: b"",
                mcp_context: None,
            },
        );
        let fabric = no_fabric();
        let (outcome, events) = crate::audit::producer::capture(charge(&intake, call(&surface, &fabric))).await;
        assert!(matches!(outcome, GateOutcome::Paid(_)));
        let sent = gate.last();
        assert_eq!(sent.path, "/v1/report");
        assert_eq!(sent.body["resource"], "/v1/report");
        assert_eq!(sent.payment_context["intent"]["resource_id"], "/v1/report");
        assert!(
            !sent
                .payment_context
                .to_string()
                .contains("SECRET")
        );
        let (details, _) = payment_events(&events)
            .into_iter()
            .next()
            .expect("a payment event");
        assert_eq!(
            details
                .delegation
                .unwrap()
                .resource
                .as_deref(),
            Some("/v1/report")
        );
    }

    #[test]
    fn the_idempotency_key_follows_the_credential_and_the_request() {
        let surface = mcp_surface("gw-key", json!({"require_all": true}));
        let credential = unique("proof");
        let key = |method: &str, path: &str, variant: Option<&str>, credential: &str, body: Value| {
            read_with(
                &surface,
                Read {
                    method,
                    path_and_query: path,
                    variant,
                    headers: &x402_headers(credential),
                    body: body.to_string().as_bytes(),
                    mcp_context: None,
                },
            )
            .key
            .expect("a credential gives a key")
        };
        let request = |id: Value, tool: &str, arguments: Value| json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": arguments}});
        let base = key("POST", "/mcp", Some("gold"), &credential, request(json!(1), "premium_a", json!({"q": 1})));
        assert_eq!(base.len(), 64);
        assert!(
            base.bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
        assert!(!base.contains(&credential), "the key never shows the credential");
        assert_eq!(
            base,
            key("POST", "/mcp", Some("gold"), &credential, request(json!(2), "premium_a", json!({"q": 1}))),
            "a retry under a new JSON-RPC id is the same request"
        );
        assert_eq!(
            base,
            key(
                "POST",
                "/mcp",
                Some("gold"),
                &credential,
                json!({"params": {"arguments": {"q": 1}, "name": "premium_a"}, "method": "tools/call", "jsonrpc": "2.0", "id": "x"})
            ),
            "key order is not part of the request"
        );
        for (label, other) in [
            ("tool", key("POST", "/mcp", Some("gold"), &credential, request(json!(1), "premium_b", json!({"q": 1})))),
            (
                "arguments",
                key("POST", "/mcp", Some("gold"), &credential, request(json!(1), "premium_a", json!({"q": 2}))),
            ),
            ("path", key("POST", "/other", Some("gold"), &credential, request(json!(1), "premium_a", json!({"q": 1})))),
            (
                "query",
                key("POST", "/mcp?x=1", Some("gold"), &credential, request(json!(1), "premium_a", json!({"q": 1}))),
            ),
            ("method", key("PUT", "/mcp", Some("gold"), &credential, request(json!(1), "premium_a", json!({"q": 1})))),
            (
                "variant",
                key("POST", "/mcp", Some("silver"), &credential, request(json!(1), "premium_a", json!({"q": 1}))),
            ),
            ("no variant", key("POST", "/mcp", None, &credential, request(json!(1), "premium_a", json!({"q": 1})))),
            (
                "credential",
                key("POST", "/mcp", Some("gold"), &unique("other"), request(json!(1), "premium_a", json!({"q": 1}))),
            ),
        ] {
            assert_ne!(base, other, "a different {label} is a different key");
        }
    }

    #[test]
    fn the_idempotency_key_is_the_documented_digest_of_the_request() {
        use sha2::{Digest, Sha256};

        let surface = mcp_surface("gw-doc", json!({"require_all": true}));
        let credential = unique("proof");
        let body = br#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"t","arguments":{"b":2,"a":[1,{"d":4,"c":3}]}}}"#;
        let intake = read_with(
            &surface,
            Read {
                method: "POST",
                path_and_query: "/mcp?x=1",
                variant: None,
                headers: &x402_headers(&credential),
                body,
                mcp_context: None,
            },
        );
        let hex = |data: &[u8]| format!("{:x}", Sha256::digest(data));
        let digest = hex(
            b"POST\n/mcp?x=1\n\n{\"method\":\"tools/call\",\"params\":{\"arguments\":{\"a\":[1,{\"c\":3,\"d\":4}],\"b\":2},\"name\":\"t\"}}",
        );
        assert_eq!(intake.key, Some(hex(format!("paid-mcp\npay-1\n{digest}\n{credential}").as_bytes())));

        let raw = read_with(
            &surface,
            Read {
                method: "POST",
                path_and_query: "/mcp",
                variant: None,
                headers: &x402_headers(&credential),
                body: b"raw, not json",
                mcp_context: None,
            },
        );
        let digest = hex(b"POST\n/mcp\n\nraw, not json");
        assert_eq!(
            raw.key,
            Some(hex(format!("paid-mcp\npay-1\n{digest}\n{credential}").as_bytes())),
            "a body that is not JSON-RPC counts as its bytes"
        );
        assert_eq!(read(&surface, &HeaderMap::new(), body).key, None, "a request without a credential has no key");
    }

    #[test]
    fn canonical_json_sorts_keys_at_every_depth() {
        let mut out = Vec::new();
        write_canonical(&json!({"b": [3, {"z": null, "a": "x\"y"}], "a": true, "c": 1.5}), &mut out);
        assert_eq!(String::from_utf8(out).unwrap(), r#"{"a":true,"b":[3,{"a":"x\"y","z":null}],"c":1.5}"#);
    }

    #[test]
    fn gate_headers_carry_only_the_allow_list() {
        let x402 = Credential {
            rail: Rail::X402,
            value: "proof".into(),
        };
        let headers = gate_headers(Some(&x402), Some("req-1"), "00-egress-span-01");
        assert_eq!(
            headers,
            HashMap::from([
                ("content-type".to_string(), "application/json".to_string()),
                ("traceparent".to_string(), "00-egress-span-01".to_string()),
                ("x-request-id".to_string(), "req-1".to_string()),
                ("PAYMENT-SIGNATURE".to_string(), "proof".to_string()),
            ])
        );
        let mpp = Credential {
            rail: Rail::Mpp,
            value: "token".into(),
        };
        let headers = gate_headers(Some(&mpp), None, "tp");
        assert_eq!(headers["authorization"], "Payment token");
        assert_eq!(headers.len(), 3);
    }

    #[test]
    fn an_intake_keeps_only_a_usable_request_id() {
        let surface = mcp_surface("gw-id", json!({"require_all": true}));
        let mut headers = HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("sid=secret"));
        headers.insert("x-request-id", HeaderValue::from_static("req-1"));
        assert_eq!(
            read(&surface, &headers, b"")
                .request_id
                .as_deref(),
            Some("req-1")
        );
        headers.insert("x-request-id", HeaderValue::from_str(&"x".repeat(200)).unwrap());
        assert_eq!(read(&surface, &headers, b"").request_id, None);
    }

    #[test]
    fn traceparent_continues_the_egress_trace_with_a_fresh_span() {
        let trace = "0af76519-16cd-43dd-8448-eb211c80319c";
        let first = traceparent(trace);
        let parts: Vec<&str> = first.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!((parts[0], parts[1], parts[3]), ("00", "0af7651916cd43dd8448eb211c80319c", "01"));
        assert_eq!(parts[2].len(), 16);
        assert_ne!(first, traceparent(trace));
        let hashed = traceparent("not-a-uuid");
        assert_eq!(
            hashed
                .split('-')
                .nth(1)
                .unwrap()
                .len(),
            32
        );
    }

    fn jwt_identity(claims: Value) -> crate::source_auth::AuthenticatedIdentity {
        crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject: claims["sub"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            claims,
        }
    }

    #[test]
    fn payment_context_never_fabricates_a_chain_and_shares_email_only_when_opted_in() {
        let snapshot =
            json!({"amount": {"amount": "0.25", "unit": "USD"}, "payment_points": [{"id": "p", "protocol": "x402"}]});
        let mut policy = policy(json!({"manifest_snapshot": snapshot}));
        policy.payment_surface_id = "pay-1".into();
        let identity =
            jwt_identity(json!({"sub": "user-1", "iss": "https://idp", "tid": "t1", "email": "a@b.example"}));
        let caller = Caller {
            identity: Some(&identity),
            verified_agent_did: None,
        };
        let context = build_payment_context("s1", &policy, None, "premium", &caller, None, "trace-1", "00-t-s-01");
        assert_eq!(
            context,
            json!({
                "payer_identity": {"jwt_claims": {"iss": "https://idp", "tid": "t1", "oid": "user-1"}},
                "intent": {"merchant": "s1", "resource_id": "premium", "amount": "0.25", "currency": "USD"},
                "correlation": {"thid": "trace-1", "trace_context": "00-t-s-01"}
            })
        );
        policy.share_payer_email = true;
        let identity = jwt_identity(json!({"sub": "user-1", "oid": "object-1", "email": "a@b.example"}));
        let anonymous = build_payment_context("s1", &policy, None, "r", &Caller::default(), None, "t", "tp");
        assert!(
            anonymous
                .get("payer_identity")
                .is_none()
        );
        let caller = Caller {
            identity: Some(&identity),
            verified_agent_did: Some("did:example:agent"),
        };
        let context = build_payment_context("s1", &policy, None, "r", &caller, Some("key"), "t", "tp");
        assert_eq!(
            context["payer_identity"],
            json!({"did": "did:example:agent", "jwt_claims": {"oid": "object-1"}, "email": "a@b.example"}),
            "with no chain the payer is the verified agent"
        );
        assert_eq!(context["correlation"]["idempotency_key"], "key");
        assert!(
            context
                .get("principal_chain")
                .is_none()
        );
        for invalid in [
            json!([{"did": "not-a-did"}]),
            json!([{"did": "did:example:a", "unknown": true}]),
            json!([]),
            json!("did:example:a"),
        ] {
            let body = json!({"params": {"_meta": {"org.paymentauth/payment_context": {"principal_chain": invalid}}}});
            assert!(
                build_payment_context("s1", &policy, Some(&body), "r", &Caller::default(), None, "t", "tp")
                    .get("principal_chain")
                    .is_none()
            );
        }
    }

    #[test]
    fn a_principal_chain_is_forwarded_only_without_a_competing_payer_did() {
        let policy = policy(json!({}));
        let identity = jwt_identity(json!({"sub": "user-1"}));
        let chain = json!([{"did": "did:example:principal", "role": "owner"}, {"did": "did:example:agent"}]);
        let mcp =
            json!({"params": {"_meta": {"org.paymentauth/payment_context": {"principal_chain": chain, "other": 1}}}});
        let a2a = json!({"params": {"message": {"metadata": {"org.paymentauth/payment_context": {"principal_chain": chain}}}}});

        let agent = Caller {
            identity: Some(&identity),
            verified_agent_did: Some("did:example:agent"),
        };
        for body in [&mcp, &a2a] {
            let context = build_payment_context("s1", &policy, Some(body), "r", &agent, None, "t", "tp");
            assert_eq!(context["principal_chain"], chain);
            assert_eq!(
                context["payer_identity"],
                json!({"jwt_claims": {"oid": "user-1"}}),
                "agent-pay takes the payer from the chain's root, so the agent's DID is not sent beside it"
            );
        }

        let unverified = Caller {
            identity: Some(&identity),
            verified_agent_did: None,
        };
        let context = build_payment_context("s1", &policy, Some(&mcp), "r", &unverified, None, "t", "tp");
        assert!(
            context
                .get("principal_chain")
                .is_none(),
            "a chain asserted by a caller this gateway did not verify as an agent is dropped"
        );
        assert_eq!(context["payer_identity"], json!({"jwt_claims": {"oid": "user-1"}}));

        let someone_else = Caller {
            identity: Some(&identity),
            verified_agent_did: Some("did:example:other-agent"),
        };
        let context = build_payment_context("s1", &policy, Some(&mcp), "r", &someone_else, None, "t", "tp");
        assert!(
            context
                .get("principal_chain")
                .is_none(),
            "a chain that does not end at the verified agent is not the caller's, and is dropped"
        );
        assert_eq!(context["payer_identity"]["did"], "did:example:other-agent");
    }

    #[test]
    fn the_audit_payer_is_a_peppered_hash_of_the_principal() {
        use sha2::{Digest, Sha256};

        let identity = crate::source_auth::AuthenticatedIdentity::ApiKey { key_name: "acme-prod".into() };
        let payer = Caller {
            identity: Some(&identity),
            verified_agent_did: None,
        }
        .audit_payer()
        .unwrap();
        assert_eq!(payer.len(), 64);
        assert_ne!(
            payer,
            format!("{:x}", Sha256::digest(b"api-key:acme-prod")),
            "a plain digest of an enumerable key name can be reversed by a dictionary"
        );
        assert_eq!(payer, crate::identity::credential_identity::hash_credential(&[("payer", "api-key:acme-prod")]));
        let verified = Caller {
            identity: Some(&identity),
            verified_agent_did: Some("did:example:agent"),
        };
        assert_eq!(
            verified
                .audit_payer()
                .as_deref(),
            Some("did:example:agent")
        );
        assert_eq!(Caller::default().audit_payer(), None);
    }

    fn receipt(rail: Rail) -> Receipt {
        Receipt {
            rail,
            value: "receipt-value".into(),
            vc_fingerprint: None,
            cache_control: Some("no-store".into()),
            claim: None,
            authorization: None,
        }
    }

    fn header_map(pairs: &[(&str, &str)]) -> HashMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(name, value)| (name.to_string(), vec![value.to_string()]))
            .collect()
    }

    #[test]
    fn a_payment_authorization_is_read_with_its_deadline_and_an_unusable_one_refused() {
        assert_eq!(held_funds(&header_map(&[("payment-receipt", "r")])), Ok(None), "no header: already captured");
        let held = held_funds(&header_map(&[
            ("Payment-Authorization", "auth_1.a-b~c"),
            ("Payment-Capture-Deadline", &(chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339()),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(held.authorization_id, "auth_1.a-b~c");
        let in_an_hour = held.capture_deadline - chrono::Utc::now();
        assert!(in_an_hour > chrono::Duration::minutes(59) && in_an_hour <= chrono::Duration::hours(1));

        for (named, bound) in
            [("2099-01-01T00:00:00Z", MAX_CAPTURE_WINDOW), ("2000-01-01T00:00:00Z", MIN_CAPTURE_WINDOW)]
        {
            let clamped =
                held_funds(&header_map(&[("payment-authorization", "auth-3"), ("payment-capture-deadline", named)]))
                    .unwrap()
                    .unwrap()
                    .capture_deadline
                    - chrono::Utc::now();
            assert!(clamped <= bound && clamped > bound - chrono::Duration::seconds(5), "{named}: {clamped}");
        }

        let before = chrono::Utc::now();
        let defaulted =
            held_funds(&header_map(&[("payment-authorization", "auth-2"), ("payment-capture-deadline", "tomorrow")]))
                .unwrap()
                .unwrap();
        assert!(defaulted.capture_deadline >= before + DEFAULT_CAPTURE_WINDOW);
        assert!(defaulted.capture_deadline <= chrono::Utc::now() + DEFAULT_CAPTURE_WINDOW);

        for unusable in ["", "has space", "slash/inside", &"a".repeat(MAX_AUTHORIZATION_CHARS + 1)] {
            assert!(
                matches!(
                    held_funds(&header_map(&[("payment-authorization", unusable)])),
                    Err(PaymentDelegationDecision::Unconfirmed { .. })
                ),
                "{unusable:?}"
            );
        }
    }

    #[test]
    fn a_target_delivered_only_with_a_success_status_and_no_json_rpc_error() {
        let ok = StatusCode::OK;
        let result = br#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        let error = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x"}}"#;
        assert!(delivered(&ChannelProtocol::Mcp, ok, Some(result)));
        assert!(delivered(&ChannelProtocol::Mcp, ok, None), "a streamed body is judged by its status");
        assert!(!delivered(&ChannelProtocol::Mcp, ok, Some(error)));
        assert!(
            !delivered(&ChannelProtocol::Mcp, ok, Some(br#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1}}"#)),
            "a message with an error and a result is not delivered"
        );
        assert!(!delivered(
            &ChannelProtocol::A2a,
            ok,
            Some(b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":1}}\n\n")
        ));
        assert!(delivered(&ChannelProtocol::A2a, ok, Some(b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n")));
        assert!(!delivered(&ChannelProtocol::Mcp, StatusCode::BAD_GATEWAY, Some(result)));
        assert!(
            delivered(&ChannelProtocol::DIDComm, StatusCode::CREATED, Some(error)),
            "only JSON-RPC bodies are read"
        );
        assert!(!delivered(&ChannelProtocol::DIDComm, StatusCode::NOT_FOUND, None));
    }

    #[test]
    fn the_charged_price_is_the_receipts_and_a_difference_is_flagged() {
        let quoted = || (Some("0.50".to_string()), Some("USD".to_string()));
        let facts = |amount: Option<&str>, currency: Option<&str>| ReceiptFacts {
            amount: amount.map(str::to_string),
            currency: currency.map(str::to_string),
            ..ReceiptFacts::default()
        };
        assert_eq!(
            charged_price(&facts(None, None), quoted()),
            (Some("0.50".to_string()), Some("USD".to_string()), false),
            "without a receipt amount the manifest price is recorded"
        );
        assert_eq!(
            charged_price(&facts(Some("0.5"), Some("usd")), quoted()),
            (Some("0.5".to_string()), Some("usd".to_string()), false)
        );
        assert_eq!(
            charged_price(&facts(Some("0.75"), None), quoted()),
            (Some("0.75".to_string()), Some("USD".to_string()), true)
        );
        assert_eq!(
            charged_price(&facts(Some("0.50"), Some("EUR")), quoted()),
            (Some("0.50".to_string()), Some("EUR".to_string()), true)
        );
        assert_eq!(charged_price(&facts(Some("1"), None), (None, None)), (Some("1".to_string()), None, false));
        assert!(!charged_price(&facts(Some("50"), Some("USD")), quoted()).2, "50 cents is 0.50 USD");
        assert!(charged_price(&facts(Some("75"), Some("USD")), quoted()).2);
        assert!(!charged_price(&facts(Some("0.500"), None), quoted()).2);
        let usdc = (Some("0.5".to_string()), Some("USDC".to_string()));
        assert!(!charged_price(&facts(Some("500000"), Some("USDC")), usdc.clone()).2);
        assert!(charged_price(&facts(Some("50"), Some("USDC")), usdc).2, "50 base units of USDC is not 0.5");
        let with_decimals = ReceiptFacts {
            amount: Some("5000".to_string()),
            currency: Some("USD".to_string()),
            decimals: Some(4),
            ..ReceiptFacts::default()
        };
        assert!(!charged_price(&with_decimals, quoted()).2, "the receipt's decimals are used");
        let wrong_decimals = ReceiptFacts {
            decimals: Some(2),
            ..with_decimals
        };
        assert!(charged_price(&wrong_decimals, quoted()).2);
        assert!(charged_price(&facts(Some("abc"), None), quoted()).2, "an unreadable amount differs");
        let read = receipt_facts(&base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            br#"{"reference":"pi_1","amount":75,"currency":"USD"}"#,
        ));
        assert_eq!((read.amount.as_deref(), read.currency.as_deref()), (Some("75"), Some("USD")));
    }

    fn authorizing_gate(authorization_id: &str) -> Arc<MockGate> {
        MockGate::answering(
            200,
            &[
                ("Payment-Receipt", "authorization-receipt"),
                ("payment-authorization", authorization_id),
                ("payment-capture-deadline", "2099-01-01T00:00:00Z"),
            ],
            json!({}),
        )
    }

    fn json_response(
        status: StatusCode,
        body: Value,
    ) -> Response {
        (status, [(axum::http::header::CONTENT_TYPE, "application/json")], body.to_string()).into_response()
    }

    async fn streaming_held_receipt(
        authorization_id: &str,
        answer: crate::payments_ledger::settlement::SettlementStatus,
    ) -> (Receipt, Arc<crate::payments_ledger::settlement::tests::Scripted>) {
        use crate::payments_ledger::settlement::{SettlementAnswer, tests::Scripted};

        let gateway = unique("gw-stream");
        let authorization_receipt = format!("authorization-receipt-{authorization_id}");
        install_test_transport(
            &gateway,
            MockGate::answering(
                200,
                &[
                    ("Payment-Receipt", authorization_receipt.as_str()),
                    ("payment-authorization", authorization_id),
                    ("payment-capture-deadline", "2099-01-01T00:00:00Z"),
                ],
                json!({}),
            ),
        );
        let settlement = Scripted::settling(vec![Ok(SettlementAnswer {
            status: answer,
            authorization_id: Some(authorization_id.to_string()),
            receipt: Some("capture-receipt".to_string()),
            reason: None,
        })]);
        crate::payments_ledger::settlement::install_test_client(&gateway, settlement.clone());
        let surface = mcp_surface(&gateway, json!({"require_all": true}));
        let fabric = no_fabric();
        let intake = read(&surface, &x402_headers(&unique("proof")), &tool_call("t", json!({})));
        (dispatched(&intake, call(&surface, &fabric)).await, settlement)
    }

    fn event_stream(chunks: Vec<Result<&'static str, &'static str>>) -> Response {
        let stream = futures::stream::iter(
            chunks
                .into_iter()
                .map(|chunk| {
                    chunk
                        .map(|text| Bytes::from_static(text.as_bytes()))
                        .map_err(axum::Error::new)
                }),
        );
        (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
            axum::body::Body::from_stream(stream),
        )
            .into_response()
    }

    fn settled_actions(
        settlement: &crate::payments_ledger::settlement::tests::Scripted
    ) -> Vec<crate::payments_ledger::SettleAction> {
        settlement
            .settled
            .lock()
            .unwrap()
            .iter()
            .map(|(_, action, _)| *action)
            .collect()
    }

    #[tokio::test]
    async fn a_streamed_answer_is_returned_before_capture_and_ends_with_the_capture_receipt() {
        use crate::payments_ledger::{SettleAction, settlement::SettlementStatus};

        let (receipt, settlement) = streaming_held_receipt("auth-s1", SettlementStatus::Captured).await;
        let response = receipt
            .settle_response(
                &ChannelProtocol::Mcp,
                event_stream(vec![Ok("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"res"), Ok("ult\":{}}\n\n")]),
            )
            .await;
        assert_eq!(settled_actions(&settlement), vec![], "nothing is captured before the stream is read");
        assert_eq!(response.headers()["payment-response"], "authorization-receipt-auth-s1");
        assert!(
            response
                .headers()
                .get(AUTHORIZATION_HEADER)
                .is_none()
                && response
                    .headers()
                    .get(CAPTURE_DEADLINE_HEADER)
                    .is_none(),
            "the authorization is never relayed to the caller"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.starts_with("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"));
        let tail = body
            .split("event: payment-receipt\ndata: ")
            .nth(1)
            .expect("a receipt event ends the stream");
        let event: Value = serde_json::from_str(tail.trim_end()).unwrap();
        assert_eq!(event, json!({"rail": "x402", "receipt": "capture-receipt", "authorization_id": "auth-s1"}));
        assert_eq!(settled_actions(&settlement), vec![SettleAction::Capture]);
    }

    #[tokio::test]
    async fn a_streamed_json_rpc_error_voids_and_carries_no_receipt_event() {
        use crate::payments_ledger::{SettleAction, settlement::SettlementStatus};

        let (receipt, settlement) = streaming_held_receipt("auth-s2", SettlementStatus::Voided).await;
        let response = receipt
            .settle_response(
                &ChannelProtocol::Mcp,
                event_stream(vec![Ok(
                    "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-1,\"message\":\"x\"}}\n\n",
                )]),
            )
            .await;
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("payment-receipt"));
        assert_eq!(settled_actions(&settlement), vec![SettleAction::Void]);
    }

    #[tokio::test]
    async fn a_failed_upstream_stream_voids() {
        use crate::payments_ledger::{SettleAction, settlement::SettlementStatus};

        let (receipt, settlement) = streaming_held_receipt("auth-s3", SettlementStatus::Voided).await;
        let response = receipt
            .settle_response(
                &ChannelProtocol::Mcp,
                event_stream(vec![Ok("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"), Err("reset")]),
            )
            .await;
        assert!(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .is_err()
        );
        assert_eq!(settled_actions(&settlement), vec![SettleAction::Void]);
    }

    #[tokio::test]
    async fn a_capture_whose_caller_goes_away_still_completes_and_is_never_voided() {
        use crate::payments_ledger::{SettleAction, settlement::SettlementStatus};

        let (receipt, settlement) = streaming_held_receipt("auth-s5", SettlementStatus::Captured).await;
        {
            let capture = receipt.settled(true);
            futures::pin_mut!(capture);
            assert!(futures::poll!(capture.as_mut()).is_pending());
        }
        drop(receipt);
        for _ in 0..200 {
            if !settled_actions(&settlement).is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(settled_actions(&settlement), vec![SettleAction::Capture]);
    }

    #[tokio::test]
    async fn a_client_leaving_a_stream_before_it_completes_voids() {
        use crate::payments_ledger::{SettleAction, settlement::SettlementStatus};

        let (receipt, settlement) = streaming_held_receipt("auth-s4", SettlementStatus::Voided).await;
        let response = receipt
            .settle_response(&ChannelProtocol::Mcp, event_stream(vec![Ok("data: {}\n\n"), Ok("data: {}\n\n")]))
            .await;
        let mut stream = response
            .into_body()
            .into_data_stream();
        assert_eq!(
            futures::StreamExt::next(&mut stream)
                .await
                .unwrap()
                .unwrap(),
            Bytes::from_static(b"data: {}\n\n")
        );
        drop(stream);
        drop(receipt);
        for _ in 0..200 {
            if !settled_actions(&settlement).is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(settled_actions(&settlement), vec![SettleAction::Void]);
    }

    #[tokio::test]
    async fn held_funds_are_captured_when_the_target_delivers_and_the_capture_receipt_returned() {
        use crate::payments_ledger::settlement::{SettlementAnswer, SettlementStatus, tests::Scripted};

        let gateway = unique("gw-capture");
        install_test_transport(&gateway, authorizing_gate("auth-c"));
        let settlement = Scripted::settling(vec![Ok(SettlementAnswer {
            status: SettlementStatus::Captured,
            authorization_id: Some("auth-c".to_string()),
            receipt: Some("capture-receipt".to_string()),
            reason: None,
        })]);
        crate::payments_ledger::settlement::install_test_client(&gateway, settlement.clone());
        let surface = mcp_surface(&gateway, json!({"require_all": true}));
        let fabric = no_fabric();
        let intake = read(&surface, &x402_headers(&unique("proof")), &tool_call("t", json!({})));
        let receipt = dispatched(&intake, call(&surface, &fabric)).await;
        assert!(
            receipt
                .authorization
                .is_some()
        );

        let result = receipt
            .attach_to_result(
                &ChannelProtocol::Mcp,
                Ok(json_response(StatusCode::OK, json!({"jsonrpc": "2.0", "id": 1, "result": {}}))),
            )
            .await;

        let (status, headers, body) = body_json(result.unwrap()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["payment-response"], "capture-receipt");
        assert_eq!(body["result"]["_meta"][RECEIPT_META], "capture-receipt");
        assert_eq!(
            settlement
                .settled
                .lock()
                .unwrap()
                .clone(),
            vec![("auth-c".to_string(), crate::payments_ledger::SettleAction::Capture, None)]
        );
        drop(receipt);
        tokio::task::yield_now().await;
        assert_eq!(
            settlement
                .settled
                .lock()
                .unwrap()
                .len(),
            1,
            "a settled authorization is not voided on drop"
        );
    }

    #[tokio::test]
    async fn held_funds_are_voided_and_no_receipt_attached_when_the_target_fails() {
        use crate::payments_ledger::settlement::{SettlementStatus, tests::Scripted, tests::answer};

        let gateway = unique("gw-void");
        install_test_transport(&gateway, authorizing_gate("auth-v"));
        let settlement = Scripted::settling(vec![answer(SettlementStatus::Voided), answer(SettlementStatus::Voided)]);
        crate::payments_ledger::settlement::install_test_client(&gateway, settlement.clone());
        let surface = mcp_surface(&gateway, json!({"require_all": true}));
        let fabric = no_fabric();

        for failed in [
            Ok(json_response(
                StatusCode::OK,
                json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "x"}}),
            )),
            Err(json_response(StatusCode::BAD_GATEWAY, json!({"error": "upstream"}))),
        ] {
            let intake = read(&surface, &x402_headers(&unique("proof")), &tool_call("t", json!({})));
            let receipt = dispatched(&intake, call(&surface, &fabric)).await;
            let response = match receipt
                .attach_to_result(&ChannelProtocol::Mcp, failed)
                .await
            {
                Ok(response) | Err(response) => response,
            };
            assert!(
                response
                    .headers()
                    .get("payment-response")
                    .is_none(),
                "the caller was not charged"
            );
        }
        let sent = settlement
            .settled
            .lock()
            .unwrap()
            .clone();
        assert_eq!(
            sent,
            vec![
                ("auth-v".to_string(), crate::payments_ledger::SettleAction::Void, Some(NOT_DELIVERED.to_string()));
                2
            ]
        );
    }

    #[tokio::test]
    async fn held_funds_whose_receipt_is_dropped_unsettled_are_voided() {
        use crate::payments_ledger::settlement::{SettlementStatus, tests::Scripted, tests::answer};

        let gateway = unique("gw-drop");
        install_test_transport(&gateway, authorizing_gate("auth-d"));
        let settlement = Scripted::settling(vec![answer(SettlementStatus::Voided)]);
        crate::payments_ledger::settlement::install_test_client(&gateway, settlement.clone());
        let surface = mcp_surface(&gateway, json!({"require_all": true}));
        let fabric = no_fabric();
        let intake = read(&surface, &x402_headers(&unique("proof")), &tool_call("t", json!({})));
        let receipt = dispatched(&intake, call(&surface, &fabric)).await;
        receipt.revoke();
        drop(receipt);
        for _ in 0..100 {
            if !settlement
                .settled
                .lock()
                .unwrap()
                .is_empty()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            settlement
                .settled
                .lock()
                .unwrap()
                .clone(),
            vec![("auth-d".to_string(), crate::payments_ledger::SettleAction::Void, Some(NOT_DELIVERED.to_string()))]
        );
    }

    #[tokio::test]
    async fn an_answer_without_an_authorization_is_captured_already_and_sends_nothing() {
        use crate::payments_ledger::settlement::tests::Scripted;

        let gateway = unique("gw-immediate");
        install_test_transport(&gateway, paid_gate());
        let settlement = Arc::new(Scripted::default());
        crate::payments_ledger::settlement::install_test_client(&gateway, settlement.clone());
        let surface = mcp_surface(&gateway, json!({"require_all": true}));
        let fabric = no_fabric();
        let intake = read(&surface, &x402_headers(&unique("proof")), &tool_call("t", json!({})));
        let receipt = dispatched(&intake, call(&surface, &fabric)).await;
        assert!(
            receipt
                .authorization
                .is_none()
        );
        let failed = receipt
            .attach_to_result(&ChannelProtocol::Mcp, Err(json_response(StatusCode::BAD_GATEWAY, json!({}))))
            .await;
        assert_eq!(
            failed.unwrap_err().headers()["payment-response"],
            "the-receipt",
            "a failed request still carries its receipt"
        );
        assert!(
            settlement
                .settled
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_breaker_counts_its_opening_and_closing_once_each() {
        let gateway = unique("gw-transitions");
        let transitions = |state: &str| {
            crate::metrics::backends::prometheus::PAYMENT_GATE_BREAKER_TRANSITIONS
                .with_label_values(&[gateway.as_str(), state])
                .get()
        };
        let now = Instant::now();
        for _ in 0..DEFAULT_BREAKER_FAILURES + 2 {
            record_transport_result(&gateway, TransportOutcome::Failed, now);
        }
        assert_eq!((transitions("open"), transitions("closed")), (1, 0), "further failures keep it open");
        record_transport_result(&gateway, TransportOutcome::Reached, now);
        assert_eq!((transitions("open"), transitions("closed")), (1, 1));
        record_transport_result(&gateway, TransportOutcome::Reached, now);
        assert_eq!(transitions("closed"), 1, "a closed breaker does not close again");
    }

    #[test]
    fn a_breaker_snapshot_reads_closed_open_and_half_open() {
        let gateway = unique("gw-snapshot");
        let now = Instant::now();
        let settings = breaker_settings();
        let closed = breaker_snapshot(&gateway, now);
        assert_eq!((closed.state, closed.consecutive_failures, closed.retry_after_secs), ("closed", 0, None));
        assert_eq!(closed.failures_to_open, settings.failures);

        record_transport_result(&gateway, TransportOutcome::Failed, now);
        let counting = breaker_snapshot(&gateway, now);
        assert_eq!((counting.state, counting.consecutive_failures), ("closed", 1));

        for _ in 1..settings.failures {
            record_transport_result(&gateway, TransportOutcome::Failed, now);
        }
        let open = breaker_snapshot(&gateway, now);
        assert_eq!(open.state, "open");
        assert_eq!(open.consecutive_failures, settings.failures);
        assert_eq!(
            open.retry_after_secs,
            Some(
                settings
                    .open_for
                    .as_secs()
                    .max(1)
            )
        );

        let half_open = breaker_snapshot(&gateway, now + settings.open_for);
        assert_eq!((half_open.state, half_open.retry_after_secs), ("half_open", None));

        record_transport_result(&gateway, TransportOutcome::Reached, now);
        assert_eq!(breaker_snapshot(&gateway, now).state, "closed");
    }

    #[test]
    fn receipts_use_the_credential_rail_headers_and_json_rpc_metadata() {
        let headers = receipt(Rail::X402).headers();
        assert_eq!(
            headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.to_str().unwrap()))
                .collect::<Vec<_>>(),
            vec![("payment-response", "receipt-value"), ("cache-control", "no-store")]
        );
        assert_eq!(receipt(Rail::Mpp).headers()[0].0, "payment-receipt");
        let no_cache_control = Receipt {
            cache_control: None,
            ..receipt(Rail::Mpp)
        };
        assert_eq!(
            no_cache_control
                .headers()
                .len(),
            1
        );
        let mcp = br#"{"jsonrpc":"2.0","id":1,"result":{"content":[],"_meta":{"k":1}}}"#;
        let injected: Value = serde_json::from_slice(
            &receipt(Rail::X402)
                .inject_into_json(&ChannelProtocol::Mcp, mcp)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(injected["result"]["_meta"], json!({"k": 1, "org.paymentauth/receipt": "receipt-value"}));
        let a2a = br#"{"jsonrpc":"2.0","id":1,"result":{"kind":"message"}}"#;
        let injected: Value = serde_json::from_slice(
            &receipt(Rail::Mpp)
                .inject_into_json(&ChannelProtocol::A2a, a2a)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(injected["result"]["metadata"]["org.paymentauth/receipt"], "receipt-value");
        assert_eq!(
            receipt(Rail::X402).inject_into_json(&ChannelProtocol::Mcp, br#"{"jsonrpc":"2.0","id":1,"error":{}}"#),
            None
        );
        assert_eq!(receipt(Rail::X402).inject_into_json(&ChannelProtocol::DIDComm, mcp), None);
        let mut message = json!({"jsonrpc": "2.0", "id": 1, "result": {}});
        assert!(receipt(Rail::X402).inject_into_message(&ChannelProtocol::Mcp, &mut message));
        assert_eq!(message["result"]["_meta"]["org.paymentauth/receipt"], "receipt-value");
    }

    #[tokio::test]
    async fn attaching_a_receipt_covers_json_events_streams_and_failures() {
        let json_response = |status: StatusCode, body: &str| {
            (
                status,
                [
                    (axum::http::header::CONTENT_TYPE, "application/json"),
                    (axum::http::header::CACHE_CONTROL, "max-age=60"),
                ],
                body.to_string(),
            )
                .into_response()
        };
        let attached = receipt(Rail::Mpp)
            .attach(&ChannelProtocol::Mcp, json_response(StatusCode::OK, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#))
            .await;
        assert_eq!(attached.headers()["payment-receipt"], "receipt-value");
        assert_eq!(attached.headers()["cache-control"], "no-store", "the gate's cache-control replaces the Target's");
        let (_, _, body) = body_json(attached).await;
        assert_eq!(body["result"]["_meta"]["org.paymentauth/receipt"], "receipt-value");

        let events = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        let sse = ([(axum::http::header::CONTENT_TYPE, "text/event-stream")], events.to_string()).into_response();
        let attached = receipt(Rail::X402)
            .attach(&ChannelProtocol::Mcp, sse)
            .await;
        assert_eq!(attached.headers()["payment-response"], "receipt-value");
        let bytes = axum::body::to_bytes(attached.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(text.starts_with("event: message\ndata: "), "{text}");
        let data: Value = serde_json::from_str(
            text.lines()
                .nth(1)
                .unwrap()
                .strip_prefix("data: ")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(data["result"]["_meta"]["org.paymentauth/receipt"], "receipt-value");

        let stream = Response::new(axum::body::Body::from_stream(futures::stream::iter([Ok::<_, std::io::Error>(
            Bytes::from_static(b"data: {}\n\n"),
        )])));
        let attached = receipt(Rail::X402)
            .attach(&ChannelProtocol::Mcp, stream)
            .await;
        assert_eq!(attached.headers()["payment-response"], "receipt-value", "a streamed body carries the headers");

        let failed = receipt(Rail::Mpp)
            .attach_to_result(
                &ChannelProtocol::Mcp,
                Err(json_response(StatusCode::BAD_GATEWAY, r#"{"error":"upstream"}"#)),
            )
            .await;
        let Err(failed) = failed else { panic!("an error stays an error") };
        assert_eq!(failed.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            failed.headers()["payment-receipt"],
            "receipt-value",
            "a request paid for and then failed keeps its receipt"
        );
        let (_, _, body) = body_json(failed).await;
        assert_eq!(body, json!({"error": "upstream"}), "an error body is not rewritten");
        let ok = receipt(Rail::Mpp)
            .attach_to_result(
                &ChannelProtocol::Mcp,
                Ok(json_response(StatusCode::OK, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#)),
            )
            .await;
        assert!(matches!(ok, Ok(response) if response.headers().contains_key("payment-receipt")));
    }

    #[test]
    fn receipt_facts_read_mpp_and_x402_receipts() {
        use base64::Engine;

        let mpp = crate::mpp::challenge::base64url_encode_nopad(
            br#"{"status":"success","method":"tempo","reference":"0xabc","challengeId":"ch-1","timestamp":"t"}"#,
        );
        assert_eq!(
            receipt_facts(&mpp),
            ReceiptFacts {
                reference: Some("0xabc".into()),
                challenge_id: Some("ch-1".into()),
                method: Some("tempo".into()),
                ..Default::default()
            }
        );
        let x402 = base64::engine::general_purpose::STANDARD
            .encode(br#"{"success":true,"transaction":"0xdef","network":"base-sepolia","payer":"0x1"}"#);
        assert_eq!(
            receipt_facts(&x402),
            ReceiptFacts {
                reference: Some("0xdef".into()),
                network: Some("base-sepolia".into()),
                ..Default::default()
            }
        );
        assert_eq!(receipt_facts("not a receipt"), ReceiptFacts::default());
    }

    fn decision(
        status: u16,
        headers: &[(&str, &str)],
        body: Value,
    ) -> PaymentDelegationDecision {
        crate::x402::map_delegation_response(
            status,
            headers
                .iter()
                .map(|(name, value)| (name.to_string(), vec![value.to_string()]))
                .collect(),
            body.to_string().into_bytes(),
        )
    }

    #[tokio::test]
    async fn every_gate_answer_maps_to_http_and_json_rpc_responses() {
        use crate::mcp::errors::{application_error_codes, error_codes, payment_transport_error_codes};

        let modern = Shape::JsonRpc {
            id: Some(json!("call-1")),
            legacy_mcp: false,
        };
        let legacy = Shape::JsonRpc {
            id: Some(json!("call-1")),
            legacy_mcp: true,
        };
        let challenge_header = r#"Payment id="c1", realm="r", method="tempo", intent="charge", request="e30""#;
        let required = (application_error_codes::PAYMENT_REQUIRED, payment_transport_error_codes::PAYMENT_REQUIRED);
        let rejected =
            (application_error_codes::PAYMENT_REJECTED, payment_transport_error_codes::PAYMENT_VERIFICATION_FAILED);
        let internal = (error_codes::INTERNAL_ERROR, error_codes::INTERNAL_ERROR);
        // (decision, HTTP status, HTTP body, JSON-RPC HTTP status, (modern code, legacy code))
        type Case = (PaymentDelegationDecision, u16, Value, u16, (i32, i32));
        let cases: Vec<Case> = vec![
            (
                decision(
                    402,
                    &[
                        ("payment-required", "eyJ4IjoxfQ=="),
                        ("www-authenticate", challenge_header),
                        ("set-cookie", "x"),
                    ],
                    json!({"accepts": []}),
                ),
                402,
                json!({"accepts": []}),
                402,
                required,
            ),
            (
                decision(400, &[], json!({"error": "invalid_payment", "detail": "bad signature"})),
                402,
                json!({"error": "invalid_payment", "detail": "bad signature"}),
                402,
                rejected,
            ),
            (
                decision(
                    402,
                    &[("www-authenticate", challenge_header)],
                    json!({"type": "https://paymentauth.org/problems/verification-failed", "detail": "nope"}),
                ),
                402,
                json!({"type": "https://paymentauth.org/problems/verification-failed", "detail": "nope"}),
                402,
                rejected,
            ),
            (
                decision(202, &[], json!({"status": "held_for_oversight", "case_id": "case-9", "reason": "limit"})),
                202,
                json!({"status": "held_for_oversight", "case_id": "case-9", "reason": "limit"}),
                200,
                (application_error_codes::PAYMENT_PENDING, application_error_codes::PAYMENT_PENDING),
            ),
            (
                decision(403, &[], json!({"status": "rejected_by_oversight"})),
                403,
                json!({"error": "rejected_by_oversight"}),
                403,
                rejected,
            ),
            (
                decision(409, &[], json!({"error": "idempotency_key_conflict"})),
                409,
                json!({"error": "idempotency_key_conflict"}),
                409,
                rejected,
            ),
            (decision(410, &[], json!({})), 410, json!({"error": "payment_session_gone"}), 410, rejected),
            (
                decision(429, &[("retry-after", "9")], json!({"error": "rate_limited"})),
                429,
                json!({"error": "rate_limited"}),
                429,
                internal,
            ),
            (
                decision(500, &[], json!({})),
                502,
                json!({
                    "error": "payment_unconfirmed", "detail": "payment gateway returned unexpected status 500",
                    "retry_same_request": true, "retry_after": 2, "replay_window_secs": 120
                }),
                502,
                internal,
            ),
            (
                decision(409, &[], json!({"error": "idempotency_key_in_use"})),
                409,
                json!({"error": "payment_in_progress", "retry_same_request": true}),
                409,
                internal,
            ),
            (
                decision(403, &[], json!({"error": "Channel not exposed on this connection point"})),
                502,
                json!({"error": "payment_unavailable", "detail": "payment gateway refused the request"}),
                502,
                internal,
            ),
            (
                PaymentDelegationDecision::deny(504, "payment gateway did not answer in time"),
                504,
                json!({"error": "payment_unavailable", "detail": "payment gateway did not answer in time"}),
                504,
                internal,
            ),
            (
                decision(503, &[], json!({"error": "payment_unavailable"})),
                503,
                json!({
                    "error": "payment_unconfirmed", "detail": "payment gateway unavailable",
                    "retry_same_request": true, "retry_after": 2, "replay_window_secs": 120
                }),
                503,
                internal,
            ),
            (
                decision(503, &[], json!({"error": "idempotency_store_full"})),
                503,
                json!({"error": "payment_unavailable", "detail": "payment gateway unavailable"}),
                503,
                internal,
            ),
        ];
        for (decision, http_status, http_body, rpc_status, codes) in cases {
            let (status, headers, body) = body_json(render(&decision, &Shape::Http)).await;
            assert_eq!((status.as_u16(), &body), (http_status, &http_body), "{decision:?}");
            assert_eq!(headers["cache-control"], "no-store", "{decision:?}");
            match &decision {
                PaymentDelegationDecision::Unconfirmed { .. } => assert_eq!(headers["retry-after"], "2"),
                PaymentDelegationDecision::InProgress { .. } => assert_eq!(headers["retry-after"], "1"),
                _ => assert!(
                    !headers.contains_key("retry-after")
                        || matches!(decision, PaymentDelegationDecision::RateLimited { .. })
                ),
            }
            assert!(!headers.contains_key("set-cookie"));
            for (shape, code) in [(&modern, codes.0), (&legacy, codes.1)] {
                let (status, headers, envelope) = body_json(render(&decision, shape)).await;
                assert_eq!(status.as_u16(), rpc_status, "{decision:?}");
                assert_eq!(envelope["id"], "call-1");
                assert_eq!(envelope["error"]["code"], code, "{decision:?} {shape:?}");
                match &decision {
                    PaymentDelegationDecision::Challenge { .. } => {
                        assert_eq!(headers["payment-required"], "eyJ4IjoxfQ==");
                        assert_eq!(envelope["error"]["data"]["httpStatus"], 402);
                        assert_eq!(envelope["error"]["data"]["x402"], json!({"accepts": []}));
                        assert_eq!(envelope["error"]["data"]["challenges"][0]["id"], "c1");
                        assert_eq!(envelope["error"]["data"]["challenges"][0]["method"], "tempo");
                    }
                    PaymentDelegationDecision::VerificationFailed { reason, .. } => {
                        assert_eq!(envelope["error"]["data"]["failure"]["reason"], reason.as_str());
                    }
                    PaymentDelegationDecision::Held { .. } => {
                        assert_eq!(
                            envelope["error"]["data"],
                            json!({"httpStatus": 202, "case_id": "case-9", "reason": "limit"})
                        );
                    }
                    PaymentDelegationDecision::Rejected { reason, .. } => {
                        assert_eq!(envelope["error"]["data"]["failure"]["reason"], reason.as_str());
                    }
                    PaymentDelegationDecision::RateLimited { .. } => {
                        assert_eq!(headers["retry-after"], "9");
                        assert_eq!(envelope["error"]["data"]["retryAfter"], "9");
                    }
                    PaymentDelegationDecision::Unconfirmed { .. } => {
                        assert_eq!(headers["retry-after"], "2");
                        let data = &envelope["error"]["data"];
                        assert_eq!(data["error"], "payment_unconfirmed");
                        assert_eq!((&data["retryAfter"], &data["replayWindowSecs"]), (&json!(2), &json!(120)));
                    }
                    PaymentDelegationDecision::InProgress { .. } => {
                        assert_eq!(headers["retry-after"], "1");
                        assert_eq!(envelope["error"]["data"]["error"], "payment_in_progress");
                        assert_eq!(envelope["error"]["data"]["httpStatus"], 409);
                    }
                    _ => assert_eq!(envelope["error"]["data"]["error"], "payment_unavailable"),
                }
            }
        }
    }

    #[test]
    fn a_legacy_mcp_caller_is_the_one_without_a_protocol_version() {
        let mcp = mcp_surface("gw-shape", json!({"require_all": true}));
        let body = tool_call("t", json!({}));
        let legacy = read(&mcp, &HeaderMap::new(), &body);
        assert!(matches!(legacy.shape, Shape::JsonRpc { legacy_mcp: true, .. }));
        let context = McpContext {
            method: "tools/call".into(),
            tool_name: Some("t".into()),
            protocol_version: Some("2026-07-28".into()),
            ..Default::default()
        };
        let modern = read_with(
            &mcp,
            Read {
                method: "POST",
                path_and_query: "/mcp",
                variant: None,
                headers: &HeaderMap::new(),
                body: &body,
                mcp_context: Some(&context),
            },
        );
        assert!(matches!(modern.shape, Shape::JsonRpc { legacy_mcp: false, .. }));
        let a2a = a2a_surface("gw-shape", json!({"require_all": true}));
        let rpc = read(&a2a, &HeaderMap::new(), &body);
        assert!(
            matches!(rpc.shape, Shape::JsonRpc { legacy_mcp: false, .. }),
            "A2A callers keep the application codes"
        );
        assert_eq!(read(&mcp, &HeaderMap::new(), b"plain").shape, Shape::Http);
    }

    #[tokio::test]
    async fn free_requests_make_no_hop_and_paid_ones_send_only_a_payment_request() {
        let gate = paid_gate();
        install_test_transport("gw-paid", gate.clone());
        let surface =
            mcp_surface("gw-paid", json!({"mcp_payment_triggers": {"mode": "match", "patterns": ["^paid_"]}}));
        let fabric = no_fabric();
        let credential = unique("proof");
        let free =
            read(&surface, &x402_headers(&credential), &tool_call("free_tool", json!({"payment_signature": "unused"})));
        assert!(matches!(charge(&free, call(&surface, &fabric)).await, GateOutcome::Free));
        let listing = read(&surface, &HeaderMap::new(), br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
        assert!(matches!(charge(&listing, call(&surface, &fabric)).await, GateOutcome::Free));
        let card = read_with(
            &surface,
            Read {
                method: "GET",
                path_and_query: "/.well-known/agent-card.json",
                variant: None,
                headers: &HeaderMap::new(),
                body: b"",
                mcp_context: None,
            },
        );
        assert!(matches!(charge(&card, call(&surface, &fabric)).await, GateOutcome::Free));
        assert_eq!(gate.calls(), 0, "a free request makes no fabric hop");

        let mut headers = x402_headers(&credential);
        headers.insert("cookie", HeaderValue::from_static("sid=1"));
        let paid =
            read(&surface, &headers, &tool_call("paid_tool", json!({"q": 1, "payment_signature": "body-proof"})));
        let GateOutcome::Paid(outcome) = charge(&paid, call(&surface, &fabric)).await else {
            panic!("expected a paid request")
        };
        assert_eq!(
            outcome.receipt,
            Receipt {
                rail: Rail::X402,
                value: "the-receipt".into(),
                vc_fingerprint: Some("fp-1".into()),
                cache_control: Some("no-store".into()),
                claim: None,
                authorization: None,
            }
        );
        let forwarded: Value = serde_json::from_slice(paid.body()).unwrap();
        assert_eq!(forwarded["params"]["arguments"], json!({"q": 1}));
        let sent = gate.last();
        assert_eq!(sent.fabric_target, "fabric://gw-paid/pay-1");
        assert_eq!(
            sent.body,
            json!({"kind": "payment_request", "protocol": "mcp", "resource": "paid_tool", "caller_surface_id": "paid-mcp"})
        );
        assert_eq!(sent.headers["PAYMENT-SIGNATURE"], credential);
        assert!(
            !sent
                .headers
                .contains_key("cookie")
        );
        assert_eq!(sent.trace_id, "0af76519-16cd-43dd-8448-eb211c80319c");
        assert_eq!(sent.payment_context["correlation"]["idempotency_key"], Value::String(paid.key.clone().unwrap()));
        assert_eq!(sent.payment_context["correlation"]["trace_context"], sent.headers["traceparent"]);
        assert_eq!(sent.payment_context["intent"]["resource_id"], "paid_tool");

        let unpaid = read(&surface, &HeaderMap::new(), &tool_call("paid_tool", json!({})));
        charge(&unpaid, call(&surface, &fabric)).await;
        assert!(
            gate.last().payment_context["correlation"]
                .get("idempotency_key")
                .is_none(),
            "a challenge-only call has no idempotency key"
        );
    }

    #[tokio::test]
    async fn records_use_the_ingress_trace_and_the_wire_uses_the_egress_trace() {
        let gate = paid_gate();
        install_test_transport("gw-trace", gate.clone());
        let surface = mcp_surface("gw-trace", json!({"require_all": true}));
        let fabric = no_fabric();
        let intake = read(&surface, &x402_headers(&unique("proof")), &tool_call("t", json!({})));
        let (outcome, events) = crate::audit::producer::capture(charge(&intake, call(&surface, &fabric))).await;
        assert!(matches!(outcome, GateOutcome::Paid(_)));
        let events = payment_events(&events);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1.as_deref(), Some("ingress-trace"), "the audit trail follows this request's own trace");
        let sent = gate.last();
        assert_eq!(sent.trace_id, "0af76519-16cd-43dd-8448-eb211c80319c");
        assert_eq!(sent.payment_context["correlation"]["thid"], "0af76519-16cd-43dd-8448-eb211c80319c");
        assert!(sent.headers["traceparent"].contains("0af7651916cd43dd8448eb211c80319c"));
        assert!(
            !sent
                .payment_context
                .to_string()
                .contains("ingress-trace")
        );
    }

    #[tokio::test]
    async fn a_paid_answer_without_a_usable_receipt_or_too_large_fails_closed() {
        let surface = mcp_surface("gw-no-receipt", json!({"require_all": true}));
        let fabric = no_fabric();
        let body = tool_call("t", json!({}));
        let intake = read(&surface, &x402_headers(&unique("proof")), &body);
        install_test_transport("gw-no-receipt", MockGate::answering(200, &[], json!({})));
        let GateOutcome::Refused(response) = charge(&intake, call(&surface, &fabric)).await else {
            panic!("a receipt-less 200 must not pass")
        };
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        let surface = mcp_surface("gw-large", json!({"require_all": true}));
        install_test_transport(
            "gw-large",
            MockGate::answering(402, &[], json!({"padding": "x".repeat(MAX_RESPONSE_BODY_BYTES)})),
        );
        let GateOutcome::Refused(response) = charge(&intake, call(&surface, &fabric)).await else {
            panic!("an oversized answer must not pass")
        };
        let (status, _, envelope) = body_json(response).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(envelope["error"]["data"]["detail"], "payment gateway response too large");
        let huge_header = "h".repeat(MAX_RESPONSE_HEADER_BYTES + 1);
        assert!(oversized(&FabricForwardResponse {
            status: 200,
            headers: HashMap::from([("payment-receipt".to_string(), vec![huge_header])]),
            body: Vec::new(),
        }));
        assert!(!oversized(&FabricForwardResponse {
            status: 200,
            headers: HashMap::new(),
            body: vec![0; MAX_RESPONSE_BODY_BYTES],
        }));
    }

    #[tokio::test]
    async fn the_breaker_opens_after_five_transport_failures_and_answers_without_a_hop() {
        let surface = mcp_surface("gw-down", json!({"require_all": true}));
        let gate = MockGate::failing("unreachable");
        install_test_transport("gw-down", gate.clone());
        let fabric = no_fabric();
        let intake = read(&surface, &HeaderMap::new(), &tool_call("t", json!({})));
        for attempt in 1..=DEFAULT_BREAKER_FAILURES {
            let GateOutcome::Refused(response) = charge(&intake, call(&surface, &fabric)).await else {
                panic!("an unreachable gate must refuse")
            };
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "attempt {attempt}");
        }
        assert_eq!(gate.calls(), DEFAULT_BREAKER_FAILURES as usize);
        let GateOutcome::Refused(response) = charge(&intake, call(&surface, &fabric)).await else {
            panic!("an open breaker must refuse")
        };
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let retry_after: u64 = response.headers()["retry-after"]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=30).contains(&retry_after));
        assert_eq!(gate.calls(), DEFAULT_BREAKER_FAILURES as usize, "an open breaker makes no hop");

        let now = Instant::now();
        record_transport_result("gw-flaky", TransportOutcome::Failed, now);
        record_transport_result("gw-flaky", TransportOutcome::Reached, now);
        for _ in 0..DEFAULT_BREAKER_FAILURES - 1 {
            record_transport_result("gw-flaky", TransportOutcome::Failed, now);
        }
        assert_eq!(breaker_admit("gw-flaky", now), Ok(()), "an answer resets the count");
        record_transport_result("gw-flaky", TransportOutcome::Failed, now);
        assert_eq!(breaker_admit("gw-flaky", now), Err(30));
        assert_eq!(
            breaker_admit("gw-flaky", now + DEFAULT_BREAKER_OPEN_FOR),
            Ok(()),
            "once the open time has passed one call is let through"
        );
    }

    #[tokio::test]
    async fn a_wait_cut_short_by_the_callers_deadline_neither_opens_the_breaker_nor_resets_it() {
        let surface = mcp_surface("gw-deadline-breaker", json!({"require_all": true}));
        let gate = MockGate::failing("timeout");
        install_test_transport("gw-deadline-breaker", gate.clone());
        let fabric = no_fabric();
        let intake = read(&surface, &HeaderMap::new(), &tool_call("t", json!({})));

        for _ in 0..(DEFAULT_BREAKER_FAILURES * 2) {
            let mut short = call(&surface, &fabric);
            short.deadline_ms = Some(now_ms() + 1_500);
            let GateOutcome::Refused(response) = charge(&intake, short).await else { panic!("a timeout must refuse") };
            assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        }
        assert_eq!(gate.calls(), (DEFAULT_BREAKER_FAILURES * 2) as usize, "short deadlines never opened the breaker");

        for _ in 0..(DEFAULT_BREAKER_FAILURES - 1) {
            charge(&intake, call(&surface, &fabric)).await;
        }
        let mut short = call(&surface, &fabric);
        short.deadline_ms = Some(now_ms() + 1_500);
        charge(&intake, short).await;
        assert_eq!(
            gate.calls(),
            (DEFAULT_BREAKER_FAILURES * 3) as usize,
            "a short wait does not reset the count either"
        );
        let GateOutcome::Refused(response) = charge(&intake, call(&surface, &fabric)).await else {
            panic!("the gate's own timeouts count")
        };
        assert_eq!(
            response.status(),
            StatusCode::GATEWAY_TIMEOUT,
            "the fifth own timeout trips the breaker after it answers"
        );
        let GateOutcome::Refused(response) = charge(&intake, call(&surface, &fabric)).await else { panic!("open") };
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn a_deadline_too_short_for_agent_pay_is_refused_without_a_hop() {
        let gate = paid_gate();
        install_test_transport("gw-short", gate.clone());
        let surface = mcp_surface("gw-short", json!({"require_all": true}));
        let fabric = no_fabric();
        let intake = read(&surface, &x402_headers(&unique("proof")), &tool_call("t", json!({})));
        for remaining in [0, 400, 990] {
            let mut short = call(&surface, &fabric);
            short.deadline_ms = Some(now_ms() + remaining);
            let GateOutcome::Refused(response) = charge(&intake, short).await else { panic!("too short") };
            let (status, _, body) = body_json(response).await;
            assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{remaining} ms");
            assert_eq!(body["error"]["data"]["detail"], "caller deadline too short for payment");
        }
        assert_eq!(gate.calls(), 0);
        let mut enough = call(&surface, &fabric);
        enough.deadline_ms = Some(now_ms() + 5_000);
        assert!(matches!(charge(&intake, enough).await, GateOutcome::Paid(_)));
        assert!(gate.last().timeout <= Duration::from_millis(5_000));
    }

    #[tokio::test]
    async fn timeouts_and_misconfiguration_fail_closed() {
        let fabric = no_fabric();
        let body = tool_call("t", json!({}));
        let surface = mcp_surface("gw-slow", json!({"require_all": true}));
        install_test_transport("gw-slow", MockGate::failing("timeout"));
        let intake = read(&surface, &HeaderMap::new(), &body);
        let GateOutcome::Refused(response) = charge(&intake, call(&surface, &fabric)).await else {
            panic!("a timeout must refuse")
        };
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);

        let mut misconfigured = mcp_surface("", json!({"require_all": true}));
        misconfigured.surface_id = "misconfigured".into();
        let intake = read(&misconfigured, &HeaderMap::new(), &body);
        let GateOutcome::Refused(response) = charge(&intake, call(&misconfigured, &fabric)).await else {
            panic!("a misconfigured policy must refuse")
        };
        let (status, _, envelope) = body_json(response).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(
            envelope["error"]["data"]["detail"]
                .as_str()
                .unwrap()
                .contains("payment delegation misconfigured")
        );
    }

    fn ledger_outcome_count(
        surface_id: &str,
        outcome: &str,
    ) -> u64 {
        crate::metrics::backends::prometheus::PAYMENT_GATE_REQUESTS
            .with_label_values(&[surface_id, outcome])
            .get()
    }

    #[tokio::test]
    async fn an_answer_that_does_not_say_whether_the_payment_was_taken_is_unconfirmed_only_when_a_credential_was_sent()
    {
        let fabric = no_fabric();
        let body = tool_call("t", json!({}));
        for (label, gate, status, detail) in [
            (
                "timeout",
                MockGate::failing("timeout"),
                StatusCode::GATEWAY_TIMEOUT,
                "payment gateway did not answer in time",
            ),
            (
                "server error",
                MockGate::answering(500, &[], json!({})),
                StatusCode::BAD_GATEWAY,
                "payment gateway returned unexpected status 500",
            ),
            (
                "unusable receipt",
                MockGate::answering(200, &[], json!({})),
                StatusCode::BAD_GATEWAY,
                "payment gateway answered without a usable receipt",
            ),
        ] {
            let gateway = unique(
                label
                    .replace(' ', "-")
                    .as_str(),
            );
            install_test_transport(&gateway, gate.clone());
            let mut surface = mcp_surface(&gateway, json!({"require_all": true}));
            surface.surface_id = unique("unconfirmed");
            let credential = unique("proof");

            let paying = read(&surface, &x402_headers(&credential), &body);
            let (outcome, events) = crate::audit::producer::capture(charge(&paying, call(&surface, &fabric))).await;
            let GateOutcome::Refused(response) = outcome else { panic!("{label}: nothing was confirmed") };
            let (answered, headers, envelope) = body_json(response).await;
            assert_eq!(answered, status, "{label}");
            assert_eq!(headers["retry-after"], "2", "{label}");
            let data = &envelope["error"]["data"];
            assert_eq!(data["error"], "payment_unconfirmed", "{label}");
            assert_eq!(data["detail"], detail, "{label}");
            assert_eq!((&data["retryAfter"], &data["replayWindowSecs"]), (&json!(2), &json!(120)));
            let events = payment_events(&events);
            assert_eq!(events[0].0.stage, crate::delegation_vault::audit::PaymentStage::Unconfirmed, "{label}");
            assert_eq!(events[0].0.error.as_deref(), Some(format!("payment_unconfirmed: {detail}").as_str()));
            assert_eq!(ledger_outcome_count(&surface.surface_id, "unconfirmed"), 1, "{label}");

            let asking = read(&surface, &HeaderMap::new(), &body);
            let GateOutcome::Refused(response) = charge(&asking, call(&surface, &fabric)).await else {
                panic!("{label}: nothing was presented")
            };
            let (_, headers, envelope) = body_json(response).await;
            assert_eq!(
                envelope["error"]["data"]["error"], "payment_unavailable",
                "{label}: nothing could have been taken"
            );
            assert!(!headers.contains_key("retry-after"), "{label}");
            assert_eq!(ledger_outcome_count(&surface.surface_id, "unavailable"), 1, "{label}");
        }
    }

    #[tokio::test]
    async fn a_request_that_never_reached_agent_pay_is_unavailable_not_unconfirmed_and_has_no_latency() {
        let fabric = no_fabric();
        let body = tool_call("t", json!({}));
        let mut surface = mcp_surface("gw-never-sent", json!({"require_all": true}));
        surface.surface_id = unique("never-sent");
        install_test_transport("gw-never-sent", MockGate::failing("down"));
        let intake = read(&surface, &x402_headers(&unique("proof")), &body);
        let GateOutcome::Refused(response) = charge(&intake, call(&surface, &fabric)).await else { panic!("refused") };
        let (status, _, envelope) = body_json(response).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(envelope["error"]["data"]["error"], "payment_unavailable");
        assert_eq!(ledger_outcome_count(&surface.surface_id, "unavailable"), 1);
        let latency = crate::metrics::backends::prometheus::PAYMENT_GATE_LATENCY
            .with_label_values(&[surface.surface_id.as_str()]);
        assert_eq!(latency.get_sample_count(), 0, "no request went on the wire, so no latency is sampled");

        let mut misconfigured = mcp_surface("", json!({"require_all": true}));
        misconfigured.surface_id = unique("misconfigured");
        let intake = read(&misconfigured, &x402_headers(&unique("proof")), &body);
        assert!(matches!(charge(&intake, call(&misconfigured, &fabric)).await, GateOutcome::Refused(_)));
        assert_eq!(ledger_outcome_count(&misconfigured.surface_id, "unavailable"), 1);
        let latency = crate::metrics::backends::prometheus::PAYMENT_GATE_LATENCY.with_label_values(&[misconfigured
            .surface_id
            .as_str()]);
        assert_eq!(latency.get_sample_count(), 0);

        let mut paid = mcp_surface("gw-timed", json!({"require_all": true}));
        paid.surface_id = unique("timed");
        install_test_transport("gw-timed", paid_gate());
        let intake = read(&paid, &x402_headers(&unique("proof")), &body);
        assert!(matches!(charge(&intake, call(&paid, &fabric)).await, GateOutcome::Paid(_)));
        let latency =
            crate::metrics::backends::prometheus::PAYMENT_GATE_LATENCY.with_label_values(&[paid.surface_id.as_str()]);
        assert_eq!(latency.get_sample_count(), 1, "a call that was made is timed");
    }

    #[tokio::test]
    async fn exactly_one_call_probes_a_payment_gateway_whose_breaker_has_been_open() {
        let gateway = "gw-probe";
        let now = Instant::now();
        for _ in 0..DEFAULT_BREAKER_FAILURES {
            record_transport_result(gateway, TransportOutcome::Failed, now);
        }
        assert_eq!(breaker_admit(gateway, now + Duration::from_secs(10)), Err(20));
        let later = now + DEFAULT_BREAKER_OPEN_FOR;
        assert_eq!(breaker_admit(gateway, later), Ok(()), "the first call after the open time is the probe");
        assert_eq!(breaker_admit(gateway, later), Err(1), "the others stay refused while it is out");
        assert_eq!(breaker_admit(gateway, later + Duration::from_secs(5)), Err(1));

        record_transport_result(gateway, TransportOutcome::Inconclusive, later);
        assert_eq!(
            breaker_admit(gateway, later),
            Ok(()),
            "a probe cut short by a caller's deadline hands over the probe"
        );
        assert_eq!(breaker_admit(gateway, later), Err(1));
        record_transport_result(gateway, TransportOutcome::Failed, later);
        assert_eq!(breaker_admit(gateway, later), Err(30), "a failed probe opens the breaker again");

        let again = later + DEFAULT_BREAKER_OPEN_FOR;
        assert_eq!(breaker_admit(gateway, again), Ok(()));
        record_transport_result(gateway, TransportOutcome::Reached, again);
        assert_eq!(breaker_admit(gateway, again), Ok(()));
        assert_eq!(breaker_admit(gateway, again), Ok(()), "a probe that is answered closes the breaker");

        let lease = later + DEFAULT_BREAKER_OPEN_FOR * 3;
        for _ in 0..DEFAULT_BREAKER_FAILURES {
            record_transport_result(gateway, TransportOutcome::Failed, later + DEFAULT_BREAKER_OPEN_FOR * 2);
        }
        assert_eq!(breaker_admit(gateway, lease), Ok(()));
        assert_eq!(
            breaker_admit(gateway, lease + DEFAULT_BREAKER_OPEN_FOR),
            Ok(()),
            "a probe that never reports expires"
        );
    }

    #[test]
    fn a_batch_is_chargeable_when_any_message_is_and_every_message_loses_its_credential() {
        let matching = policy(json!({"mcp_payment_triggers": {"mode": "match", "patterns": ["^premium_"]}}));
        let call = |tool: &str, arguments: Value| json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}});
        let free = call("free_tool", json!({}));
        let paid = call("premium_tool", json!({"payment_signature": "batch-proof", "q": 1}));
        let batch = |messages: &[&Value]| serde_json::to_vec(&json!(messages)).unwrap();
        assert!(is_chargeable(&matching, &ChannelProtocol::Mcp, &batch(&[&free, &paid]), None));
        assert!(!is_chargeable(&matching, &ChannelProtocol::Mcp, &batch(&[&free]), None));
        assert!(!is_chargeable(&matching, &ChannelProtocol::Mcp, &batch(&[]), None));

        let surface =
            mcp_surface("gw-batch", json!({"mcp_payment_triggers": {"mode": "match", "patterns": ["^premium_"]}}));
        let intake = read(&surface, &HeaderMap::new(), &batch(&[&free, &paid]));
        assert!(intake.chargeable);
        assert_eq!(
            intake.credential,
            Some(Credential {
                rail: Rail::X402,
                value: "batch-proof".into()
            })
        );
        let forwarded: Value = serde_json::from_slice(intake.body()).unwrap();
        assert_eq!(forwarded[1]["params"]["arguments"], json!({"q": 1}), "the batch's message is stripped");
        assert!(!String::from_utf8_lossy(intake.body()).contains("batch-proof"));

        let meta = json!([
            {"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {"message": {"metadata": {MCP_CREDENTIAL_META: mpp_token(), "keep": 1}}}},
            {"jsonrpc": "2.0", "id": 2, "method": "message/send", "params": {"_meta": {MCP_CREDENTIAL_META: mpp_token()}}}
        ]);
        let http = a2a_surface("gw-batch", json!({"require_all": true}));
        let stripped = read(&http, &HeaderMap::new(), &serde_json::to_vec(&meta).unwrap());
        assert_eq!(
            stripped
                .credential
                .as_ref()
                .map(|credential| credential.rail),
            Some(Rail::Mpp)
        );
        let forwarded: Value = serde_json::from_slice(stripped.body()).unwrap();
        assert_eq!(forwarded[0]["params"]["message"]["metadata"], json!({"keep": 1}));
        assert!(
            forwarded[1]["params"]
                .get("_meta")
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_batch_on_an_mcp_or_a2a_surface_that_charges_is_refused_before_any_call_to_agent_pay() {
        let gate = paid_gate();
        install_test_transport("gw-batch-refused", gate.clone());
        let fabric = no_fabric();
        let batch = serde_json::to_vec(&json!([{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "t", "arguments": {"payment_signature": "p"}}}])).unwrap();
        for surface in [
            mcp_surface("gw-batch-refused", json!({"require_all": true})),
            a2a_surface("gw-batch-refused", json!({"require_all": true})),
        ] {
            let intake = read(&surface, &x402_headers(&unique("proof")), &batch);
            let GateOutcome::Refused(response) = charge(&intake, call(&surface, &fabric)).await else {
                panic!("a batch is not charged")
            };
            let (status, _, envelope) = body_json(response).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(envelope["error"]["code"], -32600);
        }
        assert_eq!(gate.calls(), 0);

        let free = mcp_surface(
            "gw-batch-refused",
            json!({"mcp_payment_triggers": {"mode": "match", "patterns": ["^premium_"]}}),
        );
        let intake = read(&free, &HeaderMap::new(), &batch);
        assert!(
            matches!(charge(&intake, call(&free, &fabric)).await, GateOutcome::Free),
            "a batch with nothing chargeable is free"
        );
    }

    #[test]
    fn strip_modern_removes_the_credential_from_the_params_of_a_modern_message() {
        use crate::mcp::request_validation::ValidatedModernMessage;

        let surface = mcp_surface("gw-modern", json!({"require_all": true}));
        let intake = read(&surface, &HeaderMap::new(), &tool_call("t", json!({})));
        let message = |method: &str, params: Value| ValidatedModernMessage {
            protocol_version: "2026-07-28".into(),
            client_capabilities: None,
            client_info: None,
            method: method.into(),
            params: Some(params),
            id: None,
            kind: crate::mcp::request_validation::McpMessageKind::Request,
        };
        let mut call_message = message(
            "tools/call",
            json!({"name": "t", "arguments": {"payment_signature": "s", "payment_credential": "c", "q": 1},
                   "_meta": {MCP_CREDENTIAL_META: "x", "keep": true}}),
        );
        intake.strip_modern(&mut call_message);
        assert_eq!(call_message.params, Some(json!({"name": "t", "arguments": {"q": 1}, "_meta": {"keep": true}})));
        let mut other = message("resources/read", json!({"uri": "u", "_meta": {MCP_CREDENTIAL_META: "x"}}));
        intake.strip_modern(&mut other);
        assert_eq!(other.params, Some(json!({"uri": "u"})));
    }

    #[test]
    fn a_receipt_goes_into_the_metadata_of_the_object_an_a2a_result_is_made_of() {
        let receipt = receipt(Rail::X402);
        let mark = |value: Value| {
            let mut message = value;
            assert!(receipt.inject_into_message(&ChannelProtocol::A2a, &mut message));
            message
        };
        let key = "org.paymentauth/receipt";
        let legacy = mark(json!({"jsonrpc": "2.0", "id": 1, "result": {"kind": "message", "parts": []}}));
        assert_eq!(legacy["result"]["metadata"][key], "receipt-value", "an A2A 0.3 result is the message itself");

        let message =
            mark(json!({"jsonrpc": "2.0", "id": 1, "result": {"message": {"messageId": "m", "metadata": {"k": 1}}}}));
        assert_eq!(message["result"]["message"]["metadata"], json!({"k": 1, key: "receipt-value"}));
        assert!(
            message["result"]
                .get("metadata")
                .is_none(),
            "the SendMessageResponse wrapper defines no metadata"
        );

        for wrapper in ["task", "statusUpdate", "artifactUpdate"] {
            let wrapped = mark(json!({"jsonrpc": "2.0", "id": 1, "result": {wrapper: {"id": "t"}}}));
            assert_eq!(wrapped["result"][wrapper]["metadata"][key], "receipt-value", "{wrapper}");
            assert!(
                wrapped["result"]
                    .get("metadata")
                    .is_none(),
                "{wrapper}"
            );
        }
        let status_update = mark(
            json!({"jsonrpc": "2.0", "id": 1, "result": {"kind": "status-update", "status": {"state": "working"}}}),
        );
        assert_eq!(status_update["result"]["metadata"][key], "receipt-value", "a 0.3 event carries its own metadata");

        let events = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"statusUpdate\":{\"taskId\":\"t\"}}}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"task\":{\"id\":\"t\"}}}\n";
        let injected = receipt
            .inject_into_events(&ChannelProtocol::A2a, events)
            .unwrap();
        let lines: Vec<Value> = injected
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .map(|data| serde_json::from_str(data).unwrap())
            .collect();
        assert_eq!(lines[0]["result"]["statusUpdate"]["metadata"][key], "receipt-value");
        assert_eq!(lines[1]["result"]["task"]["metadata"][key], "receipt-value");
        assert!(lines.iter().all(|line| {
            line["result"]
                .get("metadata")
                .is_none()
        }));
    }

    #[test]
    fn a_principal_chain_is_forwarded_only_for_a_verified_agent_the_chain_ends_at() {
        let policy = policy(json!({}));
        let chain = json!([{"did": "did:example:root"}, {"did": "did:example:agent"}]);
        let body = json!({"params": {"_meta": {"org.paymentauth/payment_context": {"principal_chain": chain}}}});
        let forged = json!([{"did": "did:example:victim"}]);
        let forged_body =
            json!({"params": {"_meta": {"org.paymentauth/payment_context": {"principal_chain": forged}}}});
        let identity = jwt_identity(json!({"sub": "user-1"}));
        let unverified = Caller {
            identity: Some(&identity),
            verified_agent_did: None,
        };
        let verified = Caller {
            identity: Some(&identity),
            verified_agent_did: Some("did:example:agent"),
        };
        let context = |body: &Value, caller: &Caller<'_>| {
            build_payment_context("s", &policy, Some(body), "r", caller, None, "t", "tp")
        };
        assert_eq!(context(&body, &verified)["principal_chain"], chain);
        assert!(
            context(&body, &unverified)
                .get("principal_chain")
                .is_none()
        );
        assert!(
            context(&forged_body, &unverified)
                .get("principal_chain")
                .is_none()
        );
        assert!(
            context(&forged_body, &verified)
                .get("principal_chain")
                .is_none()
        );
        assert_eq!(context(&forged_body, &verified)["payer_identity"]["did"], "did:example:agent");
    }

    #[tokio::test]
    async fn continuation_evidence_is_reused_without_a_hop_and_must_match() {
        let gate = MockGate::answering(200, &[("payment-receipt", "fresh")], json!({}));
        install_test_transport("gw-evidence", gate.clone());
        let surface = mcp_surface("gw-evidence", json!({"require_all": true}));
        let fabric = no_fabric();
        let intake = read(&surface, &HeaderMap::new(), &tool_call("t", json!({})));
        let now = crate::proxy::credential_delegation::modern::now_secs().unwrap();
        let held = receipt(Rail::Mpp);
        let evidence = (held.continuation_evidence())(now, now + 60);
        for round in 0..3 {
            let mut request = call(&surface, &fabric);
            request.evidence = Some(&evidence);
            let GateOutcome::Paid(paid) = charge(&intake, request).await else { panic!("valid evidence is reused") };
            assert_eq!(paid.receipt, held, "round {round}: a later round holds the same receipt");
        }
        assert_eq!(gate.calls(), 0, "a continuation round is not charged again");
        for invalid in [
            ContinuationPayment::X402 {
                receipt: Some("r".into()),
                verified_at: now,
                expires_at: now + 60,
            },
            (held.continuation_evidence())(now - 120, now - 60),
        ] {
            let mut request = call(&surface, &fabric);
            request.evidence = Some(&invalid);
            let GateOutcome::Refused(response) = charge(&intake, request).await else {
                panic!("mismatched or expired evidence is refused")
            };
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        assert_eq!(gate.calls(), 0);
    }

    #[test]
    fn a_case_poll_is_a_get_of_a_plain_case_id_and_scoped_to_the_caller() {
        assert_eq!(polled_case("GET", "/mcp/.well-known/payment-cases/case-1"), Some("case-1"));
        assert_eq!(polled_case("POST", "/mcp/.well-known/payment-cases/case-1"), None);
        assert_eq!(polled_case("GET", "/mcp/.well-known/payment-cases/"), None);
        assert_eq!(polled_case("GET", "/mcp/.well-known/payment-cases/a/b"), None);
        assert_eq!(polled_case("GET", "/mcp/tools"), None);

        let mut paid = mcp_surface("gw-poll", json!({}));
        assert!(held_payments_unpollable(&paid), "a paid surface without source authentication");
        paid.access_point
            .caller_authentication = Some(crate::config::agent_surface::CallerAuthentication {
            methods: vec![crate::source_auth::SourceAuthConfig::ApiKey(crate::source_auth::models::ApiKeyAuthConfig {
                extraction: crate::source_auth::models::CredentialExtraction::HttpHeader {
                    field: "x-api-key".to_string(),
                },
                secret_id: "key".to_string(),
            })],
            protected_resource: None,
        });
        assert!(!held_payments_unpollable(&paid), "a paid surface with source authentication");
        paid.target.payment_policy = None;
        paid.access_point
            .caller_authentication = None;
        assert!(!held_payments_unpollable(&paid), "a surface that charges nothing");

        let alice = crate::source_auth::AuthenticatedIdentity::ApiKey { key_name: "alice".into() };
        let bob = crate::source_auth::AuthenticatedIdentity::ApiKey { key_name: "bob".into() };
        assert_eq!(caller_principal(Some(&alice)), caller_principal(Some(&alice)));
        assert_ne!(caller_principal(Some(&alice)), caller_principal(Some(&bob)));
        assert_eq!(caller_principal(None), None);
    }

    #[tokio::test]
    async fn a_gate_step_cancelled_before_its_answer_is_recorded_leaves_an_unconfirmed_row() {
        let surface = mcp_surface("gw-abandoned", json!({"require_all": true}));
        let fabric = no_fabric();
        let intake = read(&surface, &x402_headers(&unique("proof")), &tool_call("t", json!({})));
        let call = call(&surface, &fabric);
        let policy = surface
            .agent_pay_policy()
            .unwrap();

        let armed = Abandoned::arm(&intake, &call, policy);
        let row = armed
            .0
            .clone()
            .expect("a paid request is armed");
        assert_eq!(row.outcome, crate::payments_ledger::LedgerOutcome::Unconfirmed);
        assert_eq!(row.idempotency_key, intake.key);
        assert_eq!(row.payment_gateway_id, "gw-abandoned");

        let mut disarmed = Abandoned::arm(&intake, &call, policy);
        disarmed.disarm();
        assert!(disarmed.0.is_none());

        let free = read(&surface, &HeaderMap::new(), &tool_call("t", json!({})));
        assert!(
            Abandoned::arm(&free, &call, policy)
                .0
                .is_none(),
            "a request without a credential pays nothing"
        );
    }

    #[tokio::test]
    async fn continuation_evidence_of_a_voided_authorization_pays_for_no_later_round() {
        use crate::payments_ledger::settlement::SettlementStatus;

        let authorization_id = unique("auth-ev");
        let (receipt, _settlement) = streaming_held_receipt(&authorization_id, SettlementStatus::Voided).await;
        let now = crate::proxy::credential_delegation::modern::now_secs().unwrap();
        let evidence = (receipt.continuation_evidence())(now, now + 60);
        let surface = mcp_surface("gw-evidence-void", json!({"require_all": true}));
        let fabric = no_fabric();
        let intake = read(&surface, &HeaderMap::new(), &tool_call("t", json!({})));
        let mut before = call(&surface, &fabric);
        before.evidence = Some(&evidence);
        assert!(matches!(charge(&intake, before).await, GateOutcome::Paid(_)), "evidence pays before the void");

        assert_eq!(receipt.settled(false).await, None);

        let mut after = call(&surface, &fabric);
        after.evidence = Some(&evidence);
        let GateOutcome::Refused(response) = charge(&intake, after).await else {
            panic!("evidence of a voided authorization is refused")
        };
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_replayed_payment_is_refused_with_a_fresh_challenge_and_never_forwarded_twice() {
        let gate = paid_gate().challenging(
            &[
                ("payment-required", "eyJ4IjoxfQ=="),
                (
                    "www-authenticate",
                    r#"Payment id="fresh", realm="r", method="tempo", intent="charge", request="e30""#,
                ),
                ("content-type", "application/json"),
            ],
            json!({"x402Version": 2, "accepts": [{"scheme": "exact"}]}),
        );
        install_test_transport("gw-replay", gate.clone());
        let surface = mcp_surface("gw-replay", json!({"require_all": true}));
        let fabric = no_fabric();
        let credential = unique("proof");
        let first = read(&surface, &x402_headers(&credential), &tool_call("paid_tool", json!({"q": 1})));
        dispatched(&first, call(&surface, &fabric)).await;
        assert_eq!(gate.calls(), 1);

        // The same credential and request, with a new JSON-RPC id: agent-pay answers it as paid again.
        let retry_body = serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 99, "method": "tools/call", "params": {"name": "paid_tool", "arguments": {"q": 1}}})).unwrap();
        let retry = read(&surface, &x402_headers(&credential), &retry_body);
        assert_eq!(retry.key, first.key);
        let (outcome, events) = crate::audit::producer::capture(charge(&retry, call(&surface, &fabric))).await;
        let GateOutcome::Refused(response) = outcome else { panic!("a consumed payment is not forwarded again") };
        let (status, headers, body) = body_json(response).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(body["error"]["code"], -32043, "a request with no protocol version is a legacy caller");
        assert_eq!(body["error"]["data"]["failure"]["reason"], "payment_already_used");
        assert_eq!(body["error"]["data"]["challenges"][0]["id"], "fresh");
        assert_eq!(body["error"]["data"]["x402"]["accepts"][0]["scheme"], "exact");
        assert_eq!(headers["payment-required"], "eyJ4IjoxfQ==");
        assert_eq!(gate.calls(), 3, "the replayed payment, then a request for a fresh challenge");
        let challenge_request = gate.last();
        assert!(
            !challenge_request
                .headers
                .contains_key("PAYMENT-SIGNATURE"),
            "the challenge is asked for without the consumed credential"
        );
        assert!(
            challenge_request.payment_context["correlation"]
                .get("idempotency_key")
                .is_none()
        );
        let events = payment_events(&events);
        assert_eq!(events.len(), 1, "the replay is one rejected record, not a paid one");
        assert_eq!(events[0].0.stage, crate::delegation_vault::audit::PaymentStage::Failed);
        assert_eq!(events[0].0.error.as_deref(), Some("payment_already_used"));
        assert_eq!(
            events[0]
                .0
                .delegation
                .as_ref()
                .unwrap()
                .idempotency_key,
            first.key
        );

        let http = a2a_surface("gw-replay", json!({"require_all": true}));
        let a2a_credential = unique("proof");
        let a2a_first = read(&http, &x402_headers(&a2a_credential), br#"{"order":1}"#);
        dispatched(&a2a_first, call(&http, &fabric)).await;
        let a2a_retry = read(&http, &x402_headers(&a2a_credential), br#"{"order":1}"#);
        let GateOutcome::Refused(response) = charge(&a2a_retry, call(&http, &fabric)).await else { panic!("replay") };
        let (status, headers, body) = body_json(response).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(body["error"], "payment_already_used");
        assert_eq!(body["x402Version"], 2, "the fresh challenge body is relayed with the reason");
        assert_eq!(headers["payment-required"], "eyJ4IjoxfQ==");

        let other_request = read(&surface, &x402_headers(&credential), &tool_call("paid_tool", json!({"q": 2})));
        assert_ne!(other_request.key, first.key);
        assert!(
            matches!(charge(&other_request, call(&surface, &fabric)).await, GateOutcome::Paid(_)),
            "the same credential on another request is for agent-pay's own replay guard to refuse"
        );
    }

    #[tokio::test]
    async fn concurrent_identical_requests_forward_exactly_once() {
        let gate = paid_gate()
            .challenging(&[("payment-required", "eyJ4IjoxfQ==")], json!({"accepts": []}))
            .delayed(Duration::from_millis(25));
        install_test_transport("gw-concurrent", gate.clone());
        let surface = mcp_surface("gw-concurrent", json!({"require_all": true}));
        let fabric = no_fabric();
        let credential = unique("proof");
        let body = tool_call("paid_tool", json!({"q": 1}));
        let intakes: Vec<Intake> = (0..8)
            .map(|_| read(&surface, &x402_headers(&credential), &body))
            .collect();
        let outcomes = futures::future::join_all(
            intakes
                .iter()
                .map(|intake| charge(intake, call(&surface, &fabric))),
        )
        .await;
        let paid = outcomes
            .iter()
            .filter(|outcome| matches!(outcome, GateOutcome::Paid(_)))
            .count();
        assert_eq!(paid, 1, "one payment buys one forwarded request");
        for outcome in outcomes {
            if let GateOutcome::Refused(response) = outcome {
                let (status, headers, envelope) = body_json(response).await;
                assert_eq!(status, StatusCode::CONFLICT, "the claim is held by the one being dispatched");
                assert_eq!(envelope["error"]["data"]["error"], "payment_in_progress");
                assert_eq!(headers["retry-after"], "1");
            }
        }
    }

    #[tokio::test]
    async fn a_claim_dropped_before_dispatch_lets_the_same_request_be_retried_and_a_dispatched_one_does_not() {
        let gate = paid_gate().challenging(&[("payment-required", "eyJ4IjoxfQ==")], json!({"accepts": []}));
        install_test_transport("gw-claim", gate.clone());
        let surface = mcp_surface("gw-claim", json!({"require_all": true}));
        let fabric = no_fabric();
        let credential = unique("proof");
        let body = tool_call("paid_tool", json!({"q": 1}));
        let intake = read(&surface, &x402_headers(&credential), &body);

        let GateOutcome::Paid(first) = charge(&intake, call(&surface, &fabric)).await else { panic!("paid") };
        let GateOutcome::Refused(response) = charge(&intake, call(&surface, &fabric)).await else {
            panic!("the claim is held")
        };
        assert_eq!(response.status(), StatusCode::CONFLICT);
        drop(first);

        let GateOutcome::Paid(second) = charge(&intake, call(&surface, &fabric)).await else {
            panic!("a failure before dispatch gave the claim up, so the retry is paid again")
        };
        let held = second.receipt.clone();
        drop(second);
        let GateOutcome::Refused(response) = charge(&intake, call(&surface, &fabric)).await else {
            panic!("a copy of the receipt still holds the claim")
        };
        assert_eq!(response.status(), StatusCode::CONFLICT);
        held.commit();
        drop(held);
        let GateOutcome::Refused(response) = charge(&intake, call(&surface, &fabric)).await else {
            panic!("a dispatched request is not dispatched again")
        };
        let (status, _, envelope) = body_json(response).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(envelope["error"]["data"]["failure"]["reason"], "payment_already_used");
    }

    #[tokio::test]
    async fn a_charge_dropped_while_it_waits_for_agent_pay_holds_no_claim() {
        let gate = paid_gate().delayed(Duration::from_millis(200));
        install_test_transport("gw-cancel", gate.clone());
        let surface = mcp_surface("gw-cancel", json!({"require_all": true}));
        let fabric = no_fabric();
        let intake = read(&surface, &x402_headers(&unique("proof")), &tool_call("paid_tool", json!({})));
        let cancelled = tokio::time::timeout(Duration::from_millis(20), charge(&intake, call(&surface, &fabric))).await;
        assert!(cancelled.is_err());
        gate.delay
            .lock()
            .unwrap()
            .clone_from(&Duration::ZERO);
        assert!(matches!(charge(&intake, call(&surface, &fabric)).await, GateOutcome::Paid(_)));
    }

    #[tokio::test]
    async fn a_credential_on_a_different_request_is_sent_to_agent_pay_under_a_different_key() {
        let gate = paid_gate();
        install_test_transport("gw-keys", gate.clone());
        let surface = mcp_surface("gw-keys", json!({"require_all": true}));
        let fabric = no_fabric();
        let credential = unique("proof");
        for tool in ["premium_a", "premium_b"] {
            let intake = read(&surface, &x402_headers(&credential), &tool_call(tool, json!({})));
            assert!(matches!(charge(&intake, call(&surface, &fabric)).await, GateOutcome::Paid(_)), "{tool}");
        }
        let sent = gate.sent();
        let keys: Vec<&Value> = sent
            .iter()
            .map(|request| &request.payment_context["correlation"]["idempotency_key"])
            .collect();
        assert_eq!(keys.len(), 2);
        assert_ne!(keys[0], keys[1], "agent-pay can tell the two requests apart");
        assert_eq!(sent[0].headers["PAYMENT-SIGNATURE"], sent[1].headers["PAYMENT-SIGNATURE"]);
    }

    #[tokio::test]
    async fn a_paid_response_relays_the_gates_cache_control() {
        let gate = paid_gate();
        install_test_transport("gw-cache", gate);
        let surface = mcp_surface("gw-cache", json!({"require_all": true}));
        let fabric = no_fabric();
        let intake = read(&surface, &x402_headers(&unique("proof")), &tool_call("t", json!({})));
        let GateOutcome::Paid(paid) = charge(&intake, call(&surface, &fabric)).await else { panic!("paid") };
        let mut headers = HeaderMap::new();
        paid.receipt
            .apply(&mut headers);
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(headers["payment-response"], "the-receipt");

        install_test_transport("gw-cache-none", MockGate::answering(200, &[("Payment-Receipt", "r")], json!({})));
        let surface = mcp_surface("gw-cache-none", json!({"require_all": true}));
        let intake = read(&surface, &x402_headers(&unique("proof")), &tool_call("t", json!({})));
        let GateOutcome::Paid(paid) = charge(&intake, call(&surface, &fabric)).await else { panic!("paid") };
        let mut headers = HeaderMap::new();
        paid.receipt
            .apply(&mut headers);
        assert!(!headers.contains_key("cache-control"), "nothing is invented when the gate set none");
    }

    #[tokio::test]
    async fn the_gate_records_the_receipt_reference_and_one_rail_for_every_record() {
        let reference = crate::mpp::challenge::base64url_encode_nopad(br#"{"reference":"ref-77","method":"tempo"}"#);
        let gate = MockGate::answering(200, &[("payment-receipt", reference.as_str())], json!({}))
            .challenging(&[("www-authenticate", "Payment id=\"c\"")], json!({}));
        install_test_transport("gw-ledger", gate);
        let surface = mcp_surface(
            "gw-ledger",
            json!({"require_all": true, "manifest_snapshot": {"amount": {"amount": "2", "unit": "USD"},
                "payment_points": [{"id": "a", "protocol": "x402"}, {"id": "b", "protocol": "mpp"}]}}),
        );
        let fabric = no_fabric();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_str(&format!("Payment {}", mpp_token())).unwrap());
        let body = tool_call("ledgered", json!({}));
        let paid = read(&surface, &headers, &body);
        let (outcome, events) = crate::audit::producer::capture(charge(&paid, call(&surface, &fabric))).await;
        let GateOutcome::Paid(paid_outcome) = outcome else { panic!("expected paid") };
        assert_eq!(paid_outcome.receipt.headers()[0].0, "payment-receipt");
        let events = payment_events(&events);
        let (event, _) = events
            .first()
            .expect("a payment event is recorded");
        assert_eq!(event.stage, crate::delegation_vault::audit::PaymentStage::Verified);
        assert_eq!(
            event.rail,
            crate::delegation_vault::audit::PaymentRail::Mpp,
            "the rail of the presented credential"
        );
        assert_eq!(event.amount.as_deref(), Some("2"));
        assert_eq!(event.method.as_deref(), Some("tempo"));
        assert!(!format!("{event:?}").contains(&mpp_token()), "the credential is never recorded");
        let delegation = event
            .delegation
            .clone()
            .expect("delegation facts");
        assert_eq!(
            delegation
                .receipt_reference
                .as_deref(),
            Some("ref-77")
        );
        assert_eq!(delegation.resource.as_deref(), Some("ledgered"));
        assert_eq!(delegation.variant.as_deref(), Some("gold"));
        assert_eq!(
            delegation
                .gateway_did
                .as_deref(),
            Some("did:web:agent-pay.example")
        );
        assert!(
            delegation
                .idempotency_key
                .is_some()
        );

        let both = read(&surface, &HeaderMap::new(), &body);
        assert_eq!(
            serde_json::to_value(both.policy_input()).unwrap()["rail"],
            Value::Null,
            "a manifest offering both rails names none"
        );
        let (outcome, events) = crate::audit::producer::capture(charge(&both, call(&surface, &fabric))).await;
        assert!(matches!(outcome, GateOutcome::Refused(_)));
        let events = payment_events(&events);
        assert_eq!(events[0].0.stage, crate::delegation_vault::audit::PaymentStage::ChallengeIssued);
        assert_eq!(
            events[0].0.rail,
            crate::delegation_vault::audit::PaymentRail::X402,
            "the audit trail has no undetermined rail, so one that is not known is recorded as x402"
        );

        let one_rail = policy(json!({"manifest_snapshot": {"payment_points": [{"id": "b", "protocol": "mpp"}]}}));
        assert_eq!(resolved_rail(None, &one_rail), Some(Rail::Mpp));
        assert_eq!(resolved_rail(Some(Rail::X402), &one_rail), Some(Rail::X402));
        assert_eq!(resolved_rail(None, &policy(json!({}))), None);
    }

    #[tokio::test]
    async fn a_hold_a_refusal_and_an_outage_are_recorded_with_their_reasons() {
        let fabric = no_fabric();
        let surface = mcp_surface("gw-reasons", json!({"require_all": true}));
        let body = tool_call("t", json!({}));
        for (answer, expected_stage, expected_error) in [
            (
                answer(403, &[], json!({"status": "rejected_by_oversight"})),
                crate::delegation_vault::audit::PaymentStage::Failed,
                Some("rejected_by_oversight"),
            ),
            (
                answer(403, &[], json!({"error": "Gateway not authorized for this surface"})),
                crate::delegation_vault::audit::PaymentStage::Failed,
                Some("payment gateway refused the request"),
            ),
            (
                answer(202, &[], json!({"status": "held_for_oversight", "case_id": "case-1"})),
                crate::delegation_vault::audit::PaymentStage::Held,
                None,
            ),
        ] {
            let gate = MockGate::with_answer(answer);
            install_test_transport("gw-reasons", gate);
            let intake = read(&surface, &x402_headers(&unique("proof")), &body);
            let (_, events) = crate::audit::producer::capture(charge(&intake, call(&surface, &fabric))).await;
            let events = payment_events(&events);
            assert_eq!(events[0].0.stage, expected_stage);
            assert_eq!(events[0].0.error.as_deref(), expected_error);
        }
    }
}
