//! Response authentication on the request path: the one check a response from a surface's
//! Target must pass, under `target.response_auth`, before anything else reads it, and the
//! answer to a caller whose request got a response that failed it.
//!
//! An API key response passes when its key header holds exactly one value equal, compared in
//! constant time, to one of the keys the configured secret holds (comma-separated, so a key
//! can be rotated), and the secret is the surface's tenant's or appliance-wide. The key header
//! is removed whatever the outcome, so it never reaches the caller.
//!
//! An mTLS response is checked in the TLS handshake, before any response exists: the forward
//! client speaks TLS with the surface's settings ([`target_tls`]), and a handshake that fails
//! the server trust ([`handshake_failure`]) is refused like a response that fails its check.
//!
//! Every hop to the Target picks its TLS settings with [`hop_tls`] and checks what it was sent
//! back with [`authenticate_sent`], so a hop that cannot check the setting sends nothing.

mod tls;

#[cfg(test)]
pub(crate) use tests::{BRAVO_KEY, BRAVO_KEY_HEADER, api_key_bravo, bravo_key_store};
pub(crate) use tls::forget_tls_settings;
#[cfg(test)]
pub(crate) use tls::tests::{pinned_bravo, untrusted_target};
pub use tls::{handshake_failure, target_tls, tls_stamp};

use std::sync::Arc;

use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::response::Response;
use subtle::ConstantTimeEq;
use tracing::warn;
use zeroize::Zeroizing;

use crate::audit::request_events::{RejectionReason, RejectionStage, RequestFacts, request_rejected};
use crate::config::agent_surface::AgentSurface;
use crate::config::response_auth::{ApiKeyResponseAuth, ResponseAuthConfig};
use crate::secrets::SecretsStore;

/// The body of every refusal. It names no reason, so a server answering in the managed
/// agent's place learns nothing from it.
pub const REFUSAL_MESSAGE: &str = "Upstream response refused";

/// The JSON-RPC error code of a refusal answered to a JSON-RPC request.
const REFUSAL_RPC_CODE: i32 = -32603;

/// Why a Target's response failed response authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseAuthFailure {
    /// The response carries no key header.
    KeyMissing,
    /// The key header holds no accepted key, or more than one value.
    KeyMismatch,
    /// The accepted keys or certificates cannot be used: a secret or certificate is missing,
    /// inactive, outside the surface's tenant, of the wrong kind or unreadable, its store is
    /// unavailable, or the header name is invalid.
    Unverifiable,
    /// The Target's server certificate failed the configured server trust in the TLS handshake.
    ServerUntrusted,
}

impl ResponseAuthFailure {
    /// The fixed reason the refusal is logged with.
    pub fn reason(self) -> &'static str {
        match self {
            Self::KeyMissing => "key_missing",
            Self::KeyMismatch => "key_mismatch",
            Self::Unverifiable => "unverifiable",
            Self::ServerUntrusted => "server_untrusted",
        }
    }
}

/// Checks the `headers` of a response from `surface`'s Target against its
/// `target.response_auth`, removing the key header whatever the outcome. A surface without the
/// setting, or with mTLS, which the handshake already checked, accepts every response and its
/// headers are left as they are.
pub async fn authenticate_response(
    surface: &AgentSurface,
    headers: &mut HeaderMap,
    secrets: Option<&Arc<dyn SecretsStore>>,
) -> Result<(), ResponseAuthFailure> {
    match surface
        .target
        .response_auth
        .as_ref()
    {
        None | Some(ResponseAuthConfig::Mtls(_)) => Ok(()),
        Some(ResponseAuthConfig::ApiKey(config)) => authenticate_api_key(surface, config, headers, secrets).await,
    }
}

async fn authenticate_api_key(
    surface: &AgentSurface,
    config: &ApiKeyResponseAuth,
    headers: &mut HeaderMap,
    secrets: Option<&Arc<dyn SecretsStore>>,
) -> Result<(), ResponseAuthFailure> {
    let name = HeaderName::from_bytes(config.header_name.as_bytes()).map_err(|_| ResponseAuthFailure::Unverifiable)?;
    let presented: Vec<_> = headers
        .get_all(&name)
        .iter()
        .cloned()
        .collect();
    headers.remove(&name);
    let presented = match presented.as_slice() {
        [] => return Err(ResponseAuthFailure::KeyMissing),
        [presented] => presented,
        _ => return Err(ResponseAuthFailure::KeyMismatch),
    };
    let keys = accepted_keys(surface, &config.secret_id, secrets).await?;
    let matched = keys
        .split(',')
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .fold(subtle::Choice::from(0), |matched, key| {
            matched
                | presented
                    .as_bytes()
                    .ct_eq(key.as_bytes())
        });
    if bool::from(matched) {
        Ok(())
    } else {
        Err(ResponseAuthFailure::KeyMismatch)
    }
}

/// The TLS settings a hop sends a request for `surface`'s Target to `url` with: `None`
/// without Response authentication, and [`ResponseAuthFailure::Unverifiable`] when the
/// setting cannot be checked on that hop, so nothing is sent: any setting on a URL that is not
/// http or https, mTLS on one that is not https, or mTLS settings that cannot be built.
pub async fn hop_tls(
    surface: &AgentSurface,
    url: &str,
    certificates: Option<&Arc<dyn crate::certificates::CertificateStore>>,
) -> Result<Option<Arc<rustls::ClientConfig>>, ResponseAuthFailure> {
    let Some(setting) = surface
        .target
        .response_auth
        .as_ref()
    else {
        return Ok(None);
    };
    let scheme = url::Url::parse(url)
        .ok()
        .map(|url| url.scheme().to_string());
    let checkable = match setting {
        ResponseAuthConfig::ApiKey(_) => matches!(scheme.as_deref(), Some("http" | "https")),
        ResponseAuthConfig::Mtls(_) => scheme.as_deref() == Some("https"),
    };
    if !checkable {
        warn!(
            surface = %surface.surface_id,
            scheme = scheme.as_deref().unwrap_or("none"),
            "Response authentication cannot be checked on a request to this Target"
        );
        return Err(ResponseAuthFailure::Unverifiable);
    }
    target_tls(surface, certificates).await
}

/// Checks what sending a request to `surface`'s Target gave: a response's headers by
/// [`authenticate_response`], and an error by [`handshake_failure`]. Any other error passes,
/// for the hop to handle as it handles a Target it cannot reach.
pub async fn authenticate_sent(
    surface: &AgentSurface,
    sent: &mut Result<reqwest::Response, reqwest::Error>,
    secrets: Option<&Arc<dyn SecretsStore>>,
) -> Result<(), ResponseAuthFailure> {
    match sent {
        Ok(response) => authenticate_response(surface, response.headers_mut(), secrets).await,
        Err(error) => handshake_failure(surface, error).map_or(Ok(()), Err),
    }
}

/// The value of the secret `secret_id`, when `surface` may use it and it holds a key.
async fn accepted_keys(
    surface: &AgentSurface,
    secret_id: &str,
    secrets: Option<&Arc<dyn SecretsStore>>,
) -> Result<Zeroizing<String>, ResponseAuthFailure> {
    let secret = secrets
        .ok_or(ResponseAuthFailure::Unverifiable)?
        .get_by_secret_id(secret_id)
        .await
        .map_err(|_| ResponseAuthFailure::Unverifiable)?
        .ok_or(ResponseAuthFailure::Unverifiable)?;
    if !crate::tenancy::can_reference(surface.tenant_id.as_deref(), secret.tenant_id.as_deref()) {
        return Err(ResponseAuthFailure::Unverifiable);
    }
    let value = Zeroizing::new(secret.value);
    if value
        .split(',')
        .all(|key| key.trim().is_empty())
    {
        return Err(ResponseAuthFailure::Unverifiable);
    }
    Ok(value)
}

/// Refuses a request whose Target response failed with `failure`: logs the reason, records a
/// `request_rejected` at the forward stage with reason `target_response_auth_failed`, and
/// answers `502` with a body that names no reason, a JSON-RPC error echoing the request's `id`
/// when `request_body` is a JSON-RPC request.
pub fn refuse(
    failure: ResponseAuthFailure,
    facts: &RequestFacts<'_>,
    request_body: &[u8],
) -> Response {
    warn!(
        surface = %facts.surface_id,
        reason = failure.reason(),
        "Refusing a Target response that failed response authentication"
    );
    let rpc_id = jsonrpc_request_id(request_body);
    request_rejected(
        facts,
        RejectionStage::Forward,
        RejectionReason::TargetResponseAuthFailed,
        StatusCode::BAD_GATEWAY.as_u16(),
        rpc_id
            .is_some()
            .then_some(i64::from(REFUSAL_RPC_CODE)),
    );
    match rpc_id {
        Some(id) => crate::a2a::errors::create_jsonrpc_error_response_with_id(
            StatusCode::BAD_GATEWAY,
            id,
            REFUSAL_RPC_CODE,
            REFUSAL_MESSAGE,
        ),
        None => crate::a2a::create_error_response(StatusCode::BAD_GATEWAY, REFUSAL_MESSAGE),
    }
}

/// The `id` of `body` when it is a JSON-RPC request object, `null` when it has none.
fn jsonrpc_request_id(body: &[u8]) -> Option<serde_json::Value> {
    let request: serde_json::Value = serde_json::from_slice(body).ok()?;
    request
        .get("jsonrpc")
        .is_some()
        .then(|| {
            request
                .get("id")
                .cloned()
                .unwrap_or(serde_json::Value::Null)
        })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::secrets::{CreateSecretRequest, FilesystemSecretsStore};
    use serde_json::json;

    /// The header the managed agent of [`api_key_bravo`] returns its key in.
    pub(crate) const BRAVO_KEY_HEADER: &str = "X-Agent-Key";
    /// The key the managed agent of [`api_key_bravo`] returns.
    pub(crate) const BRAVO_KEY: &str = "bravo-secret";

    /// The `target.response_auth` that reads the key of secret `bravo-key` from
    /// [`BRAVO_KEY_HEADER`].
    pub(crate) fn api_key_bravo() -> serde_json::Value {
        json!({"api_key": {"header_name": BRAVO_KEY_HEADER, "secret_id": "bravo-key"}})
    }

    /// A secrets store holding the secret `bravo-key` with [`BRAVO_KEY`].
    pub(crate) async fn bravo_key_store() -> (tempfile::TempDir, Arc<dyn SecretsStore>) {
        store(&[("bravo-key", BRAVO_KEY, None)]).await
    }

    /// A secrets store holding each `(secret_id, value, tenant_id)`.
    async fn store(secrets: &[(&str, &str, Option<&str>)]) -> (tempfile::TempDir, Arc<dyn SecretsStore>) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FilesystemSecretsStore::new_async(
            dir.path()
                .to_str()
                .expect("utf-8 path"),
        )
        .await
        .expect("secrets store");
        for (secret_id, value, tenant_id) in secrets {
            store
                .create(CreateSecretRequest {
                    tenant_id: tenant_id.map(String::from),
                    name: secret_id.to_string(),
                    secret_id: secret_id.to_string(),
                    description: None,
                    value: value.to_string(),
                    secret_type: "General".to_string(),
                    tags: vec![],
                })
                .await
                .expect("secret created");
        }
        (dir, Arc::new(store))
    }

    /// A surface of `tenant_id` whose Target's responses carry a key of `bravo-key` in
    /// `X-Agent-Key`.
    fn surface(tenant_id: Option<&str>) -> AgentSurface {
        serde_json::from_value(json!({
            "surface_id": "surface-1", "name": "surface-1", "tenant_id": tenant_id,
            "access_point": {"listen_address": "0.0.0.0:9000", "route": "/agent", "protocol": "a2a"},
            "target": {"endpoint": "https://bravo.example",
                "response_auth": {"api_key": {"header_name": "X-Agent-Key", "secret_id": "bravo-key"}}}
        }))
        .expect("surface parses")
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).expect("header name"),
                value
                    .parse()
                    .expect("header value"),
            );
        }
        headers
    }

    async fn check(
        surface: &AgentSurface,
        secrets: &[(&str, &str, Option<&str>)],
        response: &[(&str, &str)],
    ) -> (Result<(), ResponseAuthFailure>, HeaderMap) {
        let (_dir, store) = store(secrets).await;
        let mut headers = headers(response);
        let outcome = authenticate_response(surface, &mut headers, Some(&store)).await;
        (outcome, headers)
    }

    #[tokio::test]
    async fn test_a_response_with_the_registered_key_passes_without_the_key_header() {
        let (outcome, headers) = check(
            &surface(None),
            &[("bravo-key", "bravo-secret", None)],
            &[("X-Agent-Key", "bravo-secret"), ("Content-Type", "application/json")],
        )
        .await;
        assert_eq!(outcome, Ok(()));
        assert!(
            headers
                .get("x-agent-key")
                .is_none(),
            "the key never reaches the caller"
        );
        assert_eq!(
            headers
                .get("content-type")
                .map(|value| value.as_bytes()),
            Some(&b"application/json"[..])
        );
    }

    #[tokio::test]
    async fn test_the_key_header_is_matched_whatever_its_case() {
        let (outcome, headers) =
            check(&surface(None), &[("bravo-key", "bravo-secret", None)], &[("x-AGENT-key", "bravo-secret")]).await;
        assert_eq!(outcome, Ok(()));
        assert!(headers.is_empty());
    }

    #[tokio::test]
    async fn test_a_response_without_the_key_fails_as_missing() {
        let (outcome, _) =
            check(&surface(None), &[("bravo-key", "bravo-secret", None)], &[("X-Other", "bravo-secret")]).await;
        assert_eq!(outcome, Err(ResponseAuthFailure::KeyMissing));
    }

    #[tokio::test]
    async fn test_a_response_with_another_key_fails_without_the_key_header() {
        for presented in ["bravo-secre", "bravo-secret2", "BRAVO-SECRET", "bravo-secret,other", ""] {
            let (outcome, headers) =
                check(&surface(None), &[("bravo-key", "bravo-secret", None)], &[("X-Agent-Key", presented)]).await;
            assert_eq!(outcome, Err(ResponseAuthFailure::KeyMismatch), "{presented:?}");
            assert!(
                headers
                    .get("x-agent-key")
                    .is_none(),
                "{presented:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_a_key_header_sent_twice_fails_even_with_the_registered_key() {
        let (outcome, headers) = check(
            &surface(None),
            &[("bravo-key", "bravo-secret", None)],
            &[("X-Agent-Key", "bravo-secret"), ("X-Agent-Key", "guess")],
        )
        .await;
        assert_eq!(outcome, Err(ResponseAuthFailure::KeyMismatch));
        assert!(
            headers
                .get("x-agent-key")
                .is_none(),
            "every value is removed"
        );
    }

    #[tokio::test]
    async fn test_every_key_of_a_rotated_secret_is_accepted() {
        for presented in ["old-secret", "new-secret"] {
            let (outcome, _) =
                check(&surface(None), &[("bravo-key", "old-secret, new-secret", None)], &[("X-Agent-Key", presented)])
                    .await;
            assert_eq!(outcome, Ok(()), "{presented}");
        }
    }

    #[tokio::test]
    async fn test_a_key_that_cannot_be_read_or_used_fails_as_unverifiable() {
        for (case, surface, secrets) in [
            ("a missing secret", surface(None), vec![("other-key", "bravo-secret", None)]),
            (
                "another tenant's secret",
                surface(Some("tenant-a")),
                vec![("bravo-key", "bravo-secret", Some("tenant-b"))],
            ),
            (
                "a tenant secret on an appliance surface",
                surface(None),
                vec![("bravo-key", "bravo-secret", Some("tenant-a"))],
            ),
            ("a secret with no key", surface(None), vec![("bravo-key", " , ", None)]),
        ] {
            let (outcome, headers) = check(&surface, &secrets, &[("X-Agent-Key", "bravo-secret")]).await;
            assert_eq!(outcome, Err(ResponseAuthFailure::Unverifiable), "{case}");
            assert!(
                headers
                    .get("x-agent-key")
                    .is_none(),
                "{case}"
            );
        }
        let mut no_store = headers(&[("X-Agent-Key", "bravo-secret")]);
        assert_eq!(
            authenticate_response(&surface(None), &mut no_store, None).await,
            Err(ResponseAuthFailure::Unverifiable),
            "no secrets store"
        );
    }

    #[tokio::test]
    async fn test_a_tenant_surface_accepts_its_own_or_an_appliance_wide_secret() {
        for owner in [Some("tenant-a"), None] {
            let (outcome, _) = check(
                &surface(Some("tenant-a")),
                &[("bravo-key", "bravo-secret", owner)],
                &[("X-Agent-Key", "bravo-secret")],
            )
            .await;
            assert_eq!(outcome, Ok(()), "{owner:?}");
        }
    }

    #[tokio::test]
    async fn test_a_surface_without_response_auth_accepts_the_response_unchanged() {
        let mut plain = surface(None);
        plain.target.response_auth = None;
        let mut response = headers(&[("X-Agent-Key", "anything")]);
        assert_eq!(authenticate_response(&plain, &mut response, None).await, Ok(()));
        assert_eq!(
            response
                .get("x-agent-key")
                .map(|value| value.as_bytes()),
            Some(&b"anything"[..])
        );
    }

    fn with_setting(response_auth: serde_json::Value) -> AgentSurface {
        let mut surface = surface(None);
        surface.surface_id = "hop-tls".to_string();
        surface.target.response_auth = serde_json::from_value(response_auth).expect("setting parses");
        surface
    }

    #[tokio::test]
    async fn test_an_api_key_is_checked_on_an_http_or_https_hop_with_the_default_tls() {
        let surface = with_setting(api_key_bravo());
        for url in ["https://bravo.example/agent", "http://bravo.example/agent"] {
            assert!(matches!(hop_tls(&surface, url, None).await, Ok(None)), "{url}");
        }
    }

    #[tokio::test]
    async fn test_a_hop_that_cannot_check_the_setting_is_refused_before_sending() {
        let api_key = with_setting(api_key_bravo());
        for url in ["proxy://weather", "a2a-proxy://proxy-1", "fabric://peer/surface", "", "not a url"] {
            assert_eq!(
                hop_tls(&api_key, url, None)
                    .await
                    .err(),
                Some(ResponseAuthFailure::Unverifiable),
                "{url:?}"
            );
        }
        let mtls = with_setting(super::tls::tests::pinned_bravo());
        assert_eq!(
            hop_tls(&mtls, "http://bravo.example/agent", None)
                .await
                .err(),
            Some(ResponseAuthFailure::Unverifiable),
            "mTLS on an http hop"
        );
        assert_eq!(
            hop_tls(&mtls, "https://bravo.example/agent", None)
                .await
                .err(),
            Some(ResponseAuthFailure::Unverifiable),
            "mTLS settings that cannot be built"
        );
    }

    #[tokio::test]
    async fn test_a_hop_without_the_setting_sends_whatever_its_url() {
        let mut plain = surface(None);
        plain.target.response_auth = None;
        for url in ["proxy://weather", "a2a-proxy://proxy-1", "", "http://bravo.example"] {
            assert!(matches!(hop_tls(&plain, url, None).await, Ok(None)), "{url:?}");
        }
    }

    fn sent_response(pairs: &[(&str, &str)]) -> Result<reqwest::Response, reqwest::Error> {
        let mut response = axum::http::Response::new(reqwest::Body::from("ok"));
        *response.headers_mut() = headers(pairs);
        Ok(reqwest::Response::from(response))
    }

    #[tokio::test]
    async fn test_a_sent_response_is_checked_and_loses_its_key_header() {
        let (_dir, store) = bravo_key_store().await;
        let surface = surface(None);

        let mut keyed = sent_response(&[(BRAVO_KEY_HEADER, BRAVO_KEY)]);
        assert_eq!(authenticate_sent(&surface, &mut keyed, Some(&store)).await, Ok(()));
        assert!(
            keyed
                .expect("a response")
                .headers()
                .get(BRAVO_KEY_HEADER)
                .is_none()
        );

        let mut unkeyed = sent_response(&[]);
        assert_eq!(authenticate_sent(&surface, &mut unkeyed, Some(&store)).await, Err(ResponseAuthFailure::KeyMissing));
    }

    #[tokio::test]
    async fn test_a_target_that_cannot_be_reached_is_left_to_the_hop() {
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind")
            .local_addr()
            .expect("address")
            .port();
        let mut sent = reqwest::Client::new()
            .get(format!("http://127.0.0.1:{closed}/"))
            .send()
            .await;
        assert!(sent.is_err(), "nothing listens");
        assert_eq!(authenticate_sent(&surface(None), &mut sent, None).await, Ok(()));
        assert!(sent.is_err(), "the error is the hop's to handle");
    }

    fn facts() -> RequestFacts<'static> {
        RequestFacts {
            surface_id: "surface-1",
            channel_name: "surface-1",
            trace_id: Some("trace-1"),
            via_fabric: false,
        }
    }

    async fn body(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("JSON body")
    }

    fn recorded(
        events: &[crate::delegation_vault::audit::DelegationAuditEvent]
    ) -> Vec<(RejectionStage, RejectionReason, Option<u16>, Option<i64>)> {
        events
            .iter()
            .filter_map(|event| match &event.event {
                crate::delegation_vault::audit::DelegationAuditAction::RequestRejected {
                    stage,
                    reason,
                    http_status,
                    rpc_error_code,
                    ..
                } => Some((*stage, *reason, *http_status, *rpc_error_code)),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn test_a_refused_json_rpc_request_gets_a_json_rpc_502_naming_no_reason_and_is_audited() {
        let request = br#"{"jsonrpc":"2.0","id":7,"method":"message/send","params":{}}"#;
        let (response, events) =
            crate::audit::producer::capture(async { refuse(ResponseAuthFailure::KeyMissing, &facts(), request) }).await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = body(response).await;
        assert_eq!(body["id"], 7);
        assert_eq!(body["error"]["code"], -32603);
        assert_eq!(body["error"]["message"], REFUSAL_MESSAGE);
        assert!(
            !body
                .to_string()
                .contains("key_missing"),
            "{body}"
        );
        assert_eq!(
            recorded(&events),
            vec![(RejectionStage::Forward, RejectionReason::TargetResponseAuthFailed, Some(502), Some(-32603))]
        );
        assert_eq!(
            serde_json::to_value(&events[0]).expect("serialises")["event"]["request_rejected"]["reason"],
            "target_response_auth_failed"
        );
    }

    #[tokio::test]
    async fn test_a_refused_request_that_is_not_json_rpc_gets_a_problem_502() {
        for request in [&br#"{"message":{"role":"user"}}"#[..], b"", b"not json"] {
            let (response, events) =
                crate::audit::producer::capture(async { refuse(ResponseAuthFailure::KeyMismatch, &facts(), request) })
                    .await;
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            let body = body(response).await;
            assert_eq!(body["detail"], REFUSAL_MESSAGE, "{body}");
            assert_eq!(
                recorded(&events),
                vec![(RejectionStage::Forward, RejectionReason::TargetResponseAuthFailed, Some(502), None)]
            );
        }
    }
}
