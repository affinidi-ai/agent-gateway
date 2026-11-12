//! Token requests of external consent: the authorization code exchange and the
//! refresh of a grant by binding, at the provider's pinned token endpoint.
//!
//! Each request goes through the pinned, Strict, `https`-only egress client,
//! with redirects refused and proxies ignored, and is sent and read by the
//! token request every credential provider shares
//! ([`super::oauth::post_token_request`]): a 30 second timeout and a 64 KiB
//! cap on the answer. It names the provider's `resource` (RFC 8707) unless the
//! provider's `send_resource` is off, and the client authenticates as its
//! `token_endpoint_auth_method` says
//! ([`super::revocation::ClientCredential`]), with a secret or signing key
//! of the provider's own tenant only (an untenanted provider uses untenanted
//! ones). The answer must be a
//! `Bearer` token. Nothing the authorization server sends is logged or
//! echoed: a refusal is reported by its OAuth `error` code alone.

use std::sync::Arc;

use serde::Deserialize;

use super::oauth::TOKEN_REQUEST_TIMEOUT;
use crate::credential_providers::CredentialProvider;
use crate::secrets::SecretsStore;

/// The longest access token lifetime accepted, a year and a day.
const MAX_EXPIRES_IN_SECS: i64 = 366 * 86_400;

/// The most scopes a token answer may name.
const MAX_SCOPES: usize = 128;

/// What is asked of the token endpoint.
pub enum TokenRequest<'a> {
    /// Redeem an authorization code with the PKCE verifier only the gateway
    /// holds, for the redirect URI the authorization request named.
    AuthorizationCode { code: &'a str, redirect_uri: &'a str, code_verifier: &'a str },
    /// Refresh a grant, asking again for the scopes its connect asked for
    /// that the grant still holds.
    Refresh { refresh_token: &'a str, scopes: &'a [String] },
}

/// Why a token request obtained no token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenFailure {
    /// The server refused the client: `invalid_client`, or a `401`.
    InvalidClient,
    /// The server refused the code or the refresh token: `invalid_grant`.
    InvalidGrant,
    /// The server refused the request for another reason.
    Refused,
    /// The server answered that it cannot serve now (`5xx`, `429`).
    Unavailable,
    /// The endpoint could not be reached, or egress policy refused it.
    Unreachable,
    /// The server's answer is not an acceptable `Bearer` token answer.
    InvalidResponse,
    /// The client's secret could not be resolved in the provider's tenant.
    ClientUnavailable,
}

impl TokenFailure {
    /// The failure as connect answers and logs name it.
    pub fn reason(self) -> &'static str {
        match self {
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::Refused => "token_endpoint_refused",
            Self::Unavailable | Self::Unreachable => "token_endpoint_unreachable",
            Self::InvalidResponse => "invalid_token_response",
            Self::ClientUnavailable => "client_unavailable",
        }
    }
}

/// The tokens a token endpoint answered with.
#[derive(Clone)]
pub struct TokenAnswer {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// The scopes the answer names, when it names them.
    pub scopes: Option<Vec<String>>,
    pub expires_in: Option<i64>,
    /// The vendor account the tokens are for: the `sub` of the answer's
    /// OpenID Connect ID token, when it has one of the provider's issuer for
    /// its client.
    pub subject: Option<String>,
}

impl std::fmt::Debug for TokenAnswer {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        formatter
            .debug_struct("TokenAnswer")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self
                    .refresh_token
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .field("scopes", &self.scopes)
            .field("expires_in", &self.expires_in)
            .field(
                "subject",
                &self
                    .subject
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Deserialize)]
struct TokenResponseBody {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<serde_json::Value>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// Send `request` to `provider`'s token endpoint and return the tokens it
/// answered with. `exact_allowlist` is the test allow-list of fixtures
/// ([`crate::egress::bdd_egress_allowlist`] on the production path, so
/// `None`).
pub async fn request_token(
    provider: &CredentialProvider,
    secrets: Option<&Arc<dyn SecretsStore>>,
    exact_allowlist: Option<&str>,
    request: TokenRequest<'_>,
) -> Result<TokenAnswer, TokenFailure> {
    let Some(endpoint) = provider
        .token_endpoint
        .as_deref()
    else {
        return Err(TokenFailure::ClientUnavailable);
    };
    let authentication = super::revocation::ClientCredential::resolve(provider, secrets)
        .await
        .ok()
        .and_then(|credential| credential.authenticate(provider))
        .ok_or(TokenFailure::ClientUnavailable)?;
    let scope;
    let mut form: Vec<(&str, &str)> = match &request {
        TokenRequest::AuthorizationCode {
            code,
            redirect_uri,
            code_verifier,
        } => vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", code_verifier),
        ],
        TokenRequest::Refresh { refresh_token, scopes } => {
            scope = scopes.join(" ");
            let mut form = vec![("grant_type", "refresh_token"), ("refresh_token", *refresh_token)];
            if !scope.is_empty() {
                form.push(("scope", scope.as_str()));
            }
            form
        }
    };
    if provider.send_resource
        && let Some(resource) = provider.resource.as_deref()
    {
        form.push(("resource", resource));
    }
    form.extend(
        authentication
            .form
            .iter()
            .map(|(name, value)| (*name, value.as_str())),
    );
    let http = crate::egress::pinned_vendor_client(endpoint, TOKEN_REQUEST_TIMEOUT, exact_allowlist)
        .await
        .map_err(|error| {
            tracing::warn!(
                target: "credential_delegation",
                surface_variant = crate::observability::policy_audit::current_request_variant().as_deref(),
                credential_provider_id = %provider.id,
                error = ?error.to_string(),
                "A token endpoint was refused by egress policy"
            );
            TokenFailure::Unreachable
        })?;
    let super::oauth::TokenEndpointAnswer { status, body } = super::oauth::post_token_request(
        &http,
        endpoint,
        &form,
        authentication
            .authorization
            .as_deref()
            .map(String::as_str),
    )
    .await
    .map_err(|failure| match failure {
        super::oauth::TokenPostFailure::TooLarge => TokenFailure::InvalidResponse,
        _ => TokenFailure::Unreachable,
    })?;
    let parsed: Option<TokenResponseBody> = serde_json::from_slice(&body).ok();
    if !status.is_success() {
        let error = parsed
            .as_ref()
            .and_then(|body| body.error.as_deref());
        return Err(match (status.as_u16(), error) {
            (_, Some("invalid_grant")) => TokenFailure::InvalidGrant,
            (_, Some("invalid_client")) | (401, _) => TokenFailure::InvalidClient,
            (429, _) => TokenFailure::Unavailable,
            (status, _) if status >= 500 => TokenFailure::Unavailable,
            _ => TokenFailure::Refused,
        });
    }
    parsed
        .ok_or(TokenFailure::InvalidResponse)
        .and_then(|body| token_answer(provider, body))
}

/// A token answer's tokens, if it is an acceptable `Bearer` answer: an access
/// token that can be sent in a header, a refresh token that is not empty, a
/// lifetime of at most a year and a day, and at most 128 scopes. The vendor
/// account is read from its ID token, when it has one of `provider`'s issuer
/// for its client.
fn token_answer(
    provider: &CredentialProvider,
    body: TokenResponseBody,
) -> Result<TokenAnswer, TokenFailure> {
    let access_token = body
        .access_token
        .filter(|token| !token.is_empty())
        .filter(|token| reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).is_ok())
        .ok_or(TokenFailure::InvalidResponse)?;
    if !body
        .token_type
        .is_some_and(|token_type| token_type.eq_ignore_ascii_case("bearer"))
    {
        return Err(TokenFailure::InvalidResponse);
    }
    let expires_in = match body.expires_in {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Number(number)) => Some(
            number
                .as_i64()
                .ok_or(TokenFailure::InvalidResponse)?,
        ),
        Some(serde_json::Value::String(text)) => Some(
            text.parse::<i64>()
                .map_err(|_| TokenFailure::InvalidResponse)?,
        ),
        Some(_) => return Err(TokenFailure::InvalidResponse),
    };
    if expires_in.is_some_and(|seconds| seconds <= 0 || seconds > MAX_EXPIRES_IN_SECS) {
        return Err(TokenFailure::InvalidResponse);
    }
    if body
        .refresh_token
        .as_deref()
        .is_some_and(str::is_empty)
    {
        return Err(TokenFailure::InvalidResponse);
    }
    let scopes = body.scope.map(|scope| {
        scope
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>()
    });
    if scopes
        .as_ref()
        .is_some_and(|scopes| scopes.len() > MAX_SCOPES)
    {
        return Err(TokenFailure::InvalidResponse);
    }
    Ok(TokenAnswer {
        access_token,
        refresh_token: body.refresh_token,
        scopes,
        expires_in,
        subject: body
            .id_token
            .as_deref()
            .and_then(|id_token| id_token_subject(provider, id_token)),
    })
}

/// The longest `sub` an OpenID Connect ID token may carry (Core 1.0, 2).
const MAX_SUBJECT_BYTES: usize = 255;

/// The vendor account an OpenID Connect ID token names: its `sub`, when the
/// token's `iss` is `provider`'s issuer and its `aud` names the provider's
/// client. The token came straight from the pinned token endpoint over TLS,
/// which OpenID Connect Core 1.0 (3.1.3.7) accepts in place of checking its
/// signature; it is used only to tell whether two grants share one
/// authorization at the vendor, never to sign anyone in. Any other token
/// names no account.
fn id_token_subject(
    provider: &CredentialProvider,
    id_token: &str,
) -> Option<String> {
    use base64::Engine as _;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Audience {
        One(String),
        Many(Vec<String>),
    }

    #[derive(Deserialize)]
    struct Claims {
        iss: String,
        aud: Audience,
        sub: String,
    }

    let mut parts = id_token.split('.');
    let (Some(_header), Some(payload), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    let claims: Claims = serde_json::from_slice(&payload).ok()?;
    let client_id = provider
        .client_id
        .as_deref()?;
    let for_client = match &claims.aud {
        Audience::One(audience) => audience == client_id,
        Audience::Many(audiences) => audiences
            .iter()
            .any(|audience| audience == client_id),
    };
    (Some(claims.iss.as_str()) == provider.issuer.as_deref()
        && for_client
        && !claims.sub.is_empty()
        && claims.sub.len() <= MAX_SUBJECT_BYTES)
        .then_some(claims.sub)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation_vault::revocation::tests::{Answer, RecordingServer};
    use serde_json::json;

    fn provider(
        server: &RecordingServer,
        method: &str,
        secret_ref: Option<&str>,
    ) -> CredentialProvider {
        let mut provider = crate::delegation_vault::revocation::tests::provider(None, method, secret_ref);
        provider.token_endpoint = Some(format!("{}/token", server.origin()));
        provider.resource = Some("https://vendor.example/mcp".into());
        provider
    }

    fn form(body: &str) -> std::collections::HashMap<String, String> {
        url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect()
    }

    fn code() -> TokenRequest<'static> {
        TokenRequest::AuthorizationCode {
            code: "the-code",
            redirect_uri: "https://boris.example/cb",
            code_verifier: "the-verifier",
        }
    }

    /// An authorization code is redeemed with the verifier, the redirect URI
    /// and the resource, the client authenticating as its method says; the
    /// answer's tokens, scopes and lifetime are returned.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_code_is_redeemed_with_the_verifier_resource_and_client_authentication() {
        let server = RecordingServer::start_answering(vec![Answer::json(
            200,
            json!({"access_token": "access", "token_type": "bearer", "expires_in": 3600,
                "refresh_token": "refresh", "scope": "read write"}),
        )])
        .await;
        let answer = request_token(&provider(&server, "none", None), None, Some(&server.origin()), code())
            .await
            .unwrap();
        assert_eq!(answer.access_token, "access");
        assert_eq!(
            answer
                .refresh_token
                .as_deref(),
            Some("refresh")
        );
        assert_eq!(answer.scopes, Some(vec!["read".to_string(), "write".to_string()]));
        assert_eq!(answer.expires_in, Some(3600));
        let (head, body) = server.requests()[0].clone();
        let sent = form(&body);
        assert_eq!(sent["grant_type"], "authorization_code");
        assert_eq!(sent["code"], "the-code");
        assert_eq!(sent["code_verifier"], "the-verifier");
        assert_eq!(sent["redirect_uri"], "https://boris.example/cb");
        assert_eq!(sent["resource"], "https://vendor.example/mcp");
        assert_eq!(sent["client_id"], "client id");
        assert!(head.starts_with("POST /token "), "{head}");
        assert!(
            !head
                .to_ascii_lowercase()
                .contains("authorization:"),
            "{head}"
        );
        assert!(!format!("{answer:?}").contains("access\""), "the answer's Debug hides its tokens");

        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets(&directory).await;
        let server = RecordingServer::start_answering(vec![Answer::json(
            200,
            json!({"access_token": "access", "token_type": "Bearer"}),
        )])
        .await;
        request_token(
            &provider(&server, "client_secret_basic", Some("client-secret")),
            Some(&secrets),
            Some(&server.origin()),
            TokenRequest::Refresh {
                refresh_token: "the-refresh",
                scopes: &["read".to_string(), "write".to_string()],
            },
        )
        .await
        .unwrap();
        let (head, body) = server.requests()[0].clone();
        let sent = form(&body);
        assert_eq!(sent["grant_type"], "refresh_token");
        assert_eq!(sent["refresh_token"], "the-refresh");
        assert_eq!(sent["scope"], "read write");
        assert_eq!(sent["resource"], "https://vendor.example/mcp");
        assert!(!sent.contains_key("client_secret") && !sent.contains_key("client_id"));
        assert!(head.contains("authorization: Basic Y2xpZW50K2lkOnMzY3JldCUzQSUyNiUzRA=="), "{head}");
    }

    /// A provider whose `send_resource` is off redeems a code and refreshes a
    /// grant without `resource`, for a token endpoint that refuses it; one
    /// that sets it, or leaves it out, sends the resource on both.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_resource_is_sent_unless_the_provider_turns_it_off() {
        let scopes = ["read".to_string()];
        for (send_resource, expected) in [
            (None, Some("https://vendor.example/mcp")),
            (Some(true), Some("https://vendor.example/mcp")),
            (Some(false), None),
        ] {
            for grant_type in ["authorization_code", "refresh_token"] {
                let server = RecordingServer::start_answering(vec![Answer::json(
                    200,
                    json!({"access_token": "access", "token_type": "Bearer"}),
                )])
                .await;
                let mut record = serde_json::to_value(provider(&server, "none", None)).unwrap();
                assert!(
                    record
                        .get("send_resource")
                        .is_none(),
                    "left out while on"
                );
                if let Some(send_resource) = send_resource {
                    record["send_resource"] = json!(send_resource);
                }
                let provider: CredentialProvider = serde_json::from_value(record).unwrap();
                let request = match grant_type {
                    "authorization_code" => code(),
                    _ => TokenRequest::Refresh {
                        refresh_token: "the-refresh",
                        scopes: &scopes,
                    },
                };
                request_token(&provider, None, Some(&server.origin()), request)
                    .await
                    .unwrap();
                let sent = form(&server.requests()[0].1);
                assert_eq!(sent["grant_type"], grant_type);
                assert_eq!(
                    sent.get("resource")
                        .map(String::as_str),
                    expected,
                    "{send_resource:?} {grant_type}"
                );
            }
        }
    }

    /// A `private_key_jwt` client redeems a code with a client assertion its
    /// key signs, built by the shared RFC 7523 assertion code and addressed to
    /// the provider's issuer, and no secret.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_private_key_jwt_client_redeems_a_code_with_a_signed_assertion() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets(&directory).await;
        let key = crate::delegation_vault::jwt_assertion::test_keys::rsa_pkcs8();
        secrets
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: Some("tenant-a".into()),
                name: "Signing key".to_string(),
                secret_id: "signing-key".to_string(),
                description: None,
                value: key.private_pem.clone(),
                secret_type: "General".to_string(),
                tags: vec![],
            })
            .await
            .unwrap();
        let server = RecordingServer::start_answering(vec![Answer::json(
            200,
            json!({"access_token": "access", "token_type": "Bearer", "expires_in": 3600}),
        )])
        .await;
        let mut signing = provider(&server, "private_key_jwt", None);
        signing
            .jwt
            .jwt_signing_key_secret_ref = Some("signing-key".into());
        signing
            .jwt
            .jwt_signing_algorithm = Some(crate::credential_providers::JwtSigningAlgorithm::RS256);
        request_token(&signing, Some(&secrets), Some(&server.origin()), code())
            .await
            .unwrap();
        let (head, body) = server.requests()[0].clone();
        assert!(
            !head
                .to_ascii_lowercase()
                .contains("authorization:"),
            "{head}"
        );
        let sent = form(&body);
        assert_eq!(sent["client_id"], "client id");
        assert_eq!(sent["client_assertion_type"], "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        assert!(!sent.contains_key("client_secret"));
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&[signing
            .issuer
            .as_deref()
            .unwrap()]);
        let claims = jsonwebtoken::decode::<serde_json::Value>(
            &sent["client_assertion"],
            &jsonwebtoken::DecodingKey::from_rsa_pem(key.public_pem.as_bytes()).unwrap(),
            &validation,
        )
        .expect("signed with the provider's key, for its issuer")
        .claims;
        assert_eq!(claims["iss"], "client id");
        assert_eq!(claims["sub"], "client id");
    }

    async fn secrets(directory: &tempfile::TempDir) -> Arc<dyn SecretsStore> {
        let store = crate::secrets::FilesystemSecretsStore::new(
            directory
                .path()
                .join("secrets")
                .to_str()
                .unwrap(),
        )
        .unwrap();
        crate::secrets::SecretsStore::create(
            &store,
            crate::secrets::CreateSecretRequest {
                tenant_id: Some("tenant-a".into()),
                name: "Client secret".to_string(),
                secret_id: "client-secret".to_string(),
                description: None,
                value: "s3cret:&=".to_string(),
                secret_type: "ApiKey".to_string(),
                tags: vec![],
            },
        )
        .await
        .unwrap();
        Arc::new(store)
    }

    /// Refusals are told apart by their OAuth `error` code and status alone.
    #[tokio::test]
    async fn refusals_are_reported_by_their_error_code_and_status() {
        for (answer, expected) in [
            (
                Answer::json(400, json!({"error": "invalid_grant", "error_description": "secret detail"})),
                TokenFailure::InvalidGrant,
            ),
            (Answer::json(400, json!({"error": "invalid_client"})), TokenFailure::InvalidClient),
            (Answer::json(401, json!({})), TokenFailure::InvalidClient),
            (Answer::json(400, json!({"error": "invalid_scope"})), TokenFailure::Refused),
            (Answer::status(403), TokenFailure::Refused),
            (Answer::status(429), TokenFailure::Unavailable),
            (Answer::status(503), TokenFailure::Unavailable),
            (Answer::json(200, json!({"access_token": "a", "token_type": "mac"})), TokenFailure::InvalidResponse),
            (Answer::json(200, json!({"access_token": "a"})), TokenFailure::InvalidResponse),
            (Answer::json(200, json!({"access_token": "", "token_type": "Bearer"})), TokenFailure::InvalidResponse),
            (Answer::json(200, json!({"access_token": "a\nb", "token_type": "Bearer"})), TokenFailure::InvalidResponse),
            (
                Answer::json(200, json!({"access_token": "a", "token_type": "Bearer", "expires_in": 0})),
                TokenFailure::InvalidResponse,
            ),
            (
                Answer::json(200, json!({"access_token": "a", "token_type": "Bearer", "expires_in": -1})),
                TokenFailure::InvalidResponse,
            ),
            (
                Answer::json(
                    200,
                    json!({"access_token": "a", "token_type": "Bearer", "expires_in": MAX_EXPIRES_IN_SECS + 1}),
                ),
                TokenFailure::InvalidResponse,
            ),
            (
                Answer::json(200, json!({"access_token": "a", "token_type": "Bearer", "expires_in": 3600.5})),
                TokenFailure::InvalidResponse,
            ),
            (
                Answer::json(200, json!({"access_token": "a", "token_type": "Bearer", "expires_in": "3600.5"})),
                TokenFailure::InvalidResponse,
            ),
            (
                Answer::json(200, json!({"access_token": "a", "token_type": "Bearer", "refresh_token": ""})),
                TokenFailure::InvalidResponse,
            ),
            (
                Answer::json(
                    200,
                    json!({"access_token": "a".repeat(super::super::oauth::MAX_TOKEN_RESPONSE_BYTES), "token_type": "Bearer"}),
                ),
                TokenFailure::InvalidResponse,
            ),
        ] {
            let server = RecordingServer::start_answering(vec![answer.clone()]).await;
            assert_eq!(
                request_token(&provider(&server, "none", None), None, Some(&server.origin()), code())
                    .await
                    .unwrap_err(),
                expected,
                "{answer:?}"
            );
        }
        let server = RecordingServer::start_answering(vec![Answer::json(
            200,
            json!({"access_token": "a", "token_type": "Bearer", "expires_in": "3600"}),
        )])
        .await;
        assert_eq!(
            request_token(&provider(&server, "none", None), None, Some(&server.origin()), code())
                .await
                .unwrap()
                .expires_in,
            Some(3600),
            "a lifetime given as a string is read"
        );
        let server = RecordingServer::start_answering(vec![Answer::json(
            200,
            json!({"access_token": "a", "token_type": "Bearer", "expires_in": MAX_EXPIRES_IN_SECS}),
        )])
        .await;
        assert_eq!(
            request_token(&provider(&server, "none", None), None, Some(&server.origin()), code())
                .await
                .unwrap()
                .expires_in,
            Some(MAX_EXPIRES_IN_SECS),
            "the longest lifetime is accepted"
        );
    }

    /// An answer's OpenID Connect ID token names the vendor account the tokens
    /// are for: its `sub`, read only when the token was issued by the
    /// provider's issuer for its client. Any other ID token, or none, names no
    /// account.
    #[tokio::test]
    async fn the_vendor_account_is_read_from_an_id_token_of_the_providers_issuer_for_its_client() {
        use base64::Engine as _;
        let id_token = |claims: serde_json::Value| {
            let encode =
                |value: serde_json::Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string());
            format!("{}.{}.signature", encode(json!({"alg": "RS256", "typ": "JWT"})), encode(claims))
        };
        let issuer = "https://203.0.113.10";
        for (token, expected) in [
            (Some(id_token(json!({"iss": issuer, "aud": "client id", "sub": "account-1"}))), Some("account-1")),
            (
                Some(id_token(json!({"iss": issuer, "aud": ["another client", "client id"], "sub": "account-2"}))),
                Some("account-2"),
            ),
            (Some(id_token(json!({"iss": "https://elsewhere.example", "aud": "client id", "sub": "account-3"}))), None),
            (Some(id_token(json!({"iss": issuer, "aud": "another client", "sub": "account-4"}))), None),
            (Some(id_token(json!({"iss": issuer, "aud": "client id", "sub": ""}))), None),
            (Some(id_token(json!({"iss": issuer, "aud": "client id", "sub": "x".repeat(256)}))), None),
            (Some(id_token(json!({"iss": issuer, "aud": "client id"}))), None),
            (Some("not.a-token".to_string()), None),
            (None, None),
        ] {
            let mut body = json!({"access_token": "a", "token_type": "Bearer"});
            if let Some(token) = &token {
                body["id_token"] = json!(token);
            }
            let server = RecordingServer::start_answering(vec![Answer::json(200, body)]).await;
            let answer = request_token(&provider(&server, "none", None), None, Some(&server.origin()), code())
                .await
                .unwrap();
            assert_eq!(answer.subject.as_deref(), expected, "{token:?}");
            if expected.is_some() {
                assert!(!format!("{answer:?}").contains("account-"), "the answer's Debug hides the account");
            }
        }
    }

    /// A token endpoint off the test allow-list, over `http`, is never called;
    /// a client whose secret is another tenant's never authenticates.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unvetted_endpoint_or_another_tenants_secret_is_never_used() {
        let server = RecordingServer::start_answering(vec![Answer::json(
            200,
            json!({"access_token": "a", "token_type": "Bearer"}),
        )])
        .await;
        assert_eq!(
            request_token(&provider(&server, "none", None), None, None, code())
                .await
                .unwrap_err(),
            TokenFailure::Unreachable
        );
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets(&directory).await;
        let mut other_tenant = provider(&server, "client_secret_post", Some("client-secret"));
        other_tenant.tenant_id = Some("tenant-b".into());
        assert_eq!(
            request_token(&other_tenant, Some(&secrets), Some(&server.origin()), code())
                .await
                .unwrap_err(),
            TokenFailure::ClientUnavailable
        );
        assert!(server.requests().is_empty());
    }
}
