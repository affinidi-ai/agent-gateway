//! Client-side RFC 8693 token exchange — lets the gateway *consume* an external
//! Security Token Service (e.g. Okta / Entra XAA) on an outbound leg by
//! exchanging a subject assertion for a downstream access token.
//!
//! This is the mirror of the gateway's own token endpoint (`handlers.rs`): here
//! the gateway is the *client* calling someone else's STS. The form builder and
//! response parser are pure and unit-tested; [`exchange_token`] performs the
//! SSRF-guarded HTTP POST.
//!
//! Reserved: this outbound external-STS consumer is documented, unit-tested, and
//! kept for a later provider-grant flow; it is not yet wired into a request path.
#![allow(dead_code)]

use serde::Deserialize;

use crate::sts::types::GRANT_TYPE_TOKEN_EXCHANGE;

/// Parameters for a client-side token exchange call.
#[derive(Debug, Clone)]
pub struct TokenExchangeClientRequest {
    /// The external STS token endpoint URL.
    pub token_endpoint: String,
    /// Client id for authenticating to the external STS.
    pub client_id: String,
    /// Client secret (sent via HTTP Basic). `None` for a public/mTLS client.
    pub client_secret: Option<String>,
    pub subject_token: String,
    pub subject_token_type: String,
    pub actor_token: Option<String>,
    pub actor_token_type: Option<String>,
    pub audience: Option<String>,
    pub resource: Option<String>,
    pub scope: Option<String>,
    pub requested_token_type: Option<String>,
}

/// The subset of an RFC 8693 token-exchange response the gateway consumes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ExternalTokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub issued_token_type: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// A client-side token-exchange failure.
#[derive(Debug, thiserror::Error)]
pub enum StsClientError {
    #[error("invalid token endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("token exchange transport error: {0}")]
    Transport(String),
    #[error("token exchange rejected ({status}): {body}")]
    Rejected { status: u16, body: String },
    #[error("malformed token response: {0}")]
    Malformed(String),
}

/// Build the `application/x-www-form-urlencoded` body for a token-exchange POST.
pub fn build_token_exchange_form(req: &TokenExchangeClientRequest) -> Vec<(&'static str, String)> {
    let mut form: Vec<(&'static str, String)> = vec![
        ("grant_type", GRANT_TYPE_TOKEN_EXCHANGE.to_string()),
        ("subject_token", req.subject_token.clone()),
        ("subject_token_type", req.subject_token_type.clone()),
    ];
    if let Some(v) = &req.actor_token {
        form.push(("actor_token", v.clone()));
    }
    if let Some(v) = &req.actor_token_type {
        form.push(("actor_token_type", v.clone()));
    }
    if let Some(v) = &req.audience {
        form.push(("audience", v.clone()));
    }
    if let Some(v) = &req.resource {
        form.push(("resource", v.clone()));
    }
    if let Some(v) = &req.scope {
        form.push(("scope", v.clone()));
    }
    if let Some(v) = &req.requested_token_type {
        form.push(("requested_token_type", v.clone()));
    }
    form
}

/// Parse a token-exchange success body.
pub fn parse_token_response(body: &str) -> Result<ExternalTokenResponse, StsClientError> {
    let resp: ExternalTokenResponse =
        serde_json::from_str(body).map_err(|e| StsClientError::Malformed(e.to_string()))?;
    if resp.access_token.is_empty() {
        return Err(StsClientError::Malformed("access_token is empty".to_string()));
    }
    Ok(resp)
}

/// Exchange a subject assertion for a downstream access token at an external STS.
pub async fn exchange_token(
    client: &reqwest::Client,
    req: &TokenExchangeClientRequest,
) -> Result<ExternalTokenResponse, StsClientError> {
    // SSRF guard: reject cloud-metadata / private targets.
    crate::url_validation::validate_url_not_cloud_metadata(&req.token_endpoint)
        .map_err(StsClientError::InvalidEndpoint)?;

    let form = build_token_exchange_form(req);
    let mut builder = client
        .post(&req.token_endpoint)
        .form(&form);
    if let Some(secret) = &req.client_secret {
        builder = builder.basic_auth(&req.client_id, Some(secret));
    }

    let response = builder
        .send()
        .await
        .map_err(|e| StsClientError::Transport(e.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| StsClientError::Transport(e.to_string()))?;

    if !status.is_success() {
        return Err(StsClientError::Rejected { status: status.as_u16(), body });
    }
    parse_token_response(&body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sts::types::{TOKEN_TYPE_ACCESS_TOKEN, TOKEN_TYPE_ID_JAG, TOKEN_TYPE_JWT};

    fn req() -> TokenExchangeClientRequest {
        TokenExchangeClientRequest {
            token_endpoint: "https://sts.example/token".to_string(),
            client_id: "agent0".to_string(),
            client_secret: Some("s".to_string()),
            subject_token: "subj".to_string(),
            subject_token_type: TOKEN_TYPE_JWT.to_string(),
            actor_token: None,
            actor_token_type: None,
            audience: None,
            resource: None,
            scope: None,
            requested_token_type: None,
        }
    }

    fn get<'a>(
        form: &'a [(&'static str, String)],
        key: &str,
    ) -> Option<&'a str> {
        form.iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn form_has_required_fields_and_omits_absent() {
        let form = build_token_exchange_form(&req());
        assert_eq!(get(&form, "grant_type"), Some(GRANT_TYPE_TOKEN_EXCHANGE));
        assert_eq!(get(&form, "subject_token"), Some("subj"));
        assert_eq!(get(&form, "subject_token_type"), Some(TOKEN_TYPE_JWT));
        assert_eq!(get(&form, "actor_token"), None);
        assert_eq!(get(&form, "audience"), None);
        assert_eq!(get(&form, "requested_token_type"), None);
    }

    #[test]
    fn form_includes_all_optionals_when_present() {
        let mut r = req();
        r.actor_token = Some("act".to_string());
        r.actor_token_type = Some(TOKEN_TYPE_JWT.to_string());
        r.audience = Some("https://api.example".to_string());
        r.resource = Some("https://api.example/v1".to_string());
        r.scope = Some("read write".to_string());
        r.requested_token_type = Some(TOKEN_TYPE_ID_JAG.to_string());
        let form = build_token_exchange_form(&r);
        assert_eq!(get(&form, "actor_token"), Some("act"));
        assert_eq!(get(&form, "actor_token_type"), Some(TOKEN_TYPE_JWT));
        assert_eq!(get(&form, "audience"), Some("https://api.example"));
        assert_eq!(get(&form, "resource"), Some("https://api.example/v1"));
        assert_eq!(get(&form, "scope"), Some("read write"));
        assert_eq!(get(&form, "requested_token_type"), Some(TOKEN_TYPE_ID_JAG));
    }

    #[test]
    fn parse_response_reads_fields() {
        let body = format!(
            r#"{{"access_token":"abc","issued_token_type":"{TOKEN_TYPE_ACCESS_TOKEN}","token_type":"Bearer","expires_in":300,"scope":"read"}}"#
        );
        let resp = parse_token_response(&body).expect("valid");
        assert_eq!(resp.access_token, "abc");
        assert_eq!(
            resp.issued_token_type
                .as_deref(),
            Some(TOKEN_TYPE_ACCESS_TOKEN)
        );
        assert_eq!(resp.token_type.as_deref(), Some("Bearer"));
        assert_eq!(resp.expires_in, Some(300));
        assert_eq!(resp.scope.as_deref(), Some("read"));
    }

    #[test]
    fn parse_response_tolerates_minimal_body() {
        let resp = parse_token_response(r#"{"access_token":"only"}"#).expect("valid");
        assert_eq!(resp.access_token, "only");
        assert!(
            resp.issued_token_type
                .is_none()
        );
    }

    #[test]
    fn parse_response_rejects_empty_access_token() {
        let err = parse_token_response(r#"{"access_token":""}"#).unwrap_err();
        assert!(matches!(err, StsClientError::Malformed(_)));
    }

    #[test]
    fn parse_response_rejects_non_json() {
        let err = parse_token_response("not json").unwrap_err();
        assert!(matches!(err, StsClientError::Malformed(_)));
    }
}
