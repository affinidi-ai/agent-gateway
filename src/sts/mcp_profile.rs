use serde::{Deserialize, Serialize};
use url::Url;

use super::errors::StsError;

pub struct McpTokenForm(pub super::types::TokenEndpointForm);

impl<State: Send + Sync> axum::extract::FromRequest<State> for McpTokenForm {
    type Rejection = StsError;

    async fn from_request(
        request: axum::extract::Request,
        _state: &State,
    ) -> Result<Self, Self::Rejection> {
        let headers = request.headers();
        let content_types = headers
            .get_all(axum::http::header::CONTENT_TYPE)
            .iter()
            .collect::<Vec<_>>();
        if content_types.len() != 1
            || content_types[0]
                .to_str()
                .ok()
                .and_then(|value| {
                    value
                        .parse::<mime::Mime>()
                        .ok()
                })
                .is_none_or(|value| {
                    value.essence_str() != "application/x-www-form-urlencoded"
                        || value
                            .get_param(mime::CHARSET)
                            .is_some_and(|charset| charset != mime::UTF_8)
                })
        {
            return Err(StsError::InvalidRequest("MCP token requests require a UTF-8 form body".into()));
        }
        let authorization = headers
            .get_all(axum::http::header::AUTHORIZATION)
            .iter()
            .collect::<Vec<_>>();
        if authorization.len() > 1 {
            return Err(StsError::InvalidClient("Exactly one client authentication method is allowed".into()));
        }
        let has_basic = if let Some(value) = authorization.first() {
            if !value
                .to_str()
                .is_ok_and(|value| value.starts_with("Basic ") && value.len() <= 16 * 1024)
            {
                return Err(StsError::InvalidClient("Unsupported client authentication method".into()));
            }
            true
        } else {
            false
        };
        let body = axum::body::to_bytes(request.into_body(), 64 * 1024)
            .await
            .map_err(|_| StsError::InvalidRequest("MCP token form exceeds its limit or could not be read".into()))?;
        let fields: Vec<(String, String)> = serde_urlencoded::from_bytes(&body)
            .map_err(|_| StsError::InvalidRequest("Invalid MCP token form".into()))?;
        let mut names = std::collections::HashSet::new();
        if fields.len() > 32
            || fields
                .iter()
                .any(|(name, value)| name.len() > 128 || value.len() > 32 * 1024 || !names.insert(name))
        {
            return Err(StsError::InvalidRequest("Duplicate or oversized MCP token parameters".into()));
        }
        if has_basic
            && fields
                .iter()
                .any(|(name, _)| name == "client_secret")
        {
            return Err(StsError::InvalidClient("Conflicting client authentication methods".into()));
        }
        let form = serde_urlencoded::from_bytes(&body)
            .map_err(|_| StsError::InvalidRequest("Invalid MCP token form".into()))?;
        Ok(Self(form))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct McpIssuerProfile {
    pub issuer: String,
}

impl McpIssuerProfile {
    pub fn bound_subject(
        &self,
        claims: &serde_json::Value,
    ) -> Result<String, StsError> {
        use sha2::{Digest, Sha256};

        let issuer = claims
            .get("iss")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| StsError::InvalidGrant("Missing subject issuer".into()))?;
        let subject = claims
            .get("sub")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| StsError::InvalidGrant("Missing subject".into()))?;
        if issuer == self.issuer {
            return Ok(subject.to_string());
        }
        let identity = serde_json_canonicalizer::to_vec(&(issuer, subject))
            .map_err(|_| StsError::ServerError("Subject binding failed".into()))?;
        Ok(format!("urn:affinidi:mcp:subject:{}", hex::encode(Sha256::digest(identity))))
    }

    pub fn validate_network(
        &self,
        network: &crate::config::network::NetworkConfig,
    ) -> Result<(), StsError> {
        self.validate()?;
        let issuer = canonical_https_url(&self.issuer)?;
        let known_origin = network
            .get_inbound_external_urls()
            .iter()
            .any(|external| Url::parse(external).is_ok_and(|external| external.origin() == issuer.origin()));
        let known_path = network
            .routes
            .values()
            .any(|route| {
                route.route_type == crate::config::RouteType::IdentityApi
                    && matches!(route.prefix.as_str(), "/" | "/api")
                    && issuer.path()
                        == format!(
                            "{}/oauth2/mcp",
                            route
                                .prefix
                                .trim_end_matches('/')
                        )
            });
        if !known_origin || !known_path {
            return Err(StsError::InvalidRequest(
                "MCP issuer must match a configured public inbound origin and root or /api identity mount".into(),
            ));
        }
        Ok(())
    }

    pub fn metadata(&self) -> Result<serde_json::Value, StsError> {
        self.validate()?;
        Ok(serde_json::json!({
            "issuer": self.issuer,
            "token_endpoint": format!("{}/token", self.issuer),
            "jwks_uri": format!("{}/jwks.json", self.issuer),
            "grant_types_supported": [super::types::GRANT_TYPE_TOKEN_EXCHANGE, super::types::GRANT_TYPE_JWT_BEARER],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "subject_token_types_supported": [super::types::TOKEN_TYPE_JWT, super::types::TOKEN_TYPE_ID_TOKEN],
            "requested_token_types_supported": [super::types::TOKEN_TYPE_ACCESS_TOKEN, super::types::TOKEN_TYPE_JWT, super::types::TOKEN_TYPE_ID_JAG]
        }))
    }

    pub fn discovery_router(&self) -> Result<axum::Router, StsError> {
        let metadata = self.metadata()?;
        Ok(axum::Router::new().route(
            &self.metadata_path()?,
            axum::routing::get(move || {
                let metadata = metadata.clone();
                async move { ([(axum::http::header::CACHE_CONTROL, "no-store")], axum::Json(metadata)) }
            }),
        ))
    }

    pub fn authorize_resource(
        &self,
        client: &super::handlers::StsClientRecord,
        resource: &str,
        scopes: &[String],
    ) -> Result<(), StsError> {
        if !client
            .allowed_audiences
            .iter()
            .any(|allowed| allowed == resource)
        {
            return Err(StsError::InvalidTarget("MCP resource is not explicitly permitted for this client".into()));
        }
        if scopes.len() > 128
            || scopes.iter().any(|scope| {
                scope.is_empty()
                    || scope.len() > 256
                    || scope
                        .bytes()
                        .any(|byte| !matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
                    || !client
                        .allowed_scopes
                        .contains(scope)
            })
        {
            return Err(StsError::InvalidScope("MCP scope is not explicitly permitted for this client".into()));
        }
        Ok(())
    }

    pub fn validate_subject(
        &self,
        claims: &serde_json::Value,
        now: u64,
    ) -> Result<u64, StsError> {
        for field in ["iss", "sub"] {
            if claims
                .get(field)
                .and_then(serde_json::Value::as_str)
                .is_none_or(str::is_empty)
            {
                return Err(StsError::InvalidGrant("MCP subject requires a verified issuer and subject".into()));
            }
        }
        let expiry = claims
            .get("exp")
            .and_then(serde_json::Value::as_u64)
            .filter(|expiry| *expiry > now)
            .ok_or_else(|| StsError::InvalidGrant("MCP subject requires a future expiry".into()))?;
        if claims
            .get("nbf")
            .is_some_and(|value| {
                value
                    .as_u64()
                    .is_none_or(|not_before| not_before > now)
            })
        {
            return Err(StsError::InvalidGrant("MCP subject is not yet valid".into()));
        }
        Ok(expiry)
    }

    pub fn validate(&self) -> Result<(), StsError> {
        let issuer = canonical_https_url(&self.issuer)?;
        if !issuer
            .path()
            .ends_with("/oauth2/mcp")
        {
            return Err(StsError::InvalidRequest("MCP issuer path must end with /oauth2/mcp".into()));
        }
        Ok(())
    }

    pub fn metadata_path(&self) -> Result<String, StsError> {
        self.validate()?;
        let issuer = canonical_https_url(&self.issuer)?;
        Ok(format!("/.well-known/oauth-authorization-server{}", issuer.path()))
    }

    pub fn requested_resource(
        &self,
        resource: Option<&str>,
        audience: Option<&str>,
        id_jag: bool,
    ) -> Result<String, StsError> {
        self.validate()?;
        let resource = resource
            .filter(|value| !value.is_empty())
            .ok_or_else(|| StsError::InvalidTarget("resource is required for the MCP issuer".into()))?;
        canonical_https_url(resource)
            .map_err(|_| StsError::InvalidTarget("resource must be a canonical HTTPS URI".into()))?;
        let expected_audience = if id_jag {
            self.issuer.as_str()
        } else {
            resource
        };
        if audience.is_some_and(|value| value != expected_audience) {
            return Err(StsError::InvalidTarget(
                "audience does not match the intended MCP resource or authorization server".into(),
            ));
        }
        Ok(resource.to_string())
    }
}

pub fn canonical_https_url(value: &str) -> Result<Url, StsError> {
    let parsed = Url::parse(value).map_err(|_| StsError::InvalidRequest("Invalid canonical HTTPS URI".into()))?;
    if value.len() > 4096
        || parsed.scheme() != "https"
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.as_str() != value
    {
        return Err(StsError::InvalidRequest(
            "Expected a canonical HTTPS URI without credentials, query or fragment".into(),
        ));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn profile_subjects_are_issuer_namespaced_and_local_redemption_is_stable() {
        let profile = McpIssuerProfile {
            issuer: "https://gateway.example/oauth2/mcp".into(),
        };
        let first = profile
            .bound_subject(&json!({"iss": "https://one.example", "sub": "user"}))
            .unwrap();
        let second = profile
            .bound_subject(&json!({"iss": "https://two.example", "sub": "user"}))
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(
            profile
                .bound_subject(&json!({"iss": profile.issuer, "sub": first}))
                .unwrap(),
            first
        );
        assert!(
            profile
                .bound_subject(&json!({"sub": "user"}))
                .is_err()
        );
    }

    #[tokio::test]
    async fn mcp_token_form_rejects_duplicate_parameters_and_authentication() {
        use axum::extract::FromRequest;

        for form in [
            "grant_type=x&resource=https%3A%2F%2Fa.example%2F&resource=https%3A%2F%2Fb.example%2F",
            "grant_type=x&client_secret=one&client_secret=two",
            "grant_type=x&scope=read&scope=write",
        ] {
            let request = axum::http::Request::builder()
                .header("content-type", "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(form))
                .unwrap();
            assert!(
                McpTokenForm::from_request(request, &())
                    .await
                    .is_err()
            );
        }
        let request = axum::http::Request::builder()
            .header("content-type", "application/x-www-form-urlencoded")
            .header("authorization", "Basic Y2xpZW50OnNlY3JldA==")
            .body(axum::body::Body::from("grant_type=x&client_secret=other"))
            .unwrap();
        assert!(matches!(McpTokenForm::from_request(request, &()).await, Err(StsError::InvalidClient(_))));
        let request = axum::http::Request::builder()
            .header("content-type", "application/x-www-form-urlencoded")
            .body(axum::body::Body::from("grant_type=x&resource=https%3A%2F%2Fgateway.example%2Fmcp&scope=read+write"))
            .unwrap();
        let form = McpTokenForm::from_request(request, &())
            .await
            .unwrap();
        assert_eq!(form.0.resource.as_deref(), Some("https://gateway.example/mcp"));
        assert_eq!(form.0.scope.as_deref(), Some("read write"));
        let request = axum::http::Request::builder()
            .header("content-type", "application/x-www-form-urlencoded")
            .body(axum::body::Body::from("x".repeat(64 * 1024 + 1)))
            .unwrap();
        assert!(
            McpTokenForm::from_request(request, &())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn mcp_profile_discovery_is_bound_to_configured_origin_and_mount() {
        use tower::ServiceExt;

        let mut network: crate::config::network::NetworkConfig = serde_json::from_value(json!({
            "did": {"domain": "gateway.example"},
            "webauthn": {"rp_id": "gateway.example", "external_origin": "https://gateway.example"},
            "integration": {"types": [], "categories": []},
            "listeners": [{"id": "in", "name": "in", "bind_address": "127.0.0.1", "port": 8080, "protocol": "http", "external_urls": ["https://gateway.example"]}],
            "routes": {"identity": {"type": "identity_api", "prefix": "/api"}}
        })).unwrap();
        let profile = McpIssuerProfile {
            issuer: "https://gateway.example/api/oauth2/mcp".into(),
        };
        assert!(
            profile
                .validate_network(&network)
                .is_ok()
        );
        let response = profile
            .discovery_router()
            .unwrap()
            .oneshot(
                axum::http::Request::builder()
                    .uri(
                        profile
                            .metadata_path()
                            .unwrap(),
                    )
                    .header("host", "attacker.example")
                    .header("x-forwarded-host", "attacker.example")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(response.headers()[axum::http::header::CACHE_CONTROL], "no-store");
        let metadata: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 16384)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(metadata["issuer"], profile.issuer);
        assert_eq!(metadata["token_endpoint"], "https://gateway.example/api/oauth2/mcp/token");
        assert_eq!(metadata["jwks_uri"], "https://gateway.example/api/oauth2/mcp/jwks.json");
        assert!(
            metadata
                .get("authorization_endpoint")
                .is_none()
        );
        assert!(
            metadata
                .get("code_challenge_methods_supported")
                .is_none()
        );
        assert!(
            metadata
                .get("registration_endpoint")
                .is_none()
        );
        network
            .routes
            .get_mut("identity")
            .unwrap()
            .prefix = "/other".into();
        assert!(
            profile
                .validate_network(&network)
                .is_err()
        );
        network
            .routes
            .get_mut("identity")
            .unwrap()
            .prefix = "/api".into();
        network.listeners[0].external_urls = vec!["https://other.example".into()];
        assert!(
            profile
                .validate_network(&network)
                .is_err()
        );
    }

    #[test]
    fn mcp_profile_keeps_resource_and_authorization_server_audiences_distinct() {
        let profile = McpIssuerProfile {
            issuer: "https://gateway.example/api/oauth2/mcp".into(),
        };
        assert!(profile.validate().is_ok());
        assert_eq!(
            profile
                .metadata_path()
                .unwrap(),
            "/.well-known/oauth-authorization-server/api/oauth2/mcp"
        );
        let resource = "https://gateway.example/surfaces/alpha";
        assert_eq!(
            profile
                .requested_resource(Some(resource), None, false)
                .unwrap(),
            resource
        );
        assert_eq!(
            profile
                .requested_resource(Some(resource), Some(resource), false)
                .unwrap(),
            resource
        );
        assert_eq!(
            profile
                .requested_resource(Some(resource), Some(&profile.issuer), true)
                .unwrap(),
            resource
        );
        assert!(
            profile
                .requested_resource(Some(resource), Some(resource), true)
                .is_err()
        );
        assert!(
            profile
                .requested_resource(Some(resource), Some(&profile.issuer), false)
                .is_err()
        );
        assert!(
            profile
                .requested_resource(None, Some(resource), false)
                .is_err()
        );
        for invalid in [
            "http://gateway.example/mcp",
            "did:web:gateway.example",
            "https://gateway.example/mcp?token=x",
            "https://user@gateway.example/mcp",
            "https://gateway.example/mcp#part",
            "https://GATEWAY.example/mcp",
        ] {
            assert!(
                profile
                    .requested_resource(Some(invalid), None, false)
                    .is_err(),
                "{invalid}"
            );
        }
        let legacy: crate::config::types::StsRuntimeConfig = serde_json::from_value(json!({})).unwrap();
        assert!(legacy.mcp_issuer.is_none());
        assert!(
            serde_json::to_value(legacy)
                .unwrap()
                .get("mcp_issuer")
                .is_none()
        );
    }
}
