use serde_json::{Value, json};

use crate::bdd_support::config::single_surface_fixture::SurfaceSourceAuthConfig;

pub fn api_key_source_auth_method_json(
    header_name: &str,
    secret_id: &str,
) -> Value {
    json!({
        "type": "api_key",
        "extraction": {
            "source": "http_header",
            "field": header_name,
        },
        "secret_id": secret_id,
    })
}

pub fn caller_authentication_method_json(config: &SurfaceSourceAuthConfig) -> Value {
    match config {
        SurfaceSourceAuthConfig::JwtBearer(cfg) => json!({
            "type": "jwt_bearer",
            "jwt_verification_strategy_id": "bdd-jwt-strategy",
            "audiences": &cfg.audiences,
        }),
        SurfaceSourceAuthConfig::ApiKey(cfg) => api_key_source_auth_method_json(&cfg.header_name, &cfg.secret_id),
        SurfaceSourceAuthConfig::ApiKeyProvider(cfg) => json!({
            "type": "api_key_provider",
            "extraction": {
                "source": "http_header",
                "field": cfg.header_name,
            },
            "agent_id": cfg.agent_id,
        }),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn api_key_source_auth_method_json_builds_shared_source_auth_method_shape() {
        let source_auth = super::api_key_source_auth_method_json("x-api-key", "bdd-source-api-key");

        assert_eq!(source_auth["type"], "api_key");
        assert_eq!(source_auth["extraction"]["source"], "http_header");
        assert_eq!(source_auth["extraction"]["field"], "x-api-key");
        assert_eq!(source_auth["secret_id"], "bdd-source-api-key");
    }

    #[test]
    fn caller_authentication_method_json_covers_all_source_auth_variants() {
        use crate::bdd_support::config::single_surface_fixture::{
            ApiKeyProviderSourceAuthConfig, ApiKeySourceAuthConfig, JwtSourceAuthConfig, SurfaceSourceAuthConfig,
        };

        let jwt = SurfaceSourceAuthConfig::JwtBearer(JwtSourceAuthConfig {
            jwks_url: "https://example.test/.well-known/jwks.json".to_string(),
            issuer: "https://example.test/".to_string(),
            audiences: vec![],
        });
        let api_key = SurfaceSourceAuthConfig::ApiKey(ApiKeySourceAuthConfig {
            header_name: "x-api-key".to_string(),
            secret_id: "bdd-source-api-key".to_string(),
            valid_key: "super-secret".to_string(),
        });
        let api_key_provider = SurfaceSourceAuthConfig::ApiKeyProvider(ApiKeyProviderSourceAuthConfig {
            header_name: "x-api-key".to_string(),
            agent_id: "did:example:agent".to_string(),
            key_id: "bdd-key-id".to_string(),
            client_id: "bdd-client-id".to_string(),
            valid_key: "super-secret".to_string(),
        });

        assert_eq!(super::caller_authentication_method_json(&jwt)["type"], "jwt_bearer");
        assert_eq!(super::caller_authentication_method_json(&api_key)["type"], "api_key");
        assert_eq!(super::caller_authentication_method_json(&api_key_provider)["type"], "api_key_provider");
    }
}
