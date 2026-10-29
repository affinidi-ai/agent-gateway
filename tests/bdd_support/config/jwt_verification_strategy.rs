use std::path::Path;

use serde_json::{Value, json};

/// The strategy a surface with JWT Bearer source authentication verifies callers with.
pub const SURFACE_JWT_STRATEGY_ID: &str = "bdd-jwt-strategy";

/// The key set a strategy created through the admin API reads its keys from.
pub const STRATEGY_KEY_SET_URI: &str = "https://keys.example/jwks.json";

pub fn write_jwt_verification_strategy_fixture(
    strategies_dir: &Path,
    id: &str,
    name: &str,
    expected_issuer: &str,
    jwks_uri: &str,
    authorization_server: Option<&Value>,
) {
    std::fs::create_dir_all(strategies_dir).unwrap();
    let mut strategy_json = json!({
        "id": id,
        "name": name,
        "expected_issuer": expected_issuer,
        "jwks_source": remote_jwks_source(jwks_uri),
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    });
    if let Some(authorization_server) = authorization_server {
        strategy_json["authorization_server"] = authorization_server.clone();
    }
    std::fs::write(strategies_dir.join(format!("{id}.json")), serde_json::to_string_pretty(&strategy_json).unwrap())
        .unwrap();
}

pub fn remote_jwks_source(jwks_uri: &str) -> Value {
    json!({
        "type": "remote",
        "jwks_uri": jwks_uri,
    })
}

/// The body of a strategy create or update through the admin API. `discover_metadata`
/// is left out when `None`, which keeps a pin on update.
pub fn jwt_verification_strategy_request(
    name: &str,
    expected_issuer: &str,
    jwks_source: Value,
    discover_metadata: Option<bool>,
) -> Value {
    let mut request = json!({
        "name": name,
        "expected_issuer": expected_issuer,
        "jwks_source": jwks_source,
    });
    if let Some(discover_metadata) = discover_metadata {
        request["discover_metadata"] = json!(discover_metadata);
    }
    request
}

#[cfg(test)]
mod tests {
    #[test]
    fn jwt_verification_strategy_fixture_writer_creates_expected_storage_record() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let strategies_dir = temp_dir
            .path()
            .join("jwt_verification_strategies");

        super::write_jwt_verification_strategy_fixture(
            &strategies_dir,
            "bdd-jwt-strategy",
            "BDD EdDSA Test",
            "https://issuer.example",
            "https://issuer.example/.well-known/jwks.json",
            None,
        );

        let strategy_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(strategies_dir.join("bdd-jwt-strategy.json")).unwrap())
                .unwrap();
        assert_eq!(strategy_json["expected_issuer"], "https://issuer.example");
        assert_eq!(strategy_json["jwks_source"]["type"], "remote");
        assert_eq!(strategy_json["jwks_source"]["jwks_uri"], "https://issuer.example/.well-known/jwks.json");
        assert!(
            strategy_json
                .get("authorization_server")
                .is_none()
        );
    }

    #[test]
    fn jwt_verification_strategy_fixture_writer_stores_the_pinned_authorization_server() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let pin = serde_json::json!({
            "issuer": "https://as.example/realms/agents",
            "metadata_url": "https://as.example/.well-known/oauth-authorization-server/realms/agents",
            "token_endpoint": "https://as.example/realms/agents/protocol/token",
            "jwks_uri": "https://as.example/realms/agents/protocol/keys",
        });

        super::write_jwt_verification_strategy_fixture(
            temp_dir.path(),
            "pinned",
            "Pinned",
            "https://as.example/realms/agents",
            "https://keys.example/jwks.json",
            Some(&pin),
        );

        let stored: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                temp_dir
                    .path()
                    .join("pinned.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(stored["authorization_server"], pin);
        assert_eq!(stored["jwks_source"]["jwks_uri"], "https://keys.example/jwks.json");
    }

    #[test]
    fn strategy_request_carries_the_discovery_choice_when_given() {
        let source = super::remote_jwks_source(super::STRATEGY_KEY_SET_URI);

        let pinning =
            super::jwt_verification_strategy_request("alpha", "https://as.example", source.clone(), Some(true));
        let clearing = super::jwt_verification_strategy_request("alpha", "https://as.example", source, Some(false));

        assert_eq!(
            pinning,
            serde_json::json!({
                "name": "alpha",
                "expected_issuer": "https://as.example",
                "jwks_source": { "type": "remote", "jwks_uri": "https://keys.example/jwks.json" },
                "discover_metadata": true,
            })
        );
        assert_eq!(clearing["discover_metadata"], false);
    }

    #[test]
    fn strategy_request_without_a_discovery_choice_omits_the_field() {
        let request = super::jwt_verification_strategy_request(
            "alpha",
            "https://as.example",
            super::remote_jwks_source(super::STRATEGY_KEY_SET_URI),
            None,
        );

        assert!(
            request
                .get("discover_metadata")
                .is_none(),
            "request {request}"
        );
        assert_eq!(request["expected_issuer"], "https://as.example");
    }
}
