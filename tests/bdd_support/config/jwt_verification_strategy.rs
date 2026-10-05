use std::path::Path;

use serde_json::json;

pub fn write_jwt_verification_strategy_fixture(
    strategies_dir: &Path,
    id: &str,
    name: &str,
    expected_issuer: &str,
    jwks_uri: &str,
) {
    std::fs::create_dir_all(strategies_dir).unwrap();
    let strategy_json = json!({
        "id": id,
        "name": name,
        "expected_issuer": expected_issuer,
        "jwks_source": {
            "type": "remote",
            "jwks_uri": jwks_uri,
        },
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    });
    std::fs::write(strategies_dir.join(format!("{id}.json")), serde_json::to_string_pretty(&strategy_json).unwrap())
        .unwrap();
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
        );

        let strategy_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(strategies_dir.join("bdd-jwt-strategy.json")).unwrap())
                .unwrap();
        assert_eq!(strategy_json["expected_issuer"], "https://issuer.example");
        assert_eq!(strategy_json["jwks_source"]["jwks_uri"], "https://issuer.example/.well-known/jwks.json");
    }
}
