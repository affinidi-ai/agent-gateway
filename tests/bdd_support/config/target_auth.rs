use std::path::Path;

use serde_json::{Value, json};

use crate::bdd_support::config::secrets::write_secret_fixture;

/// A client credentials provider the gateway uses for its own token to the Target.
#[derive(Debug, Clone)]
pub struct TargetTokenProviderFixture {
    pub provider_id: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub client_secret: String,
}

pub fn credential_provider_target_auth_json(
    credential_provider_id: &str,
    fallback: &str,
) -> Value {
    json!({
        "method": { "credential_provider": { "credential_provider_id": credential_provider_id } },
        "fallback": fallback,
    })
}

/// Store the provider record and its client credentials under `base_dir/_storage`.
pub fn write_target_token_provider(
    base_dir: &Path,
    fixture: &TargetTokenProviderFixture,
) {
    let storage_dir = base_dir.join("_storage");
    let client_id_secret = format!("bdd-{}-gateway-client-id", fixture.provider_id);
    let client_secret_secret = format!("bdd-{}-gateway-client-secret", fixture.provider_id);
    write_secret_fixture(&storage_dir.join("secrets"), &client_id_secret, &fixture.client_id);
    write_secret_fixture(&storage_dir.join("secrets"), &client_secret_secret, &fixture.client_secret);
    let now = chrono::Utc::now().to_rfc3339();
    let providers_dir = storage_dir.join("credential_providers");
    std::fs::create_dir_all(&providers_dir).expect("create credential provider dir");
    std::fs::write(
        providers_dir.join(format!("{}.json", fixture.provider_id)),
        serde_json::to_string_pretty(&json!({
            "id": fixture.provider_id,
            "name": fixture.provider_id,
            "provider_id": fixture.provider_id,
            "provider_type": "oauth2_client_credentials",
            "token_endpoint": fixture.token_endpoint,
            "client_id_secret_ref": client_id_secret,
            "client_secret_secret_ref": client_secret_secret,
            "created_at": now,
            "updated_at": now,
        }))
        .expect("serialize credential provider"),
    )
    .expect("write credential provider");
}

pub fn static_secret_target_auth_json(
    secret_id: &str,
    header_name: &str,
    header_format: &str,
    fallback: &str,
) -> Value {
    json!({
        "method": {
            "static_secret": {
                "secret_id": secret_id,
                "header_name": header_name,
                "header_format": header_format,
            }
        },
        "fallback": fallback,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn credential_provider_target_auth_json_names_the_provider_and_fallback() {
        let target_auth = super::credential_provider_target_auth_json("agent-idp", "passthrough");

        assert_eq!(target_auth["method"]["credential_provider"]["credential_provider_id"], "agent-idp");
        assert_eq!(target_auth["fallback"], "passthrough");
    }

    #[test]
    fn static_secret_target_auth_json_builds_shared_target_auth_shape() {
        let target_auth = super::static_secret_target_auth_json(
            "bdd-target-auth-secret",
            "x-target-api-key",
            "Bearer {secret}",
            "reject",
        );

        assert_eq!(target_auth["method"]["static_secret"]["secret_id"], "bdd-target-auth-secret");
        assert_eq!(target_auth["method"]["static_secret"]["header_name"], "x-target-api-key");
        assert_eq!(target_auth["method"]["static_secret"]["header_format"], "Bearer {secret}");
        assert_eq!(target_auth["fallback"], "reject");
    }
}
