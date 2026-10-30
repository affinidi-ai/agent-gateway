use std::path::Path;

use serde_json::{Value, json};

use crate::bdd_support::config::secrets::write_secret_fixture;

/// An OAuth provider the gateway uses for its own token to the Target.
#[derive(Debug, Clone)]
pub struct TargetTokenProviderFixture {
    pub provider_id: String,
    pub token_endpoint: String,
    pub grant: TargetTokenGrant,
}

/// How the gateway authenticates its own token request.
#[derive(Debug, Clone)]
pub enum TargetTokenGrant {
    ClientCredentials { client_id: String, client_secret: String },
    JwtBearer(JwtBearerAssertionFixture),
}

impl TargetTokenGrant {
    pub fn client_credentials(
        client_id: &str,
        client_secret: &str,
    ) -> Self {
        Self::ClientCredentials {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
        }
    }
}

/// The assertion settings of a JWT bearer provider and the PKCS#8 PEM key it signs with.
#[derive(Clone)]
pub struct JwtBearerAssertionFixture {
    pub issuer: String,
    pub subject: String,
    pub algorithm: String,
    pub key_id: String,
    pub signing_key_pem: String,
}

impl std::fmt::Debug for JwtBearerAssertionFixture {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("JwtBearerAssertionFixture")
            .field("issuer", &self.issuer)
            .field("subject", &self.subject)
            .field("algorithm", &self.algorithm)
            .field("key_id", &self.key_id)
            .field("signing_key_pem", &"[REDACTED]")
            .finish()
    }
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

/// The secret id that holds a JWT bearer provider's signing key.
pub fn signing_key_secret_id(provider_id: &str) -> String {
    format!("bdd-{provider_id}-gateway-signing-key")
}

/// The stored provider record, with secret references in place of every secret value.
pub fn target_token_provider_json(
    fixture: &TargetTokenProviderFixture,
    now: &str,
) -> Value {
    let mut record = json!({
        "id": fixture.provider_id,
        "name": fixture.provider_id,
        "provider_id": fixture.provider_id,
        "token_endpoint": fixture.token_endpoint,
        "created_at": now,
        "updated_at": now,
    });
    match &fixture.grant {
        TargetTokenGrant::ClientCredentials { .. } => {
            record["provider_type"] = json!("oauth2_client_credentials");
            record["client_id_secret_ref"] = json!(format!("bdd-{}-gateway-client-id", fixture.provider_id));
            record["client_secret_secret_ref"] = json!(format!("bdd-{}-gateway-client-secret", fixture.provider_id));
        }
        TargetTokenGrant::JwtBearer(assertion) => {
            record["provider_type"] = json!("oauth2_jwt_bearer");
            record["jwt_bearer"] = json!({
                "assertion_issuer": assertion.issuer,
                "assertion_subject": assertion.subject,
                "signing_key_secret_ref": signing_key_secret_id(&fixture.provider_id),
                "signing_algorithm": assertion.algorithm,
                "key_id": assertion.key_id,
            });
        }
    }
    record
}

/// Store the provider record and the secrets it references under `base_dir/_storage`.
pub fn write_target_token_provider(
    base_dir: &Path,
    fixture: &TargetTokenProviderFixture,
) {
    let storage_dir = base_dir.join("_storage");
    let secrets_dir = storage_dir.join("secrets");
    std::fs::create_dir_all(&secrets_dir).expect("create secrets dir");
    match &fixture.grant {
        TargetTokenGrant::ClientCredentials { client_id, client_secret } => {
            write_secret_fixture(&secrets_dir, &format!("bdd-{}-gateway-client-id", fixture.provider_id), client_id);
            write_secret_fixture(
                &secrets_dir,
                &format!("bdd-{}-gateway-client-secret", fixture.provider_id),
                client_secret,
            );
        }
        TargetTokenGrant::JwtBearer(assertion) => {
            write_secret_fixture(
                &secrets_dir,
                &signing_key_secret_id(&fixture.provider_id),
                &assertion.signing_key_pem,
            );
        }
    }
    let providers_dir = storage_dir.join("credential_providers");
    std::fs::create_dir_all(&providers_dir).expect("create credential provider dir");
    let record = target_token_provider_json(fixture, &chrono::Utc::now().to_rfc3339());
    std::fs::write(
        providers_dir.join(format!("{}.json", fixture.provider_id)),
        serde_json::to_string_pretty(&record).expect("serialize credential provider"),
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
    use super::*;

    const SIGNING_KEY: &str = "bdd-not-a-real-key";

    fn jwt_bearer_fixture() -> TargetTokenProviderFixture {
        TargetTokenProviderFixture {
            provider_id: "agent-idp".into(),
            token_endpoint: "http://127.0.0.1:1/token".into(),
            grant: TargetTokenGrant::JwtBearer(JwtBearerAssertionFixture {
                issuer: "gateway@example.test".into(),
                subject: "alpha@example.test".into(),
                algorithm: "ES256".into(),
                key_id: "bdd-gateway-key".into(),
                signing_key_pem: SIGNING_KEY.into(),
            }),
        }
    }

    #[test]
    fn credential_provider_target_auth_json_names_the_provider_and_fallback() {
        let target_auth = credential_provider_target_auth_json("agent-idp", "passthrough");

        assert_eq!(target_auth["method"]["credential_provider"]["credential_provider_id"], "agent-idp");
        assert_eq!(target_auth["fallback"], "passthrough");
    }

    #[test]
    fn client_credentials_record_references_the_client_secrets() {
        let fixture = TargetTokenProviderFixture {
            provider_id: "agent-idp".into(),
            token_endpoint: "http://127.0.0.1:1/token".into(),
            grant: TargetTokenGrant::client_credentials("client", "client-secret-value"),
        };

        let record = target_token_provider_json(&fixture, "2026-01-01T00:00:00Z");

        assert_eq!(record["provider_type"], "oauth2_client_credentials");
        assert_eq!(record["client_id_secret_ref"], "bdd-agent-idp-gateway-client-id");
        assert_eq!(record["client_secret_secret_ref"], "bdd-agent-idp-gateway-client-secret");
        assert!(
            record
                .get("jwt_bearer")
                .is_none()
        );
        assert!(
            !record
                .to_string()
                .contains("client-secret-value")
        );
    }

    #[test]
    fn jwt_bearer_record_carries_the_assertion_settings_and_only_a_key_reference() {
        let record = target_token_provider_json(&jwt_bearer_fixture(), "2026-01-01T00:00:00Z");

        assert_eq!(record["provider_type"], "oauth2_jwt_bearer");
        assert_eq!(record["token_endpoint"], "http://127.0.0.1:1/token");
        assert_eq!(record["jwt_bearer"]["assertion_issuer"], "gateway@example.test");
        assert_eq!(record["jwt_bearer"]["assertion_subject"], "alpha@example.test");
        assert_eq!(record["jwt_bearer"]["signing_algorithm"], "ES256");
        assert_eq!(record["jwt_bearer"]["key_id"], "bdd-gateway-key");
        assert_eq!(record["jwt_bearer"]["signing_key_secret_ref"], "bdd-agent-idp-gateway-signing-key");
        assert!(
            record
                .get("client_id_secret_ref")
                .is_none()
        );
        assert!(
            !record
                .to_string()
                .contains("bdd-not-a-real-key")
        );
    }

    #[test]
    fn jwt_bearer_provider_is_written_with_its_signing_key_secret() {
        let dir = tempfile::tempdir().expect("create temp dir");

        write_target_token_provider(dir.path(), &jwt_bearer_fixture());

        let secret: Value = serde_json::from_str(
            &std::fs::read_to_string(
                dir.path()
                    .join("_storage/secrets/bdd-agent-idp-gateway-signing-key.json"),
            )
            .expect("read signing key secret"),
        )
        .expect("parse signing key secret");
        assert_eq!(secret["value"], SIGNING_KEY);
        let record: Value = serde_json::from_str(
            &std::fs::read_to_string(
                dir.path()
                    .join("_storage/credential_providers/agent-idp.json"),
            )
            .expect("read provider record"),
        )
        .expect("parse provider record");
        assert_eq!(record["provider_type"], "oauth2_jwt_bearer");
        assert!(
            !dir.path()
                .join("_storage/secrets/bdd-agent-idp-gateway-client-secret.json")
                .exists()
        );
    }

    #[test]
    fn jwt_bearer_fixture_debug_redacts_the_signing_key() {
        let debug = format!("{:?}", jwt_bearer_fixture());

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("bdd-not-a-real-key"));
    }

    #[test]
    fn static_secret_target_auth_json_builds_shared_target_auth_shape() {
        let target_auth =
            static_secret_target_auth_json("bdd-target-auth-secret", "x-target-api-key", "Bearer {secret}", "reject");

        assert_eq!(target_auth["method"]["static_secret"]["secret_id"], "bdd-target-auth-secret");
        assert_eq!(target_auth["method"]["static_secret"]["header_name"], "x-target-api-key");
        assert_eq!(target_auth["method"]["static_secret"]["header_format"], "Bearer {secret}");
        assert_eq!(target_auth["fallback"], "reject");
    }
}
