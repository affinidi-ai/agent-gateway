use serde_json::{Value, json};

pub const TARGET_AUTH_PROVIDER_ID: &str = "bdd-target-provider";
pub const TARGET_AUTH_PROVIDER_TOKEN: &str = "bdd-target-provider-token";
pub const TARGET_AUTH_PROVIDER_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
pub const TARGET_AUTH_JWT_ISSUER: &str = "bdd-agent@bdd-project.iam.gserviceaccount.com";
pub const TARGET_AUTH_CLIENT_ID_SECRET: &str = "bdd-target-client-id";
pub const TARGET_AUTH_CLIENT_SECRET_SECRET: &str = "bdd-target-client-secret";
pub const TARGET_AUTH_SIGNING_KEY_SECRET: &str = "bdd-target-signing-key";

/// The RSA key a JWT Bearer provider signs its grant with: the private PEM goes into
/// the provider's secret, the public PEM verifies the grant the token endpoint receives.
pub struct TargetAuthSigningKey {
    pub private_pem: String,
    pub public_pem: String,
}

pub fn target_auth_signing_key() -> &'static TargetAuthSigningKey {
    static KEY: std::sync::LazyLock<TargetAuthSigningKey> = std::sync::LazyLock::new(|| {
        let key = openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
        TargetAuthSigningKey {
            private_pem: String::from_utf8(
                key.private_key_to_pem_pkcs8()
                    .unwrap(),
            )
            .unwrap(),
            public_pem: String::from_utf8(
                key.public_key_to_pem()
                    .unwrap(),
            )
            .unwrap(),
        }
    });
    &KEY
}

pub fn credential_provider_target_auth_json(
    provider_id: &str,
    fallback: &str,
) -> Value {
    json!({
        "method": { "credential_provider": { "provider_id": provider_id } },
        "fallback": fallback,
    })
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

    #[test]
    fn credential_provider_target_auth_json_names_the_provider_and_fallback() {
        let target_auth = super::credential_provider_target_auth_json("bdd-target-provider", "passthrough");

        assert_eq!(target_auth["method"]["credential_provider"]["provider_id"], "bdd-target-provider");
        assert_eq!(target_auth["fallback"], "passthrough");
    }
}
