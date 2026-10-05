use serde_json::{Value, json};

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
}
