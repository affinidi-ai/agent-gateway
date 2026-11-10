use std::path::Path;

use chrono::Utc;
use serde_json::json;

/// The events the stored sign-in integration receives.
pub const SIGN_IN_EVENTS: [&str; 2] = ["user.login", "user.login_failed"];

/// Stores an active Redis stream endpoint, an event set of [`SIGN_IN_EVENTS`] and an integration
/// joining them with an empty template, so each event is streamed as the default envelope.
pub fn write_sign_in_event_integration(
    storage_dir: &Path,
    redis_url: &str,
) {
    let now = Utc::now().to_rfc3339();
    let integrations = storage_dir.join("integrations");
    write(
        &integrations.join("endpoints/bdd-sign-in-stream.json"),
        json!({
            "id": "bdd-sign-in-stream",
            "name": "Sign-in stream",
            "type": "stream",
            "configuration": {"platform": "redis", "topic": "sign-ins", "redis_url": redis_url},
            "status": "active",
            "created_at": now,
            "updated_at": now,
        }),
    );
    write(
        &integrations.join("event_sets/bdd-sign-in-events.json"),
        json!({
            "id": "bdd-sign-in-events",
            "name": "Sign-ins",
            "events": SIGN_IN_EVENTS,
            "created_at": now,
            "updated_at": now,
        }),
    );
    write(
        &integrations.join("integrations/bdd-sign-in-integration.json"),
        json!({
            "id": "bdd-sign-in-integration",
            "name": "Sign-ins to Redis",
            "endpoint_id": "bdd-sign-in-stream",
            "event_set_id": "bdd-sign-in-events",
            "content": {},
            "status": "active",
            "created_at": now,
            "updated_at": now,
        }),
    );
}

/// Switches the gateway written under `base_dir` to SAML sign-in, trusting an identity provider
/// certificate generated for the scenario.
pub fn sign_in_with_saml(
    base_dir: &Path,
    gateway_port: u16,
) {
    let key = rcgen::KeyPair::generate().expect("an identity provider key");
    let cert = rcgen::CertificateParams::new(vec!["idp.example.test".to_string()])
        .expect("identity provider certificate parameters")
        .self_signed(&key)
        .expect("an identity provider certificate");
    let cert_path = base_dir.join("idp.crt");
    std::fs::write(&cert_path, cert.pem()).expect("write the identity provider certificate");
    let saml_path = base_dir.join("saml.json");
    write(
        &saml_path,
        json!({
            "idp_entity_id": "https://idp.example.test",
            "idp_sso_url": "https://idp.example.test/sso",
            "sp_entity_id": format!("http://localhost:{gateway_port}"),
            "sp_acs_url": format!("http://localhost:{gateway_port}/api/saml/acs"),
            "idp_cert_path": cert_path.display().to_string(),
            "sign_requests": false,
        }),
    );

    let config_path = base_dir.join("config.toml");
    let config = std::fs::read_to_string(&config_path).expect("read config.toml");
    assert!(config.contains("auth_mode = \"passkey\""), "the gateway config must set the auth mode");
    assert!(config.contains("[config_files]\n"), "the gateway config must list its config files");
    let config = config
        .replacen("auth_mode = \"passkey\"", "auth_mode = \"saml\"", 1)
        .replacen("[config_files]\n", &format!("[config_files]\nsaml = \"{}\"\n", saml_path.display()), 1);
    std::fs::write(&config_path, config).expect("write config.toml");
}

fn write(
    path: &Path,
    value: serde_json::Value,
) {
    std::fs::write(path, serde_json::to_string_pretty(&value).expect("serialize fixture"))
        .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
}
