use std::path::Path;

use chrono::Utc;
use serde_json::json;

use crate::bdd_support::sign_in_events::{APPLIANCE_ID, EVENT_TOPIC, RECORD_TEMPLATE, RECORD_TOPIC};

/// The events the stored sign-in integration receives.
pub const SIGN_IN_EVENTS: [&str; 2] = ["user.login", "user.login_failed"];

/// Stores an event set of [`SIGN_IN_EVENTS`] and an integration that streams them to
/// [`EVENT_TOPIC`] at `redis_url` with an empty template, so each event is the default envelope;
/// with `records`, a second one streams them to [`RECORD_TOPIC`] with Agent Watch's
/// [`RECORD_TEMPLATE`]. Sets [`APPLIANCE_ID`] in the stored settings, so envelopes carry it.
pub fn write_sign_in_event_integration(
    storage_dir: &Path,
    redis_url: &str,
    records: bool,
) {
    let now = Utc::now().to_rfc3339();
    let integrations = storage_dir.join("integrations");
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
    let mut streams = vec![("bdd-sign-in", EVENT_TOPIC, json!({}))];
    if records {
        let template: serde_json::Value = serde_json::from_str(RECORD_TEMPLATE).expect("the record template is JSON");
        streams.push(("bdd-sign-in-record", RECORD_TOPIC, template));
    }
    for (id, topic, content) in streams {
        write(
            &integrations.join(format!("endpoints/{id}-stream.json")),
            json!({
                "id": format!("{id}-stream"),
                "name": topic,
                "type": "stream",
                "configuration": {"platform": "redis", "topic": topic, "redis_url": redis_url},
                "status": "active",
                "created_at": now,
                "updated_at": now,
            }),
        );
        write(
            &integrations.join(format!("integrations/{id}-integration.json")),
            json!({
                "id": format!("{id}-integration"),
                "name": topic,
                "endpoint_id": format!("{id}-stream"),
                "event_set_id": "bdd-sign-in-events",
                "content": content,
                "status": "active",
                "created_at": now,
                "updated_at": now,
            }),
        );
    }
    set_appliance_id(storage_dir);
}

/// Adds [`APPLIANCE_ID`] to the settings the gateway starts with, keeping any others.
fn set_appliance_id(storage_dir: &Path) {
    let path = storage_dir.join("settings/settings.json");
    let mut settings = std::fs::read_to_string(&path)
        .ok()
        .map(|text| serde_json::from_str::<serde_json::Value>(&text).expect("the stored settings are JSON"))
        .unwrap_or_else(|| json!({}));
    settings["appliance_id"] = json!(APPLIANCE_ID);
    write(&path, settings);
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
