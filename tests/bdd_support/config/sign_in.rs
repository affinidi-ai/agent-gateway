use std::path::Path;

use chrono::Utc;
use serde_json::json;

use crate::bdd_support::dashboard_op::{
    BOUND_TENANT, DASHBOARD_CLIENT_ID, DASHBOARD_CLIENT_SECRET, DASHBOARD_PROVIDER_LABEL,
};
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
/// certificate generated for the scenario, with `settings` written over the fixture's `saml.json`.
pub fn sign_in_with_saml(
    base_dir: &Path,
    gateway_port: u16,
    settings: &serde_json::Map<String, serde_json::Value>,
) {
    let key = rcgen::KeyPair::generate().expect("an identity provider key");
    let cert = rcgen::CertificateParams::new(vec!["idp.example.test".to_string()])
        .expect("identity provider certificate parameters")
        .self_signed(&key)
        .expect("an identity provider certificate");
    let cert_path = base_dir.join("idp.crt");
    std::fs::write(&cert_path, cert.pem()).expect("write the identity provider certificate");
    std::fs::write(base_dir.join("idp.key"), key.serialize_pem()).expect("write the identity provider key");
    let saml_path = base_dir.join("saml.json");
    let mut saml = json!({
        "idp_entity_id": "https://idp.example.test",
        "idp_sso_url": "https://idp.example.test/sso",
        "sp_entity_id": format!("http://localhost:{gateway_port}"),
        "sp_acs_url": format!("http://localhost:{gateway_port}/api/saml/acs"),
        "idp_cert_path": cert_path.display().to_string(),
        "sign_requests": false,
        "role_mapping": {
            "gw-admins": "administrator",
            "gw-power": "poweruser",
            "gw-all": "user",
        },
    });
    for (key, value) in settings {
        saml[key] = value.clone();
    }
    write(&saml_path, saml);

    let config_path = base_dir.join("config.toml");
    let config = std::fs::read_to_string(&config_path).expect("read config.toml");
    assert!(config.contains("auth_mode = \"passkey\""), "the gateway config must set the auth mode");
    assert!(config.contains("[config_files]\n"), "the gateway config must list its config files");
    let config = config
        .replacen("auth_mode = \"passkey\"", "auth_mode = \"saml\"", 1)
        .replacen("[config_files]\n", &format!("[config_files]\nsaml = \"{}\"\n", saml_path.display()), 1);
    std::fs::write(&config_path, config).expect("write config.toml");
}

/// Switches the gateway written under `base_dir` to OpenID Connect sign-in at the provider
/// `issuer`, binding sign-in to [`BOUND_TENANT`] and mapping the `roles` claim, with `settings`
/// written over that `oidc.json`. The client secret is a `file://` reference to a file with a
/// trailing newline, as an operator's secret file usually has.
pub fn sign_in_with_oidc(
    base_dir: &Path,
    gateway_port: u16,
    issuer: &str,
    settings: &serde_json::Map<String, serde_json::Value>,
) {
    let secret_path = base_dir.join("oidc-client-secret");
    std::fs::write(&secret_path, format!("{DASHBOARD_CLIENT_SECRET}\n")).expect("write the OIDC client secret");
    let oidc_path = base_dir.join("oidc.json");
    let mut oidc = json!({
        "label": DASHBOARD_PROVIDER_LABEL,
        "issuer": issuer,
        "client_id": DASHBOARD_CLIENT_ID,
        "client_secret": format!("file://{}", secret_path.display()),
        "redirect_uri": format!("http://localhost:{gateway_port}/api/oidc/callback"),
        "id_token_signing_algs": ["EdDSA"],
        "required_claims": { "org_id": [BOUND_TENANT] },
        "role_mapping": {
            "claim": "roles",
            "values": { "gw-admins": "administrator", "gw-power": "poweruser", "gw-all": "user" },
        },
    });
    for (key, value) in settings {
        oidc[key] = value.clone();
    }
    write(&oidc_path, oidc);

    let config_path = base_dir.join("config.toml");
    let config = std::fs::read_to_string(&config_path).expect("read config.toml");
    assert!(config.contains("auth_mode = \"passkey\""), "the gateway config must set the auth mode");
    assert!(config.contains("[config_files]\n"), "the gateway config must list its config files");
    let config = config
        .replacen("auth_mode = \"passkey\"", "auth_mode = \"oidc\"", 1)
        .replacen("[config_files]\n", &format!("[config_files]\noidc = \"{}\"\n", oidc_path.display()), 1);
    std::fs::write(&config_path, config).expect("write config.toml");
}

/// Sets the appliance limit on human users of the gateway written under `base_dir` to `limit`.
pub fn limit_human_users(
    base_dir: &Path,
    limit: u64,
) {
    let limits_path = base_dir.join("limits.json");
    write(
        &limits_path,
        json!({ "limits": { "users": { "name": "Users", "description": "Human users", "limit": limit } } }),
    );
    let config_path = base_dir.join("config.toml");
    let config = std::fs::read_to_string(&config_path).expect("read config.toml");
    assert!(config.contains("[config_files]\n"), "the gateway config must list its config files");
    let config =
        config.replacen("[config_files]\n", &format!("[config_files]\nlimits = \"{}\"\n", limits_path.display()), 1);
    std::fs::write(&config_path, config).expect("write config.toml");
}

fn write(
    path: &Path,
    value: serde_json::Value,
) {
    std::fs::write(path, serde_json::to_string_pretty(&value).expect("serialize fixture"))
        .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
}
