//! Saving Target authentication over the admin API: a new or changed setting that breaks a
//! rule (header name, value format, a header another credential on the leg already sends, and
//! with the credential policy rules enforced, an https Target and a leg that checks its
//! callers) is refused with `400` naming the field, and a stored surface that already broke
//! one still saves while the setting is unchanged. With those rules in `warn` the https and
//! caller rules only warn.

use serde_json::{Value, json};

use super::helpers::{GatewayHarness, configure_admin_api};
use crate::config::credential_policy::{CredentialPolicyConfig, RuleMode};

const STORED_SURFACE: &str = "stored-http-surface";

/// A Target authentication, an edit to the surface around it, and the `details` its save is
/// refused with.
type RefusalCase = (Value, fn(&mut Value), &'static str);

struct Api {
    client: reqwest::Client,
    base: String,
    listener: String,
}

impl Api {
    fn url(
        &self,
        path: &str,
    ) -> String {
        format!("{}/api/v1/{path}", self.base)
    }

    async fn send(
        &self,
        request: reqwest::RequestBuilder,
    ) -> (u16, Value) {
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let text = response
            .text()
            .await
            .unwrap_or_default();
        (status, serde_json::from_str(&text).unwrap_or(Value::String(text)))
    }

    async fn create(
        &self,
        surface: &Value,
    ) -> (u16, Value) {
        self.send(
            self.client
                .post(self.url("surfaces"))
                .json(surface),
        )
        .await
    }

    async fn put(
        &self,
        surface_id: &str,
        surface: &Value,
    ) -> (u16, Value) {
        self.send(
            self.client
                .put(self.url(&format!("surfaces/{surface_id}")))
                .json(surface),
        )
        .await
    }

    async fn get(
        &self,
        surface_id: &str,
    ) -> Value {
        let (status, body) = self
            .send(
                self.client
                    .get(self.url(&format!("surfaces/{surface_id}"))),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body
    }

    /// A surface whose Access Point checks callers with an API key and whose Target is
    /// https, with `target_auth` as its Target authentication, then `edit` applied.
    fn surface(
        &self,
        route: &str,
        target_auth: Value,
        edit: impl FnOnce(&mut Value),
    ) -> Value {
        let mut surface = json!({
            "name": route.trim_start_matches('/').replace('/', "-"), "status": "disabled",
            "access_point": {
                "listen_address": self.listener, "route": route, "protocol": "a2a",
                "caller_authentication": {"methods": [{
                    "type": "api_key", "secret_id": "caller-key",
                    "extraction": {"source": "http_header", "field": "X-Caller-Key"}
                }]}
            },
            "target": {"endpoint": "https://127.0.0.1:9/", "auth": target_auth}
        });
        edit(&mut surface);
        surface
    }
}

fn static_secret(
    header_name: &str,
    header_format: &str,
) -> Value {
    json!({"method": {"static_secret": {
        "secret_id": "target-key", "header_name": header_name, "header_format": header_format
    }}})
}

fn seed_stored_surface(bootstrap: &crate::config::BootstrapConfig) {
    let gateway: Value = serde_json::from_slice(&std::fs::read(&bootstrap.config_files.gateway).unwrap()).unwrap();
    let port = gateway["listeners"][0]["port"]
        .as_u64()
        .unwrap();
    let surface = json!({
        "surface_id": STORED_SURFACE, "name": STORED_SURFACE, "status": "disabled",
        "access_point": {
            "listen_address": format!("http://localhost:{port}"), "route": "/smoke/stored", "protocol": "a2a"
        },
        "target": {"endpoint": "http://127.0.0.1:9/", "auth": static_secret("X-Target-Key", "{value}")}
    });
    let directory = &bootstrap
        .storage_paths
        .agent_surfaces;
    std::fs::create_dir_all(directory).unwrap();
    std::fs::write(
        std::path::Path::new(directory).join(format!("{STORED_SURFACE}.json")),
        serde_json::to_vec(&surface).unwrap(),
    )
    .unwrap();
}

/// A gateway with `target_https` and `target_source_auth` in `mode`.
async fn harness(mode: RuleMode) -> (GatewayHarness, Api) {
    let mut client = None;
    let harness = GatewayHarness::start(|_, _, bootstrap| {
        bootstrap.credential_policy = CredentialPolicyConfig {
            target_https: mode,
            target_source_auth: mode,
            ..Default::default()
        };
        seed_stored_surface(bootstrap);
        client = Some(configure_admin_api(bootstrap));
    })
    .await;
    let api = Api {
        client: client.unwrap(),
        base: harness.gateway_base.clone(),
        listener: harness
            .gateway_base
            .replace("127.0.0.1", "localhost"),
    };
    for secret_id in ["caller-key", "target-key"] {
        let (status, body) = api
            .send(
                api.client
                    .post(api.url("secrets/new"))
                    .json(&json!({"name": secret_id, "secret_id": secret_id, "value": "v", "secret_type": "general"})),
            )
            .await;
        assert!(matches!(status, 200 | 201), "{status} {body}");
    }
    (harness, api)
}

fn assert_refused(
    result: (u16, Value),
    details: &str,
) {
    assert_eq!(result.0, 400, "{}", result.1);
    assert_eq!(result.1["details"], details, "{}", result.1);
}

fn assert_saved(result: (u16, Value)) {
    assert!(matches!(result.0, 200 | 201), "{} {}", result.0, result.1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_target_authentication_that_breaks_a_rule_is_refused_and_its_twin_saves() {
    let (_harness, api) = harness(RuleMode::Enforce).await;
    let cases: Vec<RefusalCase> = vec![
        (
            static_secret("transfer-encoding", "{value}"),
            |_| {},
            "target.auth.header_name must not be the reserved header Transfer-Encoding",
        ),
        (static_secret("X Target", "{value}"), |_| {}, "target.auth.header_name must be an HTTP header name"),
        (
            static_secret("X-Target-Key", "{value}\r\nX-Injected: 1"),
            |_| {},
            "target.auth.header_format must not contain CR, LF or NUL",
        ),
        (
            static_secret("X-Target-Key", "Bearer"),
            |_| {},
            "target.auth.header_format must contain {value} exactly once",
        ),
        (
            static_secret("X-Target-Key", "{value}"),
            |surface| surface["target"]["endpoint"] = json!("http://127.0.0.1:9/"),
            "target.auth sends a credential, so its Target must be an https URL",
        ),
        (
            static_secret("X-Target-Key", "{value}"),
            |surface| {
                surface["access_point"]
                    .as_object_mut()
                    .unwrap()
                    .remove("caller_authentication");
            },
            "target.auth sends a credential, so it needs source authentication on the Access Point",
        ),
        (
            static_secret("x-target-key", "{value}"),
            |surface| {
                surface["access_point"]["header_metadata_mapping"] =
                    json!({"headers": [{"header": "X-Target-Key", "field": "target"}]})
            },
            "target.auth.header_name x-target-key is already sent by header metadata mapping",
        ),
    ];
    for (index, (target_auth, edit, details)) in cases.into_iter().enumerate() {
        let surface = api.surface(&format!("/smoke/refused-{index}"), target_auth, edit);
        assert_refused(api.create(&surface).await, details);
    }
    assert_saved(
        api.create(&api.surface("/smoke/twin", static_secret("X-Target-Key", "Token {value}"), |_| {}))
            .await,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_surface_that_breaks_a_rule_saves_until_its_target_authentication_changes() {
    let (_harness, api) = harness(RuleMode::Enforce).await;
    let mut renamed = api.get(STORED_SURFACE).await;
    renamed["name"] = json!("renamed");
    assert_saved(
        api.put(STORED_SURFACE, &renamed)
            .await,
    );

    let mut reformatted = api.get(STORED_SURFACE).await;
    reformatted["target"]["auth"]["method"]["static_secret"]["header_format"] = json!("Token {value}");
    assert_refused(
        api.put(STORED_SURFACE, &reformatted)
            .await,
        "target.auth sends a credential, so its Target must be an https URL",
    );

    let mut redirected = api.get(STORED_SURFACE).await;
    redirected["target"]["endpoint"] = json!("https://127.0.0.1:9/other");
    assert_refused(
        api.put(STORED_SURFACE, &redirected)
            .await,
        "target.auth sends a credential, so it needs source authentication on the Access Point",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn in_warn_a_new_http_target_or_unchecked_leg_saves_and_header_rules_still_refuse() {
    let (_harness, api) = harness(RuleMode::Warn).await;
    assert_saved(
        api.create(&api.surface("/smoke/http", static_secret("X-Target-Key", "{value}"), |surface| {
            surface["target"]["endpoint"] = json!("http://127.0.0.1:9/")
        }))
        .await,
    );
    assert_saved(
        api.create(&api.surface("/smoke/unchecked", static_secret("X-Target-Key", "{value}"), |surface| {
            surface["access_point"]
                .as_object_mut()
                .unwrap()
                .remove("caller_authentication");
        }))
        .await,
    );
    let mut reformatted = api.get(STORED_SURFACE).await;
    reformatted["target"]["auth"]["method"]["static_secret"]["header_format"] = json!("Token {value}");
    assert_saved(
        api.put(STORED_SURFACE, &reformatted)
            .await,
    );
    assert_refused(
        api.create(&api.surface("/smoke/reserved", static_secret("transfer-encoding", "{value}"), |_| {}))
            .await,
        "target.auth.header_name must not be the reserved header Transfer-Encoding",
    );
    assert_refused(
        api.create(&api.surface("/smoke/no-placeholder", static_secret("X-Target-Key", "Bearer"), |surface| {
            surface["target"]["endpoint"] = json!("http://127.0.0.1:9/")
        }))
        .await,
        "target.auth.header_format must contain {value} exactly once",
    );
}
