//! Saving a tenant surface and reassigning a tenant over the admin API: a new appliance-wide
//! credential on a tenant surface is refused, one the stored surface already held is kept in
//! `warn` mode and refused in `enforce` mode, and a reassignment that would give a tenant
//! resource an appliance-wide credential or another tenant's resource is a conflict.

use serde_json::{Value, json};

use super::helpers::{GatewayHarness, configure_admin_api};
use crate::config::credential_policy::{CredentialPolicyConfig, RuleMode};

const STORED_SECRET_SURFACE: &str = "stored-secret-surface";
const STORED_BINDING_SURFACE: &str = "stored-binding-surface";
const STORED_PROVIDER: &str = "stored-appliance-provider";
const NOT_ACCESSIBLE_SECRET: &str = "Secret reference is not accessible";
const NOT_ACCESSIBLE_PROVIDER: &str = "Credential provider reference is not accessible";

struct Api {
    client: reqwest::Client,
    base: String,
    listener: String,
    target: String,
    secret_uuids: std::collections::HashMap<String, String>,
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

    async fn secret(
        &self,
        secret_id: &str,
        tenant: Option<&str>,
    ) -> String {
        let (status, body) = self
            .send(
                self.client
                    .post(self.url("secrets/new"))
                    .json(&json!({"name": secret_id, "secret_id": secret_id, "value": "v", "tenant_id": tenant})),
            )
            .await;
        assert_eq!(status, 201, "{body}");
        body["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn provider(
        &self,
        provider_id: &str,
        provider_type: &str,
        tenant: Option<&str>,
        secrets: (&str, &str),
    ) -> String {
        let (status, body) = self
            .send(
                self.client
                    .post(self.url("credential-providers"))
                    .json(&json!({
                        "name": provider_id, "provider_id": provider_id, "provider_type": provider_type,
                        "authorization_endpoint": "https://192.0.2.1/authorize",
                        "token_endpoint": "https://192.0.2.1/token",
                        "client_id_secret_ref": secrets.0, "client_secret_secret_ref": secrets.1,
                        "tenant_id": tenant
                    })),
            )
            .await;
        assert_eq!(status, 201, "{body}");
        body["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn surface(
        &self,
        route: &str,
        tenant: Option<&str>,
        extra: Value,
    ) -> Value {
        let mut surface = json!({
            "name": route.trim_start_matches('/').replace('/', "-"), "status": "disabled",
            "access_point": {"listen_address": self.listener, "route": route, "protocol": "a2a"},
            "target": {"endpoint": self.target},
            "tenant_id": tenant
        });
        for (key, value) in extra.as_object().unwrap() {
            if key == "target_auth" {
                surface["target"]["auth"] = value.clone();
            } else {
                surface[key] = value.clone();
            }
        }
        surface
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

    async fn created_id(
        &self,
        surface: &Value,
    ) -> String {
        let (status, body) = self.create(surface).await;
        assert!(matches!(status, 200 | 201), "{status} {body}");
        body["surface_id"]
            .as_str()
            .unwrap()
            .to_string()
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

    async fn patch(
        &self,
        surface_id: &str,
        patch: &Value,
    ) -> (u16, Value) {
        self.send(
            self.client
                .patch(self.url(&format!("surfaces/{surface_id}")))
                .header("Content-Type", "application/merge-patch+json")
                .json(patch),
        )
        .await
    }

    async fn stored(
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

    async fn reassign(
        &self,
        kind: &str,
        id: &str,
        tenant: Option<&str>,
    ) -> (u16, Value) {
        self.send(
            self.client
                .put(self.url(&format!("tenant-ownership/{kind}/{id}")))
                .json(&json!({"tenant_id": tenant})),
        )
        .await
    }
}

fn static_secret(secret_id: &str) -> Value {
    json!({"method": {"static_secret": {"secret_id": secret_id, "header_name": "Authorization"}}})
}

fn binding(provider_id: &str) -> Value {
    json!([{"credential_provider_id": provider_id}])
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

fn seed_stored_credentials(bootstrap: &crate::config::BootstrapConfig) {
    let gateway: Value = serde_json::from_slice(&std::fs::read(&bootstrap.config_files.gateway).unwrap()).unwrap();
    let port = gateway["listeners"][0]["port"]
        .as_u64()
        .unwrap();
    let now = chrono::Utc::now().to_rfc3339();
    let surface = |surface_id: &str, extra: Value| {
        let mut surface = json!({
            "surface_id": surface_id, "name": surface_id, "status": "disabled", "tenant_id": "tenant-a",
            "access_point": {
                "listen_address": format!("http://localhost:{port}"), "route": format!("/smoke/{surface_id}"),
                "protocol": "a2a"
            },
            "target": {"endpoint": "http://127.0.0.1:9/"}
        });
        for (key, value) in extra.as_object().unwrap() {
            surface[key] = value.clone();
        }
        surface
    };
    let provider = json!({
        "id": STORED_PROVIDER, "name": STORED_PROVIDER, "provider_id": STORED_PROVIDER,
        "provider_type": "oauth2_client_credentials", "token_endpoint": "https://192.0.2.1/token",
        "client_id_secret_ref": "appliance-client-id", "client_secret_secret_ref": "appliance-client-secret",
        "created_at": now, "updated_at": now
    });
    for (directory, id, record) in [
        (
            &bootstrap
                .storage_paths
                .agent_surfaces,
            STORED_SECRET_SURFACE,
            surface(
                STORED_SECRET_SURFACE,
                json!({"target": {"endpoint": "http://127.0.0.1:9/", "auth": static_secret("appliance-key")}}),
            ),
        ),
        (
            &bootstrap
                .storage_paths
                .agent_surfaces,
            STORED_BINDING_SURFACE,
            surface(STORED_BINDING_SURFACE, json!({"outbound_credentials": binding(STORED_PROVIDER)})),
        ),
        (
            &bootstrap
                .storage_paths
                .credential_providers,
            STORED_PROVIDER,
            provider,
        ),
    ] {
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(
            std::path::Path::new(directory).join(format!("{id}.json")),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
    }
}

async fn harness(isolation: RuleMode) -> (GatewayHarness, Api) {
    let mut client = None;
    let harness = GatewayHarness::start(|_, _, bootstrap| {
        bootstrap.credential_policy = CredentialPolicyConfig {
            tenant_credential_isolation: isolation,
            ..Default::default()
        };
        seed_stored_credentials(bootstrap);
        client = Some(configure_admin_api(bootstrap));
    })
    .await;
    let mut api = Api {
        secret_uuids: Default::default(),
        client: client.unwrap(),
        base: harness.gateway_base.clone(),
        listener: harness
            .gateway_base
            .replace("127.0.0.1", "localhost"),
        target: harness.mock.url(),
    };
    for (secret_id, tenant) in [
        ("appliance-key", None),
        ("appliance-client-id", None),
        ("appliance-client-secret", None),
        ("tenant-key", Some("tenant-a")),
        ("tenant-client-id", Some("tenant-a")),
        ("tenant-client-secret", Some("tenant-a")),
    ] {
        let uuid = api
            .secret(secret_id, tenant)
            .await;
        api.secret_uuids
            .insert(secret_id.to_string(), uuid);
    }
    (harness, api)
}

struct Providers {
    appliance_client_credentials: String,
    appliance_authorization_code: String,
    tenant_client_credentials: String,
}

async fn providers(api: &Api) -> Providers {
    Providers {
        appliance_client_credentials: api
            .provider(
                "appliance-cc",
                "oauth2_client_credentials",
                None,
                ("appliance-client-id", "appliance-client-secret"),
            )
            .await,
        appliance_authorization_code: api
            .provider(
                "appliance-ac",
                "oauth2_authorization_code",
                None,
                ("appliance-client-id", "appliance-client-secret"),
            )
            .await,
        tenant_client_credentials: api
            .provider(
                "tenant-cc",
                "oauth2_client_credentials",
                Some("tenant-a"),
                ("tenant-client-id", "tenant-client-secret"),
            )
            .await,
    }
}

async fn assert_new_references_follow_the_tenant(api: &Api) {
    let providers = providers(api).await;

    assert_refused(
        api.create(&api.surface(
            "/smoke/new-appliance-secret",
            Some("tenant-a"),
            json!({"target_auth": static_secret("appliance-key")}),
        ))
        .await,
        NOT_ACCESSIBLE_SECRET,
    );
    assert_refused(
        api.create(&api.surface(
            "/smoke/new-appliance-binding",
            Some("tenant-a"),
            json!({"outbound_credentials": binding(&providers.appliance_client_credentials)}),
        ))
        .await,
        NOT_ACCESSIBLE_PROVIDER,
    );

    assert_saved(
        api.create(&api.surface(
            "/smoke/new-tenant-secret",
            Some("tenant-a"),
            json!({"target_auth": static_secret("tenant-key")}),
        ))
        .await,
    );
    assert_saved(
        api.create(&api.surface(
            "/smoke/new-tenant-binding",
            Some("tenant-a"),
            json!({"outbound_credentials": binding(&providers.tenant_client_credentials)}),
        ))
        .await,
    );
    assert_saved(
        api.create(&api.surface(
            "/smoke/new-consent-binding",
            Some("tenant-a"),
            json!({"outbound_credentials": binding(&providers.appliance_authorization_code)}),
        ))
        .await,
    );
    assert_saved(
        api.create(&api.surface(
            "/smoke/appliance-binding",
            None,
            json!({"outbound_credentials": binding(&providers.appliance_client_credentials), "target_auth": static_secret("appliance-key")}),
        ))
        .await,
    );

    let existing = api
        .created_id(&api.surface(
            "/smoke/existing",
            Some("tenant-a"),
            json!({"target_auth": static_secret("tenant-key")}),
        ))
        .await;
    let mut changed = api.stored(&existing).await;
    changed["target"]["auth"] = static_secret("appliance-key");
    assert_refused(
        api.put(&existing, &changed)
            .await,
        NOT_ACCESSIBLE_SECRET,
    );
    assert_refused(
        api.patch(&existing, &json!({"target": {"auth": static_secret("appliance-key")}}))
            .await,
        NOT_ACCESSIBLE_SECRET,
    );
    assert_refused(
        api.patch(&existing, &json!({"outbound_credentials": binding(&providers.appliance_client_credentials)}))
            .await,
        NOT_ACCESSIBLE_PROVIDER,
    );
    assert_saved(
        api.patch(&existing, &json!({"outbound_credentials": binding(&providers.appliance_authorization_code)}))
            .await,
    );
    assert_eq!(
        api.stored(&existing).await["target"]["auth"]["method"]["static_secret"]["secret_id"],
        "tenant-key",
        "a refused save leaves the stored surface as it was"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_appliance_wide_credential_on_a_tenant_surface_is_refused_and_a_stored_one_is_kept_in_warn_mode() {
    let (_harness, api) = harness(RuleMode::Warn).await;
    assert_new_references_follow_the_tenant(&api).await;

    for surface_id in [STORED_SECRET_SURFACE, STORED_BINDING_SURFACE] {
        let unchanged = api.stored(surface_id).await;
        assert_saved(
            api.put(surface_id, &unchanged)
                .await,
        );
    }

    let mut moved = api
        .stored(STORED_SECRET_SURFACE)
        .await;
    moved["target"]["auth"] = static_secret("appliance-client-id");
    assert_refused(
        api.put(STORED_SECRET_SURFACE, &moved)
            .await,
        NOT_ACCESSIBLE_SECRET,
    );
    moved["target"]["auth"] = static_secret("tenant-key");
    assert_saved(
        api.put(STORED_SECRET_SURFACE, &moved)
            .await,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_appliance_wide_credential_on_a_tenant_surface_is_refused_when_enforced() {
    let (_harness, api) = harness(RuleMode::Enforce).await;
    assert_new_references_follow_the_tenant(&api).await;

    let unchanged = api
        .stored(STORED_SECRET_SURFACE)
        .await;
    assert_refused(
        api.put(STORED_SECRET_SURFACE, &unchanged)
            .await,
        NOT_ACCESSIBLE_SECRET,
    );
    let unchanged = api
        .stored(STORED_BINDING_SURFACE)
        .await;
    assert_refused(
        api.put(STORED_BINDING_SURFACE, &unchanged)
            .await,
        NOT_ACCESSIBLE_PROVIDER,
    );

    let mut fixed = api
        .stored(STORED_SECRET_SURFACE)
        .await;
    fixed["target"]["auth"] = static_secret("tenant-key");
    assert_saved(
        api.put(STORED_SECRET_SURFACE, &fixed)
            .await,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reassignment_that_would_cross_tenants_or_give_a_tenant_an_appliance_wide_credential_is_a_conflict() {
    let (_harness, api) = harness(RuleMode::Warn).await;
    let providers = providers(&api).await;
    let tenant_key = api.secret_uuids["tenant-key"].clone();
    let tenant_surface = api
        .created_id(&api.surface("/smoke/owned", Some("tenant-a"), json!({"target_auth": static_secret("tenant-key")})))
        .await;
    let appliance_secret_surface = api
        .created_id(&api.surface("/smoke/wide-secret", None, json!({"target_auth": static_secret("appliance-key")})))
        .await;
    let appliance_binding_surface = api
        .created_id(&api.surface(
            "/smoke/wide-binding",
            None,
            json!({"outbound_credentials": binding(&providers.appliance_client_credentials)}),
        ))
        .await;
    let appliance_consent_surface = api
        .created_id(&api.surface(
            "/smoke/wide-consent",
            None,
            json!({"outbound_credentials": binding(&providers.appliance_authorization_code)}),
        ))
        .await;
    let plain_surface = api
        .created_id(&api.surface("/smoke/plain", None, json!({})))
        .await;

    let blocked = |result: (u16, Value), reason: &str| {
        assert_eq!(result.0, 409, "{}", result.1);
        assert_eq!(result.1["error"], "tenant_reassignment_blocked", "{}", result.1);
        let reasons: Vec<&str> = result.1["conflicts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|conflict| conflict["reason"].as_str())
            .collect();
        assert!(reasons.contains(&reason), "{reason:?} not in {reasons:?}");
    };
    let credential = "The proposed tenant would give a tenant resource an appliance-wide credential";

    blocked(
        api.reassign("surfaces", &appliance_secret_surface, Some("tenant-a"))
            .await,
        credential,
    );
    blocked(
        api.reassign("surfaces", &appliance_binding_surface, Some("tenant-a"))
            .await,
        credential,
    );
    assert_eq!(
        api.stored(&appliance_secret_surface)
            .await["tenant_id"],
        Value::Null,
        "a blocked reassignment changes nothing"
    );
    let (status, body) = api
        .reassign("surfaces", &appliance_consent_surface, Some("tenant-a"))
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["tenant_id"], "tenant-a", "{body}");
    let (status, body) = api
        .reassign("surfaces", &plain_surface, Some("tenant-b"))
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["previous_tenant_id"], Value::Null, "{body}");

    for tenant in [Some("tenant-b"), None] {
        let (status, body) = api
            .reassign("secrets", &tenant_key, tenant)
            .await;
        assert_eq!(status, 409, "{body}");
        assert_eq!(body["error"], "tenant_reassignment_blocked", "{body}");
    }
    let (status, body) = api
        .reassign("surfaces", &tenant_surface, Some("tenant-b"))
        .await;
    assert_eq!(status, 409, "{body}");
    let (status, body) = api
        .reassign("secrets", &tenant_key, Some("tenant-a"))
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["tenant_id"], "tenant-a", "{body}");
    assert_eq!(
        api.stored(&tenant_surface)
            .await["tenant_id"],
        "tenant-a",
        "the surface stays with its tenant"
    );
}
