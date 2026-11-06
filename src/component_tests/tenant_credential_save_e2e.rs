//! Saving a tenant surface or credential provider and reassigning a tenant over the admin API:
//! a new appliance-wide credential on a tenant surface or provider is refused, one the stored
//! record already held is kept in `warn` mode (on a provider, only while it stays in the same
//! field and goes to the same destination; on a surface, only while each Target and Transit
//! Point that sends it keeps its endpoint, and response custom metadata keeps going to the
//! caller, or while it stays in disabled custom metadata) and refused in `enforce` mode, a
//! custom metadata secret that does not exist is refused on a tenant surface even when stored,
//! and a reassignment that would give a tenant resource an appliance-wide credential or another
//! tenant's resource is a conflict.

use serde_json::{Value, json};

use super::helpers::{GatewayHarness, configure_admin_api};
use crate::config::credential_policy::{CredentialPolicyConfig, RuleMode};

const STORED_SECRET_SURFACE: &str = "stored-secret-surface";
const STORED_BINDING_SURFACE: &str = "stored-binding-surface";
const STORED_TENANT_PROVIDER_SURFACE: &str = "stored-tenant-provider-surface";
const STORED_METADATA_SURFACE: &str = "stored-metadata-surface";
const STORED_RESPONSE_METADATA_SURFACE: &str = "stored-response-metadata-surface";
const STORED_DANGLING_METADATA_SURFACE: &str = "stored-dangling-metadata-surface";
const STORED_DISABLED_METADATA_SURFACE: &str = "stored-disabled-metadata-surface";
const STORED_CREDENTIAL_LOOKUP_SURFACE: &str = "stored-credential-lookup-surface";
const STORED_TENANT_B_KEY_OWNER: &str = "stored-tenant-b-key-owner";
const STORED_LEGACY_SECRET_SURFACE: &str = "stored-legacy-secret-surface";
const STORED_TENANT_B_KEY: &str = "atgk_00000000000000000000000000000b11";
const STORED_KEY_OWNER_SURFACE: &str = "stored-key-owner-surface";
const STORED_APPLIANCE_KEY_SURFACE: &str = "stored-appliance-key-surface";
const STORED_APPLIANCE_KEY: &str = "atgk_00000000000000000000000000000a11";
const STORED_PROVIDER: &str = "stored-appliance-provider";
const STORED_TENANT_PROVIDER: &str = "stored-tenant-provider";
const STORED_TENANT_JWT_PROVIDER: &str = "stored-tenant-jwt-provider";
const STORED_TOKEN_ENDPOINT: &str = "https://192.0.2.1/token";
const TENANT_HOST: &str = "https://203.0.113.7/token";
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
        value: &str,
    ) -> String {
        let (status, body) = self
            .send(
                self.client
                    .post(self.url("secrets/new"))
                    .json(&json!({"name": secret_id, "secret_id": secret_id, "value": value, "tenant_id": tenant})),
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
            "access_point": {
                "listen_address": self.listener, "route": route, "protocol": "a2a",
                "caller_authentication": caller_authentication()
            },
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

    async fn update_provider(
        &self,
        id: &str,
        update: &Value,
    ) -> (u16, Value) {
        self.send(
            self.client
                .put(self.url(&format!("credential-providers/{id}")))
                .json(update),
        )
        .await
    }

    async fn stored_provider(
        &self,
        id: &str,
    ) -> Value {
        let (status, body) = self
            .send(
                self.client
                    .get(self.url(&format!("credential-providers/{id}"))),
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
    json!({"method": {"static_secret": {"secret_id": secret_id, "header_name": "X-Target-Key"}}})
}

fn api_key_caller_check() -> Value {
    json!({"type": "api_key", "secret_id": "caller-key", "extraction": {"source": "http_header", "field": "X-Caller-Key"}})
}

fn caller_authentication() -> Value {
    json!({"methods": [api_key_caller_check()]})
}

/// Makes the Target of a stored surface, its variant's, and the Transit Points at
/// `transit_points` meet the Target authentication rules a changed setting is held to: an
/// https Target and a leg that checks its callers.
fn meeting_target_auth_rules(
    surface: &mut Value,
    transit_points: &[usize],
) {
    surface["access_point"]["caller_authentication"] = caller_authentication();
    surface["target"]["endpoint"] = json!("https://127.0.0.1:9/");
    surface["variants"][0]["overrides"]["target"]["endpoint"] = json!("https://127.0.0.1:9/staging");
    for &index in transit_points {
        let point = &mut surface["transit"]["points"][index];
        point["target_endpoint"] = json!(format!(
            "https://127.0.0.1:9/{}",
            point["alias"]
                .as_str()
                .unwrap()
        ));
        point
            .as_object_mut()
            .unwrap()
            .remove("allow_unauthenticated_callers");
        point["source_auth"] = api_key_caller_check();
    }
}

fn secret_metadata(secret_id: &str) -> Value {
    json!({"enabled": true, "payload": {"outer": {"keys": [format!("$SECRET:{secret_id}")]}}})
}

fn disabled_secret_metadata(secret_id: &str) -> Value {
    json!({"enabled": false, "payload": {"k": format!("$SECRET:{secret_id}")}})
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

fn assert_provider_refused(result: (u16, Value)) {
    assert_eq!(result.0, 400, "{}", result.1);
    assert_eq!(result.1["error"], NOT_ACCESSIBLE_SECRET, "{}", result.1);
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
    let point = |alias: &str, extra: Value| {
        let mut point = json!({
            "id": format!("{alias}-id"), "alias": alias, "target_endpoint": format!("http://127.0.0.1:9/{alias}"),
            "protocol": "a2a", "require_transit_token": false, "allow_unauthenticated_callers": true
        });
        for (key, value) in extra.as_object().unwrap() {
            point[key] = value.clone();
        }
        point
    };
    let surface = |surface_id: &str, extra: Value| {
        let mut surface = json!({
            "surface_id": surface_id, "name": surface_id, "status": "disabled", "tenant_id": "tenant-a",
            "access_point": {
                "listen_address": format!("http://localhost:{port}"), "route": format!("/smoke/{surface_id}"),
                "protocol": "a2a"
            },
            "target": {"endpoint": "http://127.0.0.1:9/"},
            "transit": {"points": [point("partner", extra.get("partner").cloned().unwrap_or_else(|| json!({}))), point("peer", json!({}))]},
            "variants": [{
                "id": "staging-id", "alias": "staging", "name": "Staging",
                "overrides": {"target": {"endpoint": "http://127.0.0.1:9/staging"}}
            }]
        });
        for (key, value) in extra.as_object().unwrap() {
            if key != "partner" {
                surface[key] = value.clone();
            }
        }
        surface
    };
    let provider = json!({
        "id": STORED_PROVIDER, "name": STORED_PROVIDER, "provider_id": STORED_PROVIDER,
        "provider_type": "oauth2_client_credentials", "token_endpoint": "https://192.0.2.1/token",
        "client_id_secret_ref": "appliance-client-id", "client_secret_secret_ref": "appliance-client-secret",
        "created_at": now, "updated_at": now
    });
    let tenant_provider = json!({
        "id": STORED_TENANT_PROVIDER, "name": STORED_TENANT_PROVIDER, "provider_id": STORED_TENANT_PROVIDER,
        "tenant_id": "tenant-a", "provider_type": "oauth2_client_credentials",
        "token_endpoint": STORED_TOKEN_ENDPOINT, "default_scopes": ["read"],
        "client_id_secret_ref": "appliance-client-id", "client_secret_secret_ref": "appliance-client-secret",
        "created_at": now, "updated_at": now
    });
    let tenant_jwt_provider = json!({
        "id": STORED_TENANT_JWT_PROVIDER, "name": STORED_TENANT_JWT_PROVIDER,
        "provider_id": STORED_TENANT_JWT_PROVIDER, "tenant_id": "tenant-a", "provider_type": "oauth2_jwt_bearer",
        "token_endpoint": STORED_TOKEN_ENDPOINT, "jwt_signing_key_secret_ref": "appliance-signing-key",
        "jwt_signing_algorithm": "RS256", "jwt_issuer": "gateway@appliance.example",
        "jwt_subject": "admin@appliance.example", "jwt_audience": STORED_TOKEN_ENDPOINT,
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
                json!({
                    "target": {"endpoint": "http://127.0.0.1:9/", "auth": static_secret("appliance-key")},
                    "partner": {"target_auth": static_secret("appliance-key")}
                }),
            ),
        ),
        (
            &bootstrap
                .storage_paths
                .agent_surfaces,
            STORED_METADATA_SURFACE,
            surface(
                STORED_METADATA_SURFACE,
                json!({"target": {"endpoint": "http://127.0.0.1:9/", "custom_metadata": secret_metadata("appliance-key")}}),
            ),
        ),
        (
            &bootstrap
                .storage_paths
                .agent_surfaces,
            STORED_RESPONSE_METADATA_SURFACE,
            surface(
                STORED_RESPONSE_METADATA_SURFACE,
                json!({"target": {"endpoint": "http://127.0.0.1:9/", "response_custom_metadata": secret_metadata("appliance-key")}}),
            ),
        ),
        (
            &bootstrap
                .storage_paths
                .agent_surfaces,
            STORED_DANGLING_METADATA_SURFACE,
            surface(
                STORED_DANGLING_METADATA_SURFACE,
                json!({"target": {"endpoint": "http://127.0.0.1:9/", "custom_metadata": secret_metadata("no-such-secret")}}),
            ),
        ),
        (
            &bootstrap
                .storage_paths
                .agent_surfaces,
            STORED_DISABLED_METADATA_SURFACE,
            surface(
                STORED_DISABLED_METADATA_SURFACE,
                json!({"target": {"endpoint": "http://127.0.0.1:9/", "custom_metadata": disabled_secret_metadata("appliance-key")}}),
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
                .agent_surfaces,
            STORED_TENANT_PROVIDER_SURFACE,
            surface(STORED_TENANT_PROVIDER_SURFACE, json!({"outbound_credentials": binding(STORED_TENANT_PROVIDER)})),
        ),
        (
            &bootstrap
                .storage_paths
                .agent_surfaces,
            STORED_CREDENTIAL_LOOKUP_SURFACE,
            surface(
                STORED_CREDENTIAL_LOOKUP_SURFACE,
                json!({"tenant_id": null, "target": {"endpoint": "http://127.0.0.1:9/", "auth": {"method": "credential_lookup"}}}),
            ),
        ),
        (
            &bootstrap
                .storage_paths
                .agent_surfaces,
            STORED_KEY_OWNER_SURFACE,
            surface(STORED_KEY_OWNER_SURFACE, json!({"tenant_id": null})),
        ),
        (
            &bootstrap
                .storage_paths
                .agent_surfaces,
            STORED_TENANT_B_KEY_OWNER,
            surface(STORED_TENANT_B_KEY_OWNER, json!({"tenant_id": "tenant-b"})),
        ),
        (
            &bootstrap
                .storage_paths
                .agent_surfaces,
            STORED_LEGACY_SECRET_SURFACE,
            surface(
                STORED_LEGACY_SECRET_SURFACE,
                json!({
                    "identity_slots": {"inbound": {"type": "from_api_key"}},
                    "access_point": {
                        "listen_address": format!("http://localhost:{port}"),
                        "route": format!("/smoke/{STORED_LEGACY_SECRET_SURFACE}"), "protocol": "a2a",
                        "caller_authentication": legacy_caller(STORED_TENANT_B_KEY)
                    }
                }),
            ),
        ),
        (
            &bootstrap
                .storage_paths
                .agent_surfaces,
            STORED_APPLIANCE_KEY_SURFACE,
            surface(
                STORED_APPLIANCE_KEY_SURFACE,
                json!({"identity_slots": {"protected": from_api_key(STORED_APPLIANCE_KEY)}}),
            ),
        ),
        (
            &bootstrap
                .storage_paths
                .credential_providers,
            STORED_PROVIDER,
            provider,
        ),
        (
            &bootstrap
                .storage_paths
                .credential_providers,
            STORED_TENANT_PROVIDER,
            tenant_provider,
        ),
        (
            &bootstrap
                .storage_paths
                .credential_providers,
            STORED_TENANT_JWT_PROVIDER,
            tenant_jwt_provider,
        ),
    ] {
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(
            std::path::Path::new(directory).join(format!("{id}.json")),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
    }
    seed_api_key(bootstrap, STORED_KEY_OWNER_SURFACE, STORED_APPLIANCE_KEY);
    seed_api_key(bootstrap, STORED_TENANT_B_KEY_OWNER, STORED_TENANT_B_KEY);
    super::helpers::write_api_key_secret(
        &bootstrap
            .storage_paths
            .secrets,
        STORED_TENANT_B_KEY,
        "legacy-secret-value",
    );
}

fn api_keys_dir(bootstrap: &crate::config::BootstrapConfig) -> std::path::PathBuf {
    std::path::Path::new(
        &bootstrap
            .storage_paths
            .secrets,
    )
    .parent()
    .unwrap()
    .join("api_keys")
}

fn seed_api_key(
    bootstrap: &crate::config::BootstrapConfig,
    owner: &str,
    key_id: &str,
) {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            use crate::api_keys::store::ApiKeyStore as _;
            crate::api_keys::FileSystemApiKeyStore::new(&api_keys_dir(bootstrap).to_string_lossy())
                .await
                .unwrap()
                .create_with_material(
                    owner,
                    key_id.to_string(),
                    format!("atgs_{key_id}"),
                    "client",
                    None,
                    "component-test",
                )
                .await
                .unwrap();
        })
    });
}

fn write_stored_surface(
    bootstrap: &crate::config::BootstrapConfig,
    surface_id: &str,
    extra: Value,
) {
    let gateway: Value = serde_json::from_slice(&std::fs::read(&bootstrap.config_files.gateway).unwrap()).unwrap();
    let port = gateway["listeners"][0]["port"]
        .as_u64()
        .unwrap();
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
    let directory = std::path::Path::new(
        &bootstrap
            .storage_paths
            .agent_surfaces,
    );
    std::fs::create_dir_all(directory).unwrap();
    std::fs::write(directory.join(format!("{surface_id}.json")), serde_json::to_vec(&surface).unwrap()).unwrap();
}

async fn harness(isolation: RuleMode) -> (GatewayHarness, Api) {
    harness_seeded(isolation, |_| {}).await
}

async fn harness_seeded(
    isolation: RuleMode,
    seed: impl FnOnce(&crate::config::BootstrapConfig),
) -> (GatewayHarness, Api) {
    let mut client = None;
    let harness = GatewayHarness::start(|_, _, bootstrap| {
        bootstrap.credential_policy = CredentialPolicyConfig {
            tenant_credential_isolation: isolation,
            ..Default::default()
        };
        seed_stored_credentials(bootstrap);
        seed(bootstrap);
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
        target: "https://127.0.0.1:9/".to_string(),
    };
    let signing_key = crate::delegation_vault::jwt_assertion::test_keys::rsa_pkcs8().private_pem;
    for (secret_id, tenant, value) in [
        ("appliance-key", None, "v"),
        ("caller-key", None, "v"),
        ("appliance-client-id", None, "v"),
        ("appliance-client-secret", None, "v"),
        ("appliance-signing-key", None, signing_key.as_str()),
        ("tenant-key", Some("tenant-a"), "v"),
        ("other-tenant-key", Some("tenant-b"), "v"),
        ("tenant-client-id", Some("tenant-a"), "v"),
        ("tenant-client-secret", Some("tenant-a"), "v"),
    ] {
        let uuid = api
            .secret(secret_id, tenant, value)
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

async fn assert_a_redirected_leg_is_refused(
    api: &Api,
    surface_id: &str,
    details: &str,
) {
    let redirects: [fn(&mut Value, &str); 3] = [
        |surface, endpoint| surface["target"]["endpoint"] = json!(endpoint),
        |surface, endpoint| surface["transit"]["points"][0]["target_endpoint"] = json!(endpoint),
        |surface, endpoint| surface["variants"][0]["overrides"]["target"]["endpoint"] = json!(endpoint),
    ];
    for redirect in redirects {
        let mut redirected = api.stored(surface_id).await;
        redirect(&mut redirected, &api.target);
        assert_refused(
            api.put(surface_id, &redirected)
                .await,
            details,
        );
    }
    assert_refused(
        api.patch(surface_id, &json!({"target": {"endpoint": api.target}}))
            .await,
        details,
    );
    let stored = api.stored(surface_id).await;
    assert_eq!(
        stored["target"]["endpoint"], "http://127.0.0.1:9/",
        "a refused save leaves the stored surface as it was"
    );
    assert_eq!(stored["transit"]["points"][0]["target_endpoint"], "http://127.0.0.1:9/partner");
    assert_eq!(stored["variants"][0]["overrides"]["target"]["endpoint"], "http://127.0.0.1:9/staging");
}

async fn assert_renamed_and_reordered_legs_are_kept(
    api: &Api,
    surface_id: &str,
) {
    let mut renamed = api.stored(surface_id).await;
    renamed["description"] = json!("renamed legs");
    renamed["transit"]["points"][0]["alias"] = json!("partner-renamed");
    renamed["transit"]["points"][0]["name"] = json!("Partner renamed");
    renamed["variants"][0]["alias"] = json!("staging-renamed");
    renamed["variants"][0]["name"] = json!("Staging renamed");
    renamed["transit"]["points"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert_saved(
        api.put(surface_id, &renamed)
            .await,
    );
    let stored = api.stored(surface_id).await;
    assert_eq!(stored["description"], "renamed legs", "{stored}");
    assert_eq!(stored["transit"]["points"][1]["alias"], "partner-renamed", "{stored}");
    assert_eq!(stored["variants"][0]["alias"], "staging-renamed", "{stored}");
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

    assert_a_redirected_leg_is_refused(&api, STORED_SECRET_SURFACE, NOT_ACCESSIBLE_SECRET).await;
    assert_a_redirected_leg_is_refused(&api, STORED_BINDING_SURFACE, NOT_ACCESSIBLE_PROVIDER).await;

    let mut moved_leg = api
        .stored(STORED_SECRET_SURFACE)
        .await;
    moved_leg["transit"]["points"][1]["target_auth"] = moved_leg["transit"]["points"][0]["target_auth"].take();
    assert_refused(
        api.put(STORED_SECRET_SURFACE, &moved_leg)
            .await,
        NOT_ACCESSIBLE_SECRET,
    );
    let mut new_leg = api
        .stored(STORED_BINDING_SURFACE)
        .await;
    new_leg["transit"]["points"][0]["id"] = json!("partner-replacement-id");
    assert_refused(
        api.put(STORED_BINDING_SURFACE, &new_leg)
            .await,
        NOT_ACCESSIBLE_PROVIDER,
    );

    assert_renamed_and_reordered_legs_are_kept(&api, STORED_SECRET_SURFACE).await;
    assert_renamed_and_reordered_legs_are_kept(&api, STORED_BINDING_SURFACE).await;

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
    meeting_target_auth_rules(&mut moved, &[]);
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

    let mut target_fixed = api
        .stored(STORED_SECRET_SURFACE)
        .await;
    target_fixed["target"]["auth"] = static_secret("tenant-key");
    assert_refused(
        api.put(STORED_SECRET_SURFACE, &target_fixed)
            .await,
        NOT_ACCESSIBLE_SECRET,
    );
    let mut fixed = target_fixed;
    fixed["transit"]["points"][0]["target_auth"] = static_secret("tenant-key");
    meeting_target_auth_rules(&mut fixed, &[0]);
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

#[tokio::test(flavor = "multi_thread")]
async fn a_reassignment_that_would_give_a_tenant_a2a_proxy_an_appliance_wide_secret_is_a_conflict() {
    let (_harness, api) = harness(RuleMode::Warn).await;
    let proxy_key = api
        .secret("proxy-key", Some("tenant-a"), "v")
        .await;
    let proxy = |secret_id: &str, tenant: Option<&str>| {
        json!({
            "name": secret_id, "tenant_id": tenant,
            "backend": {"kind": "copilot_direct_line", "secret_id": secret_id, "base_url": "https://203.0.113.7/v3/directline"}
        })
    };
    let mut ids = Vec::new();
    for body in [proxy("appliance-key", None), proxy("proxy-key", Some("tenant-a"))] {
        let (status, created) = api
            .send(
                api.client
                    .post(api.url("a2a-proxies"))
                    .json(&body),
            )
            .await;
        assert!(matches!(status, 200 | 201), "{status} {created}");
        ids.push(
            created["id"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }
    let blocked = |result: (u16, Value)| {
        assert_eq!(result.0, 409, "{}", result.1);
        assert!(
            result.1["conflicts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|conflict| conflict["context"] == "A2A proxy secret"
                    && conflict["reason"]
                        == "The proposed tenant would give a tenant resource an appliance-wide credential"),
            "{}",
            result.1
        );
    };

    blocked(
        api.reassign("a2a-proxies", &ids[0], Some("tenant-a"))
            .await,
    );
    blocked(
        api.reassign("secrets", &proxy_key, None)
            .await,
    );
    let (status, body) = api
        .reassign("a2a-proxies", &ids[1], Some("tenant-a"))
        .await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_appliance_wide_credential_on_a_tenant_provider_is_kept_only_while_its_destination_is_unchanged() {
    let (_harness, api) = harness(RuleMode::Warn).await;

    for change in [
        json!({"token_endpoint": TENANT_HOST}),
        json!({"authorization_endpoint": "https://203.0.113.7/authorize"}),
        json!({"resource": "https://203.0.113.7/api"}),
        json!({"additional_params": {"audience": "https://203.0.113.7/"}}),
        json!({"provider_type": "oauth2_authorization_code"}),
        json!({"client_id_secret_ref": "appliance-client-secret", "client_secret_secret_ref": "appliance-client-id"}),
    ] {
        assert_provider_refused(
            api.update_provider(STORED_TENANT_PROVIDER, &change)
                .await,
        );
    }
    let mut redirected = api
        .stored_provider(STORED_TENANT_PROVIDER)
        .await;
    redirected["token_endpoint"] = json!(TENANT_HOST);
    assert_provider_refused(
        api.update_provider(STORED_TENANT_PROVIDER, &redirected)
            .await,
    );
    let stored = api
        .stored_provider(STORED_TENANT_PROVIDER)
        .await;
    assert_eq!(stored["token_endpoint"], STORED_TOKEN_ENDPOINT, "a refused save leaves the provider as it was");
    assert_eq!(stored["client_secret_secret_ref"], "appliance-client-secret");

    let mut rescoped = stored.clone();
    rescoped["default_scopes"] = json!(["read", "write"]);
    assert_provider_refused(
        api.update_provider(STORED_TENANT_PROVIDER, &rescoped)
            .await,
    );
    let mut renamed = stored.clone();
    renamed["name"] = json!("Renamed");
    let (status, body) = api
        .update_provider(STORED_TENANT_PROVIDER, &renamed)
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["name"], "Renamed");
    assert_eq!(body["default_scopes"], json!(["read"]));
    assert_eq!(body["token_endpoint"], STORED_TOKEN_ENDPOINT);
    assert_eq!(body["client_secret_secret_ref"], "appliance-client-secret");

    let (status, body) = api
        .update_provider(
            STORED_TENANT_PROVIDER,
            &json!({
                "token_endpoint": TENANT_HOST,
                "client_id_secret_ref": "tenant-client-id", "client_secret_secret_ref": "tenant-client-secret"
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["token_endpoint"], TENANT_HOST);

    for change in [
        json!({"token_endpoint": TENANT_HOST}),
        json!({"jwt_issuer": "tenant@tenant-a.example"}),
        json!({"jwt_subject": "someone@appliance.example"}),
        json!({"jwt_audience": TENANT_HOST}),
    ] {
        assert_provider_refused(
            api.update_provider(STORED_TENANT_JWT_PROVIDER, &change)
                .await,
        );
    }
    let (status, body) = api
        .update_provider(STORED_TENANT_JWT_PROVIDER, &json!({"name": "Renamed", "jwt_key_id": "key-1"}))
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["name"], "Renamed");
    assert_eq!(body["jwt_issuer"], "gateway@appliance.example");
    assert_eq!(body["jwt_signing_key_secret_ref"], "appliance-signing-key");

    let (status, body) = api
        .send(
            api.client
                .post(api.url("credential-providers/validate"))
                .json(&json!({
                    "tenant_id": "tenant-a", "provider_type": "oauth2_jwt_bearer", "jwt_subject": "admin@tenant-a.example",
                    "token_endpoint": STORED_TOKEN_ENDPOINT, "jwt_signing_key_secret_ref": "appliance-signing-key"
                })),
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], NOT_ACCESSIBLE_SECRET, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_appliance_wide_credential_on_a_tenant_provider_is_refused_when_enforced() {
    let (_harness, api) = harness(RuleMode::Enforce).await;
    for provider in [STORED_TENANT_PROVIDER, STORED_TENANT_JWT_PROVIDER] {
        assert_provider_refused(
            api.update_provider(provider, &json!({"name": "Renamed"}))
                .await,
        );
        assert_eq!(
            api.stored_provider(provider)
                .await["name"],
            provider
        );
    }
    let (status, body) = api
        .update_provider(
            STORED_TENANT_PROVIDER,
            &json!({"client_id_secret_ref": "tenant-client-id", "client_secret_secret_ref": "tenant-client-secret"}),
        )
        .await;
    assert_eq!(status, 200, "{body}");
}

fn provider_auth(provider_id: &str) -> Value {
    json!({"method": {"credential_provider": {"provider_id": provider_id, "header_name": "X-Target-Token"}}})
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tenant_provider_holding_an_appliance_wide_secret_is_kept_only_on_its_stored_legs_in_warn_mode() {
    let (_harness, api) = harness(RuleMode::Warn).await;
    let providers = providers(&api).await;

    let unchanged = api
        .stored(STORED_TENANT_PROVIDER_SURFACE)
        .await;
    assert_saved(
        api.put(STORED_TENANT_PROVIDER_SURFACE, &unchanged)
            .await,
    );
    assert_a_redirected_leg_is_refused(&api, STORED_TENANT_PROVIDER_SURFACE, NOT_ACCESSIBLE_PROVIDER).await;
    let mut new_leg = api
        .stored(STORED_TENANT_PROVIDER_SURFACE)
        .await;
    new_leg["transit"]["points"][0]["id"] = json!("partner-replacement-id");
    assert_refused(
        api.put(STORED_TENANT_PROVIDER_SURFACE, &new_leg)
            .await,
        NOT_ACCESSIBLE_PROVIDER,
    );
    let mut new_target_auth = api
        .stored(STORED_TENANT_PROVIDER_SURFACE)
        .await;
    new_target_auth["target"]["auth"] = provider_auth(STORED_TENANT_PROVIDER);
    assert_saved(
        api.put(STORED_TENANT_PROVIDER_SURFACE, &new_target_auth)
            .await,
    );
    let mut new_transit_binding = api
        .stored(STORED_TENANT_PROVIDER_SURFACE)
        .await;
    new_transit_binding["transit"]["points"][0]["transit_credentials"] =
        json!({"credential_provider_id": STORED_TENANT_PROVIDER});
    assert_saved(
        api.put(STORED_TENANT_PROVIDER_SURFACE, &new_transit_binding)
            .await,
    );
    assert_renamed_and_reordered_legs_are_kept(&api, STORED_TENANT_PROVIDER_SURFACE).await;

    for extra in [
        json!({"outbound_credentials": binding(STORED_TENANT_PROVIDER)}),
        json!({"target_auth": provider_auth(STORED_TENANT_PROVIDER)}),
    ] {
        assert_refused(
            api.create(&api.surface("/smoke/new-tenant-provider-leg", Some("tenant-a"), extra))
                .await,
            NOT_ACCESSIBLE_PROVIDER,
        );
    }
    assert_saved(
        api.create(&api.surface(
            "/smoke/own-secrets-provider-binding",
            Some("tenant-a"),
            json!({"outbound_credentials": binding(&providers.tenant_client_credentials)}),
        ))
        .await,
    );
    assert_saved(
        api.create(&api.surface(
            "/smoke/own-secrets-provider-target-auth",
            Some("tenant-a"),
            json!({"target_auth": provider_auth(&providers.tenant_client_credentials)}),
        ))
        .await,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tenant_provider_holding_an_appliance_wide_secret_is_refused_on_a_stored_surface_when_enforced() {
    let (_harness, api) = harness(RuleMode::Enforce).await;
    let unchanged = api
        .stored(STORED_TENANT_PROVIDER_SURFACE)
        .await;
    assert_refused(
        api.put(STORED_TENANT_PROVIDER_SURFACE, &unchanged)
            .await,
        NOT_ACCESSIBLE_PROVIDER,
    );
    assert_refused(
        api.create(&api.surface(
            "/smoke/new-tenant-provider-leg",
            Some("tenant-a"),
            json!({"outbound_credentials": binding(STORED_TENANT_PROVIDER)}),
        ))
        .await,
        NOT_ACCESSIBLE_PROVIDER,
    );
}

const METADATA_PLACES: [fn(&mut Value, Value); 4] = [
    |surface, metadata| surface["target"]["custom_metadata"] = metadata,
    |surface, metadata| surface["target"]["response_custom_metadata"] = metadata,
    |surface, metadata| surface["access_point"]["response_custom_metadata"] = metadata,
    |surface, metadata| {
        surface["transit"] = json!({"custom_metadata": metadata, "points": [{
            "id": "partner-id", "alias": "partner", "target_endpoint": "http://127.0.0.1:9/partner",
            "protocol": "a2a", "require_transit_token": false, "allow_unauthenticated_callers": true
        }]})
    },
];

fn with_metadata(
    api: &Api,
    route: &str,
    tenant: Option<&str>,
    place: fn(&mut Value, Value),
    secret_id: &str,
) -> Value {
    let mut surface = api.surface(route, tenant, json!({}));
    place(&mut surface, secret_metadata(secret_id));
    surface
}

async fn assert_new_metadata_secrets_follow_the_tenant(api: &Api) {
    for (index, place) in METADATA_PLACES
        .into_iter()
        .enumerate()
    {
        for refused in ["other-tenant-key", "appliance-key", "no-such-secret"] {
            assert_refused(
                api.create(&with_metadata(
                    api,
                    &format!("/smoke/metadata-{refused}-{index}"),
                    Some("tenant-a"),
                    place,
                    refused,
                ))
                .await,
                NOT_ACCESSIBLE_SECRET,
            );
        }
        for saved in ["tenant-key"] {
            assert_saved(
                api.create(&with_metadata(
                    api,
                    &format!("/smoke/metadata-{saved}-{index}"),
                    Some("tenant-a"),
                    place,
                    saved,
                ))
                .await,
            );
        }
    }
    for saved in ["appliance-key", "tenant-key", "other-tenant-key", "no-such-secret"] {
        assert_saved(
            api.create(&with_metadata(
                api,
                &format!("/smoke/metadata-appliance-surface-{saved}"),
                None,
                METADATA_PLACES[0],
                saved,
            ))
            .await,
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_custom_metadata_secret_follows_the_tenant_and_a_stored_appliance_wide_one_is_kept_in_warn_mode() {
    let (_harness, api) = harness(RuleMode::Warn).await;
    assert_new_metadata_secrets_follow_the_tenant(&api).await;

    let unchanged = api
        .stored(STORED_METADATA_SURFACE)
        .await;
    assert_saved(
        api.put(STORED_METADATA_SURFACE, &unchanged)
            .await,
    );
    let mut redirected = unchanged.clone();
    redirected["target"]["endpoint"] = json!(api.target);
    assert_refused(
        api.put(STORED_METADATA_SURFACE, &redirected)
            .await,
        NOT_ACCESSIBLE_SECRET,
    );
    let mut moved = unchanged;
    moved["target"]["response_custom_metadata"] = moved["target"]["custom_metadata"].take();
    assert_refused(
        api.put(STORED_METADATA_SURFACE, &moved)
            .await,
        NOT_ACCESSIBLE_SECRET,
    );

    let mut authentication_to_caller = api
        .stored(STORED_SECRET_SURFACE)
        .await;
    authentication_to_caller["target"]["response_custom_metadata"] = secret_metadata("appliance-key");
    assert_refused(
        api.put(STORED_SECRET_SURFACE, &authentication_to_caller)
            .await,
        NOT_ACCESSIBLE_SECRET,
    );
    assert_eq!(
        api.stored(STORED_SECRET_SURFACE)
            .await["target"]["response_custom_metadata"],
        Value::Null,
        "a refused save leaves the surface as it was"
    );

    let mut described = api
        .stored(STORED_RESPONSE_METADATA_SURFACE)
        .await;
    described["description"] = json!("an unrelated edit");
    assert_saved(
        api.put(STORED_RESPONSE_METADATA_SURFACE, &described)
            .await,
    );
    assert_eq!(
        api.stored(STORED_RESPONSE_METADATA_SURFACE)
            .await["target"]["response_custom_metadata"],
        secret_metadata("appliance-key"),
        "a stored response metadata secret is kept on its own destination"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_appliance_wide_custom_metadata_secret_is_refused_when_enforced() {
    let (_harness, api) = harness(RuleMode::Enforce).await;
    assert_new_metadata_secrets_follow_the_tenant(&api).await;

    let unchanged = api
        .stored(STORED_METADATA_SURFACE)
        .await;
    assert_refused(
        api.put(STORED_METADATA_SURFACE, &unchanged)
            .await,
        NOT_ACCESSIBLE_SECRET,
    );
    let mut fixed = unchanged;
    fixed["target"]["custom_metadata"] = secret_metadata("tenant-key");
    assert_saved(
        api.put(STORED_METADATA_SURFACE, &fixed)
            .await,
    );

    let mut described = api
        .stored(STORED_RESPONSE_METADATA_SURFACE)
        .await;
    described["description"] = json!("an unrelated edit");
    assert_refused(
        api.put(STORED_RESPONSE_METADATA_SURFACE, &described)
            .await,
        NOT_ACCESSIBLE_SECRET,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reassignment_that_would_give_a_tenant_surface_an_appliance_wide_custom_metadata_secret_is_a_conflict() {
    let (_harness, api) = harness(RuleMode::Warn).await;
    let appliance_metadata_surface = api
        .created_id(&with_metadata(&api, "/smoke/wide-metadata", None, METADATA_PLACES[3], "appliance-key"))
        .await;
    let missing_metadata_surface = api
        .created_id(&with_metadata(&api, "/smoke/missing-metadata", None, METADATA_PLACES[0], "no-such-secret"))
        .await;

    let (status, body) = api
        .reassign("surfaces", &appliance_metadata_surface, Some("tenant-a"))
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"], "tenant_reassignment_blocked", "{body}");
    assert_eq!(
        body["conflicts"][0]["reason"], "The proposed tenant would give a tenant resource an appliance-wide credential",
        "{body}"
    );
    assert_eq!(
        api.stored(&appliance_metadata_surface)
            .await["tenant_id"],
        Value::Null,
        "a blocked reassignment changes nothing"
    );

    let (status, body) = api
        .reassign("surfaces", &missing_metadata_surface, Some("tenant-a"))
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["conflicts"][0]["reason"], "Referenced resource does not exist", "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_surface_with_no_tenant_names_any_metadata_secret_until_it_is_given_a_tenant() {
    let (_harness, api) = harness(RuleMode::Enforce).await;
    let surface = api
        .created_id(&with_metadata(&api, "/smoke/tenant-metadata", None, METADATA_PLACES[0], "tenant-key"))
        .await;

    let (status, body) = api
        .reassign("secrets", &api.secret_uuids["tenant-key"], Some("tenant-b"))
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["tenant_id"], "tenant-b", "{body}");

    let (status, body) = api
        .reassign("surfaces", &surface, Some("tenant-a"))
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["conflicts"][0]["reason"], "The proposed tenant would make this reference cross-tenant", "{body}");
    assert_eq!(api.stored(&surface).await["tenant_id"], Value::Null, "a blocked reassignment changes nothing");

    let (status, body) = api
        .reassign("surfaces", &surface, Some("tenant-b"))
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["tenant_id"], "tenant-b", "{body}");
}

async fn assert_a_stored_missing_metadata_secret_on_a_tenant_surface_is_refused(api: &Api) {
    let unchanged = api
        .stored(STORED_DANGLING_METADATA_SURFACE)
        .await;
    let mut described = unchanged.clone();
    described["description"] = json!("an unrelated edit");
    assert_refused(
        api.put(STORED_DANGLING_METADATA_SURFACE, &described)
            .await,
        NOT_ACCESSIBLE_SECRET,
    );
    assert_refused(
        api.put(STORED_DANGLING_METADATA_SURFACE, &unchanged)
            .await,
        NOT_ACCESSIBLE_SECRET,
    );

    let (status, body) = api
        .reassign("surfaces", STORED_DANGLING_METADATA_SURFACE, Some("tenant-b"))
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["conflicts"][0]["reason"], "Referenced resource does not exist", "{body}");
    let (status, body) = api
        .reassign("surfaces", STORED_DANGLING_METADATA_SURFACE, Some("tenant-a"))
        .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = api
        .reassign("surfaces", STORED_DANGLING_METADATA_SURFACE, None)
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["tenant_id"], Value::Null, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_missing_metadata_secret_on_a_tenant_surface_is_refused_in_warn_mode() {
    let (_harness, api) = harness(RuleMode::Warn).await;
    assert_a_stored_missing_metadata_secret_on_a_tenant_surface_is_refused(&api).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_missing_metadata_secret_on_a_tenant_surface_is_refused_in_enforce_mode() {
    let (_harness, api) = harness(RuleMode::Enforce).await;
    assert_a_stored_missing_metadata_secret_on_a_tenant_surface_is_refused(&api).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_appliance_wide_secret_in_disabled_metadata_is_kept_in_warn_mode_until_it_is_enabled() {
    let (_harness, api) = harness(RuleMode::Warn).await;
    let (status, body) = api
        .reassign("surfaces", STORED_DISABLED_METADATA_SURFACE, Some("tenant-b"))
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["tenant_id"], "tenant-b", "{body}");
    let unchanged = api
        .stored(STORED_DISABLED_METADATA_SURFACE)
        .await;
    assert_eq!(unchanged["tenant_id"], "tenant-b", "{unchanged}");
    assert_eq!(unchanged["target"]["custom_metadata"], disabled_secret_metadata("appliance-key"), "{unchanged}");

    let mut described = unchanged.clone();
    described["description"] = json!("an unrelated edit");
    assert_saved(
        api.put(STORED_DISABLED_METADATA_SURFACE, &described)
            .await,
    );
    let mut enabled = unchanged;
    enabled["target"]["custom_metadata"]["enabled"] = json!(true);
    assert_refused(
        api.put(STORED_DISABLED_METADATA_SURFACE, &enabled)
            .await,
        NOT_ACCESSIBLE_SECRET,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tenant_surface_cannot_claim_a_metadata_secret_before_it_is_created_appliance_wide() {
    let (_harness, api) = harness(RuleMode::Warn).await;
    let squatter = with_metadata(&api, "/smoke/squatter", Some("tenant-a"), METADATA_PLACES[0], "stripe-live");
    let refused_before = api.create(&squatter).await;
    assert_refused(refused_before.clone(), NOT_ACCESSIBLE_SECRET);
    assert_eq!(
        refused_before,
        api.create(&with_metadata(&api, "/smoke/squatter", Some("tenant-a"), METADATA_PLACES[0], "other-tenant-key"))
            .await,
        "a missing secret and another tenant's secret answer alike"
    );

    api.secret("stripe-live", None, "v")
        .await;
    assert_refused(api.create(&squatter).await, NOT_ACCESSIBLE_SECRET);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tenant_surface_cannot_keep_a_metadata_secret_its_tenant_deleted() {
    let (_harness, api) = harness(RuleMode::Warn).await;
    let uuid = api
        .secret("squatted-id", Some("tenant-a"), "v")
        .await;
    let squatter = with_metadata(&api, "/smoke/deleted-squatter", Some("tenant-a"), METADATA_PLACES[0], "squatted-id");
    let surface_id = api
        .created_id(&squatter)
        .await;
    let (status, body) = api
        .send(
            api.client
                .delete(api.url(&format!("secrets/{uuid}?force=true"))),
        )
        .await;
    assert_eq!(status, 204, "{body}");

    let stored = api.stored(&surface_id).await;
    assert_refused(
        api.put(&surface_id, &stored)
            .await,
        NOT_ACCESSIBLE_SECRET,
    );
    let mut described = stored;
    described["description"] = json!("an unrelated edit");
    assert_refused(
        api.put(&surface_id, &described)
            .await,
        NOT_ACCESSIBLE_SECRET,
    );
}

const NOT_ACCESSIBLE_KEY_OWNER: &str = "API-key parent Surface reference is not accessible";

fn another_surfaces_key(key_id: &str) -> String {
    format!("API key '{key_id}' belongs to another surface; a surface names only its own API keys")
}

fn revoked_key(key_id: &str) -> String {
    format!("API key '{key_id}' is revoked; name an active API key of this surface")
}

impl Api {
    async fn api_key(
        &self,
        surface_id: &str,
    ) -> String {
        let (status, body) = self
            .send(
                self.client
                    .post(self.url(&format!("api-keys/{surface_id}")))
                    .json(&json!({"client_id": "client"})),
            )
            .await;
        assert_eq!(status, 201, "{body}");
        body["key_id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn revoke_api_key(
        &self,
        surface_id: &str,
        key_id: &str,
    ) {
        let (status, body) = self
            .send(
                self.client
                    .post(self.url(&format!("api-keys/{surface_id}/{key_id}/revoke")))
                    .json(&json!({})),
            )
            .await;
        assert_eq!(status, 204, "{body}");
    }

    async fn assert_create_refused(
        &self,
        surface: &Value,
        details: &str,
    ) {
        assert_refused(self.create(surface).await, details);
        let (status, body) = self
            .send(
                self.client
                    .get(self.url("surfaces")),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        let route = &surface["access_point"]["route"];
        assert!(
            !body
                .as_array()
                .unwrap()
                .iter()
                .any(|stored| &stored["access_point"]["route"] == route),
            "a refused create stores nothing: {route}"
        );
    }

    /// PUTs the stored surface `surface_id` with the top-level fields of `extra` replaced.
    async fn put_with(
        &self,
        surface_id: &str,
        extra: Value,
    ) -> (u16, Value) {
        let mut surface = self.stored(surface_id).await;
        for (key, value) in extra.as_object().unwrap() {
            surface[key] = value.clone();
        }
        self.put(surface_id, &surface)
            .await
    }

    async fn assert_put_refused(
        &self,
        surface_id: &str,
        surface: &Value,
        details: &str,
    ) {
        let before = self.stored(surface_id).await;
        assert_refused(
            self.put(surface_id, surface)
                .await,
            details,
        );
        assert_eq!(self.stored(surface_id).await, before, "a refused save stores nothing");
    }

    async fn assert_patch_refused(
        &self,
        surface_id: &str,
        patch: &Value,
        details: &str,
    ) {
        let before = self.stored(surface_id).await;
        assert_refused(
            self.patch(surface_id, patch)
                .await,
            details,
        );
        assert_eq!(self.stored(surface_id).await, before, "a refused patch stores nothing");
    }
}

fn legacy_caller(secret_id: &str) -> Value {
    json!({"methods": [{
        "type": "api_key", "extraction": {"source": "http_header", "field": "X-API-Key"}, "secret_id": secret_id
    }]})
}

fn from_api_key(key_id: &str) -> Value {
    json!({"type": "from_api_key", "api_key_id": key_id})
}

fn transit_point_identity(key_id: &str) -> Value {
    json!({"points": [{
        "id": "partner-id", "alias": "partner", "target_endpoint": "http://127.0.0.1:9/partner",
        "protocol": "a2a", "require_transit_token": false, "allow_unauthenticated_callers": true,
        "managed_identity": from_api_key(key_id)
    }]})
}

struct OwnedKeys {
    tenant_a: String,
    tenant_a_owner: String,
    tenant_b: String,
    appliance: String,
    appliance_owner: String,
}

async fn owned_keys(api: &Api) -> OwnedKeys {
    let mut owned = Vec::new();
    for (route, tenant) in
        [("/smoke/keys-a", Some("tenant-a")), ("/smoke/keys-b", Some("tenant-b")), ("/smoke/keys-wide", None)]
    {
        let owner = api
            .created_id(&api.surface(route, tenant, json!({})))
            .await;
        let key = api.api_key(&owner).await;
        owned.push((owner, key));
    }
    let [(tenant_a_owner, tenant_a), (_, tenant_b), (appliance_owner, appliance)] = owned.try_into().unwrap();
    OwnedKeys {
        tenant_a,
        tenant_a_owner,
        tenant_b,
        appliance,
        appliance_owner,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_surface_names_only_its_own_provider_keys() {
    let (_harness, api) = harness(RuleMode::Warn).await;
    let keys = owned_keys(&api).await;
    let with_slot = |route: &str, tenant: Option<&str>, slot: &str, key_id: &str| {
        api.surface(route, tenant, json!({"identity_slots": {slot: from_api_key(key_id)}}))
    };

    for slot in ["protected", "external"] {
        api.assert_create_refused(
            &with_slot(&format!("/smoke/{slot}-cross"), Some("tenant-a"), slot, &keys.tenant_b),
            NOT_ACCESSIBLE_KEY_OWNER,
        )
        .await;
        api.assert_create_refused(
            &with_slot(&format!("/smoke/{slot}-wide"), None, slot, &keys.tenant_a),
            NOT_ACCESSIBLE_KEY_OWNER,
        )
        .await;
        api.assert_create_refused(
            &with_slot(&format!("/smoke/{slot}-same-tenant"), Some("tenant-a"), slot, &keys.tenant_a),
            &another_surfaces_key(&keys.tenant_a),
        )
        .await;
        api.assert_create_refused(
            &with_slot(&format!("/smoke/{slot}-appliance"), Some("tenant-a"), slot, &keys.appliance),
            NOT_ACCESSIBLE_KEY_OWNER,
        )
        .await;
        api.assert_create_refused(
            &with_slot(&format!("/smoke/{slot}-appliance-wide"), None, slot, &keys.appliance),
            &another_surfaces_key(&keys.appliance),
        )
        .await;
        for (owner, key) in [(&keys.tenant_a_owner, &keys.tenant_a), (&keys.appliance_owner, &keys.appliance)] {
            assert_saved(
                api.put_with(owner, json!({"identity_slots": {slot: from_api_key(key)}}))
                    .await,
            );
            assert_eq!(api.stored(owner).await["identity_slots"][slot]["api_key_id"], json!(key));
        }
    }
    let same_tenant_plain = api
        .created_id(&api.surface("/smoke/same-tenant-plain", Some("tenant-a"), json!({})))
        .await;
    let mut named = api
        .stored(&same_tenant_plain)
        .await;
    named["identity_slots"] = json!({"protected": from_api_key(&keys.tenant_a)});
    api.assert_put_refused(&same_tenant_plain, &named, &another_surfaces_key(&keys.tenant_a))
        .await;
    let mut named = api
        .stored(&same_tenant_plain)
        .await;
    named["identity_slots"] = json!({"protected": from_api_key(&keys.tenant_b)});
    api.assert_put_refused(&same_tenant_plain, &named, NOT_ACCESSIBLE_KEY_OWNER)
        .await;
    api.assert_create_refused(
        &api.surface(
            "/smoke/point-cross",
            Some("tenant-a"),
            json!({"transit": transit_point_identity(&keys.tenant_b)}),
        ),
        NOT_ACCESSIBLE_KEY_OWNER,
    )
    .await;
    api.assert_create_refused(
        &api.surface(
            "/smoke/point-same-tenant",
            Some("tenant-a"),
            json!({"transit": transit_point_identity(&keys.tenant_a)}),
        ),
        &another_surfaces_key(&keys.tenant_a),
    )
    .await;
    assert_saved(
        api.put_with(&keys.tenant_a_owner, json!({"transit": transit_point_identity(&keys.tenant_a)}))
            .await,
    );
    api.assert_create_refused(
        &with_slot("/smoke/missing-key", Some("tenant-a"), "protected", "atgk_00000000000000000000000000000000"),
        "API key reference is not accessible",
    )
    .await;
}

async fn assert_a_new_appliance_key_on_a_tenant_surface_is_refused(api: &Api) {
    let protected = json!({"identity_slots": {"protected": from_api_key(STORED_APPLIANCE_KEY)}});
    api.assert_create_refused(
        &api.surface("/smoke/new-appliance-key", Some("tenant-a"), protected.clone()),
        NOT_ACCESSIBLE_KEY_OWNER,
    )
    .await;
    let plain = api
        .created_id(&api.surface("/smoke/plain-tenant-surface", Some("tenant-a"), json!({})))
        .await;
    let mut added = api.stored(&plain).await;
    added["identity_slots"] = protected["identity_slots"].clone();
    api.assert_put_refused(&plain, &added, NOT_ACCESSIBLE_KEY_OWNER)
        .await;
    api.assert_create_refused(
        &api.surface("/smoke/new-appliance-key-wide", None, protected),
        &another_surfaces_key(STORED_APPLIANCE_KEY),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_appliance_key_on_a_tenant_surface_is_kept_and_a_new_one_refused_in_warn_mode() {
    let (_harness, api) = harness(RuleMode::Warn).await;
    let stored = api
        .stored(STORED_APPLIANCE_KEY_SURFACE)
        .await;

    assert_saved(
        api.put(STORED_APPLIANCE_KEY_SURFACE, &stored)
            .await,
    );
    assert_eq!(
        api.stored(STORED_APPLIANCE_KEY_SURFACE)
            .await["identity_slots"]["protected"]["api_key_id"],
        STORED_APPLIANCE_KEY
    );
    assert_a_new_appliance_key_on_a_tenant_surface_is_refused(&api).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_appliance_key_on_a_tenant_surface_is_refused_when_enforced() {
    let (_harness, api) = harness(RuleMode::Enforce).await;
    let stored = api
        .stored(STORED_APPLIANCE_KEY_SURFACE)
        .await;

    api.assert_put_refused(STORED_APPLIANCE_KEY_SURFACE, &stored, NOT_ACCESSIBLE_KEY_OWNER)
        .await;
    assert_a_new_appliance_key_on_a_tenant_surface_is_refused(&api).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn giving_a_tenant_to_a_surface_whose_configuration_cannot_be_saved_is_refused() {
    let (_harness, api) = harness(RuleMode::Warn).await;

    let (status, body) = api
        .reassign("surfaces", STORED_CREDENTIAL_LOOKUP_SURFACE, Some("tenant-a"))
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(
        body,
        json!({"error": "Target authentication method credential_lookup is not supported; use static_secret or credential_provider"})
    );
    assert_eq!(
        api.stored(STORED_CREDENTIAL_LOOKUP_SURFACE)
            .await["tenant_id"],
        Value::Null,
        "a refused reassignment changes nothing"
    );
}

const STORED_WIDE_APPLIANCE_KEY_USER: &str = "stored-wide-appliance-key-user";

async fn assert_giving_a_tenant_to_a_surface_naming_an_appliance_key_is_a_conflict(mode: RuleMode) {
    let (_harness, api) = harness_seeded(mode, |bootstrap| {
        write_stored_surface(
            bootstrap,
            STORED_WIDE_APPLIANCE_KEY_USER,
            json!({"tenant_id": null, "identity_slots": {"protected": from_api_key(STORED_APPLIANCE_KEY)}}),
        );
    })
    .await;
    let surface = STORED_WIDE_APPLIANCE_KEY_USER.to_string();

    let (status, body) = api
        .reassign("surfaces", &surface, Some("tenant-a"))
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"], "tenant_reassignment_blocked", "{body}");
    assert_eq!(
        body["conflicts"][0]["reason"], "The proposed tenant would give a tenant resource an appliance-wide credential",
        "{body}"
    );
    assert_eq!(api.stored(&surface).await["tenant_id"], Value::Null, "a blocked reassignment changes nothing");
}

#[tokio::test(flavor = "multi_thread")]
async fn giving_a_tenant_to_a_surface_naming_an_appliance_key_is_a_conflict_in_warn_mode() {
    assert_giving_a_tenant_to_a_surface_naming_an_appliance_key_is_a_conflict(RuleMode::Warn).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn giving_a_tenant_to_a_surface_naming_an_appliance_key_is_a_conflict_when_enforced() {
    assert_giving_a_tenant_to_a_surface_naming_an_appliance_key_is_a_conflict(RuleMode::Enforce).await;
}

const NAMED_KEY_OWNER: &str = "named-key-owner";
const NAMED_KEY_USER: &str = "named-key-user";
const NAMED_KEY: &str = "atgk_00000000000000000000000000000f01";

/// A store holding a tenant `a` surface that owns [`NAMED_KEY`] and one stored naming it, as a
/// surface saved before a surface named only its own keys can be.
fn seed_named_key(bootstrap: &crate::config::BootstrapConfig) {
    write_stored_surface(bootstrap, NAMED_KEY_OWNER, json!({}));
    seed_api_key(bootstrap, NAMED_KEY_OWNER, NAMED_KEY);
    write_stored_surface(bootstrap, NAMED_KEY_USER, json!({"identity_slots": {"protected": from_api_key(NAMED_KEY)}}));
}

async fn assert_moving_a_named_keys_owner_out_of_its_tenant_is_a_conflict(mode: RuleMode) {
    let (_harness, api) = harness_seeded(mode, seed_named_key).await;

    let (status, body) = api
        .reassign("surfaces", NAMED_KEY_OWNER, None)
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"], "tenant_reassignment_blocked", "{body}");
    assert_eq!(
        api.stored(NAMED_KEY_OWNER)
            .await["tenant_id"],
        "tenant-a",
        "a blocked reassignment changes nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn moving_a_named_keys_owner_out_of_its_tenant_is_a_conflict_in_warn_mode() {
    assert_moving_a_named_keys_owner_out_of_its_tenant_is_a_conflict(RuleMode::Warn).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn moving_a_named_keys_owner_out_of_its_tenant_is_a_conflict_when_enforced() {
    assert_moving_a_named_keys_owner_out_of_its_tenant_is_a_conflict(RuleMode::Enforce).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_provider_key_a_surface_names_is_a_conflict_until_the_surface_drops_it() {
    let (_harness, api) = harness(RuleMode::Enforce).await;
    let owner = api
        .created_id(&api.surface("/smoke/named-delete-owner", Some("tenant-a"), json!({})))
        .await;
    let key_id = api.api_key(&owner).await;
    assert_saved(
        api.put_with(&owner, json!({"identity_slots": {"protected": from_api_key(&key_id)}}))
            .await,
    );
    let naming = owner.clone();
    let delete = || {
        api.send(
            api.client
                .delete(api.url(&format!("api-keys/{owner}/{key_id}"))),
        )
    };
    let get = || {
        api.send(
            api.client
                .get(api.url(&format!("api-keys/{owner}/{key_id}"))),
        )
    };

    let (status, body) = delete().await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(
        body["error"],
        format!("API key is named by surface(s) {naming}; remove it from them before deleting the key")
    );
    let (status, body) = get().await;
    assert_eq!(status, 200, "the key is kept: {body}");

    let mut dropped = api.stored(&naming).await;
    dropped["identity_slots"] = json!({});
    assert_saved(
        api.put(&naming, &dropped)
            .await,
    );
    let (status, body) = delete().await;
    assert!(matches!(status, 200 | 204), "{status} {body}");
    let (status, body) = get().await;
    assert_eq!(status, 404, "the key is gone: {body}");
}

const GONE_KEY: &str = "atgk_00000000000000000000000000000d01";
const GONE_KEY_USER: &str = "gone-key-user";

#[tokio::test(flavor = "multi_thread")]
async fn a_surface_keeps_a_provider_key_it_already_named_after_the_key_is_gone_but_cannot_add_one() {
    let (_harness, api) = harness_seeded(RuleMode::Enforce, |bootstrap| {
        write_stored_surface(
            bootstrap,
            GONE_KEY_USER,
            json!({"identity_slots": {"protected": from_api_key(GONE_KEY)}}),
        );
    })
    .await;
    let protected = json!({"identity_slots": {"protected": from_api_key(GONE_KEY)}});
    let other = api
        .created_id(&api.surface("/smoke/deleted-key-other", Some("tenant-a"), json!({})))
        .await;

    let stored = api
        .stored(GONE_KEY_USER)
        .await;
    assert_saved(
        api.put(GONE_KEY_USER, &stored)
            .await,
    );
    assert_eq!(
        api.stored(GONE_KEY_USER)
            .await["identity_slots"]["protected"]["api_key_id"],
        json!(GONE_KEY)
    );

    let mut added = api.stored(&other).await;
    added["identity_slots"] = protected["identity_slots"].clone();
    api.assert_put_refused(&other, &added, "API key reference is not accessible")
        .await;
    api.assert_create_refused(
        &api.surface("/smoke/deleted-key-new", Some("tenant-a"), protected),
        "API key reference is not accessible",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_surface_keeps_a_provider_key_whose_owning_surface_is_deleted_but_cannot_add_one() {
    let (_harness, api) = harness_seeded(RuleMode::Enforce, seed_named_key).await;
    let owner = NAMED_KEY_OWNER;
    let key_id = NAMED_KEY;
    let protected = json!({"identity_slots": {"protected": from_api_key(key_id)}});
    let naming = NAMED_KEY_USER;
    let other = api
        .created_id(&api.surface("/smoke/deleted-owner-other", Some("tenant-a"), json!({})))
        .await;
    let (status, body) = api
        .send(
            api.client
                .delete(api.url(&format!("surfaces/{owner}"))),
        )
        .await;
    assert!(matches!(status, 200 | 204), "{status} {body}");
    let (status, body) = api
        .send(
            api.client
                .get(api.url("api-keys")),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body.to_string()
            .contains(key_id),
        "the key outlives its surface: {body}"
    );

    let stored = api.stored(naming).await;
    assert_saved(api.put(naming, &stored).await);
    assert_eq!(api.stored(naming).await["identity_slots"]["protected"]["api_key_id"], json!(key_id));
    let (status, body) = api
        .reassign("surfaces", naming, Some("tenant-b"))
        .await;
    assert_eq!(status, 200, "a deleted owner does not block reassigning a surface naming its key: {body}");
    assert_eq!(api.stored(naming).await["tenant_id"], "tenant-b");

    let mut added = api.stored(&other).await;
    added["identity_slots"] = protected["identity_slots"].clone();
    api.assert_put_refused(&other, &added, NOT_ACCESSIBLE_KEY_OWNER)
        .await;
    api.assert_create_refused(
        &api.surface("/smoke/deleted-owner-new", Some("tenant-a"), protected),
        NOT_ACCESSIBLE_KEY_OWNER,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_variant_a_patch_or_a_target_identity_injection_cannot_name_another_surfaces_key() {
    let (_harness, api) = harness(RuleMode::Warn).await;
    let keys = owned_keys(&api).await;
    let variant = |key_id: &str| {
        json!({"variants": [{
            "id": "variant-id", "alias": "variant", "name": "Variant", "enabled": true,
            "overrides": {"identity_slots": {"protected": from_api_key(key_id)}}
        }]})
    };

    api.assert_create_refused(
        &api.surface("/smoke/variant-cross", Some("tenant-a"), variant(&keys.tenant_b)),
        NOT_ACCESSIBLE_KEY_OWNER,
    )
    .await;
    api.assert_create_refused(
        &api.surface("/smoke/variant-same-tenant", Some("tenant-a"), variant(&keys.tenant_a)),
        &another_surfaces_key(&keys.tenant_a),
    )
    .await;
    assert_saved(
        api.put_with(&keys.tenant_a_owner, variant(&keys.tenant_a))
            .await,
    );
    let injected = |route: &str, key_id: &str| {
        api.surface(
            route,
            Some("tenant-a"),
            json!({"target": {"endpoint": api.target, "identity_injection": from_api_key(key_id)}}),
        )
    };
    api.assert_create_refused(&injected("/smoke/injection-cross", &keys.tenant_b), NOT_ACCESSIBLE_KEY_OWNER)
        .await;
    api.assert_create_refused(
        &injected("/smoke/injection-same-tenant", &keys.tenant_a),
        &another_surfaces_key(&keys.tenant_a),
    )
    .await;
    let mut injected_own = api
        .stored(&keys.tenant_a_owner)
        .await;
    injected_own["target"]["identity_injection"] = from_api_key(&keys.tenant_a);
    assert_saved(
        api.put(&keys.tenant_a_owner, &injected_own)
            .await,
    );

    let plain = api
        .created_id(&api.surface("/smoke/patch-cross", Some("tenant-a"), json!({})))
        .await;
    api.assert_patch_refused(
        &plain,
        &json!({"identity_slots": {"protected": from_api_key(&keys.tenant_b)}}),
        NOT_ACCESSIBLE_KEY_OWNER,
    )
    .await;
    api.assert_patch_refused(
        &plain,
        &json!({"identity_slots": {"protected": from_api_key(&keys.tenant_a)}}),
        &another_surfaces_key(&keys.tenant_a),
    )
    .await;
    assert_saved(
        api.patch(&keys.tenant_a_owner, &json!({"identity_slots": {"external": from_api_key(&keys.tenant_a)}}))
            .await,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn moving_a_key_owning_surface_to_another_tenant_is_a_conflict_while_a_surface_names_its_key() {
    let (_harness, api) = harness_seeded(RuleMode::Warn, seed_named_key).await;

    let (status, body) = api
        .reassign("surfaces", NAMED_KEY_OWNER, Some("tenant-b"))
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"], "tenant_reassignment_blocked", "{body}");
    assert_eq!(
        api.stored(NAMED_KEY_OWNER)
            .await["tenant_id"],
        "tenant-a",
        "a blocked reassignment changes nothing"
    );

    let (status, body) = api
        .reassign("surfaces", NAMED_KEY_USER, Some("tenant-b"))
        .await;
    assert_eq!(status, 409, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_reference_to_another_surfaces_key_is_kept_in_warn_mode_and_refused_when_enforced() {
    let (_harness, api) = harness_seeded(RuleMode::Warn, seed_named_key).await;
    let stored = api
        .stored(NAMED_KEY_USER)
        .await;
    assert_saved(
        api.put(NAMED_KEY_USER, &stored)
            .await,
    );
    assert_eq!(
        api.stored(NAMED_KEY_USER)
            .await["identity_slots"]["protected"]["api_key_id"],
        NAMED_KEY
    );
    let mut moved = api
        .stored(NAMED_KEY_USER)
        .await;
    moved["identity_slots"] = json!({"external": from_api_key(NAMED_KEY)});
    assert_saved(
        api.put(NAMED_KEY_USER, &moved)
            .await,
    );

    let (_harness, api) = harness_seeded(RuleMode::Enforce, seed_named_key).await;
    let stored = api
        .stored(NAMED_KEY_USER)
        .await;
    api.assert_put_refused(NAMED_KEY_USER, &stored, &another_surfaces_key(NAMED_KEY))
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_legacy_secret_named_like_another_surfaces_key_is_refused() {
    let (_harness, api) = harness_seeded(RuleMode::Warn, |bootstrap| {
        seed_named_key(bootstrap);
        super::helpers::write_api_key_secret(
            &bootstrap
                .storage_paths
                .secrets,
            NAMED_KEY,
            "legacy-secret-value",
        );
    })
    .await;
    let route = "/smoke/legacy-same-tenant";
    api.assert_create_refused(
        &api.surface(
            route,
            Some("tenant-a"),
            json!({
                "identity_slots": {"inbound": {"type": "from_api_key"}},
                "access_point": {"listen_address": api.listener, "route": route, "protocol": "a2a",
                    "caller_authentication": legacy_caller(NAMED_KEY)}
            }),
        ),
        &another_surfaces_key(NAMED_KEY),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_reference_to_an_own_revoked_key_is_refused_and_an_active_one_saved() {
    let (_harness, api) = harness(RuleMode::Warn).await;
    let owner = api
        .created_id(&api.surface("/smoke/revoked-own", Some("tenant-a"), json!({})))
        .await;
    let active = api.api_key(&owner).await;
    let revoked = api.api_key(&owner).await;
    api.revoke_api_key(&owner, &revoked)
        .await;

    let mut named = api.stored(&owner).await;
    named["identity_slots"] = json!({"protected": from_api_key(&revoked)});
    api.assert_put_refused(&owner, &named, &revoked_key(&revoked))
        .await;
    api.assert_patch_refused(
        &owner,
        &json!({"identity_slots": {"external": from_api_key(&revoked)}}),
        &revoked_key(&revoked),
    )
    .await;
    let mut point = api.stored(&owner).await;
    point["transit"] = transit_point_identity(&revoked);
    api.assert_put_refused(&owner, &point, &revoked_key(&revoked))
        .await;
    let mut variant = api.stored(&owner).await;
    variant["variants"] = json!([{
        "id": "variant-id", "alias": "variant", "name": "Variant", "enabled": true,
        "overrides": {"identity_slots": {"protected": from_api_key(&revoked)}}
    }]);
    api.assert_put_refused(&owner, &variant, &revoked_key(&revoked))
        .await;
    let mut injected = api.stored(&owner).await;
    injected["target"]["identity_injection"] = from_api_key(&revoked);
    api.assert_put_refused(&owner, &injected, &revoked_key(&revoked))
        .await;

    assert_saved(
        api.put_with(&owner, json!({"identity_slots": {"protected": from_api_key(&active)}}))
            .await,
    );
    assert_eq!(api.stored(&owner).await["identity_slots"]["protected"]["api_key_id"], json!(active));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_reference_to_an_own_key_revoked_later_is_kept_on_save() {
    for mode in [RuleMode::Warn, RuleMode::Enforce] {
        let (_harness, api) = harness(mode).await;
        let owner = api
            .created_id(&api.surface("/smoke/revoked-later", Some("tenant-a"), json!({})))
            .await;
        let key_id = api.api_key(&owner).await;
        assert_saved(
            api.put_with(&owner, json!({"identity_slots": {"protected": from_api_key(&key_id)}}))
                .await,
        );
        api.revoke_api_key(&owner, &key_id)
            .await;

        let stored = api.stored(&owner).await;
        assert_saved(api.put(&owner, &stored).await);
        assert_eq!(api.stored(&owner).await["identity_slots"]["protected"]["api_key_id"], json!(key_id), "{mode:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn another_tenants_revoked_key_is_refused_without_naming_its_status() {
    let (_harness, api) = harness(RuleMode::Warn).await;
    let other = api
        .created_id(&api.surface("/smoke/revoked-other-tenant", Some("tenant-b"), json!({})))
        .await;
    let key_id = api.api_key(&other).await;
    api.revoke_api_key(&other, &key_id)
        .await;
    let plain = api
        .created_id(&api.surface("/smoke/revoked-other-user", Some("tenant-a"), json!({})))
        .await;

    let mut named = api.stored(&plain).await;
    named["identity_slots"] = json!({"protected": from_api_key(&key_id)});
    api.assert_put_refused(&plain, &named, NOT_ACCESSIBLE_KEY_OWNER)
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_legacy_secret_named_like_an_own_revoked_key_is_refused() {
    let (_harness, api) = harness_seeded(RuleMode::Warn, |bootstrap| {
        seed_named_key(bootstrap);
        super::helpers::write_api_key_secret(
            &bootstrap
                .storage_paths
                .secrets,
            NAMED_KEY,
            "legacy-secret-value",
        );
    })
    .await;
    api.revoke_api_key(NAMED_KEY_OWNER, NAMED_KEY)
        .await;

    let mut legacy = api
        .stored(NAMED_KEY_OWNER)
        .await;
    legacy["identity_slots"] = json!({"inbound": {"type": "from_api_key"}});
    legacy["access_point"]["caller_authentication"] = legacy_caller(NAMED_KEY);
    api.assert_put_refused(NAMED_KEY_OWNER, &legacy, &revoked_key(NAMED_KEY))
        .await;
}

const REFERENCES_OWNER: &str = "references-owner";
const REFERENCES_OTHER_TENANT: &str = "references-other-tenant";
const REFERENCED_ACTIVE: &str = "atgk_00000000000000000000000000000c11";
const REFERENCED_REVOKED: &str = "atgk_00000000000000000000000000000c12";
const REFERENCED_MISSING: &str = "atgk_00000000000000000000000000000c13";
const REFERENCED_OTHER_TENANT: &str = "atgk_00000000000000000000000000000c14";

/// A tenant `a` surface naming its own two keys in the base, a key no store holds in a variant,
/// and the key of a tenant `b` surface naming it on a Transit Point, as stored before those
/// rules applied.
fn seed_key_references(bootstrap: &crate::config::BootstrapConfig) {
    write_stored_surface(
        bootstrap,
        REFERENCES_OTHER_TENANT,
        json!({"tenant_id": "tenant-b", "identity_slots": {"protected": from_api_key(REFERENCED_OTHER_TENANT)}}),
    );
    seed_api_key(bootstrap, REFERENCES_OTHER_TENANT, REFERENCED_OTHER_TENANT);
    write_stored_surface(
        bootstrap,
        REFERENCES_OWNER,
        json!({
            "identity_slots": {
                "protected": from_api_key(REFERENCED_ACTIVE),
                "external": from_api_key(REFERENCED_REVOKED)
            },
            "transit": transit_point_identity(REFERENCED_OTHER_TENANT),
            "variants": [{
                "id": "variant-id", "alias": "variant", "name": "Variant", "enabled": true,
                "overrides": {"identity_slots": {"protected": from_api_key(REFERENCED_MISSING)}}
            }]
        }),
    );
    seed_api_key(bootstrap, REFERENCES_OWNER, REFERENCED_ACTIVE);
    seed_api_key(bootstrap, REFERENCES_OWNER, REFERENCED_REVOKED);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_surface_read_reports_its_own_keys_and_hides_another_surfaces_key_status() {
    let (_harness, api) = harness_seeded(RuleMode::Warn, seed_key_references).await;
    api.revoke_api_key(REFERENCES_OWNER, REFERENCED_REVOKED)
        .await;
    api.revoke_api_key(REFERENCES_OTHER_TENANT, REFERENCED_OTHER_TENANT)
        .await;
    let expected = json!([
        {"key_id": REFERENCED_ACTIVE, "status": "active"},
        {"key_id": REFERENCED_REVOKED, "status": "revoked"},
        {"key_id": REFERENCED_MISSING, "status": "missing"},
        {"key_id": REFERENCED_OTHER_TENANT, "status": "unavailable"}
    ]);

    let stored = api
        .stored(REFERENCES_OWNER)
        .await;
    assert_eq!(stored["api_key_references"], expected, "{stored}");

    let own_revoked = json!([{"key_id": REFERENCED_OTHER_TENANT, "status": "revoked"}]);
    let other = api
        .stored(REFERENCES_OTHER_TENANT)
        .await;
    assert_eq!(other["api_key_references"], own_revoked, "{other}");
    let (status, saved) = api
        .put(REFERENCES_OTHER_TENANT, &other)
        .await;
    assert_eq!(status, 200, "a read body sent back saves: {saved}");
    assert_eq!(saved["api_key_references"], own_revoked, "{saved}");
    let (status, patched) = api
        .patch(REFERENCES_OTHER_TENANT, &json!({"description": "patched", "api_key_references": []}))
        .await;
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["description"], "patched");
    assert_eq!(patched["api_key_references"], own_revoked, "a sent value is never stored: {patched}");

    let plain = api
        .created_id(&api.surface("/smoke/references-none", Some("tenant-a"), json!({})))
        .await;
    let plain = api.stored(&plain).await;
    assert!(
        plain
            .get("api_key_references")
            .is_none(),
        "a surface naming no key has none: {plain}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn moving_a_surface_that_names_only_its_own_key_to_another_tenant_is_allowed() {
    let (_harness, api) = harness(RuleMode::Enforce).await;
    let owner = api
        .created_id(&api.surface("/smoke/own-key-mover", Some("tenant-a"), json!({})))
        .await;
    let key_id = api.api_key(&owner).await;
    assert_saved(
        api.put_with(&owner, json!({"identity_slots": {"protected": from_api_key(&key_id)}}))
            .await,
    );

    let (status, body) = api
        .reassign("surfaces", &owner, Some("tenant-b"))
        .await;
    assert_eq!(status, 200, "{body}");
    let moved = api.stored(&owner).await;
    assert_eq!(moved["tenant_id"], "tenant-b");
    assert_eq!(moved["identity_slots"]["protected"]["api_key_id"], json!(key_id));
    assert_saved(api.put(&owner, &moved).await);
}

const SCOPED_KEY_OWNER: &str = "scoped-key-owner";
const SCOPED_ALLOWED_KEY: &str = "atgk_00000000000000000000000000000a01";
const SCOPED_EXCLUDED_KEY: &str = "atgk_00000000000000000000000000000e01";
const SCOPED_GONE_KEY: &str = "atgk_00000000000000000000000000000901";
const SCOPED_STORED_SURFACE: &str = "scoped-stored-surface";

#[tokio::test(flavor = "multi_thread")]
async fn a_resource_scoped_token_names_only_the_provider_keys_its_pattern_allows() {
    let mut client = None;
    let harness = GatewayHarness::start(|_, _, bootstrap| {
        configure_admin_api(bootstrap);
        write_stored_surface(bootstrap, SCOPED_KEY_OWNER, json!({}));
        write_stored_surface(
            bootstrap,
            SCOPED_STORED_SURFACE,
            json!({"identity_slots": {"protected": from_api_key(SCOPED_GONE_KEY)}}),
        );
        for key_id in [SCOPED_ALLOWED_KEY, SCOPED_EXCLUDED_KEY] {
            seed_api_key(bootstrap, SCOPED_KEY_OWNER, key_id);
        }
        client = Some(super::a2a_flow_e2e::seed_scoped_access_token(
            bootstrap,
            Some(&format!("TENANT:${{x-external-account}}:(?:surfaces:.*|api-keys:{SCOPED_ALLOWED_KEY})")),
        ));
    })
    .await;
    let api = Api {
        secret_uuids: Default::default(),
        client: client.unwrap(),
        base: harness.gateway_base.clone(),
        listener: harness
            .gateway_base
            .replace("127.0.0.1", "localhost"),
        target: harness.mock.url(),
    };
    let naming = |route: &str, key_id: &str| {
        let mut surface =
            api.surface(route, Some("tenant-a"), json!({"identity_slots": {"protected": from_api_key(key_id)}}));
        surface["access_point"]
            .as_object_mut()
            .unwrap()
            .remove("caller_authentication");
        surface
    };

    api.assert_create_refused(&naming("/smoke/scoped-excluded", SCOPED_EXCLUDED_KEY), NOT_ACCESSIBLE_KEY_OWNER)
        .await;
    assert_saved(
        api.put_with(SCOPED_KEY_OWNER, json!({"identity_slots": {"protected": from_api_key(SCOPED_ALLOWED_KEY)}}))
            .await,
    );
    let mut excluded = api
        .stored(SCOPED_KEY_OWNER)
        .await;
    excluded["identity_slots"]["protected"] = from_api_key(SCOPED_EXCLUDED_KEY);
    api.assert_put_refused(SCOPED_KEY_OWNER, &excluded, NOT_ACCESSIBLE_KEY_OWNER)
        .await;
    let stored = api
        .stored(SCOPED_STORED_SURFACE)
        .await;
    api.assert_put_refused(SCOPED_STORED_SURFACE, &stored, NOT_ACCESSIBLE_KEY_OWNER)
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_surface_naming_a_provider_key_is_not_saved_without_an_api_key_store() {
    let mut client = None;
    let harness = GatewayHarness::start(|_, _, bootstrap| {
        client = Some(configure_admin_api(bootstrap));
        write_stored_surface(
            bootstrap,
            SCOPED_STORED_SURFACE,
            json!({"identity_slots": {"protected": from_api_key(SCOPED_GONE_KEY)}}),
        );
        let blocked = api_keys_dir(bootstrap);
        std::fs::create_dir_all(blocked.parent().unwrap()).unwrap();
        std::fs::write(&blocked, b"not a directory").unwrap();
    })
    .await;
    let api = Api {
        secret_uuids: Default::default(),
        client: client.unwrap(),
        base: harness.gateway_base.clone(),
        listener: harness
            .gateway_base
            .replace("127.0.0.1", "localhost"),
        target: harness.mock.url(),
    };
    api.secret("caller-key", None, "v")
        .await;

    let (status, body) = api
        .create(&api.surface(
            "/smoke/no-key-store",
            Some("tenant-a"),
            json!({"identity_slots": {"protected": from_api_key(SCOPED_ALLOWED_KEY)}}),
        ))
        .await;
    assert_eq!(status, 500, "{body}");
    assert_eq!(body["details"], "API key store is not configured", "{body}");
    let plain = api
        .created_id(&api.surface("/smoke/no-key-store-plain", Some("tenant-a"), json!({})))
        .await;

    let (status, body) = api
        .reassign("surfaces", &plain, Some("tenant-b"))
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body, json!({"error": "API key store is not configured"}));
    assert_eq!(api.stored(&plain).await["tenant_id"], "tenant-a", "a refused reassignment changes nothing");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_legacy_secret_named_like_another_tenants_key_is_kept_in_warn_mode_and_a_new_one_refused() {
    let (_harness, api) = harness(RuleMode::Warn).await;
    let stored = api
        .stored(STORED_LEGACY_SECRET_SURFACE)
        .await;
    assert_saved(
        api.put(STORED_LEGACY_SECRET_SURFACE, &stored)
            .await,
    );

    let route = "/smoke/new-legacy-secret";
    api.assert_create_refused(
        &api.surface(
            route,
            Some("tenant-a"),
            json!({
                "identity_slots": {"inbound": {"type": "from_api_key"}},
                "access_point": {"listen_address": api.listener, "route": route, "protocol": "a2a",
                    "caller_authentication": legacy_caller(STORED_TENANT_B_KEY)}
            }),
        ),
        NOT_ACCESSIBLE_KEY_OWNER,
    )
    .await;
    let route = "/smoke/new-legacy-secret-no-identity";
    assert_saved(
        api.create(&api.surface(
            route,
            Some("tenant-a"),
            json!({"access_point": {"listen_address": api.listener, "route": route, "protocol": "a2a",
                "caller_authentication": legacy_caller(STORED_TENANT_B_KEY)}}),
        ))
        .await,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_legacy_secret_named_like_another_tenants_key_is_refused_when_enforced() {
    let (_harness, api) = harness(RuleMode::Enforce).await;
    let stored = api
        .stored(STORED_LEGACY_SECRET_SURFACE)
        .await;
    api.assert_put_refused(STORED_LEGACY_SECRET_SURFACE, &stored, NOT_ACCESSIBLE_KEY_OWNER)
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn moving_the_owner_of_a_key_a_surface_names_as_a_legacy_secret_is_a_conflict() {
    let (_harness, api) = harness(RuleMode::Warn).await;

    let (status, body) = api
        .reassign("surfaces", STORED_TENANT_B_KEY_OWNER, None)
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"], "tenant_reassignment_blocked", "{body}");
    assert_eq!(
        api.stored(STORED_TENANT_B_KEY_OWNER)
            .await["tenant_id"],
        "tenant-b",
        "a blocked reassignment changes nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_legacy_caller_secret_named_like_a_key_needs_the_api_key_store() {
    const LEGACY_ONLY: &str = "legacy-only-surface";
    const LEGACY_SECRET: &str = "atgk_00000000000000000000000000000c11";
    let mut client = None;
    let harness = GatewayHarness::start(|_, _, bootstrap| {
        client = Some(configure_admin_api(bootstrap));
        let gateway: Value = serde_json::from_slice(&std::fs::read(&bootstrap.config_files.gateway).unwrap()).unwrap();
        let port = gateway["listeners"][0]["port"]
            .as_u64()
            .unwrap();
        write_stored_surface(
            bootstrap,
            LEGACY_ONLY,
            json!({
                "identity_slots": {"inbound": {"type": "from_api_key"}},
                "access_point": {
                    "listen_address": format!("http://localhost:{port}"), "route": format!("/smoke/{LEGACY_ONLY}"),
                    "protocol": "a2a", "caller_authentication": legacy_caller(LEGACY_SECRET)
                }
            }),
        );
        super::helpers::write_api_key_secret(
            &bootstrap
                .storage_paths
                .secrets,
            LEGACY_SECRET,
            "legacy-secret-value",
        );
        let blocked = api_keys_dir(bootstrap);
        std::fs::create_dir_all(blocked.parent().unwrap()).unwrap();
        std::fs::write(&blocked, b"not a directory").unwrap();
    })
    .await;
    let api = Api {
        secret_uuids: Default::default(),
        client: client.unwrap(),
        base: harness.gateway_base.clone(),
        listener: harness
            .gateway_base
            .replace("127.0.0.1", "localhost"),
        target: harness.mock.url(),
    };
    api.secret("caller-key", None, "v")
        .await;

    let stored = api.stored(LEGACY_ONLY).await;
    let (status, body) = api
        .put(LEGACY_ONLY, &stored)
        .await;
    assert_eq!(status, 500, "{body}");
    assert_eq!(body["details"], "API key store is not configured", "{body}");
    assert_eq!(api.stored(LEGACY_ONLY).await, stored, "a refused save stores nothing");

    let plain = api
        .created_id(&api.surface("/smoke/legacy-only-plain", Some("tenant-a"), json!({})))
        .await;
    let (status, body) = api
        .reassign("surfaces", &plain, Some("tenant-b"))
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body, json!({"error": "API key store is not configured"}));
    assert_eq!(api.stored(&plain).await["tenant_id"], "tenant-a", "a refused reassignment changes nothing");

    let (status, body) = api
        .send(
            api.client
                .get(api.url(&format!("tenant-ownership/surfaces/{plain}/impact"))),
        )
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body, json!({"error": "API key store is not configured"}));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_another_node_created_after_startup_is_checked_on_save() {
    use crate::api_keys::store::ApiKeyStore as _;
    let mut client = None;
    let mut keys_dir = None;
    let harness = GatewayHarness::start(|_, _, bootstrap| {
        client = Some(configure_admin_api(bootstrap));
        keys_dir = Some(api_keys_dir(bootstrap));
    })
    .await;
    let api = Api {
        secret_uuids: Default::default(),
        client: client.unwrap(),
        base: harness.gateway_base.clone(),
        listener: harness
            .gateway_base
            .replace("127.0.0.1", "localhost"),
        target: harness.mock.url(),
    };
    api.secret("caller-key", None, "v")
        .await;
    let mut owners = Vec::new();
    for (route, tenant) in [("/smoke/later-owner-a", "tenant-a"), ("/smoke/later-owner-b", "tenant-b")] {
        owners.push(
            api.created_id(&api.surface(route, Some(tenant), json!({})))
                .await,
        );
    }
    let other_node = crate::api_keys::FileSystemApiKeyStore::new(
        &keys_dir
            .unwrap()
            .to_string_lossy(),
    )
    .await
    .unwrap();
    let mut keys = Vec::new();
    for owner in &owners {
        keys.push(
            other_node
                .create(owner, "client", None, "other-node")
                .await
                .unwrap()
                .key_id,
        );
    }
    let naming = |route: &str, key_id: &str| {
        api.surface(route, Some("tenant-a"), json!({"identity_slots": {"protected": from_api_key(key_id)}}))
    };

    let mut own = api.stored(&owners[0]).await;
    own["identity_slots"] = json!({"protected": from_api_key(&keys[0])});
    assert_saved(
        api.put(&owners[0], &own)
            .await,
    );
    api.assert_create_refused(&naming("/smoke/later-cross", &keys[1]), NOT_ACCESSIBLE_KEY_OWNER)
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_surface_cannot_take_the_id_of_a_deleted_surface_that_still_owns_api_keys() {
    const DELETED_OWNER: &str = "deleted-key-owner";
    let mut client = None;
    let harness = GatewayHarness::start(|_, _, bootstrap| {
        client = Some(configure_admin_api(bootstrap));
        seed_api_key(bootstrap, DELETED_OWNER, "atgk_00000000000000000000000000000d01");
    })
    .await;
    let api = Api {
        secret_uuids: Default::default(),
        client: client.unwrap(),
        base: harness.gateway_base.clone(),
        listener: harness
            .gateway_base
            .replace("127.0.0.1", "localhost"),
        target: harness.mock.url(),
    };

    let mut reused = api.surface("/smoke/reused-id", Some("tenant-a"), json!({}));
    reused["surface_id"] = json!(DELETED_OWNER);
    let (status, body) = api.create(&reused).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["details"], format!("Surface ID '{DELETED_OWNER}' is not available"), "{body}");
    let (status, body) = api
        .send(
            api.client
                .get(api.url(&format!("surfaces/{DELETED_OWNER}"))),
        )
        .await;
    assert_eq!(status, 404, "a refused create stores nothing: {body}");

    let mut fresh = api.surface("/smoke/fresh-id", Some("tenant-a"), json!({}));
    fresh["surface_id"] = json!("fresh-surface-id");
    assert_eq!(api.created_id(&fresh).await, "fresh-surface-id");
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_surface_revokes_its_api_keys_and_keeps_its_id_taken() {
    let (_harness, api) = harness(RuleMode::Enforce).await;
    let surface = api.surface("/smoke/doomed", Some("tenant-a"), json!({}));
    let surface_id = api.created_id(&surface).await;
    let (status, created) = api
        .send(
            api.client
                .post(api.url(&format!("api-keys/{surface_id}")))
                .json(&json!({"client_id": "client"})),
        )
        .await;
    assert_eq!(status, 201, "{created}");
    let key_id = created["key_id"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, body) = api
        .send(
            api.client
                .delete(api.url(&format!("surfaces/{surface_id}"))),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    let (status, keys) = api
        .send(
            api.client
                .get(api.url("api-keys")),
        )
        .await;
    assert_eq!(status, 200, "{keys}");
    let key = keys
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["key_id"] == key_id.as_str())
        .unwrap_or_else(|| panic!("the key is kept: {keys}"));
    assert_eq!(key["status"], "revoked", "{key}");

    let mut reused = surface.clone();
    reused["surface_id"] = json!(surface_id);
    let (status, body) = api.create(&reused).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["details"], format!("Surface ID '{surface_id}' is not available"), "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_api_key_folder_refuses_only_a_create_taking_its_id() {
    use std::os::unix::fs::PermissionsExt as _;
    const LOCKED_OWNER: &str = "locked-key-owner";
    const LOCKED_KEY: &str = "atgk_00000000000000000000000000000c01";
    let mut client = None;
    let mut locked = None;
    let harness = GatewayHarness::start(|_, _, bootstrap| {
        client = Some(configure_admin_api(bootstrap));
        seed_named_key(bootstrap);
        seed_api_key(bootstrap, LOCKED_OWNER, LOCKED_KEY);
        let folder = api_keys_dir(bootstrap).join(LOCKED_OWNER);
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o000)).unwrap();
        locked = Some(folder);
    })
    .await;
    let locked = locked.unwrap();
    if std::fs::read_dir(&locked).is_ok() {
        // Running as root: no read fails.
        return;
    }
    let api = Api {
        secret_uuids: Default::default(),
        client: client.unwrap(),
        base: harness.gateway_base.clone(),
        listener: harness
            .gateway_base
            .replace("127.0.0.1", "localhost"),
        target: harness.mock.url(),
    };
    let naming = |route: &str, key_id: &str| {
        api.surface(route, Some("tenant-a"), json!({"identity_slots": {"protected": from_api_key(key_id)}}))
    };

    let saved = api
        .put_with(NAMED_KEY_OWNER, json!({"identity_slots": {"protected": from_api_key(NAMED_KEY)}}))
        .await;
    let unseen = api
        .create(&naming("/smoke/locked-key", LOCKED_KEY))
        .await;
    let reassigned = api
        .reassign("surfaces", NAMED_KEY_OWNER, Some("tenant-b"))
        .await;
    let mut taking_locked = api.surface("/smoke/taking-locked", Some("tenant-a"), json!({}));
    taking_locked["surface_id"] = json!(LOCKED_OWNER);
    let (locked_status, locked_body) = api
        .create(&taking_locked)
        .await;
    let (stored_status, _) = api
        .send(
            api.client
                .get(api.url(&format!("surfaces/{LOCKED_OWNER}"))),
        )
        .await;
    let mut fresh = api.surface("/smoke/fresh-beside-locked", Some("tenant-a"), json!({}));
    fresh["surface_id"] = json!("fresh-beside-locked");
    let fresh_created = api.create(&fresh).await;
    let (read_status, read) = api
        .send(
            api.client
                .get(api.url(&format!("surfaces/{NAMED_KEY_OWNER}"))),
        )
        .await;
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();

    let unknown = json!([{"key_id": NAMED_KEY, "status": "unknown"}]);
    assert_saved(saved.clone());
    assert_eq!(
        saved.1["api_key_references"], unknown,
        "an unreadable key folder makes every key unknown, never missing: {}",
        saved.1
    );
    assert_eq!(read_status, 200, "{read}");
    assert_eq!(read["api_key_references"], unknown, "{read}");
    assert_refused(unseen, "API key reference is not accessible");
    assert_eq!(reassigned.0, 409, "a reassignment still checks the keys it can read: {}", reassigned.1);
    assert_eq!(reassigned.1["error"], "tenant_reassignment_blocked", "{}", reassigned.1);
    assert_eq!(locked_status, 503, "{locked_body}");
    assert_eq!(locked_body["details"], "API key store is unavailable", "{locked_body}");
    assert_eq!(stored_status, 404, "a refused create stores nothing");
    assert_saved(fresh_created);
    assert_refused(
        api.create(&taking_locked)
            .await,
        &format!("Surface ID '{LOCKED_OWNER}' is not available"),
    );
}

async fn harness_with_key_dir() -> (GatewayHarness, Api, std::path::PathBuf) {
    let mut client = None;
    let mut key_dir = None;
    let harness = GatewayHarness::start(|_, _, bootstrap| {
        client = Some(configure_admin_api(bootstrap));
        key_dir = Some(api_keys_dir(bootstrap));
    })
    .await;
    let api = Api {
        secret_uuids: Default::default(),
        client: client.unwrap(),
        base: harness.gateway_base.clone(),
        listener: harness
            .gateway_base
            .replace("127.0.0.1", "localhost"),
        target: harness.mock.url(),
    };
    (harness, api, key_dir.unwrap())
}

async fn other_node_key_store(key_dir: &std::path::Path) -> crate::api_keys::FileSystemApiKeyStore {
    crate::api_keys::FileSystemApiKeyStore::new(&key_dir.to_string_lossy())
        .await
        .unwrap()
}

async fn create_with_id(
    api: &Api,
    route: &str,
    surface_id: &str,
) -> (u16, Value) {
    let mut surface = api.surface(route, Some("tenant-a"), json!({}));
    surface["surface_id"] = json!(surface_id);
    api.create(&surface).await
}

async fn delete_surface(
    api: &Api,
    surface_id: &str,
) -> (u16, Value) {
    api.send(
        api.client
            .delete(api.url(&format!("surfaces/{surface_id}"))),
    )
    .await
}

async fn stored_key_status(
    key_dir: &std::path::Path,
    owner: &str,
    key_id: &str,
) -> crate::api_keys::ApiKeyStatus {
    use crate::api_keys::store::ApiKeyStore as _;
    other_node_key_store(key_dir)
        .await
        .get_record(owner, key_id)
        .await
        .unwrap()
        .unwrap()
        .status
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_folder_holding_any_key_record_keeps_its_id_taken() {
    use crate::api_keys::store::ApiKeyStore as _;
    let (_harness, api, key_dir) = harness_with_key_dir().await;
    other_node_key_store(&key_dir)
        .await
        .create("misplaced-owner", "client", None, "component-test")
        .await
        .unwrap();
    std::fs::rename(key_dir.join("misplaced-owner"), key_dir.join("holding-folder")).unwrap();
    for (folder, file) in [
        ("unparseable-folder", "atgk_00000000000000000000000000000e01.json"),
        ("undecryptable-folder", "atgk_00000000000000000000000000000e02.json.enc"),
    ] {
        std::fs::create_dir_all(key_dir.join(folder)).unwrap();
        std::fs::write(
            key_dir
                .join(folder)
                .join(file),
            b"{\"key_id\": }\n}}",
        )
        .unwrap();
    }
    std::fs::create_dir_all(key_dir.join("empty-folder")).unwrap();

    let mut refused = Vec::new();
    for surface_id in ["holding-folder", "unparseable-folder", "undecryptable-folder"] {
        refused.push((surface_id, create_with_id(&api, &format!("/smoke/{surface_id}"), surface_id).await));
    }
    let (empty_status, empty_body) = create_with_id(&api, "/smoke/empty-folder", "empty-folder").await;

    for (surface_id, (status, body)) in refused {
        assert_eq!(status, 400, "{surface_id}: {body}");
        assert_eq!(body["details"], format!("Surface ID '{surface_id}' is not available"), "{body}");
    }
    assert!(matches!(empty_status, 200 | 201), "a folder without keys does not take the id: {empty_body}");
    assert_eq!(empty_body["surface_id"], "empty-folder", "{empty_body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_surface_revokes_a_key_another_node_created_after_boot() {
    use crate::api_keys::store::ApiKeyStore as _;
    let (_harness, api, key_dir) = harness_with_key_dir().await;
    let (status, body) = create_with_id(&api, "/smoke/remote-keyed", "remote-keyed").await;
    assert!(matches!(status, 200 | 201), "{status} {body}");
    let created = other_node_key_store(&key_dir)
        .await
        .create("remote-keyed", "client", None, "component-test")
        .await
        .unwrap();

    let (status, body) = delete_surface(&api, "remote-keyed").await;

    assert_eq!(status, 200, "{body}");
    assert_eq!(
        stored_key_status(&key_dir, "remote-keyed", &created.key_id).await,
        crate::api_keys::ApiKeyStatus::Revoked
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_surface_whose_key_folder_cannot_be_read_still_deletes_it() {
    use crate::api_keys::store::ApiKeyStore as _;
    use std::os::unix::fs::PermissionsExt as _;
    let (_harness, api, key_dir) = harness_with_key_dir().await;
    let (status, body) = create_with_id(&api, "/smoke/locked-keyed", "locked-keyed").await;
    assert!(matches!(status, 200 | 201), "{status} {body}");
    let created = other_node_key_store(&key_dir)
        .await
        .create("locked-keyed", "client", None, "component-test")
        .await
        .unwrap();
    let folder = key_dir.join("locked-keyed");
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read_dir(&folder).is_ok() {
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }

    let (status, body) = delete_surface(&api, "locked-keyed").await;
    let (stored_status, _) = api
        .send(
            api.client
                .get(api.url("surfaces/locked-keyed")),
        )
        .await;
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(status, 200, "{body}");
    assert_eq!(stored_status, 404, "the surface is deleted");
    assert_eq!(
        stored_key_status(&key_dir, "locked-keyed", &created.key_id).await,
        crate::api_keys::ApiKeyStatus::Active
    );
}
