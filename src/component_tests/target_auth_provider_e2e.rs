//! Hop 2 through a credential provider: the gateway obtains its own token from an
//! authorization server and sends it to the Target on the card fetch and on
//! authenticated calls, reusing one token, with the Client Credentials grant or a
//! signed JWT bearer assertion. The admin API refuses cross-tenant
//! references, unsafe configurations, and deleting or retyping a provider in use, and a
//! tenant surface never sends an appliance-wide Target secret or gateway token. Editing a
//! provider or its secret, reassigning its tenant and an operator reload drop the kept token.

use serde_json::{Value, json};

use super::helpers::mock_auth_server::{JwtBearerClient, MockAuthServer};
use super::helpers::oidc_keys::SigningFixture;
use super::helpers::test_mode::TestModeEnv;
use super::helpers::{self, GatewayHarness, MockServer};

const CALLER_KEY: &str = "caller-key-1";
const ROUTE: &str = "/agent";
const ASSERTION_ISSUER: &str = "https://hop-two-agent.example";
const ASSERTION_SUBJECT: &str = "hop-two-agent";

struct Admin {
    client: reqwest::Client,
    base: String,
}

impl Admin {
    async fn send(
        &self,
        request: reqwest::RequestBuilder,
    ) -> (u16, Value) {
        let response = request
            .send()
            .await
            .expect("admin API request");
        let status = response.status().as_u16();
        (
            status,
            response
                .json()
                .await
                .unwrap_or(Value::Null),
        )
    }

    async fn post(
        &self,
        client: &reqwest::Client,
        path: &str,
        body: Value,
    ) -> (u16, Value) {
        self.send(
            client
                .post(format!("{}{path}", self.base))
                .json(&body),
        )
        .await
    }
}

fn secret(
    secret_id: &str,
    value: &str,
) -> Value {
    json!({"name": secret_id, "secret_id": secret_id, "value": value})
}

fn client_credentials_provider(
    slug: &str,
    token_endpoint: &str,
    id_ref: &str,
    secret_ref: &str,
) -> Value {
    json!({
        "name": slug, "provider_id": slug, "provider_type": "oauth2_client_credentials",
        "token_endpoint": token_endpoint, "client_id_secret_ref": id_ref, "client_secret_secret_ref": secret_ref,
        "default_scopes": ["agent.invoke"]
    })
}

fn surface(
    listener: &str,
    route: &str,
    target: &str,
    provider_id: &str,
    authenticated: bool,
) -> Value {
    let mut access_point = json!({"listen_address": listener, "route": route, "protocol": "a2a"});
    if authenticated {
        access_point["caller_authentication"] = json!({"methods": [{
            "type": "api_key", "extraction": {"source": "http_header", "field": "X-Caller-Key"},
            "secret_id": "CALLER_KEYS"
        }]});
    }
    json!({
        "name": route.trim_start_matches('/').replace('/', "-"), "status": "active",
        "access_point": access_point,
        "target": {"endpoint": target, "auth": {
            "method": {"credential_provider": {"credential_provider_id": provider_id}},
            "fallback": "reject"
        }}
    })
}

async fn wait_until_ready(
    admin: &Admin,
    url: &str,
) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let ready = admin
            .client
            .get(url)
            .send()
            .await
            .is_ok_and(|response| response.status() != 404);
        if ready {
            return;
        }
        assert!(tokio::time::Instant::now() < deadline, "{url} never became ready");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_api_refuses_unsafe_or_cross_tenant_provider_target_authentication() {
    let auth_server = MockAuthServer::start().await;
    auth_server.register_client("gateway-client", "gateway-secret");
    let card = json!({"name": "agent", "description": "hop 2", "url": "http://agent.invalid/", "version": "1.0",
        "capabilities": {}, "skills": [], "defaultInputModes": ["text"], "defaultOutputModes": ["text"]});
    let mock = MockServer::start_with_response(card.to_string()).await;
    let _test_mode = TestModeEnv::enabled(
        &format!("{},{}", mock.url(), auth_server.egress_allowlist()),
        &auth_server.oauth_endpoint_allowlist(),
    );
    let mut clients = None;
    let h = GatewayHarness::start_with_mock(mock, |_, _, bootstrap| {
        clients = Some((
            helpers::configure_admin_api(bootstrap),
            helpers::seed_scoped_access_token(
                bootstrap,
                Some("TENANT:${x-external-account}:(?:surfaces:.*|secrets:.*|credential-providers:.*)"),
            ),
        ));
    })
    .await;
    let (client, tenant) = clients.expect("clients");
    let admin = Admin {
        client: client.clone(),
        base: h.gateway_base.clone(),
    };
    wait_until_ready(&admin, &format!("{}/api/v1/health", h.gateway_base)).await;
    let mut listener = url::Url::parse(&h.gateway_base).expect("gateway URL");
    listener
        .set_host(Some("localhost"))
        .expect("host");
    let listener = listener
        .origin()
        .ascii_serialization();
    let target = h.mock.url();

    for (secret_id, value) in [("GW_ID", "gateway-client"), ("GW_SECRET", "gateway-secret"), ("CALLER_KEYS", "key")] {
        let (status, body) = admin
            .post(&client, "/api/v1/secrets/new", secret(secret_id, value))
            .await;
        assert_eq!(status, 201, "{body}");
    }
    let (status, provider) = admin
        .post(
            &client,
            "/api/v1/credential-providers",
            client_credentials_provider("hop-two", &auth_server.token_endpoint(), "GW_ID", "GW_SECRET"),
        )
        .await;
    assert_eq!(status, 201, "{provider}");
    let provider_id = provider["id"]
        .as_str()
        .expect("provider id")
        .to_string();

    let (status, body) = admin
        .post(&client, "/api/v1/surfaces", surface(&listener, "/smoke/open", &target, &provider_id, false))
        .await;
    assert_eq!(status, 400, "a surface without caller authentication cannot use a provider: {body}");
    let (status, body) = admin
        .post(
            &client,
            "/api/v1/surfaces",
            surface(&listener, "/smoke/cleartext", "http://agent.invalid", &provider_id, true),
        )
        .await;
    assert_eq!(status, 400, "a provider needs an https Target: {body}");
    let (status, created) = admin
        .post(&client, "/api/v1/surfaces", surface(&listener, "/smoke/hop2", &target, &provider_id, true))
        .await;
    assert_eq!(status, 201, "{created}");

    let (status, body) = admin
        .send(client.delete(format!("{}/api/v1/credential-providers/{provider_id}", h.gateway_base)))
        .await;
    assert_eq!(status, 409, "a provider in use cannot be deleted: {body}");
    let (status, body) = admin
        .send(
            client
                .put(format!("{}/api/v1/credential-providers/{provider_id}", h.gateway_base))
                .json(&json!({"provider_type": "oauth2_authorization_code",
                    "authorization_endpoint": "https://192.0.2.10/authorize"})),
        )
        .await;
    assert_eq!(status, 409, "nor retyped to a consent provider: {body}");

    let (status, body) = admin
        .post(&tenant, "/api/v1/surfaces", surface(&listener, "/smoke/tenant", &target, &provider_id, true))
        .await;
    assert_eq!(status, 400, "a tenant surface cannot use an appliance-wide provider: {body}");
    let (status, body) = admin
        .post(
            &tenant,
            "/api/v1/credential-providers",
            client_credentials_provider("tenant-hop-two", &auth_server.token_endpoint(), "GW_ID", "GW_SECRET"),
        )
        .await;
    assert_eq!(status, 400, "a tenant provider cannot use appliance-wide secrets: {body}");

    for (secret_id, value) in [("TENANT_ID", "gateway-client"), ("TENANT_SECRET", "gateway-secret")] {
        let (status, body) = admin
            .post(&tenant, "/api/v1/secrets/new", secret(secret_id, value))
            .await;
        assert_eq!(status, 201, "{body}");
    }
    let (status, tenant_provider) = admin
        .post(
            &tenant,
            "/api/v1/credential-providers",
            client_credentials_provider("tenant-hop-two", &auth_server.token_endpoint(), "TENANT_ID", "TENANT_SECRET"),
        )
        .await;
    assert_eq!(status, 201, "{tenant_provider}");
    assert_eq!(tenant_provider["tenant_id"], "tenant-a");
    let tenant_provider_id = tenant_provider["id"]
        .as_str()
        .expect("provider id");
    let mut own = surface(&listener, "/smoke/tenant", &target, tenant_provider_id, true);
    own["access_point"]["caller_authentication"] = json!({"methods": [{
        "type": "api_key", "extraction": {"source": "http_header", "field": "X-Caller-Key"}, "secret_id": "TENANT_ID"
    }]});
    let (status, body) = admin
        .post(&tenant, "/api/v1/surfaces", own)
        .await;
    assert_eq!(status, 201, "a tenant surface uses its own tenant's provider: {body}");
    let mut foreign = surface(&listener, "/smoke/appliance", &target, tenant_provider_id, true);
    foreign["name"] = json!("appliance-uses-tenant-provider");
    let (status, body) = admin
        .post(&client, "/api/v1/surfaces", foreign)
        .await;
    assert_eq!(status, 400, "an appliance-wide surface cannot use a tenant provider: {body}");

    let (status, body) = admin
        .post(&tenant, "/api/v1/secrets/new", secret("TENANT_TARGET_KEY", "tenant-target-key"))
        .await;
    assert_eq!(status, 201, "{body}");
    let tenant_target_key = body["id"]
        .as_str()
        .expect("secret id")
        .to_string();
    let static_secret = |route: &str, secret_id: &str| {
        let mut surface = surface(&listener, route, &target, "", false);
        surface["target"]["auth"] = json!({
            "method": {"static_secret": {"secret_id": secret_id, "header_name": "X-Key"}}, "fallback": "reject"
        });
        surface
    };
    let (status, body) = admin
        .post(&tenant, "/api/v1/surfaces", static_secret("/smoke/tenant-static-shared", "GW_SECRET"))
        .await;
    assert_eq!(status, 400, "a tenant surface cannot send an appliance-wide Target secret: {body}");
    let (status, body) = admin
        .post(&tenant, "/api/v1/surfaces", static_secret("/smoke/tenant-static-own", "TENANT_TARGET_KEY"))
        .await;
    assert_eq!(status, 201, "a tenant surface sends its own tenant's Target secret: {body}");
    let (status, body) = admin
        .send(
            client
                .put(format!("{}/api/v1/tenant-ownership/secrets/{tenant_target_key}", h.gateway_base))
                .json(&json!({"tenant_id": null})),
        )
        .await;
    assert_eq!(status, 409, "that secret cannot become appliance-wide: {body}");

    let bound = |route: &str, provider: &str| {
        let mut surface = surface(&listener, route, &target, "", false);
        surface["target"]
            .as_object_mut()
            .expect("target")
            .remove("auth");
        surface["outbound_credentials"] = json!([{"credential_provider_id": provider}]);
        surface
    };
    let (status, body) = admin
        .post(&tenant, "/api/v1/surfaces", bound("/smoke/tenant-bound-shared", &provider_id))
        .await;
    assert_eq!(status, 400, "a tenant surface cannot bind an appliance-wide gateway token provider: {body}");
    let (status, body) = admin
        .post(&tenant, "/api/v1/surfaces", bound("/smoke/tenant-bound-own", tenant_provider_id))
        .await;
    assert_eq!(status, 201, "a tenant surface binds its own tenant's gateway token provider: {body}");
    let (status, consent) = admin
        .post(
            &client,
            "/api/v1/credential-providers",
            json!({
                "name": "consent", "provider_id": "consent", "provider_type": "oauth2_authorization_code",
                "authorization_endpoint": "https://192.0.2.10/authorize", "token_endpoint": auth_server.token_endpoint(),
                "client_id_secret_ref": "GW_ID", "client_secret_secret_ref": "GW_SECRET"
            }),
        )
        .await;
    assert_eq!(status, 201, "{consent}");
    let consent_id = consent["id"]
        .as_str()
        .expect("provider id");
    let (status, body) = admin
        .post(&tenant, "/api/v1/surfaces", bound("/smoke/tenant-bound-consent", consent_id))
        .await;
    assert_eq!(status, 201, "a tenant surface may bind an appliance-wide consent provider: {body}");
    let (status, body) = admin
        .send(
            client
                .put(format!("{}/api/v1/credential-providers/{consent_id}", h.gateway_base))
                .json(&json!({"provider_type": "oauth2_client_credentials"})),
        )
        .await;
    assert_eq!(status, 409, "which then cannot start sending the gateway's own credential: {body}");

    let (status, appliance_bound) = admin
        .post(&client, "/api/v1/surfaces", bound("/smoke/appliance-bound", &provider_id))
        .await;
    assert_eq!(status, 201, "{appliance_bound}");
    let appliance_bound_id = appliance_bound["surface_id"]
        .as_str()
        .expect("surface id");
    let (status, body) = admin
        .send(
            client
                .put(format!("{}/api/v1/tenant-ownership/surfaces/{appliance_bound_id}", h.gateway_base))
                .json(&json!({"tenant_id": "tenant-a"})),
        )
        .await;
    assert_eq!(status, 409, "a surface bound to an appliance-wide gateway token provider stays appliance-wide: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_api_checks_variants_transit_credentials_and_provider_types_for_target_authentication() {
    let auth_server = MockAuthServer::start().await;
    auth_server.register_client("gateway-client", "gateway-secret");
    let card = json!({"name": "agent", "description": "hop 2", "url": "http://agent.invalid/", "version": "1.0",
        "capabilities": {}, "skills": [], "defaultInputModes": ["text"], "defaultOutputModes": ["text"]});
    let mock = MockServer::start_with_response(card.to_string()).await;
    let _test_mode = TestModeEnv::enabled(
        &format!("{},{}", mock.url(), auth_server.egress_allowlist()),
        &auth_server.oauth_endpoint_allowlist(),
    );
    let mut client = None;
    let h = GatewayHarness::start_with_mock(mock, |_, _, bootstrap| {
        client = Some(helpers::configure_admin_api(bootstrap));
    })
    .await;
    let client = client.expect("client");
    let admin = Admin {
        client: client.clone(),
        base: h.gateway_base.clone(),
    };
    wait_until_ready(&admin, &format!("{}/api/v1/health", h.gateway_base)).await;
    let mut listener = url::Url::parse(&h.gateway_base).expect("gateway URL");
    listener
        .set_host(Some("localhost"))
        .expect("host");
    let listener = listener
        .origin()
        .ascii_serialization();
    let target = h.mock.url();

    for (secret_id, value) in [
        ("GW_ID", "gateway-client"),
        ("GW_SECRET", "gateway-secret"),
        ("CALLER_KEYS", "key"),
        ("SIGNING_KEY", SigningFixture::es256(0).private_pkcs8_pem()),
    ] {
        let (status, body) = admin
            .post(&client, "/api/v1/secrets/new", secret(secret_id, value))
            .await;
        assert_eq!(status, 201, "{body}");
    }
    let id_of = |body: &Value| {
        body["id"]
            .as_str()
            .expect("provider id")
            .to_string()
    };
    let (status, provider) = admin
        .post(
            &client,
            "/api/v1/credential-providers",
            client_credentials_provider("variant-hop-two", &auth_server.token_endpoint(), "GW_ID", "GW_SECRET"),
        )
        .await;
    assert_eq!(status, 201, "{provider}");
    let provider_id = id_of(&provider);
    let (status, consent) = admin
        .post(
            &client,
            "/api/v1/credential-providers",
            json!({
                "name": "consent", "provider_id": "consent", "provider_type": "oauth2_authorization_code",
                "authorization_endpoint": "https://192.0.2.10/authorize", "token_endpoint": auth_server.token_endpoint(),
                "client_id_secret_ref": "GW_ID", "client_secret_secret_ref": "GW_SECRET"
            }),
        )
        .await;
    assert_eq!(status, 201, "{consent}");
    let consent_id = id_of(&consent);
    let mut jwt_bearer = jwt_bearer_grant(&auth_server, ASSERTION_ISSUER);
    jwt_bearer["name"] = json!("variant-jwt");
    jwt_bearer["provider_id"] = json!("variant-jwt");
    let (status, jwt_provider) = admin
        .post(&client, "/api/v1/credential-providers", jwt_bearer)
        .await;
    assert_eq!(status, 201, "{jwt_provider}");
    let jwt_provider_id = id_of(&jwt_provider);

    let (status, body) = admin
        .post(&client, "/api/v1/surfaces", surface(&listener, "/variants/consent", &target, &consent_id, true))
        .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body["details"]
            .as_str()
            .expect("error message")
            .contains("cannot be used for Target Authentication"),
        "a consent provider cannot authenticate to the Target: {body}"
    );

    let mut lookup = surface(&listener, "/variants/lookup", &target, "", true);
    lookup["target"]["auth"] = json!({"method": "credential_lookup", "fallback": "reject"});
    let (status, body) = admin
        .post(&client, "/api/v1/surfaces", lookup)
        .await;
    assert_eq!(status, 201, "a credential lookup references no provider: {body}");

    let transit_surface = |route: &str, endpoint: &str| {
        let mut surface = surface(&listener, route, &target, "", true);
        surface["target"]
            .as_object_mut()
            .expect("target")
            .remove("auth");
        surface["transit"] = json!({"points": [{
            "alias": "partner", "name": "Partner", "protocol": "a2a", "target_endpoint": endpoint,
            "transit_credentials": {"credential_provider_id": jwt_provider_id}
        }]});
        surface
    };
    let (status, body) = admin
        .post(&client, "/api/v1/surfaces", transit_surface("/variants/transit-clear", "http://partner.invalid"))
        .await;
    assert_eq!(status, 400, "a Transit Point binding a JWT bearer provider needs https: {body}");
    assert!(
        body["details"]
            .as_str()
            .expect("error message")
            .contains("requires an https endpoint"),
        "{body}"
    );
    let (status, body) = admin
        .post(&client, "/api/v1/surfaces", transit_surface("/variants/transit-https", "https://partner.invalid"))
        .await;
    assert_eq!(status, 201, "an https Transit Point may bind a JWT bearer provider: {body}");

    let (status, created) = admin
        .post(&client, "/api/v1/surfaces", surface(&listener, "/variants/base", &target, &provider_id, true))
        .await;
    assert_eq!(status, 201, "{created}");
    let surface_id = created["surface_id"]
        .as_str()
        .expect("surface id")
        .to_string();
    let variants = format!("{}/api/v1/surfaces/{surface_id}/variants", h.gateway_base);

    let (status, variant) = admin
        .post(&client, &format!("/api/v1/surfaces/{surface_id}/variants"), json!({"alias": "canary", "name": "Canary"}))
        .await;
    assert_eq!(status, 201, "{variant}");
    assert_eq!(variant["alias"], "canary");
    assert_eq!(variant["enabled"], true);
    let variant_id = variant["id"]
        .as_str()
        .expect("variant id")
        .to_string();
    let (status, body) = admin
        .post(&client, &format!("/api/v1/surfaces/{surface_id}/variants"), json!({"alias": "canary", "name": "Again"}))
        .await;
    assert_eq!(status, 400, "a variant alias is unique on its surface: {body}");

    let (status, body) = admin
        .send(
            client
                .put(format!("{variants}/{variant_id}"))
                .json(&json!({"overrides": {"target": {"auth": {
                    "method": {"credential_provider": {"credential_provider_id": consent_id}}, "fallback": "reject"
                }}}})),
        )
        .await;
    assert_eq!(status, 400, "a variant cannot authenticate through a consent provider either: {body}");
    let (status, body) = admin
        .send(
            client
                .put(format!("{variants}/{variant_id}"))
                .json(&json!({"overrides": {"target": {"auth": {
                    "method": {"credential_provider": {"credential_provider_id": provider_id}}, "fallback": "reject"
                }}}})),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    let (status, promoted) = admin
        .send(client.post(format!("{variants}/{variant_id}/promote-to-default")))
        .await;
    assert_eq!(status, 200, "{promoted}");
    assert_eq!(promoted["default_variant_id"], variant_id);
    let (status, stored) = admin
        .send(client.get(format!("{}/api/v1/surfaces/{surface_id}", h.gateway_base)))
        .await;
    assert_eq!(status, 200, "{stored}");
    assert_eq!(stored["default_variant_id"], variant_id, "the promotion is stored");

    let (status, body) = admin
        .send(client.post(format!("{variants}/missing/promote-to-default")))
        .await;
    assert_eq!(status, 404, "{body}");
    let (status, disabled) = admin
        .post(&client, &format!("/api/v1/surfaces/{surface_id}/variants"), json!({"alias": "dark", "name": "Dark"}))
        .await;
    assert_eq!(status, 201, "{disabled}");
    let disabled_id = disabled["id"]
        .as_str()
        .expect("variant id");
    let (status, body) = admin
        .send(
            client
                .put(format!("{variants}/{disabled_id}"))
                .json(&json!({"enabled": false})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = admin
        .send(client.post(format!("{variants}/{disabled_id}/promote-to-default")))
        .await;
    assert_eq!(status, 400, "a disabled variant cannot become the default: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_changes_drop_the_kept_gateway_token_of_their_provider() {
    use crate::delegation_vault::gateway_token::{
        Freshness, GatewayTokenKey, ProviderSecrets, acquire_gateway_token, target_token_cache,
    };

    let auth_server = MockAuthServer::start().await;
    auth_server.register_client("drop-client", "drop-secret");
    let mock = MockServer::start_with_response(String::new()).await;
    let _test_mode = TestModeEnv::enabled(&auth_server.egress_allowlist(), &auth_server.oauth_endpoint_allowlist());
    let mut clients = None;
    let h = GatewayHarness::start_with_mock(mock, |_, _, bootstrap| {
        clients = Some((
            helpers::configure_admin_api(bootstrap),
            helpers::seed_scoped_access_token(
                bootstrap,
                Some("TENANT:${x-external-account}:(?:surfaces:.*|secrets:.*|credential-providers:.*)"),
            ),
        ));
    })
    .await;
    let (client, tenant) = clients.expect("clients");
    let admin = Admin {
        client: client.clone(),
        base: h.gateway_base.clone(),
    };
    wait_until_ready(&admin, &format!("{}/api/v1/health", h.gateway_base)).await;

    let directory = tempfile::tempdir().expect("tempdir");
    let secrets: std::sync::Arc<dyn crate::secrets::SecretsStore> = std::sync::Arc::new(
        crate::secrets::FilesystemSecretsStore::new_async(
            directory
                .path()
                .join("secrets")
                .to_str()
                .expect("utf-8 path"),
        )
        .await
        .expect("secrets store"),
    );
    let mut secret_ids = std::collections::HashMap::new();
    for (secret_id, value) in [("DROP_ID", "drop-client"), ("DROP_SECRET", "drop-secret")] {
        let (status, body) = admin
            .post(&client, "/api/v1/secrets/new", secret(secret_id, value))
            .await;
        assert_eq!(status, 201, "{body}");
        secret_ids.insert(
            secret_id,
            body["id"]
                .as_str()
                .expect("secret id")
                .to_string(),
        );
        secrets
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: None,
                name: secret_id.into(),
                secret_id: secret_id.into(),
                description: None,
                value: value.into(),
                secret_type: "General".into(),
                tags: vec![],
            })
            .await
            .expect("secret");
    }
    let (status, created) = admin
        .post(
            &client,
            "/api/v1/credential-providers",
            client_credentials_provider("hop-two-drop", &auth_server.token_endpoint(), "DROP_ID", "DROP_SECRET"),
        )
        .await;
    assert_eq!(status, 201, "{created}");
    let provider: crate::credential_providers::CredentialProvider =
        serde_json::from_value(created).expect("the admin API returns the provider");
    let key = GatewayTokenKey::for_target_auth(&provider, &provider.default_scopes).expect("key");
    let acquire = async || {
        acquire_gateway_token(&target_token_cache(), &key, &provider, &ProviderSecrets::new(&secrets, &provider))
            .await
            .expect("the authorization server grants a token")
            .freshness
    };

    assert_eq!(acquire().await, Freshness::Fresh);
    assert_eq!(acquire().await, Freshness::Cached, "the token is kept");

    let changes = [
        (
            "editing the provider",
            client
                .put(format!("{}/api/v1/credential-providers/{}", h.gateway_base, provider.id))
                .json(&json!({"name": "hop-two-drop-renamed"})),
        ),
        (
            "editing its client secret",
            client
                .put(format!("{}/api/v1/secrets/{}", h.gateway_base, secret_ids["DROP_SECRET"]))
                .json(&json!({"description": "rotated"})),
        ),
        (
            "reassigning the provider's tenant",
            client
                .put(format!("{}/api/v1/tenant-ownership/credential-providers/{}", h.gateway_base, provider.id))
                .json(&json!({"tenant_id": null})),
        ),
        (
            "reassigning its client secret's tenant",
            client
                .put(format!("{}/api/v1/tenant-ownership/secrets/{}", h.gateway_base, secret_ids["DROP_SECRET"]))
                .json(&json!({"tenant_id": null})),
        ),
        ("an operator configuration reload", client.post(format!("{}/api/v1/config/reload", h.gateway_base))),
    ];
    for (change, request) in changes {
        let (status, body) = admin.send(request).await;
        assert_eq!(status, 200, "{change}: {body}");
        assert_eq!(acquire().await, Freshness::Fresh, "{change} drops the kept token");
        assert_eq!(acquire().await, Freshness::Cached, "the token granted after {change} is kept");
    }
    assert_eq!(auth_server.token_request_count(), 6, "one grant at first and one after each change");

    let (status, body) = admin
        .send(tenant.post(format!("{}/api/v1/config/reload", h.gateway_base)))
        .await;
    assert_eq!(status, 403, "a tenant cannot reload the configuration: {body}");
    assert_eq!(acquire().await, Freshness::Cached, "a refused tenant reload keeps the token");
    assert_eq!(auth_server.token_request_count(), 6);
}

struct HopTwo {
    _directory: tempfile::TempDir,
    state: crate::state::ProxyState,
    vault: std::sync::Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage>,
}

impl HopTwo {
    async fn start(
        auth_server: &MockAuthServer,
        surface: Value,
    ) -> Self {
        Self::start_with_grant(
            json!({
                "provider_type": "oauth2_client_credentials", "token_endpoint": auth_server.token_endpoint(),
                "client_id_secret_ref": "GW_ID", "client_secret_secret_ref": "GW_SECRET"
            }),
            surface,
        )
        .await
    }

    async fn start_with_grant(
        grant: Value,
        surface: Value,
    ) -> Self {
        use crate::secrets::SecretsStore;
        use std::sync::Arc;

        let directory = tempfile::tempdir().expect("tempdir");
        let path = |name: &str| directory.path().join(name);
        let secrets: Arc<dyn SecretsStore> = Arc::new(
            crate::secrets::FilesystemSecretsStore::new_async(
                path("secrets")
                    .to_str()
                    .expect("utf-8 path"),
            )
            .await
            .expect("secrets store"),
        );
        for (secret_id, value) in [
            ("GW_ID", "gateway-client"),
            ("GW_SECRET", "gateway-secret"),
            ("CALLER_KEYS", CALLER_KEY),
            ("SIGNING_KEY", SigningFixture::es256(0).private_pkcs8_pem()),
        ] {
            secrets
                .create(crate::secrets::CreateSecretRequest {
                    tenant_id: None,
                    name: secret_id.into(),
                    secret_id: secret_id.into(),
                    description: None,
                    value: value.into(),
                    secret_type: "General".into(),
                    tags: vec![],
                })
                .await
                .expect("secret");
        }
        let providers: Arc<dyn crate::credential_providers::storage::CredentialProviderStorage> = Arc::new(
            crate::credential_providers::storage::FileSystemCredentialProviderStore::new(path("providers"))
                .await
                .expect("provider store"),
        );
        let mut record = json!({
            "id": "cp-hop-two", "name": "hop-two", "provider_id": "hop-two",
            "default_scopes": ["agent.invoke"],
            "created_at": "2026-10-21T00:00:00Z", "updated_at": "2026-10-21T00:00:00Z"
        });
        if let (Some(record), Some(grant)) = (record.as_object_mut(), grant.as_object()) {
            record.extend(grant.clone());
        }
        let mut provider: crate::credential_providers::CredentialProvider =
            serde_json::from_value(record).expect("provider JSON");
        provider.updated_at = chrono::Utc::now();
        providers
            .create(provider)
            .await
            .expect("provider");
        let vault: Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage> = Arc::new(
            crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(path("vault"))
                .await
                .expect("vault"),
        );
        let surface = serde_json::from_value(surface).expect("surface JSON");
        let sessions = Arc::new(crate::didauth::DidAuthSessionStore::new());
        let strategies = Arc::new(
            crate::jwt_bearer::FileSystemJwtVerificationStrategyStore::new(path("strategies"))
                .await
                .expect("strategy store"),
        );
        let middleware = Arc::new(crate::source_auth::SourceAuthMiddleware::new(
            sessions.clone(),
            strategies,
            Arc::new(crate::jwt_bearer::JwksClient::new()),
            Some(secrets.clone()),
            Arc::new(dashmap::DashMap::new()),
            None,
            None,
        ));
        let network = serde_json::from_value(json!({
            "did": {"domain": "gateway.example"},
            "webauthn": {"rp_id": "gateway.example", "external_origin": "https://gateway.example"},
            "integration": {"types": [], "categories": []},
            "listeners": [{"id": "in", "name": "in", "bind_address": "127.0.0.1", "port": 8080,
                "protocol": "http", "external_urls": ["https://gateway.example"]}],
            "routes": {"identity": {"type": "identity_api", "prefix": "/api"}}
        }))
        .expect("network JSON");
        let config = serde_json::from_value(json!({
            "tls": {"cert_path": "unused.pem", "key_path": "unused-key.pem"},
            "integration": {"variable_pattern": "\\$\\{([^}]+)\\}", "custom_variable_prefix": "_", "types": [], "categories": []}
        }))
        .expect("config JSON");
        let state = crate::state::ProxyState {
            config: Arc::new(config),
            network_config: Arc::new(network),
            client: reqwest::Client::new(),
            metrics_store: None,
            identity_rules_engine: None,
            identity_selector: None,
            protected_rules_engine: None,
            protected_selector: None,
            external_rules_engine: None,
            external_selector: None,
            task_monitor: None,
            task_id: None,
            ws_state: None,
            listener_manager: Arc::new(tokio::sync::RwLock::new(None)),
            secrets_store: Some(secrets),
            certificates_store: None,
            vc_issuer: None,
            policy_manager: None,
            gateway_policy_manager: None,
            didauth_session_store: sessions,
            transaction_store: None,
            mpp_transaction_store: None,
            trust_registry_listener_manager: None,
            source_auth_middleware: Some(middleware),
            #[cfg(feature = "didwebvh")]
            didwebvh_identity_store: None,
            #[cfg(feature = "didwebvh")]
            didwebvh_log_manager: None,
            credential_provider_store: Some(providers),
            delegation_vault_store: Some(vault.clone()),
            gateway_base_url: Some("https://gateway.example".into()),
            transit_token_issuer: None,
            mcp_proxy_store: None,
            a2a_proxy_store: None,
            active_variant_alias: None,
            active_variant_id: None,
            variant_resolution_error: None,
            access_point_declaration: None,
            surface: Arc::new(surface),
        };
        Self {
            _directory: directory,
            state,
            vault,
        }
    }

    async fn card(&self) -> u16 {
        self.card_with_body().await.0
    }

    async fn card_with_body(&self) -> (u16, String) {
        let response = crate::proxy::handler::handle_agent_card(
            axum::extract::ConnectInfo(
                "127.0.0.1:12345"
                    .parse()
                    .expect("address"),
            ),
            axum::extract::State(self.state.clone()),
            axum::http::HeaderMap::new(),
        )
        .await
        .unwrap_or_else(|response| response);
        let status = response.status().as_u16();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    async fn call(
        &self,
        caller_key: Option<&str>,
    ) -> u16 {
        self.call_with_body(caller_key)
            .await
            .0
    }

    async fn call_with_body(
        &self,
        caller_key: Option<&str>,
    ) -> (u16, String) {
        self.call_with(
            caller_key,
            r#"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","messageId":"m-1","parts":[{"kind":"text","text":"hi"}]}}}"#,
        )
        .await
    }

    async fn call_with(
        &self,
        caller_key: Option<&str>,
        body: &'static str,
    ) -> (u16, String) {
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri(format!("https://gateway.example{ROUTE}"))
            .header("content-type", "application/json");
        if let Some(key) = caller_key {
            request = request.header("x-caller-key", key);
        }
        let request = request
            .body(axum::body::Body::from(body))
            .expect("request");
        let response = Box::pin(crate::proxy::handler::proxy_handler_with_mcp_runtime(
            "127.0.0.1:12345"
                .parse()
                .expect("address"),
            self.state.clone(),
            request,
            crate::mcp::request_validation::MODERN_CAPABLE_POLICY,
            None,
        ))
        .await
        .unwrap_or_else(|response| response);
        let status = response.status().as_u16();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        (status, String::from_utf8_lossy(&body).into_owned())
    }
}

fn jwt_bearer_grant(
    auth_server: &MockAuthServer,
    assertion_issuer: &str,
) -> Value {
    json!({
        "provider_type": "oauth2_jwt_bearer", "token_endpoint": auth_server.token_endpoint(),
        "jwt_bearer": {
            "assertion_issuer": assertion_issuer, "assertion_subject": ASSERTION_SUBJECT,
            "signing_key_secret_ref": "SIGNING_KEY", "signing_algorithm": "ES256",
            "key_id": SigningFixture::es256(0).kid
        }
    })
}

fn jwt_claims(token: &str) -> Value {
    use base64::Engine;
    let payload = token
        .split('.')
        .nth(1)
        .expect("a JWT has a payload");
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("payload is base64url"),
    )
    .expect("payload is JSON")
}

fn last_authorization(mock: &MockServer) -> Option<String> {
    mock.last_request_rx
        .borrow()
        .as_ref()
        .and_then(|request| {
            request
                .headers
                .get("authorization")
                .cloned()
        })
}

#[test]
fn hop_two_sends_one_provider_token_on_the_card_fetch_and_authenticated_calls() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let card = json!({"name": "agent", "description": "hop 2", "url": "http://agent.invalid/", "version": "1.0",
        "capabilities": {}, "skills": [], "defaultInputModes": ["text"], "defaultOutputModes": ["text"]});
    let auth_server = runtime.block_on(MockAuthServer::start());
    auth_server.register_client("gateway-client", "gateway-secret");
    let mock = runtime.block_on(MockServer::start_with_response(card.to_string()));
    let _test_mode = TestModeEnv::enabled(
        &format!("{},{}", mock.url(), auth_server.egress_allowlist()),
        &auth_server.oauth_endpoint_allowlist(),
    );
    let handle = runtime.handle().clone();
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            handle.block_on(crate::delegation_vault::gateway_token::with_own_target_token_cache(async {
                let hop = HopTwo::start(
                    &auth_server,
                    surface("https://gateway.example", ROUTE, &mock.url(), "cp-hop-two", true),
                )
                .await;
                for _ in 0..2 {
                    assert_eq!(hop.card().await, 200);
                    let bearer = last_authorization(&mock).expect("the card fetch carries the gateway token");
                    assert!(bearer.starts_with("Bearer ey"), "{bearer}");
                }
                let token = last_authorization(&mock);

                assert_eq!(
                    hop.call(Some(CALLER_KEY))
                        .await,
                    200
                );
                assert_eq!(last_authorization(&mock), token, "the call reuses the card fetch's token");
                assert_eq!(auth_server.token_request_count(), 1, "one grant for every request");

                let forwarded = mock
                    .request_count
                    .load(std::sync::atomic::Ordering::SeqCst);
                assert_eq!(
                    hop.call(Some("wrong-key"))
                        .await,
                    200,
                    "a failed caller is left to policy"
                );
                assert_eq!(
                    mock.request_count
                        .load(std::sync::atomic::Ordering::SeqCst),
                    forwarded + 1
                );
                assert_eq!(
                    last_authorization(&mock),
                    None,
                    "a caller nobody authenticated never gets the gateway token"
                );
                assert_eq!(hop.call(None).await, 200);
                assert_eq!(last_authorization(&mock), None);
                assert_eq!(auth_server.token_request_count(), 1);
                assert!(
                    hop.vault
                        .list_all()
                        .await
                        .expect("vault lists")
                        .is_empty(),
                    "gateway tokens are never stored in the vault or counted as credentials"
                );
            }));
        })
        .expect("test thread")
        .join()
        .expect("hop two checks pass");
}

#[test]
fn hop_two_through_a_jwt_bearer_provider_sends_the_token_its_assertion_earned() {
    use crate::credential_providers::jwt_assertion::{ASSERTION_IAT_BACKDATE_SECS, ASSERTION_LIFETIME_SECS};

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let auth_server = runtime.block_on(MockAuthServer::start());
    auth_server.register_jwt_client(JwtBearerClient {
        iss: ASSERTION_ISSUER.into(),
        sub: ASSERTION_SUBJECT.into(),
        keys: vec![SigningFixture::es256(0)],
    });
    let mock = runtime.block_on(MockServer::start_with_response(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_string()));
    let _test_mode = TestModeEnv::enabled(
        &format!("{},{}", mock.url(), auth_server.egress_allowlist()),
        &auth_server.oauth_endpoint_allowlist(),
    );
    let handle = runtime.handle().clone();
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            handle.block_on(async {
                let forwarded = || {
                    mock.request_count
                        .load(std::sync::atomic::Ordering::SeqCst)
                };
                let hop = HopTwo::start_with_grant(
                    jwt_bearer_grant(&auth_server, ASSERTION_ISSUER),
                    surface("https://gateway.example", ROUTE, &mock.url(), "cp-hop-two", true),
                )
                .await;
                assert_eq!(
                    hop.call(Some(CALLER_KEY))
                        .await,
                    200
                );
                let authorization = last_authorization(&mock).expect("the Target receives the gateway token");
                let token = authorization
                    .strip_prefix("Bearer ")
                    .expect("a Bearer token");
                let issued = jwt_claims(token);
                assert_eq!(issued["iss"], auth_server.issuer());
                assert_eq!(issued["sub"], ASSERTION_SUBJECT);
                assert_eq!(issued["scope"], "agent.invoke");
                assert_eq!(issued["jti"], "mock-token-0", "the token is the one the authorization server issued");

                let assertions = auth_server.accepted_assertions();
                assert_eq!(assertions.len(), 1);
                let assertion = &assertions[0];
                assert_eq!(assertion["iss"], ASSERTION_ISSUER);
                assert_eq!(assertion["sub"], ASSERTION_SUBJECT);
                assert_eq!(assertion["aud"], auth_server.token_endpoint());
                assert_eq!(assertion["scope"], "agent.invoke");
                assert_eq!(
                    assertion["exp"]
                        .as_i64()
                        .expect("exp")
                        - assertion["iat"]
                            .as_i64()
                            .expect("iat"),
                    ASSERTION_LIFETIME_SECS + ASSERTION_IAT_BACKDATE_SECS,
                    "the assertion is short-lived"
                );

                let refused = HopTwo::start_with_grant(
                    jwt_bearer_grant(&auth_server, "https://unregistered-agent.example"),
                    surface("https://gateway.example", ROUTE, &mock.url(), "cp-hop-two", true),
                )
                .await;
                let before = forwarded();
                let (status, body) = refused
                    .call_with_body(Some(CALLER_KEY))
                    .await;
                assert_eq!(status, 502, "{body}");
                let body: Value = serde_json::from_str(&body).expect("JSON error body");
                assert_eq!(body["detail"], crate::proxy::target_credentials::TARGET_AUTH_FAILED);
                let text = body.to_string();
                let token_endpoint = auth_server.token_endpoint();
                let endpoint = url::Url::parse(&token_endpoint).expect("token endpoint URL");
                let endpoint_authority = format!(
                    "{}:{}",
                    endpoint
                        .host_str()
                        .expect("host"),
                    endpoint
                        .port_or_known_default()
                        .expect("port")
                );
                let kid = SigningFixture::es256(0).kid;
                for detail in [
                    "invalid_grant",
                    "unknown issuer",
                    "unregistered-agent",
                    "PRIVATE KEY",
                    "Bearer",
                    "SIGNING_KEY",
                    "cp-hop-two",
                    token,
                    token_endpoint.as_str(),
                    endpoint_authority.as_str(),
                    kid.as_str(),
                ] {
                    assert!(!text.contains(detail), "the caller never sees {detail}: {text}");
                }
                assert_eq!(forwarded(), before, "the request never reaches the Target");
                assert_eq!(auth_server.token_request_count(), 2);
                assert_eq!(
                    auth_server
                        .accepted_assertions()
                        .len(),
                    1,
                    "the refused assertion earned no token"
                );
            });
        })
        .expect("test thread")
        .join()
        .expect("JWT bearer hop two checks pass");
}

#[test]
fn a_tenant_surface_never_sends_appliance_wide_gateway_credentials() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let auth_server = runtime.block_on(MockAuthServer::start());
    auth_server.register_client("gateway-client", "gateway-secret");
    let mock = runtime.block_on(MockServer::start_with_response(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_string()));
    let _test_mode = TestModeEnv::enabled(
        &format!("{},{}", mock.url(), auth_server.egress_allowlist()),
        &auth_server.oauth_endpoint_allowlist(),
    );
    let handle = runtime.handle().clone();
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            handle.block_on(async {
                let tenant_surface = |auth: Option<Value>| {
                    let mut tenant = surface("https://gateway.example", ROUTE, &mock.url(), "cp-hop-two", true);
                    tenant["tenant_id"] = json!("tenant-a");
                    match auth {
                        Some(auth) => tenant["target"]["auth"] = auth,
                        None => {
                            tenant["target"]
                                .as_object_mut()
                                .expect("target")
                                .remove("auth");
                        }
                    }
                    tenant
                };
                let forwarded = || {
                    mock.request_count
                        .load(std::sync::atomic::Ordering::SeqCst)
                };

                let mut bound = tenant_surface(None);
                bound["outbound_credentials"] = json!([{"credential_provider_id": "cp-hop-two"}]);
                let hop = HopTwo::start(&auth_server, bound).await;
                let before = forwarded();
                assert_eq!(
                    hop.call(Some(CALLER_KEY))
                        .await,
                    200
                );
                assert_eq!(forwarded(), before + 1);
                assert_eq!(last_authorization(&mock), None, "an appliance-wide provider's token is not bound");
                assert_eq!(auth_server.token_request_count(), 0, "and never requested");

                let hop = HopTwo::start(
                    &auth_server,
                    tenant_surface(Some(json!({
                        "method": {"static_secret": {"secret_id": "GW_SECRET", "header_name": "X-Key"}},
                        "fallback": "passthrough"
                    }))),
                )
                .await;
                let before = forwarded();
                assert_eq!(
                    hop.call(Some(CALLER_KEY))
                        .await,
                    502,
                    "an appliance-wide Target secret fails closed on a tenant surface"
                );
                assert_eq!(forwarded(), before, "the request never reaches the Target");
            });
        })
        .expect("test thread")
        .join()
        .expect("tenant surface checks pass");
}

#[test]
fn a_delegated_credential_and_the_target_credential_never_share_a_header() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let auth_server = runtime.block_on(MockAuthServer::start());
    auth_server.register_client("gateway-client", "gateway-secret");
    let mock = runtime.block_on(MockServer::start_with_response(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_string()));
    let _test_mode = TestModeEnv::enabled(
        &format!("{},{}", mock.url(), auth_server.egress_allowlist()),
        &auth_server.oauth_endpoint_allowlist(),
    );
    let handle = runtime.handle().clone();
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            handle.block_on(async {
                let bound = |auth: Value| {
                    let mut bound = surface("https://gateway.example", ROUTE, &mock.url(), "cp-hop-two", true);
                    bound["target"]["auth"] = auth;
                    bound["outbound_credentials"] = json!([{"credential_provider_id": "cp-hop-two"}]);
                    bound
                };
                let forwarded = || {
                    mock.request_count
                        .load(std::sync::atomic::Ordering::SeqCst)
                };

                let hop = HopTwo::start(
                    &auth_server,
                    bound(json!({
                        "method": {"static_secret": {"secret_id": "GW_SECRET", "header_name": "Authorization",
                            "header_format": "Static {value}"}},
                        "fallback": "reject"
                    })),
                )
                .await;
                assert_eq!(
                    hop.call(Some(CALLER_KEY))
                        .await,
                    200
                );
                let authorization = last_authorization(&mock).expect("the Target receives one Authorization header");
                assert!(
                    authorization.starts_with("Bearer ey") && !authorization.contains(','),
                    "the delegated credential replaces a static Target secret: {authorization}"
                );

                let hop = HopTwo::start(
                    &auth_server,
                    bound(json!({
                        "method": {"credential_provider": {"credential_provider_id": "cp-hop-two"}},
                        "fallback": "passthrough"
                    })),
                )
                .await;
                let before = forwarded();
                assert_eq!(
                    hop.call(Some(CALLER_KEY))
                        .await,
                    502,
                    "a provider credential never silently replaces a delegated one, whatever the fallback"
                );
                assert_eq!(forwarded(), before, "the request never reaches the Target");
            });
        })
        .expect("test thread")
        .join()
        .expect("precedence checks pass");
}

#[test]
fn a_delegated_credential_header_with_an_unusable_name_is_refused_before_the_target() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let auth_server = runtime.block_on(MockAuthServer::start());
    auth_server.register_client("gateway-client", "gateway-secret");
    let mock = runtime.block_on(MockServer::start_with_response(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_string()));
    let _test_mode = TestModeEnv::enabled(
        &format!("{},{}", mock.url(), auth_server.egress_allowlist()),
        &auth_server.oauth_endpoint_allowlist(),
    );
    let handle = runtime.handle().clone();
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            handle.block_on(async {
                let bound = |inject_as: Value| {
                    let mut bound = surface("https://gateway.example", ROUTE, &mock.url(), "cp-hop-two", true);
                    bound["outbound_credentials"] =
                        json!([{"credential_provider_id": "cp-hop-two", "inject_as": inject_as}]);
                    bound
                };
                let forwarded = || {
                    mock.request_count
                        .load(std::sync::atomic::Ordering::SeqCst)
                };

                let hop = HopTwo::start(
                    &auth_server,
                    bound(json!({"type": "custom_header", "name": "X-Delegated-Key", "format": "{value}"})),
                )
                .await;
                let before = forwarded();
                assert_eq!(
                    hop.call(Some(CALLER_KEY))
                        .await,
                    200
                );
                assert_eq!(forwarded(), before + 1, "a usable header name is delivered");

                let hop = HopTwo::start(
                    &auth_server,
                    bound(json!({"type": "custom_header", "name": "Bad Header Name", "format": "{value}"})),
                )
                .await;
                let before = forwarded();
                let (status, body) = hop
                    .call_with_body(Some(CALLER_KEY))
                    .await;
                assert_eq!(status, 500, "{body}");
                assert!(body.contains("Invalid delegated credential header"), "{body}");
                assert_eq!(forwarded(), before, "the request never reaches the Target");
            });
        })
        .expect("test thread")
        .join()
        .expect("unusable header name checks pass");
}

#[test]
fn the_card_fetch_follows_the_card_location_override_and_a_refused_grant_never_reaches_the_target() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let card = json!({"name": "agent", "description": "hop 2", "url": "http://agent.invalid/", "version": "1.0",
        "capabilities": {}, "skills": [], "defaultInputModes": ["text"], "defaultOutputModes": ["text"]});
    let auth_server = runtime.block_on(MockAuthServer::start());
    auth_server.register_jwt_client(JwtBearerClient {
        iss: ASSERTION_ISSUER.into(),
        sub: ASSERTION_SUBJECT.into(),
        keys: vec![SigningFixture::es256(0)],
    });
    let mock = runtime.block_on(MockServer::start_with_response(card.to_string()));
    let _test_mode = TestModeEnv::enabled(
        &format!("{},{}", mock.url(), auth_server.egress_allowlist()),
        &auth_server.oauth_endpoint_allowlist(),
    );
    let handle = runtime.handle().clone();
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            handle.block_on(async {
                let overridden = |provider_issuer: &str| {
                    let mut value =
                        surface("https://gateway.example", ROUTE, &format!("{}/api", mock.url()), "cp-hop-two", true);
                    value["access_point"]["agent_card_path"] = json!("/cards/agent.json");
                    (jwt_bearer_grant(&auth_server, provider_issuer), value)
                };

                let (grant, value) = overridden(ASSERTION_ISSUER);
                let hop = HopTwo::start_with_grant(grant, value).await;
                let (status, body) = hop.card_with_body().await;
                assert_eq!(status, 200, "{body}");
                let received = mock
                    .last_request_rx
                    .borrow()
                    .clone()
                    .expect("the Target received the card fetch");
                assert_eq!(received.path, "/cards/agent.json", "the card is fetched from the override path");
                assert!(
                    last_authorization(&mock).is_some_and(|bearer| bearer.starts_with("Bearer ey")),
                    "the card fetch carries the gateway token"
                );

                let before = mock
                    .request_count
                    .load(std::sync::atomic::Ordering::SeqCst);
                let (grant, value) = overridden("https://unregistered-agent.example");
                let refused = HopTwo::start_with_grant(grant, value).await;
                let (status, body) = refused.card_with_body().await;
                assert_eq!(status, 502, "{body}");
                let body: Value = serde_json::from_str(&body).expect("JSON error body");
                assert_eq!(body["detail"], crate::proxy::target_credentials::TARGET_AUTH_FAILED);
                assert!(
                    !body
                        .to_string()
                        .contains("unregistered-agent"),
                    "{body}"
                );
                assert_eq!(
                    mock.request_count
                        .load(std::sync::atomic::Ordering::SeqCst),
                    before,
                    "a card fetch without a credential never reaches the Target"
                );
            });
        })
        .expect("test thread")
        .join()
        .expect("card fetch checks pass");
}

const MCP_TOOL_CALL: &str = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#;

async fn mcp_proxy_hop(
    secret_id: &str,
    mock_url: &str,
    directory: &std::path::Path,
) -> HopTwo {
    use crate::mcp_proxies::McpProxyStore;

    let proxy = crate::mcp_proxies::types::McpProxy::new(
        "Hop two tools".into(),
        String::new(),
        mock_url.to_string(),
        json!({
            "openapi": "3.0.0", "info": {"title": "Tools", "version": "1.0"}, "paths": {
                "/echo": {"get": {"operationId": "echo", "responses": {"200": {"description": "OK"}}}}
            }
        })
        .to_string(),
        "/mcp".into(),
        "/owned".into(),
    );
    let mut value = surface("https://gateway.example", ROUTE, &format!("proxy://{}", proxy.id), "cp-hop-two", true);
    value["access_point"]["protocol"] = json!("mcp");
    value["target"]["auth"] = json!({
        "method": {"static_secret": {"secret_id": secret_id, "header_name": "X-Api-Key"}},
        "fallback": "reject"
    });
    let mut hop = HopTwo::start_with_grant(
        json!({
            "provider_type": "oauth2_client_credentials", "token_endpoint": "https://auth.example/token",
            "client_id_secret_ref": "GW_ID", "client_secret_secret_ref": "GW_SECRET"
        }),
        value,
    )
    .await;
    let store = crate::mcp_proxies::filesystem::FileSystemMcpProxyStore::new(directory.join("mcp-proxies"))
        .await
        .expect("MCP proxy store");
    store
        .create(&proxy)
        .await
        .expect("MCP proxy");
    hop.state.mcp_proxy_store = Some(std::sync::Arc::new(store));
    hop
}

#[test]
fn an_mcp_proxy_surface_sends_its_target_secret_to_the_backend_and_refuses_without_one() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let mock = runtime.block_on(MockServer::start_with_response(r#"{"echoed":true}"#.to_string()));
    let _test_mode = TestModeEnv::enabled(&mock.url(), "");
    let handle = runtime.handle().clone();
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            handle.block_on(async {
                let directory = tempfile::tempdir().expect("tempdir");
                let hop = mcp_proxy_hop("GW_SECRET", &mock.url(), directory.path()).await;
                let (status, body) = hop
                    .call_with(Some(CALLER_KEY), MCP_TOOL_CALL)
                    .await;
                assert_eq!(status, 200, "{body}");
                let received = mock
                    .last_request_rx
                    .borrow()
                    .clone()
                    .expect("the backend received the call");
                assert_eq!(
                    received
                        .headers
                        .get("x-api-key")
                        .map(String::as_str),
                    Some("gateway-secret")
                );

                let before = mock
                    .request_count
                    .load(std::sync::atomic::Ordering::SeqCst);
                let refused_directory = tempfile::tempdir().expect("tempdir");
                let refused = mcp_proxy_hop("MISSING_SECRET", &mock.url(), refused_directory.path()).await;
                let (status, body) = refused
                    .call_with(Some(CALLER_KEY), MCP_TOOL_CALL)
                    .await;
                assert_eq!(status, 502, "{body}");
                let body: Value = serde_json::from_str(&body).expect("JSON error body");
                assert_eq!(body["detail"], crate::proxy::target_credentials::TARGET_AUTH_FAILED);
                assert!(
                    !body
                        .to_string()
                        .contains("MISSING_SECRET"),
                    "{body}"
                );
                assert_eq!(
                    mock.request_count
                        .load(std::sync::atomic::Ordering::SeqCst),
                    before,
                    "the backend never sees a call without its credential"
                );
            });
        })
        .expect("test thread")
        .join()
        .expect("MCP proxy checks pass");
}
