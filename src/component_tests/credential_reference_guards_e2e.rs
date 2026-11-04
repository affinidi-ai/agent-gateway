//! Deleting or retyping a credential provider, and deleting a secret, over the admin API while
//! a surface or a credential provider still uses it: refused with `409` naming the referrers,
//! a secret deleted anyway with `force=true`, and both deleted once nothing uses them.

use serde_json::{Value, json};

use super::helpers::{GatewayHarness, configure_admin_api};

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

    async fn created(
        &self,
        path: &str,
        body: Value,
    ) -> Value {
        let (status, created) = self
            .send(
                self.client
                    .post(self.url(path))
                    .json(&body),
            )
            .await;
        assert!(matches!(status, 200 | 201), "{path}: {status} {created}");
        created
    }

    async fn delete(
        &self,
        path: &str,
    ) -> (u16, Value) {
        self.send(
            self.client
                .delete(self.url(path)),
        )
        .await
    }
}

async fn harness() -> (GatewayHarness, Api) {
    let mut client = None;
    let harness = GatewayHarness::start(|_, _, bootstrap| {
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
    (harness, api)
}

fn referenced_ids(body: &Value) -> Vec<String> {
    let mut ids: Vec<String> = body["references"]
        .as_array()
        .unwrap_or_else(|| panic!("no references in {body}"))
        .iter()
        .map(|reference| {
            format!(
                "{}:{}",
                reference["kind"]
                    .as_str()
                    .unwrap(),
                reference["id"]
                    .as_str()
                    .unwrap()
            )
        })
        .collect();
    ids.sort();
    ids
}

#[tokio::test(flavor = "multi_thread")]
async fn a_credential_provider_or_secret_in_use_is_kept_until_nothing_uses_it() {
    let (_harness, api) = harness().await;
    let mut secret_uuids = std::collections::HashMap::new();
    for secret_id in ["caller-key", "client-id", "client-secret"] {
        let created = api
            .created(
                "secrets/new",
                json!({"name": secret_id, "secret_id": secret_id, "value": "v", "secret_type": "general"}),
            )
            .await;
        secret_uuids.insert(
            secret_id,
            created["id"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }
    let provider = api
        .created(
            "credential-providers",
            json!({
                "name": "Machine", "provider_id": "machine", "provider_type": "oauth2_client_credentials",
                "token_endpoint": "https://192.0.2.1/token",
                "client_id_secret_ref": "client-id", "client_secret_secret_ref": "client-secret"
            }),
        )
        .await;
    let provider_id = provider["id"]
        .as_str()
        .unwrap()
        .to_string();
    let surface = api
        .created(
            "surfaces",
            json!({
                "name": "orders", "status": "disabled",
                "access_point": {
                    "listen_address": api.listener, "route": "/smoke/orders", "protocol": "a2a",
                    "caller_authentication": {"methods": [{
                        "type": "api_key", "secret_id": "caller-key",
                        "extraction": {"source": "http_header", "field": "X-Caller-Key"}
                    }]}
                },
                "target": {"endpoint": "https://127.0.0.1:9/", "auth": {"method": {
                    "credential_provider": {"provider_id": provider_id}
                }}}
            }),
        )
        .await;
    let surface_id = surface["surface_id"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, body) = api
        .delete(&format!("credential-providers/{provider_id}"))
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["code"], "provider_in_use");
    assert_eq!(body["surface_id"], surface_id);

    let (status, body) = api
        .send(
            api.client
                .put(api.url(&format!("credential-providers/{provider_id}")))
                .json(&json!({"provider_type": "oauth2_authorization_code"})),
        )
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(
        body["message"],
        "The credential provider is used for Target authentication, which cannot use a provider that needs a user's consent"
    );

    let (status, body) = api
        .delete(&format!("secrets/{}", secret_uuids["client-id"]))
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["message"], "The secret is in use; remove its references first, or delete it with force=true");
    assert_eq!(referenced_ids(&body), [format!("credential_provider:{provider_id}")]);
    let (status, body) = api
        .delete(&format!("secrets/{}", secret_uuids["caller-key"]))
        .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(referenced_ids(&body), [format!("surface:{surface_id}")]);

    let (status, body) = api
        .delete(&format!("secrets/{}?force=true", secret_uuids["caller-key"]))
        .await;
    assert_eq!(status, 204, "{body}");

    let (status, body) = api
        .delete(&format!("surfaces/{surface_id}"))
        .await;
    assert!(matches!(status, 200 | 204), "{status} {body}");
    let (status, body) = api
        .delete(&format!("credential-providers/{provider_id}"))
        .await;
    assert_eq!(status, 204, "{body}");
    let (status, body) = api
        .delete(&format!("secrets/{}", secret_uuids["client-id"]))
        .await;
    assert_eq!(status, 204, "{body}");
}
