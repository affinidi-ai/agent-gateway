//! New Access Points are closed: the admin API refuses a new surface without
//! caller authentication unless it is marked public, and a closed Access Point
//! refuses a caller whose credential is missing or invalid with `401`, in the
//! caller's protocol shape, before policy and the Target. Public discovery
//! reads stay open, and a surface stored without the new fields keeps the
//! behaviour it had.

use super::helpers::{
    GatewayHarness, MockServer, build_minimal_channel, configure_admin_api, configure_gateway_route_prefixes,
    write_api_key_secret,
};
use crate::config::agent_surface::{CALLER_AUTHENTICATION_REQUIRED, PUBLIC_ACCESS_POINT_WARNING};
use crate::source_auth::errors::CALLER_CREDENTIAL_REFUSED;
use serde_json::{Value, json};
use std::sync::atomic::Ordering;

const KEY_ID: &str = "closed-access-point-key";
const VALID_KEY: &str = "valid-key";

fn api_key_authentication() -> Value {
    json!({"methods": [{"type": "api_key", "extraction": {"source": "http_header", "field": "x-api-key"},
        "secret_id": KEY_ID}]})
}

fn a2a_request() -> Value {
    json!({"jsonrpc": "2.0", "id": "a2a-1", "method": "message/send",
        "params": {"message": {"role": "user", "messageId": "m-1", "parts": [{"kind": "text", "text": "hi"}]}}})
}

struct ClosedGateway {
    h: GatewayHarness,
    admin: reqwest::Client,
    listen_address: String,
    surfaces_dir: std::path::PathBuf,
}

impl ClosedGateway {
    async fn start(legacy: Vec<crate::config::agent_surface::AgentSurface>) -> Self {
        let mock = MockServer::start_with_response(
            json!({"jsonrpc": "2.0", "id": "a2a-1", "result": {"kind": "message", "messageId": "r-1", "role": "agent",
                "parts": []}})
            .to_string(),
        )
        .await;
        let mut admin = None;
        let mut surfaces_dir = None;
        let h = GatewayHarness::start_with_mock(mock, |_, gateway, bootstrap| {
            surfaces_dir = Some(std::path::PathBuf::from(
                &bootstrap
                    .storage_paths
                    .agent_surfaces,
            ));
            write_api_key_secret(
                &bootstrap
                    .storage_paths
                    .secrets,
                KEY_ID,
                VALID_KEY,
            );
            admin = Some(configure_admin_api(bootstrap));
            let prefixes: Vec<(&str, &str, &str)> = legacy
                .iter()
                .map(|surface| {
                    (
                        surface.surface_id.as_str(),
                        surface.surface_id.as_str(),
                        surface
                            .access_point
                            .route
                            .as_str(),
                    )
                })
                .collect();
            if !prefixes.is_empty() {
                configure_gateway_route_prefixes(bootstrap, &prefixes);
            }
            gateway.surfaces = legacy;
        })
        .await;
        let mut listener = url::Url::parse(&h.gateway_base).unwrap();
        listener
            .set_host(Some("localhost"))
            .unwrap();
        Self {
            listen_address: listener
                .origin()
                .ascii_serialization(),
            admin: admin.unwrap(),
            surfaces_dir: surfaces_dir.unwrap(),
            h,
        }
    }

    fn surfaces(&self) -> String {
        format!("{}/api/v1/surfaces", self.h.gateway_base)
    }

    fn body(
        &self,
        route: &str,
        protocol: &str,
        access_point: Value,
    ) -> Value {
        let mut body = json!({
            "name": route.trim_start_matches('/').replace('/', "-"), "status": "active",
            "access_point": {"listen_address": self.listen_address, "route": route, "protocol": protocol},
            "target": {"endpoint": self.h.mock.url()}
        });
        body["access_point"]
            .as_object_mut()
            .unwrap()
            .extend(
                access_point
                    .as_object()
                    .unwrap()
                    .clone(),
            );
        body
    }

    async fn send(
        &self,
        request: reqwest::RequestBuilder,
    ) -> (u16, reqwest::header::HeaderMap, Value) {
        let response = request
            .send()
            .await
            .expect("request");
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response
            .json()
            .await
            .unwrap_or(Value::Null);
        (status, headers, body)
    }

    async fn create(
        &self,
        body: &Value,
    ) -> (u16, Value) {
        let (status, _, body) = self
            .send(
                self.admin
                    .post(self.surfaces())
                    .json(body),
            )
            .await;
        (status, body)
    }

    async fn put(
        &self,
        surface_id: &str,
        body: &Value,
    ) -> (u16, Value) {
        let (status, _, body) = self
            .send(
                self.admin
                    .put(format!("{}/{surface_id}", self.surfaces()))
                    .json(body),
            )
            .await;
        (status, body)
    }

    async fn call(
        &self,
        path: &str,
        body: &Value,
        key: Option<&str>,
    ) -> (u16, reqwest::header::HeaderMap, Value) {
        let mut request = reqwest::Client::new()
            .post(format!("{}{path}", self.h.gateway_base))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(body.to_string());
        if let Some(key) = key {
            request = request.header("x-api-key", key);
        }
        self.send(request).await
    }

    fn reached(&self) -> usize {
        self.h
            .mock
            .request_count
            .load(Ordering::SeqCst)
    }
}

fn surface_id(surface: &Value) -> &str {
    surface["surface_id"]
        .as_str()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_surface_without_caller_authentication_is_refused_unless_public() {
    let g = ClosedGateway::start(Vec::new()).await;

    let (status, refused) = g
        .create(&g.body("/smoke/unsecured", "a2a", json!({})))
        .await;
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["details"], CALLER_AUTHENTICATION_REQUIRED, "{refused}");
    let (status, refused) = g
        .create(&g.body("/smoke/unsecured", "a2a", json!({"public": false, "caller_authentication": {"methods": []}})))
        .await;
    assert_eq!(status, 400, "{refused}");

    let (status, created) = g
        .create(&g.body("/smoke/public", "a2a", json!({"public": true})))
        .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["access_point"]["public"], true);
    assert_eq!(created["warnings"], json!([PUBLIC_ACCESS_POINT_WARNING]));

    let (status, _, _) = g
        .call("/smoke/public", &a2a_request(), None)
        .await;
    assert_eq!(status, 200);
    assert_eq!(g.reached(), 1, "a public Access Point forwards a caller without credentials");

    let (status, saved) = g
        .put(surface_id(&created), &created)
        .await;
    assert_eq!(status, 200, "a save response can be sent back as it is: {saved}");
    assert_eq!(saved["warnings"], json!([PUBLIC_ACCESS_POINT_WARNING]), "the warning is on every save");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_closed_a2a_access_point_refuses_a_missing_or_wrong_key_before_the_target() {
    let g = ClosedGateway::start(Vec::new()).await;
    let (status, created) = g
        .create(&g.body("/smoke/closed", "a2a", json!({"caller_authentication": api_key_authentication()})))
        .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["access_point"]["public"], false);
    assert_eq!(created["access_point"]["caller_authentication"]["on_failure"], "reject");
    assert!(
        created
            .get("warnings")
            .is_none(),
        "{created}"
    );

    for key in [None, Some("wrong-key")] {
        let (status, headers, body) = g
            .call("/smoke/closed", &a2a_request(), key)
            .await;
        assert_eq!(status, 401, "{key:?}: {body}");
        assert_eq!(headers["content-type"], "application/problem+json");
        assert_eq!(body["detail"], CALLER_CREDENTIAL_REFUSED, "the refusal never says why: {body}");
        assert_eq!(body["status"], 401);
        assert_eq!(g.reached(), 0, "a refused caller never reaches the Target");
    }

    let (status, _, body) = g
        .call("/smoke/closed", &a2a_request(), Some(VALID_KEY))
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(g.reached(), 1, "a valid caller reaches the Target");

    for path in ["/.well-known/agent-card.json", "/.well-known/agent.json", "/agent-card.json"] {
        let response = reqwest::Client::new()
            .get(format!("{}/smoke/closed{path}", g.h.gateway_base))
            .send()
            .await
            .unwrap();
        assert_ne!(response.status(), 401, "a discovery read of {path} is not refused for missing credentials");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_closed_mcp_access_point_refuses_with_a_json_rpc_error_carrying_the_request_id() {
    let g = ClosedGateway::start(Vec::new()).await;
    let (status, created) = g
        .create(&g.body("/smoke/closed-mcp", "mcp", json!({"caller_authentication": api_key_authentication()})))
        .await;
    assert_eq!(status, 201, "{created}");
    let tools_list = json!({"jsonrpc": "2.0", "id": "closed-1", "method": "tools/list", "params": {}});

    for path in ["/smoke/closed-mcp", "/smoke/closed-mcp/agent.json"] {
        for key in [None, Some("wrong-key")] {
            let (status, _, body) = g
                .call(path, &tools_list, key)
                .await;
            assert_eq!(status, 401, "{path} {key:?}: {body}");
            assert_eq!(
                body,
                json!({"jsonrpc": "2.0", "id": "closed-1", "error": {
                    "code": crate::mcp::errors::error_codes::INTERNAL_ERROR, "message": CALLER_CREDENTIAL_REFUSED
                }})
            );
        }
    }
    assert_eq!(g.reached(), 0, "a refused caller never reaches the Target");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_closed_surface_cannot_be_reopened_by_an_update_or_a_variant() {
    let g = ClosedGateway::start(Vec::new()).await;
    let (status, created) = g
        .create(&g.body("/smoke/kept-closed", "a2a", json!({"caller_authentication": api_key_authentication()})))
        .await;
    assert_eq!(status, 201, "{created}");
    let id = surface_id(&created).to_string();

    let mut dropped = created.clone();
    let access_point = dropped["access_point"]
        .as_object_mut()
        .unwrap();
    access_point.remove("public");
    access_point.remove("caller_authentication");
    let (status, refused) = g.put(&id, &dropped).await;
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["details"], CALLER_AUTHENTICATION_REQUIRED);

    let mut without_public = created.clone();
    without_public["access_point"]
        .as_object_mut()
        .unwrap()
        .remove("public");
    without_public["access_point"]["caller_authentication"]["on_failure"] = json!("continue");
    let (status, saved) = g
        .put(&id, &without_public)
        .await;
    assert_eq!(status, 200, "{saved}");
    assert_eq!(saved["access_point"]["public"], false, "a PUT that drops public keeps it");
    assert_eq!(saved["access_point"]["caller_authentication"]["on_failure"], "reject");

    let (status, _, refused) = g
        .send(
            g.admin
                .patch(format!("{}/{id}", g.surfaces()))
                .header("content-type", "application/merge-patch+json")
                .json(&json!({"access_point": {"public": null, "caller_authentication": null}})),
        )
        .await;
    assert_eq!(status, 400, "{refused}");

    let mut cleared_by_variant = saved.clone();
    cleared_by_variant["variants"] = json!([{"id": "open", "alias": "open", "name": "Open", "enabled": true,
        "overrides": {"complete": true, "access_point": {}}}]);
    let (status, refused) = g
        .put(&id, &cleared_by_variant)
        .await;
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["details"], format!("variant 'open': {CALLER_AUTHENTICATION_REQUIRED}"));

    let mut opened = saved.clone();
    opened["access_point"]["public"] = json!(true);
    opened["access_point"]
        .as_object_mut()
        .unwrap()
        .remove("caller_authentication");
    let (status, public) = g.put(&id, &opened).await;
    assert_eq!(status, 200, "an explicit public opt-out is accepted: {public}");
    assert_eq!(public["warnings"], json!([PUBLIC_ACCESS_POINT_WARNING]));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_surface_stored_before_the_change_keeps_its_behaviour() {
    let mut open = build_minimal_channel();
    open.surface_id = "legacy-open".to_string();
    open.access_point.route = "/legacy-open".to_string();
    let mut keyed = build_minimal_channel();
    keyed.surface_id = "legacy-keyed".to_string();
    keyed.access_point.route = "/legacy-keyed".to_string();
    keyed
        .access_point
        .caller_authentication = serde_json::from_value(api_key_authentication()).unwrap();
    let g = ClosedGateway::start(vec![open, keyed]).await;

    let (status, _, _) = g
        .call("/legacy-open/rpc", &a2a_request(), None)
        .await;
    assert_eq!(status, 200);
    let (status, _, _) = g
        .call("/legacy-keyed/rpc", &a2a_request(), Some("wrong-key"))
        .await;
    assert_eq!(status, 200, "a failed caller still goes on to policy");
    assert_eq!(g.reached(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_update_of_a_surface_stored_without_public_keeps_todays_rules() {
    let g = ClosedGateway::start(Vec::new()).await;
    let (status, created) = g
        .create(&g.body("/smoke/legacy", "a2a", json!({"public": true})))
        .await;
    assert_eq!(status, 201, "{created}");
    let id = surface_id(&created).to_string();
    let stored_path = std::fs::read_dir(&g.surfaces_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| std::fs::read_to_string(path).is_ok_and(|content| content.contains(&id)))
        .expect("stored surface file");
    let mut stored: Value = serde_json::from_str(&std::fs::read_to_string(&stored_path).unwrap()).unwrap();
    stored["access_point"]
        .as_object_mut()
        .unwrap()
        .remove("public");
    std::fs::write(&stored_path, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();
    let (status, _, _) = g
        .send(
            g.admin
                .post(format!("{}/api/v1/config/reload", g.h.gateway_base)),
        )
        .await;
    assert_eq!(status, 200);

    let (status, _, loaded) = g
        .send(
            g.admin
                .get(format!("{}/{id}", g.surfaces())),
        )
        .await;
    assert_eq!(status, 200, "{loaded}");
    let (status, saved) = g.put(&id, &loaded).await;
    assert_eq!(status, 200, "an update keeps today's rules: {saved}");
    assert!(
        saved["access_point"]
            .get("public")
            .is_none(),
        "{saved}"
    );
    assert!(
        saved
            .get("warnings")
            .is_none(),
        "{saved}"
    );
}
