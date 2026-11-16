//! New Access Points are closed: a closed Access Point without caller
//! authentication saves with a `Warning` header but is not ready, and refuses every
//! request with `503`, discovery reads included. Once it has caller
//! authentication it refuses a caller whose credential is missing or invalid
//! with `401`, in the caller's protocol shape, before policy and the Target,
//! and public discovery reads stay open. A legacy surface (no
//! `access_point.public`) refuses a failed caller too, and admits every caller
//! when it has no caller authentication.

use super::helpers::{
    GatewayHarness, MockServer, build_minimal_channel, configure_admin_api, configure_gateway_route_prefixes,
    write_api_key_secret,
};
use crate::config::agent_surface::{
    ACCESS_POINT_NOT_READY_WARNING, LEGACY_OPEN_ACCESS_POINT_WARNING, PUBLIC_ACCESS_POINT_WARNING,
};
use crate::source_auth::errors::{ACCESS_POINT_UNAVAILABLE, CALLER_CREDENTIAL_REFUSED};
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
    ) -> (u16, Vec<String>, Value) {
        let (status, headers, body) = self
            .send(
                self.admin
                    .post(self.surfaces())
                    .json(body),
            )
            .await;
        (status, warning_messages(&headers), body)
    }

    async fn put(
        &self,
        surface_id: &str,
        body: &Value,
    ) -> (u16, Vec<String>, Value) {
        let (status, headers, body) = self
            .send(
                self.admin
                    .put(format!("{}/{surface_id}", self.surfaces()))
                    .json(body),
            )
            .await;
        (status, warning_messages(&headers), body)
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

    async fn get(
        &self,
        path: &str,
    ) -> (u16, Value) {
        let (status, _, body) = self
            .send(
                self.admin
                    .get(format!("{}{path}", self.surfaces())),
            )
            .await;
        (status, body)
    }

    async fn patch(
        &self,
        url: &str,
        patch: &Value,
    ) -> (u16, Vec<String>, Value) {
        let (status, headers, body) = self
            .send(
                self.admin
                    .patch(url)
                    .header("content-type", "application/merge-patch+json")
                    .json(patch),
            )
            .await;
        (status, warning_messages(&headers), body)
    }

    /// Rewrites the stored file of surface `id` as an operator editing the
    /// store by hand would, and reloads the gateway's configuration.
    async fn edit_stored_surface(
        &self,
        id: &str,
        edit: impl FnOnce(&mut Value),
    ) {
        let stored_path = std::fs::read_dir(&self.surfaces_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| std::fs::read_to_string(path).is_ok_and(|content| content.contains(id)))
            .expect("stored surface file");
        let mut stored: Value = serde_json::from_str(&std::fs::read_to_string(&stored_path).unwrap()).unwrap();
        edit(&mut stored);
        std::fs::write(&stored_path, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();
        let (status, _, _) = self
            .send(
                self.admin
                    .post(format!("{}/api/v1/config/reload", self.h.gateway_base)),
            )
            .await;
        assert_eq!(status, 200);
    }

    fn reached(&self) -> usize {
        self.h
            .mock
            .request_count
            .load(Ordering::SeqCst)
    }
}

fn assert_unavailable_problem(
    status: u16,
    headers: &reqwest::header::HeaderMap,
    body: &Value,
    context: &str,
) {
    assert_eq!(status, 503, "{context}: {body}");
    assert_eq!(headers["content-type"], "application/problem+json", "{context}");
    assert_eq!(body["detail"], ACCESS_POINT_UNAVAILABLE, "{context}: the refusal never says why: {body}");
    assert_eq!(body["status"], 503, "{context}");
}

/// The messages of a response's `Warning` headers (`299 - "<message>"`).
fn warning_messages(headers: &reqwest::header::HeaderMap) -> Vec<String> {
    headers
        .get_all(reqwest::header::WARNING)
        .iter()
        .map(|value| {
            let value = value
                .to_str()
                .expect("a visible-ASCII Warning header");
            value
                .strip_prefix("299 - \"")
                .and_then(|quoted| quoted.strip_suffix('"'))
                .unwrap_or_else(|| panic!("a 299 Warning header: {value}"))
                .replace("\\\"", "\"")
                .replace("\\\\", "\\")
        })
        .collect()
}

fn surface_id(surface: &Value) -> &str {
    surface["surface_id"]
        .as_str()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_surface_without_caller_authentication_is_created_not_ready_and_refuses_every_caller() {
    let gateway = ClosedGateway::start(Vec::new()).await;

    let (status, warnings, created) = gateway
        .create(&gateway.body("/smoke/unsecured", "a2a", json!({})))
        .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["access_point"]["public"], false);
    assert_eq!(created["access_point_status"], "not_ready");
    assert_eq!(warnings, [ACCESS_POINT_NOT_READY_WARNING]);
    assert!(
        created
            .get("warnings")
            .is_none(),
        "warnings are Warning headers: {created}"
    );
    assert!(
        created["access_point"]
            .get("access_point_status")
            .is_none(),
        "{created}"
    );
    let id = surface_id(&created).to_string();
    let (status, _, emptied) = gateway
        .create(&gateway.body(
            "/smoke/emptied",
            "a2a",
            json!({"public": false, "caller_authentication": {"methods": []}}),
        ))
        .await;
    assert_eq!(status, 201, "{emptied}");
    assert_eq!(emptied["access_point_status"], "not_ready");

    let (status, read) = gateway
        .get(&format!("/{id}"))
        .await;
    assert_eq!(status, 200, "{read}");
    assert_eq!(read["access_point_status"], "not_ready");
    let (status, listed) = gateway.get("").await;
    assert_eq!(status, 200, "{listed}");
    let listed = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|surface| surface["surface_id"] == id.as_str())
        .cloned()
        .unwrap();
    assert_eq!(listed["access_point_status"], "not_ready");

    let (status, headers, body) = gateway
        .call("/smoke/unsecured", &a2a_request(), None)
        .await;
    assert_unavailable_problem(status, &headers, &body, "a call");
    for path in ["/.well-known/agent-card.json", "/.well-known/agent.json", "/agent-card.json"] {
        let response = reqwest::Client::new()
            .get(format!("{}/smoke/unsecured{path}", gateway.h.gateway_base))
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response
            .json()
            .await
            .unwrap_or(Value::Null);
        assert_unavailable_problem(status, &headers, &body, path);
    }
    assert_eq!(gateway.reached(), 0, "a not-ready Access Point never reaches the Target");

    let (status, warnings, saved) = gateway
        .put(&id, &created)
        .await;
    assert_eq!(status, 200, "a save response can be sent back as it is: {saved}");
    assert_eq!(warnings, [ACCESS_POINT_NOT_READY_WARNING], "the warning is on every save");
    assert_eq!(saved["access_point_status"], "not_ready");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_public_surface_is_ready_and_admits_callers_without_credentials() {
    let gateway = ClosedGateway::start(Vec::new()).await;

    let (status, warnings, created) = gateway
        .create(&gateway.body("/smoke/public", "a2a", json!({"public": true})))
        .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["access_point"]["public"], true);
    assert_eq!(created["access_point_status"], "ready");
    assert_eq!(warnings, [PUBLIC_ACCESS_POINT_WARNING]);

    let (status, _, _) = gateway
        .call("/smoke/public", &a2a_request(), None)
        .await;
    assert_eq!(status, 200);
    assert_eq!(gateway.reached(), 1, "a public Access Point forwards a caller without credentials");

    let (status, warnings, saved) = gateway
        .put(surface_id(&created), &created)
        .await;
    assert_eq!(status, 200, "a save response can be sent back as it is: {saved}");
    assert_eq!(warnings, [PUBLIC_ACCESS_POINT_WARNING], "the warning is on every save");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_not_ready_mcp_access_point_refuses_with_a_json_rpc_error_carrying_the_request_id() {
    let gateway = ClosedGateway::start(Vec::new()).await;
    let (status, _, created) = gateway
        .create(&gateway.body("/smoke/unsecured-mcp", "mcp", json!({})))
        .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["access_point_status"], "not_ready");
    let tools_list = json!({"jsonrpc": "2.0", "id": "unready-1", "method": "tools/list", "params": {}});

    for key in [None, Some(VALID_KEY)] {
        let (status, _, body) = gateway
            .call("/smoke/unsecured-mcp", &tools_list, key)
            .await;
        assert_eq!(status, 503, "{key:?}: {body}");
        assert_eq!(
            body,
            json!({"jsonrpc": "2.0", "id": "unready-1", "error": {
                "code": crate::mcp::errors::error_codes::INTERNAL_ERROR, "message": ACCESS_POINT_UNAVAILABLE
            }})
        );
    }
    assert_eq!(gateway.reached(), 0, "a not-ready Access Point never reaches the Target");
}

#[tokio::test(flavor = "multi_thread")]
async fn adding_caller_authentication_makes_a_not_ready_access_point_ready() {
    let gateway = ClosedGateway::start(Vec::new()).await;
    let (status, _, created) = gateway
        .create(&gateway.body("/smoke/later", "a2a", json!({})))
        .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["access_point_status"], "not_ready");

    let mut secured = created.clone();
    secured["access_point"]["caller_authentication"] = api_key_authentication();
    let (status, warnings, saved) = gateway
        .put(surface_id(&created), &secured)
        .await;
    assert_eq!(status, 200, "{saved}");
    assert_eq!(saved["access_point_status"], "ready");
    assert_eq!(saved["access_point"]["caller_authentication"]["on_failure"], "reject");
    assert_eq!(warnings, Vec::<String>::new());

    let (status, _, body) = gateway
        .call("/smoke/later", &a2a_request(), Some(VALID_KEY))
        .await;
    assert_eq!(status, 200, "a valid caller is served with no other step: {body}");
    assert_eq!(gateway.reached(), 1);
    let (status, _, body) = gateway
        .call("/smoke/later", &a2a_request(), None)
        .await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["detail"], CALLER_CREDENTIAL_REFUSED);
    assert_eq!(gateway.reached(), 1, "a refused caller never reaches the Target");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_closed_surface_stored_without_caller_authentication_refuses_every_caller() {
    let gateway = ClosedGateway::start(Vec::new()).await;
    let (status, _, created) = gateway
        .create(&gateway.body("/smoke/hand-edited", "a2a", json!({"caller_authentication": api_key_authentication()})))
        .await;
    assert_eq!(status, 201, "{created}");

    gateway
        .edit_stored_surface(surface_id(&created), |stored| {
            stored["access_point"]
                .as_object_mut()
                .unwrap()
                .remove("caller_authentication");
            assert_eq!(stored["access_point"]["public"], false);
        })
        .await;
    // The reload reaches the listener asynchronously; until then the stored
    // API key still refuses a caller without one.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while gateway
        .call("/smoke/hand-edited", &a2a_request(), None)
        .await
        .0
        == 401
        && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    for key in [None, Some(VALID_KEY)] {
        let (status, headers, body) = gateway
            .call("/smoke/hand-edited", &a2a_request(), key)
            .await;
        assert_unavailable_problem(status, &headers, &body, &format!("{key:?}"));
    }
    assert_eq!(gateway.reached(), 0, "a store edited by hand never opens a closed Access Point");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_closed_a2a_access_point_refuses_a_missing_or_wrong_key_before_the_target() {
    let gateway = ClosedGateway::start(Vec::new()).await;
    let (status, warnings, created) = gateway
        .create(&gateway.body("/smoke/closed", "a2a", json!({"caller_authentication": api_key_authentication()})))
        .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["access_point"]["public"], false);
    assert_eq!(created["access_point"]["caller_authentication"]["on_failure"], "reject");
    assert_eq!(warnings, Vec::<String>::new());

    for key in [None, Some("wrong-key")] {
        let (status, headers, body) = gateway
            .call("/smoke/closed", &a2a_request(), key)
            .await;
        assert_eq!(status, 401, "{key:?}: {body}");
        assert_eq!(headers["content-type"], "application/problem+json");
        assert_eq!(body["detail"], CALLER_CREDENTIAL_REFUSED, "the refusal never says why: {body}");
        assert_eq!(body["status"], 401);
        assert_eq!(gateway.reached(), 0, "a refused caller never reaches the Target");
    }

    let (status, _, body) = gateway
        .call("/smoke/closed", &a2a_request(), Some(VALID_KEY))
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(gateway.reached(), 1, "a valid caller reaches the Target");

    for path in ["/.well-known/agent-card.json", "/.well-known/agent.json", "/agent-card.json"] {
        let response = reqwest::Client::new()
            .get(format!("{}/smoke/closed{path}", gateway.h.gateway_base))
            .send()
            .await
            .unwrap();
        assert_ne!(response.status(), 401, "a discovery read of {path} is not refused for missing credentials");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_closed_mcp_access_point_refuses_with_a_json_rpc_error_carrying_the_request_id() {
    let gateway = ClosedGateway::start(Vec::new()).await;
    let (status, _, created) = gateway
        .create(&gateway.body("/smoke/closed-mcp", "mcp", json!({"caller_authentication": api_key_authentication()})))
        .await;
    assert_eq!(status, 201, "{created}");
    let tools_list = json!({"jsonrpc": "2.0", "id": "closed-1", "method": "tools/list", "params": {}});

    for path in ["/smoke/closed-mcp", "/smoke/closed-mcp/agent.json"] {
        for key in [None, Some("wrong-key")] {
            let (status, _, body) = gateway
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
    assert_eq!(gateway.reached(), 0, "a refused caller never reaches the Target");
}

#[tokio::test(flavor = "multi_thread")]
async fn removing_caller_authentication_from_a_closed_surface_makes_it_not_ready() {
    let gateway = ClosedGateway::start(Vec::new()).await;
    let (status, _, created) = gateway
        .create(&gateway.body("/smoke/kept-closed", "a2a", json!({"caller_authentication": api_key_authentication()})))
        .await;
    assert_eq!(status, 201, "{created}");
    let id = surface_id(&created).to_string();

    let mut without_public = created.clone();
    without_public["access_point"]
        .as_object_mut()
        .unwrap()
        .remove("public");
    without_public["access_point"]["caller_authentication"]["on_failure"] = json!("continue");
    let (status, _, saved) = gateway
        .put(&id, &without_public)
        .await;
    assert_eq!(status, 200, "{saved}");
    assert_eq!(saved["access_point"]["public"], false, "a PUT that drops public keeps it");
    assert_eq!(saved["access_point"]["caller_authentication"]["on_failure"], "reject");

    let mut dropped = created.clone();
    let access_point = dropped["access_point"]
        .as_object_mut()
        .unwrap();
    access_point.remove("public");
    access_point.remove("caller_authentication");
    let (status, warnings, saved) = gateway
        .put(&id, &dropped)
        .await;
    assert_eq!(status, 200, "{saved}");
    assert_eq!(saved["access_point"]["public"], false, "it is never reopened");
    assert_eq!(saved["access_point_status"], "not_ready");
    assert_eq!(warnings, [ACCESS_POINT_NOT_READY_WARNING]);

    for key in [None, Some(VALID_KEY)] {
        let (status, headers, body) = gateway
            .call("/smoke/kept-closed", &a2a_request(), key)
            .await;
        assert_unavailable_problem(status, &headers, &body, &format!("{key:?}"));
    }
    assert_eq!(gateway.reached(), 0, "a not-ready Access Point never reaches the Target");

    let (status, _, patched) = gateway
        .patch(&format!("{}/{id}", gateway.surfaces()), &json!({"access_point": {"public": null}}))
        .await;
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["access_point"]["public"], false, "a PATCH that clears public keeps it");
    assert_eq!(patched["access_point_status"], "not_ready");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_closed_surface_saved_as_public_admits_callers_without_credentials() {
    let gateway = ClosedGateway::start(Vec::new()).await;
    let (status, _, created) = gateway
        .create(&gateway.body("/smoke/opened", "a2a", json!({"caller_authentication": api_key_authentication()})))
        .await;
    assert_eq!(status, 201, "{created}");
    let id = surface_id(&created).to_string();

    let mut opened = created.clone();
    opened["access_point"]["public"] = json!(true);
    let (status, warnings, saved) = gateway
        .put(&id, &opened)
        .await;
    assert_eq!(status, 200, "{saved}");
    assert!(
        saved["access_point"]["caller_authentication"]
            .get("on_failure")
            .is_none(),
        "a public Access Point continues a failed caller, whatever was sent: {saved}"
    );
    assert_eq!(warnings, [PUBLIC_ACCESS_POINT_WARNING]);

    for key in [None, Some("wrong-key")] {
        let (status, _, body) = gateway
            .call("/smoke/opened", &a2a_request(), key)
            .await;
        assert_eq!(status, 200, "{key:?}: {body}");
    }
    assert_eq!(gateway.reached(), 2, "a public Access Point forwards a caller without credentials");

    let mut closed = saved.clone();
    closed["access_point"]["public"] = json!(false);
    let (status, _, saved) = gateway
        .put(&id, &closed)
        .await;
    assert_eq!(status, 200, "{saved}");
    assert_eq!(saved["access_point"]["caller_authentication"]["on_failure"], "reject");
    let (status, _, _) = gateway
        .call("/smoke/opened", &a2a_request(), None)
        .await;
    assert_eq!(status, 401, "turning Public access off closes it again");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_variant_without_caller_authentication_is_not_ready_while_the_base_stays_ready() {
    let gateway = ClosedGateway::start(Vec::new()).await;
    let (status, _, created) = gateway
        .create(&gateway.body("/smoke/variant", "a2a", json!({"caller_authentication": api_key_authentication()})))
        .await;
    assert_eq!(status, 201, "{created}");
    let id = surface_id(&created).to_string();
    let variants = format!("{}/{id}/variants", gateway.surfaces());

    let (status, _, variant) = gateway
        .send(
            gateway
                .admin
                .post(&variants)
                .json(&json!({"alias": "beta", "name": "Beta"})),
        )
        .await;
    assert_eq!(status, 201, "a variant that keeps the base caller authentication is accepted: {variant}");
    assert_eq!(variant["access_point_status"], "ready", "{variant}");
    let variant_url = format!(
        "{variants}/{}",
        variant["id"]
            .as_str()
            .unwrap()
    );

    let (status, warnings, saved) = gateway
        .patch(&variant_url, &json!({"enabled": true, "overrides": {"complete": true, "access_point": {}}}))
        .await;
    assert_eq!(status, 200, "{saved}");
    assert_eq!(warnings, [format!("variant 'beta': {ACCESS_POINT_NOT_READY_WARNING}")]);
    assert_eq!(saved["access_point_status"], "ready", "the base stays ready");
    let (status, _, updated) = gateway
        .send(
            gateway
                .admin
                .put(&variant_url)
                .json(&json!({"name": "Beta"})),
        )
        .await;
    assert_eq!(status, 200, "{updated}");
    assert_eq!(updated["access_point_status"], "not_ready", "a variant response reports that variant: {updated}");
    let (status, resolved) = gateway
        .get(&format!("/{id}/variants/beta/resolved"))
        .await;
    assert_eq!(status, 200, "{resolved}");
    assert_eq!(resolved["access_point_status"], "not_ready");

    let (status, headers, body) = gateway
        .call("/smoke/variant$beta", &a2a_request(), Some(VALID_KEY))
        .await;
    assert_unavailable_problem(status, &headers, &body, "the variant");
    assert_eq!(gateway.reached(), 0);
    let (status, _, body) = gateway
        .call("/smoke/variant", &a2a_request(), Some(VALID_KEY))
        .await;
    assert_eq!(status, 200, "the base still serves a valid caller: {body}");
    assert_eq!(gateway.reached(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_legacy_surface_refuses_a_failed_caller_and_admits_any_caller_without_caller_authentication() {
    let mut open = build_minimal_channel();
    open.surface_id = "legacy-open".to_string();
    open.access_point.route = "/legacy-open".to_string();
    let mut keyed = build_minimal_channel();
    keyed.surface_id = "legacy-keyed".to_string();
    keyed.access_point.route = "/legacy-keyed".to_string();
    keyed
        .access_point
        .caller_authentication = serde_json::from_value(api_key_authentication()).unwrap();
    let gateway = ClosedGateway::start(vec![open, keyed]).await;

    let (status, _, _) = gateway
        .call("/legacy-open/rpc", &a2a_request(), None)
        .await;
    assert_eq!(status, 200);
    let (status, _, _) = gateway
        .call("/legacy-keyed/rpc", &a2a_request(), Some("wrong-key"))
        .await;
    assert_eq!(status, 401, "a failed caller is refused, as on a closed Access Point");
    assert_eq!(gateway.reached(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_update_of_a_legacy_surface_keeps_the_legacy_rules() {
    let gateway = ClosedGateway::start(Vec::new()).await;
    let (status, _, created) = gateway
        .create(&gateway.body("/smoke/legacy", "a2a", json!({"public": true})))
        .await;
    assert_eq!(status, 201, "{created}");
    let id = surface_id(&created).to_string();
    gateway
        .edit_stored_surface(&id, |stored| {
            stored["access_point"]
                .as_object_mut()
                .unwrap()
                .remove("public");
        })
        .await;

    let (status, _, loaded) = gateway
        .send(
            gateway
                .admin
                .get(format!("{}/{id}", gateway.surfaces())),
        )
        .await;
    assert_eq!(status, 200, "{loaded}");
    let (status, warnings, saved) = gateway
        .put(&id, &loaded)
        .await;
    assert_eq!(status, 200, "an update keeps the legacy rules: {saved}");
    assert!(
        saved["access_point"]
            .get("public")
            .is_none(),
        "{saved}"
    );
    assert_eq!(warnings, [LEGACY_OPEN_ACCESS_POINT_WARNING], "a legacy surface that admits every caller says so");
}
