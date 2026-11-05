//! `GET /v1/surfaces/{id}/agent-card` and `POST .../agent-card/refresh` end to end
//! over the admin API: who may preview and refresh, how each fetch is reported, and
//! the fetch limits.

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use super::helpers::{GatewayHarness, MockServer, RecordingTarget, configure_admin_api};

fn agent_card() -> Value {
    json!({"name": "Orders agent", "url": "http://agent.internal/a2a", "skills": []})
}

struct AdminApi {
    client: reqwest::Client,
    base: String,
    listener: String,
}

impl AdminApi {
    fn url(
        &self,
        path: &str,
    ) -> String {
        format!("{}/api/v1/{path}", self.base)
    }

    async fn send(
        &self,
        request: reqwest::RequestBuilder,
    ) -> (u16, Value, reqwest::header::HeaderMap) {
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let text = response
            .text()
            .await
            .unwrap_or_default();
        (status, serde_json::from_str(&text).unwrap_or(Value::String(text)), headers)
    }

    async fn post(
        &self,
        path: &str,
        body: &Value,
    ) -> Value {
        let (status, created, _) = self
            .send(
                self.client
                    .post(self.url(path))
                    .json(body),
            )
            .await;
        assert!(matches!(status, 200 | 201), "{path}: {status} {created}");
        created
    }

    /// An A2A surface on the harness listener, running unless `status` says otherwise.
    async fn create_surface(
        &self,
        route: &str,
        target: Value,
        extra: Value,
    ) -> String {
        let mut surface = json!({
            "name": route.trim_start_matches('/').replace('/', "-"), "status": "active",
            "access_point": {"listen_address": self.listener, "route": route, "protocol": "a2a", "public": true},
            "target": target
        });
        for (key, value) in extra.as_object().unwrap() {
            surface[key] = value.clone();
        }
        self.post("surfaces", &surface)
            .await["surface_id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn card(
        &self,
        client: &reqwest::Client,
        surface_id: &str,
    ) -> reqwest::RequestBuilder {
        client.get(self.url(&format!("surfaces/{surface_id}/agent-card")))
    }

    fn refresh(
        &self,
        client: &reqwest::Client,
        surface_id: &str,
    ) -> reqwest::RequestBuilder {
        client.post(self.url(&format!("surfaces/{surface_id}/agent-card/refresh")))
    }

    /// The preview once the saved surface is running on its listener.
    async fn running_card(
        &self,
        surface_id: &str,
    ) -> Value {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            let (status, body, _) = self
                .send(
                    self.card(&self.client, surface_id)
                        .header(reqwest::header::COOKIE, "__Host-session_token=management-cookie"),
                )
                .await;
            assert_eq!(status, 200, "{body}");
            if body["unsupported_reason"] != "not_running" {
                return body;
            }
            assert!(tokio::time::Instant::now() < deadline, "{surface_id} never started running");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    /// A personal access token with feature `scopes`, bound to `tenant` and a
    /// resource pattern when given.
    async fn pat(
        &self,
        tenant: Option<(&str, &str)>,
        scopes: &[&str],
    ) -> reqwest::Client {
        let mut request = json!({"name": "card token", "scopes": scopes});
        if let Some((tenant, resource_pattern)) = tenant {
            request["resource_pattern"] = json!(resource_pattern);
            request["required_headers"] = json!([{"name": "x-external-account", "pattern": tenant}]);
        }
        let created = self
            .post("access-tokens", &request)
            .await;
        let mut headers = reqwest::header::HeaderMap::new();
        let mut authorization = reqwest::header::HeaderValue::from_str(&format!(
            "Bearer {}",
            created["token"]
                .as_str()
                .unwrap()
        ))
        .unwrap();
        authorization.set_sensitive(true);
        headers.insert(reqwest::header::AUTHORIZATION, authorization);
        if let Some((tenant, _)) = tenant {
            headers.insert("x-external-account", reqwest::header::HeaderValue::from_str(tenant).unwrap());
        }
        reqwest::Client::builder()
            .no_proxy()
            .default_headers(headers)
            .build()
            .unwrap()
    }
}

async fn admin_harness_with<F>(
    mock: MockServer,
    setup: F,
) -> (GatewayHarness, AdminApi)
where
    F: FnOnce(&mut crate::config::GatewayConfig),
{
    let mut client = None;
    let harness = GatewayHarness::start_with_mock(mock, |_, gw_config, bootstrap| {
        setup(gw_config);
        client = Some(configure_admin_api(bootstrap));
    })
    .await;
    let mut listener = url::Url::parse(&harness.gateway_base).unwrap();
    listener
        .set_host(Some("localhost"))
        .unwrap();
    let admin = AdminApi {
        client: client.unwrap(),
        base: harness.gateway_base.clone(),
        listener: listener
            .origin()
            .ascii_serialization(),
    };
    (harness, admin)
}

async fn admin_harness() -> (GatewayHarness, AdminApi) {
    admin_harness_with(MockServer::start_with_response(agent_card().to_string()).await, |_| {}).await
}

fn fetch_of(preview: &Value) -> (Value, Value, Value) {
    (preview["fetch"]["status"].clone(), preview["fetch"]["cause"].clone(), preview["fetch"]["http_status"].clone())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_running_a2a_surface_is_previewed_as_callers_get_its_card() {
    let (harness, admin) = admin_harness().await;
    let target = json!({"endpoint": harness.mock.url()});
    let surface_id = admin
        .create_surface("/smoke/card-preview", target.clone(), json!({}))
        .await;

    let first = admin
        .running_card(&surface_id)
        .await;
    assert_eq!(first["supported"], true, "{first}");
    assert_eq!(first["surface_id"], surface_id.as_str());
    assert_eq!(fetch_of(&first), (json!("ok"), Value::Null, Value::Null), "{first}");
    assert_eq!((first["cached"].clone(), first["generated"].clone()), (json!(false), json!(false)));
    assert_eq!(first["before"], agent_card());
    assert_eq!(first["auth"]["kind"], "none");
    assert_eq!(first["auth"]["result"], "not_configured");
    for key in ["variant", "outcome", "last_caller_fetch"] {
        assert_eq!(first.get(key), Some(&Value::Null), "{key}");
    }
    let received = harness
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .unwrap();
    assert_eq!(received.path, "/.well-known/agent-card.json");
    assert!(
        !received
            .headers
            .contains_key("authorization")
            && !received
                .headers
                .contains_key("cookie"),
        "the management request's credentials never reach the agent: {:?}",
        received.headers
    );

    let (status, refreshed, _) = admin
        .send(admin.refresh(&admin.client, &surface_id))
        .await;
    assert_eq!(status, 200, "{refreshed}");
    assert_eq!(refreshed["cached"], false, "a refresh fetches again");
    let served: Value = reqwest::Client::new()
        .get(format!("{}/smoke/card-preview/.well-known/agent-card.json", harness.gateway_base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(refreshed["after"], served, "after is what the card route serves");
    assert_eq!(refreshed["served_url"], format!("{}/smoke/card-preview/.well-known/agent-card.json", admin.listener));

    let mcp_id = admin
        .create_surface("/smoke/card-preview-mcp", target.clone(), json!({}))
        .await;
    admin
        .send(
            admin
                .client
                .patch(admin.url(&format!("surfaces/{mcp_id}")))
                .header("Content-Type", "application/merge-patch+json")
                .json(&json!({"access_point": {"protocol": "mcp"}})),
        )
        .await;
    let off_id = admin
        .create_surface("/smoke/card-preview-off", target, json!({"status": "disabled"}))
        .await;
    for (id, reason) in [(&mcp_id, "not_a2a"), (&off_id, "not_running")] {
        let (status, preview, _) = admin
            .send(admin.card(&admin.client, id))
            .await;
        assert_eq!(status, 200, "{preview}");
        assert_eq!(preview["supported"], false, "{preview}");
        assert_eq!(preview["unsupported_reason"], reason, "{preview}");
        assert_eq!((preview["fetch"].clone(), preview["after"].clone()), (Value::Null, Value::Null));
    }

    for request in [admin.card(&admin.client, "no-such-surface"), admin.refresh(&admin.client, "no-such-surface")] {
        assert_eq!(admin.send(request).await.0, 404);
    }
    let anonymous = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap();
    for request in [admin.card(&anonymous, &surface_id), admin.refresh(&anonymous, &surface_id)] {
        let (status, body, _) = admin.send(request).await;
        assert_eq!(status, 401, "{body}");
        assert!(body.get("after").is_none(), "{body}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tenants_see_only_their_own_cards_and_refresh_needs_edit() {
    let (harness, admin) = admin_harness().await;
    let target = json!({"endpoint": harness.mock.url()});
    let tenant_id = admin
        .create_surface("/smoke/card-tenant", target.clone(), json!({"tenant_id": "tenant-a"}))
        .await;
    let other_tenant = admin
        .pat(Some(("tenant-b", "TENANT:${x-external-account}:surfaces:.*")), &[])
        .await;
    for request in [admin.card(&other_tenant, &tenant_id), admin.refresh(&other_tenant, &tenant_id)] {
        let (status, body, _) = admin.send(request).await;
        assert_eq!(status, 404, "another tenant finds no surface: {body}");
        assert!(body.get("after").is_none() && body.get("fetch").is_none(), "{body}");
    }
    let owner = admin
        .pat(Some(("tenant-a", "TENANT:${x-external-account}:surfaces:.*")), &[])
        .await;
    admin
        .running_card(&tenant_id)
        .await;
    for request in [admin.card(&owner, &tenant_id), admin.refresh(&owner, &tenant_id)] {
        let (status, body, _) = admin.send(request).await;
        assert_eq!(status, 200, "the owning tenant reads and refreshes its card: {body}");
        assert_eq!(body["supported"], true, "{body}");
    }

    let appliance_id = admin
        .create_surface("/smoke/card-appliance", target, json!({}))
        .await;
    admin
        .running_card(&appliance_id)
        .await;
    let requests = harness
        .mock
        .request_count
        .load(Ordering::SeqCst);
    let (status, body, _) = admin
        .send(admin.card(&owner, &appliance_id))
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["unsupported_reason"], "operator_only", "{body}");
    for field in ["before", "after", "auth", "fetch"] {
        assert_eq!(body[field], Value::Null, "a tenant sees no {field} of an appliance-wide card: {body}");
    }
    assert_eq!(
        harness
            .mock
            .request_count
            .load(Ordering::SeqCst),
        requests,
        "a tenant's read of an appliance-wide card fetches nothing"
    );
    let (status, body, _) = admin
        .send(admin.refresh(&owner, &appliance_id))
        .await;
    assert_eq!(status, 403, "a tenant never refreshes an appliance-wide card: {body}");

    let viewer = admin
        .pat(None, &["surfaces.view"])
        .await;
    let (status, body, _) = admin
        .send(admin.card(&viewer, &appliance_id))
        .await;
    assert_eq!(status, 200, "surfaces.view reads the card: {body}");
    assert_eq!(body["before"], agent_card(), "{body}");
    let (status, body, _) = admin
        .send(admin.refresh(&viewer, &appliance_id))
        .await;
    assert_eq!(status, 403, "only surfaces.edit refreshes: {body}");

    let editor = admin
        .pat(None, &["surfaces.view", "surfaces.edit"])
        .await;
    let (status, body, _) = admin
        .send(admin.refresh(&editor, &appliance_id))
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["surface_id"], appliance_id.as_str());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_eleventh_refresh_is_refused_and_a_read_answers_with_the_last_preview() {
    let (answering, answer) = MockServer::start_with_response_channel(agent_card().to_string()).await;
    let (_harness, admin) = admin_harness().await;
    let surface_id = admin
        .create_surface("/smoke/card-limit", json!({"endpoint": answering.url()}), json!({}))
        .await;
    let good = admin
        .running_card(&surface_id)
        .await;
    assert_eq!(fetch_of(&good).0, "ok", "{good}");

    answer
        .send("not a card".into())
        .unwrap();
    let (status, failed, _) = admin
        .send(admin.refresh(&admin.client, &surface_id))
        .await;
    assert_eq!(status, 200, "a failed fetch is still a 200: {failed}");
    assert_eq!(fetch_of(&failed), (json!("failed"), json!("invalid_card"), Value::Null));
    assert_eq!(failed["after"], good["after"], "the last good card stays on screen");
    assert_eq!((failed["before"].clone(), failed["cached"].clone()), (Value::Null, json!(false)));

    for attempt in 3..=crate::proxy::card_preview::FETCHES_PER_MINUTE.get() {
        let (status, body, _) = admin
            .send(admin.refresh(&admin.client, &surface_id))
            .await;
        assert_eq!(status, 200, "fetch {attempt}: {body}");
    }
    let (status, body, headers) = admin
        .send(admin.refresh(&admin.client, &surface_id))
        .await;
    assert_eq!(status, 429, "{body}");
    assert_eq!(body, json!({"error": "Too many card fetches; try again in a few seconds", "code": "rate_limited"}));
    let retry_after: u64 = headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .expect("a numeric Retry-After");
    assert!((1..=6).contains(&retry_after), "Retry-After is {retry_after}, not the 60 of a full minute");
    let requests = answering
        .request_count
        .load(Ordering::SeqCst);

    let (status, cached, _) = admin
        .send(admin.card(&admin.client, &surface_id))
        .await;
    assert_eq!(status, 200, "{cached}");
    assert_eq!(cached["cached"], true, "{cached}");
    assert_eq!(fetch_of(&cached).1, "invalid_card");
    assert_eq!(
        answering
            .request_count
            .load(Ordering::SeqCst),
        requests,
        "a limited read fetches nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_static_secret_is_sent_and_an_unanswered_token_is_reported() {
    let (harness, admin) = admin_harness().await;
    admin
        .post(
            "secrets/new",
            &json!({"name": "CARD_STATIC_KEY", "secret_id": "CARD_STATIC_KEY", "value": "static-value"}),
        )
        .await;
    let unauthorized = RecordingTarget::start(axum::http::StatusCode::UNAUTHORIZED, &[]).await;
    let cases = [
        (
            "/smoke/card-static",
            json!({"endpoint": harness.mock.url(), "auth": {"method": {"static_secret": {
                "secret_id": "CARD_STATIC_KEY", "header_name": "x-agent-key"}}}}),
            ("static_secret", "sent"),
            (json!("ok"), Value::Null, Value::Null),
            Some(("x-agent-key", "static-value")),
        ),
        (
            "/smoke/card-needs-token",
            json!({"endpoint": unauthorized.url}),
            ("none", "not_configured"),
            (json!("failed"), json!("needs_token"), json!(401)),
            None,
        ),
    ];
    for (route, target, (kind, result), fetch, header) in cases {
        let surface_id = admin
            .create_surface(route, target, json!({}))
            .await;
        let preview = admin
            .running_card(&surface_id)
            .await;
        assert_eq!(fetch_of(&preview), fetch, "{route}: {preview}");
        assert_eq!(
            (preview["auth"]["kind"].clone(), preview["auth"]["result"].clone()),
            (json!(kind), json!(result)),
            "{route}: {preview}"
        );
        assert_eq!(
            (preview["auth"]["provider_name"].clone(), preview["auth"]["token_expires_at"].clone()),
            (Value::Null, Value::Null)
        );
        let text = preview.to_string();
        assert!(!text.contains("static-value"), "{route}: {text}");
        if let Some((name, value)) = header {
            let received = harness
                .mock
                .last_request_rx
                .borrow()
                .clone()
                .unwrap();
            assert_eq!(
                received
                    .headers
                    .get(name)
                    .map(String::as_str),
                Some(value),
                "{route}"
            );
        }
    }
    assert_eq!(unauthorized.received().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_card_over_the_body_limit_is_too_large_while_a_smaller_card_is_shown() {
    let card = json!({"name": "x".repeat(2048)});
    let (harness, admin) = admin_harness_with(MockServer::start_with_response(card.to_string()).await, |config| {
        config.a2a.max_body_size = 1024;
    })
    .await;
    let small = MockServer::start_with_response(agent_card().to_string()).await;
    let large_id = admin
        .create_surface("/smoke/card-large", json!({"endpoint": harness.mock.url()}), json!({}))
        .await;
    let small_id = admin
        .create_surface("/smoke/card-small", json!({"endpoint": small.url()}), json!({}))
        .await;

    let large = admin
        .running_card(&large_id)
        .await;
    assert_eq!(fetch_of(&large), (json!("failed"), json!("too_large"), Value::Null), "{large}");
    assert_eq!((large["before"].clone(), large["after"].clone()), (Value::Null, Value::Null));
    let small = admin
        .running_card(&small_id)
        .await;
    assert_eq!(fetch_of(&small).0, "ok", "{small}");
}
