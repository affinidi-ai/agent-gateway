//! An Access Point with more than one caller authentication method, proven at
//! the wire: each request is verified by the method whose credential it
//! carries, a request carrying several credentials fails, and no method's
//! credential reaches the target.

use super::helpers::jwt::{JwksFixture, now_secs, sign_jwt, write_jwt_strategy};
use super::helpers::{self, GatewayHarness, RecordingTarget, write_api_key_secret};
use axum::http::StatusCode;
use serde_json::json;

const API_KEY_SECRET_ID: &str = "multi-method-source-key";
const API_KEY: &str = "partner-key";
const DENY_FAILED_POLICY_ID: &str = "deny-failed-source-auth";
const API_KEY_ONLY_POLICY_ID: &str = "allow-api-key-callers";

fn write_policy(
    temp_dir: &std::path::Path,
    id: &str,
    description: &str,
    policy: &str,
) {
    let dir = temp_dir.join("policy_definitions");
    std::fs::create_dir_all(&dir).expect("create policy_definitions dir");
    let definition = json!({
        "id": id,
        "name": id,
        "description": description,
        "policy_type": "agent_surface",
        "policy": policy,
        "enabled": true,
        "created_at": "2026-01-01T00:00:00Z"
    });
    std::fs::write(
        dir.join(format!("{id}.json")),
        serde_json::to_string_pretty(&definition).expect("serialize policy definition"),
    )
    .expect("write policy definition fixture");
}

fn write_policies(temp_dir: &std::path::Path) {
    write_policy(
        temp_dir,
        DENY_FAILED_POLICY_ID,
        "Refuses callers whose source authentication failed",
        "package surface.policy\n\ndefault allow := false\n\nallow if not deny\n\ndeny if input.source_auth.method == \"failed\"\n",
    );
    write_policy(
        temp_dir,
        API_KEY_ONLY_POLICY_ID,
        "Admits only callers an API key method verified",
        "package surface.policy\n\ndefault allow := false\n\nallow if input.source_auth.method == \"api_key\"\n",
    );
}

fn jwt_method(
    strategy_id: &str,
    forward_header: bool,
) -> serde_json::Value {
    json!({
        "type": "jwt_bearer",
        "jwt_verification_strategy_id": strategy_id,
        "audiences": [],
        "forward_header": forward_header
    })
}

fn api_key_method() -> serde_json::Value {
    json!({
        "type": "api_key",
        "extraction": { "source": "http_header", "field": "x-api-key" },
        "secret_id": API_KEY_SECRET_ID
    })
}

async fn start_gateway(
    fixture: &JwksFixture,
    target: &RecordingTarget,
    methods: impl Fn(&str) -> serde_json::Value,
    policy: Option<&'static str>,
) -> GatewayHarness {
    let target_url = target.url.clone();
    GatewayHarness::start(move |temp_dir, gw_config, bootstrap| {
        let strategy_id = write_jwt_strategy(fixture, temp_dir);
        write_api_key_secret(
            &bootstrap
                .storage_paths
                .secrets,
            API_KEY_SECRET_ID,
            API_KEY,
        );
        write_policies(temp_dir);
        let mut surface = helpers::build_minimal_channel();
        surface
            .access_point
            .caller_authentication =
            Some(serde_json::from_value(json!({ "methods": methods(strategy_id) })).expect("caller authentication"));
        surface.target.endpoint = target_url.clone();
        surface.target.policy = policy.map(|id| crate::config::agent_surface::PolicyRef {
            policy_definition_id: id.to_string(),
            require_agent_context: false,
        });
        gw_config.surfaces = vec![surface];
    })
    .await
}

fn valid_jwt(issuer: &str) -> String {
    sign_jwt(
        json!({
            "iss": issuer,
            "sub": "internal-user",
            "aud": "any",
            "exp": now_secs() + 300,
            "iat": now_secs(),
        }),
        "e2e-test-key",
    )
}

async fn send(
    h: &GatewayHarness,
    headers: &[(&str, String)],
) -> u16 {
    let mut request = reqwest::Client::new()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","method":"message/send","id":1,"params":{"message":{"role":"user","messageId":"m1","parts":[{"kind":"text","text":"hi"}]}}}"#);
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    request
        .send()
        .await
        .expect("inbound request failed")
        .status()
        .as_u16()
}

#[tokio::test(flavor = "multi_thread")]
async fn each_caller_authenticates_with_the_method_its_credential_belongs_to() {
    let fixture = JwksFixture::start().await;
    let target = RecordingTarget::start(StatusCode::OK, &[]).await;
    let h = start_gateway(
        &fixture,
        &target,
        |strategy_id| json!([jwt_method(strategy_id, false), api_key_method()]),
        Some(DENY_FAILED_POLICY_ID),
    )
    .await;
    let jwt = format!("Bearer {}", valid_jwt(&fixture.issuer));

    assert_eq!(send(&h, &[("authorization", jwt.clone())]).await, 200, "a JWT caller is authenticated");
    assert_eq!(send(&h, &[("x-api-key", API_KEY.to_string())]).await, 200, "an API-key caller is authenticated");
    assert_eq!(send(&h, &[]).await, 403, "a caller with no credential fails source auth");
    assert_eq!(send(&h, &[("x-api-key", "wrong".to_string())]).await, 403, "a wrong API key fails source auth");
    assert_eq!(
        send(&h, &[("authorization", "Bearer not-a-jwt".to_string()), ("x-api-key", API_KEY.to_string())]).await,
        403,
        "a valid API key does not rescue a request whose JWT fails"
    );
    assert_eq!(
        send(&h, &[("authorization", jwt), ("x-api-key", API_KEY.to_string())]).await,
        403,
        "a caller presenting two valid credentials fails, so it can't choose the identity"
    );
    assert_eq!(
        send(&h, &[("authorization", "Payment cred".to_string()), ("x-api-key", API_KEY.to_string())]).await,
        200,
        "an Authorization value in another scheme, such as an MPP payment, is not the JWT credential"
    );

    let received = target.received();
    assert_eq!(received.len(), 3, "only authenticated callers are forwarded");
    for sent in &received {
        assert!(!sent.contains_key("authorization"), "{sent:?}");
        assert!(!sent.contains_key("x-api-key"), "{sent:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forwarded_jwt_reaches_the_target_only_when_the_jwt_method_verified_the_request() {
    let fixture = JwksFixture::start().await;
    let target = RecordingTarget::start(StatusCode::OK, &[]).await;
    let h =
        start_gateway(&fixture, &target, |strategy_id| json!([api_key_method(), jwt_method(strategy_id, true)]), None)
            .await;
    let jwt = format!("Bearer {}", valid_jwt(&fixture.issuer));

    assert_eq!(send(&h, &[("authorization", jwt.clone())]).await, 200);
    assert_eq!(send(&h, &[("authorization", jwt.clone()), ("x-api-key", API_KEY.to_string())]).await, 200);

    let received = target.received();
    assert_eq!(received.len(), 2);
    assert_eq!(received[0]["authorization"], jwt.as_str(), "the selected JWT method forwards its token");
    assert!(
        !received[1].contains_key("authorization"),
        "a request carrying two credentials is verified by neither method, so the JWT stays at the gateway: {:?}",
        received[1]
    );
    assert!(!received[1].contains_key("x-api-key"), "{:?}", received[1]);
}

/// With the forwarding JWT method primary, a request carrying a JWT and an API
/// key selects that method but is ambiguous, so its JWT, verified by no method,
/// stays at the gateway; a JWT alone is still forwarded.
#[tokio::test(flavor = "multi_thread")]
async fn an_ambiguous_request_forwards_no_jwt_even_when_the_forwarding_method_is_primary() {
    let fixture = JwksFixture::start().await;
    let target = RecordingTarget::start(StatusCode::OK, &[]).await;
    let h =
        start_gateway(&fixture, &target, |strategy_id| json!([jwt_method(strategy_id, true), api_key_method()]), None)
            .await;
    let jwt = format!("Bearer {}", valid_jwt(&fixture.issuer));

    assert_eq!(send(&h, &[("authorization", jwt.clone())]).await, 200);
    assert_eq!(send(&h, &[("authorization", jwt.clone()), ("x-api-key", API_KEY.to_string())]).await, 200);

    let received = target.received();
    assert_eq!(received.len(), 2);
    assert_eq!(received[0]["authorization"], jwt.as_str(), "the verified JWT is forwarded");
    assert!(
        !received[1].contains_key("authorization"),
        "an ambiguous request's JWT is verified by no method and stays at the gateway: {:?}",
        received[1].keys()
    );
    assert!(!received[1].contains_key("x-api-key"), "{:?}", received[1].keys());
}

/// Policy sees the method that verified each caller: on one two-method
/// surface a policy admitting only API key callers lets the API key caller
/// through and refuses the JWT caller, though both authenticated.
#[tokio::test(flavor = "multi_thread")]
async fn policy_sees_the_method_that_verified_the_caller() {
    let fixture = JwksFixture::start().await;
    let target = RecordingTarget::start(StatusCode::OK, &[]).await;
    let h = start_gateway(
        &fixture,
        &target,
        |strategy_id| json!([jwt_method(strategy_id, false), api_key_method()]),
        Some(API_KEY_ONLY_POLICY_ID),
    )
    .await;
    let jwt = format!("Bearer {}", valid_jwt(&fixture.issuer));

    assert_eq!(send(&h, &[("x-api-key", API_KEY.to_string())]).await, 200, "the API key caller is admitted");
    assert_eq!(send(&h, &[("authorization", jwt)]).await, 403, "the verified JWT caller is not an API key caller");
    assert_eq!(target.received().len(), 1);
}

/// A config reload runs the boot fallback: a stored surface whose methods break
/// the rules for several methods, here two on one header, is served and stored
/// with its first method alone, so a valid key is not refused as ambiguous.
#[tokio::test(flavor = "multi_thread")]
async fn a_reload_serves_a_rule_breaking_surface_with_its_first_method() {
    let mut paths = None;
    let h = GatewayHarness::start_with_mock(helpers::MockServer::start().await, |_, _, bootstrap| {
        write_api_key_secret(
            &bootstrap
                .storage_paths
                .secrets,
            API_KEY_SECRET_ID,
            API_KEY,
        );
        let admin = helpers::configure_admin_api(bootstrap);
        paths = Some((
            admin,
            std::path::PathBuf::from(
                &bootstrap
                    .storage_paths
                    .agent_surfaces,
            ),
        ));
    })
    .await;
    let (admin, surfaces_dir) = paths.unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    while admin
        .get(format!("{}/api/v1/health", h.gateway_base))
        .send()
        .await
        .map_or(true, |response| response.status() != 200)
    {
        assert!(tokio::time::Instant::now() < deadline, "the gateway never became ready to serve");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let mut listener = url::Url::parse(&h.gateway_base).unwrap();
    listener
        .set_host(Some("localhost"))
        .unwrap();
    let created = admin
        .post(format!("{}/api/v1/surfaces", h.gateway_base))
        .json(&json!({
            "name": "reloaded-methods", "status": "active",
            "access_point": {"listen_address": listener.origin().ascii_serialization(), "route": "/smoke/reloaded-methods",
                             "protocol": "a2a", "caller_authentication": {"methods": [api_key_method()]}},
            "target": {"endpoint": h.mock.url()}
        }))
        .send()
        .await
        .expect("create surface");
    assert_eq!(created.status(), 201);
    let created: serde_json::Value = created.json().await.unwrap();
    let surface_id = created["surface_id"]
        .as_str()
        .unwrap();
    let send_key = || async {
        reqwest::Client::new()
            .post(format!("{}/smoke/reloaded-methods", h.gateway_base))
            .header("content-type", "application/json")
            .header("x-api-key", API_KEY)
            .body(r#"{"jsonrpc":"2.0","method":"message/send","id":1,"params":{"message":{"role":"user","messageId":"m1","parts":[{"kind":"text","text":"hi"}]}}}"#)
            .send()
            .await
            .expect("inbound request failed")
            .status()
            .as_u16()
    };
    assert_eq!(send_key().await, 200, "the stored surface accepts its key");

    let stored_path = std::fs::read_dir(&surfaces_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| std::fs::read_to_string(path).is_ok_and(|content| content.contains(surface_id)))
        .expect("stored surface file");
    let mut stored: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&stored_path).unwrap()).unwrap();
    let mut same_header = api_key_method();
    same_header["extraction"]["field"] = json!("X-API-KEY");
    stored["access_point"]["caller_authentication"]["methods"]
        .as_array_mut()
        .unwrap()
        .push(same_header);
    std::fs::write(&stored_path, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();

    let reload = admin
        .post(format!("{}/api/v1/config/reload", h.gateway_base))
        .send()
        .await
        .expect("reload");
    assert!(reload.status().is_success(), "reload: {}", reload.status());

    assert_eq!(send_key().await, 200, "the reloaded surface serves its first method alone");
    let stored: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&stored_path).unwrap()).unwrap();
    assert_eq!(
        stored["access_point"]["caller_authentication"]["methods"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "the reload stores the correction"
    );
}

/// Creating a surface checks its caller authentication methods as an update
/// does, on the base and on each enabled variant.
#[tokio::test(flavor = "multi_thread")]
async fn creating_a_surface_refuses_two_methods_on_one_header() {
    let mut admin = None;
    let h = GatewayHarness::start_with_mock(helpers::MockServer::start().await, |_, _, bootstrap| {
        write_api_key_secret(
            &bootstrap
                .storage_paths
                .secrets,
            API_KEY_SECRET_ID,
            API_KEY,
        );
        admin = Some(helpers::configure_admin_api(bootstrap));
    })
    .await;
    let admin = admin.unwrap();
    let mut listener = url::Url::parse(&h.gateway_base).unwrap();
    listener
        .set_host(Some("localhost"))
        .unwrap();
    let mut same_header = api_key_method();
    same_header["extraction"]["field"] = json!("X-API-KEY");
    let two_on_one_header = json!([api_key_method(), same_header]);
    let create = |route: &str, base_methods: serde_json::Value, variants: serde_json::Value| {
        admin
            .post(format!("{}/api/v1/surfaces", h.gateway_base))
            .json(&json!({
                "name": route.trim_start_matches("/smoke/"), "status": "active",
                "access_point": {"listen_address": listener.origin().ascii_serialization(), "route": route,
                                 "protocol": "a2a", "caller_authentication": {"methods": base_methods}},
                "target": {"endpoint": h.mock.url()},
                "variants": variants
            }))
            .send()
    };

    let base = create("/smoke/two-on-one-header", two_on_one_header.clone(), json!([]))
        .await
        .expect("create surface");
    assert_eq!(base.status(), 400);
    let body = base.text().await.unwrap();
    assert!(body.contains("both read the 'X-API-KEY' header"), "{body}");

    let variant = create(
        "/smoke/variant-two-on-one-header",
        json!([api_key_method()]),
        json!([{"id": "v1", "alias": "partners", "name": "Partners",
                "overrides": {"access_point": {"caller_authentication": {"methods": two_on_one_header}}}}]),
    )
    .await
    .expect("create surface");
    assert_eq!(variant.status(), 400);
    let body = variant.text().await.unwrap();
    assert!(body.contains("variant 'partners': ") && body.contains("both read the 'X-API-KEY' header"), "{body}");
}

/// A storage event, here the periodic disk scan picking up an edit another
/// process made, applies the fallback as a load does: a stored surface whose
/// methods break the rules for several methods is served with its first method
/// alone, from memory. The scan interval is process-wide, so the test runs in
/// a process of its own.
#[test]
fn a_storage_event_serves_a_rule_breaking_surface_with_its_first_method() {
    const CHILD: &str = "ATG_STORAGE_EVENT_ISOLATED_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let test_name = std::thread::current()
            .name()
            .unwrap()
            .to_string();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test_name, "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated test {test_name} failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    crate::storage::filesystem::set_cache_refresh_interval_secs(1);
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(Box::pin(storage_event_fallback_flow()));
}

async fn storage_event_fallback_flow() {
    const ROTATED_SECRET_ID: &str = "multi-method-rotated-key";
    const ROTATED_KEY: &str = "rotated-partner-key";

    let mut paths = None;
    let h = GatewayHarness::start_with_mock(helpers::MockServer::start().await, |_, _, bootstrap| {
        for (secret_id, value) in [(API_KEY_SECRET_ID, API_KEY), (ROTATED_SECRET_ID, ROTATED_KEY)] {
            write_api_key_secret(
                &bootstrap
                    .storage_paths
                    .secrets,
                secret_id,
                value,
            );
        }
        let admin = helpers::configure_admin_api(bootstrap);
        paths = Some((
            admin,
            std::path::PathBuf::from(
                &bootstrap
                    .storage_paths
                    .agent_surfaces,
            ),
        ));
    })
    .await;
    let (admin, surfaces_dir) = paths.unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    while admin
        .get(format!("{}/api/v1/health", h.gateway_base))
        .send()
        .await
        .map_or(true, |response| response.status() != 200)
    {
        assert!(tokio::time::Instant::now() < deadline, "the gateway never became ready to serve");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let mut listener = url::Url::parse(&h.gateway_base).unwrap();
    listener
        .set_host(Some("localhost"))
        .unwrap();
    let created = admin
        .post(format!("{}/api/v1/surfaces", h.gateway_base))
        .json(&json!({
            "name": "evented-methods", "status": "active",
            "access_point": {"listen_address": listener.origin().ascii_serialization(), "route": "/smoke/evented-methods",
                             "protocol": "a2a", "caller_authentication": {"methods": [api_key_method()]}},
            "target": {"endpoint": h.mock.url()}
        }))
        .send()
        .await
        .expect("create surface");
    assert_eq!(created.status(), 201);
    let created: serde_json::Value = created.json().await.unwrap();
    let surface_id = created["surface_id"]
        .as_str()
        .unwrap();
    let send_key = |key: &'static str| {
        let url = format!("{}/smoke/evented-methods", h.gateway_base);
        async move {
            reqwest::Client::new()
                .post(url)
                .header("content-type", "application/json")
                .header("x-api-key", key)
                .body(r#"{"jsonrpc":"2.0","method":"message/send","id":1,"params":{"message":{"role":"user","messageId":"m1","parts":[{"kind":"text","text":"hi"}]}}}"#)
                .send()
                .await
                .expect("inbound request failed")
                .status()
                .as_u16()
        }
    };
    assert_eq!(send_key(API_KEY).await, 200, "the stored surface accepts its key");

    let stored_path = std::fs::read_dir(&surfaces_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| std::fs::read_to_string(path).is_ok_and(|content| content.contains(surface_id)))
        .expect("stored surface file");
    let mut stored: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&stored_path).unwrap()).unwrap();
    let mut rotated = api_key_method();
    rotated["secret_id"] = json!(ROTATED_SECRET_ID);
    let mut same_header = api_key_method();
    same_header["extraction"]["field"] = json!("X-API-KEY");
    stored["access_point"]["caller_authentication"]["methods"] = json!([rotated, same_header]);
    std::fs::write(&stored_path, serde_json::to_vec_pretty(&stored).unwrap()).unwrap();

    // Only the event's trimmed copy admits the rotated key: untrimmed, both
    // methods read the header and every request is ambiguous.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    while send_key(ROTATED_KEY).await != 200 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the storage event never served the surface with its first method"
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert_ne!(send_key(API_KEY).await, 200, "the dropped method no longer admits its key");
    let stored: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&stored_path).unwrap()).unwrap();
    assert_eq!(
        stored["access_point"]["caller_authentication"]["methods"]
            .as_array()
            .map(Vec::len),
        Some(2),
        "a storage event serves the trim without writing it back"
    );
}
