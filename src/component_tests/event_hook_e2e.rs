//! Event hook behaviour over the Management API, with a mock hook receiver.
//!
//! No test here has a real mediator. Tests that never install a fake see a
//! Connection Point create end at the OOB invitation step with a 500, after DID
//! provisioning. Tests that install `test_mediator` for their mediator DID fake
//! the OOB invitation result and let the listener connect without a mediator
//! socket, so `created`, `connected` and `deleted` are observed over HTTP. The
//! real mediator round trip is covered by the compose end-to-end suite.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use serde_json::{Value, json};

use super::helpers::{GatewayHarness, configure_admin_api};
use crate::event_hook::EventHookSettings;

#[derive(Clone)]
struct HookReply {
    status: u16,
    body: Value,
    delay: Duration,
}

impl HookReply {
    fn accept() -> Self {
        Self {
            status: 204,
            body: Value::Null,
            delay: Duration::ZERO,
        }
    }

    fn status(
        status: u16,
        body: Value,
    ) -> Self {
        Self {
            status,
            body,
            delay: Duration::ZERO,
        }
    }
}

#[derive(Clone)]
struct HookState {
    calls: Arc<Mutex<Vec<(String, HeaderMap)>>>,
    reply: HookReply,
}

struct MockHook {
    url: String,
    calls: Arc<Mutex<Vec<(String, HeaderMap)>>>,
}

impl MockHook {
    async fn start(reply: HookReply) -> Self {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let state = HookState { calls: calls.clone(), reply };
        let app =
            Router::new()
                .route(
                    "/hooks/events",
                    post(
                        |axum::extract::State(state): axum::extract::State<HookState>,
                         headers: HeaderMap,
                         body: String| async move {
                            state
                                .calls
                                .lock()
                                .unwrap()
                                .push((body, headers));
                            tokio::time::sleep(state.reply.delay).await;
                            (StatusCode::from_u16(state.reply.status).unwrap(), axum::Json(state.reply.body))
                        },
                    ),
                )
                .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap();
        });
        Self {
            url: format!("http://{addr}/hooks/events"),
            calls,
        }
    }

    fn settings(&self) -> EventHookSettings {
        EventHookSettings {
            hook_url: Some(self.url.clone()),
            hook_timeout: Duration::from_secs(5),
            ..EventHookSettings::default()
        }
    }

    fn events(&self) -> Vec<Value> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(body, _)| serde_json::from_str(body).unwrap())
            .collect()
    }

    fn events_in_order(&self) -> Vec<Value> {
        let mut events = self.events();
        events.sort_by_key(|event| event["sequence"].as_u64());
        events
    }

    fn headers(&self) -> Vec<HeaderMap> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(_, headers)| headers.clone())
            .collect()
    }
}

struct MockDirectory {
    url: String,
    secret: String,
    calls: Arc<Mutex<Vec<HeaderMap>>>,
}

impl MockDirectory {
    async fn start(
        status: u16,
        body: Value,
    ) -> Self {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let sink = calls.clone();
        let app = Router::new().route(
            "/directory/mediators",
            axum::routing::get(move |headers: HeaderMap| {
                let sink = sink.clone();
                let body = body.clone();
                async move {
                    sink.lock()
                        .unwrap()
                        .push(headers);
                    (StatusCode::from_u16(status).unwrap(), axum::Json(body))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap();
        });
        Self {
            url: format!("http://{addr}/directory/mediators"),
            secret: uuid::Uuid::new_v4()
                .simple()
                .to_string(),
            calls,
        }
    }

    fn settings(&self) -> EventHookSettings {
        EventHookSettings {
            directory_url: Some(self.url.clone()),
            hook_secret: crate::event_hook::HookSecret::new(&self.secret),
            ..EventHookSettings::default()
        }
    }
}

fn directory_items(mediator: &FakeMediator) -> Value {
    json!({"items": [{
        "did": mediator.did(),
        "name": "Shared mediator",
        "description": "ignored",
        "badge": "ignored",
        "warning": "ignored"
    }]})
}

fn dead_hook_url() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener
        .local_addr()
        .unwrap()
        .port();
    format!("http://127.0.0.1:{port}/hooks/events")
}

struct FakeMediator {
    port: u16,
    resolvable: bool,
}

impl FakeMediator {
    async fn start() -> Self {
        Self::bind(false).await
    }

    async fn start_resolvable() -> Self {
        Self::bind(true).await
    }

    async fn bind(resolvable: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let port = listener
            .local_addr()
            .unwrap()
            .port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        Self { port, resolvable }
    }

    fn did(&self) -> String {
        format!("did:web:127.0.0.1%3A{}", self.port)
    }

    fn service_id(&self) -> String {
        if self.resolvable {
            format!("{}#didcomm", self.did())
        } else {
            "#didcomm".to_string()
        }
    }

    fn create_request(&self) -> Value {
        json!({
            "name": "Local mediator",
            "description": "test",
            "did": self.did(),
            "did_document": {
                "id": self.did(),
                "service": [{
                    "id": self.service_id(),
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": [{ "uri": format!("http://127.0.0.1:{}", self.port) }]
                }]
            }
        })
    }
}

struct Api {
    harness: GatewayHarness,
    client: reqwest::Client,
    connection_points_dir: std::path::PathBuf,
    _hook_settings: Option<crate::event_hook::test_settings::Registration>,
}

impl Api {
    async fn start(settings: Option<EventHookSettings>) -> Self {
        Self::start_with(settings, |_| {}).await
    }

    async fn start_with(
        settings: Option<EventHookSettings>,
        tweak: impl FnOnce(&mut crate::config::BootstrapConfig),
    ) -> Self {
        let mut client = None;
        let mut registration = None;
        let mut connection_points_dir = std::path::PathBuf::new();
        let harness = GatewayHarness::start(|_, _, bootstrap| {
            client = Some(configure_admin_api(bootstrap));
            tweak(bootstrap);
            registration = settings.map(|settings| {
                crate::event_hook::test_settings::install(
                    &bootstrap
                        .storage_paths
                        .gateways,
                    settings,
                )
            });
            connection_points_dir = bootstrap
                .storage_paths
                .connection_points
                .clone()
                .into();
        })
        .await;
        Self {
            harness,
            client: client.unwrap(),
            connection_points_dir,
            _hook_settings: registration,
        }
    }

    async fn start_listing(
        mediator: &FakeMediator,
        hook: &MockHook,
    ) -> (Self, MockDirectory) {
        install_directory_mediator_document(mediator);
        let directory = MockDirectory::start(200, directory_items(mediator)).await;
        let mut settings = hook.settings();
        settings.directory_url = Some(directory.url.clone());
        (Self::start(Some(settings)).await, directory)
    }

    async fn create_on_directory_mediator(
        &self,
        mediator: &FakeMediator,
    ) -> (u16, Value) {
        let (status, listed) = self.get("/mediators").await;
        assert_eq!(status, 200, "{listed}");
        let mediator_id = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["did"] == json!(mediator.did()))
            .and_then(|item| item["id"].as_str())
            .unwrap()
            .to_string();
        self.post(
            "/connection-points",
            &json!({
                "gateway_id": self_gateway_id(self).await,
                "mediator_id": mediator_id,
                "name": "cp",
                "description": "cp",
                "secret": "s3cret",
                "did_method": "peer"
            }),
        )
        .await
    }

    fn url(
        &self,
        path: &str,
    ) -> String {
        format!("{}/api/v1{path}", self.harness.gateway_base)
    }

    async fn get(
        &self,
        path: &str,
    ) -> (u16, Value) {
        let response = self
            .client
            .get(self.url(path))
            .send()
            .await
            .unwrap();
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
        path: &str,
        body: &Value,
    ) -> (u16, Value) {
        let response = self
            .client
            .post(self.url(path))
            .json(body)
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let text = response.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or(Value::String(text)))
    }

    async fn create_connection_point(
        &self,
        mediator: &FakeMediator,
    ) -> (u16, Value) {
        let (status, created) = self
            .post("/mediators", &mediator.create_request())
            .await;
        assert_eq!(status, 200, "{created}");
        let (status, gateways) = self.get("/gateways").await;
        assert_eq!(status, 200, "{gateways}");
        let gateway_id = gateways
            .as_array()
            .unwrap()
            .iter()
            .find(|gateway| gateway["gateway_type"] == "self")
            .and_then(|gateway| gateway["id"].as_str())
            .unwrap()
            .to_string();
        self.post(
            "/connection-points",
            &json!({
                "gateway_id": gateway_id,
                "mediator_id": created["id"],
                "name": "cp",
                "description": "cp",
                "secret": "s3cret",
                "did_method": "peer"
            }),
        )
        .await
    }

    fn install_fake_mediator(
        mediator: &FakeMediator,
        outcome: crate::gateways::connection_points::test_mediator::OobOutcome,
    ) {
        crate::gateways::connection_points::test_mediator::install(&mediator.did(), outcome);
    }

    fn connection_point_key_dirs(&self) -> usize {
        std::fs::read_dir(&self.connection_points_dir)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter(|entry| entry.path().is_dir() && entry.file_name() != "pending")
                    .count()
            })
            .unwrap_or(0)
    }
}

async fn eventually<F: std::future::Future<Output = bool>>(
    description: &str,
    mut condition: impl FnMut() -> F,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !condition().await {
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {description}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn fake_invitation() -> crate::gateways::connection_points::test_mediator::OobOutcome {
    Ok((
        "oobid-1".to_string(),
        "https://mediator.invalid/oob?_oobid=oobid-1".to_string(),
        json!({"@id": "invitation-1"}),
    ))
}

fn event_names(events: &[Value]) -> Vec<&str> {
    events
        .iter()
        .map(|event| {
            event["event"]
                .as_str()
                .unwrap()
        })
        .collect()
}

fn is_oob_failure(body: &Value) -> bool {
    body.as_str()
        .is_some_and(|text| text.contains("OOB invitation"))
}

#[tokio::test(flavor = "multi_thread")]
async fn without_the_hook_connection_point_creation_is_unchanged() {
    let api = Api::start(None).await;
    let mediator = FakeMediator::start().await;
    let (status, body) = api
        .create_connection_point(&mediator)
        .await;
    assert_eq!(status, 500, "{body}");
    assert!(is_oob_failure(&body), "{body}");
    assert_eq!(api.connection_point_key_dirs(), 1, "keys are kept for debugging, as before");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_creation_reports_started_then_failed_and_never_created() {
    let hook = MockHook::start(HookReply::accept()).await;
    let api = Api::start(Some(hook.settings())).await;
    let mediator = FakeMediator::start().await;
    let (status, body) = api
        .create_connection_point(&mediator)
        .await;
    assert_eq!(status, 500, "{body}");
    assert!(is_oob_failure(&body), "{body}");

    eventually("the started and failed events", || std::future::ready(hook.events().len() >= 2)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let events = hook.events();
    let started = events
        .iter()
        .find(|event| event["event"] == "connection_point.creation_started")
        .expect("creation_started");
    let failed = events
        .iter()
        .find(|event| event["event"] == "connection_point.creation_failed")
        .expect("creation_failed");
    assert!(
        events
            .iter()
            .all(|event| event["event"] != "connection_point.created")
    );
    assert_eq!(events.len(), 2, "{events:?}");

    assert!(started["sequence"].as_u64() < failed["sequence"].as_u64());
    assert!(started["timestamp"].as_str() <= failed["timestamp"].as_str());
    assert!(started["event_id"].is_string());
    assert_ne!(started["event_id"], failed["event_id"]);
    let cp = &started["connection_point"];
    assert_eq!(cp, &failed["connection_point"]);
    assert_eq!(cp["name"], "cp");
    assert_eq!(cp["mediator_did"], mediator.did());
    assert_eq!(cp["did_method"], "peer");
    assert!(
        cp["did"]
            .as_str()
            .unwrap()
            .starts_with("did:peer:")
    );
    assert!(cp["id"].is_string() && cp["gateway_id"].is_string() && cp["mediator_id"].is_string());
    for headers in hook.headers() {
        assert_eq!(headers["content-type"], "application/json");
        assert!(
            headers
                .get("x-webhook-signature-256")
                .is_none()
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_connection_point_reports_deleted_with_its_did_and_mediator() {
    let hook = MockHook::start(HookReply::accept()).await;
    let api = Api::start_with(Some(hook.settings()), |bootstrap| bootstrap.cache_refresh_interval_secs = 1).await;
    let (status, gateways) = api.get("/gateways").await;
    assert_eq!(status, 200, "{gateways}");
    let gateway_id = gateways
        .as_array()
        .unwrap()
        .iter()
        .find(|gateway| gateway["gateway_type"] == "self")
        .and_then(|gateway| gateway["id"].as_str())
        .unwrap()
        .to_string();
    let mut record = crate::gateways::connection_points::types::GatewayConnectionPoint::new(
        gateway_id,
        "mediator-record".into(),
        "did:peer:2.stored".into(),
        "stored".into(),
        "stored cp".into(),
        "oob".into(),
        "https://example.invalid/oob".into(),
        json!({}),
        None,
        crate::gateways::connection_points::types::ConnectionPointType::User,
        "secret".into(),
    );
    record.mediator_did = Some("did:web:mediator.example".into());
    std::fs::create_dir_all(&api.connection_points_dir).unwrap();
    std::fs::write(
        api.connection_points_dir
            .join(format!("{}.json", record.id)),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    let path = format!("/connection-points/{}", record.id);
    eventually("the stored record to be picked up", || async { api.get(&path).await.0 == 200 }).await;

    let response = api
        .client
        .delete(api.url(&path))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 204);
    eventually("the deleted event", || std::future::ready(!hook.events().is_empty())).await;
    let event = hook.events()[0].clone();
    assert_eq!(event["event"], "connection_point.deleted");
    let cp = &event["connection_point"];
    assert_eq!(cp["id"], record.id);
    assert_eq!(cp["did"], "did:peer:2.stored");
    assert_eq!(cp["mediator_did"], "did:web:mediator.example");
    assert_eq!(cp["name"], "stored");
    assert_eq!(cp["did_method"], "peer");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_hook_does_not_affect_creation() {
    let settings = EventHookSettings {
        hook_url: Some(dead_hook_url()),
        ..EventHookSettings::default()
    };
    let api = Api::start(Some(settings)).await;
    let mediator = FakeMediator::start().await;
    let (status, body) = api
        .create_connection_point(&mediator)
        .await;
    assert_eq!(status, 500, "{body}");
    assert!(is_oob_failure(&body), "creation went past the hook: {body}");
    assert_eq!(api.connection_point_key_dirs(), 1, "keys are kept, as without the hook");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_retryable_answer_is_retried_and_leaves_creation_unaffected() {
    let hook = MockHook::start(HookReply::status(503, json!({"reason": "unavailable"}))).await;
    let api = Api::start(Some(hook.settings())).await;
    let mediator = FakeMediator::start().await;
    let (status, body) = api
        .create_connection_point(&mediator)
        .await;
    assert_eq!(status, 500, "{body}");
    assert!(is_oob_failure(&body), "{body}");
    eventually("the started event to be retried", || {
        std::future::ready(
            hook.events()
                .iter()
                .filter(|event| event["event"] == "connection_point.creation_started")
                .count()
                >= 2,
        )
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn with_a_secret_every_event_is_signed_and_a_401_is_retried() {
    const SECRET: &str = "0123456789abcdef0123456789abcdef";
    let hook = MockHook::start(HookReply::status(401, json!({"reason": "bad_signature"}))).await;
    let mut settings = hook.settings();
    settings.hook_secret = crate::event_hook::HookSecret::new(SECRET);
    let api = Api::start(Some(settings)).await;
    let mediator = FakeMediator::start().await;
    let (status, body) = api
        .create_connection_point(&mediator)
        .await;
    assert_eq!(status, 500, "{body}");
    assert!(is_oob_failure(&body), "an auth failure never fails creation: {body}");
    eventually("the first event to be retried after the 401", || {
        std::future::ready(
            hook.events()
                .iter()
                .filter(|event| event["event"] == "connection_point.creation_started")
                .count()
                >= 2,
        )
    })
    .await;
    let calls = hook
        .calls
        .lock()
        .unwrap()
        .clone();
    assert!(!calls.is_empty());
    for (body, headers) in calls {
        let timestamp = headers["x-webhook-timestamp"]
            .to_str()
            .unwrap();
        let expected =
            crate::integrations::webhook_signing::sign_timestamped_payload(SECRET, timestamp, body.as_bytes()).unwrap();
        let signature = headers["x-webhook-signature-256"]
            .to_str()
            .unwrap();
        assert_eq!(signature, format!("sha256={expected}"), "the signature does not match the received body");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_hook_that_never_answers_does_not_slow_or_change_creation() {
    let hook = MockHook::start(HookReply {
        delay: Duration::from_secs(60),
        ..HookReply::accept()
    })
    .await;
    let api = Api::start(Some(EventHookSettings {
        hook_timeout: Duration::from_secs(10),
        ..hook.settings()
    }))
    .await;
    let mediator = FakeMediator::start().await;
    let started = std::time::Instant::now();
    let (status, body) = api
        .create_connection_point(&mediator)
        .await;
    let elapsed = started.elapsed();
    assert_eq!(status, 500, "{body}");
    assert!(is_oob_failure(&body), "{body}");
    assert!(elapsed < Duration::from_secs(5), "the request waited for the hook: {elapsed:?}");
    eventually("the hook to be called in the background", || std::future::ready(!hook.events().is_empty())).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_permanent_rejection_is_dropped_without_a_retry_and_does_not_affect_creation() {
    let hook = MockHook::start(HookReply::status(
        422,
        json!({"reason": "not_eligible", "message": "Project is not eligible"}),
    ))
    .await;
    let api = Api::start(Some(hook.settings())).await;
    let mediator = FakeMediator::start().await;
    let (status, body) = api
        .create_connection_point(&mediator)
        .await;
    assert_eq!(status, 500, "{body}");
    assert!(is_oob_failure(&body), "{body}");
    eventually("the hook to be told", || std::future::ready(hook.events().len() >= 2)).await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(hook.events().len(), 2, "each rejected event is sent once");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_successful_creation_reports_started_then_created_with_the_final_record() {
    let hook = MockHook::start(HookReply::accept()).await;
    let api = Api::start(Some(hook.settings())).await;
    let mediator = FakeMediator::start_resolvable().await;
    Api::install_fake_mediator(&mediator, fake_invitation());
    let (status, body) = api
        .create_connection_point(&mediator)
        .await;
    assert_eq!(status, 200, "{body}");

    eventually("started, created and connected", || std::future::ready(hook.events().len() >= 3)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let events = hook.events_in_order();
    assert_eq!(
        event_names(&events),
        ["connection_point.creation_started", "connection_point.created", "connection_point.connected"]
    );
    let (started, created) = (&events[0], &events[1]);
    assert!(started["sequence"].as_u64() < created["sequence"].as_u64());
    assert!(started["event_id"].is_string());
    assert_ne!(started["event_id"], created["event_id"]);
    for event in [started, created] {
        uuid::Uuid::parse_str(
            event["event_id"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let cp = &event["connection_point"];
        assert_eq!(cp["id"], body["connection_point"]["id"]);
        assert_eq!(cp["name"], "cp");
        assert_eq!(cp["mediator_did"], mediator.did());
        assert_eq!(cp["did_method"], "peer");
        assert!(
            cp["did"]
                .as_str()
                .unwrap()
                .starts_with("did:peer:")
        );
        assert!(cp["gateway_id"].is_string() && cp["mediator_id"].is_string());
    }
    assert_eq!(started["connection_point"]["did"], created["connection_point"]["did"]);
    assert!(
        started["connection_point"]
            .get("created_at")
            .is_none()
    );
    assert!(created["connection_point"]["created_at"].is_string());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_invitation_reports_started_then_failed_and_never_created() {
    let hook = MockHook::start(HookReply::accept()).await;
    let api = Api::start(Some(hook.settings())).await;
    let mediator = FakeMediator::start_resolvable().await;
    Api::install_fake_mediator(&mediator, Err("mediator refused".to_string()));
    let (status, body) = api
        .create_connection_point(&mediator)
        .await;
    assert_eq!(status, 500, "{body}");
    assert!(is_oob_failure(&body), "{body}");

    eventually("started and failed", || std::future::ready(hook.events().len() >= 2)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        event_names(&hook.events_in_order()),
        ["connection_point.creation_started", "connection_point.creation_failed"]
    );
}

fn quick_retry(attempts: u32) -> crate::gateways::connection_points::first_call_retry::FirstCallRetry {
    crate::gateways::connection_points::first_call_retry::FirstCallRetry {
        attempts,
        delay: Duration::from_millis(5),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_first_call_is_retried_with_the_same_did_and_creation_succeeds() {
    let hook = MockHook::start(HookReply::accept()).await;
    let mediator = FakeMediator::start_resolvable().await;
    let (api, _directory) = Api::start_listing(&mediator, &hook).await;
    crate::gateways::connection_points::test_mediator::install_refusing(
        &mediator.did(),
        fake_invitation(),
        2,
        quick_retry(5),
    );
    let (status, body) = api
        .create_on_directory_mediator(&mediator)
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(crate::gateways::connection_points::test_mediator::first_calls(&mediator.did()), 3);

    eventually("started, created and connected", || std::future::ready(hook.events().len() >= 3)).await;
    let events = hook.events_in_order();
    assert_eq!(
        event_names(&events),
        ["connection_point.creation_started", "connection_point.created", "connection_point.connected"]
    );
    assert_eq!(events[0]["connection_point"]["did"], events[1]["connection_point"]["did"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_first_call_refused_beyond_the_retries_reports_started_then_failed() {
    let hook = MockHook::start(HookReply::accept()).await;
    let mediator = FakeMediator::start_resolvable().await;
    let (api, _directory) = Api::start_listing(&mediator, &hook).await;
    crate::gateways::connection_points::test_mediator::install_refusing(
        &mediator.did(),
        fake_invitation(),
        99,
        quick_retry(2),
    );
    let (status, body) = api
        .create_on_directory_mediator(&mediator)
        .await;
    assert_eq!(status, 500, "{body}");
    assert!(is_oob_failure(&body), "{body}");
    assert_eq!(crate::gateways::connection_points::test_mediator::first_calls(&mediator.did()), 3);

    eventually("started and failed", || std::future::ready(hook.events().len() >= 2)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        event_names(&hook.events_in_order()),
        ["connection_point.creation_started", "connection_point.creation_failed"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_for_an_operator_added_mediator_is_never_retried() {
    let hook = MockHook::start(HookReply::accept()).await;
    let api = Api::start(Some(hook.settings())).await;
    let mediator = FakeMediator::start_resolvable().await;
    crate::gateways::connection_points::test_mediator::install_refusing(
        &mediator.did(),
        fake_invitation(),
        99,
        quick_retry(5),
    );
    let (status, body) = api
        .create_connection_point(&mediator)
        .await;
    assert_eq!(status, 500, "{body}");
    assert!(is_oob_failure(&body), "{body}");
    assert!(
        !body
            .to_string()
            .contains("no longer offered"),
        "{body}"
    );
    assert_eq!(crate::gateways::connection_points::test_mediator::first_calls(&mediator.did()), 1);

    eventually("started and failed", || std::future::ready(hook.events().len() >= 2)).await;
    assert_eq!(
        event_names(&hook.events_in_order()),
        ["connection_point.creation_started", "connection_point.creation_failed"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn without_retries_a_refused_first_call_fails_at_once() {
    let hook = MockHook::start(HookReply::accept()).await;
    let mediator = FakeMediator::start_resolvable().await;
    let (api, _directory) = Api::start_listing(&mediator, &hook).await;
    crate::gateways::connection_points::test_mediator::install_refusing(
        &mediator.did(),
        fake_invitation(),
        1,
        quick_retry(0),
    );
    let (status, body) = api
        .create_on_directory_mediator(&mediator)
        .await;
    assert_eq!(status, 500, "{body}");
    assert_eq!(crate::gateways::connection_points::test_mediator::first_calls(&mediator.did()), 1);
}

fn install_directory_mediator_document(mediator: &FakeMediator) {
    crate::mediators::utils::test_documents::install(
        &mediator.did(),
        mediator.create_request()["did_document"].clone(),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn directory_mediators_are_listed_with_a_signed_request_as_provided_and_without_extra_fields() {
    let mediator = FakeMediator::start_resolvable().await;
    let directory = MockDirectory::start(200, directory_items(&mediator)).await;
    let api = Api::start(Some(directory.settings())).await;

    let (status, listed) = api.get("/mediators").await;
    assert_eq!(status, 200, "{listed}");
    let items = listed.as_array().unwrap();
    assert_eq!(items.len(), 1, "{listed}");
    assert!(
        items[0]["id"]
            .as_str()
            .unwrap()
            .starts_with("directory:")
    );
    assert_eq!(items[0]["did"], mediator.did());
    assert_eq!(items[0]["provided"], true);
    assert_eq!(items[0]["name"], "Shared mediator");
    assert_eq!(items[0]["description"], "");
    for key in ["badge", "warning"] {
        assert!(items[0].get(key).is_none(), "{key} is not part of a mediator");
    }
    assert_eq!(items[0]["registered"], false);

    let headers = directory
        .calls
        .lock()
        .unwrap()[0]
        .clone();
    let timestamp = headers["x-webhook-timestamp"]
        .to_str()
        .unwrap();
    let expected =
        crate::integrations::webhook_signing::sign_timestamped_payload(&directory.secret, timestamp, b"").unwrap();
    assert_eq!(
        headers["x-webhook-signature-256"]
            .to_str()
            .unwrap(),
        format!("sha256={expected}")
    );

    let (status, compatible) = api
        .get("/mediators/compatible")
        .await;
    assert_eq!(status, 200, "{compatible}");
    assert_eq!(
        compatible
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_directory_the_mediator_list_is_the_stored_records_only() {
    let api = Api::start(None).await;
    let mediator = FakeMediator::start().await;
    assert_eq!(
        api.post("/mediators", &mediator.create_request())
            .await
            .0,
        200
    );
    let (status, listed) = api.get("/mediators").await;
    assert_eq!(status, 200, "{listed}");
    let items = listed.as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert!(
        items[0]
            .get("provided")
            .is_none(),
        "provided must not appear without a directory"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failing_directory_leaves_the_stored_mediators_listed() {
    let directory = MockDirectory::start(503, Value::Null).await;
    let api = Api::start(Some(directory.settings())).await;
    let mediator = FakeMediator::start().await;
    assert_eq!(
        api.post("/mediators", &mediator.create_request())
            .await
            .0,
        200
    );
    let (status, listed) = api.get("/mediators").await;
    assert_eq!(status, 200, "{listed}");
    assert_eq!(
        listed
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        listed[0]
            .get("provided")
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn creating_a_connection_point_on_a_directory_mediator_stores_one_provided_record() {
    let mediator = FakeMediator::start_resolvable().await;
    install_directory_mediator_document(&mediator);
    Api::install_fake_mediator(&mediator, fake_invitation());
    let directory = MockDirectory::start(200, directory_items(&mediator)).await;
    let api = Api::start(Some(directory.settings())).await;
    let (status, listed) = api.get("/mediators").await;
    assert_eq!(status, 200, "{listed}");
    let directory_id = listed[0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, gateways) = api.get("/gateways").await;
    assert_eq!(status, 200, "{gateways}");
    let gateway_id = gateways
        .as_array()
        .unwrap()
        .iter()
        .find(|gateway| gateway["gateway_type"] == "self")
        .and_then(|gateway| gateway["id"].as_str())
        .unwrap()
        .to_string();
    let request = json!({
        "gateway_id": gateway_id,
        "mediator_id": directory_id,
        "name": "cp",
        "description": "cp",
        "secret": "s3cret",
        "did_method": "peer"
    });

    let mut stored_ids = Vec::new();
    for _ in 0..2 {
        let (status, body) = api
            .post("/connection-points", &request)
            .await;
        assert_eq!(status, 200, "{body}");
        assert_ne!(body["connection_point"]["mediator_id"], json!(directory_id), "{body}");
        stored_ids.push(body["connection_point"]["mediator_id"].clone());
    }
    assert_eq!(stored_ids[0], stored_ids[1], "both connection points share one stored record");

    let (status, listed) = api.get("/mediators").await;
    assert_eq!(status, 200, "{listed}");
    let items = listed.as_array().unwrap();
    assert_eq!(items.len(), 2, "the entry, then the stored record the connection points use: {listed}");
    assert_eq!(items[0]["id"], json!(directory_id));
    assert_eq!(items[0]["provided"], true);
    assert_eq!(items[1]["id"], stored_ids[0]);
    assert_eq!(items[1]["provided"], true);

    let (status, stored) = api
        .get(&format!(
            "/mediators/{}",
            stored_ids[0]
                .as_str()
                .unwrap()
        ))
        .await;
    assert_eq!(status, 200, "{stored}");
    assert_eq!(stored["provided"], true);
    assert_eq!(stored["name"], "Shared mediator");
    assert_eq!(stored["registered"], true);
}

async fn self_gateway_id(api: &Api) -> String {
    let (status, gateways) = api.get("/gateways").await;
    assert_eq!(status, 200, "{gateways}");
    gateways
        .as_array()
        .unwrap()
        .iter()
        .find(|gateway| gateway["gateway_type"] == "self")
        .and_then(|gateway| gateway["id"].as_str())
        .unwrap()
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn every_event_for_a_directory_mediator_carries_the_id_of_the_stored_record() {
    let mediator = FakeMediator::start_resolvable().await;
    install_directory_mediator_document(&mediator);
    Api::install_fake_mediator(&mediator, fake_invitation());
    let hook = MockHook::start(HookReply::accept()).await;
    let directory = MockDirectory::start(200, directory_items(&mediator)).await;
    let mut settings = hook.settings();
    settings.directory_url = Some(directory.url.clone());
    let api = Api::start(Some(settings)).await;
    let (_, listed) = api.get("/mediators").await;
    let directory_id = listed[0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let request = json!({
        "gateway_id": self_gateway_id(&api).await,
        "mediator_id": directory_id,
        "name": "cp",
        "description": "cp",
        "secret": "s3cret",
        "did_method": "peer"
    });

    let (status, body) = api
        .post("/connection-points", &request)
        .await;
    assert_eq!(status, 200, "{body}");
    eventually("created", || {
        std::future::ready(
            hook.events()
                .iter()
                .any(|event| event["event"] == "connection_point.created"),
        )
    })
    .await;

    let stored_id = body["connection_point"]["mediator_id"].clone();
    assert!(
        !stored_id
            .as_str()
            .unwrap()
            .starts_with("directory:")
    );
    for event in hook.events() {
        assert_eq!(event["connection_point"]["mediator_id"], stored_id, "{event}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_provided_mediator_cannot_be_edited_or_deleted_while_the_directory_offers_it() {
    let mediator = FakeMediator::start_resolvable().await;
    Api::install_fake_mediator(&mediator, fake_invitation());
    let hook = MockHook::start(HookReply::accept()).await;
    let (api, _directory) = Api::start_listing(&mediator, &hook).await;
    let (status, body) = api
        .create_on_directory_mediator(&mediator)
        .await;
    assert_eq!(status, 200, "{body}");
    let stored_id = body["connection_point"]["mediator_id"]
        .as_str()
        .unwrap()
        .to_string();

    let response = api
        .client
        .put(api.url(&format!("/mediators/{stored_id}")))
        .json(&json!({"name": "renamed"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 409);
    let response = api
        .client
        .delete(api.url(&format!("/mediators/{stored_id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 409);
    let point_id = body["connection_point"]["id"]
        .as_str()
        .unwrap();
    let response = api
        .client
        .delete(api.url(&format!("/connection-points/{point_id}")))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let response = api
        .client
        .delete(api.url(&format!("/mediators/{stored_id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status().as_u16(),
        409,
        "while the directory still offers the mediator its record is not removed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_connection_point_creation_leaves_no_directory_mediator_record() {
    let mediator = FakeMediator::start_resolvable().await;
    install_directory_mediator_document(&mediator);
    Api::install_fake_mediator(&mediator, Err("mediator refused".to_string()));
    let directory = MockDirectory::start(200, directory_items(&mediator)).await;
    let api = Api::start(Some(directory.settings())).await;
    let (_, listed) = api.get("/mediators").await;
    let directory_id = listed[0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let request = json!({
        "gateway_id": self_gateway_id(&api).await,
        "mediator_id": directory_id,
        "name": "cp",
        "description": "cp",
        "secret": "s3cret",
        "did_method": "peer"
    });

    let (status, body) = api
        .post("/connection-points", &request)
        .await;
    assert_eq!(status, 500, "{body}");

    let (status, listed) = api.get("/mediators").await;
    assert_eq!(status, 200, "{listed}");
    let items = listed.as_array().unwrap();
    assert_eq!(items.len(), 1, "{listed}");
    assert_eq!(items[0]["id"], json!(directory_id), "the entry is still only offered, not stored: {listed}");
    assert_eq!(items[0]["registered"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_operator_added_mediator_and_the_directory_entry_for_the_same_did_are_listed_separately() {
    let mediator = FakeMediator::start_resolvable().await;
    install_directory_mediator_document(&mediator);
    Api::install_fake_mediator(&mediator, fake_invitation());
    let hook = MockHook::start(HookReply::accept()).await;
    let (api, _directory) = Api::start_listing(&mediator, &hook).await;
    let (status, created) = api
        .post("/mediators", &mediator.create_request())
        .await;
    assert_eq!(status, 200, "{created}");

    let (status, listed) = api.get("/mediators").await;
    assert_eq!(status, 200, "{listed}");
    let items = listed.as_array().unwrap();
    assert_eq!(items.len(), 2, "{listed}");
    assert!(
        items[0]["id"]
            .as_str()
            .unwrap()
            .starts_with("directory:")
    );
    assert_eq!(items[0]["provided"], true);
    assert_eq!(items[0]["name"], "Shared mediator");
    assert_eq!(items[1]["id"], created["id"]);
    assert_ne!(items[1]["provided"], json!(true), "{listed}");

    let (status, body) = api
        .create_on_directory_mediator(&mediator)
        .await;
    assert_eq!(status, 200, "{body}");
    assert_ne!(
        body["connection_point"]["mediator_id"], created["id"],
        "a directory id never resolves to the operator's record"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_directory_id_while_the_directory_has_not_answered_is_unavailable_not_missing() {
    let directory = MockDirectory::start(503, Value::Null).await;
    let api = Api::start(Some(directory.settings())).await;
    let response = api
        .client
        .post(api.url("/connection-points"))
        .json(&json!({
            "gateway_id": self_gateway_id(&api).await,
            "mediator_id": "directory:0123456789abcdef",
            "name": "cp",
            "description": "cp",
            "secret": "s3cret",
            "did_method": "peer"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 503);
    assert_eq!(
        response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok()),
        Some("5")
    );
    assert_eq!(response.text().await.unwrap(), "The mediator directory is not available yet; try again shortly");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_directory_id_is_not_found() {
    let mediator = FakeMediator::start_resolvable().await;
    let directory = MockDirectory::start(200, directory_items(&mediator)).await;
    let api = Api::start(Some(directory.settings())).await;
    let (_, gateways) = api.get("/gateways").await;
    let gateway_id = gateways
        .as_array()
        .unwrap()
        .iter()
        .find(|gateway| gateway["gateway_type"] == "self")
        .and_then(|gateway| gateway["id"].as_str())
        .unwrap()
        .to_string();
    let (status, body) = api
        .post(
            "/connection-points",
            &json!({
                "gateway_id": gateway_id,
                "mediator_id": "directory:0000000000000000",
                "name": "cp",
                "description": "cp",
                "secret": "s3cret"
            }),
        )
        .await;
    assert_eq!(status, 404, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_directory_id_without_a_configured_directory_is_not_found() {
    let api = Api::start(None).await;
    let (_, gateways) = api.get("/gateways").await;
    let gateway_id = gateways
        .as_array()
        .unwrap()
        .iter()
        .find(|gateway| gateway["gateway_type"] == "self")
        .and_then(|gateway| gateway["id"].as_str())
        .unwrap()
        .to_string();
    let (status, _) = api
        .post(
            "/connection-points",
            &json!({
                "gateway_id": gateway_id,
                "mediator_id": "directory:0000000000000000",
                "name": "cp",
                "description": "cp",
                "secret": "s3cret"
            }),
        )
        .await;
    assert_eq!(status, 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_whole_lifecycle_is_reported_in_order_for_one_did() {
    let hook = MockHook::start(HookReply::accept()).await;
    let api = Api::start(Some(hook.settings())).await;
    let mediator = FakeMediator::start_resolvable().await;
    Api::install_fake_mediator(&mediator, fake_invitation());
    let (status, body) = api
        .create_connection_point(&mediator)
        .await;
    assert_eq!(status, 200, "{body}");
    eventually("connected", || {
        std::future::ready(
            hook.events()
                .iter()
                .any(|event| event["event"] == "connection_point.connected"),
        )
    })
    .await;

    let response = api
        .client
        .delete(api.url(&format!("/connection-points/{}", body["connection_point"]["id"].as_str().unwrap())))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 204);
    eventually("deleted", || {
        std::future::ready(
            hook.events()
                .iter()
                .any(|event| event["event"] == "connection_point.deleted"),
        )
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let events = hook.events_in_order();
    assert_eq!(
        event_names(&events),
        [
            "connection_point.creation_started",
            "connection_point.created",
            "connection_point.connected",
            "connection_point.deleted"
        ]
    );
    let sequences: Vec<u64> = events
        .iter()
        .map(|event| {
            event["sequence"]
                .as_u64()
                .unwrap()
        })
        .collect();
    assert!(
        sequences
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "{sequences:?}"
    );
    let did = &events[0]["connection_point"]["did"];
    for event in &events {
        assert_eq!(&event["connection_point"]["did"], did);
        assert_eq!(event["connection_point"]["id"], body["connection_point"]["id"]);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_gateways_each_report_only_to_their_own_hook() {
    let hook_a = MockHook::start(HookReply::accept()).await;
    let hook_b = MockHook::start(HookReply::accept()).await;
    let (api_a, api_b, api_off) =
        tokio::join!(Api::start(Some(hook_a.settings())), Api::start(Some(hook_b.settings())), Api::start(None));
    let (mediator_a, mediator_b, mediator_off) =
        tokio::join!(FakeMediator::start(), FakeMediator::start(), FakeMediator::start());
    let (a, b, off) = tokio::join!(
        api_a.create_connection_point(&mediator_a),
        api_b.create_connection_point(&mediator_b),
        api_off.create_connection_point(&mediator_off)
    );
    for (status, body) in [a, b, off] {
        assert_eq!(status, 500, "{body}");
    }

    eventually("both hooks to be told", || {
        std::future::ready(hook_a.events().len() >= 2 && hook_b.events().len() >= 2)
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    for (hook, mediator) in [(&hook_a, &mediator_a), (&hook_b, &mediator_b)] {
        let events = hook.events();
        assert_eq!(events.len(), 2, "{events:?}");
        assert!(
            events
                .iter()
                .all(|event| event["connection_point"]["mediator_did"] == mediator.did())
        );
    }
}
