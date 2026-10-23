//! A2A event streams — end-to-end.
//!
//! A direct A2A Target that answers a streaming method with `text/event-stream`
//! has its events forwarded one at a time and in order, each checked as a
//! non-streaming reply would be. A response policy deny or an identity claim
//! that cannot be resolved ends the stream with a JSON-RPC error event; a Target
//! that closes its stream closes the caller's. The Target must send its headers
//! within the request timeout, and a streaming call is never retried.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::helpers::{self, GatewayHarness, MockServer};

const AGENT_IDENTITY_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity/v1";
const AGENT_IDENTITY_CREDENTIAL_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity-credential/v1";
const STALL_BUDGET: Duration = Duration::from_secs(10);
const COMPLETION_DELAY: Duration = Duration::from_secs(2);

const NO_SECRETS_POLICY_ID: &str = "pol-no-secret-artifacts";
const NO_SECRETS_REGO: &str = r#"package surface.policy

default allow := true

allow := false if contains(input.response.body.result.artifactUpdate.artifact.parts[_].text, "SECRET")
"#;

fn event(result: Value) -> String {
    format!("data: {}\n\n", json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
}

fn submitted() -> Value {
    json!({ "task": { "id": "t-1", "contextId": "c-1", "status": { "state": "TASK_STATE_SUBMITTED" } } })
}

fn working() -> Value {
    json!({ "statusUpdate": { "taskId": "t-1", "contextId": "c-1", "status": { "state": "TASK_STATE_WORKING" } } })
}

fn artifact(text: &str) -> Value {
    json!({ "artifactUpdate": {
        "taskId": "t-1", "contextId": "c-1", "lastChunk": true,
        "artifact": { "artifactId": "a-1", "parts": [{ "text": text }] }
    } })
}

fn completed(message: Option<Value>) -> Value {
    let mut status = json!({ "state": "TASK_STATE_COMPLETED" });
    if let Some(message) = message {
        status["message"] = message;
    }
    json!({ "statusUpdate": { "taskId": "t-1", "contextId": "c-1", "status": status } })
}

fn agent_message(identity: Value) -> Value {
    json!({
        "messageId": "m-2",
        "role": "ROLE_AGENT",
        "parts": [{ "text": "done" }],
        "extensions": [AGENT_IDENTITY_URI],
        "metadata": identity
    })
}

fn identity_payload() -> Value {
    identity_payload_named("backend-agent")
}

fn identity_payload_named(name: &str) -> Value {
    json!({ AGENT_IDENTITY_URI: { "softwareInfo": { "name": name, "version": "2.0" }, "cloudProvider": "local" } })
}

async fn send_streaming_message(h: &GatewayHarness) -> reqwest::Response {
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .header("accept", "text/event-stream")
        .header("A2A-Version", "1.0")
        .body(
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "SendStreamingMessage",
                "params": { "message": { "messageId": "m-1", "role": "ROLE_USER", "parts": [{ "text": "hi" }] } }
            })
            .to_string(),
        )
        .send()
        .await
        .expect("the gateway answers")
}

/// Events the caller received, with how long after `started` each arrived,
/// and whether the body ended. Reading stops at the first event `stop_at`
/// accepts, or when the body ends.
async fn read_events(
    mut response: reqwest::Response,
    started: Instant,
    stop_at: impl Fn(&Value) -> bool,
) -> (Vec<(Duration, Value)>, bool) {
    let mut events = Vec::new();
    let mut buffer = String::new();
    loop {
        let chunk = tokio::time::timeout(STALL_BUDGET, response.chunk())
            .await
            .expect("the event stream stopped delivering")
            .expect("reading the event stream");
        let Some(chunk) = chunk else {
            return (events, true);
        };
        buffer.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(end) = buffer.find("\n\n") {
            let block: String = buffer
                .drain(..end + 2)
                .collect();
            let Some(data) = block
                .lines()
                .find_map(|line| line.strip_prefix("data: "))
            else {
                continue;
            };
            let event: Value = serde_json::from_str(data).expect("every event is JSON");
            let stop = stop_at(&event);
            events.push((started.elapsed(), event));
            if stop {
                return (events, false);
            }
        }
    }
}

fn state_of(event: &Value) -> Option<&str> {
    event["result"]
        .as_object()?
        .values()
        .next()?
        .get("status")?
        .get("state")?
        .as_str()
}

fn is_completion_or_error(event: &Value) -> bool {
    state_of(event) == Some("TASK_STATE_COMPLETED") || event.get("error").is_some()
}

fn error_code(event: &Value) -> Option<&str> {
    event["error"]["data"]["code"].as_str()
}

fn write_no_secrets_policy(temp_dir: &std::path::Path) {
    let dir = temp_dir.join("policy_definitions");
    std::fs::create_dir_all(&dir).expect("create policy_definitions dir");
    std::fs::write(
        dir.join(format!("{NO_SECRETS_POLICY_ID}.json")),
        json!({
            "id": NO_SECRETS_POLICY_ID, "name": "No secret artifacts", "description": "Blocks secret artifacts.",
            "policy_type": "agent_surface", "policy": NO_SECRETS_REGO, "enabled": true,
            "created_at": "2026-01-01T00:00:00Z"
        })
        .to_string(),
    )
    .expect("write policy definition");
}

fn surface_with_networking(networking: Value) -> crate::config::agent_surface::AgentSurface {
    let mut surface = helpers::build_minimal_channel();
    surface.target.networking = Some(serde_json::from_value(networking).expect("networking config"));
    surface
}

#[tokio::test(flavor = "multi_thread")]
async fn streamed_task_events_reach_the_caller_one_at_a_time_in_order() {
    let mock = MockServer::start_with_streamed_body(
        "text/event-stream",
        vec![
            (Duration::ZERO, event(submitted())),
            (Duration::ZERO, event(working())),
            (Duration::ZERO, event(artifact("draft"))),
            (COMPLETION_DELAY, event(completed(None))),
        ],
    )
    .await;
    let h = GatewayHarness::start_with_mock(mock, |_, config, _| {
        config.surfaces = vec![helpers::build_minimal_channel()];
    })
    .await;

    let started = Instant::now();
    let response = send_streaming_message(&h).await;
    assert_eq!(response.status(), 200);
    assert!(
        response.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream"),
        "the stream is not turned into a JSON response"
    );
    let (events, _) = read_events(response, started, is_completion_or_error).await;

    let members: Vec<&str> = events
        .iter()
        .map(|(_, event)| {
            event["result"]
                .as_object()
                .expect("every event is a result")
                .keys()
                .next()
                .unwrap()
                .as_str()
        })
        .collect();
    assert_eq!(members, ["task", "statusUpdate", "artifactUpdate", "statusUpdate"]);
    assert_eq!(state_of(&events[3].1), Some("TASK_STATE_COMPLETED"), "the terminal state is kept");
    assert_eq!(events[2].1["result"]["artifactUpdate"]["artifact"]["parts"][0]["text"], "draft");
    assert!(
        events[0].0 < COMPLETION_DELAY,
        "the first event arrives before the Target sends the last, got {:?}",
        events[0].0
    );
    assert!(events[3].0 >= COMPLETION_DELAY, "the last event cannot arrive before it is sent");

    let forwarded = h
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("the Target received the request");
    assert_eq!(forwarded.headers["accept-encoding"], "identity", "the stream is asked for uncompressed");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_v0_3_stream_ends_when_the_target_closes_it() {
    let status_update = |state: &str, last: bool| {
        format!(
            "event: message\ndata: {}\n\n",
            json!({ "jsonrpc": "2.0", "id": 1, "result": {
                "kind": "status-update", "taskId": "t-1", "contextId": "c-1", "final": last, "status": { "state": state }
            } })
        )
    };
    let mock = MockServer::start_with_finished_stream(
        "text/event-stream; charset=utf-8",
        vec![
            (Duration::ZERO, status_update("working", false)),
            (Duration::ZERO, status_update("input-required", true)),
        ],
    )
    .await;
    let h = GatewayHarness::start_with_mock(mock, |_, config, _| {
        config.surfaces = vec![helpers::build_minimal_channel()];
    })
    .await;

    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "message/stream",
                "params": { "message": { "kind": "message", "messageId": "m-1", "role": "user", "parts": [{ "kind": "text", "text": "hi" }] } }
            })
            .to_string(),
        )
        .send()
        .await
        .expect("the gateway answers");
    let (events, ended) = read_events(response, Instant::now(), |_| false).await;

    assert!(ended, "the caller's stream closes with the Target's");
    let states: Vec<_> = events
        .iter()
        .map(|(_, event)| event["result"]["status"]["state"].clone())
        .collect();
    assert_eq!(states, [json!("working"), json!("input-required")], "the interrupted state is kept");
    assert!(
        events
            .iter()
            .all(|(_, event)| event.get("error").is_none()),
        "a clean end adds no error event"
    );
    assert_eq!(events[1].1["result"]["final"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_response_policy_deny_ends_the_stream_with_an_error_event() {
    let mock = MockServer::start_with_streamed_body(
        "text/event-stream",
        vec![
            (Duration::ZERO, event(submitted())),
            (Duration::ZERO, event(artifact("the SECRET plan"))),
            (Duration::ZERO, event(completed(None))),
        ],
    )
    .await;
    let h = GatewayHarness::start_with_mock(mock, |temp_dir, config, _| {
        write_no_secrets_policy(temp_dir);
        let mut surface = helpers::build_minimal_channel();
        surface.target.response_policy = Some(crate::config::agent_surface::PolicyRef {
            policy_definition_id: NO_SECRETS_POLICY_ID.into(),
            require_agent_context: false,
        });
        config.surfaces = vec![surface];
    })
    .await;

    let response = send_streaming_message(&h).await;
    let (events, ended) = read_events(response, Instant::now(), |_| false).await;

    assert!(ended, "the gateway closes the stream after the error event");
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[0].1["result"]["task"]["id"], "t-1");
    let error = &events[1].1;
    assert_eq!(error["id"], 1);
    assert_eq!(error["error"]["code"], -32603);
    assert_eq!(error_code(error), Some("response_policy_denied"));
    assert!(
        !events
            .iter()
            .any(|(_, event)| event
                .to_string()
                .contains("SECRET")),
        "the denied event is never sent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_identity_claim_on_a_stream_event_is_replaced_by_a_credential() {
    let mock = MockServer::start_with_finished_stream(
        "text/event-stream",
        vec![
            (Duration::ZERO, event(working())),
            (Duration::ZERO, event(completed(Some(agent_message(identity_payload()))))),
        ],
    )
    .await;
    let h = GatewayHarness::start_with_mock(mock, |_, config, _| {
        config.surfaces = vec![helpers::build_identity_channel()];
    })
    .await;

    let response = send_streaming_message(&h).await;
    let (events, ended) = read_events(response, Instant::now(), |_| false).await;

    assert!(ended);
    assert_eq!(events.len(), 2, "a stream whose claim resolved ends without an error event: {events:?}");
    assert_eq!(events[0].1["result"], working(), "an event without a claim is forwarded unchanged");
    let message = &events[1].1["result"]["statusUpdate"]["status"]["message"];
    assert_eq!(message["extensions"], json!([AGENT_IDENTITY_CREDENTIAL_URI]), "{message}");
    assert!(
        message["metadata"]
            .get(AGENT_IDENTITY_URI)
            .is_none()
    );
    let credential = &message["metadata"][AGENT_IDENTITY_CREDENTIAL_URI];
    assert!(
        credential["did"]
            .as_str()
            .is_some_and(|did| did.starts_with("did:")),
        "{credential}"
    );
    assert!(
        credential["verifiablePresentation"]
            .as_str()
            .is_some_and(|vp| !vp.is_empty()),
        "{credential}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_keeps_the_agent_identity_its_first_claim_resolved() {
    for (second_agent, refused) in [("backend-agent", false), ("another-agent", true)] {
        let working_claim = json!({ "statusUpdate": { "taskId": "t-1", "contextId": "c-1", "status": {
            "state": "TASK_STATE_WORKING", "message": agent_message(identity_payload())
        } } });
        let mock = MockServer::start_with_finished_stream(
            "text/event-stream",
            vec![
                (Duration::ZERO, event(working_claim)),
                (Duration::ZERO, event(completed(Some(agent_message(identity_payload_named(second_agent)))))),
            ],
        )
        .await;
        let h = GatewayHarness::start_with_mock(mock, |_, config, _| {
            config.surfaces = vec![helpers::build_identity_channel()];
        })
        .await;

        let response = send_streaming_message(&h).await;
        let (events, ended) = read_events(response, Instant::now(), |_| false).await;

        assert!(ended, "{second_agent}");
        assert_eq!(events.len(), 2, "{second_agent}: {events:?}");
        let first = &events[0].1["result"]["statusUpdate"]["status"]["message"]["metadata"];
        assert!(first[AGENT_IDENTITY_CREDENTIAL_URI]["did"].is_string(), "{second_agent}: {first}");
        if refused {
            assert_eq!(error_code(&events[1].1), Some("identity_changed"));
        } else {
            assert_eq!(state_of(&events[1].1), Some("TASK_STATE_COMPLETED"));
            assert_eq!(
                events[1].1["result"]["statusUpdate"]["status"]["message"]["metadata"][AGENT_IDENTITY_CREDENTIAL_URI]["did"],
                first[AGENT_IDENTITY_CREDENTIAL_URI]["did"]
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_that_never_claims_the_agent_identity_ends_with_an_identity_error() {
    let mock = MockServer::start_with_finished_stream(
        "text/event-stream",
        vec![
            (Duration::ZERO, event(submitted())),
            (Duration::ZERO, event(working())),
            (Duration::ZERO, event(artifact("draft"))),
            (Duration::ZERO, event(completed(None))),
        ],
    )
    .await;
    let h = GatewayHarness::start_with_mock(mock, |_, config, _| {
        config.surfaces = vec![helpers::build_identity_channel()];
    })
    .await;

    let response = send_streaming_message(&h).await;
    let (events, ended) = read_events(response, Instant::now(), |_| false).await;

    assert!(ended);
    assert_eq!(events.len(), 5, "{events:?}");
    assert_eq!(state_of(&events[3].1), Some("TASK_STATE_COMPLETED"), "every event is delivered first");
    let error = &events[4].1;
    assert_eq!(error["id"], 1);
    assert_eq!(error_code(error), Some("identity_extension_missing"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_that_only_reports_an_error_gets_no_identity_error() {
    let agent_error = json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32001, "message": "Task not found" } });
    let mock = MockServer::start_with_finished_stream(
        "text/event-stream",
        vec![(Duration::ZERO, format!("data: {agent_error}\n\n"))],
    )
    .await;
    let h = GatewayHarness::start_with_mock(mock, |_, config, _| {
        config.surfaces = vec![helpers::build_identity_channel()];
    })
    .await;

    let response = send_streaming_message(&h).await;
    let (events, ended) = read_events(response, Instant::now(), |_| false).await;

    assert!(ended);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].1, agent_error, "the agent's own error is the only event");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unresolvable_identity_claim_ends_the_stream() {
    let mock = MockServer::start_with_streamed_body(
        "text/event-stream",
        vec![
            (Duration::ZERO, event(working())),
            (Duration::ZERO, event(completed(Some(agent_message(json!({ "other": {} })))))),
        ],
    )
    .await;
    let h = GatewayHarness::start_with_mock(mock, |_, config, _| {
        config.surfaces = vec![helpers::build_identity_channel()];
    })
    .await;

    let response = send_streaming_message(&h).await;
    let (events, ended) = read_events(response, Instant::now(), |_| false).await;

    assert!(ended);
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[0].1["result"], working());
    assert_eq!(error_code(&events[1].1), Some("identity_extension_missing"));
    assert!(
        !events
            .iter()
            .any(|(_, event)| event
                .to_string()
                .contains("TASK_STATE_COMPLETED")),
        "the event whose claim failed is not sent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_json_reply_to_a_streaming_method_stays_json() {
    let reply =
        json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32004, "message": "Streaming is not supported" } });
    let mock = MockServer::start_with_response(reply.to_string()).await;
    let h = GatewayHarness::start_with_mock(mock, |_, config, _| {
        config.surfaces = vec![helpers::build_minimal_channel()];
    })
    .await;

    let response = send_streaming_message(&h).await;
    assert_eq!(response.status(), 200);
    assert!(
        response.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("application/json")
    );
    let body: Value = response.json().await.unwrap();
    assert_eq!(body, reply);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_target_that_sends_no_headers_times_out_at_the_request_timeout() {
    let (mock, _gate) = MockServer::start_paused("{}").await;
    let h = GatewayHarness::start_with_mock(mock, |_, config, _| {
        config.surfaces = vec![surface_with_networking(json!({ "timeout": { "request_secs": 1 } }))];
    })
    .await;

    let started = Instant::now();
    let response = tokio::time::timeout(STALL_BUDGET, send_streaming_message(&h))
        .await
        .expect("the gateway stops waiting for the Target's headers");

    assert_eq!(response.status(), 504);
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert_eq!(
        h.mock
            .request_count
            .load(Ordering::SeqCst),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_streaming_call_is_sent_once_whatever_the_retry_policy() {
    let mock =
        MockServer::start_with_finished_stream("text/event-stream", vec![(Duration::ZERO, event(completed(None)))])
            .await;
    let h = GatewayHarness::start_with_mock(mock, |_, config, _| {
        config.surfaces = vec![surface_with_networking(json!({ "retry": {
            "max_attempts": 2, "initial_backoff_ms": 10, "max_backoff_ms": 10, "retryable_status_codes": [200]
        } }))];
    })
    .await;

    let response = send_streaming_message(&h).await;
    let (events, ended) = read_events(response, Instant::now(), |_| false).await;

    assert!(ended);
    assert_eq!(state_of(&events[0].1), Some("TASK_STATE_COMPLETED"));
    assert_eq!(
        h.mock
            .request_count
            .load(Ordering::SeqCst),
        1,
        "a status the retry policy lists does not resend a streaming call"
    );
}
