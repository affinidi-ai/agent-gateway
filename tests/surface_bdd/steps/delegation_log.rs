use std::collections::{BTreeSet, HashMap};

use cucumber::{given, then};

use crate::steps::then::gateway_log;
use crate::steps::when::gateway_is_running;
use crate::world::SurfaceWorld;

/// The gateway reads its log level when it starts, so a scenario asks for the
/// log before anything starts the gateway.
#[given("the gateway keeps its log of delegation events")]
fn gateway_keeps_its_log_of_delegation_events(world: &mut SurfaceWorld) {
    assert!(!gateway_is_running(world), "the gateway reads its log level when it starts");
    world
        .surface_config
        .keeps_gateway_log = true;
    world
        .surface_config
        .logs_at_info = true;
}

type LoggedEvent = HashMap<String, String>;

/// The `key=value` fields of every `Delegation event` line in the gateway log. A value a
/// caller or a vendor chose is logged as a quoted token: it is kept as logged, quotes included.
fn delegation_events(world: &SurfaceWorld) -> Vec<LoggedEvent> {
    gateway_log(world)
        .lines()
        .filter_map(|line| line.split_once("Delegation event "))
        .map(|(_, fields)| {
            fields
                .split_whitespace()
                .filter_map(|field| field.split_once('='))
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect()
        })
        .collect()
}

/// A request is answered before the log line of its last step is flushed, so
/// the log is read again until `expected` holds, for up to five seconds.
/// Returns whether it held and the delegation events last read.
async fn eventually_delegation_events(
    world: &SurfaceWorld,
    expected: impl Fn(&[LoggedEvent]) -> bool,
) -> (bool, Vec<LoggedEvent>) {
    let mut events = Vec::new();
    for _ in 0..50 {
        events = delegation_events(world);
        if expected(&events) {
            return (true, events);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    (false, events)
}

fn names<'a>(
    event: &'a str,
    provider: &'a str,
) -> impl Fn(&&LoggedEvent) -> bool + 'a {
    move |logged| {
        logged
            .get("event")
            .is_some_and(|name| name == event)
            && logged
                .get("provider_id")
                .is_some_and(|id| id == provider)
    }
}

/// A logged delegation event names a credential provider by its record id, as
/// an audit record does.
#[then(expr = "the gateway log records delegation event {string} for {word} provider {string}")]
async fn gateway_log_records_delegation_event(
    world: &mut SurfaceWorld,
    event: String,
    _kind: String,
    provider: String,
) {
    let id = world
        .surface_config
        .provider_record_id(&provider);
    let (found, events) = eventually_delegation_events(world, |events| {
        events
            .iter()
            .any(|logged| names(&event, &id)(&logged))
    })
    .await;
    assert!(
        found,
        "the gateway log records no delegation event {event:?} for provider {provider:?} ({id}): {events:?}"
    );
}

#[then(expr = "the gateway log records {int} delegation events {string} for OAuth provider {string}")]
async fn gateway_log_records_delegation_events(
    world: &mut SurfaceWorld,
    count: usize,
    event: String,
    provider: String,
) {
    let id = world
        .surface_config
        .provider_record_id(&provider);
    let (found, events) = eventually_delegation_events(world, |events| {
        events
            .iter()
            .filter(names(&event, &id))
            .count()
            == count
    })
    .await;
    assert!(
        found,
        "the gateway log does not record {count} delegation events {event:?} for provider {provider:?} ({id}): {events:?}"
    );
}

#[then(expr = "the gateway log records delegation event {string} for OAuth provider {string} naming MCP tool {string}")]
async fn gateway_log_records_delegation_event_naming_tool(
    world: &mut SurfaceWorld,
    event: String,
    provider: String,
    tool: String,
) {
    let id = world
        .surface_config
        .provider_record_id(&provider);
    let (found, events) = eventually_delegation_events(world, |events| {
        events
            .iter()
            .filter(names(&event, &id))
            .any(|logged| {
                logged
                    .get("mcp_tool_name")
                    .is_some_and(|name| *name == format!("{tool:?}"))
            })
    })
    .await;
    assert!(
        found,
        "the gateway log records no delegation event {event:?} for provider {provider:?} ({id}) naming MCP tool {tool:?}: {events:?}"
    );
}

/// The log names a caller by identity hash, so two callers behind one Agent
/// DID are two hashes under one DID.
#[then(
    expr = "the gateway log records delegation event {string} for OAuth provider {string} by two callers of one Agent DID"
)]
async fn gateway_log_records_two_callers_of_one_agent(
    world: &mut SurfaceWorld,
    event: String,
    provider: String,
) {
    let id = world
        .surface_config
        .provider_record_id(&provider);
    let named = |events: &[LoggedEvent], field: &str| -> BTreeSet<String> {
        events
            .iter()
            .filter(names(&event, &id))
            .filter_map(|logged| logged.get(field))
            .filter(|value| value.as_str() != "-")
            .cloned()
            .collect()
    };
    let (found, events) = eventually_delegation_events(world, |events| named(events, "user_hash").len() == 2).await;
    assert!(found, "the gateway log does not record {event:?} for two callers: {events:?}");
    let agents = named(&events, "agent_did")
        .iter()
        .map(|did| {
            did.trim_matches('"')
                .to_string()
        })
        .collect();
    crate::steps::then::assert_one_agent_did(&agents, &events);
}
