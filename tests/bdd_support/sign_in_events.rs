//! The fields of a sign-in event as an integration receives it, and its golden files under
//! `tests/fixtures/integration_events/`.
//!
//! A golden file holds one event in the default `webhook`/`stream` envelope, with the values that
//! differ between runs (times, user ids, the Appliance ID) replaced by fixed placeholders.
//! Setting `BDD_UPDATE_GOLDEN=1` writes each compared event to its golden file instead.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::Value;

/// The Appliance ID the scenario gateway is given, so every envelope carries one.
pub const APPLIANCE_ID: &str = "bdd-appliance";

/// The topic the default envelope is streamed to.
pub const EVENT_TOPIC: &str = "sign-ins";
/// The topic Agent Watch's record content is streamed to.
pub const RECORD_TOPIC: &str = "sign-in-records";

/// Agent Watch's template: the event data under `record`.
pub const RECORD_TEMPLATE: &str = r#"{"event_type":"${EVENT_TYPE}","timestamp":"${TIMESTAMP}","appliance_id":"${APPLIANCE_ID}","record":"${EVENT_DATA}"}"#;

pub const ENVELOPE_FIELDS: [&str; 6] = ["event_type", "event_name", "timestamp", "appliance_id", "summary", "data"];
pub const RECORD_FIELDS: [&str; 4] = ["event_type", "timestamp", "appliance_id", "record"];
/// The event data of a sign-in by an existing account, besides `failure_reason`.
pub const ACCOUNT_DATA_FIELDS: [&str; 8] =
    ["old_state", "new_state", "user_id", "username", "user_email", "user_role", "user_status", "login_method"];
/// The event data of a failed sign-in that names no account.
pub const NO_ACCOUNT_DATA_FIELDS: [&str; 4] = ["old_state", "new_state", "login_method", "failure_reason"];
/// The fields of a user's `NEW_STATE`.
pub const STATE_FIELDS: [&str; 6] = ["user_id", "role", "status", "is_primary", "created_at", "updated_at"];

const TIME: &str = "<timestamp>";

/// The field names of a JSON object, or none for anything else.
pub fn keys(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .map(|object| {
            object
                .keys()
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

pub fn names(fields: &[&str]) -> BTreeSet<String> {
    fields
        .iter()
        .map(|field| field.to_string())
        .collect()
}

/// `event` with every value that differs between runs replaced by a fixed placeholder: the
/// envelope's `timestamp` and `appliance_id`, and in the event data (`data` or `record`) the
/// `user_id` and the user id and times of `new_state`.
pub fn normalise(event: &Value) -> Value {
    let mut event = event.clone();
    replace(&mut event, "timestamp", TIME);
    replace(&mut event, "appliance_id", "<appliance_id>");
    for data in ["data", "record"] {
        if let Some(data) = event.get_mut(data) {
            replace(data, "user_id", "<user_id>");
            if let Some(state) = data
                .get_mut("new_state")
                .filter(|state| state.is_object())
            {
                replace(state, "user_id", "<user_id>");
                replace(state, "created_at", TIME);
                replace(state, "updated_at", TIME);
            }
        }
    }
    event
}

fn replace(
    object: &mut Value,
    field: &str,
    placeholder: &str,
) {
    if let Some(value) = object.get_mut(field) {
        *value = Value::String(placeholder.to_string());
    }
}

pub fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/integration_events")
        .join(format!("{name}.json"))
}

/// The golden event `name`, as stored.
pub fn golden(name: &str) -> Value {
    let path = golden_path(name);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("read golden event {}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse golden event {}: {error}", path.display()))
}

pub fn updates_golden() -> bool {
    std::env::var("BDD_UPDATE_GOLDEN").is_ok_and(|value| matches!(value.as_str(), "1" | "true"))
}

/// Writes the normalised `event` as the golden event `name`.
pub fn write_golden(
    name: &str,
    event: &Value,
) {
    let path = golden_path(name);
    std::fs::write(&path, format!("{}\n", serde_json::to_string_pretty(&normalise(event)).expect("serialize")))
        .unwrap_or_else(|error| panic!("write golden event {}: {error}", path.display()));
}
