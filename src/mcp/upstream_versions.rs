//! Protocol versions learned from forwarded `server/discover` results.
//!
//! An unsupported-version error lists the versions the endpoint's path admits,
//! but the upstream MCP server may serve fewer. The latest discovery result the
//! client received for the same endpoint and Target narrows that list. Only
//! versions are kept, entries expire, and the table is bounded; admission and
//! the upstream are never consulted.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::error_codes;
use super::request_validation::McpRequestValidationError;
use super::{MCP_LEGACY_VERSION, MCP_MODERN_VERSION};

const TTL: Duration = Duration::from_secs(300);
const CAPACITY: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UpstreamRoute {
    /// Stable variant ID, or `None` for the base surface.
    AccessPoint(Option<String>),
    /// Transit Point alias, which survives records whose ID is regenerated.
    TransitPoint(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamKey {
    pub surface_id: String,
    pub route: UpstreamRoute,
    pub target: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Versions {
    legacy: bool,
    modern: bool,
}

impl Versions {
    /// A listed `supportedVersions` is authoritative; `-32601` means the
    /// upstream predates discovery. Any other outcome teaches nothing.
    fn from_discovery(message: &Value) -> Option<Self> {
        if let Some(supported) = message
            .pointer("/result/supportedVersions")
            .and_then(Value::as_array)
        {
            let lists = |version: &str| {
                supported
                    .iter()
                    .any(|listed| listed.as_str() == Some(version))
            };
            return Some(Self {
                legacy: lists(MCP_LEGACY_VERSION),
                modern: lists(MCP_MODERN_VERSION),
            });
        }
        (message
            .pointer("/error/code")
            .and_then(Value::as_i64)
            == Some(i64::from(error_codes::METHOD_NOT_FOUND)))
        .then_some(Self { legacy: true, modern: false })
    }

    fn serves(
        self,
        version: &str,
    ) -> bool {
        (self.legacy && version == MCP_LEGACY_VERSION) || (self.modern && version == MCP_MODERN_VERSION)
    }
}

struct LearnedVersions {
    entries: HashMap<UpstreamKey, (Versions, Instant)>,
    capacity: usize,
}

impl LearnedVersions {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
        }
    }

    fn record(
        &mut self,
        key: UpstreamKey,
        versions: Versions,
        now: Instant,
    ) {
        if !self
            .entries
            .contains_key(&key)
            && self.entries.len() >= self.capacity
        {
            self.entries
                .retain(|_, (_, recorded)| now.duration_since(*recorded) < TTL);
            if self.entries.len() >= self.capacity
                && let Some(oldest) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, (_, recorded))| *recorded)
                    .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries
            .insert(key, (versions, now));
    }

    fn get(
        &self,
        key: &UpstreamKey,
        now: Instant,
    ) -> Option<Versions> {
        self.entries
            .get(key)
            .filter(|(_, recorded)| now.duration_since(*recorded) < TTL)
            .map(|(versions, _)| *versions)
    }
}

fn learned() -> &'static Mutex<LearnedVersions> {
    static LEARNED: OnceLock<Mutex<LearnedVersions>> = OnceLock::new();
    LEARNED.get_or_init(|| Mutex::new(LearnedVersions::new(CAPACITY)))
}

/// Records the versions a forwarded `server/discover` response delivered to
/// the client, replacing anything learned earlier for the same key.
pub fn record_discovery(
    key: UpstreamKey,
    message: &Value,
) {
    if let Some(versions) = Versions::from_discovery(message)
        && let Ok(mut learned) = learned().lock()
    {
        learned.record(key, versions, Instant::now());
    }
}

/// Limits an unsupported-version error's `supported` list to the versions
/// learned for this upstream, keeping the path's list when nothing is learned
/// or nothing would remain. Other errors are returned unchanged.
pub fn restrict_unsupported(
    mut error: Box<McpRequestValidationError>,
    key: &UpstreamKey,
) -> Box<McpRequestValidationError> {
    if error.code != error_codes::UNSUPPORTED_PROTOCOL_VERSION {
        return error;
    }
    let learned = learned()
        .lock()
        .ok()
        .and_then(|learned| learned.get(key, Instant::now()));
    if let Some(versions) = learned
        && let Some(supported) = error
            .data
            .as_mut()
            .and_then(|data| data.get_mut("supported"))
            .and_then(Value::as_array_mut)
    {
        let served: Vec<Value> = supported
            .iter()
            .filter(|version| {
                version
                    .as_str()
                    .is_some_and(|version| versions.serves(version))
            })
            .cloned()
            .collect();
        if !served.is_empty() {
            *supported = served;
        }
    }
    error
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::mcp::request_validation::McpVersionPolicy;

    const DUAL: McpVersionPolicy<'static> =
        McpVersionPolicy::new(&[MCP_MODERN_VERSION], &[MCP_LEGACY_VERSION, MCP_MODERN_VERSION]);

    fn key(surface_id: &str) -> UpstreamKey {
        UpstreamKey {
            surface_id: surface_id.to_string(),
            route: UpstreamRoute::AccessPoint(None),
            target: "https://upstream.example/mcp".to_string(),
        }
    }

    fn discovery(versions: &[&str]) -> Value {
        json!({"jsonrpc": "2.0", "id": 1, "result": {
            "resultType": "complete", "supportedVersions": versions, "capabilities": {},
            "ttlMs": 0, "cacheScope": "private"
        }})
    }

    fn error(code: i32) -> Value {
        json!({"jsonrpc": "2.0", "id": 1, "error": {"code": code, "message": "failed"}})
    }

    fn unsupported(policy: McpVersionPolicy<'_>) -> Box<McpRequestValidationError> {
        McpRequestValidationError::unsupported(Some(json!("request")), "2025-11-25", policy)
    }

    fn advertised(
        key: &UpstreamKey,
        policy: McpVersionPolicy<'_>,
    ) -> Value {
        restrict_unsupported(unsupported(policy), key)
            .data
            .unwrap()["supported"]
            .clone()
    }

    #[test]
    fn upstream_versions_narrow_the_advertised_list_to_what_discovery_listed() {
        let modern_only = key("upstream-versions-modern-only");
        record_discovery(modern_only.clone(), &discovery(&[MCP_MODERN_VERSION, "2025-11-25"]));
        assert_eq!(advertised(&modern_only, DUAL), json!([MCP_MODERN_VERSION]));
        let both = key("upstream-versions-both");
        record_discovery(both.clone(), &discovery(&[MCP_LEGACY_VERSION, MCP_MODERN_VERSION]));
        assert_eq!(advertised(&both, DUAL), json!([MCP_LEGACY_VERSION, MCP_MODERN_VERSION]));
        let error = restrict_unsupported(unsupported(DUAL), &modern_only);
        assert_eq!(error.id, Some(json!("request")));
        assert_eq!(error.data.unwrap()["requested"], "2025-11-25");
    }

    #[test]
    fn upstream_versions_treat_method_not_found_as_a_legacy_only_upstream() {
        let legacy = key("upstream-versions-method-not-found");
        record_discovery(legacy.clone(), &error(error_codes::METHOD_NOT_FOUND));
        assert_eq!(advertised(&legacy, DUAL), json!([MCP_LEGACY_VERSION]));
    }

    #[test]
    fn upstream_versions_learn_nothing_from_other_outcomes() {
        let untouched = key("upstream-versions-other-outcomes");
        for message in [
            error(-32001),
            error(error_codes::INTERNAL_ERROR),
            error(error_codes::UNSUPPORTED_PROTOCOL_VERSION),
            json!({"jsonrpc": "2.0", "id": 1, "result": {"resultType": "complete", "supportedVersions": "2026-07-28"}}),
            json!({"jsonrpc": "2.0", "id": 1, "result": {"resultType": "complete"}}),
            json!({"jsonrpc": "2.0", "id": 1, "error": {"code": "-32601", "message": "failed"}}),
        ] {
            record_discovery(untouched.clone(), &message);
            assert_eq!(advertised(&untouched, DUAL), json!([MCP_LEGACY_VERSION, MCP_MODERN_VERSION]), "{message}");
        }
    }

    #[test]
    fn upstream_versions_keep_the_path_list_for_an_unknown_upstream() {
        assert_eq!(
            advertised(&key("upstream-versions-unknown"), DUAL),
            json!([MCP_LEGACY_VERSION, MCP_MODERN_VERSION])
        );
        let learned = key("upstream-versions-distinct-keys");
        record_discovery(learned.clone(), &discovery(&[MCP_MODERN_VERSION]));
        for other in [
            UpstreamKey {
                route: UpstreamRoute::AccessPoint(Some("variant".into())),
                ..learned.clone()
            },
            UpstreamKey {
                route: UpstreamRoute::TransitPoint("partner".into()),
                ..learned.clone()
            },
            UpstreamKey {
                target: "https://other.example/mcp".into(),
                ..learned.clone()
            },
        ] {
            assert_eq!(advertised(&other, DUAL), json!([MCP_LEGACY_VERSION, MCP_MODERN_VERSION]), "{other:?}");
        }
        assert_eq!(advertised(&learned, DUAL), json!([MCP_MODERN_VERSION]));
    }

    #[test]
    fn upstream_versions_keep_the_latest_discovery() {
        let latest = key("upstream-versions-latest");
        record_discovery(latest.clone(), &discovery(&[MCP_MODERN_VERSION]));
        record_discovery(latest.clone(), &error(error_codes::METHOD_NOT_FOUND));
        assert_eq!(advertised(&latest, DUAL), json!([MCP_LEGACY_VERSION]));
        record_discovery(latest.clone(), &error(error_codes::INTERNAL_ERROR));
        assert_eq!(advertised(&latest, DUAL), json!([MCP_LEGACY_VERSION]));
        record_discovery(latest.clone(), &discovery(&[MCP_LEGACY_VERSION, MCP_MODERN_VERSION]));
        assert_eq!(advertised(&latest, DUAL), json!([MCP_LEGACY_VERSION, MCP_MODERN_VERSION]));
    }

    #[test]
    fn upstream_versions_expire_after_their_ttl() {
        let modern = Versions { legacy: false, modern: true };
        let start = Instant::now();
        let mut learned = LearnedVersions::new(CAPACITY);
        learned.record(key("expiring"), modern, start);
        assert_eq!(learned.get(&key("expiring"), start + TTL - Duration::from_millis(1)), Some(modern));
        assert_eq!(learned.get(&key("expiring"), start + TTL), None);
        learned.record(key("expiring"), modern, start + TTL);
        assert_eq!(learned.get(&key("expiring"), start + TTL), Some(modern));
    }

    #[test]
    fn upstream_versions_stay_within_capacity() {
        let modern = Versions { legacy: false, modern: true };
        let start = Instant::now();
        let at = |seconds| start + Duration::from_secs(seconds);
        let mut learned = LearnedVersions::new(3);
        for (name, seconds) in [("a", 0), ("b", 1), ("c", 2), ("a", 3)] {
            learned.record(key(name), modern, at(seconds));
        }
        assert_eq!(learned.entries.len(), 3);
        learned.record(key("d"), modern, at(4));
        let present = |learned: &LearnedVersions, now| {
            let mut names: Vec<_> = learned
                .entries
                .keys()
                .filter(|key| {
                    learned
                        .get(key, now)
                        .is_some()
                })
                .map(|key| key.surface_id.clone())
                .collect();
            names.sort();
            names
        };
        assert_eq!(present(&learned, at(4)), ["a", "c", "d"]);
        learned.record(key("e"), modern, at(303));
        assert_eq!(learned.entries.len(), 2);
        assert_eq!(present(&learned, at(303)), ["d", "e"]);
    }

    #[test]
    fn upstream_versions_never_empty_the_advertised_list() {
        let legacy = key("upstream-versions-never-empty");
        record_discovery(legacy.clone(), &error(error_codes::METHOD_NOT_FOUND));
        let modern_only = McpVersionPolicy::new(&[MCP_MODERN_VERSION], &[MCP_MODERN_VERSION]);
        assert_eq!(advertised(&legacy, modern_only), json!([MCP_MODERN_VERSION]));
        let unmodelled = key("upstream-versions-unmodelled");
        record_discovery(unmodelled.clone(), &discovery(&["2025-11-25"]));
        assert_eq!(advertised(&unmodelled, DUAL), json!([MCP_LEGACY_VERSION, MCP_MODERN_VERSION]));
    }

    #[test]
    fn upstream_versions_leave_other_errors_untouched() {
        let legacy = key("upstream-versions-other-errors");
        record_discovery(legacy.clone(), &error(error_codes::METHOD_NOT_FOUND));
        let other = Box::new(McpRequestValidationError {
            status: axum::http::StatusCode::BAD_REQUEST,
            id: Some(json!("request")),
            code: error_codes::INVALID_PARAMS,
            message: "Invalid params".into(),
            data: Some(json!({"supported": [MCP_LEGACY_VERSION, MCP_MODERN_VERSION]})),
        });
        assert_eq!(restrict_unsupported(other.clone(), &legacy), other);
        let mut without_data = unsupported(DUAL);
        without_data.data = None;
        assert_eq!(restrict_unsupported(without_data.clone(), &legacy), without_data);
    }
}
