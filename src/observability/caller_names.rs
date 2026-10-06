//! Background, cached display-name resolution for external callers.
//!
//! A caller name comes from, in order: a verified agent name (an `alsoKnownAs`
//! `host/@local` entry whose resolution returns exactly the caller DID), the
//! caller's Agent Card `name` (unverified), or nothing. Names are dashboard-only
//! and never published. Lookups never block the caller: [`CallerNameService::lookup_or_spawn`]
//! returns the cached value, or [`CallerLookup::Pending`] before the first lookup finishes,
//! and refreshes it in the background.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::{DashMap, DashSet};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::identity::display_name::DisplayName;

pub const CALLER_NAME_TTL: Duration = Duration::from_secs(300);
pub const MAX_AGENT_NAME_CANDIDATES: usize = 4;
pub const AGENT_CARD_FETCH_TIMEOUT: Duration = Duration::from_secs(5);
pub const AGENT_CARD_MAX_BYTES: usize = 64 * 1024;
pub const DID_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONCURRENT_RESOLUTIONS: usize = 4;
const AGENT_CARD_SERVICE_TYPES: [&str; 2] = ["AgentCard", "A2AAgentCard"];
const AGENT_CARD_SERVICE_ID_SUFFIX: &str = "#agent-card";
const AGENT_CARD_CACHE_PATH: &str = "caller-agent-card";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisplayNameSource {
    SurfaceName,
    AgentName,
    AgentCard,
    TargetAgentCard,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerName {
    pub name: String,
    pub source: DisplayNameSource,
    pub verified: bool,
    pub resolved_at: DateTime<Utc>,
}

#[async_trait]
pub trait CallerNameSources: Send + Sync {
    async fn resolve_did_document(
        &self,
        did: &str,
    ) -> Result<Value, String>;

    /// Returns the DID the agent name resolves to after the resolver's `alsoKnownAs` back-check.
    async fn verify_agent_name(
        &self,
        name: &str,
    ) -> Result<String, String>;

    async fn fetch_agent_card(
        &self,
        url: &str,
    ) -> Result<Value, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallerLookup {
    /// No lookup for this DID has finished yet.
    Pending,
    /// The latest finished lookup; `None` when it found no name or failed.
    Resolved(Option<CallerName>),
}

#[cfg(test)]
impl CallerLookup {
    pub fn into_name(self) -> Option<CallerName> {
        match self {
            Self::Pending => None,
            Self::Resolved(name) => name,
        }
    }
}

struct CacheEntry {
    name: Option<CallerName>,
    checked_at: Instant,
    changed_at: Option<DateTime<Utc>>,
}

pub struct CallerNameService {
    cache: DashMap<String, CacheEntry>,
    inflight: DashSet<String>,
    permits: Semaphore,
    ttl: Duration,
    resolution_timeout: Duration,
    sources: Arc<dyn CallerNameSources>,
}

struct InflightGuard<'a> {
    inflight: &'a DashSet<String>,
    did: String,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.inflight
            .remove(&self.did);
    }
}

impl CallerNameService {
    pub fn global() -> &'static Arc<CallerNameService> {
        static GLOBAL: OnceLock<Arc<CallerNameService>> = OnceLock::new();
        GLOBAL.get_or_init(|| Arc::new(CallerNameService::new(Arc::new(SdkCallerNameSources))))
    }

    pub fn new(sources: Arc<dyn CallerNameSources>) -> Self {
        Self::with_ttl(sources, CALLER_NAME_TTL)
    }

    pub fn with_ttl(
        sources: Arc<dyn CallerNameSources>,
        ttl: Duration,
    ) -> Self {
        Self {
            cache: DashMap::new(),
            inflight: DashSet::new(),
            permits: Semaphore::new(MAX_CONCURRENT_RESOLUTIONS),
            ttl,
            resolution_timeout: DID_RESOLUTION_TIMEOUT,
            sources,
        }
    }

    /// Returns the cached name (possibly stale) without waiting, and starts a single
    /// background refresh when the DID is unknown or its entry is older than the TTL.
    pub fn lookup_or_spawn(
        self: &Arc<Self>,
        did: &str,
    ) -> CallerLookup {
        let (cached, fresh) = match self.cache.get(did) {
            Some(entry) => (CallerLookup::Resolved(entry.name.clone()), entry.checked_at.elapsed() < self.ttl),
            None => (CallerLookup::Pending, false),
        };
        if !fresh {
            self.spawn_refresh(did);
        }
        cached
    }

    fn spawn_refresh(
        self: &Arc<Self>,
        did: &str,
    ) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if !self
            .inflight
            .insert(did.to_string())
        {
            return;
        }
        let service = Arc::clone(self);
        let did = did.to_string();
        handle.spawn(async move {
            let _guard = InflightGuard {
                inflight: &service.inflight,
                did: did.clone(),
            };
            let Ok(_permit) = service
                .permits
                .acquire()
                .await
            else {
                return;
            };
            let name = service.resolve(&did).await;
            service.store(&did, name);
        });
    }

    fn store(
        &self,
        did: &str,
        name: Option<CallerName>,
    ) {
        let previous = self
            .cache
            .get(did)
            .map(|e| (e.name.clone(), e.changed_at));
        let first_lookup = previous.is_none();
        let (previous_name, previous_changed_at) = previous.unwrap_or((None, None));
        let changed = first_lookup
            || previous_name
                .as_ref()
                .map(|n| (&n.name, n.source, n.verified))
                != name
                    .as_ref()
                    .map(|n| (&n.name, n.source, n.verified));
        let changed_at = if changed {
            Some(Utc::now())
        } else {
            previous_changed_at
        };
        self.cache.insert(
            did.to_string(),
            CacheEntry {
                name,
                checked_at: Instant::now(),
                changed_at,
            },
        );
    }

    pub async fn resolve(
        &self,
        did: &str,
    ) -> Option<CallerName> {
        let doc = match self
            .within_resolution_timeout(
                self.sources
                    .resolve_did_document(did),
            )
            .await
        {
            Ok(doc) => doc,
            Err(e) => {
                debug!(did, error = %e, "Caller DID document unavailable; no caller name");
                return None;
            }
        };
        if let Some(name) = self
            .verified_agent_name(did, &doc)
            .await
        {
            return Some(name);
        }
        self.agent_card_name(did, &doc)
            .await
    }

    async fn within_resolution_timeout<T>(
        &self,
        resolution: impl std::future::Future<Output = Result<T, String>>,
    ) -> Result<T, String> {
        let limit = self.resolution_timeout;
        tokio::time::timeout(limit, resolution)
            .await
            .unwrap_or_else(|_| Err(format!("DID resolution timed out after {limit:?}")))
    }

    async fn verified_agent_name(
        &self,
        did: &str,
        doc: &Value,
    ) -> Option<CallerName> {
        for candidate in agent_name_candidates(doc) {
            match self
                .within_resolution_timeout(
                    self.sources
                        .verify_agent_name(&candidate),
                )
                .await
            {
                Ok(resolved) if resolved == did => {
                    let display = candidate
                        .split_once("://")
                        .map_or(candidate.as_str(), |(_, rest)| rest);
                    match DisplayName::parse(display) {
                        Ok(name) => {
                            return Some(CallerName {
                                name: name.as_str().to_string(),
                                source: DisplayNameSource::AgentName,
                                verified: true,
                                resolved_at: Utc::now(),
                            });
                        }
                        Err(e) => {
                            warn!(did, agent_name = %candidate, error = %e, "Verified agent name is not displayable")
                        }
                    }
                }
                Ok(resolved) => {
                    warn!(did, agent_name = %candidate, resolved_did = %resolved, "Agent name resolves to a different DID");
                }
                Err(e) => warn!(did, agent_name = %candidate, error = %e, "Agent name verification failed"),
            }
        }
        None
    }

    async fn agent_card_name(
        &self,
        did: &str,
        doc: &Value,
    ) -> Option<CallerName> {
        let url = agent_card_endpoint(doc)?;
        let card = match self
            .sources
            .fetch_agent_card(&url)
            .await
        {
            Ok(card) => card,
            Err(e) => {
                debug!(did, url = %url, error = %e, "Caller Agent Card unavailable");
                return None;
            }
        };
        let raw = card
            .get("name")
            .and_then(Value::as_str)?;
        match DisplayName::parse(raw) {
            Ok(name) => Some(CallerName {
                name: name.as_str().to_string(),
                source: DisplayNameSource::AgentCard,
                verified: false,
                resolved_at: Utc::now(),
            }),
            Err(e) => {
                warn!(did, url = %url, error = %e, "Caller Agent Card name rejected");
                None
            }
        }
    }

    /// DIDs whose first lookup finished, or whose resolved name changed (appeared, changed, or
    /// disappeared), after `since`.
    pub fn changed_since(
        &self,
        since: DateTime<Utc>,
    ) -> Vec<String> {
        self.cache
            .iter()
            .filter(|e| {
                e.changed_at
                    .is_some_and(|t| t > since)
            })
            .map(|e| e.key().clone())
            .collect()
    }
}

pub fn agent_name_candidates(doc: &Value) -> Vec<String> {
    doc.get("alsoKnownAs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|s| s.contains("/@"))
        .take(MAX_AGENT_NAME_CANDIDATES)
        .map(str::to_string)
        .collect()
}

pub fn agent_card_endpoint(doc: &Value) -> Option<String> {
    doc.get("service")
        .and_then(Value::as_array)?
        .iter()
        .filter(|service| is_agent_card_service(service))
        .find_map(|service| match service.get("serviceEndpoint")? {
            Value::String(uri) => Some(uri.clone()),
            Value::Object(obj) => obj
                .get("uri")
                .and_then(Value::as_str)
                .map(str::to_string),
            _ => None,
        })
}

fn is_agent_card_service(service: &Value) -> bool {
    let type_matches = match service.get("type") {
        Some(Value::String(t)) => AGENT_CARD_SERVICE_TYPES.contains(&t.as_str()),
        Some(Value::Array(types)) => types
            .iter()
            .filter_map(Value::as_str)
            .any(|t| AGENT_CARD_SERVICE_TYPES.contains(&t)),
        _ => false,
    };
    type_matches
        || service
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| id.ends_with(AGENT_CARD_SERVICE_ID_SUFFIX))
}

struct SdkCallerNameSources;

#[async_trait]
impl CallerNameSources for SdkCallerNameSources {
    async fn resolve_did_document(
        &self,
        did: &str,
    ) -> Result<Value, String> {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .map_err(|e| e.to_string())?;
        let response = crate::gateways::did_cache::shared_resolver()
            .resolve(did)
            .await
            .map_err(|e| e.to_string())?;
        serde_json::to_value(&response.doc).map_err(|e| e.to_string())
    }

    async fn verify_agent_name(
        &self,
        name: &str,
    ) -> Result<String, String> {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .map_err(|e| e.to_string())?;
        crate::gateways::did_cache::shared_resolver()
            .resolve_any(name)
            .await
            .map(|response| response.did)
            .map_err(|e| e.to_string())
    }

    async fn fetch_agent_card(
        &self,
        url: &str,
    ) -> Result<Value, String> {
        use crate::proxy::agent_card_cache;
        match agent_card_cache::lookup(url, Some(AGENT_CARD_CACHE_PATH)) {
            Some(Some(card)) => return Ok(card),
            Some(None) => return Err("recent Agent Card fetch failed".to_string()),
            None => {}
        }
        let fetched = fetch_card_uncached(url).await;
        agent_card_cache::insert(url, Some(AGENT_CARD_CACHE_PATH), fetched.as_ref().ok().cloned());
        fetched
    }
}

async fn fetch_card_uncached(url: &str) -> Result<Value, String> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::ACCEPT, reqwest::header::HeaderValue::from_static("application/json"));
    let allowlist = crate::egress::bdd_egress_allowlist();
    let mut response = crate::egress::guarded_send_inner(
        reqwest::Method::GET,
        url,
        headers,
        None,
        crate::egress::EgressPolicy::Strict,
        AGENT_CARD_FETCH_TIMEOUT,
        allowlist.as_deref(),
    )
    .await
    .map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err(format!("Agent Card fetch returned {}", response.status()));
    }
    if response
        .content_length()
        .is_some_and(|len| len > AGENT_CARD_MAX_BYTES as u64)
    {
        return Err("Agent Card exceeds the size limit".to_string());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| e.to_string())?
    {
        if body.len() + chunk.len() > AGENT_CARD_MAX_BYTES {
            return Err("Agent Card exceeds the size limit".to_string());
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|e| format!("Agent Card is not JSON: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    const DID: &str = "did:web:acme.com:billing";

    #[derive(Default)]
    struct FakeSources {
        docs: HashMap<String, Value>,
        names: HashMap<String, String>,
        cards: HashMap<String, Value>,
        doc_calls: AtomicUsize,
        gate: Option<Arc<Notify>>,
        doc_delay: Option<Duration>,
        name_delay: Option<Duration>,
    }

    #[async_trait]
    impl CallerNameSources for FakeSources {
        async fn resolve_did_document(
            &self,
            did: &str,
        ) -> Result<Value, String> {
            self.doc_calls
                .fetch_add(1, Ordering::SeqCst);
            if let Some(gate) = &self.gate {
                gate.notified().await;
            }
            if let Some(delay) = self.doc_delay {
                tokio::time::sleep(delay).await;
            }
            self.docs
                .get(did)
                .cloned()
                .ok_or_else(|| "not found".to_string())
        }

        async fn verify_agent_name(
            &self,
            name: &str,
        ) -> Result<String, String> {
            if let Some(delay) = self.name_delay {
                tokio::time::sleep(delay).await;
            }
            self.names
                .get(name)
                .cloned()
                .ok_or_else(|| "name does not resolve".to_string())
        }

        async fn fetch_agent_card(
            &self,
            url: &str,
        ) -> Result<Value, String> {
            self.cards
                .get(url)
                .cloned()
                .ok_or_else(|| "unreachable".to_string())
        }
    }

    fn doc(
        also_known_as: &[&str],
        services: Value,
    ) -> Value {
        json!({ "id": DID, "alsoKnownAs": also_known_as, "service": services })
    }

    fn card_service() -> Value {
        json!([{ "id": format!("{DID}#a2a"), "type": "AgentCard", "serviceEndpoint": "https://acme.com/card.json" }])
    }

    fn service_with(sources: FakeSources) -> CallerNameService {
        CallerNameService::new(Arc::new(sources))
    }

    const SHORT_TIMEOUT: Duration = Duration::from_millis(50);
    const HUNG: Duration = Duration::from_secs(30);

    fn service_with_short_timeout(sources: FakeSources) -> CallerNameService {
        let mut service = service_with(sources);
        service.resolution_timeout = SHORT_TIMEOUT;
        service
    }

    #[test]
    fn test_agent_name_candidates_keeps_order_ignores_non_names_and_caps() {
        let d = doc(
            &[
                "did:web:other",
                "acme.com/@a",
                "https://example.com",
                "acme.com/@b",
                "acme.com/@c",
                "acme.com/@d",
                "acme.com/@e",
            ],
            json!([]),
        );
        assert_eq!(agent_name_candidates(&d), vec!["acme.com/@a", "acme.com/@b", "acme.com/@c", "acme.com/@d"]);
    }

    #[test]
    fn test_agent_name_candidates_without_also_known_as_is_empty() {
        assert!(agent_name_candidates(&json!({ "id": DID })).is_empty());
    }

    #[test]
    fn test_agent_card_endpoint_accepts_string_and_object_endpoints() {
        let string_endpoint = json!({ "service": [{ "type": "A2AAgentCard", "serviceEndpoint": "https://a/card" }] });
        assert_eq!(agent_card_endpoint(&string_endpoint).as_deref(), Some("https://a/card"));

        let object_endpoint =
            json!({ "service": [{ "type": ["Other", "AgentCard"], "serviceEndpoint": { "uri": "https://b/card" } }] });
        assert_eq!(agent_card_endpoint(&object_endpoint).as_deref(), Some("https://b/card"));

        let by_id =
            json!({ "service": [{ "id": "did:x#agent-card", "type": "X", "serviceEndpoint": "https://c/card" }] });
        assert_eq!(agent_card_endpoint(&by_id).as_deref(), Some("https://c/card"));
    }

    #[test]
    fn test_agent_card_endpoint_ignores_other_services() {
        let d = json!({ "service": [
            { "id": "did:x#mediator", "type": "DIDCommMessaging", "serviceEndpoint": "https://m" },
            { "type": "AgentCard", "serviceEndpoint": ["https://array"] }
        ] });
        assert_eq!(agent_card_endpoint(&d), None);
    }

    #[tokio::test]
    async fn test_resolve_verified_agent_name() {
        let mut sources = FakeSources::default();
        sources
            .docs
            .insert(DID.into(), doc(&["https://acme.com/@billing"], card_service()));
        sources
            .names
            .insert("https://acme.com/@billing".into(), DID.into());
        let name = service_with(sources)
            .resolve(DID)
            .await
            .expect("verified name");
        assert_eq!(name.name, "acme.com/@billing");
        assert_eq!(name.source, DisplayNameSource::AgentName);
        assert!(name.verified);
    }

    #[tokio::test]
    async fn test_resolve_name_redirecting_elsewhere_falls_through_to_unverified_card() {
        let mut sources = FakeSources::default();
        sources
            .docs
            .insert(DID.into(), doc(&["acme.com/@billing"], card_service()));
        sources
            .names
            .insert("acme.com/@billing".into(), "did:web:attacker".into());
        sources
            .cards
            .insert("https://acme.com/card.json".into(), json!({ "name": "Billing Bot" }));
        let name = service_with(sources)
            .resolve(DID)
            .await
            .expect("card name");
        assert_eq!(name.name, "Billing Bot");
        assert_eq!(name.source, DisplayNameSource::AgentCard);
        assert!(!name.verified);
    }

    #[tokio::test]
    async fn test_resolve_case_mismatched_name_is_rejected() {
        let mut sources = FakeSources::default();
        sources
            .docs
            .insert(DID.into(), doc(&["acme.com/@Billing"], json!([])));
        sources
            .names
            .insert("acme.com/@billing".into(), DID.into());
        assert_eq!(
            service_with(sources)
                .resolve(DID)
                .await,
            None
        );
    }

    #[tokio::test]
    async fn test_resolve_uses_first_verified_candidate() {
        let mut sources = FakeSources::default();
        sources
            .docs
            .insert(DID.into(), doc(&["acme.com/@broken", "acme.com/@second", "acme.com/@third"], json!([])));
        sources
            .names
            .insert("acme.com/@second".into(), DID.into());
        sources
            .names
            .insert("acme.com/@third".into(), DID.into());
        let name = service_with(sources)
            .resolve(DID)
            .await
            .expect("second candidate");
        assert_eq!(name.name, "acme.com/@second");
    }

    #[tokio::test]
    async fn test_resolve_without_sources_is_none() {
        let mut sources = FakeSources::default();
        sources
            .docs
            .insert(DID.into(), doc(&[], json!([])));
        assert_eq!(
            service_with(sources)
                .resolve(DID)
                .await,
            None
        );
        assert_eq!(
            service_with(FakeSources::default())
                .resolve(DID)
                .await,
            None
        );
    }

    #[tokio::test]
    async fn test_resolve_card_name_with_control_characters_is_none() {
        let mut sources = FakeSources::default();
        sources
            .docs
            .insert(DID.into(), doc(&[], card_service()));
        sources
            .cards
            .insert("https://acme.com/card.json".into(), json!({ "name": "Billing\u{7}Bot" }));
        assert_eq!(
            service_with(sources)
                .resolve(DID)
                .await,
            None
        );
    }

    #[tokio::test]
    async fn test_resolve_card_unreachable_is_none() {
        let mut sources = FakeSources::default();
        sources
            .docs
            .insert(DID.into(), doc(&[], card_service()));
        assert_eq!(
            service_with(sources)
                .resolve(DID)
                .await,
            None
        );
    }

    #[tokio::test]
    async fn test_resolve_hung_did_resolution_times_out_to_none() {
        let mut sources = FakeSources::default();
        sources
            .docs
            .insert(DID.into(), doc(&[], card_service()));
        sources
            .cards
            .insert("https://acme.com/card.json".into(), json!({ "name": "Billing Bot" }));
        sources.doc_delay = Some(HUNG);
        let started = Instant::now();

        let name = service_with_short_timeout(sources)
            .resolve(DID)
            .await;

        assert_eq!(name, None);
        assert!(started.elapsed() < HUNG / 2);
    }

    #[tokio::test]
    async fn test_resolve_hung_agent_name_falls_through_to_card() {
        let mut sources = FakeSources::default();
        sources
            .docs
            .insert(DID.into(), doc(&["acme.com/@billing"], card_service()));
        sources
            .names
            .insert("acme.com/@billing".into(), DID.into());
        sources
            .cards
            .insert("https://acme.com/card.json".into(), json!({ "name": "Billing Bot" }));
        sources.name_delay = Some(HUNG);

        let name = service_with_short_timeout(sources)
            .resolve(DID)
            .await
            .expect("card name");

        assert_eq!(name.name, "Billing Bot");
        assert_eq!(name.source, DisplayNameSource::AgentCard);
    }

    #[tokio::test]
    async fn test_resolve_slow_agent_name_within_timeout_is_verified() {
        let mut sources = FakeSources::default();
        sources
            .docs
            .insert(DID.into(), doc(&["acme.com/@billing"], json!([])));
        sources
            .names
            .insert("acme.com/@billing".into(), DID.into());
        sources.name_delay = Some(SHORT_TIMEOUT);

        let name = service_with(sources)
            .resolve(DID)
            .await
            .expect("verified name");

        assert_eq!(name.source, DisplayNameSource::AgentName);
        assert!(name.verified);
    }

    async fn wait_for_name(
        service: &Arc<CallerNameService>,
        did: &str,
    ) -> CallerName {
        for _ in 0..200 {
            if let Some(entry) = service.cache.get(did)
                && let Some(name) = &entry.name
            {
                return name.clone();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("caller name for {did} never resolved");
    }

    #[tokio::test]
    async fn test_lookup_or_spawn_returns_pending_then_value_without_double_spawn() {
        let gate = Arc::new(Notify::new());
        let mut sources = FakeSources {
            gate: Some(gate.clone()),
            ..Default::default()
        };
        sources
            .docs
            .insert(DID.into(), doc(&["acme.com/@billing"], json!([])));
        sources
            .names
            .insert("acme.com/@billing".into(), DID.into());
        let sources = Arc::new(sources);
        let service = Arc::new(CallerNameService::new(sources.clone()));

        assert_eq!(service.lookup_or_spawn(DID), CallerLookup::Pending);
        assert_eq!(service.lookup_or_spawn(DID), CallerLookup::Pending);
        tokio::time::sleep(Duration::from_millis(20)).await;
        gate.notify_one();

        let resolved = wait_for_name(&service, DID).await;
        assert_eq!(resolved.name, "acme.com/@billing");
        assert_eq!(
            service
                .lookup_or_spawn(DID)
                .into_name()
                .map(|n| n.name),
            Some("acme.com/@billing".to_string())
        );
        assert_eq!(
            sources
                .doc_calls
                .load(Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn test_lookup_or_spawn_refreshes_after_ttl() {
        let mut sources = FakeSources::default();
        sources
            .docs
            .insert(DID.into(), doc(&["acme.com/@billing"], json!([])));
        sources
            .names
            .insert("acme.com/@billing".into(), DID.into());
        let sources = Arc::new(sources);
        let service = Arc::new(CallerNameService::with_ttl(sources.clone(), Duration::ZERO));

        service.lookup_or_spawn(DID);
        wait_for_name(&service, DID).await;
        while !service.inflight.is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            service
                .lookup_or_spawn(DID)
                .into_name()
                .map(|n| n.verified),
            Some(true)
        );
        for _ in 0..200 {
            if sources
                .doc_calls
                .load(Ordering::SeqCst)
                >= 2
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("stale entry was not refreshed");
    }

    #[tokio::test]
    async fn test_lookup_or_spawn_reports_finished_lookup_without_name_as_resolved() {
        let service = Arc::new(service_with(FakeSources::default()));
        service.store("did:example:unnamed", None);
        assert_eq!(service.lookup_or_spawn("did:example:unnamed"), CallerLookup::Resolved(None));
        assert_eq!(service.lookup_or_spawn("did:example:other"), CallerLookup::Pending);
    }

    #[tokio::test]
    async fn test_changed_since_reports_first_lookups_and_changed_names() {
        let service = service_with(FakeSources::default());
        let before = Utc::now() - chrono::Duration::seconds(1);
        service.store("did:example:unnamed", None);
        service.store(
            DID,
            Some(CallerName {
                name: "Billing Bot".into(),
                source: DisplayNameSource::AgentCard,
                verified: false,
                resolved_at: Utc::now(),
            }),
        );
        let mut changed = service.changed_since(before);
        changed.sort();
        assert_eq!(changed, vec!["did:example:unnamed".to_string(), DID.to_string()]);

        let after = Utc::now() + chrono::Duration::seconds(1);
        service.store("did:example:unnamed", None);
        service.store(
            DID,
            Some(CallerName {
                name: "Billing Bot".into(),
                source: DisplayNameSource::AgentCard,
                verified: false,
                resolved_at: Utc::now(),
            }),
        );
        assert!(
            service
                .changed_since(after)
                .is_empty()
        );
    }
}
