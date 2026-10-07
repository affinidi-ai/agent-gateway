//! Cached managed-agent names read from the `name` of the surface target's Agent Card.
//!
//! For A2A and AP2 surfaces with an HTTP(S) target, the dashboard shows this name in place
//! of the surface name, marked unverified. The name is self-asserted by the target, so it is
//! never signed into the identity VC or published to trust registries.
//! [`TargetCardNameService::lookup_or_spawn`] never waits.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use tracing::warn;

use crate::config::agent_surface::{AgentSurface, SurfaceProtocol};
use crate::identity::display_name::DisplayName;
use crate::observability::caller_names::{AGENT_CARD_FETCH_TIMEOUT, AGENT_CARD_MAX_BYTES};
use crate::observability::refresh_cache::RefreshCache;

pub const TARGET_CARD_NAME_TTL: Duration = Duration::from_secs(300);
const MAX_CONCURRENT_FETCHES: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardLocation {
    pub endpoint: String,
    pub card_path: Option<String>,
}

impl CardLocation {
    pub fn for_surface(surface: &AgentSurface) -> Option<Self> {
        let has_card = matches!(surface.access_point.protocol, SurfaceProtocol::A2a | SurfaceProtocol::Ap2);
        let endpoint = surface.target.endpoint.trim();
        let is_http = endpoint.starts_with("http://") || endpoint.starts_with("https://");
        (has_card && is_http).then(|| Self {
            endpoint: endpoint.to_string(),
            card_path: surface
                .access_point
                .agent_card_path
                .clone(),
        })
    }
}

#[async_trait]
pub trait TargetCardSource: Send + Sync {
    async fn fetch_agent_card(
        &self,
        location: &CardLocation,
    ) -> Option<Value>;
}

enum CardName {
    Unreadable,
    Read(Option<String>),
}

#[derive(Clone)]
struct CardEntry {
    location: CardLocation,
    name: Option<String>,
}

/// A change is a name appearing, changing, or disappearing; a target moving with the same
/// name is not.
fn card_name_changed(
    previous: Option<&CardEntry>,
    entry: &CardEntry,
) -> bool {
    previous.and_then(|p| p.name.as_ref()) != entry.name.as_ref()
}

pub struct TargetCardNameService {
    cache: Arc<RefreshCache<CardEntry>>,
    source: Arc<dyn TargetCardSource>,
}

impl TargetCardNameService {
    pub fn global() -> &'static Arc<TargetCardNameService> {
        static GLOBAL: OnceLock<Arc<TargetCardNameService>> = OnceLock::new();
        GLOBAL.get_or_init(|| Arc::new(TargetCardNameService::new(Arc::new(HttpTargetCardSource))))
    }

    pub fn new(source: Arc<dyn TargetCardSource>) -> Self {
        Self::with_ttl(source, TARGET_CARD_NAME_TTL)
    }

    pub fn with_ttl(
        source: Arc<dyn TargetCardSource>,
        ttl: Duration,
    ) -> Self {
        Self {
            cache: Arc::new(RefreshCache::new(ttl, MAX_CONCURRENT_FETCHES, card_name_changed)),
            source,
        }
    }

    /// Returns the cached name for the surface's current card location without waiting, and
    /// starts a single background refresh when the entry is missing, stale, or was read from a
    /// different location.
    pub fn lookup_or_spawn(
        self: &Arc<Self>,
        surface_id: &str,
        location: &CardLocation,
    ) -> Option<String> {
        let (cached, fresh) = match self.cache.get(surface_id) {
            Some((entry, fresh)) if entry.location == *location => (entry.name, fresh),
            _ => (None, false),
        };
        if !fresh {
            self.spawn_refresh(surface_id, location);
        }
        cached
    }

    fn spawn_refresh(
        self: &Arc<Self>,
        surface_id: &str,
        location: &CardLocation,
    ) {
        let service = Arc::clone(self);
        let owned_id = surface_id.to_string();
        let location = location.clone();
        self.cache
            .spawn_refresh(surface_id, move || async move {
                let name = match service
                    .resolve(&owned_id, &location)
                    .await
                {
                    CardName::Read(name) => name,
                    CardName::Unreadable => service.last_known_name(&owned_id, &location),
                };
                CardEntry { location, name }
            });
    }

    async fn resolve(
        &self,
        surface_id: &str,
        location: &CardLocation,
    ) -> CardName {
        let Some(card) = self
            .source
            .fetch_agent_card(location)
            .await
        else {
            return CardName::Unreadable;
        };
        let Some(raw) = card
            .get("name")
            .and_then(Value::as_str)
        else {
            return CardName::Read(None);
        };
        match DisplayName::parse(raw) {
            Ok(name) => CardName::Read(Some(name.as_str().to_string())),
            Err(e) => {
                warn!(surface_id, endpoint = %location.endpoint, error = %e, "Target Agent Card name rejected");
                CardName::Read(None)
            }
        }
    }

    fn last_known_name(
        &self,
        surface_id: &str,
        location: &CardLocation,
    ) -> Option<String> {
        self.cache
            .get(surface_id)
            .filter(|(e, _)| e.location == *location)
            .and_then(|(e, _)| e.name)
    }

    /// Surfaces whose target Agent Card name appeared, changed, or disappeared after `since`.
    pub fn changed_since(
        &self,
        since: DateTime<Utc>,
    ) -> Vec<String> {
        self.cache
            .changed_since(since)
    }
}

struct HttpTargetCardSource;

#[async_trait]
impl TargetCardSource for HttpTargetCardSource {
    async fn fetch_agent_card(
        &self,
        location: &CardLocation,
    ) -> Option<Value> {
        crate::proxy::outbound_handler::fetch_agent_card(
            &location.endpoint,
            location.card_path.as_deref(),
            "managed-agent-name",
            AGENT_CARD_FETCH_TIMEOUT,
            crate::proxy::upstream_body::UpstreamBodyLimits::new(
                AGENT_CARD_MAX_BYTES,
                None,
                AGENT_CARD_FETCH_TIMEOUT.as_secs(),
            ),
        )
        .await
    }
}

#[cfg(test)]
pub(crate) struct NoTargetCards;

#[cfg(test)]
#[async_trait]
impl TargetCardSource for NoTargetCards {
    async fn fetch_agent_card(
        &self,
        _location: &CardLocation,
    ) -> Option<Value> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct FakeSource {
        card: Mutex<Option<Value>>,
        calls: AtomicUsize,
    }

    impl FakeSource {
        fn with_card(card: Value) -> Arc<Self> {
            let source = Self::default();
            *source.card.lock().unwrap() = Some(card);
            Arc::new(source)
        }
    }

    #[async_trait]
    impl TargetCardSource for FakeSource {
        async fn fetch_agent_card(
            &self,
            _location: &CardLocation,
        ) -> Option<Value> {
            self.calls
                .fetch_add(1, Ordering::SeqCst);
            self.card
                .lock()
                .unwrap()
                .clone()
        }
    }

    fn location(endpoint: &str) -> CardLocation {
        CardLocation {
            endpoint: endpoint.to_string(),
            card_path: None,
        }
    }

    async fn wait_for(
        service: &Arc<TargetCardNameService>,
        surface_id: &str,
        location: &CardLocation,
    ) -> Option<String> {
        for _ in 0..200 {
            if service.cache.is_idle()
                && service
                    .cache
                    .get(surface_id)
                    .is_some()
            {
                return service.lookup_or_spawn(surface_id, location);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("target card lookup did not finish");
    }

    fn store(
        service: &TargetCardNameService,
        surface_id: &str,
        location: CardLocation,
        name: Option<String>,
    ) {
        service
            .cache
            .store(surface_id, CardEntry { location, name });
    }

    fn surface(
        protocol: SurfaceProtocol,
        endpoint: &str,
    ) -> AgentSurface {
        let mut surface = AgentSurface::default();
        surface.access_point.protocol = protocol;
        surface.target.endpoint = endpoint.to_string();
        surface
    }

    #[test]
    fn test_location_for_a2a_and_ap2_http_targets_only() {
        let a2a = CardLocation::for_surface(&surface(SurfaceProtocol::A2a, "http://localhost:9000"));
        assert_eq!(a2a, Some(location("http://localhost:9000")));
        assert!(CardLocation::for_surface(&surface(SurfaceProtocol::Ap2, "https://pay.example")).is_some());
        assert_eq!(CardLocation::for_surface(&surface(SurfaceProtocol::Mcp, "http://localhost:9000")), None);
        assert_eq!(CardLocation::for_surface(&surface(SurfaceProtocol::A2a, "fabric://gw/surface")), None);
    }

    #[test]
    fn test_location_carries_access_point_card_path() {
        let mut s = surface(SurfaceProtocol::A2a, "http://localhost:9000/api");
        s.access_point.agent_card_path = Some("/card.json".into());
        let loc = CardLocation::for_surface(&s).unwrap();
        assert_eq!(loc.card_path.as_deref(), Some("/card.json"));
    }

    #[tokio::test]
    async fn test_lookup_returns_none_then_card_name() {
        let source = FakeSource::with_card(json!({"name": "  DateTime Agent  "}));
        let service = Arc::new(TargetCardNameService::new(source.clone()));
        let loc = location("http://localhost:9000");

        assert_eq!(service.lookup_or_spawn("s1", &loc), None);
        assert_eq!(
            wait_for(&service, "s1", &loc)
                .await
                .as_deref(),
            Some("DateTime Agent")
        );
        assert_eq!(
            source
                .calls
                .load(Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn test_card_without_valid_name_is_none() {
        for card in [json!({"description": "no name"}), json!({"name": "bad\nname"}), json!({"name": 7})] {
            let service = Arc::new(TargetCardNameService::new(FakeSource::with_card(card)));
            let loc = location("http://localhost:9000");
            service.lookup_or_spawn("s1", &loc);
            assert_eq!(wait_for(&service, "s1", &loc).await, None);
        }
    }

    #[tokio::test]
    async fn test_unreachable_card_is_none() {
        let service = Arc::new(TargetCardNameService::new(Arc::new(FakeSource::default())));
        let loc = location("http://localhost:9000");
        service.lookup_or_spawn("s1", &loc);
        assert_eq!(wait_for(&service, "s1", &loc).await, None);
    }

    async fn refresh(
        service: &Arc<TargetCardNameService>,
        surface_id: &str,
        location: &CardLocation,
    ) -> Option<String> {
        service
            .cache
            .expire(surface_id);
        service.lookup_or_spawn(surface_id, location);
        for _ in 0..200 {
            if service.cache.is_idle() {
                return service
                    .cache
                    .get(surface_id)
                    .and_then(|(e, _)| e.name);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("target card refresh did not finish");
    }

    #[tokio::test]
    async fn test_unreachable_card_keeps_last_known_name_without_change() {
        let source = FakeSource::with_card(json!({"name": "DateTime Agent"}));
        let service = Arc::new(TargetCardNameService::new(source.clone()));
        let loc = location("http://localhost:9000");
        service.lookup_or_spawn("s1", &loc);
        wait_for(&service, "s1", &loc).await;

        let since = Utc::now();
        *source.card.lock().unwrap() = None;
        assert_eq!(
            refresh(&service, "s1", &loc)
                .await
                .as_deref(),
            Some("DateTime Agent")
        );
        assert!(
            service
                .changed_since(since)
                .is_empty()
        );
        assert_eq!(
            source
                .calls
                .load(Ordering::SeqCst),
            2
        );
    }

    #[tokio::test]
    async fn test_reachable_card_without_name_clears_last_known_name() {
        let source = FakeSource::with_card(json!({"name": "DateTime Agent"}));
        let service = Arc::new(TargetCardNameService::new(source.clone()));
        let loc = location("http://localhost:9000");
        service.lookup_or_spawn("s1", &loc);
        wait_for(&service, "s1", &loc).await;

        let since = Utc::now();
        *source.card.lock().unwrap() = Some(json!({"description": "renamed away"}));
        assert_eq!(refresh(&service, "s1", &loc).await, None);
        assert_eq!(service.changed_since(since), vec!["s1".to_string()]);
    }

    #[tokio::test]
    async fn test_unreachable_card_at_new_location_does_not_reuse_old_name() {
        let source = FakeSource::with_card(json!({"name": "Old Agent"}));
        let service = Arc::new(TargetCardNameService::new(source.clone()));
        let old = location("http://localhost:9000");
        service.lookup_or_spawn("s1", &old);
        wait_for(&service, "s1", &old).await;

        *source.card.lock().unwrap() = None;
        let new = location("http://localhost:9100");
        assert_eq!(refresh(&service, "s1", &new).await, None);
    }

    #[tokio::test]
    async fn test_location_change_hides_stale_name_and_refetches() {
        let source = FakeSource::with_card(json!({"name": "Old Agent"}));
        let service = Arc::new(TargetCardNameService::new(source.clone()));
        let old = location("http://localhost:9000");
        service.lookup_or_spawn("s1", &old);
        wait_for(&service, "s1", &old).await;

        *source.card.lock().unwrap() = Some(json!({"name": "New Agent"}));
        let new = location("http://localhost:9100");
        assert_eq!(service.lookup_or_spawn("s1", &new), None);
        for _ in 0..200 {
            if service
                .lookup_or_spawn("s1", &new)
                .as_deref()
                == Some("New Agent")
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("moved target was not re-read");
    }

    #[tokio::test]
    async fn test_fresh_entry_is_not_refetched() {
        let source = FakeSource::with_card(json!({"name": "DateTime Agent"}));
        let service = Arc::new(TargetCardNameService::new(source.clone()));
        let loc = location("http://localhost:9000");
        service.lookup_or_spawn("s1", &loc);
        wait_for(&service, "s1", &loc).await;
        assert_eq!(
            service
                .lookup_or_spawn("s1", &loc)
                .as_deref(),
            Some("DateTime Agent")
        );
        assert_eq!(
            source
                .calls
                .load(Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn test_changed_since_reports_only_name_changes() {
        let source = FakeSource::with_card(json!({"name": "DateTime Agent"}));
        let service = Arc::new(TargetCardNameService::new(source));
        let before = Utc::now();
        store(&service, "named", location("http://a"), Some("DateTime Agent".into()));
        store(&service, "unnamed", location("http://b"), None);
        assert_eq!(service.changed_since(before), vec!["named".to_string()]);

        let after = Utc::now();
        store(&service, "named", location("http://a"), Some("DateTime Agent".into()));
        assert!(
            service
                .changed_since(after)
                .is_empty()
        );
        store(&service, "named", location("http://a"), None);
        assert_eq!(service.changed_since(after), vec!["named".to_string()]);
    }
}
