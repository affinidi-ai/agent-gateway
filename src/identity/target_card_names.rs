//! Cached managed-agent names read from the `name` of the surface target's Agent Card.
//!
//! For A2A and AP2 surfaces with an HTTP(S) target, the dashboard shows this name in place
//! of the surface name. The name is self-asserted by the target and never verified, so it is
//! never signed into the identity VC or published to trust registries. A surface with
//! `target.response_auth` has its card read under it, and an answer that fails shows no name.
//! [`TargetCardNameService::lookup_or_spawn`] never waits.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use tracing::warn;

use crate::config::agent_surface::{AgentSurface, SurfaceProtocol};
use crate::config::response_auth::ResponseAuthConfig;
use crate::identity::display_name::DisplayName;
use crate::observability::caller_names::{AGENT_CARD_FETCH_TIMEOUT, AGENT_CARD_MAX_BYTES};
use crate::observability::refresh_cache::RefreshCache;
use crate::proxy::response_auth::ResponseAuthFailure;

pub const TARGET_CARD_NAME_TTL: Duration = Duration::from_secs(300);
const MAX_CONCURRENT_FETCHES: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardLocation {
    pub endpoint: String,
    pub card_path: Option<String>,
}

impl CardLocation {
    /// The endpoint never carries userinfo, so a card fetch sends no credential.
    pub fn for_surface(surface: &AgentSurface) -> Option<Self> {
        let has_card = matches!(surface.access_point.protocol, SurfaceProtocol::A2a | SurfaceProtocol::Ap2);
        let endpoint = surface.target.endpoint.trim();
        let is_http = endpoint.starts_with("http://") || endpoint.starts_with("https://");
        if !(has_card && is_http) {
            return None;
        }
        Some(Self {
            endpoint: without_userinfo(endpoint)?,
            card_path: surface
                .access_point
                .agent_card_path
                .clone(),
        })
    }
}

/// `None` when the endpoint doesn't parse, since its userinfo can't then be told apart.
fn without_userinfo(endpoint: &str) -> Option<String> {
    let mut url = url::Url::parse(endpoint).ok()?;
    if url.username().is_empty() && url.password().is_none() {
        return Some(endpoint.to_string());
    }
    url.set_username("").ok()?;
    url.set_password(None).ok()?;
    Some(url.to_string())
}

#[async_trait]
pub trait TargetCardSource: Send + Sync {
    async fn fetch_agent_card(
        &self,
        location: &CardLocation,
    ) -> Option<Value>;

    /// [`Self::fetch_agent_card`] for a `surface` with `target.response_auth`, whose answer
    /// must pass it: `Err` when it does not or cannot be checked.
    async fn fetch_checked_agent_card(
        &self,
        location: &CardLocation,
        _surface: &AgentSurface,
    ) -> Result<Option<Value>, ResponseAuthFailure> {
        Ok(self
            .fetch_agent_card(location)
            .await)
    }
}

enum CardName {
    Unreadable,
    Read(Option<String>),
}

#[derive(Clone)]
struct CardEntry {
    location: CardLocation,
    response_auth: Option<ResponseAuthConfig>,
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

    /// [`Self::lookup_or_spawn_for`] of a surface `surface_id` without Response authentication.
    #[cfg(test)]
    pub fn lookup_or_spawn(
        self: &Arc<Self>,
        surface_id: &str,
        location: &CardLocation,
    ) -> Option<String> {
        self.lookup(surface_id, location, None)
    }

    /// Returns the cached name for `surface`'s current card location without waiting, and
    /// starts a single background refresh when the entry is missing, stale, or was read from a
    /// different location or under another `target.response_auth`. A card read under the
    /// surface's Response authentication that fails it yields no name.
    pub fn lookup_or_spawn_for(
        self: &Arc<Self>,
        surface: &AgentSurface,
        location: &CardLocation,
    ) -> Option<String> {
        self.lookup(&surface.surface_id, location, Some(surface))
    }

    fn lookup(
        self: &Arc<Self>,
        surface_id: &str,
        location: &CardLocation,
        surface: Option<&AgentSurface>,
    ) -> Option<String> {
        let checked_by = surface.filter(|surface| {
            surface
                .target
                .response_auth
                .is_some()
        });
        let response_auth = checked_by.and_then(|surface| {
            surface
                .target
                .response_auth
                .clone()
        });
        let (cached, fresh) = match self.cache.get(surface_id) {
            Some((entry, fresh)) if entry.location == *location && entry.response_auth == response_auth => {
                (entry.name, fresh)
            }
            _ => (None, false),
        };
        if !fresh {
            self.spawn_refresh(surface_id, location, checked_by.map(|surface| Arc::new(surface.clone())));
        }
        cached
    }

    fn spawn_refresh(
        self: &Arc<Self>,
        surface_id: &str,
        location: &CardLocation,
        checked_by: Option<Arc<AgentSurface>>,
    ) {
        let service = Arc::clone(self);
        let owned_id = surface_id.to_string();
        let location = location.clone();
        self.cache
            .spawn_refresh(surface_id, move || async move {
                let response_auth = checked_by
                    .as_ref()
                    .and_then(|surface| {
                        surface
                            .target
                            .response_auth
                            .clone()
                    });
                let name = match service
                    .resolve(&owned_id, &location, checked_by.as_deref())
                    .await
                {
                    CardName::Read(name) => name,
                    CardName::Unreadable => service.last_known_name(&owned_id, &location, response_auth.as_ref()),
                };
                CardEntry { location, response_auth, name }
            });
    }

    async fn resolve(
        &self,
        surface_id: &str,
        location: &CardLocation,
        checked_by: Option<&AgentSurface>,
    ) -> CardName {
        let fetched = match checked_by {
            Some(surface) => {
                self.source
                    .fetch_checked_agent_card(location, surface)
                    .await
            }
            None => Ok(self
                .source
                .fetch_agent_card(location)
                .await),
        };
        let card = match fetched {
            Ok(Some(card)) => card,
            Ok(None) => return CardName::Unreadable,
            Err(failure) => {
                warn!(
                    surface_id,
                    endpoint = %location.endpoint,
                    reason = failure.reason(),
                    "Target Agent Card failed Response authentication; no name shown"
                );
                return CardName::Read(None);
            }
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
        response_auth: Option<&ResponseAuthConfig>,
    ) -> Option<String> {
        self.cache
            .get(surface_id)
            .filter(|(e, _)| e.location == *location && e.response_auth.as_ref() == response_auth)
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

fn card_limits() -> crate::proxy::upstream_body::UpstreamBodyLimits {
    crate::proxy::upstream_body::UpstreamBodyLimits::new(AGENT_CARD_MAX_BYTES, None, AGENT_CARD_FETCH_TIMEOUT.as_secs())
}

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
            card_limits(),
        )
        .await
    }

    async fn fetch_checked_agent_card(
        &self,
        location: &CardLocation,
        surface: &AgentSurface,
    ) -> Result<Option<Value>, ResponseAuthFailure> {
        checked_card(
            location,
            surface,
            crate::gateways::connection_points::message_processor::get_secrets_store(),
            crate::proxy::server::get_certificates_store(),
        )
        .await
    }
}

/// The card at `location`, read under `surface`'s Response authentication with its key secret
/// from `secrets` and its certificates from `certificates`.
async fn checked_card(
    location: &CardLocation,
    surface: &AgentSurface,
    secrets: Option<Arc<dyn crate::secrets::SecretsStore>>,
    certificates: Option<Arc<dyn crate::certificates::CertificateStore>>,
) -> Result<Option<Value>, ResponseAuthFailure> {
    crate::proxy::outbound_handler::fetch_checked_agent_card(
        &location.endpoint,
        location.card_path.as_deref(),
        "managed-agent-name",
        AGENT_CARD_FETCH_TIMEOUT,
        card_limits(),
        crate::proxy::outbound_handler::CardCheck {
            surface,
            secrets: secrets.as_ref(),
            certificates: certificates.as_ref(),
        },
    )
    .await
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
    use axum::response::IntoResponse;
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
        service.cache.store(
            surface_id,
            CardEntry {
                location,
                response_auth: None,
                name,
            },
        );
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

    #[test]
    fn test_location_drops_userinfo() {
        for (raw, expected) in [
            ("https://user:pw@agent.example/a2a", Some("https://agent.example/a2a")),
            ("https://user@agent.example:8443/a2a?x=1", Some("https://agent.example:8443/a2a?x=1")),
            ("https://:pw@agent.example", Some("https://agent.example/")),
            ("http://localhost:9000", Some("http://localhost:9000")),
            ("http://user:pw@", None),
        ] {
            let loc = CardLocation::for_surface(&surface(SurfaceProtocol::A2a, raw));
            assert_eq!(
                loc.map(|loc| loc.endpoint)
                    .as_deref(),
                expected,
                "{raw}"
            );
        }
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

    /// Reads cards as [`HttpTargetCardSource`] does, with its own stores.
    struct CheckedSource {
        secrets: Option<Arc<dyn crate::secrets::SecretsStore>>,
        certificates: Option<Arc<dyn crate::certificates::CertificateStore>>,
    }

    #[async_trait]
    impl TargetCardSource for CheckedSource {
        async fn fetch_agent_card(
            &self,
            _location: &CardLocation,
        ) -> Option<Value> {
            panic!("a surface with Response authentication reads its card checked")
        }

        async fn fetch_checked_agent_card(
            &self,
            location: &CardLocation,
            surface: &AgentSurface,
        ) -> Result<Option<Value>, ResponseAuthFailure> {
            checked_card(location, surface, self.secrets.clone(), self.certificates.clone()).await
        }
    }

    fn checked_surface(
        endpoint: &str,
        response_auth: Value,
    ) -> AgentSurface {
        serde_json::from_value(json!({
            "surface_id": format!("bravo-{}", uuid::Uuid::new_v4()), "name": "Bravo",
            "access_point": {"listen_address": "0.0.0.0:9000", "route": "/bravo", "protocol": "a2a"},
            "target": {"endpoint": endpoint, "response_auth": response_auth}
        }))
        .expect("surface parses")
    }

    /// The name shown for `surface` once its card was read through `source`.
    async fn checked_name(
        source: CheckedSource,
        surface: &AgentSurface,
    ) -> Option<String> {
        let service = Arc::new(TargetCardNameService::new(Arc::new(source)));
        let location = CardLocation::for_surface(surface).expect("an A2A http Target");
        service.lookup_or_spawn_for(surface, &location);
        for _ in 0..400 {
            if service.cache.is_idle()
                && service
                    .cache
                    .get(&surface.surface_id)
                    .is_some()
            {
                return service.lookup_or_spawn_for(surface, &location);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("target card lookup did not finish");
    }

    /// A Target on 127.0.0.1 serving its card named `Bravo Agent`, with the key of
    /// [`crate::proxy::response_auth::api_key_bravo`] when `keyed`.
    async fn card_target(keyed: bool) -> String {
        use crate::proxy::response_auth::{BRAVO_KEY, BRAVO_KEY_HEADER};
        let app = axum::Router::new().route(
            "/.well-known/agent-card.json",
            axum::routing::get(move || async move {
                let mut response = axum::Json(json!({"name": "Bravo Agent"})).into_response();
                if keyed {
                    response.headers_mut().insert(
                        axum::http::HeaderName::from_bytes(BRAVO_KEY_HEADER.as_bytes()).expect("a valid header name"),
                        axum::http::HeaderValue::from_static(BRAVO_KEY),
                    );
                }
                response
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await });
        url
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_a_card_without_the_response_key_yields_no_name_and_one_with_it_does() {
        use crate::proxy::response_auth::{api_key_bravo, bravo_key_store};
        let (_dir, secrets) = bravo_key_store().await;
        for (keyed, expected) in [(false, None), (true, Some("Bravo Agent"))] {
            let surface = checked_surface(&card_target(keyed).await, api_key_bravo());
            let source = CheckedSource {
                secrets: Some(Arc::clone(&secrets)),
                certificates: None,
            };
            assert_eq!(
                checked_name(source, &surface)
                    .await
                    .as_deref(),
                expected,
                "keyed: {keyed}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_a_card_from_a_server_failing_the_mtls_trust_yields_no_name_and_a_trusted_one_does() {
        use crate::proxy::response_auth::{pinned_bravo, trusted_target, untrusted_target};
        let (trusted_port, _trusted_dir, trusted_certificates) = trusted_target(r#"{"name":"Bravo Agent"}"#).await;
        let (untrusted_port, _untrusted_dir, untrusted_certificates) = untrusted_target().await;
        for (port, certificates, expected) in
            [(trusted_port, trusted_certificates, Some("Bravo Agent")), (untrusted_port, untrusted_certificates, None)]
        {
            let surface = checked_surface(&format!("https://127.0.0.1:{port}"), pinned_bravo());
            let source = CheckedSource {
                secrets: None,
                certificates: Some(certificates),
            };
            assert_eq!(
                checked_name(source, &surface)
                    .await
                    .as_deref(),
                expected,
                "port {port}"
            );
        }
    }

    #[tokio::test]
    async fn test_a_surface_without_response_authentication_reads_its_card_unchecked() {
        let source = FakeSource::with_card(json!({"name": "DateTime Agent"}));
        let service = Arc::new(TargetCardNameService::new(source.clone()));
        let plain = surface(SurfaceProtocol::A2a, "http://localhost:9000");
        let loc = CardLocation::for_surface(&plain).unwrap();
        service.lookup_or_spawn_for(&plain, &loc);
        assert_eq!(
            wait_for(&service, &plain.surface_id, &loc)
                .await
                .as_deref(),
            Some("DateTime Agent")
        );
    }
}
