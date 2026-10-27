mod config;
mod directory;
mod event;
mod transport;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio_retry::RetryIf;
use tokio_retry::strategy::jitter;
use tracing::{debug, info, warn};

pub use config::{EventHookSettings, HookSecret};
pub use directory::{DirectoryEntry, Listing, MediatorDirectory, is_directory_mediator_id};

/// Per-gateway hook settings for in-process gateways in component tests, keyed
/// by the gateway's storage directory, so no test has to touch the process
/// environment.
#[cfg(test)]
pub(crate) mod test_settings {
    use super::EventHookSettings;

    fn registry() -> &'static dashmap::DashMap<String, EventHookSettings> {
        static SETTINGS: std::sync::OnceLock<dashmap::DashMap<String, EventHookSettings>> = std::sync::OnceLock::new();
        SETTINGS.get_or_init(dashmap::DashMap::new)
    }

    pub(crate) struct Registration(String);

    impl Drop for Registration {
        fn drop(&mut self) {
            registry().remove(&self.0);
        }
    }

    pub(crate) fn install(
        key: &str,
        settings: EventHookSettings,
    ) -> Registration {
        registry().insert(key.to_string(), settings);
        Registration(key.to_string())
    }

    pub(crate) fn get(key: &str) -> Option<EventHookSettings> {
        registry()
            .get(key)
            .map(|settings| settings.clone())
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    pub(crate) use super::transport::tests::{Captured, serve};
}
pub use event::{ConnectionPointPayload, EventKind, HookEvent};
pub use transport::HookOutcome;

/// Lifecycle deliveries (`creation_*`, `created`, `deleted`) in flight at once;
/// further events are dropped with a warning so an unresponsive receiver
/// cannot starve other background work.
const MAX_IN_FLIGHT_LIFECYCLE_DELIVERIES: usize = 64;

/// `connected` deliveries in flight at once. They have their own pool because
/// a restart emits one per listener and they can be dropped, so a burst of
/// them must never take permits from lifecycle events.
const MAX_IN_FLIGHT_CONNECTED_DELIVERIES: usize = 16;

pub struct EventHook {
    hook_url: String,
    hook_timeout: Duration,
    hook_secret: Option<HookSecret>,
    sequence: AtomicU64,
    lifecycle_permits: Arc<Semaphore>,
    connected_permits: Arc<Semaphore>,
}

enum Failure {
    Retry(String),
    Rejected,
}

impl EventHook {
    pub fn new(settings: EventHookSettings) -> Option<Arc<Self>> {
        Self::with_capacity(settings, MAX_IN_FLIGHT_LIFECYCLE_DELIVERIES, MAX_IN_FLIGHT_CONNECTED_DELIVERIES)
    }

    fn with_capacity(
        settings: EventHookSettings,
        lifecycle_capacity: usize,
        connected_capacity: usize,
    ) -> Option<Arc<Self>> {
        let hook_url = settings.hook_url?;
        if settings.hook_secret.is_none() {
            warn!(
                "Event hook is enabled without a signing secret; requests are sent unsigned. Set {} to sign them",
                config::ENV_HOOK_SECRET
            );
        }
        info!(
            signed = settings.hook_secret.is_some(),
            timeout_ms = settings
                .hook_timeout
                .as_millis() as u64,
            "Event hook configured"
        );
        Some(Arc::new(Self {
            hook_url,
            hook_timeout: settings.hook_timeout,
            hook_secret: settings.hook_secret,
            sequence: AtomicU64::new(0),
            lifecycle_permits: Arc::new(Semaphore::new(lifecycle_capacity)),
            connected_permits: Arc::new(Semaphore::new(connected_capacity)),
        }))
    }

    /// Strictly increasing within the process. Seeded from the clock in
    /// microseconds, so a restart normally starts above the previous process
    /// unless the clock stepped backwards.
    fn next_sequence(&self) -> u64 {
        let clock = u64::try_from(
            chrono::Utc::now()
                .timestamp_micros()
                .max(0),
        )
        .unwrap_or(0);
        let previous = self
            .sequence
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |last| Some((last + 1).max(clock)))
            .unwrap_or_default();
        (previous + 1).max(clock)
    }

    pub fn emit(
        self: &Arc<Self>,
        kind: EventKind,
        connection_point: ConnectionPointPayload,
    ) {
        let (pool, capacity) = match kind {
            EventKind::Connected => (&self.connected_permits, MAX_IN_FLIGHT_CONNECTED_DELIVERIES),
            _ => (&self.lifecycle_permits, MAX_IN_FLIGHT_LIFECYCLE_DELIVERIES),
        };
        let Ok(permit) = pool
            .clone()
            .try_acquire_owned()
        else {
            warn!(
                event = kind.as_str(),
                connection_point_id = %connection_point.id,
                capacity,
                "Event hook delivery pool is full; dropping the event"
            );
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            warn!(
                event = kind.as_str(),
                connection_point_id = %connection_point.id,
                "Event hook has no async runtime to deliver on; dropping the event"
            );
            return;
        };
        let event = HookEvent {
            event: kind,
            event_id: uuid::Uuid::new_v4().to_string(),
            sequence: self.next_sequence(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            connection_point,
        };
        let hook = self.clone();
        runtime.spawn(async move {
            let _permit = permit;
            hook.deliver(event).await
        });
    }

    async fn deliver(
        &self,
        event: HookEvent,
    ) {
        let body = match serde_json::to_string(&event) {
            Ok(body) => body,
            Err(e) => {
                warn!(event = event.event.as_str(), error = %e, "Event hook event could not be serialized");
                return;
            }
        };
        deliver_with_retry(&event, || async {
            transport::post_json(&self.hook_url, &body, self.hook_timeout, self.hook_secret.as_ref()).await
        })
        .await;
    }
}

/// Reports `connection_point.creation_started` on construction and
/// `connection_point.creation_failed` when dropped before [`Self::created`],
/// so a creation that returns early, panics or is cancelled (for example when
/// the client disconnects) is always closed with a terminal event.
pub struct CreationGuard {
    hook: Option<Arc<EventHook>>,
    minted: ConnectionPointPayload,
    armed: bool,
}

impl CreationGuard {
    pub fn start(
        hook: Option<Arc<EventHook>>,
        minted: ConnectionPointPayload,
    ) -> Self {
        if let Some(hook) = hook.as_ref() {
            hook.emit(EventKind::CreationStarted, minted.clone());
        }
        Self { hook, minted, armed: true }
    }

    /// Runs `create` to completion on its own task and reports `created` when it
    /// succeeds, so dropping the caller mid-write cannot report `creation_failed`
    /// for a record that was stored. A failure drops the guard and reports
    /// `creation_failed`.
    pub async fn complete<T, E, F>(
        self,
        create: F,
        saved: ConnectionPointPayload,
    ) -> Result<T, E>
    where
        F: std::future::Future<Output = Result<T, E>> + Send + 'static,
        T: Send + 'static,
        E: Send + 'static,
    {
        let task = tokio::spawn(async move {
            let outcome = create.await;
            if outcome.is_ok() {
                self.created(saved);
            }
            outcome
        });
        match task.await {
            Ok(outcome) => outcome,
            Err(join) => std::panic::resume_unwind(join.into_panic()),
        }
    }

    pub fn created(
        mut self,
        saved: ConnectionPointPayload,
    ) {
        self.armed = false;
        if let Some(hook) = self.hook.as_ref() {
            hook.emit(EventKind::Created, saved);
        }
    }
}

impl Drop for CreationGuard {
    fn drop(&mut self) {
        if self.armed
            && let Some(hook) = self.hook.as_ref()
        {
            hook.emit(EventKind::CreationFailed, self.minted.clone());
        }
    }
}

async fn deliver_with_retry<F, Fut>(
    event: &HookEvent,
    send: F,
) where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = HookOutcome>,
{
    let attempts = AtomicU32::new(0);
    let result = RetryIf::start(
        crate::integrations::delivery::retry::retry_delays().map(jitter),
        || async {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
            match send().await {
                HookOutcome::Accepted => Ok(attempt),
                HookOutcome::Rejected { status, reason } => {
                    warn!(
                        event = event.event.as_str(),
                        sequence = event.sequence,
                        connection_point_id = %event.connection_point.id,
                        did = %event.connection_point.did,
                        status,
                        reason = reason.as_deref().unwrap_or(""),
                        "Event hook rejected an event; dropping it"
                    );
                    Err(Failure::Rejected)
                }
                HookOutcome::Retry { reason } => {
                    warn!(
                        event = event.event.as_str(),
                        sequence = event.sequence,
                        connection_point_id = %event.connection_point.id,
                        did = %event.connection_point.did,
                        attempt,
                        error = %reason,
                        "Event hook delivery failed"
                    );
                    Err(Failure::Retry(reason))
                }
            }
        },
        |failure: &Failure| matches!(failure, Failure::Retry(_)),
    )
    .await;
    match result {
        Ok(attempt) if event.event == EventKind::Connected => {
            debug!(event = event.event.as_str(), sequence = event.sequence, did = %event.connection_point.did, attempt, "Event hook event delivered");
        }
        Ok(attempt) => {
            info!(
                event = event.event.as_str(),
                sequence = event.sequence,
                connection_point_id = %event.connection_point.id,
                did = %event.connection_point.did,
                attempt,
                "Event hook event delivered"
            );
        }
        Err(Failure::Retry(reason)) => {
            warn!(
                event = event.event.as_str(),
                sequence = event.sequence,
                connection_point_id = %event.connection_point.id,
                did = %event.connection_point.did,
                attempts = attempts.load(Ordering::SeqCst),
                error = %reason,
                "Event hook event dropped after the last retry"
            );
        }
        Err(Failure::Rejected) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_hook::transport::tests::serve;
    use std::sync::Mutex;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn payload() -> ConnectionPointPayload {
        ConnectionPointPayload::minted("cp-1", "cp", "a cp", "gw-1", "med-1", "did:web:m.example", "did:peer:2.abc")
    }

    fn event(kind: EventKind) -> HookEvent {
        HookEvent {
            event: kind,
            event_id: "id".into(),
            sequence: 1,
            timestamp: "now".into(),
            connection_point: payload(),
        }
    }

    fn hook(
        url: String,
        secret: Option<&str>,
    ) -> Arc<EventHook> {
        EventHook::new(EventHookSettings {
            hook_url: Some(url),
            hook_secret: secret.and_then(HookSecret::new),
            hook_timeout: Duration::from_secs(5),
            directory_url: None,
        })
        .unwrap()
    }

    async fn counted(
        outcomes: Vec<HookOutcome>,
        kind: EventKind,
    ) -> (usize, Duration) {
        let calls = Mutex::new(0usize);
        let outcomes = Mutex::new(outcomes.into_iter());
        let started = tokio::time::Instant::now();
        deliver_with_retry(&event(kind), || {
            *calls.lock().unwrap() += 1;
            let next = outcomes
                .lock()
                .unwrap()
                .next()
                .unwrap_or(HookOutcome::retry("down"));
            async move { next }
        })
        .await;
        let calls = *calls.lock().unwrap();
        (calls, started.elapsed())
    }

    #[test]
    fn no_hook_url_builds_nothing() {
        assert!(EventHook::new(EventHookSettings::default()).is_none());
    }

    #[test]
    fn a_short_secret_disables_the_hook_and_builds_nothing() {
        let settings = EventHookSettings::from_lookup(|name| match name {
            config::ENV_HOOK_URL => Some("http://127.0.0.1:9/hook".to_string()),
            config::ENV_HOOK_SECRET => Some("short".to_string()),
            _ => None,
        });
        assert!(EventHook::new(settings).is_none());
    }

    #[tokio::test]
    async fn the_sequence_is_strictly_increasing_and_seeded_from_the_clock() {
        let hook = hook("http://127.0.0.1:1/hook".into(), None);
        let before = u64::try_from(chrono::Utc::now().timestamp_micros()).unwrap();
        let first = hook.next_sequence();
        let second = hook.next_sequence();
        assert!(first >= before);
        assert!(second > first);
        tokio::time::sleep(Duration::from_millis(5)).await;
        let restarted = self::hook("http://127.0.0.1:1/hook".into(), None);
        assert!(restarted.next_sequence() > second, "a new process starts above the old one");
    }

    #[tokio::test]
    async fn events_dropped_before_scheduling_take_no_sequence_number() {
        let hook = EventHook::with_capacity(
            EventHookSettings {
                hook_url: Some("http://127.0.0.1:1/hook".into()),
                ..EventHookSettings::default()
            },
            0,
            0,
        )
        .unwrap();
        for _ in 0..4 {
            hook.emit(EventKind::Connected, payload());
            hook.emit(EventKind::Deleted, payload());
        }
        assert_eq!(
            hook.sequence
                .load(Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn emit_posts_the_event_in_the_background() {
        let (url, captured) = serve(204, "").await;
        let hook = hook(url, None);
        hook.emit(EventKind::CreationStarted, payload());
        let started = std::time::Instant::now();
        while captured
            .lock()
            .unwrap()
            .is_empty()
        {
            assert!(started.elapsed() < Duration::from_secs(3));
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let request = captured.lock().unwrap()[0].clone();
        assert_eq!(request.method, "POST");
        assert_eq!(request.headers["content-type"], "application/json");
        assert!(
            request
                .headers
                .get("x-webhook-signature-256")
                .is_none()
        );
        let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();
        assert_eq!(body["event"], "connection_point.creation_started");
        assert!(body["event_id"].is_string());
        assert!(body["sequence"].is_u64());
        assert!(body["timestamp"].is_string());
        let cp = &body["connection_point"];
        assert_eq!(cp["id"], "cp-1");
        assert_eq!(cp["name"], "cp");
        assert_eq!(cp["description"], "a cp");
        assert_eq!(cp["gateway_id"], "gw-1");
        assert_eq!(cp["mediator_id"], "med-1");
        assert_eq!(cp["mediator_did"], "did:web:m.example");
        assert_eq!(cp["did"], "did:peer:2.abc");
        assert_eq!(cp["did_method"], "peer");
    }

    #[tokio::test]
    async fn emit_signs_with_a_secret_over_the_exact_body() {
        let (url, captured) = serve(204, "").await;
        let hook = hook(url, Some(SECRET));
        hook.emit(EventKind::Created, payload());
        let started = std::time::Instant::now();
        while captured
            .lock()
            .unwrap()
            .is_empty()
        {
            assert!(started.elapsed() < Duration::from_secs(3));
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let request = captured.lock().unwrap()[0].clone();
        let timestamp = request.headers["x-webhook-timestamp"]
            .to_str()
            .unwrap();
        let expected =
            crate::integrations::webhook_signing::sign_timestamped_payload(SECRET, timestamp, request.body.as_bytes())
                .unwrap();
        assert_eq!(request.headers["x-webhook-signature-256"], format!("sha256={expected}").as_str());
    }

    #[tokio::test]
    async fn events_beyond_the_delivery_pool_are_dropped() {
        let (url, captured) = serve(204, "").await;
        let hook = EventHook::with_capacity(
            EventHookSettings {
                hook_url: Some(url),
                ..EventHookSettings::default()
            },
            0,
            0,
        )
        .unwrap();
        hook.emit(EventKind::Created, payload());
        hook.emit(EventKind::Connected, payload());
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            captured
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_hook_that_never_answers_never_delays_the_caller() {
        let app = axum::Router::new().route(
            "/{*path}",
            axum::routing::any(|| async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                axum::http::StatusCode::NO_CONTENT
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap();
        });
        let hook = hook(url, None);
        let started = std::time::Instant::now();
        for kind in [EventKind::CreationStarted, EventKind::Created, EventKind::Connected, EventKind::Deleted] {
            hook.emit(kind, payload());
        }
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    }

    #[tokio::test(start_paused = true)]
    async fn a_retryable_failure_is_retried_on_the_integration_schedule_then_dropped() {
        let (calls, elapsed) = counted(vec![], EventKind::Created).await;
        assert_eq!(calls, 6, "the first attempt and five retries");
        assert!(elapsed <= Duration::from_secs(31), "{elapsed:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn the_schedule_is_the_one_integration_publishes_use() {
        let seconds: Vec<u64> = crate::integrations::delivery::retry::retry_delays()
            .map(|delay| delay.as_secs())
            .collect();
        assert_eq!(seconds, vec![1, 2, 4, 8, 16]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_retry_that_succeeds_stops_retrying() {
        let (calls, _) = counted(
            vec![
                HookOutcome::retry("hook answered 503"),
                HookOutcome::retry("hook answered 503"),
                HookOutcome::Accepted,
            ],
            EventKind::Created,
        )
        .await;
        assert_eq!(calls, 3);
    }

    #[tokio::test(start_paused = true)]
    async fn auth_failures_are_retried_like_outages() {
        let reason = "hook answered 401 Unauthorized: the receiver rejected the signature".to_string();
        let (calls, _) = counted(
            vec![HookOutcome::retry(reason.clone()), HookOutcome::retry(reason), HookOutcome::Accepted],
            EventKind::Created,
        )
        .await;
        assert_eq!(calls, 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_permanent_rejection_is_dropped_without_a_retry() {
        let (calls, _) = counted(
            vec![HookOutcome::Rejected {
                status: 422,
                reason: Some("not_eligible".into()),
            }],
            EventKind::Created,
        )
        .await;
        assert_eq!(calls, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn an_accepted_event_is_sent_once() {
        let (calls, _) = counted(vec![HookOutcome::Accepted], EventKind::Connected).await;
        assert_eq!(calls, 1);
    }

    async fn wait_for(
        captured: &Arc<Mutex<Vec<crate::event_hook::transport::tests::Captured>>>,
        count: usize,
    ) {
        let started = std::time::Instant::now();
        while captured.lock().unwrap().len() < count {
            assert!(started.elapsed() < Duration::from_secs(3), "expected {count} requests");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn kinds(captured: &Arc<Mutex<Vec<crate::event_hook::transport::tests::Captured>>>) -> Vec<String> {
        captured
            .lock()
            .unwrap()
            .iter()
            .map(|request| {
                let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();
                body["event"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect()
    }

    #[tokio::test]
    async fn connected_events_cannot_take_permits_from_lifecycle_events() {
        let (url, captured) = serve(204, "").await;
        let hook = EventHook::with_capacity(
            EventHookSettings {
                hook_url: Some(url),
                ..EventHookSettings::default()
            },
            4,
            0,
        )
        .unwrap();
        for _ in 0..32 {
            hook.emit(EventKind::Connected, payload());
        }
        hook.emit(EventKind::Deleted, payload());
        wait_for(&captured, 1).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(kinds(&captured), vec!["connection_point.deleted"]);
    }

    #[tokio::test]
    async fn lifecycle_events_cannot_take_permits_from_connected_events() {
        let (url, captured) = serve(204, "").await;
        let hook = EventHook::with_capacity(
            EventHookSettings {
                hook_url: Some(url),
                ..EventHookSettings::default()
            },
            0,
            4,
        )
        .unwrap();
        hook.emit(EventKind::Deleted, payload());
        hook.emit(EventKind::Connected, payload());
        wait_for(&captured, 1).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(kinds(&captured), vec!["connection_point.connected"]);
    }

    #[test]
    fn emit_without_a_runtime_drops_the_event_instead_of_panicking() {
        let hook = hook("http://127.0.0.1:1/hook".into(), None);
        hook.emit(EventKind::Created, payload());
    }

    #[tokio::test]
    async fn a_guard_that_returns_early_reports_creation_failed_after_started() {
        let (url, captured) = serve(204, "").await;
        let hook = hook(url, None);
        {
            let _creation = CreationGuard::start(Some(hook), payload());
        }
        wait_for(&captured, 2).await;
        let mut seen = kinds(&captured);
        seen.sort();
        assert_eq!(seen, vec!["connection_point.creation_failed", "connection_point.creation_started"]);
    }

    #[tokio::test]
    async fn a_guard_whose_future_is_dropped_reports_creation_failed() {
        let (url, captured) = serve(204, "").await;
        let hook = hook(url, None);
        let creation = async {
            let _creation = CreationGuard::start(Some(hook), payload());
            std::future::pending::<()>().await;
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(50), creation)
                .await
                .is_err()
        );
        wait_for(&captured, 2).await;
        assert!(kinds(&captured).contains(&"connection_point.creation_failed".to_string()));
    }

    #[tokio::test]
    async fn a_completed_write_reports_created_even_when_the_caller_is_dropped() {
        let (url, captured) = serve(204, "").await;
        let hook = hook(url, None);
        let wrote = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = wrote.clone();
        let caller = CreationGuard::start(Some(hook), payload()).complete(
            async move {
                tokio::time::sleep(Duration::from_millis(150)).await;
                flag.store(true, Ordering::SeqCst);
                Ok::<_, String>(())
            },
            payload(),
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(30), caller)
                .await
                .is_err()
        );
        wait_for(&captured, 2).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(wrote.load(Ordering::SeqCst));
        let mut seen = kinds(&captured);
        seen.sort();
        assert_eq!(seen, vec!["connection_point.created", "connection_point.creation_started"]);
    }

    #[tokio::test]
    async fn a_failed_write_reports_creation_failed_and_returns_the_error() {
        let (url, captured) = serve(204, "").await;
        let hook = hook(url, None);
        let outcome = CreationGuard::start(Some(hook), payload())
            .complete(async { Err::<(), _>("disk full") }, payload())
            .await;
        assert_eq!(outcome, Err("disk full"));
        wait_for(&captured, 2).await;
        let mut seen = kinds(&captured);
        seen.sort();
        assert_eq!(seen, vec!["connection_point.creation_failed", "connection_point.creation_started"]);
    }

    #[tokio::test]
    async fn a_guard_that_reports_created_never_reports_creation_failed() {
        let (url, captured) = serve(204, "").await;
        let hook = hook(url, None);
        CreationGuard::start(Some(hook), payload()).created(payload());
        wait_for(&captured, 2).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut seen = kinds(&captured);
        seen.sort();
        assert_eq!(seen, vec!["connection_point.created", "connection_point.creation_started"]);
    }

    #[tokio::test]
    async fn a_guard_without_a_hook_does_nothing() {
        let _creation = CreationGuard::start(None, payload());
    }
}
