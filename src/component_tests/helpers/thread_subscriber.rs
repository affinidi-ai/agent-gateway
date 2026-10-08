//! Installs a subscriber as the current thread's default in a way that stays
//! reliable while other tests emit events on their own threads.
//!
//! `tracing-core` 0.1.36 caches each callsite's interest the first time the
//! callsite fires. While only one dispatcher is registered, it computes that
//! interest from the default subscriber of whichever thread fires first. A test
//! thread with no subscriber then caches the callsite as never enabled, and a
//! capture installed on another thread misses the event until the next
//! dispatcher registers. Keeping one extra dispatcher registered for the whole
//! run makes `tracing-core` combine the interest of every live dispatcher
//! instead, so a callsite seen while a capture is alive is never cached as
//! disabled. This relies on `tracing-core` internals, so recheck it when that
//! crate is upgraded.

use std::sync::OnceLock;

use tracing::Dispatch;
use tracing::subscriber::{DefaultGuard, NoSubscriber};

static EXTRA_DISPATCHER: OnceLock<Dispatch> = OnceLock::new();

/// Sets `subscriber` as the current thread's default until the guard drops.
pub(crate) fn set_thread_default<S>(subscriber: S) -> DefaultGuard
where
    S: tracing::Subscriber + Send + Sync + 'static,
{
    EXTRA_DISPATCHER.get_or_init(|| Dispatch::new(NoSubscriber::new()));
    tracing::subscriber::set_default(subscriber)
}

#[cfg(test)]
mod tests {
    use super::super::audit_events::AuditEvents;

    fn emit_probe() {
        tracing::info!(target: "audit", event = "thread_subscriber.probe");
    }

    #[test]
    fn a_capture_sees_an_event_first_emitted_on_a_thread_without_a_subscriber() {
        let audit = AuditEvents::capture();
        std::thread::spawn(emit_probe)
            .join()
            .unwrap();

        emit_probe();

        assert_eq!(
            audit
                .named("thread_subscriber.probe")
                .len(),
            1
        );
    }
}
