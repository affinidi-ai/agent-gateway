//! The audit sinks and the events each one selects.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use parking_lot::RwLock;
use tokio::sync::watch;

use crate::audit::catalog::{AUDIT_EVENTS, event_bit};

/// A set of catalog events, one bit per event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EventMask(u64);

impl EventMask {
    /// Names that are not in the catalog are ignored.
    pub fn from_categories<'a>(categories: impl IntoIterator<Item = &'a str>) -> Self {
        Self(
            categories
                .into_iter()
                .filter_map(event_bit)
                .fold(0, |mask, bit| mask | (1 << bit)),
        )
    }

    pub fn contains(
        self,
        bit: u32,
    ) -> bool {
        bit < u64::BITS && self.0 & (1 << bit) != 0
    }

    #[cfg(test)]
    pub fn categories(self) -> Vec<&'static str> {
        AUDIT_EVENTS
            .iter()
            .filter(|event| event_bit(event.category).is_some_and(|bit| self.contains(bit)))
            .map(|event| event.category)
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SinkId {
    AuditLog,
    Integration(String),
}

impl SinkId {
    /// Metric and log label: `audit_log`, or the integration's id.
    pub fn label(&self) -> &str {
        match self {
            SinkId::AuditLog => "audit_log",
            SinkId::Integration(id) => id,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Sink {
    pub id: SinkId,
    pub events: EventMask,
    /// Records older than this are skipped for this sink instead of delivered.
    pub drop_older_than: Option<Duration>,
}

impl Sink {
    pub fn new(
        id: SinkId,
        events: EventMask,
    ) -> Self {
        Self {
            id,
            events,
            drop_older_than: None,
        }
    }

    pub fn dropping_older_than(
        mut self,
        age: Option<Duration>,
    ) -> Self {
        self.drop_older_than = age;
        self
    }
}

/// The sinks that selected each event, the union of every selection, and the
/// paused integrations.
#[derive(Debug, Default)]
pub struct SinkRegistry {
    union: EventMask,
    index: Vec<Vec<SinkId>>,
    ids: Vec<SinkId>,
    drop_older_than: HashMap<SinkId, Duration>,
    paused: Vec<SinkId>,
}

impl SinkRegistry {
    pub fn new(sinks: Vec<Sink>) -> Self {
        let mut index = vec![Vec::new(); AUDIT_EVENTS.len()];
        let mut union = 0;
        let mut ids = Vec::with_capacity(sinks.len());
        let mut drop_older_than = HashMap::new();
        for sink in sinks {
            union |= sink.events.0;
            if let Some(age) = sink.drop_older_than {
                drop_older_than.insert(sink.id.clone(), age);
            }
            for (bit, recipients) in (0..).zip(index.iter_mut()) {
                if sink.events.contains(bit) {
                    recipients.push(sink.id.clone());
                }
            }
            ids.push(sink.id);
        }
        Self {
            union: EventMask(union),
            index,
            ids,
            drop_older_than,
            paused: Vec::new(),
        }
    }

    /// Every sink, whether or not it selects any event.
    pub fn ids(&self) -> &[SinkId] {
        &self.ids
    }

    /// Integrations that exist but do not receive audit records. They are not
    /// sinks; the dispatcher keeps their parked cursors so they resume from
    /// their pause, and drops the parked cursors of every other integration.
    pub fn paused(&self) -> &[SinkId] {
        &self.paused
    }

    pub fn drop_older_than(
        &self,
        sink: &SinkId,
    ) -> Option<Duration> {
        self.drop_older_than
            .get(sink)
            .copied()
    }

    #[cfg(test)]
    pub fn wants(
        &self,
        bit: u32,
    ) -> bool {
        self.union.contains(bit)
    }

    pub fn recipients(
        &self,
        bit: u32,
    ) -> &[SinkId] {
        usize::try_from(bit)
            .ok()
            .and_then(|position| self.index.get(position))
            .map_or(&[], Vec::as_slice)
    }
}

static SINKS: LazyLock<Sinks> = LazyLock::new(Sinks::default);

/// The process-wide audit sinks.
pub fn sinks() -> &'static Sinks {
    &SINKS
}

/// The current registry. [`Sinks::wants`] reads only an atomic, so the
/// request path never takes the lock.
#[derive(Debug)]
pub struct Sinks {
    union: AtomicU64,
    registry: RwLock<Arc<SinkRegistry>>,
    changes: watch::Sender<()>,
}

impl Default for Sinks {
    fn default() -> Self {
        Self {
            union: AtomicU64::new(0),
            registry: RwLock::default(),
            changes: watch::Sender::new(()),
        }
    }
}

impl Sinks {
    /// Replaces the sinks, and the paused integrations (see
    /// [`SinkRegistry::paused`]).
    pub fn replace(
        &self,
        sinks: Vec<Sink>,
        paused: Vec<SinkId>,
    ) {
        let registry = Arc::new(SinkRegistry {
            paused,
            ..SinkRegistry::new(sinks)
        });
        let union = registry.union.0;
        *self.registry.write() = registry;
        self.union
            .store(union, Ordering::Release);
        self.changes.send_replace(());
    }

    /// Notified on every [`Sinks::replace`].
    pub fn subscribe(&self) -> watch::Receiver<()> {
        self.changes.subscribe()
    }

    pub fn wants(
        &self,
        bit: u32,
    ) -> bool {
        EventMask(
            self.union
                .load(Ordering::Acquire),
        )
        .contains(bit)
    }

    pub fn snapshot(&self) -> Arc<SinkRegistry> {
        self.registry.read().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::catalog::event_bit;

    fn bit(category: &str) -> u32 {
        event_bit(category).unwrap()
    }

    fn sink(
        id: SinkId,
        categories: &[&str],
    ) -> Sink {
        Sink::new(id, EventMask::from_categories(categories.iter().copied()))
    }

    #[test]
    fn registry_keeps_each_sinks_drop_policy() {
        let hour = Duration::from_secs(3600);
        let registry = SinkRegistry::new(vec![
            sink(SinkId::AuditLog, &[]),
            sink(integration("slack"), &["auth_failed"]).dropping_older_than(Some(hour)),
        ]);
        assert_eq!(registry.drop_older_than(&SinkId::AuditLog), None);
        assert_eq!(registry.drop_older_than(&integration("slack")), Some(hour));
        assert_eq!(registry.drop_older_than(&integration("gone")), None);
    }

    fn integration(id: &str) -> SinkId {
        SinkId::Integration(id.to_string())
    }

    #[test]
    fn sink_ids_have_a_stable_stored_form() {
        assert_eq!(serde_json::to_value(SinkId::AuditLog).unwrap(), serde_json::json!("audit_log"));
        assert_eq!(serde_json::to_value(integration("siem")).unwrap(), serde_json::json!({ "integration": "siem" }));
        let read: SinkId = serde_json::from_value(serde_json::json!({ "integration": "siem" })).unwrap();
        assert_eq!(read, integration("siem"));
    }

    #[test]
    fn mask_holds_the_named_events_and_ignores_unknown_names() {
        let mask = EventMask::from_categories(["policy_decision", "no_such_event", "auth_failed"]);
        assert!(mask.contains(bit("policy_decision")));
        assert!(mask.contains(bit("auth_failed")));
        assert!(!mask.contains(bit("trust_check")));
        assert_eq!(mask.categories(), vec!["policy_decision", "auth_failed"]);
    }

    #[test]
    fn empty_mask_holds_nothing() {
        let mask = EventMask::from_categories([]);
        assert_eq!(mask, EventMask::default());
        assert!(mask.categories().is_empty());
        assert!(!mask.contains(bit("payment")));
    }

    #[test]
    fn registry_wants_an_event_any_sink_selected() {
        let registry = SinkRegistry::new(vec![
            sink(SinkId::AuditLog, &["policy_decision"]),
            sink(integration("siem"), &["auth_failed"]),
        ]);
        assert!(registry.wants(bit("policy_decision")));
        assert!(registry.wants(bit("auth_failed")));
        assert!(!registry.wants(bit("trust_check")));
    }

    #[test]
    fn registry_lists_exactly_the_sinks_that_selected_an_event() {
        let registry = SinkRegistry::new(vec![
            sink(SinkId::AuditLog, &["policy_decision", "trust_check"]),
            sink(integration("siem"), &["policy_decision"]),
            sink(integration("slack"), &["auth_failed"]),
        ]);
        assert_eq!(registry.recipients(bit("policy_decision")), &[SinkId::AuditLog, integration("siem")]);
        assert_eq!(registry.recipients(bit("trust_check")), &[SinkId::AuditLog]);
        assert_eq!(registry.recipients(bit("auth_failed")), &[integration("slack")]);
        assert!(
            registry
                .recipients(bit("payment"))
                .is_empty()
        );
    }

    #[test]
    fn registry_without_sinks_wants_nothing() {
        let registry = SinkRegistry::new(Vec::new());
        assert!(!registry.wants(bit("policy_decision")));
        assert!(
            registry
                .recipients(bit("policy_decision"))
                .is_empty()
        );
    }

    #[test]
    fn bit_outside_the_catalog_is_never_wanted() {
        let registry = SinkRegistry::new(vec![sink(SinkId::AuditLog, &["policy_decision"])]);
        assert!(!registry.wants(63));
        assert!(
            registry
                .recipients(63)
                .is_empty()
        );
        assert!(!registry.wants(64));
        assert!(
            registry
                .recipients(64)
                .is_empty()
        );
    }

    #[test]
    fn replacing_the_sinks_updates_what_is_wanted() {
        let sinks = Sinks::default();
        assert!(!sinks.wants(bit("auth_failed")));

        sinks.replace(vec![sink(integration("siem"), &["auth_failed"])], Vec::new());
        assert!(sinks.wants(bit("auth_failed")));
        assert_eq!(
            sinks
                .snapshot()
                .recipients(bit("auth_failed")),
            &[integration("siem")]
        );

        sinks.replace(vec![sink(SinkId::AuditLog, &["trust_check"])], Vec::new());
        assert!(!sinks.wants(bit("auth_failed")));
        assert!(sinks.wants(bit("trust_check")));
    }

    #[test]
    fn registry_lists_every_sink_once_including_those_selecting_nothing() {
        let registry =
            SinkRegistry::new(vec![sink(SinkId::AuditLog, &[]), sink(integration("siem"), &["auth_failed"])]);
        assert_eq!(registry.ids(), &[SinkId::AuditLog, integration("siem")]);
    }

    #[test]
    fn a_registry_keeps_the_paused_integrations_apart_from_its_sinks() {
        let sinks = Sinks::default();
        assert!(
            sinks
                .snapshot()
                .paused()
                .is_empty()
        );

        sinks.replace(
            vec![sink(SinkId::AuditLog, &[]), sink(integration("siem"), &["auth_failed"])],
            vec![integration("disabled")],
        );
        let registry = sinks.snapshot();
        assert_eq!(registry.ids(), &[SinkId::AuditLog, integration("siem")]);
        assert_eq!(registry.paused(), &[integration("disabled")]);
        assert_eq!(registry.recipients(bit("auth_failed")), &[integration("siem")]);
    }

    #[test]
    fn replacing_the_sinks_notifies_subscribers() {
        let sinks = Sinks::default();
        let mut changes = sinks.subscribe();
        assert!(!changes.has_changed().unwrap());
        sinks.replace(vec![sink(SinkId::AuditLog, &[])], Vec::new());
        assert!(changes.has_changed().unwrap());
        changes.mark_unchanged();
        sinks.replace(Vec::new(), Vec::new());
        assert!(changes.has_changed().unwrap());
    }

    #[test]
    fn a_snapshot_is_unchanged_by_a_later_replace() {
        let sinks = Sinks::default();
        sinks.replace(vec![sink(integration("siem"), &["auth_failed"])], Vec::new());
        let before = sinks.snapshot();

        sinks.replace(Vec::new(), Vec::new());
        assert_eq!(before.recipients(bit("auth_failed")), &[integration("siem")]);
        assert!(
            sinks
                .snapshot()
                .recipients(bit("auth_failed"))
                .is_empty()
        );
    }
}
