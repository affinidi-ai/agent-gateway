//! The one place an audit record is finalised and handed to the journal.

use std::sync::mpsc::Sender;
use std::sync::{Arc, LazyLock};

use parking_lot::{Mutex, RwLock};
use tracing::{debug, error, warn};

use crate::audit::catalog::event_bit;
use crate::audit::journal::Pending;
use crate::audit::registry::{Sinks, sinks};
use crate::delegation_vault::audit::{DelegationAuditEvent, action_category, new_event_id};
use crate::metrics::backends::prometheus::{track_audit_record_produced, track_audit_records_lost};

pub struct Producer {
    sinks: &'static Sinks,
    journal: RwLock<Option<Sender<Pending>>>,
}

static PRODUCER: LazyLock<Producer> = LazyLock::new(|| Producer::new(sinks()));

/// The process-wide producer, addressing records to the process-wide sinks.
pub fn producer() -> &'static Producer {
    &PRODUCER
}

impl Producer {
    pub fn new(sinks: &'static Sinks) -> Self {
        Self {
            sinks,
            journal: RwLock::new(None),
        }
    }

    /// Connects the producer to the journal writer. Selected records produced
    /// while it is not connected are dropped and counted as
    /// `pipeline_not_running`.
    pub fn connect(
        &self,
        journal: Sender<Pending>,
    ) {
        let mut connected = self.journal.write();
        if connected.is_some() {
            warn!("Audit producer is already connected to a journal");
            return;
        }
        *connected = Some(journal);
    }

    /// Disconnects the producer. The writer journals what it was already
    /// handed, then stops once it has no other sender.
    pub fn disconnect(&self) {
        self.journal.write().take();
    }

    /// Whether any sink selects the event. One atomic read.
    pub fn wants(
        &self,
        category: &str,
    ) -> bool {
        #[cfg(test)]
        if CAPTURING
            .try_with(|_| ())
            .is_ok()
        {
            return event_bit(category).is_some();
        }
        event_bit(category).is_some_and(|bit| self.sinks.wants(bit))
    }

    /// Builds and submits a record only when a sink selects `category`.
    pub fn emit(
        &self,
        category: &'static str,
        build: impl FnOnce() -> DelegationAuditEvent,
    ) {
        if self.wants(category) {
            self.submit(build());
        }
    }

    /// Finalises a built record: held while a [`DeferredAudit`] scope is
    /// active, otherwise given an event id, addressed to the sinks that
    /// select it now, and handed to the journal without waiting.
    pub fn submit(
        &self,
        event: DelegationAuditEvent,
    ) {
        match DEFERRED.try_with(Arc::clone) {
            Ok(held) => held.lock().push(event),
            Err(_) => self.finalise(event),
        }
    }

    fn finalise(
        &self,
        mut event: DelegationAuditEvent,
    ) {
        let category = action_category(&event.event);
        let Some(bit) = event_bit(category) else {
            return;
        };
        let recipients = self
            .sinks
            .snapshot()
            .recipients(bit)
            .to_vec();
        if recipients.is_empty() {
            return;
        }
        if event.event_id.is_none() {
            event.event_id = new_event_id();
        }
        let connected = self.journal.read();
        let Some(journal) = connected.as_ref() else {
            track_audit_records_lost("pipeline_not_running", 1);
            debug!(category, "Audit journal not running; record dropped");
            return;
        };
        track_audit_record_produced(category);
        if journal
            .send(Pending { recipients, record: event })
            .is_err()
        {
            track_audit_records_lost("journal_closed", 1);
            error!(category, "Audit journal writer has stopped; record lost");
        }
    }
}

tokio::task_local! {
    static DEFERRED: Arc<Mutex<Vec<DelegationAuditEvent>>>;
}

#[cfg(test)]
tokio::task_local! {
    static CAPTURING: ();
}

/// Runs `future` treating every catalog event as selected, and returns the
/// records it submitted instead of journalling them.
#[cfg(test)]
pub async fn capture<F: std::future::Future>(future: F) -> (F::Output, Vec<DelegationAuditEvent>) {
    let held = DeferredAudit::new(producer());
    let output = CAPTURING
        .scope((), held.scope(future))
        .await;
    (output, held.take())
}

/// Holds the records submitted inside [`DeferredAudit::scope`] until the
/// request's identity VP is known. Whatever has not been flushed when the
/// guard is dropped is submitted without a VP, so no return path loses them.
pub struct DeferredAudit {
    producer: &'static Producer,
    held: Arc<Mutex<Vec<DelegationAuditEvent>>>,
}

impl DeferredAudit {
    pub fn new(producer: &'static Producer) -> Self {
        Self { producer, held: Arc::default() }
    }

    /// Runs `future` with records submitted from it held by this guard.
    pub async fn scope<F: std::future::Future>(
        &self,
        future: F,
    ) -> F::Output {
        DEFERRED
            .scope(self.held.clone(), future)
            .await
    }

    /// Stamps every held record with the VP and submits it.
    pub fn flush_with_vp(
        &self,
        vp_jwt: &str,
    ) {
        for mut event in self.take() {
            event.vp_jwt = Some(vp_jwt.to_string());
            self.producer.finalise(event);
        }
    }

    /// Submits every held record without a VP.
    pub fn flush(&self) {
        for event in self.take() {
            self.producer.finalise(event);
        }
    }

    fn take(&self) -> Vec<DelegationAuditEvent> {
        std::mem::take(&mut *self.held.lock())
    }
}

impl Drop for DeferredAudit {
    fn drop(&mut self) {
        self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::registry::{EventMask, Sink, SinkId};
    use crate::delegation_vault::audit::{DelegationAuditAction, audit_event};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{self, Receiver};

    fn consent() -> DelegationAuditEvent {
        audit_event(DelegationAuditAction::ConsentGranted, None, None, None, None)
    }

    fn siem() -> SinkId {
        SinkId::Integration("siem".to_string())
    }

    fn producer(selections: &[(SinkId, &[&str])]) -> (&'static Producer, Receiver<Pending>) {
        let sinks: &'static Sinks = Box::leak(Box::default());
        sinks.replace(
            selections
                .iter()
                .map(|(id, events)| Sink::new(id.clone(), EventMask::from_categories(events.iter().copied())))
                .collect(),
            Vec::new(),
        );
        let producer: &'static Producer = Box::leak(Box::new(Producer::new(sinks)));
        let (tx, rx) = mpsc::channel();
        producer.connect(tx);
        (producer, rx)
    }

    fn received(rx: &Receiver<Pending>) -> Vec<Pending> {
        rx.try_iter().collect()
    }

    #[test]
    fn a_record_no_sink_selects_is_never_built() {
        let (producer, rx) = producer(&[(SinkId::AuditLog, &["policy_decision"])]);
        let built = AtomicBool::new(false);

        assert!(!producer.wants("consent_granted"));
        producer.emit("consent_granted", || {
            built.store(true, Ordering::SeqCst);
            consent()
        });

        assert!(!built.load(Ordering::SeqCst));
        assert!(received(&rx).is_empty());
    }

    #[test]
    fn a_selected_record_goes_to_the_journal_addressed_to_its_sinks() {
        let (producer, rx) =
            producer(&[(SinkId::AuditLog, &["consent_granted"]), (siem(), &["consent_granted", "auth_failed"])]);

        assert!(producer.wants("consent_granted"));
        producer.emit("consent_granted", consent);

        let pending = received(&rx);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].recipients, vec![SinkId::AuditLog, siem()]);
        assert!(
            pending[0]
                .record
                .event_id
                .is_some()
        );
    }

    #[test]
    fn a_submitted_record_without_an_event_id_is_given_one() {
        let (producer, rx) = producer(&[(SinkId::AuditLog, &["consent_granted"])]);
        let mut record = consent();
        record.event_id = None;

        producer.submit(record);

        assert!(
            received(&rx)[0]
                .record
                .event_id
                .is_some()
        );
    }

    #[test]
    fn a_selected_record_with_no_journal_connected_is_dropped_and_counted() {
        let lost = || {
            crate::metrics::backends::prometheus::AUDIT_RECORDS_LOST
                .with_label_values(&["pipeline_not_running"])
                .get()
        };
        let sinks: &'static Sinks = Box::leak(Box::default());
        sinks.replace(vec![Sink::new(SinkId::AuditLog, EventMask::from_categories(["consent_granted"]))], Vec::new());
        let producer = Producer::new(sinks);
        let before = lost();

        producer.submit(consent());

        assert!(lost() > before, "the dropped record is counted");
    }

    #[test]
    fn records_go_to_the_journal_connected_now_and_none_while_disconnected() {
        let (producer, first) = producer(&[(SinkId::AuditLog, &["consent_granted"])]);
        producer.disconnect();
        producer.submit(consent());
        assert!(received(&first).is_empty());

        let (tx, second) = mpsc::channel();
        producer.connect(tx);
        producer.submit(consent());
        assert_eq!(received(&second).len(), 1);
        assert!(received(&first).is_empty());
    }

    #[test]
    fn connecting_twice_keeps_the_first_journal() {
        let (producer, first) = producer(&[(SinkId::AuditLog, &["consent_granted"])]);
        let (tx, second) = mpsc::channel();
        producer.connect(tx);

        producer.submit(consent());
        assert_eq!(received(&first).len(), 1);
        assert!(received(&second).is_empty());
    }

    #[tokio::test]
    async fn deferred_records_wait_for_the_vp_and_carry_it() {
        let (producer, rx) = producer(&[(SinkId::AuditLog, &["consent_granted"])]);
        let deferred = DeferredAudit::new(producer);

        deferred
            .scope(async {
                producer.submit(consent());
                producer.submit(consent());
            })
            .await;
        assert!(received(&rx).is_empty());

        deferred.flush_with_vp("vp.jwt.value");
        let pending = received(&rx);
        assert_eq!(pending.len(), 2);
        assert!(
            pending
                .iter()
                .all(|p| p.record.vp_jwt.as_deref() == Some("vp.jwt.value"))
        );
    }

    #[tokio::test]
    async fn deferred_records_are_submitted_without_a_vp_when_the_guard_is_dropped() {
        let (producer, rx) = producer(&[(SinkId::AuditLog, &["consent_granted"])]);
        {
            let deferred = DeferredAudit::new(producer);
            deferred
                .scope(async {
                    producer.submit(consent());
                })
                .await;
        }
        let pending = received(&rx);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].record.vp_jwt, None);
    }

    #[tokio::test]
    async fn recipients_are_decided_when_a_deferred_record_is_flushed() {
        let (producer, rx) = producer(&[(SinkId::AuditLog, &["consent_granted"])]);
        let deferred = DeferredAudit::new(producer);
        deferred
            .scope(async {
                producer.submit(consent());
            })
            .await;

        producer.sinks.replace(
            vec![
                Sink::new(SinkId::AuditLog, EventMask::from_categories(["consent_granted"])),
                Sink::new(siem(), EventMask::from_categories(["consent_granted"])),
            ],
            Vec::new(),
        );
        deferred.flush_with_vp("vp");

        assert_eq!(received(&rx)[0].recipients, vec![SinkId::AuditLog, siem()]);
    }

    #[tokio::test]
    async fn a_flushed_guard_submits_nothing_more_when_dropped() {
        let (producer, rx) = producer(&[(SinkId::AuditLog, &["consent_granted"])]);
        {
            let deferred = DeferredAudit::new(producer);
            deferred
                .scope(async {
                    producer.submit(consent());
                })
                .await;
            deferred.flush_with_vp("vp");
        }
        assert_eq!(received(&rx).len(), 1);
    }

    #[tokio::test]
    async fn records_submitted_outside_the_scope_are_not_held() {
        let (producer, rx) = producer(&[(SinkId::AuditLog, &["consent_granted"])]);
        let _deferred = DeferredAudit::new(producer);
        producer.submit(consent());
        assert_eq!(received(&rx).len(), 1);
    }
}
