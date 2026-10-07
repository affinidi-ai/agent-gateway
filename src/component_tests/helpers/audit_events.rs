//! Captures tracing events on the `audit` target emitted on the current thread
//! while an `AuditEvents` value is alive.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::subscriber::DefaultGuard;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt};

pub(crate) type AuditEvent = HashMap<String, String>;

pub(crate) struct AuditEvents {
    events: Arc<Mutex<Vec<AuditEvent>>>,
    _guard: DefaultGuard,
}

impl AuditEvents {
    pub(crate) fn capture() -> Self {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(AuditLayer(events.clone()));
        Self {
            events,
            _guard: tracing::subscriber::set_default(subscriber),
        }
    }

    /// Every captured event whose `event` field equals `name`.
    pub(crate) fn named(
        &self,
        name: &str,
    ) -> Vec<AuditEvent> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| {
                event
                    .get("event")
                    .map(String::as_str)
                    == Some(name)
            })
            .cloned()
            .collect()
    }
}

struct AuditLayer(Arc<Mutex<Vec<AuditEvent>>>);

impl<S: tracing::Subscriber> Layer<S> for AuditLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: Context<'_, S>,
    ) {
        if event.metadata().target() != "audit" {
            return;
        }
        let mut fields = FieldCollector(HashMap::new());
        event.record(&mut fields);
        self.0
            .lock()
            .unwrap()
            .push(fields.0);
    }
}

struct FieldCollector(AuditEvent);

impl Visit for FieldCollector {
    fn record_str(
        &mut self,
        field: &Field,
        value: &str,
    ) {
        self.0
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_debug(
        &mut self,
        field: &Field,
        value: &dyn std::fmt::Debug,
    ) {
        self.0
            .insert(field.name().to_string(), format!("{value:?}"));
    }
}
