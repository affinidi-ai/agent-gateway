//! Captures tracing events on the `audit` target emitted on the current thread
//! while an `AuditEvents` value is alive.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tracing::Level;
use tracing::field::{Field, Visit};
use tracing::subscriber::DefaultGuard;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt};

use super::thread_subscriber::set_thread_default;

/// One captured event: its level and its fields rendered as strings.
#[derive(Clone)]
pub(crate) struct AuditEvent {
    pub(crate) level: Level,
    fields: HashMap<String, String>,
}

impl AuditEvent {
    pub(crate) fn get(
        &self,
        field: &str,
    ) -> Option<&str> {
        self.fields
            .get(field)
            .map(String::as_str)
    }
}

impl std::ops::Index<&str> for AuditEvent {
    type Output = String;

    fn index(
        &self,
        field: &str,
    ) -> &String {
        self.fields
            .get(field)
            .unwrap_or_else(|| panic!("audit event has no `{field}` field"))
    }
}

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
            _guard: set_thread_default(subscriber),
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
            .filter(|event| event.get("event") == Some(name))
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
            .push(AuditEvent {
                level: *event.metadata().level(),
                fields: fields.0,
            });
    }
}

struct FieldCollector(HashMap<String, String>);

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
