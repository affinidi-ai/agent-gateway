#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageOperation {
    Backup,
    Restore,
}

#[derive(Debug, Clone, Copy)]
pub struct StorageAuditEvent<'a> {
    pub operation: StorageOperation,
    pub actor_id: &'a str,
    pub actor_type: &'a str,
    pub restore_path: Option<&'a str>,
    pub key_source: Option<&'a str>,
    pub source_domain: Option<&'a str>,
    pub target_domain: Option<&'a str>,
    pub outcome: &'a str,
    pub failure_category: Option<&'a str>,
    pub archive_size_bytes: Option<usize>,
}

pub fn record_storage_audit(event: StorageAuditEvent<'_>) {
    let event_name = match event.operation {
        StorageOperation::Backup => "storage.backup",
        StorageOperation::Restore => "storage.restore",
    };
    let restore_path = event
        .restore_path
        .unwrap_or("none");
    let key_source = event
        .key_source
        .unwrap_or("none");
    let source_domain = event
        .source_domain
        .unwrap_or("none");
    let target_domain = event
        .target_domain
        .unwrap_or("none");
    let failure_category = event
        .failure_category
        .unwrap_or("none");
    let archive_size_bytes = event
        .archive_size_bytes
        .unwrap_or(0);

    if matches!(event.outcome, "attempt" | "success") {
        tracing::info!(
            target: "audit",
            event = event_name,
            product = "agent-gateway",
            actor_id = event.actor_id,
            actor_type = event.actor_type,
            restore_path,
            key_source,
            source_domain,
            target_domain,
            outcome = event.outcome,
            failure_category,
            archive_size_bytes,
            "Storage operation audit"
        );
    } else {
        tracing::warn!(
            target: "audit",
            event = event_name,
            product = "agent-gateway",
            actor_id = event.actor_id,
            actor_type = event.actor_type,
            restore_path,
            key_source,
            source_domain,
            target_domain,
            outcome = event.outcome,
            failure_category,
            archive_size_bytes,
            "Storage operation audit"
        );
    }
}

pub fn record_startup_storage_audit(event: StorageAuditEvent<'_>) {
    eprintln!("{}", format_startup_storage_audit(event));
    record_storage_audit(event);
}

fn format_startup_storage_audit(event: StorageAuditEvent<'_>) -> String {
    format!(
        "AUDIT event=storage.restore product=agent-gateway actor_id={} actor_type={} restore_path={} key_source={} source_domain={} target_domain={} outcome={} failure_category={} archive_size_bytes={}",
        event.actor_id,
        event.actor_type,
        event
            .restore_path
            .unwrap_or("none"),
        event
            .key_source
            .unwrap_or("none"),
        event
            .source_domain
            .unwrap_or("none"),
        event
            .target_domain
            .unwrap_or("none"),
        event.outcome,
        event
            .failure_category
            .unwrap_or("none"),
        event
            .archive_size_bytes
            .unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing_subscriber::{Layer, layer::Context, prelude::*};

    #[derive(Clone)]
    struct CapturedEvent(Vec<(String, String)>);

    struct Visitor(Vec<(String, String)>);

    impl Visit for Visitor {
        fn record_debug(
            &mut self,
            field: &Field,
            value: &dyn std::fmt::Debug,
        ) {
            self.0.push((
                field.name().to_string(),
                format!("{value:?}")
                    .trim_matches('"')
                    .to_string(),
            ));
        }
    }

    struct CapturingLayer(Arc<Mutex<Vec<CapturedEvent>>>);

    impl<S: tracing::Subscriber> Layer<S> for CapturingLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: Context<'_, S>,
        ) {
            let mut visitor = Visitor(Vec::new());
            event.record(&mut visitor);
            self.0
                .lock()
                .unwrap()
                .push(CapturedEvent(visitor.0));
        }
    }

    fn capture(f: impl FnOnce()) -> Vec<CapturedEvent> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(CapturingLayer(events.clone()));
        tracing::subscriber::with_default(subscriber, f);
        events.lock().unwrap().clone()
    }

    fn field<'a>(
        event: &'a CapturedEvent,
        name: &str,
    ) -> Option<&'a str> {
        event
            .0
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn restore_audit_records_actor_path_key_source_and_outcome() {
        let events = capture(|| {
            record_storage_audit(StorageAuditEvent {
                operation: StorageOperation::Restore,
                actor_id: "admin-42",
                actor_type: "user",
                restore_path: Some("api"),
                key_source: Some("legacy"),
                source_domain: Some("gateway.example.com"),
                target_domain: Some("gateway.example.com"),
                outcome: "success",
                failure_category: None,
                archive_size_bytes: Some(128),
            });
        });

        let event = events
            .iter()
            .find(|event| field(event, "event") == Some("storage.restore"))
            .unwrap();
        assert_eq!(field(event, "actor_id"), Some("admin-42"));
        assert_eq!(field(event, "restore_path"), Some("api"));
        assert_eq!(field(event, "key_source"), Some("legacy"));
        assert_eq!(field(event, "outcome"), Some("success"));
    }

    #[test]
    fn startup_stderr_audit_identifies_product() {
        let line = format_startup_storage_audit(StorageAuditEvent {
            operation: StorageOperation::Restore,
            actor_id: "system",
            actor_type: "system",
            restore_path: Some("startup"),
            key_source: None,
            source_domain: None,
            target_domain: Some("gateway.example.com"),
            outcome: "failure",
            failure_category: Some("key_unavailable"),
            archive_size_bytes: None,
        });

        assert!(line.contains("event=storage.restore product=agent-gateway"));
        assert!(line.contains("failure_category=key_unavailable"));
    }

    #[test]
    fn startup_restore_audit_identifies_system_actor() {
        let events = capture(|| {
            record_startup_storage_audit(StorageAuditEvent {
                operation: StorageOperation::Restore,
                actor_id: "system",
                actor_type: "system",
                restore_path: Some("startup"),
                key_source: Some("current"),
                source_domain: Some("gateway.example.com"),
                target_domain: Some("gateway.example.com"),
                outcome: "success",
                failure_category: None,
                archive_size_bytes: Some(128),
            });
        });

        let event = events
            .iter()
            .find(|event| field(event, "event") == Some("storage.restore"))
            .unwrap();
        assert_eq!(field(event, "actor_id"), Some("system"));
        assert_eq!(field(event, "restore_path"), Some("startup"));
        assert_eq!(field(event, "key_source"), Some("current"));
    }
}
