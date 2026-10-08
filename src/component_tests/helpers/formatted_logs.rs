//! Captures every tracing event emitted on the current thread while a
//! `FormattedLogs` value is alive, rendered by the plain-text `SimpleFormat`
//! formatter the gateway writes to its log file.

use std::io::Write;
use std::sync::{Arc, Mutex};

use tracing::subscriber::DefaultGuard;
use tracing_subscriber::layer::SubscriberExt;

use super::thread_subscriber::set_thread_default;
use crate::observability::SimpleFormat;

pub(crate) struct FormattedLogs {
    buffer: Arc<Mutex<Vec<u8>>>,
    _guard: DefaultGuard,
}

impl FormattedLogs {
    pub(crate) fn capture() -> Self {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = SharedBuffer(buffer.clone());
        let layer = tracing_subscriber::fmt::layer()
            .event_format(SimpleFormat)
            .with_writer(move || writer.clone())
            .with_ansi(false);
        Self {
            buffer,
            _guard: set_thread_default(tracing_subscriber::registry().with(layer)),
        }
    }

    /// The formatted output captured so far.
    pub(crate) fn text(&self) -> String {
        String::from_utf8(
            self.buffer
                .lock()
                .unwrap()
                .clone(),
        )
        .expect("log output is UTF-8")
    }
}

#[derive(Clone)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuffer {
    fn write(
        &mut self,
        bytes: &[u8],
    ) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap()
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
