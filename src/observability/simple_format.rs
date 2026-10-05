//! Custom log formatter that excludes span context
//!
//! This formatter outputs logs without span paths or span fields,
//! making logs cleaner while still sending full span data to OpenTelemetry.

use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

/// A simple event formatter that only shows: timestamp, level, and message
/// Span context is excluded from output but still available to other layers (like OpenTelemetry)
pub struct SimpleFormat;

impl<S, N> FormatEvent<S, N> for SimpleFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let meta = event.metadata();

        // Write timestamp
        let now = chrono::Utc::now();
        write!(writer, "{} ", now.format("%Y-%m-%dT%H:%M:%S%.6fZ"))?;

        // Write level with padding
        write!(writer, "{:>5} ", meta.level())?;

        // Write the event fields (the actual log message)
        ctx.field_format()
            .format_fields(writer.by_ref(), event)?;

        writeln!(writer)
    }
}
