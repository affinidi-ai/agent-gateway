//! When and how often a failed delivery is tried again.

use std::time::Duration;

use tokio_retry::strategy::ExponentialBackoff;

/// Delays before the retries of a transient publish failure, before jitter:
/// 1 s, 2 s, 4 s, 8 s and 16 s. tokio-retry's `ExponentialBackoff` raises its
/// base to successive powers, so the base is 2 and the factor scales it to
/// seconds (`from_millis(1000)` would wait 1 s and then the 16 s cap four times).
pub fn retry_delays() -> impl Iterator<Item = Duration> {
    ExponentialBackoff::from_millis(2)
        .factor(500)
        .max_delay(Duration::from_secs(16))
        .take(5)
}

/// Whether a publish failure may succeed on retry: a connect, timeout or send
/// error, or an HTTP 429 / 5xx. Any other HTTP status (a 401, a 404) fails
/// the same way every time, so retrying only delays the next delivery.
pub fn is_transient_publish_error(error: &anyhow::Error) -> bool {
    let send_failed = error.chain().any(|cause| {
        cause
            .downcast_ref::<reqwest::Error>()
            .is_some_and(|e| e.is_timeout() || e.is_connect() || e.is_request())
    });
    if send_failed {
        return true;
    }
    let text = format!("{error:#}").to_lowercase();
    if let Some(status) = http_failure_status(&text) {
        return status == 429 || status >= 500;
    }
    ["timeout", "timed out", "connection", "network"]
        .iter()
        .any(|marker| text.contains(marker))
}

/// The status in a publisher's `... failed: <status> - <body>` error.
fn http_failure_status(text: &str) -> Option<u16> {
    let (_, rest) = text.split_once("failed: ")?;
    rest.get(..3)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_failures_back_off_one_two_four_eight_sixteen_seconds() {
        let seconds: Vec<u64> = retry_delays()
            .map(|delay| delay.as_secs())
            .collect();
        assert_eq!(seconds, vec![1, 2, 4, 8, 16]);
    }

    #[test]
    fn only_transient_publish_errors_are_retried() {
        for (message, transient) in [
            ("Webhook failed: 503 Service Unavailable - down", true),
            ("Slack webhook failed: 429 Too Many Requests - slow down", true),
            ("Webhook failed: 500 Internal Server Error - {\"error\":\"x\"}", true),
            ("Webhook failed: 401 Unauthorized - {\"error\":\"connection refused\"}", false),
            ("Webhook failed: 404 Not Found - missing", false),
            ("Kafka produce timed out", true),
            ("SMTP connection reset", true),
            ("Missing url in webhook configuration", false),
        ] {
            assert_eq!(is_transient_publish_error(&anyhow::anyhow!("{message}")), transient, "{message}");
        }
    }
}
