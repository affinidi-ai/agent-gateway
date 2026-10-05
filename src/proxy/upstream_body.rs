//! Bounded buffering of upstream response bodies.

use std::time::Duration;

use axum::http::StatusCode;
use bytes::{Bytes, BytesMut};

use crate::config::TimeoutConfig;

#[derive(Debug, Clone, Copy)]
pub(crate) struct UpstreamBodyLimits {
    max_bytes: usize,
    idle: Option<Duration>,
    total: Duration,
}

impl UpstreamBodyLimits {
    /// `idle_secs` bounds the gap between chunks (`0` disables it) and
    /// `request_secs` bounds the whole read, counted from the response headers.
    pub(crate) fn new(
        max_bytes: usize,
        timeout: Option<&TimeoutConfig>,
        default_request_secs: u64,
    ) -> Self {
        let (request_secs, idle_secs) = timeout.map_or_else(
            || (default_request_secs, TimeoutConfig::default().idle_secs),
            |timeout| (timeout.request_secs, timeout.idle_secs),
        );
        Self {
            max_bytes,
            idle: (idle_secs > 0).then(|| Duration::from_secs(idle_secs)),
            total: Duration::from_secs(request_secs),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum UpstreamBodyError {
    #[error("upstream response exceeds {0} bytes")]
    TooLarge(usize),
    #[error("upstream response body stalled or exceeded its read deadline")]
    TimedOut,
    #[error("failed to read upstream response: {0}")]
    Read(#[from] reqwest::Error),
}

impl UpstreamBodyError {
    /// HTTP status and caller-facing message for a failed bounded read: `502`
    /// for an oversized or unreadable body, `504` for a stalled or late one.
    pub(crate) fn status_and_message(&self) -> (StatusCode, &'static str) {
        match self {
            Self::TooLarge(_) => (StatusCode::BAD_GATEWAY, "Upstream response too large"),
            Self::TimedOut => (StatusCode::GATEWAY_TIMEOUT, "Upstream response timed out"),
            Self::Read(_) => (StatusCode::BAD_GATEWAY, "Failed to read upstream response"),
        }
    }
}

pub(crate) async fn read_bounded(
    response: reqwest::Response,
    limits: UpstreamBodyLimits,
) -> Result<Bytes, UpstreamBodyError> {
    let mut chunks = BoundedChunks::new(response, limits)?;
    let mut body = BytesMut::new();
    while let Some(chunk) = chunks.next().await? {
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

/// An upstream body read chunk by chunk within [`UpstreamBodyLimits`], for a
/// caller that may stop before the end: the size cap counts every chunk
/// returned, the idle bound applies to each wait, and the total bound runs from
/// construction.
pub(crate) struct BoundedChunks {
    response: reqwest::Response,
    limits: UpstreamBodyLimits,
    /// `None` when `limits.total` is too large to express as an instant.
    deadline: Option<tokio::time::Instant>,
    read: usize,
}

impl BoundedChunks {
    /// Refuses a declared length over the size cap without reading it.
    pub(crate) fn new(
        response: reqwest::Response,
        limits: UpstreamBodyLimits,
    ) -> Result<Self, UpstreamBodyError> {
        if response
            .content_length()
            .is_some_and(|length| length > limits.max_bytes as u64)
        {
            return Err(UpstreamBodyError::TooLarge(limits.max_bytes));
        }
        Ok(Self {
            response,
            limits,
            deadline: tokio::time::Instant::now().checked_add(limits.total),
            read: 0,
        })
    }

    /// The next chunk, or `None` at the end of the body.
    pub(crate) async fn next(&mut self) -> Result<Option<Bytes>, UpstreamBodyError> {
        let idle = self.limits.idle;
        let next = self.response.chunk();
        let waited = async {
            match idle {
                Some(idle) => tokio::time::timeout(idle, next)
                    .await
                    .map_err(|_| UpstreamBodyError::TimedOut),
                None => Ok(next.await),
            }
        };
        let chunk = match self.deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, waited)
                .await
                .map_err(|_| UpstreamBodyError::TimedOut)??,
            None => waited.await?,
        };
        let chunk = chunk.map_err(|error| {
            if error.is_timeout() {
                UpstreamBodyError::TimedOut
            } else {
                UpstreamBodyError::Read(error)
            }
        })?;
        let Some(chunk) = chunk else {
            return Ok(None);
        };
        if chunk.len() > self.limits.max_bytes - self.read {
            return Err(UpstreamBodyError::TooLarge(self.limits.max_bytes));
        }
        self.read += chunk.len();
        Ok(Some(chunk))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub(crate) const CHUNKED_HEAD: &str =
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n";
    pub(crate) const PATIENT: Duration = Duration::from_secs(30);

    pub(crate) fn chunk(data: &[u8]) -> Vec<u8> {
        let mut framed = format!("{:x}\r\n", data.len()).into_bytes();
        framed.extend_from_slice(data);
        framed.extend_from_slice(b"\r\n");
        framed
    }

    /// Serves one response: `head`, then each `(delay, bytes)` write in order,
    /// then holds the connection open without sending anything further.
    async fn upstream_with_client(
        client: reqwest::Client,
        head: String,
        writes: Vec<(Duration, Vec<u8>)>,
    ) -> reqwest::Response {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut socket, _) = listener
                .accept()
                .await
                .unwrap();
            let mut request = [0u8; 4096];
            let _ = socket
                .read(&mut request)
                .await;
            if socket
                .write_all(head.as_bytes())
                .await
                .is_err()
            {
                return;
            }
            for (delay, bytes) in writes {
                tokio::time::sleep(delay).await;
                if socket
                    .write_all(&bytes)
                    .await
                    .is_err()
                {
                    return;
                }
            }
            std::future::pending::<()>().await;
        });
        client
            .get(url)
            .send()
            .await
            .unwrap()
    }

    pub(crate) async fn upstream(
        head: String,
        writes: Vec<(Duration, Vec<u8>)>,
    ) -> reqwest::Response {
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap();
        upstream_with_client(client, head, writes).await
    }

    pub(crate) fn limits(
        max_bytes: usize,
        idle: Option<Duration>,
        total: Duration,
    ) -> UpstreamBodyLimits {
        UpstreamBodyLimits { max_bytes, idle, total }
    }

    fn timeout_config(
        request_secs: u64,
        idle_secs: u64,
    ) -> TimeoutConfig {
        TimeoutConfig {
            request_secs,
            connect_secs: 10,
            idle_secs,
        }
    }

    #[tokio::test]
    async fn reads_a_complete_body_up_to_the_limit() {
        let body = br#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        let response = upstream(
            CHUNKED_HEAD.to_string(),
            vec![
                (Duration::ZERO, chunk(&body[..10])),
                (Duration::ZERO, chunk(&body[10..])),
                (Duration::ZERO, chunk(b"")),
            ],
        )
        .await;

        let read = read_bounded(response, limits(body.len(), Some(PATIENT), PATIENT))
            .await
            .unwrap();

        assert_eq!(&read[..], body);
    }

    /// A HEAD response declares the length of the body a GET would return but
    /// carries none, so a declared length over the limit is not refused.
    #[tokio::test]
    async fn a_head_response_declaring_a_large_body_reads_as_empty() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut socket, _) = listener
                .accept()
                .await
                .unwrap();
            let mut request = [0u8; 4096];
            let _ = socket
                .read(&mut request)
                .await;
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 20971520\r\n\r\n")
                .await;
            std::future::pending::<()>().await;
        });
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .head(url)
            .send()
            .await
            .unwrap();

        let read = read_bounded(response, limits(16, Some(PATIENT), PATIENT))
            .await
            .unwrap();

        assert!(read.is_empty());
    }

    #[tokio::test]
    async fn accepts_a_declared_length_equal_to_the_limit() {
        let head = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n";
        let response = upstream(head.to_string(), vec![(Duration::ZERO, b"{}".to_vec())]).await;

        let read = read_bounded(response, limits(2, Some(PATIENT), PATIENT))
            .await
            .unwrap();

        assert_eq!(&read[..], b"{}");
    }

    #[tokio::test]
    async fn rejects_a_declared_length_over_the_limit_without_reading_it() {
        let head = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 1024\r\n\r\n";
        let response = upstream(head.to_string(), Vec::new()).await;

        let error = read_bounded(response, limits(16, Some(PATIENT), PATIENT))
            .await
            .unwrap_err();

        assert!(matches!(error, UpstreamBodyError::TooLarge(16)), "{error:?}");
    }

    #[tokio::test]
    async fn rejects_an_undeclared_body_once_it_grows_past_the_limit() {
        let response = upstream(
            CHUNKED_HEAD.to_string(),
            vec![(Duration::ZERO, chunk(&[b'a'; 12])), (Duration::ZERO, chunk(&[b'b'; 12]))],
        )
        .await;

        let error = read_bounded(response, limits(16, Some(PATIENT), PATIENT))
            .await
            .unwrap_err();

        assert!(matches!(error, UpstreamBodyError::TooLarge(16)), "{error:?}");
    }

    #[tokio::test]
    async fn gives_up_when_the_body_stalls_for_the_idle_deadline() {
        let response = upstream(CHUNKED_HEAD.to_string(), vec![(Duration::ZERO, chunk(b"{\"jsonrpc\":"))]).await;
        let started = std::time::Instant::now();

        let error = read_bounded(response, limits(1024, Some(Duration::from_millis(200)), PATIENT))
            .await
            .unwrap_err();

        assert!(matches!(error, UpstreamBodyError::TimedOut), "{error:?}");
        assert!(started.elapsed() < Duration::from_secs(5), "took {:?}", started.elapsed());
    }

    #[tokio::test]
    async fn resets_the_idle_deadline_on_every_chunk() {
        let mut writes: Vec<_> = (0..8)
            .map(|_| (Duration::from_millis(100), chunk(b" ")))
            .collect();
        writes.push((Duration::ZERO, chunk(b"")));
        let response = upstream(CHUNKED_HEAD.to_string(), writes).await;

        let read = read_bounded(response, limits(1024, Some(Duration::from_millis(300)), PATIENT))
            .await
            .unwrap();

        assert_eq!(read.len(), 8);
    }

    #[tokio::test]
    async fn gives_up_when_a_trickling_body_outlives_the_overall_deadline() {
        let trickle = (0..50)
            .map(|_| (Duration::from_millis(50), chunk(b" ")))
            .collect();
        let response = upstream(CHUNKED_HEAD.to_string(), trickle).await;
        let started = std::time::Instant::now();

        let error = read_bounded(response, limits(1024, Some(Duration::from_millis(500)), Duration::from_millis(400)))
            .await
            .unwrap_err();

        assert!(matches!(error, UpstreamBodyError::TimedOut), "{error:?}");
        assert!(started.elapsed() >= Duration::from_millis(400), "took {:?}", started.elapsed());
        assert!(started.elapsed() < Duration::from_secs(2), "took {:?}", started.elapsed());
    }

    #[tokio::test]
    async fn reports_the_clients_own_timeout_as_a_timeout() {
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(300))
            .build()
            .unwrap();
        let response =
            upstream_with_client(client, CHUNKED_HEAD.to_string(), vec![(Duration::ZERO, chunk(b"{"))]).await;

        let error = read_bounded(response, limits(1024, None, PATIENT))
            .await
            .unwrap_err();

        assert!(matches!(error, UpstreamBodyError::TimedOut), "{error:?}");
    }

    #[tokio::test]
    async fn tolerates_a_request_timeout_too_large_for_a_deadline() {
        let response =
            upstream(CHUNKED_HEAD.to_string(), vec![(Duration::ZERO, chunk(b"{}")), (Duration::ZERO, chunk(b""))])
                .await;
        let limits = UpstreamBodyLimits::new(1024, Some(&timeout_config(u64::MAX, u64::MAX)), 30);

        let read = read_bounded(response, limits)
            .await
            .unwrap();

        assert_eq!(&read[..], b"{}");
    }

    #[test]
    fn derives_both_deadlines_from_the_timeout_config_or_its_defaults() {
        let configured = UpstreamBodyLimits::new(1, Some(&timeout_config(45, 5)), 30);
        assert_eq!(configured.idle, Some(Duration::from_secs(5)));
        assert_eq!(configured.total, Duration::from_secs(45));

        let disabled_idle = UpstreamBodyLimits::new(1, Some(&timeout_config(45, 0)), 30);
        assert_eq!(disabled_idle.idle, None);

        let defaulted = UpstreamBodyLimits::new(1, None, 30);
        assert_eq!(defaulted.idle, Some(Duration::from_secs(TimeoutConfig::default().idle_secs)));
        assert_eq!(defaulted.total, Duration::from_secs(30));
    }
}
