//! Trust Task **carriers** — how a document reaches the VTA.
//!
//! Until now the only carrier was HTTPS, which assumes the VTA has an address
//! the gateway can dial. BYO-VTA breaks that assumption: a VTA on a Raspberry
//! Pi at home, a laptop, or anything behind NAT has no reachable address. The
//! canonical answer is the one the stack already ships — the VTA connects
//! **outbound** to a mediator and the gateway addresses it by **DID**.
//!
//! [`TrustTaskTransport`] is the seam that makes that a per-connection choice.
//! Everything above it — the DI-signed auth handshake, session caching, the
//! resilience layer (timeout, bounded concurrency, circuit breaker, ≤1 retry),
//! redacted typed errors — is carrier-agnostic and unchanged.
//!
//! ## Why the seam returns a raw body
//!
//! Response parsing (the flat-vs-`#response`-envelope handling) is a property
//! of the Trust Task protocol, not of the carrier, so it stays in one place
//! above this trait. Keeping the generic response type out also keeps the trait
//! object-safe, which is what lets a connection pick its carrier at runtime.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::{Mutex, oneshot};

use super::error::VtaError;

/// Delivers one Trust Task document and returns the raw response body.
#[async_trait]
pub trait TrustTaskTransport: Send + Sync {
    /// Carrier label for metrics and audit (`https` | `didcomm`), so an
    /// operator can tell which path a slow or failing call took.
    fn carrier(&self) -> &'static str;

    /// Deliver `doc`, optionally bearer-authenticated, and return the response
    /// body. One attempt: back-pressure, retry and the circuit breaker live
    /// above this.
    async fn deliver(
        &self,
        doc: &Value,
        bearer: Option<&str>,
    ) -> Result<String, VtaError>;
}

// ── HTTPS ────────────────────────────────────────────────────────────────────

/// `POST {base_url}/trust-tasks`. The original carrier, unchanged.
pub struct HttpsTransport {
    http: reqwest::Client,
    trust_tasks_url: String,
}

impl HttpsTransport {
    pub fn new(
        base_url: &str,
        timeout: Duration,
    ) -> Result<Self, VtaError> {
        let http = crate::http_client::with_timeout(timeout)
            .map_err(|e| VtaError::Config(format!("build HTTP client: {e}")))?;
        Ok(Self {
            http,
            trust_tasks_url: format!("{}{}", base_url.trim_end_matches('/'), super::client::TRUST_TASKS_PATH),
        })
    }
}

#[async_trait]
impl TrustTaskTransport for HttpsTransport {
    fn carrier(&self) -> &'static str {
        "https"
    }

    async fn deliver(
        &self,
        doc: &Value,
        bearer: Option<&str>,
    ) -> Result<String, VtaError> {
        let mut req = self
            .http
            .post(&self.trust_tasks_url)
            .json(doc);
        if let Some(token) = bearer {
            req = req.bearer_auth(token);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| VtaError::Transport(e.to_string()))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| VtaError::Transport(e.to_string()))?;
        if !status.is_success() {
            return Err(VtaError::Http { status: status.as_u16(), body });
        }
        Ok(body)
    }
}

// ── DIDComm ──────────────────────────────────────────────────────────────────

/// Sends a Trust Task message to a DID through a mediator, and reports replies.
///
/// A port rather than a concrete mediator client: the correlation, deadline and
/// memory-bounding rules below are the gateway's responsibility and are worth
/// testing on their own, while the mediator plumbing is existing infrastructure
/// this ticket deliberately does not re-implement.
#[async_trait]
pub trait DidCommChannel: Send + Sync {
    /// Send `body` to `to_did`, tagged with `correlation_id` so the reply can
    /// be matched back. Returns once the mediator has accepted the message —
    /// **not** when the VTA replies.
    async fn send(
        &self,
        to_did: &str,
        correlation_id: &str,
        body: &Value,
    ) -> Result<(), VtaError>;

    /// Whether the mediator is reachable. Checked before the first send so a
    /// cold mediator produces a clear error instead of a deadline expiry.
    async fn is_ready(&self) -> bool;
}

/// Replies the gateway is still waiting for.
///
/// Bounded on purpose: DIDComm is asynchronous, so a VTA that simply never
/// answers leaves an entry behind. Without a cap, a silent peer plus a retrying
/// caller is an unbounded memory leak reachable from the data plane.
const MAX_IN_FLIGHT: usize = 1_024;

type Pending = Arc<Mutex<HashMap<String, oneshot::Sender<String>>>>;

/// Trust Tasks carried over DIDComm, addressed by DID through a mediator.
///
/// No inbound reachability is required of the VTA: it connects outbound to the
/// mediator and the gateway never dials it.
pub struct DidCommTransport {
    channel: Arc<dyn DidCommChannel>,
    vta_did: String,
    /// The gateway owns the deadline (VTA-04). DIDComm has no connection to
    /// time out, so without this a missing reply would hold a surface request
    /// slot indefinitely.
    timeout: Duration,
    pending: Pending,
}

impl DidCommTransport {
    pub fn new(
        channel: Arc<dyn DidCommChannel>,
        vta_did: &str,
        timeout: Duration,
    ) -> Self {
        Self {
            channel,
            vta_did: vta_did.to_string(),
            timeout,
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Hand a reply to whoever is waiting for it.
    ///
    /// Returns `false` for a correlation id nobody is waiting on — a late
    /// reply after a deadline, or an unsolicited message. Both are dropped
    /// rather than stored: keeping them would be an unbounded buffer fed by a
    /// remote party.
    ///
    /// Called by the mediator adapter that receives inbound DIDComm messages;
    /// the correlation, deadline and bounding rules live here so they are
    /// testable without a live mediator.
    #[allow(dead_code)]
    pub async fn deliver_reply(
        &self,
        correlation_id: &str,
        body: String,
    ) -> bool {
        let waiter = self
            .pending
            .lock()
            .await
            .remove(correlation_id);
        match waiter {
            Some(tx) => tx.send(body).is_ok(),
            None => false,
        }
    }

    /// How many replies are outstanding, for diagnostics and tests.
    #[allow(dead_code)]
    pub async fn in_flight(&self) -> usize {
        self.pending
            .lock()
            .await
            .len()
    }
}

#[async_trait]
impl TrustTaskTransport for DidCommTransport {
    fn carrier(&self) -> &'static str {
        "didcomm"
    }

    async fn deliver(
        &self,
        doc: &Value,
        bearer: Option<&str>,
    ) -> Result<String, VtaError> {
        if !self.channel.is_ready().await {
            // A clear error beats a deadline expiry: the operator needs to know
            // the mediator is the problem, not the VTA.
            return Err(VtaError::Transport("the DIDComm mediator is not ready".to_string()));
        }

        // Correlate on the Trust Task document's own id. It is already unique
        // per request and already travels with the document, so the carrier
        // adds no identifier the VTA has to understand.
        let correlation_id = doc
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| VtaError::Protocol("Trust Task document has no id to correlate on".to_string()))?
            .to_string();

        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().await;
            if pending.len() >= MAX_IN_FLIGHT {
                // Fail closed rather than grow: shedding one request is
                // recoverable, exhausting memory is not.
                return Err(VtaError::Transport(format!(
                    "too many VTA requests are awaiting a DIDComm reply ({MAX_IN_FLIGHT})"
                )));
            }
            pending.insert(correlation_id.clone(), tx);
        }

        // The bearer travels inside the message body: DIDComm has no header to
        // put it in, and the envelope is already authenticated and encrypted to
        // the VTA's DID.
        let mut envelope = doc.clone();
        if let Some(token) = bearer
            && let Some(object) = envelope.as_object_mut()
        {
            object.insert("authorization".to_string(), Value::String(format!("Bearer {token}")));
        }

        // Clean up on *every* exit path below, so a send failure or a deadline
        // cannot leave the entry behind.
        let send = self
            .channel
            .send(&self.vta_did, &correlation_id, &envelope)
            .await;
        if let Err(e) = send {
            self.forget(&correlation_id)
                .await;
            return Err(e);
        }

        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(body)) => Ok(body),
            // The waiter was dropped — only possible if something else removed
            // the entry, so treat it as a lost reply rather than a panic.
            Ok(Err(_)) => {
                self.forget(&correlation_id)
                    .await;
                Err(VtaError::Transport("the VTA reply was lost before it could be read".to_string()))
            }
            Err(_) => {
                self.forget(&correlation_id)
                    .await;
                Err(VtaError::Transport(format!(
                    "the VTA did not reply over DIDComm within {}ms",
                    self.timeout.as_millis()
                )))
            }
        }
    }
}

impl DidCommTransport {
    async fn forget(
        &self,
        correlation_id: &str,
    ) {
        self.pending
            .lock()
            .await
            .remove(correlation_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;

    struct RecordingChannel {
        ready: bool,
        sends: AtomicUsize,
        pending: Mutex<Vec<String>>,
    }

    impl RecordingChannel {
        fn new(ready: bool) -> Arc<Self> {
            Arc::new(Self {
                ready,
                sends: AtomicUsize::new(0),
                pending: Mutex::new(Vec::new()),
            })
        }

        fn sends(&self) -> usize {
            self.sends
                .load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl DidCommChannel for RecordingChannel {
        async fn send(
            &self,
            _to_did: &str,
            correlation_id: &str,
            _body: &Value,
        ) -> Result<(), VtaError> {
            self.sends
                .fetch_add(1, Ordering::SeqCst);
            self.pending
                .lock()
                .await
                .push(correlation_id.to_string());
            Ok(())
        }

        async fn is_ready(&self) -> bool {
            self.ready
        }
    }

    struct FailingChannel;

    #[async_trait]
    impl DidCommChannel for FailingChannel {
        async fn send(
            &self,
            _to_did: &str,
            _correlation_id: &str,
            _body: &Value,
        ) -> Result<(), VtaError> {
            Err(VtaError::Transport("mediator refused the message".to_string()))
        }

        async fn is_ready(&self) -> bool {
            true
        }
    }

    fn doc(id: &str) -> Value {
        json!({
            "id": id,
            "type": "https://trusttasks.org/spec/keys/sign-jws/0.1",
            "payload": {},
        })
    }

    fn detail(err: VtaError) -> String {
        err.log_detail().to_string()
    }

    /// `Result<String, _>` is `Debug`, but a uniform helper keeps the failure
    /// messages consistent with the rest of the VTA modules.
    fn expect_error(
        result: Result<String, VtaError>,
        expectation: &str,
    ) -> String {
        match result {
            Ok(_) => panic!("{expectation}"),
            Err(e) => detail(e),
        }
    }

    #[test]
    fn carriers_are_labelled_distinctly() {
        let https = HttpsTransport::new("https://vta.example", Duration::from_secs(5)).unwrap();
        assert_eq!(https.carrier(), "https");
        assert_eq!(https.trust_tasks_url, "https://vta.example/trust-tasks");

        let didcomm = DidCommTransport::new(RecordingChannel::new(true), "did:webvh:vta", Duration::from_secs(5));
        assert_eq!(didcomm.carrier(), "didcomm");
    }

    #[tokio::test]
    async fn a_reply_is_correlated_back_to_its_request() {
        let channel = RecordingChannel::new(true);
        let transport = Arc::new(DidCommTransport::new(channel.clone(), "did:webvh:vta", Duration::from_secs(5)));

        let waiting = {
            let transport = Arc::clone(&transport);
            tokio::spawn(async move {
                transport
                    .deliver(&doc("urn:uuid:req-1"), Some("tok"))
                    .await
            })
        };

        // Wait for the send to land, then answer it.
        let correlation = loop {
            let seen = channel
                .pending
                .lock()
                .await
                .clone();
            if let Some(first) = seen.first() {
                break first.clone();
            }
            tokio::task::yield_now().await;
        };
        assert_eq!(correlation, "urn:uuid:req-1", "the document id is the correlation id");
        assert!(
            transport
                .deliver_reply(&correlation, "{\"ok\":true}".to_string())
                .await
        );

        let body = waiting
            .await
            .unwrap()
            .expect("the correlated reply resolves the request");
        assert_eq!(body, "{\"ok\":true}");
        assert_eq!(transport.in_flight().await, 0, "the entry is removed once answered");
    }

    #[tokio::test]
    async fn a_silent_vta_fails_closed_within_the_deadline_and_leaks_nothing() {
        let channel = RecordingChannel::new(true);
        let transport = DidCommTransport::new(channel.clone(), "did:webvh:vta", Duration::from_millis(40));

        let msg = expect_error(
            transport
                .deliver(&doc("urn:uuid:silent"), None)
                .await,
            "a missing reply must not hang the caller",
        );
        assert!(msg.contains("did not reply"), "unexpected error: {msg}");
        assert!(msg.contains("40ms"), "the deadline must be named: {msg}");
        // The in-flight entry is the thing that would leak, so it must be gone.
        assert_eq!(transport.in_flight().await, 0);
        assert_eq!(channel.sends(), 1);
    }

    #[tokio::test]
    async fn a_late_reply_is_dropped_rather_than_buffered() {
        let transport = DidCommTransport::new(RecordingChannel::new(true), "did:webvh:vta", Duration::from_millis(20));
        let _ = transport
            .deliver(&doc("urn:uuid:late"), None)
            .await;

        // Nobody is waiting any more. Keeping this would be an unbounded buffer
        // fed by a remote party.
        assert!(
            !transport
                .deliver_reply("urn:uuid:late", "{}".to_string())
                .await
        );
        assert_eq!(transport.in_flight().await, 0);
    }

    #[tokio::test]
    async fn an_unsolicited_reply_is_ignored() {
        let transport = DidCommTransport::new(RecordingChannel::new(true), "did:webvh:vta", Duration::from_secs(5));
        assert!(
            !transport
                .deliver_reply("urn:uuid:never-sent", "{}".to_string())
                .await
        );
        assert_eq!(transport.in_flight().await, 0);
    }

    #[tokio::test]
    async fn a_send_failure_does_not_leave_an_entry_behind() {
        let transport = DidCommTransport::new(Arc::new(FailingChannel), "did:webvh:vta", Duration::from_secs(5));
        let msg = expect_error(
            transport
                .deliver(&doc("urn:uuid:nope"), None)
                .await,
            "the mediator refused",
        );
        assert!(msg.contains("mediator refused"), "unexpected error: {msg}");
        assert_eq!(transport.in_flight().await, 0);
    }

    #[tokio::test]
    async fn a_cold_mediator_says_so_instead_of_timing_out() {
        let channel = RecordingChannel::new(false);
        let transport = DidCommTransport::new(channel.clone(), "did:webvh:vta", Duration::from_secs(30));

        let msg = expect_error(
            transport
                .deliver(&doc("urn:uuid:cold"), None)
                .await,
            "an unready mediator must fail fast",
        );
        assert!(msg.contains("mediator is not ready"), "unexpected error: {msg}");
        assert_eq!(channel.sends(), 0, "nothing is sent through an unready mediator");
        assert_eq!(transport.in_flight().await, 0);
    }

    #[tokio::test]
    async fn the_in_flight_map_is_bounded() {
        let transport = Arc::new(DidCommTransport::new(
            RecordingChannel::new(true),
            "did:webvh:vta",
            // Long enough that nothing times out while the map fills.
            Duration::from_secs(30),
        ));

        // Fill it to the cap with requests that will never be answered.
        let mut tasks = Vec::new();
        for i in 0..MAX_IN_FLIGHT {
            let transport = Arc::clone(&transport);
            tasks.push(tokio::spawn(async move {
                transport
                    .deliver(&doc(&format!("urn:uuid:{i}")), None)
                    .await
            }));
        }
        while transport.in_flight().await < MAX_IN_FLIGHT {
            tokio::task::yield_now().await;
        }

        let msg = expect_error(
            transport
                .deliver(&doc("urn:uuid:one-too-many"), None)
                .await,
            "the cap must shed rather than grow",
        );
        assert!(msg.contains("awaiting a DIDComm reply"), "unexpected error: {msg}");
        assert!(msg.contains(&MAX_IN_FLIGHT.to_string()), "the cap must be named: {msg}");
        assert_eq!(transport.in_flight().await, MAX_IN_FLIGHT, "the rejected request added nothing");

        for task in tasks {
            task.abort();
        }
    }

    #[tokio::test]
    async fn a_document_without_an_id_cannot_be_correlated() {
        let transport = DidCommTransport::new(RecordingChannel::new(true), "did:webvh:vta", Duration::from_secs(5));
        let msg = expect_error(
            transport
                .deliver(&json!({ "type": "x", "payload": {} }), None)
                .await,
            "there would be no way to match the reply",
        );
        assert!(msg.contains("correlate"), "unexpected error: {msg}");
    }
}
