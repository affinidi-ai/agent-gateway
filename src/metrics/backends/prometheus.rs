//! Prometheus metrics helpers

use lazy_static::lazy_static;
use prometheus::{
    Counter, Gauge, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
};

use super::metric_names::prom as names;

lazy_static! {
    /// Global Prometheus registry
    pub static ref REGISTRY: Registry = Registry::new();


    /// Total number of requests processed
    pub static ref REQUEST_COUNTER: Counter = {
        let opts = Opts::new(names::REQUESTS_TOTAL, "Total number of requests processed");
        let counter = Counter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };


    /// Total number of successful requests
    pub static ref SUCCESS_COUNTER: Counter = {
        let opts = Opts::new(names::REQUESTS_SUCCESS_TOTAL, "Total number of successful requests");
        let counter = Counter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };


    /// Total number of failed requests
    pub static ref FAILURE_COUNTER: Counter = {
        let opts = Opts::new(names::REQUESTS_FAILURE_TOTAL, "Total number of failed requests");
        let counter = Counter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };


    /// Total number of gateway fault requests
    pub static ref GATEWAY_FAULT_COUNTER: Counter = {
        let opts = Opts::new(names::REQUESTS_GATEWAY_FAULT_TOTAL, "Total number of gateway fault requests");
        let counter = Counter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };


    /// Request duration histogram (in seconds)
    pub static ref REQUEST_DURATION: Histogram = {
        let opts = HistogramOpts::new(names::REQUEST_DURATION_SECONDS, "Request duration in seconds")
            .buckets(vec![0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0]);
        let histogram = Histogram::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(histogram.clone())).unwrap();
        histogram
    };


    /// Number of currently active connections
    pub static ref ACTIVE_CONNECTIONS: Gauge = {
        let opts = Opts::new(names::ACTIVE_CONNECTIONS, "Number of currently active connections");
        let gauge = Gauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };


    /// Total bytes sent
    pub static ref BYTES_SENT: IntCounter = {
        let opts = Opts::new(names::BYTES_SENT_TOTAL, "Total bytes sent to clients");
        let counter = IntCounter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };


    /// Total bytes received
    pub static ref BYTES_RECEIVED: IntCounter = {
        let opts = Opts::new(names::BYTES_RECEIVED_TOTAL, "Total bytes received from clients");
        let counter = IntCounter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };


    /// Number of validated rule acceptances
    pub static ref RULE_ACCEPT_COUNTER: Counter = {
        let opts = Opts::new(names::RULE_VALIDATIONS_ACCEPTED_TOTAL, "Total number of accepted rule validations");
        let counter = Counter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };


    /// Number of validated rule rejections
    pub static ref RULE_REJECT_COUNTER: Counter = {
        let opts = Opts::new(names::RULE_VALIDATIONS_REJECTED_TOTAL, "Total number of rejected rule validations");
        let counter = Counter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Authentication attempts (labeled by channel and scheme)
    pub static ref AUTH_ATTEMPTS: IntCounterVec = {
        let opts = Opts::new(names::AUTH_ATTEMPTS_TOTAL, "Total number of authentication attempts");
        let counter = IntCounterVec::new(opts, &["channel_id", "scheme", "result"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Authentication failures (labeled by channel, scheme, and reason)
    pub static ref AUTH_FAILURES: IntCounterVec = {
        let opts = Opts::new(names::AUTH_FAILURES_TOTAL, "Total number of authentication failures");
        let counter = IntCounterVec::new(opts, &["channel_id", "scheme", "reason"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Number of identities seen
    pub static ref UNIQUE_IDENTITIES: IntGauge = {
        let opts = Opts::new(names::UNIQUE_IDENTITIES, "Number of unique agent identities observed");
        let gauge = IntGauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };

    /// Processed fabric envelopes remembered for replay protection
    pub static ref FABRIC_ENVELOPE_SEEN_ENTRIES: IntGauge = {
        let opts = Opts::new(
            names::FABRIC_ENVELOPE_SEEN_ENTRIES,
            "Number of processed fabric envelopes remembered for replay protection",
        );
        let gauge = IntGauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };

    /// A2A protocol version negotiation outcomes, labeled by channel, the version
    /// negotiated from `A2A-Version` (empty header ⇒ `0.3` per spec), and the era
    /// the request's JSON-RPC method name belongs to (`0.3` slash-form, `1.0`
    /// PascalCase, `unknown`, or `none` when the body carried no method).
    ///
    /// The gateway accepts either era regardless of the negotiated version, so
    /// `negotiated_version` and `method_era` can legitimately differ — that skew is
    /// exactly what this metric is here to reveal.
    pub static ref A2A_PROTOCOL_VERSION: IntCounterVec = {
        let opts = Opts::new(
            names::A2A_PROTOCOL_VERSION_TOTAL,
            "A2A protocol version negotiation outcomes (negotiated_version = 0.3|1.0|rejected; \
             method_era = 0.3|1.0|unknown|none)",
        );
        let counter = IntCounterVec::new(opts, &["channel_id", "negotiated_version", "method_era"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Managed identity resolution attempts (labeled by channel_id, mode, result)
    pub static ref MANAGED_IDENTITY_RESOLVE: IntCounterVec = {
        let opts = Opts::new(
            names::MANAGED_IDENTITY_RESOLVE_TOTAL,
            "Managed identity resolution outcomes (mode = payload_extraction|from_mtls|from_api_key|static|from_jwt_claim; \
             result = ok_new|ok_cached|ok_bound|<error_reason_label>)",
        );
        let counter = IntCounterVec::new(opts, &["channel_id", "mode", "result"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Managed identity resolution latency (labeled by channel_id, mode)
    pub static ref MANAGED_IDENTITY_RESOLVE_DURATION: HistogramVec = {
        let opts = HistogramOpts::new(
            names::MANAGED_IDENTITY_RESOLVE_DURATION_SECONDS,
            "Managed identity resolution duration in seconds",
        )
        // Tight buckets: cache hits should be sub-millisecond; miss ~1-10ms; store failures up to a second.
        .buckets(vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]);
        let h = HistogramVec::new(opts, &["channel_id", "mode"]).unwrap();
        REGISTRY.register(Box::new(h.clone())).unwrap();
        h
    };

    /// Trust Check element outcomes (labeled by trust_registry_id, query_type, result).
    /// `result` = `ok` (allowed) | `denied` (clean negative) | `error` (stage failure).
    pub static ref TRUST_CHECK: IntCounterVec = {
        let opts = Opts::new(
            names::TRUST_CHECK_TOTAL,
            "Trust Check element outcomes (result = ok|denied|error; \
             query_type = authorization|recognition)",
        );
        let counter = IntCounterVec::new(opts, &["trust_registry_id", "query_type", "result"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Trust Check element latency in seconds (labeled by trust_registry_id, query_type).
    /// Skipped for `TEMPLATE_RESOLUTION_FAILED` stage failures since no network call fires.
    pub static ref TRUST_CHECK_DURATION: HistogramVec = {
        let opts = HistogramOpts::new(
            names::TRUST_CHECK_DURATION_SECONDS,
            "Trust Check element execution duration in seconds",
        )
        .buckets(vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]);
        let h = HistogramVec::new(opts, &["trust_registry_id", "query_type"]).unwrap();
        REGISTRY.register(Box::new(h.clone())).unwrap();
        h
    };

    /// STS token-exchange issuance outcomes (labeled by grant, result).
    /// `grant` = `token_exchange` | `jwt_bearer` | `other`; `result` = `ok` | `denied` | `error`.
    pub static ref STS_TOKEN_EXCHANGE: IntCounterVec = {
        let opts = Opts::new(
            names::STS_TOKEN_EXCHANGE_TOTAL,
            "STS token-exchange issuance outcomes (grant = token_exchange|jwt_bearer|other; result = ok|denied|error)",
        );
        let counter = IntCounterVec::new(opts, &["grant", "result"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// STS issuance latency in seconds (labeled by grant). Observed on every
    /// outcome (success and rejection) so allow/deny latency is comparable.
    pub static ref STS_TOKEN_EXCHANGE_DURATION: HistogramVec = {
        let opts = HistogramOpts::new(
            names::STS_TOKEN_EXCHANGE_DURATION_SECONDS,
            "STS token issuance duration in seconds (grant = token_exchange|jwt_bearer|other)",
        )
        .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]);
        let h = HistogramVec::new(opts, &["grant"]).unwrap();
        REGISTRY.register(Box::new(h.clone())).unwrap();
        h
    };

    /// AWS KMS per-value envelope operation outcomes (labeled by op, result).
    /// `op` = `generate_data_key` | `decrypt`; `result` = `ok` | `error`.
    pub static ref KMS_OPERATION: IntCounterVec = {
        let opts = Opts::new(
            names::KMS_OPERATION_TOTAL,
            "AWS KMS per-value envelope operation outcomes (op = generate_data_key|decrypt; result = ok|error)",
        );
        let counter = IntCounterVec::new(opts, &["op", "result"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// AWS KMS per-value envelope operation latency in seconds (labeled by op).
    pub static ref KMS_OPERATION_DURATION: HistogramVec = {
        let opts = HistogramOpts::new(
            names::KMS_OPERATION_DURATION_SECONDS,
            "AWS KMS per-value envelope operation duration in seconds",
        )
        .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]);
        let h = HistogramVec::new(opts, &["op"]).unwrap();
        REGISTRY.register(Box::new(h.clone())).unwrap();
        h
    };

    /// Fabric forward requests received at a connection point (labeled by destination surface_id).
    /// Incremented once per inbound gateway-to-gateway `ForwardRequest` before any policy or
    /// forwarding, so it is the authoritative signal that a gateway received a fabric forward.
    pub static ref FABRIC_FORWARD_REQUESTS_RECEIVED: IntCounterVec = {
        let opts = Opts::new(
            names::FABRIC_FORWARD_REQUESTS_RECEIVED_TOTAL,
            "Total fabric (gateway-to-gateway) forward requests received at a connection point",
        );
        let counter = IntCounterVec::new(opts, &["surface_id"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// DID Auth challenges issued via `POST /authenticate/challenge` (labeled by surface_id).
    pub static ref DIDAUTH_CHALLENGE_ISSUED: IntCounterVec = {
        let opts = Opts::new(
            names::DIDAUTH_CHALLENGE_ISSUED_TOTAL,
            "Total DID Auth challenges issued (per surface)",
        );
        let counter = IntCounterVec::new(opts, &["surface_id"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// DID Auth `POST /authenticate` outcomes (labeled by surface_id + result).
    /// `result` = `ok` | one of the `DidAuthVerifyError::code()` values
    /// (`malformed_jws`, `algorithm_rejected`, `kid_mismatch`, `resolver_error`,
    /// `verification_method_not_found`, `unsupported_verification_method`,
    /// `bad_signature`, `malformed_payload`, `challenge_mismatch`,
    /// `iat_out_of_range`, `expired`, `audience_mismatch`, `did_not_allowed`).
    pub static ref DIDAUTH_AUTHENTICATE: IntCounterVec = {
        let opts = Opts::new(
            names::DIDAUTH_AUTHENTICATE_TOTAL,
            "DID Auth authenticate outcomes (result = ok | verify-error-code)",
        );
        let counter = IntCounterVec::new(opts, &["surface_id", "result"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// DID Auth verification latency in seconds (labeled by surface_id + result).
    /// Observations are skipped when the request never reaches verification
    /// (challenge-issuance path and DID-not-allowed pre-check).
    pub static ref DIDAUTH_VERIFY_DURATION: HistogramVec = {
        let opts = HistogramOpts::new(
            names::DIDAUTH_VERIFY_DURATION_SECONDS,
            "DID Auth verification duration in seconds",
        )
        .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]);
        let h = HistogramVec::new(opts, &["surface_id", "result"]).unwrap();
        REGISTRY.register(Box::new(h.clone())).unwrap();
        h
    };

    /// Storage records that failed to load or were skipped (labeled by entity, reason).
    /// A non-zero value means the gateway booted degraded — one or more persisted records are
    /// missing from the in-memory store. `reason` is low-cardinality, e.g.
    /// `encrypted_but_encryption_disabled`.
    pub static ref STORAGE_LOAD_ERRORS: IntCounterVec = {
        let opts = Opts::new(
            names::STORAGE_LOAD_ERRORS_TOTAL,
            "Storage records that failed to load or were skipped at startup/on-demand \
             (reason = encrypted_but_encryption_disabled|...)",
        );
        let counter = IntCounterVec::new(opts, &["entity", "reason"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Plaintext key-material files that could not be deleted after their encrypted sibling
    /// became authoritative (labeled by entity). A non-zero value means decrypted key material
    /// may still linger on disk — operators should alert on it.
    pub static ref STORAGE_PLAINTEXT_REMOVAL_FAILED: IntCounterVec = {
        let opts = Opts::new(
            names::STORAGE_PLAINTEXT_REMOVAL_FAILED_TOTAL,
            "Plaintext key-material files that could not be deleted after encryption \
             (non-zero means plaintext key material may remain on disk)",
        );
        let counter = IntCounterVec::new(opts, &["entity"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Attempts to deliver governance audit records to audit integrations (labeled by
    /// result: delivered|failed|not_receiving). `not_receiving` means the integration was
    /// disabled or changed so it no longer receives audit records; the record is kept and
    /// delivered if it receives them again.
    pub static ref AUDIT_FORWARD: IntCounterVec = {
        let opts = Opts::new(
            names::AUDIT_FORWARD_TOTAL,
            "Attempts to deliver governance audit records to audit integrations (result = delivered|failed|not_receiving)",
        );
        let counter = IntCounterVec::new(opts, &["result", "integration_id"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Governance audit records the system itself lost, by reason. `journal_write` means
    /// the records could not be written to the audit journal and were discarded once the
    /// in-memory backlog was full; `journal_closed` that the journal writer had stopped;
    /// `pipeline_not_running` that the audit pipeline was not running to take them;
    /// `aborted` that the pipeline stopped before the journal writer had written them.
    pub static ref AUDIT_RECORDS_LOST: IntCounterVec = {
        let opts = Opts::new(
            names::AUDIT_RECORDS_LOST_TOTAL,
            "Governance audit records the gateway lost before any sink received them (reason = journal_write|journal_closed|pipeline_not_running|aborted)",
        );
        let counter = IntCounterVec::new(opts, &["reason"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Governance audit records produced and handed to the journal, by event.
    pub static ref AUDIT_RECORDS_PRODUCED: IntCounterVec = {
        let opts = Opts::new(
            names::AUDIT_RECORDS_PRODUCED_TOTAL,
            "Governance audit records produced and handed to the journal (event = audit event name)",
        );
        let counter = IntCounterVec::new(opts, &["event"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Size of the governance audit journal on disk, in bytes.
    pub static ref AUDIT_JOURNAL_BYTES: IntGauge = {
        let opts = Opts::new(names::AUDIT_JOURNAL_BYTES, "Size of the governance audit journal on disk, in bytes");
        let gauge = IntGauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };

    /// Governance audit records a sink skipped, by sink and reason:
    /// `backlog_cap`, `expired`, `corrupt`, `paused` for records addressed
    /// to an integration it let go when it was paused, or `rejected` for a
    /// record that failed as many delivery attempts as the integration's
    /// attempt limit.
    pub static ref AUDIT_SINK_SKIPPED: IntCounterVec = {
        let opts = Opts::new(
            names::AUDIT_SINK_SKIPPED_TOTAL,
            "Governance audit records a sink skipped (reason = backlog_cap|expired|corrupt|paused|rejected; sink = audit_log or the integration id)",
        );
        let counter = IntCounterVec::new(opts, &["sink", "reason"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Whether the governance audit pipeline is running: 1 when it is, 0 when
    /// it failed to start or the node is in Standby, keeping and forwarding no
    /// audit records.
    pub static ref AUDIT_PIPELINE_STARTED: IntGauge = {
        let opts = Opts::new(
            names::AUDIT_PIPELINE_STARTED,
            "Whether the governance audit pipeline is running (1) or not, keeping and forwarding no audit records (0: failed to start, or the node is in Standby)",
        );
        let gauge = IntGauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };

    /// Governance audit sink rebuilds that could not list the integrations and
    /// kept the previous sinks until a retry succeeds.
    pub static ref AUDIT_SINK_REBUILD_FAILED: IntCounter = {
        let opts = Opts::new(
            names::AUDIT_SINK_REBUILD_FAILED_TOTAL,
            "Governance audit sink rebuilds that failed to list integrations, keeping the previous sinks until a retry succeeds",
        );
        let counter = IntCounter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Consent epoch reads that failed, each closing every MCP subscription on the vault.
    pub static ref MCP_SUBSCRIPTION_EPOCH_UNAVAILABLE: IntCounter = {
        let opts = Opts::new(
            names::MCP_SUBSCRIPTION_EPOCH_UNAVAILABLE_TOTAL,
            "Consent epoch reads that failed, each closing every MCP subscription on the vault",
        );
        let counter = IntCounter::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    pub static ref AFFINIDI_TERMS_REFRESH: IntCounterVec = {
        let opts = Opts::new(
            names::AFFINIDI_TERMS_REFRESH_TOTAL,
            "Affinidi Terms metadata refresh attempts by result",
        );
        let counter = IntCounterVec::new(opts, &["result"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    pub static ref AFFINIDI_TERMS_REFRESH_DURATION_SECONDS: Histogram = {
        let opts = HistogramOpts::new(
            names::AFFINIDI_TERMS_REFRESH_DURATION_SECONDS,
            "Affinidi Terms metadata refresh duration in seconds",
        );
        let histogram = Histogram::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(histogram.clone())).unwrap();
        histogram
    };

    pub static ref AFFINIDI_TERMS_CACHE_AGE_SECONDS: Gauge = {
        let opts = Opts::new(
            names::AFFINIDI_TERMS_CACHE_AGE_SECONDS,
            "Seconds since the last successful Affinidi Terms metadata refresh",
        );
        let gauge = Gauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };

    pub static ref AFFINIDI_TERMS_PUBLICATION_SEQUENCE: Gauge = {
        let opts = Opts::new(
            names::AFFINIDI_TERMS_PUBLICATION_SEQUENCE,
            "Current Affinidi Terms publication sequence",
        );
        let gauge = Gauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };

    /// Throughput in bytes per second
    pub static ref THROUGHPUT_BYTES_PER_SEC: Gauge = {
        let opts = Opts::new(names::THROUGHPUT_BYTES_PER_SEC, "Throughput in bytes per second");
        let gauge = Gauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };


    /// Connections per minute
    pub static ref CONNECTIONS_PER_MINUTE: Gauge = {
        let opts = Opts::new(names::CONNECTIONS_PER_MINUTE, "Connections per minute");
        let gauge = Gauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };


    /// Average request latency in milliseconds
    pub static ref AVG_REQUEST_LATENCY_MS: Gauge = {
        let opts = Opts::new(names::AVG_REQUEST_LATENCY_MS, "Average request latency in milliseconds (client to target)");
        let gauge = Gauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };


    /// Average response latency in milliseconds
    pub static ref AVG_RESPONSE_LATENCY_MS: Gauge = {
        let opts = Opts::new(names::AVG_RESPONSE_LATENCY_MS, "Average response latency in milliseconds (target to client)");
        let gauge = Gauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };


    // ============ User Lifecycle Metrics ============


    /// User events counter (labeled by event type and role)
    pub static ref USER_EVENTS: IntCounterVec = {
        let opts = Opts::new(names::USER_EVENTS_TOTAL, "Total number of user lifecycle events");
        let counter = IntCounterVec::new(opts, &["event", "role"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };

    /// Current number of active users (labeled by role and status)
    pub static ref USERS_ACTIVE: IntGauge = {
        let opts = Opts::new(names::USERS_ACTIVE, "Current number of active (approved) users");
        let gauge = IntGauge::with_opts(opts).unwrap();
        REGISTRY.register(Box::new(gauge.clone())).unwrap();
        gauge
    };

    /// User login counter (labeled by role)
    pub static ref USER_LOGINS: IntCounterVec = {
        let opts = Opts::new(names::USER_LOGINS_TOTAL, "Total number of user logins");
        let counter = IntCounterVec::new(opts, &["role"]).unwrap();
        REGISTRY.register(Box::new(counter.clone())).unwrap();
        counter
    };
}

/// Get metrics in Prometheus text format
pub fn get_metrics() -> String {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .unwrap();
    String::from_utf8(buffer).unwrap()
}

/// Track a connection event in Prometheus metrics
pub fn track_connection(
    status: crate::metrics::ConnectionStatus,
    duration_ms: Option<u64>,
    bytes_sent: u64,
    bytes_received: u64,
) {
    use crate::metrics::ConnectionStatus;

    REQUEST_COUNTER.inc();

    match status {
        ConnectionStatus::Success => SUCCESS_COUNTER.inc(),
        ConnectionStatus::Failed => FAILURE_COUNTER.inc(),
        ConnectionStatus::GatewayFault => GATEWAY_FAULT_COUNTER.inc(),
    }

    if let Some(duration) = duration_ms {
        REQUEST_DURATION.observe(duration as f64 / 1000.0);
    }

    BYTES_SENT.inc_by(bytes_sent);
    BYTES_RECEIVED.inc_by(bytes_received);
}

/// Track a rule validation event
pub fn track_rule_validation(accepted: bool) {
    if accepted {
        RULE_ACCEPT_COUNTER.inc();
    } else {
        RULE_REJECT_COUNTER.inc();
    }
}

/// Track an authentication attempt result
pub fn _track_auth_attempt(
    channel_id: &str,
    scheme: &str,
    result: &str,
) {
    AUTH_ATTEMPTS
        .with_label_values(&[channel_id, scheme, result])
        .inc();
}

/// Track an authentication failure with a reason
pub fn _track_auth_failure(
    channel_id: &str,
    scheme: &str,
    reason: &str,
) {
    AUTH_FAILURES
        .with_label_values(&[channel_id, scheme, reason])
        .inc();
}

/// Record an A2A protocol version negotiation.
///
/// `negotiated_version` is what `A2A-Version` resolved to (an absent or empty
/// header means `0.3`), or `rejected` for a request refused with `-32009`, and `method_era` is the era of the request's JSON-RPC
/// method name. They may differ: the gateway deliberately accepts either era
/// regardless of the negotiated version, and this counter shows the skew.
pub fn track_a2a_protocol_version(
    channel_id: &str,
    negotiated_version: &str,
    method_era: &str,
) {
    A2A_PROTOCOL_VERSION
        .with_label_values(&[channel_id, negotiated_version, method_era])
        .inc();
}

/// Track a managed-identity resolution outcome.
///
/// `mode`   = `payload_extraction` | `from_mtls` | `from_api_key` | `static` | `from_jwt_claim`
/// `result` = `ok_new` | `ok_cached` | `ok_bound` | `<error_reason_label>`
pub fn track_managed_identity_resolve(
    channel_id: &str,
    mode: &str,
    result: &str,
    duration_secs: f64,
) {
    MANAGED_IDENTITY_RESOLVE
        .with_label_values(&[channel_id, mode, result])
        .inc();
    MANAGED_IDENTITY_RESOLVE_DURATION
        .with_label_values(&[channel_id, mode])
        .observe(duration_secs);
}

/// Track a Trust Check element outcome.
///
/// `query_type` = `authorization` | `recognition`
/// `result`     = `ok` | `denied` | `error`
///
/// `duration_secs = None` skips the histogram observation (used for
/// `TEMPLATE_RESOLUTION_FAILED`, where no network call fired).
pub fn track_trust_check(
    trust_registry_id: &str,
    query_type: &str,
    result: &str,
    duration_secs: Option<f64>,
) {
    TRUST_CHECK
        .with_label_values(&[trust_registry_id, query_type, result])
        .inc();
    if let Some(d) = duration_secs {
        TRUST_CHECK_DURATION
            .with_label_values(&[trust_registry_id, query_type])
            .observe(d);
    }
}

/// Track an STS token-exchange issuance outcome.
///
/// `grant`  = `token_exchange` | `jwt_bearer` | `other`
/// `result` = `ok` | `denied` | `error`
pub fn track_sts_token_exchange(
    grant: &str,
    result: &str,
    duration_secs: f64,
) {
    STS_TOKEN_EXCHANGE
        .with_label_values(&[grant, result])
        .inc();
    STS_TOKEN_EXCHANGE_DURATION
        .with_label_values(&[grant])
        .observe(duration_secs);
}

/// Track an AWS KMS per-value envelope operation.
///
/// `op`     = `generate_data_key` | `decrypt`
/// `result` = `ok` | `error`
pub fn track_kms_operation(
    op: &str,
    result: &str,
    duration_secs: f64,
) {
    KMS_OPERATION
        .with_label_values(&[op, result])
        .inc();
    KMS_OPERATION_DURATION
        .with_label_values(&[op])
        .observe(duration_secs);
}

/// Track a fabric (gateway-to-gateway) forward request received at a connection point.
///
/// Called once per inbound `ForwardRequest`, before policy evaluation or forwarding, so the
/// counter is the authoritative signal that a gateway received a fabric forward to `surface_id`.
pub fn track_fabric_forward_received(surface_id: &str) {
    FABRIC_FORWARD_REQUESTS_RECEIVED
        .with_label_values(&[surface_id])
        .inc();
}

/// Track a DID Auth challenge issuance (labeled by surface_id).
pub fn track_didauth_challenge_issued(surface_id: &str) {
    DIDAUTH_CHALLENGE_ISSUED
        .with_label_values(&[surface_id])
        .inc();
}

/// Track a DID Auth `POST /authenticate` outcome.
///
/// `result` = `ok` on success, or one of the
/// [`crate::didauth::verify::DidAuthVerifyError::code()`] values
/// (`bad_signature`, `challenge_mismatch`, …).
///
/// `duration_secs = None` skips the histogram observation (used when the
/// request short-circuits before any signature-verification work — e.g. the
/// `did_not_allowed` allow-list check on the challenge endpoint).
pub fn track_didauth_authenticate(
    surface_id: &str,
    result: &str,
    duration_secs: Option<f64>,
) {
    DIDAUTH_AUTHENTICATE
        .with_label_values(&[surface_id, result])
        .inc();
    if let Some(d) = duration_secs {
        DIDAUTH_VERIFY_DURATION
            .with_label_values(&[surface_id, result])
            .observe(d);
    }
}

/// Track a storage record that failed to load or was skipped.
///
/// A non-zero count means the gateway is running degraded — one or more persisted records
/// (identities, certificates, surfaces, policies, …) are missing from the in-memory store.
/// `reason` is a low-cardinality label such as `encrypted_but_encryption_disabled`.
pub fn track_storage_load_error(
    entity: &str,
    reason: &str,
) {
    STORAGE_LOAD_ERRORS
        .with_label_values(&[entity, reason])
        .inc();
}

/// Track a plaintext key-material file that could not be deleted after encryption.
///
/// A non-zero count means decrypted key material may still linger on disk beside its
/// authoritative encrypted sibling. Operators should alert on this — accumulated plaintext
/// files defeat encryption at rest.
pub fn track_storage_plaintext_removal_failed(entity: &str) {
    STORAGE_PLAINTEXT_REMOVAL_FAILED
        .with_label_values(&[entity])
        .inc();
}

/// Track the outcome of one attempt to deliver a governance audit record to
/// an audit integration.
pub fn track_audit_forward(
    result: &str,
    integration_id: Option<&str>,
) {
    AUDIT_FORWARD
        .with_label_values(&[result, integration_id.unwrap_or_default()])
        .inc();
}

pub fn track_audit_records_lost(
    reason: &str,
    count: u64,
) {
    AUDIT_RECORDS_LOST
        .with_label_values(&[reason])
        .inc_by(count);
}

pub fn track_audit_record_produced(event: &str) {
    AUDIT_RECORDS_PRODUCED
        .with_label_values(&[event])
        .inc();
}

pub fn set_audit_journal_bytes(bytes: u64) {
    AUDIT_JOURNAL_BYTES.set(i64::try_from(bytes).unwrap_or(i64::MAX));
}

pub fn set_audit_pipeline_started(started: bool) {
    AUDIT_PIPELINE_STARTED.set(i64::from(started));
}

pub fn track_audit_sink_rebuild_failed() {
    AUDIT_SINK_REBUILD_FAILED.inc();
}

pub fn track_audit_sink_skipped(
    sink: &str,
    reason: &str,
    count: u64,
) {
    AUDIT_SINK_SKIPPED
        .with_label_values(&[sink, reason])
        .inc_by(count);
}

/// Track a failed consent epoch read that closed every MCP subscription on
/// its vault.
pub fn track_mcp_subscription_epoch_unavailable() {
    MCP_SUBSCRIPTION_EPOCH_UNAVAILABLE.inc();
}

/// Update active connections gauge
#[allow(dead_code)]
pub fn set_active_connections(count: i64) {
    ACTIVE_CONNECTIONS.set(count as f64);
}

/// Update unique identities count
#[allow(dead_code)]
pub fn set_unique_identities(count: i64) {
    UNIQUE_IDENTITIES.set(count);
}

/// Update the number of fabric envelopes remembered for replay protection
pub fn set_fabric_envelope_seen_entries(count: i64) {
    FABRIC_ENVELOPE_SEEN_ENTRIES.set(count);
}

/// Track a user lifecycle event (created, approved, updated, deleted)
pub fn track_user_event(
    event: &str,
    role: &str,
) {
    USER_EVENTS
        .with_label_values(&[event, role])
        .inc();
}

/// Track a user login
pub fn track_user_login(role: &str) {
    USER_LOGINS
        .with_label_values(&[role])
        .inc();
}

/// Update the active users gauge
#[allow(dead_code)]
pub fn set_active_users(count: i64) {
    USERS_ACTIVE.set(count);
}

#[cfg(test)]
mod tests {
    use super::{
        A2A_PROTOCOL_VERSION, AUDIT_PIPELINE_STARTED, AUDIT_SINK_REBUILD_FAILED, get_metrics, names,
        set_audit_pipeline_started, track_a2a_protocol_version, track_audit_sink_rebuild_failed,
        track_fabric_forward_received,
    };

    #[test]
    fn the_audit_pipeline_gauge_reports_whether_it_started() {
        assert_eq!(names::AUDIT_PIPELINE_STARTED, "agent_gateway_audit_pipeline_started");
        set_audit_pipeline_started(false);
        assert_eq!(AUDIT_PIPELINE_STARTED.get(), 0);
        set_audit_pipeline_started(true);
        assert_eq!(AUDIT_PIPELINE_STARTED.get(), 1);
        assert!(get_metrics().contains("agent_gateway_audit_pipeline_started 1"));
    }

    #[test]
    fn a_failed_audit_sink_rebuild_is_counted() {
        assert_eq!(names::AUDIT_SINK_REBUILD_FAILED_TOTAL, "agent_gateway_audit_sink_rebuild_failed_total");
        let before = AUDIT_SINK_REBUILD_FAILED.get();
        track_audit_sink_rebuild_failed();
        assert!(AUDIT_SINK_REBUILD_FAILED.get() > before);
        assert!(get_metrics().contains("agent_gateway_audit_sink_rebuild_failed_total"));
    }

    #[test]
    fn track_fabric_forward_received_increments_labeled_counter() {
        track_fabric_forward_received("ut_surface_alpha");
        let exposition = get_metrics();
        assert!(
            exposition
                .contains("agent_gateway_fabric_forward_requests_received_total{surface_id=\"ut_surface_alpha\"} 1"),
            "expected fabric forward counter for ut_surface_alpha in exposition:\n{exposition}"
        );
    }

    #[test]
    fn a2a_protocol_version_metric_uses_the_agent_gateway_prefix() {
        assert_eq!(names::A2A_PROTOCOL_VERSION_TOTAL, "agent_gateway_a2a_protocol_version_total");
        track_a2a_protocol_version("ut_a2a_version_name", "1.0", "1.0");
        assert!(get_metrics().contains("agent_gateway_a2a_protocol_version_total{"));
    }

    #[test]
    fn track_a2a_protocol_version_increments_only_the_matching_series() {
        let series = |negotiated: &str, era: &str| {
            A2A_PROTOCOL_VERSION
                .with_label_values(&["ut_a2a_version_skew", negotiated, era])
                .get()
        };
        let skewed_before = series("0.3", "1.0");
        let aligned_before = series("1.0", "1.0");

        track_a2a_protocol_version("ut_a2a_version_skew", "0.3", "1.0");

        assert_eq!(series("0.3", "1.0") - skewed_before, 1);
        assert_eq!(series("1.0", "1.0") - aligned_before, 0);
    }
}
