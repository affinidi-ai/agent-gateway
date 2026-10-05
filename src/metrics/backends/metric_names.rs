//! Centralized metric name constants shared across all backends (Prometheus, OpenTelemetry, CloudWatch).

// ============ Prometheus Metric Names ============

pub mod prom {
    // Gateway core
    pub const REQUESTS_TOTAL: &str = "agent_gateway_requests_total";
    pub const REQUESTS_SUCCESS_TOTAL: &str = "agent_gateway_requests_success_total";
    pub const REQUESTS_FAILURE_TOTAL: &str = "agent_gateway_requests_failure_total";
    pub const REQUESTS_GATEWAY_FAULT_TOTAL: &str = "agent_gateway_requests_gateway_fault_total";
    pub const REQUEST_DURATION_SECONDS: &str = "agent_gateway_request_duration_seconds";
    pub const ACTIVE_CONNECTIONS: &str = "agent_gateway_active_connections";
    pub const BYTES_SENT_TOTAL: &str = "agent_gateway_bytes_sent_total";
    pub const BYTES_RECEIVED_TOTAL: &str = "agent_gateway_bytes_received_total";

    // Rule validation
    pub const RULE_VALIDATIONS_ACCEPTED_TOTAL: &str = "agent_gateway_rule_validations_accepted_total";
    pub const RULE_VALIDATIONS_REJECTED_TOTAL: &str = "agent_gateway_rule_validations_rejected_total";

    // Auth
    #[allow(dead_code)]
    pub const AUTH_ATTEMPTS_TOTAL: &str = "agent_gateway_auth_attempts_total";
    #[allow(dead_code)]
    pub const AUTH_FAILURES_TOTAL: &str = "agent_gateway_auth_failures_total";

    // A2A protocol version negotiation (which era callers actually speak).
    pub const A2A_PROTOCOL_VERSION_TOTAL: &str = "agent_gateway_a2a_protocol_version_total";

    // Managed identity resolution (FromMtls / FromApiKey / Static / PayloadExtraction)
    pub const MANAGED_IDENTITY_RESOLVE_TOTAL: &str = "agent_gateway_managed_identity_resolve_total";
    pub const MANAGED_IDENTITY_RESOLVE_DURATION_SECONDS: &str =
        "agent_gateway_managed_identity_resolve_duration_seconds";

    // Trust Check element execution (TRQP authorization/recognition queries)
    pub const TRUST_CHECK_TOTAL: &str = "agent_gateway_trust_check_total";
    pub const TRUST_CHECK_DURATION_SECONDS: &str = "agent_gateway_trust_check_duration_seconds";

    // STS token exchange (RFC 8693 / ID-JAG) issuance outcomes
    pub const STS_TOKEN_EXCHANGE_TOTAL: &str = "agent_gateway_sts_token_exchange_total";
    pub const STS_TOKEN_EXCHANGE_DURATION_SECONDS: &str = "agent_gateway_sts_token_exchange_duration_seconds";

    // AWS KMS per-value envelope operations (GenerateDataKey / Decrypt)
    pub const KMS_OPERATION_TOTAL: &str = "agent_gateway_kms_operation_total";
    pub const KMS_OPERATION_DURATION_SECONDS: &str = "agent_gateway_kms_operation_duration_seconds";

    // Fabric (gateway-to-gateway) forwarding received at a connection point
    pub const FABRIC_FORWARD_REQUESTS_RECEIVED_TOTAL: &str = "agent_gateway_fabric_forward_requests_received_total";

    // DID Auth challenge issuance + JWS verification outcomes.
    pub const DIDAUTH_CHALLENGE_ISSUED_TOTAL: &str = "agent_gateway_didauth_challenge_issued_total";
    pub const DIDAUTH_AUTHENTICATE_TOTAL: &str = "agent_gateway_didauth_authenticate_total";
    pub const DIDAUTH_VERIFY_DURATION_SECONDS: &str = "agent_gateway_didauth_verify_duration_seconds";

    // Storage records that failed to load or were skipped at startup / on-demand.
    // Non-zero means the gateway is running degraded (records missing from the in-memory store).
    pub const STORAGE_LOAD_ERRORS_TOTAL: &str = "agent_gateway_storage_load_errors_total";

    // Plaintext key-material files that could not be deleted after their encrypted sibling
    // became authoritative. Non-zero means decrypted key material may still linger on disk.
    pub const STORAGE_PLAINTEXT_REMOVAL_FAILED_TOTAL: &str = "agent_gateway_storage_plaintext_removal_failed_total";

    // Governance audit records forwarded to audit integrations.
    pub const AUDIT_FORWARD_TOTAL: &str = "agent_gateway_audit_forward_total";

    pub const AFFINIDI_TERMS_REFRESH_TOTAL: &str = "agent_gateway_affinidi_terms_refresh_total";
    pub const AFFINIDI_TERMS_REFRESH_DURATION_SECONDS: &str = "agent_gateway_affinidi_terms_refresh_duration_seconds";
    pub const AFFINIDI_TERMS_CACHE_AGE_SECONDS: &str = "agent_gateway_affinidi_terms_cache_age_seconds";
    pub const AFFINIDI_TERMS_PUBLICATION_SEQUENCE: &str = "agent_gateway_affinidi_terms_publication_sequence";

    // Identity & connection gauges
    pub const UNIQUE_IDENTITIES: &str = "agent_gateway_unique_identities";
    pub const FABRIC_ENVELOPE_SEEN_ENTRIES: &str = "agent_gateway_fabric_envelope_seen_entries";
    pub const THROUGHPUT_BYTES_PER_SEC: &str = "agent_gateway_throughput_bytes_per_sec";
    pub const CONNECTIONS_PER_MINUTE: &str = "agent_gateway_connections_per_minute";
    pub const AVG_REQUEST_LATENCY_MS: &str = "agent_gateway_avg_request_latency_ms";
    pub const AVG_RESPONSE_LATENCY_MS: &str = "agent_gateway_avg_response_latency_ms";

    // User lifecycle
    pub const USER_EVENTS_TOTAL: &str = "agent_gateway_user_events_total";
    pub const USERS_ACTIVE: &str = "agent_gateway_users_active";
    pub const USER_LOGINS_TOTAL: &str = "agent_gateway_user_logins_total";
}

// ============ OpenTelemetry Instrument Names ============

pub mod otel {
    pub const CONNECTIONS_TOTAL: &str = "gateway.connections.total";
    pub const CONNECTION_LATENCY: &str = "gateway.connection.latency";
    pub const CONNECTIONS_ACTIVE: &str = "gateway.connections.active";

    pub const CHANNEL_REQUESTS_TOTAL: &str = "gateway.channel.requests.total";
    pub const CHANNEL_LATENCY: &str = "gateway.channel.latency";

    pub const MCP_REQUESTS_TOTAL: &str = "gateway.mcp.requests.total";
    pub const MCP_LATENCY: &str = "gateway.mcp.latency";

    pub const RULES_VALIDATIONS_TOTAL: &str = "gateway.rules.validations.total";

    pub const BYTES_SENT_TOTAL: &str = "gateway.bytes.sent.total";
    pub const BYTES_RECEIVED_TOTAL: &str = "gateway.bytes.received.total";

    pub const USER_EVENTS_TOTAL: &str = "gateway.user.events.total";
    pub const USER_LOGINS_TOTAL: &str = "gateway.user.logins.total";
}

// ============ CloudWatch Metric Names ============

pub mod cloudwatch {
    pub const REQUEST_COUNT: &str = "RequestCount";
    pub const SUCCESS_COUNT: &str = "SuccessCount";
    pub const FAILURE_COUNT: &str = "FailureCount";
    pub const GATEWAY_FAULT_COUNT: &str = "GatewayFaultCount";
    pub const SUCCESS_RATE: &str = "SuccessRate";
    pub const AVG_REQUEST_LATENCY: &str = "AverageRequestLatency";
    pub const REQUEST_LATENCY_SAMPLE_COUNT: &str = "RequestLatencySampleCount";
    pub const AVG_RESPONSE_LATENCY: &str = "AverageResponseLatency";
    pub const RESPONSE_LATENCY_SAMPLE_COUNT: &str = "ResponseLatencySampleCount";
    pub const ACTIVE_CONNECTIONS: &str = "ActiveConnections";
    pub const THROUGHPUT_BYTES_PER_SEC: &str = "ThroughputBytesPerSec";
    pub const CONNECTIONS_PER_MINUTE: &str = "ConnectionsPerMinute";
    pub const UNIQUE_IDENTITIES: &str = "UniqueIdentities";
    pub const RULE_ACCEPT_COUNT: &str = "RuleAcceptCount";
    pub const RULE_REJECT_COUNT: &str = "RuleRejectCount";
    pub const USER_CREATED_COUNT: &str = "UserCreatedCount";
    pub const ACTIVE_USERS: &str = "ActiveUsers";
    pub const USER_LOGINS: &str = "UserLogins";
}
