//! Custom HTTP tracing middleware that uses agent_gateway as the target
//!
//! This ensures HTTP request spans pass through our OpenTelemetry filter

use axum::{extract::Request, middleware::Next, response::Response};
use opentelemetry::global;
use opentelemetry::trace::TraceContextExt;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{Instrument, Level, debug, info};
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Opt-in toggle for recording the authenticated caller's identity on the
/// root HTTP span. Off by default; set from `traces.record_caller_identity`
/// at startup. When off, [`record_caller_identity_on_current_span`] is a
/// no-op so no `caller.*` attributes are emitted.
static RECORD_CALLER_IDENTITY: AtomicBool = AtomicBool::new(false);

/// Enable or disable recording of `caller.*` span attributes. Called once at
/// startup from the loaded observability configuration.
pub fn set_record_caller_identity(enabled: bool) {
    RECORD_CALLER_IDENTITY.store(enabled, Ordering::Relaxed);
}

fn record_caller_identity_enabled() -> bool {
    RECORD_CALLER_IDENTITY.load(Ordering::Relaxed)
}

/// Map an [`AuthenticatedIdentity`](crate::source_auth::AuthenticatedIdentity)
/// to the `caller.*` span attributes that describe it. Returns
/// `caller.auth_method` and `caller.principal` for every variant, plus
/// `caller.did` only for `did_auth` — the one variant whose DID is known at
/// authentication time. For the other methods the DID (when one exists) is
/// *derived* later in the pipeline (e.g. `from_jwt_claim` managed identity)
/// and is stamped separately via [`record_caller_did_on_current_span`].
pub fn caller_span_fields(identity: &crate::source_auth::AuthenticatedIdentity) -> Vec<(&'static str, String)> {
    use crate::source_auth::AuthenticatedIdentity;
    match identity {
        AuthenticatedIdentity::JwtBearer { subject, .. } => {
            vec![("caller.auth_method", "jwt_bearer".to_string()), ("caller.principal", subject.clone())]
        }
        AuthenticatedIdentity::ApiKey { key_name } => {
            vec![("caller.auth_method", "api_key".to_string()), ("caller.principal", key_name.clone())]
        }
        AuthenticatedIdentity::DidAuth { did } => vec![
            ("caller.auth_method", "did_auth".to_string()),
            ("caller.principal", did.clone()),
            ("caller.did", did.clone()),
        ],
        AuthenticatedIdentity::Mtls { principal, .. } => {
            vec![("caller.auth_method", "mtls".to_string()), ("caller.principal", principal.clone())]
        }
    }
}

/// Stamp the authenticated caller's identity onto the current span as
/// `caller.*` attributes. No-op when the toggle is disabled. The target span
/// (the root HTTP request span created by [`trace_http_request`]) pre-declares
/// these fields as `Empty`, so the values appear on the exported span even
/// when the request later fails (e.g. an OPA policy deny after auth succeeds).
pub fn record_caller_identity_on_current_span(identity: &crate::source_auth::AuthenticatedIdentity) {
    if !record_caller_identity_enabled() {
        return;
    }
    let span = tracing::Span::current();
    for (key, value) in caller_span_fields(identity) {
        span.record(key, value.as_str());
    }
}

/// Stamp the caller's *derived* DID onto the current span as `caller.did`.
///
/// Used for auth methods whose DID is not known at authentication time but is
/// resolved later by managed identity — most notably `from_jwt_claim`, where
/// the agent DID is derived from a validated JWT claim. For `did_auth` the DID
/// is already recorded by [`record_caller_identity_on_current_span`], so this
/// is a harmless overwrite with the same value. No-op when the toggle is off.
pub fn record_caller_did_on_current_span(did: &str) {
    if !record_caller_identity_enabled() || did.is_empty() {
        return;
    }
    tracing::Span::current().record("caller.did", did);
}

/// Returns true for paths that serve dashboard/UX static assets — these are
/// noisy (one request per JS/CSS/map/image) and only useful when actively
/// debugging the management UI, so we drop them to DEBUG.
fn is_static_asset_path(path: &str) -> bool {
    if path.starts_with("/static/") {
        return true;
    }
    // Catch hashed top-level bundles, source maps, and common dashboard
    // asset types served from `/` or other UI prefixes.
    matches!(
        std::path::Path::new(path)
            .extension()
            .and_then(|e| e.to_str()),
        Some(
            "js" | "css"
                | "map"
                | "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "svg"
                | "ico"
                | "webp"
                | "woff"
                | "woff2"
                | "ttf"
                | "eot"
        )
    )
}

/// Returns true for the dashboard's management API — high-volume polling
/// (surfaces, channels, metrics, health) that adds no signal to normal logs.
fn is_management_api_path(path: &str) -> bool {
    path.starts_with("/api/")
}

/// Returns true for DID:web document resolution endpoints served by the
/// gateway (e.g. `/connection-points/{id}/did.json`, `/.well-known/did.json`).
/// These are polled frequently by remote DID resolvers and add no signal.
fn is_did_resolution_path(path: &str) -> bool {
    path.ends_with("/did.json")
}

fn is_noisy_path(path: &str) -> bool {
    is_static_asset_path(path) || is_management_api_path(path) || is_did_resolution_path(path)
}

/// Returns true for dashboard SPA page loads — the React app is served as
/// `index.html` for any non-API/non-asset path, and a browser navigation or
/// refresh shows up as a GET with `Accept: text/html`. These are user UI
/// navigations, not backend traffic worth INFO-level visibility.
fn is_spa_html_navigation(
    method: &axum::http::Method,
    accept: &str,
) -> bool {
    method == axum::http::Method::GET && accept.contains("text/html")
}

/// Unconditional access log: logs every inbound HTTP request with method, path,
/// query, peer, and a small set of headers useful for debugging external
/// integrations (Accept, Host, User-Agent, Origin, MCP session id).
///
/// Logged at INFO so it surfaces in normal logs without enabling debug. Useful
/// for diagnosing situations where a client (e.g. Microsoft Copilot Studio)
/// reaches the gateway but doesn't trigger any channel handler — for instance
/// when it sends a probe GET, OPTIONS preflight, or hits an unmapped route.
///
/// Dashboard/UX static asset requests (JS/CSS/maps/images under `/static/` or
/// with a known asset extension) are logged at DEBUG instead — they're high
/// volume and add no signal for backend troubleshooting.
pub async fn access_log(
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path().to_string();
    let query = uri
        .query()
        .unwrap_or("")
        .to_string();
    let headers = request.headers();
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let origin = headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let mcp_session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let xfwd_for = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let xfwd_proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let is_asset = is_noisy_path(&path) || is_spa_html_navigation(&method, &accept);

    if is_asset {
        debug!(
            target: "agent_gateway::access",
            "➡️  HTTP {} {}{}{} host=\"{}\" accept=\"{}\" ua=\"{}\" origin=\"{}\" mcp_sid=\"{}\" xff=\"{}\" xfp=\"{}\"",
            method,
            path,
            if query.is_empty() { "" } else { "?" },
            query,
            host,
            accept,
            user_agent,
            origin,
            mcp_session_id,
            xfwd_for,
            xfwd_proto,
        );
    } else {
        info!(
            target: "agent_gateway::access",
            "➡️  HTTP {} {}{}{} host=\"{}\" accept=\"{}\" ua=\"{}\" origin=\"{}\" mcp_sid=\"{}\" xff=\"{}\" xfp=\"{}\"",
            method,
            path,
            if query.is_empty() { "" } else { "?" },
            query,
            host,
            accept,
            user_agent,
            origin,
            mcp_session_id,
            xfwd_for,
            xfwd_proto,
        );
    }

    let started = std::time::Instant::now();
    let response = next.run(request).await;
    let status = response.status();
    let elapsed_ms = started.elapsed().as_millis();
    let resp_ct = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if is_asset {
        debug!(
            target: "agent_gateway::access",
            "⬅️  HTTP {} {} → {} ({}ms) content-type=\"{}\"",
            method, path, status.as_u16(), elapsed_ms, resp_ct
        );
    } else {
        info!(
            target: "agent_gateway::access",
            "⬅️  HTTP {} {} → {} ({}ms) content-type=\"{}\"",
            method, path, status.as_u16(), elapsed_ms, resp_ct
        );
    }
    response
}

/// Check if a request path should be traced
/// Returns true ONLY for agent-to-agent communication, NOT dashboard/API calls
///
/// This dynamically checks against registered channel and MCP proxy prefixes.
/// Prefixes are registered when channels/MCP proxies are created.
///
/// This traces ONLY:
/// - A2A/MCP protocol traffic (agents using channels) - based on registered channel prefixes
/// - Background tasks are traced separately via spawn_traced_task
///
/// This does NOT trace:
/// - Identity API endpoints (dashboard/UX)
/// - Metrics, logs, monitoring endpoints
/// - Static files
#[allow(dead_code)]
fn should_trace_request(path: &str) -> bool {
    // Use the dynamic trace registry to check if this path should be traced
    super::should_trace_path(path)
}

/// Middleware that creates a root span for each HTTP request
///
/// This extracts trace context from HTTP headers if present (W3C traceparent),
/// otherwise creates a new root span.
///
/// Only business logic endpoints are traced (opt-in approach).
pub async fn trace_http_request(
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path().to_string();

    // Check if this path should be traced and get its human-readable name
    let trace_info = super::get_trace_info(&path);
    if trace_info.is_none() {
        return next.run(request).await;
    }

    let (entity_name, _entity_type) = trace_info.unwrap();

    // Create a human-readable span name using the entity name
    // entity_name already includes the [TYPE] prefix (e.g., "[CHANNEL] GW1 A2A Direct")
    // So the final span name will be like "POST [CHANNEL] GW1 A2A Direct"
    let span_name = format!("{} {}", method, entity_name);

    // Extract trace context from HTTP headers if present
    let parent_context = global::get_text_map_propagator(|propagator| {
        use opentelemetry::propagation::Extractor;

        struct HeaderExtractor<'a>(&'a axum::http::HeaderMap);

        impl<'a> Extractor for HeaderExtractor<'a> {
            fn get(
                &self,
                key: &str,
            ) -> Option<&str> {
                self.0
                    .get(key)
                    .and_then(|v| v.to_str().ok())
            }

            fn keys(&self) -> Vec<&str> {
                self.0
                    .keys()
                    .map(|k| k.as_str())
                    .collect()
            }
        }

        propagator.extract(&HeaderExtractor(request.headers()))
    });

    // Check if we got a valid parent context
    let has_parent = parent_context
        .span()
        .span_context()
        .is_valid();

    // Create a span with agent_gateway as the target
    // If there's a valid parent context, use it; otherwise create a root span
    let span = if has_parent {
        tracing::span!(
            target: "agent_gateway",
            Level::INFO,
            "http.request",
            otel.name = %span_name,
            http.method = %method,
            http.uri = %uri,
            http.path = %path,
            http.status_code = tracing::field::Empty,
            caller.auth_method = tracing::field::Empty,
            caller.principal = tracing::field::Empty,
            caller.did = tracing::field::Empty,
        )
    } else {
        tracing::span!(
            target: "agent_gateway",
            parent: None,
            Level::INFO,
            "http.request",
            otel.name = %span_name,
            http.method = %method,
            http.uri = %uri,
            http.path = %path,
            http.status_code = tracing::field::Empty,
            caller.auth_method = tracing::field::Empty,
            caller.principal = tracing::field::Empty,
            caller.did = tracing::field::Empty,
        )
    };

    // Set the parent context if we extracted one
    if has_parent {
        let _ = span.set_parent(parent_context);
    }

    // Use .instrument() to properly scope the async operation within the span
    async move {
        let response = next.run(request).await;
        let status = response.status();

        // Record status while span is active
        tracing::Span::current().record("http.status_code", status.as_u16());

        response
    }
    .instrument(span)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_auth::AuthenticatedIdentity;
    use crate::source_auth::models::{MtlsSans, PeerCertSource};

    fn field(
        fields: &[(&'static str, String)],
        key: &str,
    ) -> Option<String> {
        fields
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.clone())
    }

    #[test]
    fn caller_span_fields_jwt_bearer() {
        let id = AuthenticatedIdentity::JwtBearer {
            subject: "alice@example.com".to_string(),
            claims: serde_json::json!({"sub": "alice@example.com"}),
        };
        let f = caller_span_fields(&id);
        assert_eq!(field(&f, "caller.auth_method").as_deref(), Some("jwt_bearer"));
        assert_eq!(field(&f, "caller.principal").as_deref(), Some("alice@example.com"));
        assert_eq!(field(&f, "caller.did"), None);
    }

    #[test]
    fn caller_span_fields_api_key() {
        let id = AuthenticatedIdentity::ApiKey {
            key_name: "key-prod-01".to_string(),
        };
        let f = caller_span_fields(&id);
        assert_eq!(field(&f, "caller.auth_method").as_deref(), Some("api_key"));
        assert_eq!(field(&f, "caller.principal").as_deref(), Some("key-prod-01"));
        assert_eq!(field(&f, "caller.did"), None);
    }

    #[test]
    fn caller_span_fields_did_auth() {
        let id = AuthenticatedIdentity::DidAuth {
            did: "did:web:agent.example.com".to_string(),
        };
        let f = caller_span_fields(&id);
        assert_eq!(field(&f, "caller.auth_method").as_deref(), Some("did_auth"));
        assert_eq!(field(&f, "caller.principal").as_deref(), Some("did:web:agent.example.com"));
        assert_eq!(field(&f, "caller.did").as_deref(), Some("did:web:agent.example.com"));
    }

    #[test]
    fn caller_span_fields_mtls() {
        let id = AuthenticatedIdentity::Mtls {
            principal: "CN=client".to_string(),
            fingerprint: "abc123".to_string(),
            subject_dn: "CN=client,O=Acme".to_string(),
            issuer_dn: "CN=Acme CA".to_string(),
            sans: MtlsSans::default(),
            source: PeerCertSource::DirectTls,
        };
        let f = caller_span_fields(&id);
        assert_eq!(field(&f, "caller.auth_method").as_deref(), Some("mtls"));
        assert_eq!(field(&f, "caller.principal").as_deref(), Some("CN=client"));
        assert_eq!(field(&f, "caller.did"), None);
    }

    // ── Component test: proxied request produces a span with caller.* ──────────

    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::error::OTelSdkError;
    use opentelemetry_sdk::trace::{SdkTracerProvider, SpanData, SpanExporter};
    use std::sync::{Arc, Mutex};

    /// Minimal in-memory span exporter that captures exported spans for
    /// assertions. Spans are stored after any wrapping exporter (e.g. the
    /// redacting exporter) has run.
    #[derive(Debug, Clone)]
    struct CapturingExporter {
        spans: Arc<Mutex<Vec<SpanData>>>,
    }

    impl SpanExporter for CapturingExporter {
        async fn export(
            &self,
            batch: Vec<SpanData>,
        ) -> Result<(), OTelSdkError> {
            self.spans
                .lock()
                .unwrap()
                .extend(batch);
            Ok(())
        }

        fn set_resource(
            &mut self,
            _resource: &Resource,
        ) {
        }

        fn shutdown(&mut self) -> Result<(), OTelSdkError> {
            Ok(())
        }
    }

    fn span_attr(
        span: &SpanData,
        key: &str,
    ) -> Option<String> {
        span.attributes
            .iter()
            .find(|kv| kv.key.as_str() == key)
            .map(|kv| kv.value.as_str().to_string())
    }

    #[test]
    fn proxied_request_records_caller_auth_method_and_redacts_principal() {
        use crate::config::types::{LogRedactionConfig, LogRedactionRule};
        use crate::observability::log_redact::{LogRedactor, RedactingSpanExporter};
        use axum::{Router, body::Body, http::Request, routing::post};
        use opentelemetry::trace::TracerProvider as _;
        use tower::ServiceExt;
        use tracing_subscriber::layer::SubscriberExt;

        set_record_caller_identity(true);
        super::super::register_channel_prefix("/test-caller-span".to_string(), "Test Caller Span".to_string());

        let captured = Arc::new(Mutex::new(Vec::<SpanData>::new()));
        let exporter = CapturingExporter { spans: captured.clone() };

        // Redact email-shaped principals, exercising AC #8.
        let redactor = LogRedactor::from_config(&LogRedactionConfig {
            enabled: true,
            rules: vec![LogRedactionRule {
                name: "Email".to_string(),
                pattern: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b".to_string(),
                replacement: "[REDACTED-EMAIL]".to_string(),
            }],
        });
        let redacting = RedactingSpanExporter::new(exporter, redactor);

        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(redacting)
            .build();
        let tracer = provider.tracer("test");
        let subscriber = tracing_subscriber::registry().with(tracing_opentelemetry::OpenTelemetryLayer::new(tracer));

        tracing::subscriber::with_default(subscriber, || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                async fn handler() -> &'static str {
                    let identity = AuthenticatedIdentity::JwtBearer {
                        subject: "alice@example.com".to_string(),
                        claims: serde_json::json!({"sub": "alice@example.com"}),
                    };
                    record_caller_identity_on_current_span(&identity);
                    "ok"
                }
                let app = Router::new()
                    .route("/test-caller-span", post(handler))
                    .layer(axum::middleware::from_fn(trace_http_request));
                let req = Request::builder()
                    .method("POST")
                    .uri("/test-caller-span")
                    .body(Body::empty())
                    .unwrap();
                let _ = app
                    .oneshot(req)
                    .await
                    .unwrap();
            });
        });

        provider
            .force_flush()
            .unwrap();

        let spans = captured.lock().unwrap();
        let http_span = spans
            .iter()
            .find(|s| span_attr(s, "caller.auth_method").is_some())
            .expect("a span carrying caller.* attributes was exported");
        assert_eq!(span_attr(http_span, "caller.auth_method").as_deref(), Some("jwt_bearer"));
        assert_eq!(
            span_attr(http_span, "caller.principal").as_deref(),
            Some("[REDACTED-EMAIL]"),
            "principal email must be redacted by the redacting span exporter"
        );
    }

    #[test]
    fn proxied_request_records_derived_caller_did() {
        use axum::{Router, body::Body, http::Request, routing::post};
        use opentelemetry::trace::TracerProvider as _;
        use tower::ServiceExt;
        use tracing_subscriber::layer::SubscriberExt;

        set_record_caller_identity(true);
        super::super::register_channel_prefix("/test-caller-did".to_string(), "Test Caller Did".to_string());

        let captured = Arc::new(Mutex::new(Vec::<SpanData>::new()));
        let exporter = CapturingExporter { spans: captured.clone() };

        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter)
            .build();
        let tracer = provider.tracer("test");
        let subscriber = tracing_subscriber::registry().with(tracing_opentelemetry::OpenTelemetryLayer::new(tracer));

        tracing::subscriber::with_default(subscriber, || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                async fn handler() -> &'static str {
                    // Caller authenticated with a JWT bearer (no DID known here)…
                    let identity = AuthenticatedIdentity::JwtBearer {
                        subject: "agent-oid-123".to_string(),
                        claims: serde_json::json!({"oid": "agent-oid-123"}),
                    };
                    record_caller_identity_on_current_span(&identity);
                    // …then a DID is derived later in the pipeline (from_jwt_claim).
                    record_caller_did_on_current_span("did:web:agent.example.com");
                    "ok"
                }
                let app = Router::new()
                    .route("/test-caller-did", post(handler))
                    .layer(axum::middleware::from_fn(trace_http_request));
                let req = Request::builder()
                    .method("POST")
                    .uri("/test-caller-did")
                    .body(Body::empty())
                    .unwrap();
                let _ = app
                    .oneshot(req)
                    .await
                    .unwrap();
            });
        });

        provider
            .force_flush()
            .unwrap();

        let spans = captured.lock().unwrap();
        let http_span = spans
            .iter()
            .find(|s| span_attr(s, "caller.auth_method").is_some())
            .expect("a span carrying caller.* attributes was exported");
        assert_eq!(span_attr(http_span, "caller.auth_method").as_deref(), Some("jwt_bearer"));
        assert_eq!(span_attr(http_span, "caller.principal").as_deref(), Some("agent-oid-123"));
        assert_eq!(
            span_attr(http_span, "caller.did").as_deref(),
            Some("did:web:agent.example.com"),
            "derived agent DID must be stamped as caller.did even when auth method is jwt_bearer"
        );
    }
}
