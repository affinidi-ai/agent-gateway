//! Configurable log redaction for all output destinations.
//!
//! Provides:
//! - `LogRedactor`         — compiled regex ruleset (built once, shared via `Arc`)
//! - `RedactingMakeWriter` — wraps any `MakeWriter` to redact formatted output
//! - `RedactingSpanExporter` — wraps an OTEL `SpanExporter` to redact span attributes
//! - `RedactingLogProcessor` — wraps an OTEL `LogProcessor` to redact log records

use crate::config::types::{LogRedactionConfig, LogRedactionRule};
use crate::observability::loggable;
use opentelemetry::logs::{AnyValue, LogRecord as _, Logger as _, LoggerProvider as _};
use opentelemetry::{InstrumentationScope, Key, KeyValue, Value as OtelValue};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::{LogProcessor, SdkLogRecord, SdkLogger, SdkLoggerProvider};
use opentelemetry_sdk::trace::{SpanData, SpanExporter};
use regex::Regex;
use std::borrow::Cow;
use std::io::Write;
use std::sync::{Arc, LazyLock};
use tracing_subscriber::fmt::MakeWriter;

// ── Built-in rules ──────────────────────────────────────────────────

/// Rules applied when `logging.redaction` sets no `rules`: credentials, private keys and
/// email addresses, as `(name, pattern, replacement)`.
const BUILT_IN_RULES: &[(&str, &str, &str)] = &[
    ("JWT tokens", r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED-JWT]"),
    (
        "Authorization header values",
        r#"(?i)((?:Authorization|Proxy-Authorization)\\?["']?\s*[:=]\s*\\?["']?(?:Bearer|Basic|Digest|Token|ApiKey)\s+)[^\s"'\\,]+"#,
        "${1}[REDACTED]",
    ),
    ("Password fields", r#"(?i)((?:password|passwd|pwd)\\?["']?\s*[:=]\s*\\?["']?)[^\s"'\\,;&}\]]+"#, "${1}[REDACTED]"),
    (
        "Access and refresh tokens",
        r#"(?i)((?:access_token|refresh_token|token)\\?["']?\s*[:=]\s*\\?["']?)[^\s"'\\,;&}\]]+"#,
        "${1}[REDACTED]",
    ),
    (
        "Session identifiers",
        r#"(?i)((?:session_id|sessionid|sid|jsessionid|connect\.sid)\\?["']?\s*[:=]\s*\\?["']?)[A-Za-z0-9_\-\.]+"#,
        "${1}[REDACTED-SESSION]",
    ),
    (
        "API key and secret assignments",
        r#"(?i)((?:api[_-]?key|secret)\\?["']?\s*[:=]\s*\\?["']?)[^\s"'\\,;&}\]]+"#,
        "${1}[REDACTED]",
    ),
    (
        "Quoted credential fields",
        r#"(?i)("[A-Za-z0-9_.-]*(?:authorization|cookie|api[_-]?key|secret(?:[_-]?key)?|private[_-]?key|token|passw(?:or)?d|session[_-]?id|credentials?)\\?"\s*:\s*\\?")[^"\\]*"#,
        "${1}[REDACTED]",
    ),
    ("Personal access tokens", r"agpat_[A-Za-z0-9_-]+", "[REDACTED-PAT]"),
    (
        "Private key material (PEM)",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
        "[REDACTED-PRIVATE-KEY]",
    ),
    ("Email addresses", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[REDACTED-EMAIL]"),
];

/// The built-in redaction rules, the default of `logging.redaction.rules`.
pub fn built_in_rules() -> Vec<LogRedactionRule> {
    BUILT_IN_RULES
        .iter()
        .map(|(name, pattern, replacement)| LogRedactionRule {
            name: (*name).to_string(),
            pattern: (*pattern).to_string(),
            replacement: (*replacement).to_string(),
        })
        .collect()
}

/// Exported attribute names whose values are credentials. An attribute is one when its
/// name, ignoring case, is one of these or ends with one after a `.`, `_` or `-`.
const CREDENTIAL_ATTRIBUTE_NAMES: &[&str] = &[
    "authorization",
    "cookie",
    "token",
    "session_id",
    "sessionid",
    "jsessionid",
    "password",
    "passwd",
    "secret",
    "secret_key",
    "api_key",
    "apikey",
    "private_key",
    "credential",
    "credentials",
];

fn is_credential_attribute(name: &str) -> bool {
    let normalized = name
        .to_ascii_lowercase()
        .replace(['.', '-'], "_");
    CREDENTIAL_ATTRIBUTE_NAMES
        .iter()
        .any(|credential| {
            normalized
                .strip_suffix(credential)
                .is_some_and(|prefix| prefix.is_empty() || prefix.ends_with('_'))
        })
}

// ── Compiled ruleset ────────────────────────────────────────────────

/// A single compiled rule: pre-compiled regex + replacement template.
struct CompiledRule {
    regex: Regex,
    replacement: String,
}

/// Thread-safe, immutable set of compiled redaction rules.
/// Built once at startup from [`LogRedactionConfig`] and shared via `Arc`.
pub struct LogRedactor {
    enabled: bool,
    rules: Vec<CompiledRule>,
}

impl LogRedactor {
    /// Compile rules from config. Invalid regexes are logged to stderr and skipped.
    pub fn from_config(config: &LogRedactionConfig) -> Arc<Self> {
        let rules = if config.enabled {
            config
                .rules
                .iter()
                .filter_map(Self::compile_rule)
                .collect()
        } else {
            Vec::new()
        };
        Arc::new(Self { enabled: config.enabled, rules })
    }

    fn compile_rule(rule: &LogRedactionRule) -> Option<CompiledRule> {
        match Regex::new(&rule.pattern) {
            Ok(regex) => Some(CompiledRule {
                regex,
                replacement: rule.replacement.clone(),
            }),
            Err(e) => {
                eprintln!("⚠️  Skipping invalid redaction rule '{}': {}", rule.name, e);
                None
            }
        }
    }

    /// Apply all rules in order to the input string.
    /// Returns the input borrowed when no rule matches.
    #[inline]
    pub fn redact<'a>(
        &self,
        input: &'a str,
    ) -> Cow<'a, str> {
        let mut output = Cow::Borrowed(input);
        for rule in &self.rules {
            if rule.regex.is_match(&output) {
                output = Cow::Owned(
                    rule.regex
                        .replace_all(&output, rule.replacement.as_str())
                        .into_owned(),
                );
            }
        }
        output
    }

    /// The value an exported attribute named `name` must carry instead of its own, or
    /// `None` when it is exported unchanged. A credential-named attribute is replaced
    /// whatever its type; any other attribute has the rules applied to its `text` value.
    fn redact_attribute(
        &self,
        name: &str,
        text: Option<&str>,
    ) -> Option<String> {
        if !self.enabled {
            return None;
        }
        if is_credential_attribute(name) {
            return Some(loggable::REDACTED.to_string());
        }
        match self.redact(text?) {
            Cow::Owned(redacted) => Some(redacted),
            Cow::Borrowed(_) => None,
        }
    }

    /// Returns true unless redaction is turned off with `enabled: false`.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Number of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl std::fmt::Debug for LogRedactor {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("LogRedactor")
            .field("enabled", &self.enabled)
            .field("rule_count", &self.rules.len())
            .finish()
    }
}

// ── Redacting MakeWriter ────────────────────────────────────────────

/// Wraps any [`MakeWriter`] so every write goes through [`LogRedactor`].
#[derive(Clone)]
pub struct RedactingMakeWriter<W> {
    inner: W,
    redactor: Arc<LogRedactor>,
}

impl<W> RedactingMakeWriter<W> {
    pub fn new(
        inner: W,
        redactor: Arc<LogRedactor>,
    ) -> Self {
        Self { inner, redactor }
    }
}

impl<'a, W: MakeWriter<'a>> MakeWriter<'a> for RedactingMakeWriter<W> {
    type Writer = RedactingWriter<W::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter {
            inner: self.inner.make_writer(),
            redactor: Arc::clone(&self.redactor),
        }
    }
}

/// Writer that buffers each `write` call, redacts it, then forwards.
pub struct RedactingWriter<W> {
    inner: W,
    redactor: Arc<LogRedactor>,
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(
        &mut self,
        buf: &[u8],
    ) -> std::io::Result<usize> {
        let original_len = buf.len();
        if let Ok(text) = std::str::from_utf8(buf) {
            let redacted = self.redactor.redact(text);
            self.inner
                .write_all(redacted.as_bytes())?;
            // Report original length consumed so tracing-subscriber doesn't retry
            Ok(original_len)
        } else {
            // Non-UTF-8: pass through unchanged
            self.inner.write_all(buf)?;
            Ok(original_len)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

// ── Redacting OTEL Span Exporter ────────────────────────────────────

/// Wraps a [`SpanExporter`] and redacts the name, attributes and events of every exported span.
#[derive(Debug)]
pub struct RedactingSpanExporter<E> {
    inner: E,
    redactor: Arc<LogRedactor>,
}

impl<E> RedactingSpanExporter<E> {
    pub fn new(
        inner: E,
        redactor: Arc<LogRedactor>,
    ) -> Self {
        Self { inner, redactor }
    }

    /// Redact the span name, attributes and events (in-place).
    fn redact_span(
        &self,
        span: &mut SpanData,
    ) {
        if !self.redactor.is_enabled() {
            return;
        }
        if let Cow::Owned(name) = self
            .redactor
            .redact(span.name.as_ref())
        {
            span.name = name.into();
        }

        for attribute in span.attributes.iter_mut() {
            self.redact_key_value(attribute);
        }

        // Redact event (log) messages attached to spans
        for event in span.events.events.iter_mut() {
            if let Cow::Owned(name) = self
                .redactor
                .redact(event.name.as_ref())
            {
                event.name = name.into();
            }
            for attribute in event.attributes.iter_mut() {
                self.redact_key_value(attribute);
            }
        }
    }

    fn redact_key_value(
        &self,
        attribute: &mut KeyValue,
    ) {
        let text = match &attribute.value {
            OtelValue::String(value) => Some(value.as_str()),
            _ => None,
        };
        if let Some(redacted) = self
            .redactor
            .redact_attribute(attribute.key.as_str(), text)
        {
            attribute.value = OtelValue::String(redacted.into());
        }
    }
}

impl<E> SpanExporter for RedactingSpanExporter<E>
where
    E: SpanExporter,
{
    async fn export(
        &self,
        batch: Vec<SpanData>,
    ) -> std::result::Result<(), opentelemetry_sdk::error::OTelSdkError> {
        let mut redacted_batch = batch;
        for span in redacted_batch.iter_mut() {
            self.redact_span(span);
        }
        self.inner
            .export(redacted_batch)
            .await
    }

    fn set_resource(
        &mut self,
        resource: &Resource,
    ) {
        self.inner
            .set_resource(resource);
    }

    fn shutdown(&mut self) -> std::result::Result<(), opentelemetry_sdk::error::OTelSdkError> {
        self.inner.shutdown()
    }
}

// ── Redacting OTEL Log Processor ────────────────────────────────────

/// Creates the empty records that redacted copies are built in: the SDK offers no other
/// way to make one, nor to change or remove an attribute of an existing record.
static RECORD_FACTORY: LazyLock<SdkLogger> = LazyLock::new(|| {
    SdkLoggerProvider::builder()
        .build()
        .logger("log-redaction")
});

/// Wraps a [`LogProcessor`] and redacts the body and attributes of every log record
/// before passing it on.
#[derive(Debug)]
pub struct RedactingLogProcessor<P> {
    inner: P,
    redactor: Arc<LogRedactor>,
}

impl<P> RedactingLogProcessor<P> {
    pub fn new(
        inner: P,
        redactor: Arc<LogRedactor>,
    ) -> Self {
        Self { inner, redactor }
    }

    fn redact_record(
        &self,
        record: &mut SdkLogRecord,
    ) {
        if let Some(AnyValue::String(body)) = record.body()
            && let Cow::Owned(redacted) = self
                .redactor
                .redact(body.as_str())
        {
            record.set_body(AnyValue::String(redacted.into()));
        }

        let mut changed = false;
        let attributes: Vec<(Key, AnyValue)> = record
            .attributes_iter()
            .map(|(key, value)| {
                let text = match value {
                    AnyValue::String(text) => Some(text.as_str()),
                    _ => None,
                };
                match self
                    .redactor
                    .redact_attribute(key.as_str(), text)
                {
                    Some(redacted) => {
                        changed = true;
                        (key.clone(), AnyValue::String(redacted.into()))
                    }
                    None => (key.clone(), value.clone()),
                }
            })
            .collect();
        if changed {
            *record = with_attributes(record, attributes);
        }
    }
}

/// A copy of `record` that carries `attributes` instead of its own.
fn with_attributes(
    record: &SdkLogRecord,
    attributes: Vec<(Key, AnyValue)>,
) -> SdkLogRecord {
    let mut copy = RECORD_FACTORY.create_log_record();
    if let Some(event_name) = record.event_name() {
        copy.set_event_name(event_name);
    }
    if let Some(target) = record.target() {
        copy.set_target(target.clone());
    }
    if let Some(timestamp) = record.timestamp() {
        copy.set_timestamp(timestamp);
    }
    if let Some(observed_timestamp) = record.observed_timestamp() {
        copy.set_observed_timestamp(observed_timestamp);
    }
    if let Some(trace_context) = record.trace_context() {
        copy.set_trace_context(trace_context.trace_id, trace_context.span_id, trace_context.trace_flags);
    }
    if let Some(severity_text) = record.severity_text() {
        copy.set_severity_text(severity_text);
    }
    if let Some(severity_number) = record.severity_number() {
        copy.set_severity_number(severity_number);
    }
    if let Some(body) = record.body() {
        copy.set_body(body.clone());
    }
    copy.add_attributes(attributes);
    copy
}

impl<P: LogProcessor> LogProcessor for RedactingLogProcessor<P> {
    fn emit(
        &self,
        record: &mut SdkLogRecord,
        scope: &InstrumentationScope,
    ) {
        if self.redactor.is_enabled() {
            self.redact_record(record);
        }
        self.inner.emit(record, scope);
    }

    fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult {
        self.inner.force_flush()
    }

    fn shutdown_with_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> opentelemetry_sdk::error::OTelSdkResult {
        self.inner
            .shutdown_with_timeout(timeout)
    }

    fn set_resource(
        &mut self,
        resource: &Resource,
    ) {
        self.inner
            .set_resource(resource);
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{LogRedactionConfig, LogRedactionRule};

    fn make_config(rules: Vec<(&str, &str, &str)>) -> LogRedactionConfig {
        LogRedactionConfig {
            enabled: true,
            rules: rules
                .into_iter()
                .map(|(name, pat, repl)| LogRedactionRule {
                    name: name.to_string(),
                    pattern: pat.to_string(),
                    replacement: repl.to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn test_no_match_returns_input_borrowed() {
        let r = LogRedactor::from_config(&LogRedactionConfig::default());
        let input = "agent_gateway::proxy::handler: forwarded request in 12 ms";
        assert!(matches!(r.redact(input), Cow::Borrowed(text) if text == input));
    }

    #[test]
    fn test_default_config_applies_built_in_rules() {
        let r = LogRedactor::from_config(&LogRedactionConfig::default());
        let result = r.redact("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc");
        assert_eq!(result.as_ref(), "Bearer [REDACTED-JWT]");
        assert!(r.is_enabled());
        assert_eq!(r.rule_count(), BUILT_IN_RULES.len());
    }

    #[test]
    fn test_jwt_redaction() {
        let cfg = make_config(vec![("JWT", r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED-JWT]")]);
        let r = LogRedactor::from_config(&cfg);
        let input = "token=eyJhbG.eyJzdW.sig done";
        let expected = "token=[REDACTED-JWT] done";
        assert_eq!(r.redact(input).as_ref(), expected);
    }

    #[test]
    fn test_bearer_redaction() {
        let cfg = make_config(vec![("Bearer", r"(?i)(Bearer\s+)\S+", "${1}[REDACTED]")]);
        let r = LogRedactor::from_config(&cfg);
        let input = "Authorization: Bearer abc123.def456.ghi789";
        assert!(
            r.redact(input)
                .contains("[REDACTED]")
        );
        assert!(
            !r.redact(input)
                .contains("abc123")
        );
    }

    #[test]
    fn test_email_redaction() {
        let cfg =
            make_config(vec![("Email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[REDACTED-EMAIL]")]);
        let r = LogRedactor::from_config(&cfg);
        assert_eq!(
            r.redact("user test@example.com logged in")
                .as_ref(),
            "user [REDACTED-EMAIL] logged in"
        );
    }

    #[test]
    fn test_ipv4_redaction() {
        let cfg = make_config(vec![("IPv4", r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[REDACTED-IP]")]);
        let r = LogRedactor::from_config(&cfg);
        assert_eq!(
            r.redact("connected from 192.168.1.42 ok")
                .as_ref(),
            "connected from [REDACTED-IP] ok"
        );
    }

    #[test]
    fn test_multiple_rules_applied_in_order() {
        let cfg = make_config(vec![
            ("Email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[REDACTED-EMAIL]"),
            ("IPv4", r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[REDACTED-IP]"),
        ]);
        let r = LogRedactor::from_config(&cfg);
        let input = "user@host.com from 10.0.0.1";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-EMAIL]"));
        assert!(result.contains("[REDACTED-IP]"));
        assert!(!result.contains("user@host.com"));
        assert!(!result.contains("10.0.0.1"));
    }

    #[test]
    fn test_disabled_does_nothing() {
        let cfg = LogRedactionConfig {
            enabled: false,
            rules: vec![LogRedactionRule {
                name: "everything".into(),
                pattern: r".+".into(),
                replacement: "GONE".into(),
            }],
        };
        let r = LogRedactor::from_config(&cfg);
        assert!(!r.is_enabled());
        assert_eq!(r.rule_count(), 0);
        assert_eq!(r.redact("keep me").as_ref(), "keep me");
        assert_eq!(r.redact_attribute("authorization", Some("Bearer abc")), None);
    }

    #[test]
    fn test_invalid_regex_skipped() {
        let cfg = make_config(vec![
            ("bad", r"[invalid", "x"),         // invalid regex
            ("good", r"secret", "[REDACTED]"), // valid
        ]);
        let r = LogRedactor::from_config(&cfg);
        assert_eq!(r.rule_count(), 1);
        assert_eq!(
            r.redact("my secret data")
                .as_ref(),
            "my [REDACTED] data"
        );
    }

    #[test]
    fn test_did_redaction() {
        let cfg = make_config(vec![("DID", r"did:[a-z]+:[A-Za-z0-9._:%-]+", "did:redacted:***")]);
        let r = LogRedactor::from_config(&cfg);
        assert_eq!(
            r.redact("resolved did:web:example.com:abc123 ok")
                .as_ref(),
            "resolved did:redacted:*** ok"
        );
    }

    #[test]
    fn test_eth_address_redaction() {
        let cfg = make_config(vec![("Ethereum", r"0x[0-9a-fA-F]{40}", "[REDACTED-ETH]")]);
        let r = LogRedactor::from_config(&cfg);
        let input = "pay to 0xAbCdEf0123456789AbCdEf0123456789AbCdEf01 now";
        assert!(
            r.redact(input)
                .contains("[REDACTED-ETH]")
        );
    }

    #[test]
    fn test_writer_redacts() {
        let cfg = make_config(vec![("secret", r"hunter2", "****")]);
        let redactor = LogRedactor::from_config(&cfg);

        let mut output = Vec::new();
        {
            let mut writer = RedactingWriter { inner: &mut output, redactor };
            writer
                .write_all(b"my password is hunter2 ok")
                .unwrap();
            writer.flush().unwrap();
        }
        assert_eq!(String::from_utf8(output).unwrap(), "my password is **** ok");
    }

    /// Redactor built from the `logging.redaction` rules of `gateway.example.json`.
    fn full_redactor() -> Arc<LogRedactor> {
        let example: serde_json::Value =
            serde_json::from_str(include_str!("../../config/examples/gateway.example.json")).unwrap();
        let config: LogRedactionConfig = serde_json::from_value(example["logging"]["redaction"].clone()).unwrap();
        let redactor = LogRedactor::from_config(&config);
        assert_eq!(redactor.rule_count(), config.rules.len(), "every example rule must compile");
        redactor
    }

    // ── Category 1: Always masked (high-risk secrets) ───────────────

    #[test]
    fn test_full_jwt_token() {
        let r = full_redactor();
        let input = "auth: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyIsImlhdCI6MTcwMH0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-JWT]"), "JWT not redacted: {result}");
        assert!(!result.contains("eyJhbGci"), "JWT payload leaked: {result}");
    }

    #[test]
    fn test_full_authorization_bearer() {
        let r = full_redactor();
        let input = r#"Authorization: Bearer sk-live-abc123def456"#;
        let result = r.redact(input);
        assert!(!result.contains("sk-live"), "Bearer token leaked: {result}");
    }

    #[test]
    fn test_full_authorization_basic() {
        let r = full_redactor();
        let input = r#"Authorization: Basic dXNlcjpwYXNzd29yZA=="#;
        let result = r.redact(input);
        assert!(!result.contains("dXNlcjpwYXNzd29yZA=="), "Basic cred leaked: {result}");
    }

    #[test]
    fn test_full_authorization_digest() {
        let r = full_redactor();
        let input = r#"Authorization: Digest username="admin",response="6629fae""#;
        let result = r.redact(input);
        assert!(result.contains("[REDACTED]"), "Digest cred not redacted: {result}");
    }

    #[test]
    fn test_full_proxy_authorization() {
        let r = full_redactor();
        let input = r#"Proxy-Authorization: Bearer proxy-token-xyz789"#;
        let result = r.redact(input);
        assert!(!result.contains("proxy-token"), "Proxy auth leaked: {result}");
    }

    #[test]
    fn test_full_password_equals() {
        let r = full_redactor();
        let input = "password=SuperSecret123!";
        let result = r.redact(input);
        assert!(!result.contains("SuperSecret"), "Password leaked: {result}");
    }

    #[test]
    fn test_full_password_json() {
        let r = full_redactor();
        let input = r#""password": "my-db-p@ss""#;
        let result = r.redact(input);
        assert!(!result.contains("my-db-p@ss"), "JSON password leaked: {result}");
    }

    #[test]
    fn test_full_passwd_field() {
        let r = full_redactor();
        let input = "passwd=hunter2";
        let result = r.redact(input);
        assert!(!result.contains("hunter2"), "passwd leaked: {result}");
    }

    #[test]
    fn test_full_access_token() {
        let r = full_redactor();
        let input = "access_token=ya29.a0ARrdaM8xyz-LONG_TOKEN_VALUE";
        let result = r.redact(input);
        assert!(!result.contains("ya29"), "Access token leaked: {result}");
    }

    #[test]
    fn test_full_refresh_token() {
        let r = full_redactor();
        let input = r#"refresh_token: "1//0eXYZ-refresh-value""#;
        let result = r.redact(input);
        assert!(!result.contains("0eXYZ"), "Refresh token leaked: {result}");
    }

    #[test]
    fn test_full_session_id() {
        let r = full_redactor();
        let input = "session_id=abc123-session-value.xyz";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-SESSION]"), "Session ID not redacted: {result}");
        assert!(!result.contains("abc123-session"), "Session value leaked: {result}");
    }

    #[test]
    fn test_full_jsessionid() {
        let r = full_redactor();
        let input = "JSESSIONID=1A2B3C4D5E6F7890ABCDEF";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-SESSION]"), "JSESSIONID not redacted: {result}");
    }

    #[test]
    fn test_full_pem_private_key() {
        let r = full_redactor();
        let input = "key: -----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRERnRB2gKF\nbase64data==\n-----END RSA PRIVATE KEY-----";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-PRIVATE-KEY]"), "PEM key not redacted: {result}");
        assert!(!result.contains("MIIBog"), "Key material leaked: {result}");
    }

    #[test]
    fn test_full_ec_private_key() {
        let r = full_redactor();
        let input = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIIr3...\n-----END EC PRIVATE KEY-----";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-PRIVATE-KEY]"), "EC key not redacted: {result}");
    }

    // ── Category 2: Common personal identifiers ─────────────────────

    #[test]
    fn test_full_email() {
        let r = full_redactor();
        let input = "User john.doe+tag@example.co.uk requested access";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-EMAIL]"), "Email not redacted: {result}");
        assert!(!result.contains("john.doe"), "Email leaked: {result}");
    }

    #[test]
    fn test_full_phone_international() {
        let r = full_redactor();
        let input = "Contact: +1-555-123-4567";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-PHONE]"), "Phone not redacted: {result}");
    }

    #[test]
    fn test_full_phone_with_parens() {
        let r = full_redactor();
        let input = "Call (0201) 555-7890 for support";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-PHONE]"), "Phone with parens not redacted: {result}");
    }

    #[test]
    fn test_full_phone_dots() {
        let r = full_redactor();
        let input = "Fax: +44.20.7946.0958";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-PHONE]"), "Dotted phone not redacted: {result}");
    }

    #[test]
    fn test_full_credit_card_visa() {
        let r = full_redactor();
        let input = "Card: 4111111111111111";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-CARD]"), "Visa not redacted: {result}");
        assert!(!result.contains("4111111111111111"), "Card number leaked: {result}");
    }

    #[test]
    fn test_full_credit_card_mastercard() {
        let r = full_redactor();
        let input = "Charged 5500000000000004";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-CARD]"), "Mastercard not redacted: {result}");
    }

    #[test]
    fn test_full_credit_card_amex() {
        let r = full_redactor();
        let input = "Amex: 378282246310005";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-CARD]"), "Amex not redacted: {result}");
    }

    #[test]
    fn test_full_credit_card_formatted() {
        let r = full_redactor();
        let input = "Card: 4111-1111-1111-1111";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-CARD]"), "Formatted card not redacted: {result}");
    }

    #[test]
    fn test_full_credit_card_keyword() {
        let r = full_redactor();
        let input = "credit card 4111111111111111";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-CARD]"), "Card with keyword not redacted: {result}");
    }

    // ── Category 3: Online / technical identifiers ──────────────────

    #[test]
    fn test_full_ipv4() {
        let r = full_redactor();
        let input = "Request from 192.168.1.100 to server";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-IP]"), "IPv4 not redacted: {result}");
        assert!(!result.contains("192.168.1.100"), "IPv4 leaked: {result}");
    }

    #[test]
    fn test_full_ipv6_full() {
        let r = full_redactor();
        let input = "Connected from 2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-IPv6]"), "IPv6 not redacted: {result}");
    }

    #[test]
    fn test_full_ipv6_abbreviated() {
        let r = full_redactor();
        let input = "Source: fe80::1";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-IPv6]"), "Abbreviated IPv6 not redacted: {result}");
    }

    #[test]
    fn test_full_device_id() {
        let r = full_redactor();
        let input = "device_id=a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-DEVICE-ID]"), "Device ID not redacted: {result}");
    }

    #[test]
    fn test_full_android_id() {
        let r = full_redactor();
        let input = "android_id: abcdef0123456789abcdef0123456789";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-DEVICE-ID]"), "Android ID not redacted: {result}");
    }

    // ── Category 4: Platform-specific identity artefacts ────────────

    #[test]
    fn test_full_did_web() {
        let r = full_redactor();
        let input = "Resolved did:web:example.com:users:alice";
        let result = r.redact(input);
        assert!(result.contains("did:redacted:***"), "DID web not redacted: {result}");
        assert!(!result.contains("example.com"), "DID domain leaked: {result}");
    }

    #[test]
    fn test_full_did_key() {
        let r = full_redactor();
        let input = "Verified did:key:z6Mkexampleexampleexampleexample";
        let result = r.redact(input);
        assert!(result.contains("did:redacted:***"), "DID key not redacted: {result}");
    }

    #[test]
    fn test_full_ethereum_address() {
        let r = full_redactor();
        let input = "Wallet: 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD20";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-ETH]"), "ETH address not redacted: {result}");
        assert!(!result.contains("742d35"), "ETH address leaked: {result}");
    }

    #[test]
    fn test_full_public_key() {
        let r = full_redactor();
        let input = r#"publicKey: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjBtoy0VL""#;
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-PUBKEY]"), "Public key not redacted: {result}");
        assert!(!result.contains("MFkwEw"), "Public key material leaked: {result}");
    }

    #[test]
    fn test_full_api_key_assignment() {
        let r = full_redactor();
        let input = "api_key=sk-proj-example";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED]"), "API key not redacted: {result}");
        assert!(!result.contains("sk-proj"), "API key value leaked: {result}");
    }

    #[test]
    fn test_full_secret_assignment() {
        let r = full_redactor();
        let input = "secret: my-super-secret-value-2024";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED]"), "Secret not redacted: {result}");
        assert!(!result.contains("my-super-secret"), "Secret value leaked: {result}");
    }

    // ── Category 5: Region-specific ─────────────────────────────────

    #[test]
    fn test_full_us_ssn() {
        let r = full_redactor();
        let input = "SSN: 123-45-6789";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-US-SSN]"), "US SSN not redacted: {result}");
        assert!(!result.contains("123-45-6789"), "SSN leaked: {result}");
    }

    #[test]
    fn test_full_cn_resident_id() {
        let r = full_redactor();
        // Valid 18-digit Chinese resident ID (Beijing, 1990-01-01, male)
        let input = "ID: 110101199001011234";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-CN-RES-ID-NO]"), "CN ID not redacted: {result}");
    }

    #[test]
    fn test_full_uk_national_insurance() {
        let r = full_redactor();
        let input = "NI number: AB123456C";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-UK-INS-NO]"), "UK NI not redacted: {result}");
        assert!(!result.contains("AB123456C"), "UK NI leaked: {result}");
    }

    #[test]
    fn test_full_passport_number() {
        let r = full_redactor();
        let input = "passport: AB1234567";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-ID]"), "Passport not redacted: {result}");
        assert!(!result.contains("AB1234567"), "Passport leaked: {result}");
    }

    #[test]
    fn test_full_national_id() {
        let r = full_redactor();
        let input = "national id: XY12345678901";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-ID]"), "National ID not redacted: {result}");
    }

    // ── Category 2b: Physical address fields ────────────────────────

    #[test]
    fn test_full_address_json() {
        let r = full_redactor();
        let input = r#""address": "123 Main Street, Springfield, IL 62704""#;
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-ADDRESS]"), "JSON address not redacted: {result}");
        assert!(!result.contains("Main Street"), "Address leaked: {result}");
    }

    #[test]
    fn test_full_street_field() {
        let r = full_redactor();
        let input = r#""street": "42 Baker Street""#;
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-ADDRESS]"), "Street not redacted: {result}");
        assert!(!result.contains("Baker"), "Street leaked: {result}");
    }

    #[test]
    fn test_full_address_line_1() {
        let r = full_redactor();
        let input = r#""address_line_1": "Flat 3, 12 High Road""#;
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-ADDRESS]"), "address_line_1 not redacted: {result}");
        assert!(!result.contains("High Road"), "Address line leaked: {result}");
    }

    #[test]
    fn test_full_postal_code() {
        let r = full_redactor();
        let input = r#"postal_code: "EC2V 7AN""#;
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-ADDRESS]"), "Postal code not redacted: {result}");
        assert!(!result.contains("EC2V"), "Postal code leaked: {result}");
    }

    #[test]
    fn test_full_zip_code() {
        let r = full_redactor();
        let input = "zip_code=90210";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-ADDRESS]"), "Zip code not redacted: {result}");
        assert!(!result.contains("90210"), "Zip code leaked: {result}");
    }

    #[test]
    fn test_full_address_key_value() {
        let r = full_redactor();
        let input = "address=Unit 5, 200 Broadway, New York";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-ADDRESS]"), "KV address not redacted: {result}");
        assert!(!result.contains("Broadway"), "Address leaked: {result}");
    }

    // ── Multi-rule interaction tests ────────────────────────────────

    #[test]
    fn test_full_log_line_multiple_sensitive_values() {
        let r = full_redactor();
        let input = "User admin@corp.com from 10.0.0.42 with api_key=sk-abc123 accessed did:web:example.com";
        let result = r.redact(input);
        assert!(result.contains("[REDACTED-EMAIL]"), "Email missed in multi-value: {result}");
        assert!(result.contains("[REDACTED-IP]"), "IP missed in multi-value: {result}");
        assert!(result.contains("[REDACTED]"), "API key missed in multi-value: {result}");
        assert!(result.contains("did:redacted:***"), "DID missed in multi-value: {result}");
        assert!(!result.contains("admin@corp.com"), "Email leaked in multi-value: {result}");
        assert!(!result.contains("10.0.0.42"), "IP leaked in multi-value: {result}");
    }

    #[test]
    fn test_full_json_payload_with_secrets() {
        let r = full_redactor();
        let input = r#"{"password": "s3cret!", "access_token": "ya29.abc", "email": "user@test.com"}"#;
        let result = r.redact(input);
        assert!(!result.contains("s3cret!"), "JSON password leaked: {result}");
        assert!(!result.contains("ya29.abc"), "JSON access_token leaked: {result}");
        assert!(!result.contains("user@test.com"), "JSON email leaked: {result}");
    }

    // ── Built-in rules ──────────────────────────────────────────────

    fn built_in_redactor() -> Arc<LogRedactor> {
        LogRedactor::from_config(&LogRedactionConfig::default())
    }

    #[test]
    fn test_built_in_rules_all_compile() {
        assert_eq!(built_in_redactor().rule_count(), BUILT_IN_RULES.len());
        assert_eq!(built_in_rules().len(), BUILT_IN_RULES.len());
    }

    #[test]
    fn test_built_in_rules_redact_json_quoted_authorization() {
        let result = built_in_redactor()
            .redact(r#"headers={"authorization": "Bearer abc123secretvalue", "accept": "*/*"}"#)
            .into_owned();
        assert_eq!(result, r#"headers={"authorization": "[REDACTED]", "accept": "*/*"}"#);
    }

    #[test]
    fn test_built_in_rules_redact_json_quoted_api_key() {
        let result = built_in_redactor()
            .redact(r#"{"x-api-key": "abc", "content-type": "application/json"}"#)
            .into_owned();
        assert_eq!(result, r#"{"x-api-key": "[REDACTED]", "content-type": "application/json"}"#);
    }

    #[test]
    fn test_built_in_rules_redact_json_escaped_quoted_values() {
        let result = built_in_redactor()
            .redact(r#"{"message":"headers {\"Authorization\": \"Bearer abc123\", \"cookie\": \"sid-value\"}"}"#)
            .into_owned();
        assert_eq!(result, r#"{"message":"headers {\"Authorization\": \"[REDACTED]\", \"cookie\": \"[REDACTED]\"}"}"#);
    }

    #[test]
    fn test_built_in_quoted_rule_ignores_counts_and_secret_references() {
        let input = r#"{"input_tokens": "12", "token_count": "3", "secret_id": "otel-token", "api_key_id": "key-1"}"#;
        assert_eq!(
            built_in_redactor()
                .redact(input)
                .as_ref(),
            input
        );
    }

    #[test]
    fn test_built_in_rules_redact_personal_access_token() {
        let result = built_in_redactor()
            .redact("authenticated with agpat_0f2c9d7e1b3a4c5d")
            .into_owned();
        assert_eq!(result, "authenticated with [REDACTED-PAT]");
    }

    #[test]
    fn test_built_in_rules_redact_credentials_and_email() {
        let r = built_in_redactor();
        for (input, hidden) in [
            ("Authorization: Bearer sk-live-abc123", "sk-live-abc123"),
            ("password=SuperSecret123!", "SuperSecret123!"),
            ("access_token=ya29.a0ARrdaM8xyz", "ya29.a0ARrdaM8xyz"),
            ("session_id=abc123-session-value", "abc123-session-value"),
            ("api_key=sk-proj-example", "sk-proj-example"),
            ("secret: my-super-secret-value", "my-super-secret-value"),
            ("user alice@example.com signed in", "alice@example.com"),
            ("-----BEGIN PRIVATE KEY-----\nMIIBogIBAAJBALRE\n-----END PRIVATE KEY-----", "MIIBogIBAAJBALRE"),
        ] {
            let result = r.redact(input);
            assert!(!result.contains(hidden), "a credential leaked: {result}");
            assert!(result.contains("[REDACTED"), "no placeholder in: {result}");
        }
    }

    #[test]
    fn test_built_in_rules_keep_ordinary_log_text() {
        let r = built_in_redactor();
        for input in [
            "agent_gateway::observability::opentelemetry: Initializing OpenTelemetry logs",
            "Listening on 0.0.0.0:8443 for 2001:db8::1",
            "Resolved did:web:example.com in 1700000000123 ns",
            "Failed to read the secret store: not found",
            "AG_EVENT_HOOK_SECRET matches the key the receiver uses",
        ] {
            assert_eq!(r.redact(input).as_ref(), input);
        }
    }

    #[test]
    fn test_built_in_rules_keep_json_log_lines_valid() {
        let r = built_in_redactor();
        for (line, hidden_values) in [
            (
                r#"{"fields":{"message":"Minted DID Auth session","session_id":"7c1e5a90-session","expires_at":"2026"},"target":"agent_gateway::didauth"}"#,
                vec!["7c1e5a90-session"],
            ),
            (
                r#"{"fields":{"message":"login","password":"hunter2","api_key":"sk-123","token":"abc"},"target":"agent_gateway::auth"}"#,
                vec!["hunter2", "sk-123", "\"abc\""],
            ),
            (
                r#"{"fields":{"message":"HTTP GET /x mcp_sid=\"abcd1234...\" password=\"pw-value\" Authorization: Bearer xyz-token, next"},"target":"agent_gateway::access"}"#,
                vec!["abcd1234", "pw-value", "xyz-token"],
            ),
        ] {
            let redacted = r.redact(line);
            let parsed: serde_json::Value = serde_json::from_str(&redacted).unwrap_or_else(|error| {
                panic!("redaction broke the JSON line ({error}): {redacted}");
            });
            assert!(parsed["target"].is_string(), "{redacted}");
            assert!(redacted.contains("[REDACTED"), "{redacted}");
            for hidden in hidden_values {
                assert!(!redacted.contains(hidden), "a credential leaked: {redacted}");
            }
        }
    }

    #[test]
    fn test_example_rules_start_with_the_built_in_rules() {
        let example: serde_json::Value =
            serde_json::from_str(include_str!("../../config/examples/gateway.example.json")).unwrap();
        let config: LogRedactionConfig = serde_json::from_value(example["logging"]["redaction"].clone()).unwrap();
        assert_eq!(config.rules[..BUILT_IN_RULES.len()], built_in_rules()[..]);
    }

    // ── Attribute names ─────────────────────────────────────────────

    #[test]
    fn test_credential_attribute_names_match_case_insensitively_after_a_separator() {
        for name in [
            "authorization",
            "Authorization",
            "http.request.header.authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "token",
            "access_token",
            "session_id",
            "mcp_session_id",
            "PASSWORD",
            "client_secret",
            "stripe_secret_key",
            "api_key",
            "x-api-key",
            "private_key",
            "credentials",
        ] {
            assert!(is_credential_attribute(name), "{name} must be treated as a credential");
        }
    }

    #[test]
    fn test_non_credential_attribute_names_are_not_matched() {
        for name in [
            "token_count",
            "gen_ai.usage.input_tokens",
            "max_tokens",
            "secret_id",
            "api_key_id",
            "session",
            "http.uri",
            "caller.did",
            "message",
        ] {
            assert!(!is_credential_attribute(name), "{name} must not be treated as a credential");
        }
    }

    #[test]
    fn test_redact_attribute_replaces_credential_names_and_applies_rules_to_others() {
        let r = built_in_redactor();
        assert_eq!(r.redact_attribute("token", Some("0f2c9d7e...")), Some(loggable::REDACTED.to_string()));
        assert_eq!(r.redact_attribute("session_id", None), Some(loggable::REDACTED.to_string()));
        assert_eq!(
            r.redact_attribute("detail", Some("login by bob@example.com")),
            Some("login by [REDACTED-EMAIL]".to_string())
        );
        assert_eq!(r.redact_attribute("detail", Some("ok")), None);
        assert_eq!(r.redact_attribute("detail", None), None);
    }

    // ── Span exporter ───────────────────────────────────────────────

    #[derive(Debug)]
    struct CapturingSpanExporter {
        spans: Arc<std::sync::Mutex<Vec<SpanData>>>,
    }

    impl SpanExporter for CapturingSpanExporter {
        async fn export(
            &self,
            batch: Vec<SpanData>,
        ) -> opentelemetry_sdk::error::OTelSdkResult {
            self.spans
                .lock()
                .unwrap()
                .extend(batch);
            Ok(())
        }
    }

    fn export_span(
        redactor: Arc<LogRedactor>,
        attributes: Vec<KeyValue>,
    ) -> SpanData {
        use opentelemetry::trace::{Span as _, Tracer as _, TracerProvider as _};

        let spans = Arc::new(std::sync::Mutex::new(Vec::new()));
        let exporter = RedactingSpanExporter::new(CapturingSpanExporter { spans: spans.clone() }, redactor);
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter)
            .build();
        let tracer = provider.tracer("log-redact-test");
        let mut span = tracer
            .span_builder("http.request")
            .with_attributes(attributes)
            .start(&tracer);
        span.add_event("upstream answered", vec![KeyValue::new("cookie", "sid=abc123")]);
        span.end();
        let exported = spans.lock().unwrap().pop();
        exported.expect("one span exported")
    }

    fn span_attribute(
        span: &SpanData,
        key: &str,
    ) -> Option<OtelValue> {
        span.attributes
            .iter()
            .find(|attribute| attribute.key.as_str() == key)
            .map(|attribute| attribute.value.clone())
    }

    #[test]
    fn test_span_exporter_redacts_attributes_by_credential_name() {
        let span = export_span(
            built_in_redactor(),
            vec![
                KeyValue::new("http.request.header.authorization", "Bearer opaque-upstream-key"),
                KeyValue::new("mcp_session_id", "4f1e2d3c-0000-4000-8000-123456789abc"),
                KeyValue::new("token", 42_i64),
                KeyValue::new("http.method", "POST"),
                KeyValue::new("gen_ai.usage.input_tokens", 1200_i64),
            ],
        );

        let redacted = OtelValue::String(loggable::REDACTED.into());
        assert_eq!(span_attribute(&span, "http.request.header.authorization"), Some(redacted.clone()));
        assert_eq!(span_attribute(&span, "mcp_session_id"), Some(redacted.clone()));
        assert_eq!(span_attribute(&span, "token"), Some(redacted.clone()));
        assert_eq!(span_attribute(&span, "http.method"), Some(OtelValue::from("POST")));
        assert_eq!(span_attribute(&span, "gen_ai.usage.input_tokens"), Some(OtelValue::I64(1200)));
        let event_cookie = span.events.events[0]
            .attributes
            .iter()
            .find(|attribute| attribute.key.as_str() == "cookie")
            .map(|attribute| attribute.value.clone());
        assert_eq!(event_cookie, Some(redacted));
    }

    #[test]
    fn test_span_exporter_applies_rules_to_other_string_attributes() {
        let span = export_span(
            built_in_redactor(),
            vec![KeyValue::new("http.request.headers", r#"{"x-api-key": "abc", "accept": "*/*"}"#)],
        );

        assert_eq!(
            span_attribute(&span, "http.request.headers"),
            Some(OtelValue::from(r#"{"x-api-key": "[REDACTED]", "accept": "*/*"}"#))
        );
    }

    #[test]
    fn test_span_exporter_keeps_operator_rules_and_name_redaction() {
        let redactor = LogRedactor::from_config(&make_config(vec![("Ticket ids", r"TCK-\d+", "[TICKET]")]));
        let span =
            export_span(redactor, vec![KeyValue::new("note", "see TCK-1234"), KeyValue::new("api_key", "sk-opaque")]);

        assert_eq!(span_attribute(&span, "note"), Some(OtelValue::from("see [TICKET]")));
        assert_eq!(span_attribute(&span, "api_key"), Some(OtelValue::String(loggable::REDACTED.into())));
    }

    #[test]
    fn test_span_exporter_leaves_spans_unchanged_when_disabled() {
        let redactor = LogRedactor::from_config(&LogRedactionConfig {
            enabled: false,
            rules: built_in_rules(),
        });
        let span = export_span(redactor, vec![KeyValue::new("authorization", "Bearer opaque-upstream-key")]);

        assert_eq!(span_attribute(&span, "authorization"), Some(OtelValue::from("Bearer opaque-upstream-key")));
    }

    // ── Log processor ───────────────────────────────────────────────

    #[derive(Debug, Clone, Default)]
    struct CapturingLogProcessor {
        records: Arc<std::sync::Mutex<Vec<SdkLogRecord>>>,
    }

    impl LogProcessor for CapturingLogProcessor {
        fn emit(
            &self,
            record: &mut SdkLogRecord,
            _scope: &InstrumentationScope,
        ) {
            self.records
                .lock()
                .unwrap()
                .push(record.clone());
        }

        fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult {
            Ok(())
        }
    }

    fn sample_record() -> SdkLogRecord {
        let mut record = RECORD_FACTORY.create_log_record();
        record.set_event_name("event src/proxy/handler.rs:42");
        record.set_target("agent_gateway::proxy::handler");
        record.set_timestamp(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000));
        record
            .set_observed_timestamp(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_001));
        record.set_trace_context(
            opentelemetry::trace::TraceId::from(7_u128),
            opentelemetry::trace::SpanId::from(9_u64),
            Some(opentelemetry::trace::TraceFlags::SAMPLED),
        );
        record.set_severity_text("INFO");
        record.set_severity_number(opentelemetry::logs::Severity::Info);
        record.set_body(AnyValue::from("forwarding with Authorization: Bearer sk-live-abc123".to_string()));
        record.add_attribute("detail", "api_key=sk-proj-example");
        record.add_attribute("session_id", "4f1e2d3c-0000-4000-8000-123456789abc");
        record.add_attribute("status", 200_i64);
        record
    }

    fn emit_through_redaction(
        redactor: Arc<LogRedactor>,
        mut record: SdkLogRecord,
    ) -> SdkLogRecord {
        let capturing = CapturingLogProcessor::default();
        let processor = RedactingLogProcessor::new(capturing.clone(), redactor);
        processor.emit(&mut record, &InstrumentationScope::builder("log-redact-test").build());
        let captured = capturing
            .records
            .lock()
            .unwrap()
            .pop();
        captured.expect("one record passed on")
    }

    fn record_attribute(
        record: &SdkLogRecord,
        key: &str,
    ) -> Option<AnyValue> {
        record
            .attributes_iter()
            .find(|(name, _)| name.as_str() == key)
            .map(|(_, value)| value.clone())
    }

    #[test]
    fn test_log_processor_redacts_body_and_attributes() {
        let exported = emit_through_redaction(built_in_redactor(), sample_record());

        let body = format!("{:?}", exported.body());
        assert!(!body.contains("sk-live-abc123"), "{body}");
        assert!(body.contains("Authorization: Bearer [REDACTED]"), "{body}");
        assert_eq!(record_attribute(&exported, "detail"), Some(AnyValue::from("api_key=[REDACTED]".to_string())));
        assert_eq!(record_attribute(&exported, "session_id"), Some(AnyValue::from(loggable::REDACTED.to_string())));
        assert_eq!(record_attribute(&exported, "status"), Some(AnyValue::Int(200)));
    }

    #[test]
    fn test_log_processor_keeps_every_other_record_field() {
        let original = sample_record();
        let exported = emit_through_redaction(built_in_redactor(), original.clone());

        assert_eq!(exported.event_name(), original.event_name());
        assert_eq!(exported.target(), original.target());
        assert_eq!(exported.timestamp(), original.timestamp());
        assert_eq!(exported.observed_timestamp(), original.observed_timestamp());
        assert_eq!(exported.trace_context(), original.trace_context());
        assert_eq!(exported.severity_text(), original.severity_text());
        assert_eq!(exported.severity_number(), original.severity_number());
    }

    #[test]
    fn test_with_attributes_copies_a_record_exactly() {
        let original = sample_record();
        let attributes = original
            .attributes_iter()
            .cloned()
            .collect();

        assert_eq!(with_attributes(&original, attributes), original);
    }

    #[test]
    fn test_log_processor_passes_records_unchanged_when_disabled() {
        let redactor = LogRedactor::from_config(&LogRedactionConfig {
            enabled: false,
            rules: built_in_rules(),
        });
        let original = sample_record();

        assert_eq!(emit_through_redaction(redactor, original.clone()), original);
    }
}
