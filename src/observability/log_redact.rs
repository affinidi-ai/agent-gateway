//! Configurable log redaction for all output destinations.
//!
//! Provides:
//! - `LogRedactor`         — compiled regex ruleset (built once, shared via `Arc`)
//! - `RedactingMakeWriter` — wraps any `MakeWriter` to redact formatted output
//! - `RedactingSpanExporter` — wraps an OTEL `SpanExporter` to redact span attributes

use crate::config::types::{LogRedactionConfig, LogRedactionRule};
use opentelemetry::Value as OtelValue;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::{SpanData, SpanExporter};
use regex::Regex;
use std::io::Write;
use std::sync::Arc;
use tracing_subscriber::fmt::MakeWriter;

// ── Compiled ruleset ────────────────────────────────────────────────

/// A single compiled rule: pre-compiled regex + replacement template.
struct CompiledRule {
    regex: Regex,
    replacement: String,
}

/// Thread-safe, immutable set of compiled redaction rules.
/// Built once at startup from [`LogRedactionConfig`] and shared via `Arc`.
pub struct LogRedactor {
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
        Arc::new(Self { rules })
    }

    fn compile_rule(rule: &LogRedactionRule) -> Option<CompiledRule> {
        // Build case-insensitive regex
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
    /// Returns the original string unchanged if there are no rules.
    #[inline]
    pub fn redact<'a>(
        &self,
        input: &'a str,
    ) -> std::borrow::Cow<'a, str> {
        if self.rules.is_empty() {
            return std::borrow::Cow::Borrowed(input);
        }
        let mut buf = String::from(input);
        for rule in &self.rules {
            // Avoid allocation when there is no match
            if rule.regex.is_match(&buf) {
                buf = rule
                    .regex
                    .replace_all(&buf, rule.replacement.as_str())
                    .into_owned();
            }
        }
        std::borrow::Cow::Owned(buf)
    }

    /// Returns true when redaction is effectively a no-op (no rules compiled).
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl std::fmt::Debug for LogRedactor {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("LogRedactor")
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

/// Wraps a [`SpanExporter`] and redacts string attributes on every exported span.
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

    /// Redact all string-valued attributes on a span (in-place).
    fn redact_span(
        &self,
        span: &mut SpanData,
    ) {
        if self.redactor.is_empty() {
            return;
        }
        // Redact span name
        let name_redacted = self
            .redactor
            .redact(span.name.as_ref());
        if let std::borrow::Cow::Owned(s) = name_redacted {
            span.name = s.into();
        }

        // Redact span attributes
        for kv in span.attributes.iter_mut() {
            if let OtelValue::String(ref s) = kv.value {
                let redacted = self
                    .redactor
                    .redact(s.as_str());
                if let std::borrow::Cow::Owned(new_val) = redacted {
                    kv.value = OtelValue::String(new_val.into());
                }
            }
        }

        // Redact event (log) messages attached to spans
        for event in span.events.events.iter_mut() {
            let event_name = self
                .redactor
                .redact(event.name.as_ref());
            if let std::borrow::Cow::Owned(s) = event_name {
                event.name = s.into();
            }
            for kv in event.attributes.iter_mut() {
                if let OtelValue::String(ref s) = kv.value {
                    let redacted = self
                        .redactor
                        .redact(s.as_str());
                    if let std::borrow::Cow::Owned(new_val) = redacted {
                        kv.value = OtelValue::String(new_val.into());
                    }
                }
            }
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
    fn test_no_rules_passthrough() {
        let cfg = LogRedactionConfig::default();
        let r = LogRedactor::from_config(&cfg);
        let input = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc";
        assert_eq!(r.redact(input).as_ref(), input);
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
        assert!(r.is_empty());
        assert_eq!(r.redact("keep me").as_ref(), "keep me");
    }

    #[test]
    fn test_invalid_regex_skipped() {
        let cfg = make_config(vec![
            ("bad", r"[invalid", "x"),         // invalid regex
            ("good", r"secret", "[REDACTED]"), // valid
        ]);
        let r = LogRedactor::from_config(&cfg);
        // Should have only 1 compiled rule (the valid one)
        assert!(!r.is_empty());
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

    /// Helper: build a redactor with ALL gateway.example.json rules.
    fn full_redactor() -> Arc<LogRedactor> {
        let cfg = make_config(vec![
            // 1. JWT tokens
            ("JWT tokens", r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED-JWT]"),
            // 2. Authorization header values
            (
                "Authorization header values",
                r#"(?i)((?:Authorization|Proxy-Authorization)["']?\s*[:=]\s*(?:Bearer|Basic|Digest|Token|ApiKey)\s+)\S+"#,
                "${1}[REDACTED]",
            ),
            // 3. Password fields
            ("Password fields", r#"(?i)(password|passwd|pwd)["']?\s*[:=]\s*["']?\S+"#, "${1}=[REDACTED]"),
            // 4. Access and refresh tokens
            (
                "Access and refresh tokens",
                r#"(?i)(access_token|refresh_token|token)["']?\s*[:=]\s*["']?[^\s"']+"#,
                "${1}=[REDACTED]",
            ),
            // 5. Session identifiers
            (
                "Session identifiers",
                r#"(?i)(session_id|sessionid|sid|jsessionid|connect\.sid)["']?\s*[:=]\s*["']?[A-Za-z0-9_\-\.]+"#,
                "${1}=[REDACTED-SESSION]",
            ),
            // 6. Private key material (PEM)
            (
                "Private key material (PEM)",
                r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
                "[REDACTED-PRIVATE-KEY]",
            ),
            // 7. Email addresses
            ("Email addresses", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[REDACTED-EMAIL]"),
            // 8. IPv4 addresses
            ("IPv4 addresses", r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[REDACTED-IP]"),
            // 9. IPv6 addresses (require 4+ groups or :: to avoid matching timestamps)
            (
                "IPv6 addresses",
                r"(?i)\b(?:[0-9a-f]{1,4}:){4,7}[0-9a-f]{1,4}\b|(?:[0-9a-f]{0,4}::(?:[0-9a-f]{1,4}:)*[0-9a-f]{0,4})|(?:[0-9a-f]{1,4}:)+:(?:[0-9a-f]{1,4}:)*[0-9a-f]{0,4}",
                "[REDACTED-IPv6]",
            ),
            // 10. Device identifiers
            (
                "Device identifiers",
                r#"(?i)(device_id|device-id|udid|idfa|gaid|android_id)["']?\s*[:=]\s*["']?[0-9a-f\-]{32,36}"#,
                "${1}=[REDACTED-DEVICE-ID]",
            ),
            // 11. DID identifiers
            ("DID identifiers", r"did:[a-z]+:[A-Za-z0-9._:%-]+", "did:redacted:***"),
            // 12. Ethereum addresses
            ("Ethereum addresses", r"0x[0-9a-fA-F]{40}", "[REDACTED-ETH]"),
            // 13. Public key values
            (
                "Public key values",
                r#"(?i)(public_key|publicKey|pub_key|pubkey)["']?\s*[:=]\s*["']?[A-Za-z0-9+/=_\-]{43,}"#,
                "${1}=[REDACTED-PUBKEY]",
            ),
            // 14. API key assignments
            ("API key assignments", r"(?i)(api[_-]?key|secret)[=:\s]+\S+", "${1}=[REDACTED]"),
            // 15. Credit card (structural)
            (
                "CREDIT / DEBIT CARD NO (structural)",
                r"\b(?:4[0-9]{12}(?:[0-9]{3,6})?|[25][1-7][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12,15}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b|\b(?:\d{4}[- .]){3}\d{4}(?:[- .]\d{1,4})?\b",
                "[REDACTED-CARD]",
            ),
            // 16. Credit card (keyword)
            (
                "CREDIT / DEBIT CARD NO (keyword)",
                r"(?i)(?:credit[ \t]*card|debit[ \t]*card|card[ \t]*(?:no\.?|num(?:ber)?|#?))[ \t:_=-]*\d{13,19}",
                "[REDACTED-CARD]",
            ),
            // 17. US SSN
            (
                "US SSN",
                r"\b(?:00[1-9]|0[1-9]\d|[1-5]\d{2}|6(?:[0-5]\d|6[0-57-9]|[7-9]\d)|[78]\d{2})-(?:0[1-9]|[1-9]\d)-(?:000[1-9]|00[1-9]\d|0[1-9]\d{2}|[1-9]\d{3})\b",
                "[REDACTED-US-SSN]",
            ),
            // 18. CN Resident ID Card
            (
                "CN RESIDENT ID CARD NUM",
                r"(([1-9]\d{5})(18|19|([23]\d))\d{2}((0[1-9])|10|11|12)([0-2][1-9]|10|20|30|31)(\d{3}[0-9Xx]))|(^[1-9]\d{5}\d{2}(0[1-9]|10|11|12)(([0-2][1-9])|10|20|30|31)\d{2})",
                "${2}[REDACTED-CN-RES-ID-NO]${8}",
            ),
            // 19. UK National Insurance Number
            (
                "UK INSURANCE NUM",
                r"(?i)\b(?:[ACEHJLMOPRSWXY][ABCEGHJ-NPRSTW-Z]|B[ABCEHJ-NPRSTW-Z]|G[ACEGHJ-NPRSTW-Z]|K[ABCEGHJ-MPRSTW-Z]|N[ABCEGHJ-MPRSW-Z]|T[ABCEGHJ-MPRSTW-Z]|Z[ABCEGHJ-NPRSTW-Y])\d{6}[ABCD]\b",
                "[REDACTED-UK-INS-NO]",
            ),
            // 20. National ID / Passport / User ID
            (
                "NATIONAL ID | PASSPORT NO | USER ID",
                r"(?i)(?:national\s*id|\bpassport\b|user\s*id)[\w\s]*[\s:_-]*([A-Z0-9\-]{8,30})",
                "[REDACTED-ID]",
            ),
            // 21. Physical address fields (structured key-value / JSON)
            (
                "Physical address fields",
                r#"(?i)(["']?(?:address|street|address_line_?[12]?|postal_code|zip_code|zipcode)["']?\s*[:=]\s*["']?)[^"'\n}]+"#,
                "${1}[REDACTED-ADDRESS]",
            ),
            // 22. Phone numbers (MUST be last among digit-based rules to avoid eating card/SSN/ID numbers)
            (
                "Phone numbers",
                r"(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{1,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{4,}",
                "[REDACTED-PHONE]",
            ),
        ]);
        LogRedactor::from_config(&cfg)
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
}
