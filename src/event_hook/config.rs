use std::time::Duration;

use tracing::{error, warn};

use crate::config::loaders::{environment::optional_env, load};

pub const ENV_HOOK_URL: &str = "AG_EVENT_HOOK_URL";
pub const ENV_HOOK_TIMEOUT_MS: &str = "AG_EVENT_HOOK_TIMEOUT_MS";
pub const ENV_HOOK_SECRET: &str = "AG_EVENT_HOOK_SECRET";

const MIN_SECRET_CHARS: usize = 32;

const DEFAULT_HOOK_TIMEOUT_MS: u64 = 5_000;

/// HMAC key for signing hook requests. Never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct HookSecret(String);

impl HookSecret {
    pub fn new(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        (trimmed.chars().count() >= MIN_SECRET_CHARS).then(|| Self(trimmed.to_string()))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for HookSecret {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.write_str("HookSecret(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EventHookSettings {
    pub hook_url: Option<String>,
    pub hook_timeout: Duration,
    pub hook_secret: Option<HookSecret>,
}

impl Default for EventHookSettings {
    fn default() -> Self {
        Self {
            hook_url: None,
            hook_timeout: Duration::from_millis(DEFAULT_HOOK_TIMEOUT_MS),
            hook_secret: None,
        }
    }
}

fn is_http_url(raw: &str) -> bool {
    url::Url::parse(raw).is_ok_and(|parsed| matches!(parsed.scheme(), "http" | "https") && parsed.host_str().is_some())
}

impl EventHookSettings {
    pub async fn from_env() -> Self {
        let secret = match optional_env(ENV_HOOK_SECRET) {
            None => None,
            Some(reference) => Some(
                load(&reference)
                    .await
                    .map_err(|e| e.to_string()),
            ),
        };
        Self::from_resolved(
            |name| match name {
                ENV_HOOK_SECRET => None,
                _ => std::env::var(name).ok(),
            },
            secret,
        )
    }

    #[cfg(test)]
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let secret = lookup(ENV_HOOK_SECRET).map(Ok);
        Self::from_resolved(lookup, secret)
    }

    fn from_resolved(
        lookup: impl Fn(&str) -> Option<String>,
        secret: Option<Result<String, String>>,
    ) -> Self {
        let text = |name: &str| {
            lookup(name)
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        };
        let timeout_ms = match text(ENV_HOOK_TIMEOUT_MS) {
            None => DEFAULT_HOOK_TIMEOUT_MS,
            Some(raw) => match raw.parse::<u64>() {
                Ok(value) if value > 0 => value,
                _ => {
                    warn!("{ENV_HOOK_TIMEOUT_MS}={raw:?} is not a positive integer; using {DEFAULT_HOOK_TIMEOUT_MS}");
                    DEFAULT_HOOK_TIMEOUT_MS
                }
            },
        };
        let mut hook_url = text(ENV_HOOK_URL);
        if let Some(raw) = hook_url.as_deref()
            && !is_http_url(raw)
        {
            error!("{ENV_HOOK_URL} must be an http or https URL with a host; the event hook is disabled");
            hook_url = None;
        }
        let hook_secret = match secret.filter(|_| hook_url.is_some()) {
            None => None,
            Some(Err(reason)) => {
                error!("{ENV_HOOK_SECRET} could not be loaded ({reason}); the event hook is disabled");
                hook_url = None;
                None
            }
            Some(Ok(raw)) => match HookSecret::new(&raw) {
                Some(secret) => Some(secret),
                None => {
                    error!(
                        "{ENV_HOOK_SECRET} must be at least {MIN_SECRET_CHARS} characters; the event hook is disabled"
                    );
                    hook_url = None;
                    None
                }
            },
        };
        Self {
            hook_url,
            hook_timeout: Duration::from_millis(timeout_ms),
            hook_secret,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn settings(pairs: &[(&str, &str)]) -> EventHookSettings {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        EventHookSettings::from_lookup(|name| map.get(name).cloned())
    }

    #[test]
    fn no_env_means_disabled_with_defaults() {
        let parsed = settings(&[]);
        assert_eq!(parsed, EventHookSettings::default());
        assert!(parsed.hook_url.is_none());
        assert_eq!(parsed.hook_timeout, Duration::from_secs(5));
    }

    #[test]
    fn reads_every_variable() {
        let parsed = settings(&[(ENV_HOOK_URL, " http://127.0.0.1:8085/hooks/events "), (ENV_HOOK_TIMEOUT_MS, "1000")]);
        assert_eq!(parsed.hook_url.as_deref(), Some("http://127.0.0.1:8085/hooks/events"));
        assert_eq!(parsed.hook_timeout, Duration::from_millis(1000));
    }

    #[test]
    fn invalid_values_fall_back_to_safe_defaults() {
        let parsed = settings(&[(ENV_HOOK_URL, "   "), (ENV_HOOK_TIMEOUT_MS, "-5")]);
        assert_eq!(parsed.hook_url, None);
        assert_eq!(parsed.hook_timeout, Duration::from_secs(5));
    }

    #[test]
    fn only_http_and_https_urls_with_a_host_are_accepted() {
        for valid in ["http://127.0.0.1:8085/h", "https://hooks.example.com/events"] {
            assert_eq!(
                settings(&[(ENV_HOOK_URL, valid)])
                    .hook_url
                    .as_deref(),
                Some(valid)
            );
        }
        for invalid in [
            "hooks.example.com/events",
            "localhost:8085/h",
            "http://",
            "http://:8080/h",
            "ftp://hooks.example.com/h",
            "not a url",
        ] {
            assert!(
                settings(&[(ENV_HOOK_URL, invalid)])
                    .hook_url
                    .is_none(),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn a_valid_secret_is_trimmed_and_kept() {
        let parsed = settings(&[(ENV_HOOK_URL, "http://127.0.0.1:1/h"), (ENV_HOOK_SECRET, &format!("  {SECRET}\n"))]);
        assert_eq!(
            parsed
                .hook_secret
                .as_ref()
                .map(HookSecret::expose),
            Some(SECRET)
        );
        assert!(parsed.hook_url.is_some());
    }

    #[test]
    fn no_secret_leaves_the_hook_enabled_and_unsigned() {
        let parsed = settings(&[(ENV_HOOK_URL, "http://127.0.0.1:1/h")]);
        assert!(parsed.hook_secret.is_none());
        assert!(parsed.hook_url.is_some());
    }

    #[test]
    fn a_short_or_blank_secret_disables_the_hook() {
        for raw in ["", "   ", "too-short", &format!(" {} ", &SECRET[..31])] {
            let parsed = settings(&[(ENV_HOOK_URL, "http://127.0.0.1:1/h"), (ENV_HOOK_SECRET, raw)]);
            assert!(parsed.hook_url.is_none(), "{raw:?}");
            assert!(parsed.hook_secret.is_none(), "{raw:?}");
        }
    }

    #[test]
    fn the_secret_never_appears_in_debug_output() {
        let parsed = settings(&[(ENV_HOOK_URL, "http://127.0.0.1:1/h"), (ENV_HOOK_SECRET, SECRET)]);
        let debug = format!("{parsed:?} {:?}", parsed.hook_secret);
        assert!(!debug.contains(SECRET), "{debug}");
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn a_secret_that_could_not_be_loaded_disables_the_hook() {
        let parsed = EventHookSettings::from_resolved(
            |name| (name == ENV_HOOK_URL).then(|| "http://127.0.0.1:1/h".to_string()),
            Some(Err("aws_secrets://x failed".to_string())),
        );
        assert!(parsed.hook_url.is_none());
        assert!(parsed.hook_secret.is_none());
    }

    #[test]
    fn a_loaded_secret_is_validated_like_a_plain_one() {
        let url = |name: &str| (name == ENV_HOOK_URL).then(|| "http://127.0.0.1:1/h".to_string());
        let good = EventHookSettings::from_resolved(url, Some(Ok(SECRET.to_string())));
        assert!(good.hook_url.is_some());
        assert!(good.hook_secret.is_some());
        let short = EventHookSettings::from_resolved(url, Some(Ok("short".to_string())));
        assert!(short.hook_url.is_none());
    }

    #[test]
    fn the_load_failure_and_the_short_secret_log_one_distinct_error_each() {
        let logs = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        #[derive(Clone)]
        struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(
                &mut self,
                buf: &[u8],
            ) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .unwrap()
                    .extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
            type Writer = Sink;

            fn make_writer(&'a self) -> Sink {
                self.clone()
            }
        }
        let subscriber = tracing_subscriber::fmt()
            .with_writer(Sink(logs.clone()))
            .with_ansi(false)
            .finish();
        let url = |name: &str| (name == ENV_HOOK_URL).then(|| "http://127.0.0.1:1/h".to_string());
        let read = || String::from_utf8(logs.lock().unwrap().clone()).unwrap();
        tracing::subscriber::with_default(subscriber, || {
            EventHookSettings::from_resolved(url, Some(Err("boom".to_string())));
            let failed = read();
            assert_eq!(
                failed
                    .matches("ERROR")
                    .count(),
                1,
                "{failed}"
            );
            assert!(failed.contains("could not be loaded (boom)"), "{failed}");
            assert!(!failed.contains("at least"), "{failed}");
            logs.lock().unwrap().clear();
            EventHookSettings::from_resolved(url, Some(Ok("short".to_string())));
            let short = read();
            assert_eq!(short.matches("ERROR").count(), 1, "{short}");
            assert!(short.contains("at least 32 characters"), "{short}");
            assert!(!short.contains("could not be loaded"), "{short}");
        });
    }
}
