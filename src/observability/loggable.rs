//! Renders credentials, request URIs and endpoint URLs in a form that is safe to log.

use std::path::{Path, PathBuf};

use axum::http::Uri;

/// Placeholder logged in place of a value that must not appear in logs.
pub const REDACTED: &str = "<redacted>";

/// Characters of a secret that are logged: enough to correlate log lines, too few to use it.
const SECRET_PREFIX_CHARS: usize = 8;

/// Path segments followed by a capability id, such as an onboarding session id.
const CAPABILITY_PARENT_SEGMENTS: &[&str] = &["onboard", "delete-temp-channel"];

/// `value`, such as a session token, as it may appear in logs: its first characters, or
/// [`REDACTED`] when the value is too short for a prefix to leave most of it hidden.
pub fn secret(value: &str) -> String {
    if value.chars().count() < 2 * SECRET_PREFIX_CHARS {
        return REDACTED.to_string();
    }
    let prefix: String = value
        .chars()
        .take(SECRET_PREFIX_CHARS)
        .collect();
    format!("{prefix}...")
}

/// Path and query of `uri` with its capability ids shortened and every query value redacted.
pub fn uri(uri: &Uri) -> String {
    match uri.query() {
        Some(query) => format!("{}?{}", path(uri.path()), self::query(query)),
        None => path(uri.path()),
    }
}

/// Request `path` with each capability id, a UUID that follows an `onboard` or
/// `delete-temp-channel` segment, rendered as a [`secret`].
pub fn path(path: &str) -> String {
    let mut previous = "";
    path.split('/')
        .map(|segment| {
            let rendered = if CAPABILITY_PARENT_SEGMENTS.contains(&previous) && uuid::Uuid::parse_str(segment).is_ok() {
                secret(segment)
            } else {
                segment.to_string()
            };
            previous = segment;
            rendered
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// `query` with parameter names kept and every value redacted. A segment without `=`
/// can itself be a credential, so it is redacted whole.
pub fn query(query: &str) -> String {
    query
        .split('&')
        .map(|segment| match segment.split_once('=') {
            Some((name, _)) => format!("{name}={REDACTED}"),
            None if segment.is_empty() => String::new(),
            None => REDACTED.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// `url` without userinfo or fragment and with every query value redacted. An
/// unparseable URL is redacted whole.
pub fn url(url: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(url) else {
        return REDACTED.to_string();
    };
    if parsed.cannot_be_a_base() {
        return REDACTED.to_string();
    }
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_fragment(None);
    let redacted_query = parsed.query().map(query);
    parsed.set_query(None);
    match redacted_query {
        Some(redacted_query) => format!("{parsed}?{redacted_query}"),
        None => parsed.to_string(),
    }
}

/// Scheme, host and port of `url`, for endpoints whose path or query can carry a
/// provider API key. A URL without a host is redacted whole.
pub fn origin(url: &str) -> String {
    let Ok(parsed) = url::Url::parse(url) else {
        return REDACTED.to_string();
    };
    let Some(host) = parsed.host_str() else {
        return REDACTED.to_string();
    };
    match parsed.port() {
        Some(port) => format!("{}://{host}:{port}", parsed.scheme()),
        None => format!("{}://{host}", parsed.scheme()),
    }
}

/// `error`'s text with every rendering of `url` replaced by its [`origin`], for client
/// errors that quote the endpoint they failed to reach.
pub fn error_without_url(
    error: &impl std::fmt::Display,
    url: &str,
) -> String {
    let origin = origin(url);
    let normalized = url::Url::parse(url)
        .map(String::from)
        .unwrap_or_default();
    [url, normalized.as_str()]
        .into_iter()
        .filter(|rendering| !rendering.is_empty())
        .fold(error.to_string(), |text, rendering| text.replace(rendering, &origin))
}

/// The directory of a storage file whose name can be a credential, with the file name
/// replaced by [`REDACTED`].
pub fn record_path(path: &Path) -> PathBuf {
    path.parent()
        .unwrap_or_else(|| Path::new(""))
        .join(REDACTED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_keeps_prefix_of_long_value() {
        assert_eq!(secret("0f2c9d7e-1b3a-4c5d-8e9f-a0b1c2d3e4f5"), "0f2c9d7e...");
    }

    #[test]
    fn test_secret_redacts_short_value_whole() {
        assert_eq!(secret(""), REDACTED);
        assert_eq!(secret("abc"), REDACTED);
        assert_eq!(secret("123456789012345"), REDACTED);
        assert_eq!(secret("1234567890123456"), "12345678...");
    }

    #[test]
    fn test_secret_counts_characters_not_bytes() {
        assert_eq!(secret("ééééééééééééééééé"), "éééééééé...");
        assert_eq!(secret("éééééééééééééé"), REDACTED);
    }

    #[test]
    fn test_query_keeps_names_and_redacts_values() {
        assert_eq!(query("code=abc&state=xyz"), "code=<redacted>&state=<redacted>");
        assert_eq!(query("token=a=b"), "token=<redacted>");
        assert_eq!(query("access%5Ftoken=abc"), "access%5Ftoken=<redacted>");
        assert_eq!(query("empty="), "empty=<redacted>");
    }

    #[test]
    fn test_query_redacts_segment_without_name() {
        assert_eq!(query("abc123secret"), REDACTED);
        assert_eq!(query("a=1&&bare"), "a=<redacted>&&<redacted>");
        assert_eq!(query(""), "");
    }

    #[test]
    fn test_uri_redacts_query_values_only() {
        let with_query: Uri = "/v1/identity/oauth/callback/google?code=abc&state=xyz"
            .parse()
            .unwrap();
        assert_eq!(uri(&with_query), "/v1/identity/oauth/callback/google?code=<redacted>&state=<redacted>");

        let without_query: Uri = "/api/v1/health"
            .parse()
            .unwrap();
        assert_eq!(uri(&without_query), "/api/v1/health");
    }

    #[test]
    fn test_url_drops_userinfo_and_fragment_and_redacts_query() {
        assert_eq!(
            url("https://user:pass@api.example.com:8443/v1/models?key=sk-123&mode=x#frag"),
            "https://api.example.com:8443/v1/models?key=<redacted>&mode=<redacted>"
        );
        assert_eq!(url("https://api.example.com/v1/models"), "https://api.example.com/v1/models");
    }

    #[test]
    fn test_url_redacts_unparseable_value_whole() {
        assert_eq!(url("not a url ?key=sk-123"), REDACTED);
    }

    #[test]
    fn test_url_redacts_value_without_authority_whole() {
        assert_eq!(url("user:pass@agent.example.com/a2a"), REDACTED);
        assert_eq!(url("mailto:ops@example.com"), REDACTED);
    }

    #[test]
    fn test_path_shortens_capability_ids_only() {
        assert_eq!(path("/onboard/0f2c9d7e-1b3a-4c5d-8e9f-a0b1c2d3e4f5/rpc"), "/onboard/0f2c9d7e.../rpc");
        assert_eq!(
            path("/api/v1/onboard/delete-temp-channel/0f2c9d7e-1b3a-4c5d-8e9f-a0b1c2d3e4f5"),
            "/api/v1/onboard/delete-temp-channel/0f2c9d7e..."
        );
        assert_eq!(path("/v1/onboard/create-temp-surface"), "/v1/onboard/create-temp-surface");
        assert_eq!(
            path("/v1/surfaces/0f2c9d7e-1b3a-4c5d-8e9f-a0b1c2d3e4f5"),
            "/v1/surfaces/0f2c9d7e-1b3a-4c5d-8e9f-a0b1c2d3e4f5"
        );
    }

    #[test]
    fn test_uri_shortens_capability_ids_in_the_path() {
        let onboarding: Uri = "/onboard/0f2c9d7e-1b3a-4c5d-8e9f-a0b1c2d3e4f5/rpc?code=abc"
            .parse()
            .unwrap();
        assert_eq!(uri(&onboarding), "/onboard/0f2c9d7e.../rpc?code=<redacted>");
    }

    #[test]
    fn test_error_without_url_keeps_only_the_origin() {
        let error = "error sending request for url (https://rpc.example.com/v2/provider-key/)";
        assert_eq!(
            error_without_url(&error, "https://rpc.example.com/v2/provider-key"),
            "error sending request for url (https://rpc.example.com/)"
        );
        assert_eq!(
            error_without_url(&"error for url (https://host.example/key)", "https://HOST.example/key"),
            "error for url (https://host.example)"
        );
        assert_eq!(error_without_url(&"connection refused", "https://rpc.example.com/v2/key"), "connection refused");
    }

    #[test]
    fn test_record_path_keeps_only_the_directory() {
        assert_eq!(
            record_path(Path::new("sessions/0f2c9d7e-1b3a-4c5d-8e9f-a0b1c2d3e4f5.json.enc")),
            Path::new("sessions").join(REDACTED)
        );
    }

    #[test]
    fn test_origin_keeps_scheme_host_and_port_only() {
        assert_eq!(origin("https://eth-mainnet.example.com/v2/provider-key"), "https://eth-mainnet.example.com");
        assert_eq!(origin("http://localhost:8545/?apikey=abc"), "http://localhost:8545");
    }

    #[test]
    fn test_origin_redacts_url_without_host() {
        assert_eq!(origin("not a url"), REDACTED);
        assert_eq!(origin("mailto:ops@example.com"), REDACTED);
    }
}
