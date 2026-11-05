use cookie::time::Duration;
use cookie::{Cookie, SameSite};

pub(crate) const SESSION_COOKIE_NAME: &str = "__Host-session_token";

pub(crate) fn build_session_cookie(
    session_token: &str,
    max_age: u64,
) -> String {
    Cookie::build((SESSION_COOKIE_NAME, session_token))
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Strict)
        .max_age(Duration::seconds(max_age.min(i64::MAX as u64) as i64))
        .build()
        .encoded()
        .to_string()
}

/// The session token in a request's `Cookie` header: the first non-empty
/// value of the session cookie.
pub(crate) fn session_cookie_value(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|cookie| {
            let (name, value) = cookie
                .trim()
                .split_once('=')?;
            let value = value.trim();
            (name == SESSION_COOKIE_NAME && !value.is_empty()).then_some(value)
        })
}

pub(crate) fn clear_session_cookie() -> String {
    let mut cookie = Cookie::build((SESSION_COOKIE_NAME, ""))
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Strict)
        .build();
    cookie.make_removal();
    cookie.encoded().to_string()
}

#[cfg(test)]
mod tests {
    use super::{SESSION_COOKIE_NAME, build_session_cookie, clear_session_cookie, session_cookie_value};
    use cookie::time::{Duration, OffsetDateTime};
    use cookie::{Cookie, SameSite};

    #[test]
    fn test_build_session_cookie_encodes_value_and_sets_attributes() {
        let cookie = build_session_cookie("abc 123?;", 1200);

        assert!(cookie.contains("abc%20123%3F%3B"));

        let parsed = Cookie::parse_encoded(cookie).expect("session cookie should parse");

        assert_eq!(parsed.name(), SESSION_COOKIE_NAME);
        assert_eq!(parsed.name(), "__Host-session_token");
        assert_eq!(parsed.value(), "abc 123?;");
        assert_eq!(parsed.path(), Some("/"));
        assert_eq!(parsed.secure(), Some(true));
        assert_eq!(parsed.domain(), None);
        assert_eq!(parsed.http_only(), Some(true));
        assert_eq!(parsed.same_site(), Some(SameSite::Strict));
        assert_eq!(parsed.max_age(), Some(Duration::seconds(1200)));
    }

    fn cookie_header(value: &str) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(axum::http::header::COOKIE, value.parse().unwrap());
        headers
    }

    #[test]
    fn the_session_token_is_read_from_among_other_cookies() {
        let headers = cookie_header("theme=dark; __Host-session_token= abc-123 ; lang=en");

        assert_eq!(session_cookie_value(&headers), Some("abc-123"));
    }

    #[test]
    fn an_empty_session_cookie_is_skipped_for_a_later_one() {
        let headers = cookie_header("__Host-session_token=; __Host-session_token=abc-123");

        assert_eq!(session_cookie_value(&headers), Some("abc-123"));
    }

    #[test]
    fn no_session_token_is_read_without_the_session_cookie() {
        for value in ["session_token=abc-123", "__Host-session_token=", "__Host-session_token", "theme=dark"] {
            assert_eq!(session_cookie_value(&cookie_header(value)), None, "{value}");
        }
        assert_eq!(session_cookie_value(&axum::http::HeaderMap::new()), None);
    }

    #[test]
    fn test_clear_session_cookie_expires_immediately() {
        let cookie = clear_session_cookie();

        let parsed = Cookie::parse(cookie).expect("clear cookie should parse");

        assert_eq!(parsed.name(), SESSION_COOKIE_NAME);
        assert_eq!(parsed.value(), "");
        assert_eq!(parsed.path(), Some("/"));
        assert_eq!(parsed.secure(), Some(true));
        assert_eq!(parsed.http_only(), Some(true));
        assert_eq!(parsed.same_site(), Some(cookie::SameSite::Strict));
        assert_eq!(parsed.max_age(), Some(Duration::ZERO));
        assert!(
            parsed
                .expires_datetime()
                .is_some_and(|expires| expires <= OffsetDateTime::now_utc())
        );
    }
}
