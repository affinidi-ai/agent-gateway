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

/// Name of the OIDC binding cookie, holding the `state` of the sign-in this browser started. The
/// `__Host-` prefix stops a sibling subdomain from planting one.
pub(crate) const OIDC_STATE_COOKIE_NAME: &str = "__Host-oidc_state";

/// Cookie binding a browser to the OIDC sign-in it started, so a callback URL captured from one
/// browser cannot complete a sign-in in another (login CSRF). The provider sends the browser back
/// with a cross-site top-level `GET`, on which a `Lax` cookie is sent and a `Strict` one is not.
pub(crate) fn build_oidc_state_cookie(
    state: &str,
    max_age: u64,
) -> String {
    Cookie::build((OIDC_STATE_COOKIE_NAME, state))
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::seconds(max_age.min(i64::MAX as u64) as i64))
        .build()
        .encoded()
        .to_string()
}

/// Expire the OIDC binding cookie, with the attributes it was set with.
pub(crate) fn clear_oidc_state_cookie() -> String {
    let mut cookie = Cookie::build((OIDC_STATE_COOKIE_NAME, ""))
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .build();
    cookie.make_removal();
    cookie.encoded().to_string()
}

/// The value of the cookie `name` on a request: the first non-empty one, read verbatim (the
/// values these helpers set are URL-safe, so cookie encoding leaves them unchanged).
pub(crate) fn request_cookie<'a>(
    headers: &'a axum::http::HeaderMap,
    name: &str,
) -> Option<&'a str> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| {
            let (cookie_name, value) = pair.trim().split_once('=')?;
            let value = value.trim();
            (cookie_name == name && !value.is_empty()).then_some(value)
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
    use super::{
        OIDC_STATE_COOKIE_NAME, SESSION_COOKIE_NAME, build_oidc_state_cookie, build_session_cookie,
        clear_oidc_state_cookie, clear_session_cookie, request_cookie, session_cookie_value,
    };
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

    #[test]
    fn the_oidc_state_cookie_satisfies_host_prefix_rules_and_survives_the_return_trip() {
        let cookie = Cookie::parse(build_oidc_state_cookie("state-123", 600)).unwrap();

        assert_eq!(cookie.name(), OIDC_STATE_COOKIE_NAME);
        assert_eq!(cookie.value(), "state-123");
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.domain(), None);
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax), "sent on the provider's cross-site redirect back");
        assert_eq!(cookie.max_age(), Some(Duration::seconds(600)));

        let cleared = Cookie::parse(clear_oidc_state_cookie()).unwrap();
        assert_eq!(cleared.name(), OIDC_STATE_COOKIE_NAME);
        assert_eq!(cleared.value(), "");
        assert_eq!(cleared.path(), Some("/"));
        assert_eq!(cleared.secure(), Some(true));
        assert_eq!(cleared.same_site(), Some(SameSite::Lax));
        assert_eq!(cleared.max_age(), Some(Duration::ZERO));
    }

    #[test]
    fn a_named_cookie_is_read_from_any_cookie_header() {
        let mut headers = cookie_header("theme=dark; __Host-oidc_state=");
        headers.append(
            axum::http::header::COOKIE,
            "__Host-oidc_state=s-1; lang=en"
                .parse()
                .unwrap(),
        );

        assert_eq!(request_cookie(&headers, OIDC_STATE_COOKIE_NAME), Some("s-1"));
        assert_eq!(request_cookie(&headers, "theme"), Some("dark"));
        assert_eq!(request_cookie(&headers, "oidc_state"), None, "the name must match exactly");
        assert_eq!(request_cookie(&axum::http::HeaderMap::new(), OIDC_STATE_COOKIE_NAME), None);
    }
}
