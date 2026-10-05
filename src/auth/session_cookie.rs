use cookie::time::Duration;
use cookie::{Cookie, SameSite};

pub(crate) const SESSION_COOKIE_NAME: &str = "session_token";

pub(crate) fn build_session_cookie(
    session_token: &str,
    max_age: u64,
) -> String {
    Cookie::build((SESSION_COOKIE_NAME, session_token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .max_age(Duration::seconds(max_age.min(i64::MAX as u64) as i64))
        .build()
        .encoded()
        .to_string()
}

pub(crate) fn clear_session_cookie() -> String {
    let mut cookie = Cookie::build((SESSION_COOKIE_NAME, ""))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .build();
    cookie.make_removal();
    cookie.encoded().to_string()
}

#[cfg(test)]
mod tests {
    use super::{SESSION_COOKIE_NAME, build_session_cookie, clear_session_cookie};
    use cookie::time::{Duration, OffsetDateTime};
    use cookie::{Cookie, SameSite};

    #[test]
    fn test_build_session_cookie_encodes_value_and_sets_attributes() {
        let cookie = build_session_cookie("abc 123?;", 1200);

        assert!(cookie.contains("abc%20123%3F%3B"));

        let parsed = Cookie::parse_encoded(cookie).expect("session cookie should parse");

        assert_eq!(parsed.name(), SESSION_COOKIE_NAME);
        assert_eq!(parsed.value(), "abc 123?;");
        assert_eq!(parsed.path(), Some("/"));
        assert_eq!(parsed.http_only(), Some(true));
        assert_eq!(parsed.same_site(), Some(SameSite::Strict));
        assert_eq!(parsed.max_age(), Some(Duration::seconds(1200)));
    }

    #[test]
    fn test_clear_session_cookie_expires_immediately() {
        let cookie = clear_session_cookie();

        let parsed = Cookie::parse(cookie).expect("clear cookie should parse");

        assert_eq!(parsed.name(), SESSION_COOKIE_NAME);
        assert_eq!(parsed.value(), "");
        assert_eq!(parsed.path(), Some("/"));
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
