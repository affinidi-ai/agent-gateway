//! Third-party-initiated login (OpenID Connect Core 1.0 section 4): the provider, or a page it
//! controls, sends the browser here to start a sign-in at that provider, optionally naming the
//! account and where the dashboard should open. Every request starts a fresh sign-in; nothing
//! here reads or changes a session.

use std::sync::Arc;

use axum::{
    Extension, Form,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use url::{Position, Url};

use super::handlers::{OidcState, Refusal, refused, start_sign_in, throttled};
use crate::auth::sign_in_pages::is_allowed_return_target;
use crate::source_auth::client_ip::ClientIp;

/// The longest `login_hint` passed on to the provider, in characters.
const MAX_LOGIN_HINT_CHARS: usize = 256;

/// The parameters of a third-party-initiated login, in the query (`GET`) or a form body (`POST`).
#[derive(Debug, Deserialize)]
pub struct InitiateParams {
    iss: Option<String>,
    login_hint: Option<String>,
    target_link_uri: Option<String>,
}

/// GET or POST /oidc/initiate. `Form` reads the query string of a `GET` and the body of a `POST`,
/// a form the provider's page submits cross-site, so the route is behind no same-origin check.
/// It spends the client's sign-in budget like `/oidc/login`.
pub async fn oidc_initiate(
    State(oidc): State<Arc<OidcState>>,
    client_ip: Option<Extension<ClientIp>>,
    Form(params): Form<InitiateParams>,
) -> Response {
    if let Some(throttled) = throttled(&oidc, client_ip.map(|Extension(ClientIp(ip))| ip)) {
        return throttled;
    }
    if params.iss.as_deref() != Some(oidc.config.issuer.as_str()) {
        return refused(Refusal::IssuerMismatch, None, "iss is missing or names another provider").into_response();
    }
    let login_hint = params
        .login_hint
        .as_deref()
        .filter(|hint| usable_login_hint(hint));
    let return_target = params
        .target_link_uri
        .as_deref()
        .and_then(|target| return_target(target, &oidc.config.redirect_uri))
        .unwrap_or_else(|| "/".to_string());
    start_sign_in(&oidc, login_hint, return_target).await
}

/// A `login_hint` is passed on only when it is short and plain text.
fn usable_login_hint(hint: &str) -> bool {
    !hint.is_empty()
        && hint.chars().count() <= MAX_LOGIN_HINT_CHARS
        && !hint
            .chars()
            .any(char::is_control)
}

/// The path and query of `target` when it is a safe place to open the dashboard: an absolute URL
/// on the dashboard's own origin (that of `redirect_uri`) without user information, holding no
/// backslash or control character, whose parsed path and query the return-target allowlist
/// admits. The backslash is refused before parsing, since parsing turns a backslash in an `https`
/// path into a slash. Anything else, a relative target included, gives `None`.
fn return_target(
    target: &str,
    redirect_uri: &Url,
) -> Option<String> {
    if target.contains('\\')
        || target
            .chars()
            .any(char::is_control)
    {
        return None;
    }
    let url = Url::parse(target).ok()?;
    if url.origin() != redirect_uri.origin() || !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    let path_and_query = &url[Position::BeforePath..Position::AfterQuery];
    is_allowed_return_target(path_and_query).then(|| path_and_query.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dashboard() -> Url {
        Url::parse("https://gateway.example.com/api/oidc/callback").unwrap()
    }

    const CLI_TARGET: &str = "/api/auth/cli/authorize?port=52111&state=st&challenge=ch";

    #[test]
    fn a_target_on_the_dashboards_origin_opens_its_allowed_path_and_query() {
        for (target, expected) in [
            ("https://gateway.example.com/", "/"),
            ("https://gateway.example.com", "/"),
            ("https://GATEWAY.example.com:443/access-tokens/new", "/access-tokens/new"),
            ("https://gateway.example.com/access-tokens/new?name=CI#top", "/access-tokens/new?name=CI"),
            (
                "https://gateway.example.com/access-tokens/new?resource_pattern=surfaces%2F%2A",
                "/access-tokens/new?resource_pattern=surfaces%2F%2A",
            ),
            (&format!("https://gateway.example.com{CLI_TARGET}"), CLI_TARGET),
        ] {
            assert_eq!(return_target(target, &dashboard()).as_deref(), Some(expected), "{target}");
        }
    }

    #[test]
    fn a_target_anywhere_else_or_outside_the_allowlist_is_ignored() {
        for target in [
            "https://evil.example/access-tokens/new",
            "http://gateway.example.com/access-tokens/new",
            "https://gateway.example.com:8443/access-tokens/new",
            "https://gateway.example.com.evil.example/",
            "https://user:pw@gateway.example.com/access-tokens/new",
            "https://:pw@gateway.example.com/access-tokens/new",
            "//evil.example/access-tokens/new",
            "/access-tokens/new",
            "access-tokens/new",
            "javascript:alert(1)",
            "data:text/html,hi",
            "not a url",
            "https://gateway.example.com/settings",
            "https://gateway.example.com/api/auth/cli/authorize",
        ] {
            assert_eq!(return_target(target, &dashboard()), None, "{target}");
        }
    }

    #[test]
    fn a_path_the_browser_could_read_as_another_host_is_ignored() {
        for target in [
            "https://gateway.example.com//evil.example/",
            "https://gateway.example.com/\\evil.example/",
            "https://gateway.example.com\\access-tokens\\new",
            "https://gateway.example.com/.//evil.example/",
            "https://gateway.example.com/%2e//evil.example/",
            "https://gateway.example.com/%2fevil.example/",
            "https://gateway.example.com/%5Cevil.example/",
            "https://gateway.example.com/access-tokens%2Fnew",
            "https://gateway.example.com/access-tokens/new?name=a\\b",
            "https://gateway.example.com/access-tokens/new?name=a\nb",
            "https://gateway.example.com/access-tokens/\tnew",
        ] {
            assert_eq!(return_target(target, &dashboard()), None, "{target:?}");
        }
    }

    #[test]
    fn a_target_whose_path_and_query_fit_in_1024_characters_is_kept_whole() {
        let at_limit = format!("/access-tokens/new?name={}", "a".repeat(1024 - "/access-tokens/new?name=".len()));
        assert_eq!(at_limit.len(), 1024);
        let over = format!("{at_limit}a");

        assert_eq!(
            return_target(&format!("https://gateway.example.com{at_limit}"), &dashboard()).as_deref(),
            Some(at_limit.as_str())
        );
        assert_eq!(return_target(&format!("https://gateway.example.com{over}"), &dashboard()), None);
    }

    #[test]
    fn only_a_short_plain_login_hint_is_passed_on() {
        assert!(usable_login_hint("alice@example.com"));
        assert!(usable_login_hint(&"é".repeat(MAX_LOGIN_HINT_CHARS)), "counted in characters, not bytes");
        assert!(!usable_login_hint(""));
        assert!(!usable_login_hint(&"a".repeat(MAX_LOGIN_HINT_CHARS + 1)));
        assert!(!usable_login_hint("alice\r\nX-Injected: 1"));
        assert!(!usable_login_hint("alice\u{7f}"));
    }
}
