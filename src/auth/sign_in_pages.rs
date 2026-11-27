//! What a browser sign-in through an identity provider (SAML or OpenID Connect) answers with:
//! the hand-off page that stores the new session for the dashboard and navigates on, the readable
//! error and throttle pages, and the allowlist of where a signed-in browser may be sent.

use axum::{
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use tracing::error;

use crate::auth::cli_login::CLI_AUTHORIZE_PATH;

/// The dashboard's new access token form. Its query only presets the form, which the signed-in
/// user still has to submit.
pub(crate) const ACCESS_TOKEN_NEW_PATH: &str = "/access-tokens/new";

/// Only the dashboard root, the new access token form (with or without its preset query) and the
/// CLI authorize path (with its query) may be a return target. Anything else, including
/// off-origin and protocol-relative targets, an encoded slash or backslash in the path, and
/// characters that could break out of the hand-off markup, is rejected. The query may carry an
/// encoded slash or backslash, since the CLI `state` is opaque.
pub(crate) fn is_allowed_return_target(target: &str) -> bool {
    let path = target
        .split_once('?')
        .map_or(target, |(path, _)| path)
        .to_ascii_lowercase();
    if path.contains("%2f") || path.contains("%5c") {
        return false;
    }
    let charset_ok = target.len() <= 1024
        && target.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'-' | b'_' | b'.' | b'/' | b'?' | b'&' | b'=' | b'%' | b'~' | b':' | b'+')
        });
    if !charset_ok {
        return false;
    }
    match target.split_once('?') {
        None => target == "/" || target == ACCESS_TOKEN_NEW_PATH,
        Some((path, query)) => (path == CLI_AUTHORIZE_PATH && !query.is_empty()) || path == ACCESS_TOKEN_NEW_PATH,
    }
}

/// A self-contained HTML page for a failed sign-in, so the user sees why (for example that the
/// appliance user limit was reached) instead of a blank status page.
pub(crate) fn sign_in_error_page(
    status: StatusCode,
    title: &str,
    message: &str,
) -> Response {
    let escape = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head><title>{title}</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 40rem; margin: 4rem auto; padding: 0 1rem;">
    <h1>{title}</h1>
    <p>{message}</p>
    <p><a href="/login">Return to sign in</a></p>
</body>
</html>"#,
        title = escape(title),
        message = escape(message),
    );
    (status, Html(html)).into_response()
}

/// The `429` page for a client over its sign-in limit, with `Retry-After`.
pub(crate) fn throttled_sign_in_page(retry_after: u64) -> Response {
    let mut response = sign_in_error_page(
        StatusCode::TOO_MANY_REQUESTS,
        "Too many sign-in attempts",
        &format!("Please try again in {retry_after} seconds."),
    );
    let headers = response.headers_mut();
    headers.insert(header::RETRY_AFTER, HeaderValue::from(retry_after));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn js_string_literal(value: &str) -> String {
    serde_json::Value::String(value.to_owned())
        .to_string()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

fn script_nonce() -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>())
}

fn content_security_policy(nonce: &str) -> String {
    format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
}

fn success_html(
    redirect_target: &str,
    session_token: &str,
    nonce: &str,
) -> String {
    let redirect_target_js = js_string_literal(redirect_target);
    let session_token_js = js_string_literal(session_token);
    let redirect_target_attr = redirect_target
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Login Successful</title>
    <meta http-equiv="refresh" content="0;url={redirect_target_attr}">
    <script nonce="{nonce}">
        sessionStorage.setItem('session_token', {session_token_js});
        window.location.href = {redirect_target_js};
    </script>
</head>
<body>
    <p>Login successful. Redirecting...</p>
</body>
</html>"#
    )
}

/// The hand-off page that completes a sign-in: the session's `headers` (its cookie), and a page
/// whose one nonced script stores `session_token` for the dashboard and navigates to
/// `redirect_target`. It is a page rather than a redirect because the session cookie is
/// `SameSite=Strict`, so a redirect chained from the identity provider's cross-site navigation
/// would load the dashboard without it.
pub(crate) fn sign_in_success_response(
    mut headers: HeaderMap,
    redirect_target: &str,
    session_token: &str,
) -> Result<Response, StatusCode> {
    let nonce = script_nonce();
    let html = success_html(redirect_target, session_token, &nonce);
    let policy = HeaderValue::from_str(&content_security_policy(&nonce)).map_err(|e| {
        error!("Failed to build the sign-in hand-off page Content-Security-Policy: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    headers.insert(header::CONTENT_SECURITY_POLICY, policy);
    Ok((headers, Html(html)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLI_TARGET: &str = "/api/auth/cli/authorize?port=52111&state=st&challenge=ch";

    #[test]
    fn return_target_accepts_the_dashboard_root_and_cli_authorize() {
        assert!(is_allowed_return_target("/"));
        assert!(is_allowed_return_target(CLI_TARGET));
        assert!(is_allowed_return_target("/api/auth/cli/authorize?port=52111&state=a%20b&challenge=ch"));
    }

    #[test]
    fn return_target_accepts_the_new_access_token_form_with_its_preset_query() {
        assert!(is_allowed_return_target("/access-tokens/new"));
        assert!(is_allowed_return_target(
            "/access-tokens/new?name=CI&scopes=gateways.view%2Csecrets.view&expires_at=2026-12-31T00%3A00%3A00.000Z"
        ));
        assert!(is_allowed_return_target(
            "/access-tokens/new?resource_pattern=TENANT%3A%24%7Baccount%7D%3Agateways%3A.%2A&header=account%3Atenant-a"
        ));
    }

    #[test]
    fn return_target_rejects_other_access_token_paths() {
        assert!(!is_allowed_return_target("/access-tokens/new/extra?name=x"));
        assert!(!is_allowed_return_target("/access-tokens/agpat_1?name=x"));
        assert!(!is_allowed_return_target("/access-tokens/new%2f..%2fsettings?x=1"));
        assert!(!is_allowed_return_target("//access-tokens/new?name=x"));
        assert!(!is_allowed_return_target("/access-tokens/new?name=a\"<script>"));
    }

    #[test]
    fn return_target_rejects_paths_outside_the_allow_list() {
        assert!(!is_allowed_return_target("/settings"));
        assert!(!is_allowed_return_target("/api/auth/cli/authorize"));
        assert!(!is_allowed_return_target("/api/auth/cli/authorize?"));
        assert!(!is_allowed_return_target("/api/auth/cli/authorize/extra?port=1"));
        assert!(!is_allowed_return_target("/?port=52111"));
        assert!(!is_allowed_return_target("/api/v1/secrets?x=1"));
    }

    #[test]
    fn return_target_rejects_off_origin_targets() {
        assert!(!is_allowed_return_target("//evil.example"));
        assert!(!is_allowed_return_target("https://evil.example"));
        assert!(!is_allowed_return_target("/\\evil.example"));
        assert!(!is_allowed_return_target("/%2fevil.example"));
        assert!(!is_allowed_return_target("/%5Cevil.example"));
        assert!(!is_allowed_return_target("evil.example"));
    }

    #[test]
    fn return_target_accepts_an_encoded_slash_or_backslash_in_the_cli_state() {
        let target = format!("/api/auth/cli/authorize?port=52111&state={}&challenge=ch", urlencoding::encode("a/b\\c"));
        assert_eq!(target, "/api/auth/cli/authorize?port=52111&state=a%2Fb%5Cc&challenge=ch");

        assert!(is_allowed_return_target(&target));
    }

    #[test]
    fn return_target_rejects_traversal_in_the_path_even_with_a_query() {
        assert!(!is_allowed_return_target("/api/auth/cli/authorize%2f?port=1"));
        assert!(!is_allowed_return_target("/api/auth/cli%2Fauthorize?port=1"));
        assert!(!is_allowed_return_target("/api/auth/cli%5cauthorize?port=1"));
        assert!(!is_allowed_return_target("/api/auth/cli\\authorize?port=1"));
        assert!(!is_allowed_return_target("/api/auth/../auth/cli/authorize?port=1"));
        assert!(!is_allowed_return_target("/api/auth/%2e%2e/cli/authorize?port=1"));
        assert!(!is_allowed_return_target("//api/auth/cli/authorize?port=1"));
        assert!(!is_allowed_return_target("/%2f/api/auth/cli/authorize?port=1"));
    }

    #[test]
    fn return_target_rejects_markup_and_control_characters() {
        assert!(!is_allowed_return_target("/a\"</script><script>alert(1)"));
        assert!(!is_allowed_return_target("/a'b"));
        assert!(!is_allowed_return_target("/a b"));
        assert!(!is_allowed_return_target("/api/auth/cli/authorize?port=1<"));
        assert!(!is_allowed_return_target("/api/auth/cli/authorize?port=1>"));
        assert!(!is_allowed_return_target("/api/auth/cli/authorize?port=1\n"));
        assert!(!is_allowed_return_target("/api/auth/cli/authorize?port=1\u{7f}"));
    }

    #[test]
    fn success_html_redirects_to_the_target_in_markup_and_script() {
        let html = success_html(CLI_TARGET, "tok-1", "n0nce");

        assert!(html.contains("content=\"0;url=/api/auth/cli/authorize?port=52111&amp;state=st&amp;challenge=ch\""));
        assert!(html.contains(
            "window.location.href = \"/api/auth/cli/authorize?port=52111\\u0026state=st\\u0026challenge=ch\";"
        ));
        assert!(html.contains("sessionStorage.setItem('session_token', \"tok-1\");"));
        assert!(html.contains("<script nonce=\"n0nce\">"));
    }

    #[test]
    fn success_html_encodes_a_hostile_token_as_a_script_safe_string_literal() {
        let html = success_html("/", "a'\"\\</script><script>x()</script>&\u{2028}", "n");

        assert!(!html.contains("</script><script>x()"));
        assert!(html.contains(
            "sessionStorage.setItem('session_token', \"a'\\\"\\\\\\u003c/script\\u003e\\u003cscript\\u003ex()\\u003c/script\\u003e\\u0026\\u2028\");"
        ));
        assert_eq!(
            html.matches("</script>")
                .count(),
            1
        );
    }

    #[test]
    fn success_html_encodes_a_hostile_target_as_a_script_safe_string_literal() {
        let html = success_html("/a\"</script><script>x()</script>&\u{2029}", "tok-1", "n");

        assert!(!html.contains("</script><script>x()"));
        assert!(html.contains(
            "window.location.href = \"/a\\\"\\u003c/script\\u003e\\u003cscript\\u003ex()\\u003c/script\\u003e\\u0026\\u2029\";"
        ));
        assert_eq!(
            html.matches("</script>")
                .count(),
            1
        );
    }

    #[test]
    fn content_security_policy_allows_only_the_nonced_script() {
        let policy = content_security_policy("abc");

        assert!(policy.contains("script-src 'nonce-abc'"));
        assert!(policy.contains("default-src 'none'"));
        assert!(policy.contains("frame-ancestors 'none'"));
        assert!(!policy.contains("unsafe-inline"));
    }

    #[tokio::test]
    async fn success_response_pairs_the_policy_nonce_with_the_script_nonce() {
        let mut session_headers = HeaderMap::new();
        session_headers.insert(header::SET_COOKIE, "session=abc".parse().unwrap());
        let response = sign_in_success_response(session_headers, "/", "tok-1").unwrap();
        assert_eq!(
            response
                .headers()
                .get(header::SET_COOKIE)
                .unwrap(),
            "session=abc"
        );
        let policy = response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        let nonce = policy
            .split("'nonce-")
            .nth(1)
            .and_then(|rest| rest.split('\'').next())
            .unwrap();

        assert!(html.contains(&format!("<script nonce=\"{nonce}\">")));
    }

    #[test]
    fn script_nonces_are_unique_and_url_safe() {
        let (a, b) = (script_nonce(), script_nonce());

        assert_ne!(a, b);
        assert_eq!(a.len(), 22);
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn success_html_escapes_a_hostile_target_in_the_meta_refresh() {
        let html = success_html("/a\"><script>x</script>", "tok-1", "n");

        assert!(html.contains("content=\"0;url=/a&quot;&gt;&lt;script&gt;x&lt;/script&gt;\""));
    }

    #[tokio::test]
    async fn the_error_page_escapes_its_text_and_keeps_its_status() {
        let response = sign_in_error_page(StatusCode::FORBIDDEN, "No <access>", "a & b");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("<h1>No &lt;access&gt;</h1>"), "{html}");
        assert!(html.contains("<p>a &amp; b</p>"), "{html}");
    }

    #[test]
    fn the_throttled_page_says_when_to_retry_and_is_not_cached() {
        let response = throttled_sign_in_page(42);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .unwrap(),
            "42"
        );
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .unwrap(),
            "no-store"
        );
    }
}
