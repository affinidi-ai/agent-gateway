//! The consent binding cookie never leaves the gateway. Every request loses it
//! before a handler reads the headers, so no relay forwards it to an agent or a
//! target, and every response loses an `ag_consent` `Set-Cookie` the gateway did
//! not write, so no upstream can plant one in the person's browser.

use axum::{
    extract::Request,
    http::{HeaderMap, HeaderValue, header},
    middleware::Next,
    response::Response,
};

/// Whether `name` is a consent binding cookie's name, `ag_consent…` with or
/// without a `__Secure-` or `__Host-` prefix, in any case.
pub fn is_consent_cookie_name(name: &str) -> bool {
    let name = name
        .trim()
        .to_ascii_lowercase();
    name.strip_prefix("__host-")
        .or_else(|| name.strip_prefix("__secure-"))
        .unwrap_or(&name)
        .starts_with("ag_consent")
}

/// The consent cookies a request carried, as `(name, value)`, taken off its
/// headers by [`guard`] for the consent callback alone.
#[derive(Clone, Debug, Default)]
pub struct ConsentCookies(pub Vec<(String, String)>);

impl ConsentCookies {
    /// The value of the first cookie named exactly `name`.
    pub fn get(
        &self,
        name: &str,
    ) -> Option<&str> {
        self.0
            .iter()
            .find(|(cookie, _)| cookie == name)
            .map(|(_, value)| value.as_str())
    }
}

/// Marks a response whose consent `Set-Cookie` the gateway itself wrote.
#[derive(Clone, Copy, Debug)]
pub struct GatewayConsentCookie;

/// Takes the consent cookies off the request into [`ConsentCookies`], and
/// removes from the response every consent `Set-Cookie` the gateway did not
/// write.
pub async fn guard(
    mut request: Request,
    next: Next,
) -> Response {
    let cookies = take_consent_cookies(request.headers_mut());
    request
        .extensions_mut()
        .insert(ConsentCookies(cookies));
    let mut response = next.run(request).await;
    if response
        .extensions()
        .get::<GatewayConsentCookie>()
        .is_none()
    {
        strip_consent_set_cookies(response.headers_mut());
    }
    response
}

/// Removes the consent cookie pairs from `headers`' `Cookie` values, keeping
/// every other pair, and returns them.
pub fn take_consent_cookies(headers: &mut HeaderMap) -> Vec<(String, String)> {
    let mut taken = Vec::new();
    let mut kept = Vec::new();
    for value in headers.get_all(header::COOKIE) {
        let Ok(text) = value.to_str() else {
            kept.push(value.clone());
            continue;
        };
        let mut others = Vec::new();
        for pair in text
            .split(';')
            .map(str::trim)
            .filter(|pair| !pair.is_empty())
        {
            match pair.split_once('=') {
                Some((name, value)) if is_consent_cookie_name(name) => {
                    taken.push((name.trim().to_string(), value.trim().to_string()));
                }
                _ => others.push(pair),
            }
        }
        if !others.is_empty()
            && let Ok(value) = HeaderValue::from_str(&others.join("; "))
        {
            kept.push(value);
        }
    }
    if taken.is_empty() {
        return taken;
    }
    headers.remove(header::COOKIE);
    for value in kept {
        headers.append(header::COOKIE, value);
    }
    taken
}

/// Removes every `Set-Cookie` whose cookie is a consent cookie.
pub fn strip_consent_set_cookies(headers: &mut HeaderMap) {
    let consent = |value: &HeaderValue| {
        value
            .to_str()
            .ok()
            .and_then(|text| text.split_once('='))
            .is_some_and(|(name, _)| is_consent_cookie_name(name))
    };
    if !headers
        .get_all(header::SET_COOKIE)
        .iter()
        .any(consent)
    {
        return;
    }
    let kept: Vec<HeaderValue> = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter(|value| !consent(value))
        .cloned()
        .collect();
    headers.remove(header::SET_COOKIE);
    for value in kept {
        headers.append(header::SET_COOKIE, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, routing::get};
    use tower::ServiceExt;

    #[test]
    fn consent_cookie_names_are_recognised_with_any_prefix_or_case() {
        for name in
            ["ag_consent", "__Host-ag_consent_abc", "__Secure-ag_consent", "__host-AG_CONSENT_x", " ag_consent_1"]
        {
            assert!(is_consent_cookie_name(name), "{name}");
        }
        for name in ["session", "__Host-session", "consent", "xag_consent", "__Secure-ag_consen"] {
            assert!(!is_consent_cookie_name(name), "{name}");
        }
    }

    /// A relay behind the guard: what reached it, and an upstream answer that
    /// tries to set a consent cookie next to its own.
    #[tokio::test]
    async fn a_relayed_request_and_response_carry_no_consent_cookie() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = seen.clone();
        let app = Router::new()
            .route(
                "/relay",
                get(move |headers: HeaderMap| async move {
                    recorded
                        .lock()
                        .unwrap()
                        .push(headers);
                    let mut response = Response::new(Body::empty());
                    for value in [
                        "vendor_sid=1; Path=/",
                        "__Host-ag_consent_abc=planted; Path=/; Secure",
                        "ag_consent=planted",
                        "__Secure-ag_consent=planted; Path=/x",
                        "lb=node-2",
                    ] {
                        response
                            .headers_mut()
                            .append(header::SET_COOKIE, HeaderValue::from_static(value));
                    }
                    response
                }),
            )
            .layer(axum::middleware::from_fn(guard));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/relay")
                    .header("cookie", "a=1; __Host-ag_consent_abc=secret; b=2")
                    .header("cookie", "__Secure-ag_consent=old")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let set: Vec<_> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(set, ["vendor_sid=1; Path=/", "lb=node-2"]);
        let seen = seen.lock().unwrap();
        let cookies: Vec<_> = seen[0]
            .get_all(header::COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(cookies, ["a=1; b=2"]);
    }

    /// The gateway's own consent responses keep their cookie, and the callback
    /// reads the cookies the guard took.
    #[tokio::test]
    async fn the_gateways_own_consent_cookie_and_the_taken_cookies_reach_the_consent_routes() {
        let app = Router::new()
            .route(
                "/own",
                get(|axum::Extension(cookies): axum::Extension<ConsentCookies>| async move {
                    let mut response = Response::new(Body::from(
                        cookies
                            .get("__Host-ag_consent_abc")
                            .unwrap_or_default()
                            .to_string(),
                    ));
                    response
                        .headers_mut()
                        .append(header::SET_COOKIE, HeaderValue::from_static("__Host-ag_consent_new=v; Path=/"));
                    response
                        .extensions_mut()
                        .insert(GatewayConsentCookie);
                    response
                }),
            )
            .layer(axum::middleware::from_fn(guard));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/own")
                    .header("cookie", "__Host-ag_consent_abc=secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers()[header::SET_COOKIE], "__Host-ag_consent_new=v; Path=/");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body, "secret");
    }
}
