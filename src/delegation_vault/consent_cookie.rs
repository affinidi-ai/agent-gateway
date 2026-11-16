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

/// Whether `name`, raw header bytes, is a consent binding cookie's name:
/// `ag_consent…` with or without a `__Secure-` or `__Host-` prefix, in any
/// ASCII case. Bytes, not text, so a byte outside visible ASCII anywhere in a
/// header never hides a consent cookie.
fn is_consent_name(name: &[u8]) -> bool {
    let name = name.trim_ascii();
    let starts_with = |bytes: &[u8], prefix: &[u8]| {
        bytes
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    };
    let bare = [&b"__host-"[..], b"__secure-"]
        .into_iter()
        .find(|prefix| starts_with(name, prefix))
        .map_or(name, |prefix| &name[prefix.len()..]);
    starts_with(bare, b"ag_consent")
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

/// Removes the consent cookie pairs from `headers`' `Cookie` values, judged by
/// their bytes, and returns them; every other pair is kept byte for byte, and a
/// `Cookie` header left with none is dropped.
pub fn take_consent_cookies(headers: &mut HeaderMap) -> Vec<(String, String)> {
    let mut taken = Vec::new();
    let mut kept = Vec::new();
    let mut changed = false;
    for value in headers.get_all(header::COOKIE) {
        let mut others: Vec<&[u8]> = Vec::new();
        for pair in value
            .as_bytes()
            .split(|byte| *byte == b';')
            .map(<[u8]>::trim_ascii)
            .filter(|pair| !pair.is_empty())
        {
            let (name, cookie) = match pair
                .iter()
                .position(|byte| *byte == b'=')
            {
                Some(at) => (&pair[..at], Some(&pair[at + 1..])),
                None => (pair, None),
            };
            if !is_consent_name(name) {
                others.push(pair);
                continue;
            }
            changed = true;
            if let Some(cookie) = cookie {
                taken.push((
                    String::from_utf8_lossy(name.trim_ascii()).into_owned(),
                    String::from_utf8_lossy(cookie.trim_ascii()).into_owned(),
                ));
            }
        }
        if !others.is_empty()
            && let Ok(value) = HeaderValue::from_bytes(&others.join(&b"; "[..]))
        {
            kept.push(value);
        }
    }
    if changed {
        headers.remove(header::COOKIE);
        for value in kept {
            headers.append(header::COOKIE, value);
        }
    }
    taken
}

/// Whether a `Set-Cookie` sets a consent cookie, judged by its bytes: its name,
/// or, for a nameless one (no `=`, or nothing before it), its value.
fn sets_consent_cookie(value: &HeaderValue) -> bool {
    let bytes = value.as_bytes();
    let pair = bytes
        .split(|byte| *byte == b';')
        .next()
        .unwrap_or(bytes);
    match pair
        .iter()
        .position(|byte| *byte == b'=')
    {
        Some(at)
            if !pair[..at]
                .trim_ascii()
                .is_empty() =>
        {
            is_consent_name(&pair[..at])
        }
        Some(at) => is_consent_name(&pair[at + 1..]),
        None => is_consent_name(pair),
    }
}

/// Removes every `Set-Cookie` that sets a consent cookie.
pub fn strip_consent_set_cookies(headers: &mut HeaderMap) {
    if !headers
        .get_all(header::SET_COOKIE)
        .iter()
        .any(sets_consent_cookie)
    {
        return;
    }
    let kept: Vec<HeaderValue> = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter(|value| !sets_consent_cookie(value))
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
            assert!(is_consent_name(name.as_bytes()), "{name}");
        }
        for name in ["session", "__Host-session", "consent", "xag_consent", "__Secure-ag_consen"] {
            assert!(!is_consent_name(name.as_bytes()), "{name}");
        }
        assert!(is_consent_name(b"__HOST-AG_CONSENT_\xff"), "a high byte after the name");
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

    /// A header holding a byte outside visible ASCII is judged by its bytes too:
    /// a consent cookie in it is still taken off the request or the response,
    /// and the other cookies in it pass byte for byte.
    #[tokio::test]
    async fn headers_with_non_ascii_bytes_carry_no_consent_cookie_either() {
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
                        &b"__Host-ag_consent_abc=planted; Path=/; Secure; X=caf\xc3\xa9"[..],
                        b" __HOST-AG_CONSENT_x=planted\xff",
                        b"=__Host-ag_consent_abc=planted; Path=/",
                        b"__Secure-ag_consent",
                        b"pref=caf\xc3\xa9; Path=/",
                        b"lb=node-2",
                    ] {
                        response
                            .headers_mut()
                            .append(header::SET_COOKIE, HeaderValue::from_bytes(value).unwrap());
                    }
                    response
                }),
            )
            .layer(axum::middleware::from_fn(guard));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/relay")
                    .header("cookie", HeaderValue::from_bytes(b"pref=caf\xc3\xa9; __Host-ag_consent_x=SECRET").unwrap())
                    .header("cookie", HeaderValue::from_bytes(b"__Host-ag_consent_y=caf\xc3\xa9").unwrap())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let set: Vec<_> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect();
        assert_eq!(set, [b"pref=caf\xc3\xa9; Path=/".to_vec(), b"lb=node-2".to_vec()]);
        let seen = seen.lock().unwrap();
        let cookies: Vec<_> = seen[0]
            .get_all(header::COOKIE)
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect();
        assert_eq!(cookies, [b"pref=caf\xc3\xa9".to_vec()]);
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
