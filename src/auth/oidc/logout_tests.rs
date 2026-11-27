//! The real logout handlers against the stub OpenID provider: back-channel logout ending the
//! sessions a signed logout token names, and the dashboard sign-out that hands the browser the
//! provider's sign-out address.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use serde_json::{Value, json};

use super::sign_in_tests::{BROWSER, Flow, body, handed_off_token, header_value};
use super::test_support::{
    CLIENT_ID, KEY_A_KID, KEY_A_PEM, KEY_B_KID, KEY_B_PEM, logout_claims, sign_logout, sign_logout_with,
};
use crate::auth::session::{OidcSessionBinding, SessionManager, TermsSessionGate};
use crate::component_tests::helpers::formatted_logs::FormattedLogs;
use crate::server::mode::{self, ServerMode};

impl Flow {
    /// Sign in with the provider session `sid`, and return the dashboard's session token.
    async fn signed_in_with_sid(
        &self,
        sid: &str,
    ) -> String {
        let page = self
            .sign_in(|claims| claims["sid"] = json!(sid))
            .await;
        assert_eq!(page.status(), StatusCode::OK);
        handed_off_token(&body(page).await)
    }

    async fn backchannel_logout(
        &self,
        token: &str,
    ) -> Response<Body> {
        self.post_form("/oidc/backchannel-logout", &format!("logout_token={token}"))
            .await
    }

    /// Post a logout token signed by the provider over the claims of a valid one, `change`d.
    async fn logout_by(
        &self,
        change: impl FnOnce(&mut Value),
    ) -> Response<Body> {
        let mut claims = logout_claims(&self.provider.issuer, "op-session-1");
        change(&mut claims);
        self.backchannel_logout(&sign_logout(&claims))
            .await
    }

    async fn sign_out(
        &self,
        path: &str,
        session: Option<&str>,
    ) -> Response<Body> {
        let mut request = Request::builder()
            .method("POST")
            .uri(path);
        if let Some(session) = session {
            request = request.header(header::AUTHORIZATION, format!("Bearer {session}"));
        }
        self.send_from(
            BROWSER,
            request
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }
}

/// A session of `user_id` from a sign-in at `issuer` as the account `subject` in the provider
/// session `sid`.
async fn bound_session(
    flow: &Flow,
    user_id: &str,
    issuer: &str,
    subject: &str,
    sid: &str,
) -> String {
    flow.oidc
        .session_manager
        .create_session_with_terms_gate(
            user_id.to_string(),
            user_id.to_string(),
            TermsSessionGate::AllowedAtLogin,
            Some(OidcSessionBinding {
                issuer: issuer.to_string(),
                subject: subject.to_string(),
                sid: Some(sid.to_string()),
                id_token: None,
            }),
        )
        .await
}

fn without(
    claims: &mut Value,
    name: &str,
) {
    claims
        .as_object_mut()
        .unwrap()
        .remove(name);
}

async fn refused_as_invalid(response: Response<Body>) {
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(header_value(&response, header::CACHE_CONTROL), "no-store");
    assert_eq!(body(response).await, r#"{"error":"invalid_request"}"#);
}

#[tokio::test]
async fn a_session_records_the_provider_sign_in_it_came_from() {
    let flow = Flow::new().await;

    let token = flow
        .signed_in_with_sid("op-session-1")
        .await;

    let binding = flow
        .oidc
        .session_manager
        .validate_session_record(&token)
        .await
        .unwrap()
        .oidc
        .unwrap();
    assert_eq!(binding.issuer, flow.provider.issuer);
    assert_eq!(binding.subject, "user-1");
    assert_eq!(binding.sid.as_deref(), Some("op-session-1"));
    let id_token = binding
        .id_token
        .expect("the ID token is kept for the sign-out hint");
    let claims = jsonwebtoken::dangerous::insecure_decode::<Value>(&id_token)
        .unwrap()
        .claims;
    assert_eq!(claims["sid"], "op-session-1");
}

#[tokio::test]
async fn an_id_token_whose_sid_is_not_a_short_string_is_refused() {
    let flow = Flow::new().await;

    let response = flow
        .sign_in(|claims| claims["sid"] = json!(""))
        .await;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "id_token_invalid");
    assert!(flow.user().await.is_none());
}

#[tokio::test]
async fn a_logout_naming_a_provider_session_ends_only_that_session() {
    let _ready = mode::ready_for_test().await;
    let flow = Flow::new().await;
    let first = flow
        .signed_in_with_sid("op-session-1")
        .await;
    let second = flow
        .signed_in_with_sid("op-session-2")
        .await;

    let response = flow
        .logout_by(|claims| without(claims, "sub"))
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(header_value(&response, header::CACHE_CONTROL), "no-store");
    assert_eq!(body(response).await, "{}");
    assert!(
        !flow
            .session_is_live(&first)
            .await
    );
    assert!(
        flow.session_is_live(&second)
            .await,
        "the other provider session continues"
    );
}

#[tokio::test]
async fn a_logout_naming_only_the_account_ends_all_its_sessions() {
    let _ready = mode::ready_for_test().await;
    let flow = Flow::new().await;
    let first = flow
        .signed_in_with_sid("op-session-1")
        .await;
    let second = flow
        .signed_in_with_sid("op-session-2")
        .await;

    let response = flow
        .logout_by(|claims| without(claims, "sid"))
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        !flow
            .session_is_live(&first)
            .await
    );
    assert!(
        !flow
            .session_is_live(&second)
            .await
    );
}

#[tokio::test]
async fn a_logout_with_sid_and_sub_ends_that_accounts_sessions_whose_id_token_had_no_sid() {
    let _ready = mode::ready_for_test().await;
    let flow = Flow::new().await;
    let without_sid = handed_off_token(&body(flow.sign_in(|_| {}).await).await);

    let response = flow
        .logout_by(|claims| claims["sid"] = json!("op-session-9"))
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        !flow
            .session_is_live(&without_sid)
            .await
    );
}

#[tokio::test]
async fn a_logout_ends_only_the_sessions_of_its_account_at_this_provider() {
    let _ready = mode::ready_for_test().await;
    for (logout, left_out) in [("by sub", "sid"), ("by sid", "sub")] {
        let flow = Flow::new().await;
        let signed_in = flow
            .signed_in_with_sid("op-session-1")
            .await;
        let user = flow.user().await.unwrap();
        let issuer = flow.provider.issuer.clone();
        let others = [
            (
                "the user's session from no provider sign-in",
                flow.other_session(&user)
                    .await,
            ),
            ("another account's session", bound_session(&flow, "user-bob", &issuer, "user-2", "op-session-2").await),
            (
                "a session from another provider for the same sub and sid",
                bound_session(&flow, &user.user_id, "https://other.example", "user-1", "op-session-1").await,
            ),
        ];

        let response = flow
            .logout_by(|claims| without(claims, left_out))
            .await;

        assert_eq!(response.status(), StatusCode::OK, "{logout}");
        assert!(
            !flow
                .session_is_live(&signed_in)
                .await,
            "{logout}"
        );
        for (other, session) in &others {
            assert!(
                flow.session_is_live(session)
                    .await,
                "{logout}: {other} continues"
            );
        }
    }
}

#[tokio::test]
async fn a_logout_token_within_the_clock_skew_leeway_is_accepted_once() {
    let _ready = mode::ready_for_test().await;
    let flow = Flow::new().await;
    let now = chrono::Utc::now().timestamp();
    let first = flow
        .signed_in_with_sid("op-session-1")
        .await;
    let second = flow
        .signed_in_with_sid("op-session-2")
        .await;
    let mut claims = logout_claims(&flow.provider.issuer, "op-session-1");
    claims["exp"] = json!(now - 30);
    let expired_within_leeway = sign_logout(&claims);

    assert_eq!(
        flow.backchannel_logout(&expired_within_leeway)
            .await
            .status(),
        StatusCode::OK
    );
    assert!(
        !flow
            .session_is_live(&first)
            .await
    );
    refused_as_invalid(
        flow.backchannel_logout(&expired_within_leeway)
            .await,
    )
    .await;

    let issued_ahead_within_leeway = flow
        .logout_by(|claims| {
            claims["sid"] = json!("op-session-2");
            claims["iat"] = json!(now + 30);
        })
        .await;
    assert_eq!(issued_ahead_within_leeway.status(), StatusCode::OK);
    assert!(
        !flow
            .session_is_live(&second)
            .await
    );
}

#[tokio::test]
async fn a_logout_for_an_unknown_session_or_account_still_answers_ok() {
    let _ready = mode::ready_for_test().await;
    let flow = Flow::new().await;
    let session = flow
        .signed_in_with_sid("op-session-1")
        .await;

    for change in [json!({ "sid": "never-seen", "sub": null }), json!({ "sub": "someone-else", "sid": null })] {
        let response = flow
            .logout_by(|claims| {
                for (name, value) in change.as_object().unwrap() {
                    if value.is_null() {
                        without(claims, name);
                    } else {
                        claims[name] = value.clone();
                    }
                }
            })
            .await;
        assert_eq!(response.status(), StatusCode::OK, "a logout is idempotent: {change}");
    }
    assert!(
        flow.session_is_live(&session)
            .await
    );
}

#[tokio::test]
async fn a_logout_token_that_does_not_verify_ends_nothing() {
    let _ready = mode::ready_for_test().await;
    let flow = Flow::new().await;
    let session = flow
        .signed_in_with_sid("op-session-1")
        .await;
    let used = sign_logout(&logout_claims(&flow.provider.issuer, "never-seen"));
    assert_eq!(
        flow.backchannel_logout(&used)
            .await
            .status(),
        StatusCode::OK
    );
    let id_token = flow
        .oidc
        .session_manager
        .validate_session_record(&session)
        .await
        .unwrap()
        .oidc
        .unwrap()
        .id_token
        .unwrap();

    refused_as_invalid(
        flow.backchannel_logout(&used)
            .await,
    )
    .await;
    refused_as_invalid(
        flow.backchannel_logout(&id_token)
            .await,
    )
    .await;
    refused_as_invalid(
        flow.logout_by(|claims| claims["nonce"] = json!("n"))
            .await,
    )
    .await;
    refused_as_invalid(
        flow.logout_by(|claims| claims["iss"] = json!("https://other.example"))
            .await,
    )
    .await;
    refused_as_invalid(
        flow.logout_by(|claims| claims["aud"] = json!("another-client"))
            .await,
    )
    .await;
    refused_as_invalid(
        flow.logout_by(|claims| without(claims, "events"))
            .await,
    )
    .await;
    refused_as_invalid(
        flow.logout_by(|claims| without(claims, "exp"))
            .await,
    )
    .await;
    refused_as_invalid(
        flow.backchannel_logout(&sign_logout_with(
            KEY_B_PEM,
            Some(KEY_A_KID),
            &logout_claims(&flow.provider.issuer, "op-session-1"),
        ))
        .await,
    )
    .await;
    refused_as_invalid(
        flow.backchannel_logout("not-a-token")
            .await,
    )
    .await;
    refused_as_invalid(
        flow.post_form("/oidc/backchannel-logout", "other=1")
            .await,
    )
    .await;

    assert!(
        flow.session_is_live(&session)
            .await
    );
}

#[tokio::test]
async fn a_logout_request_that_is_not_a_form_or_over_the_size_limit_is_refused_like_any_invalid_request() {
    let _ready = mode::ready_for_test().await;
    let flow = Flow::new().await;

    let json = flow
        .send_from(
            BROWSER,
            Request::builder()
                .method("POST")
                .uri("/oidc/backchannel-logout")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"logout_token":"x"}"#))
                .unwrap(),
        )
        .await;
    refused_as_invalid(json).await;

    let oversized = format!("logout_token={}", "a".repeat(super::MAX_BACKCHANNEL_LOGOUT_BYTES));
    refused_as_invalid(
        flow.post_form("/oidc/backchannel-logout", &oversized)
            .await,
    )
    .await;
}

/// A form posting a valid logout token for the provider session `op-session-1`, padded with a
/// claim until the form is `len` bytes long, or one byte longer where the token's encoding skips
/// that length.
fn padded_logout_form(
    issuer: &str,
    len: usize,
) -> String {
    let form = |padding: usize| {
        let mut claims = logout_claims(issuer, "op-session-1");
        claims["padding"] = json!("a".repeat(padding));
        format!("logout_token={}", sign_logout(&claims))
    };
    let mut padding = 0;
    loop {
        let candidate = form(padding);
        if candidate.len() >= len {
            return candidate;
        }
        padding += ((len - candidate.len()) * 3 / 4).max(1);
    }
}

#[tokio::test]
async fn a_logout_form_just_over_16_kib_is_refused_and_one_just_under_is_accepted() {
    let _ready = mode::ready_for_test().await;
    let flow = Flow::new().await;
    let session = flow
        .signed_in_with_sid("op-session-1")
        .await;
    let limit = super::MAX_BACKCHANNEL_LOGOUT_BYTES;
    let over = padded_logout_form(&flow.provider.issuer, limit + 1);
    let under = padded_logout_form(&flow.provider.issuer, limit - 1);
    assert!((limit + 1..=limit + 2).contains(&over.len()), "{}", over.len());
    assert!((limit - 1..=limit).contains(&under.len()), "{}", under.len());

    refused_as_invalid(
        flow.post_form("/oidc/backchannel-logout", &over)
            .await,
    )
    .await;
    assert!(
        flow.session_is_live(&session)
            .await
    );

    assert_eq!(
        flow.post_form("/oidc/backchannel-logout", &under)
            .await
            .status(),
        StatusCode::OK
    );
    assert!(
        !flow
            .session_is_live(&session)
            .await
    );
}

#[tokio::test]
async fn a_logout_that_cannot_end_a_session_fails_and_the_provider_can_send_it_again() {
    let _ready = mode::ready_for_test().await;
    let failing = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let flow = Flow::with_parts(|_| {}, Arc::new(SessionManager::with_failing_deletes(failing.clone()))).await;
    let session = flow
        .signed_in_with_sid("op-session-1")
        .await;
    let token = sign_logout(&logout_claims(&flow.provider.issuer, "op-session-1"));

    let failed = flow
        .backchannel_logout(&token)
        .await;
    assert_eq!(failed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(header_value(&failed, header::CACHE_CONTROL), "no-store");
    assert_eq!(body(failed).await, r#"{"error":"logout_failed"}"#);
    assert!(
        flow.session_is_live(&session)
            .await
    );

    failing.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        flow.backchannel_logout(&token)
            .await
            .status(),
        StatusCode::OK
    );
    assert!(
        !flow
            .session_is_live(&session)
            .await
    );
}

#[tokio::test]
async fn a_logout_whose_provider_or_keys_cannot_be_reached_answers_unavailable() {
    let _ready = mode::ready_for_test().await;
    let flow = Flow::new().await;
    let session = flow
        .signed_in_with_sid("op-session-1")
        .await;
    flow.provider
        .set_jwks(json!("not a key set"));
    let signed_with_a_new_key =
        sign_logout_with(KEY_B_PEM, Some(KEY_B_KID), &logout_claims(&flow.provider.issuer, "op-session-1"));
    let logs = FormattedLogs::capture();

    let response = flow
        .backchannel_logout(&signed_with_a_new_key)
        .await;

    assert!(
        logs.text()
            .contains("the provider's keys are unavailable"),
        "{}",
        logs.text()
    );
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(header_value(&response, header::CACHE_CONTROL), "no-store");
    assert_eq!(body(response).await, r#"{"error":"temporarily_unavailable"}"#);
    assert!(
        flow.session_is_live(&session)
            .await
    );

    let unreachable = Flow::new().await;
    unreachable
        .provider
        .set_discovery_down(true);
    let response = unreachable
        .backchannel_logout(&sign_logout(&logout_claims(&unreachable.provider.issuer, "op-session-1")))
        .await;
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "the token was not judged, so the provider may retry"
    );
}

#[tokio::test]
async fn a_logout_signed_with_a_key_published_during_the_unknown_key_cooldown_answers_unavailable() {
    let _ready = mode::ready_for_test().await;
    let flow = Flow::new().await;
    let session = flow
        .signed_in_with_sid("op-session-1")
        .await;
    let made_up_kid =
        sign_logout_with(KEY_A_PEM, Some("made-up"), &logout_claims(&flow.provider.issuer, "op-session-1"));
    refused_as_invalid(
        flow.backchannel_logout(&made_up_kid)
            .await,
    )
    .await;

    flow.provider
        .rotate_to_key_b();
    let signed_with_key_b =
        sign_logout_with(KEY_B_PEM, Some(KEY_B_KID), &logout_claims(&flow.provider.issuer, "op-session-1"));
    let response = flow
        .backchannel_logout(&signed_with_key_b)
        .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "the provider retries after the cooldown");
    assert_eq!(flow.provider.jwks_fetches(), 2, "the made-up key was fetched for once");
    assert!(
        flow.session_is_live(&session)
            .await
    );
    flow.backchannel_logout(&signed_with_key_b)
        .await;
    assert_eq!(
        flow.provider
            .discovery_fetches(),
        1,
        "a key the cooldown keeps unknown leaves the discovery document as it is"
    );
}

#[tokio::test]
async fn a_logout_whose_keys_cannot_be_fetched_has_the_discovery_document_fetched_again() {
    let _ready = mode::ready_for_test().await;
    let flow = Flow::new().await;
    flow.signed_in_with_sid("op-session-1")
        .await;
    flow.provider
        .set_jwks(json!("not a key set"));
    let signed_with_a_new_key =
        sign_logout_with(KEY_B_PEM, Some(KEY_B_KID), &logout_claims(&flow.provider.issuer, "op-session-1"));
    assert_eq!(
        flow.backchannel_logout(&signed_with_a_new_key)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        flow.provider
            .discovery_fetches(),
        1
    );

    let response = flow
        .backchannel_logout(&signed_with_a_new_key)
        .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        flow.provider
            .discovery_fetches(),
        2,
        "a key set that could not be fetched may have moved"
    );
}

#[tokio::test]
async fn a_logout_during_the_key_cooldown_is_logged_apart_from_unreachable_keys_with_its_kid_escaped() {
    let _ready = mode::ready_for_test().await;
    let flow = Flow::new().await;
    flow.signed_in_with_sid("op-session-1")
        .await;
    let claims = logout_claims(&flow.provider.issuer, "op-session-1");
    refused_as_invalid(
        flow.backchannel_logout(&sign_logout_with(KEY_A_PEM, Some("made-up"), &claims))
            .await,
    )
    .await;
    let logs = FormattedLogs::capture();

    let response = flow
        .backchannel_logout(&sign_logout_with(KEY_A_PEM, Some("made-up-2\nERROR forged line"), &claims))
        .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let text = logs.text();
    assert!(text.contains("the keys were fetched again too recently to look for a new one"), "{text}");
    assert!(!text.contains("the provider's keys are unavailable"), "{text}");
    assert!(text.contains(r"made-up-2\nERROR forged line"), "{text}");
    assert!(!text.contains("made-up-2\nERROR"), "the kid forged a log line: {text}");
}

#[tokio::test]
async fn a_logout_posted_to_an_instance_that_is_not_ready_answers_unavailable_and_ends_nothing() {
    let _ready = mode::ready_for_test().await;
    for (instance, server_mode) in [("standby", ServerMode::Standby), ("active, not yet ready", ServerMode::Active)] {
        let flow = Flow::new().await;
        let session = flow
            .signed_in_with_sid("op-session-1")
            .await;
        let token = sign_logout(&logout_claims(&flow.provider.issuer, "op-session-1"));

        let response = {
            let _not_ready = mode::switched_for_test(server_mode);
            assert!(!mode::is_ready_to_serve(), "{instance}");
            flow.backchannel_logout(&token)
                .await
        };

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{instance}");
        assert_eq!(header_value(&response, header::CACHE_CONTROL), "no-store", "{instance}");
        assert_eq!(body(response).await, r#"{"error":"temporarily_unavailable"}"#, "{instance}");
        assert!(
            flow.session_is_live(&session)
                .await,
            "{instance}"
        );
        assert_eq!(
            flow.backchannel_logout(&token)
                .await
                .status(),
            StatusCode::OK,
            "{instance}: the token was not used, so the provider can send it again to the ready instance"
        );
        assert!(
            !flow
                .session_is_live(&session)
                .await,
            "{instance}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_logout_whose_request_is_dropped_still_ends_its_sessions() {
    let _ready = mode::ready_for_test().await;
    let flow = Flow::new().await;
    let session = flow
        .signed_in_with_sid("op-session-1")
        .await;
    let (entered, release) = (Arc::new(std::sync::Barrier::new(2)), Arc::new(std::sync::Barrier::new(2)));
    let busy = tokio::spawn({
        let (sessions, entered, release) = (
            flow.oidc
                .session_manager
                .clone(),
            entered.clone(),
            release.clone(),
        );
        let blocked = std::sync::atomic::AtomicBool::new(false);
        async move {
            sessions
                .remove_sessions_where(move |_| {
                    if !blocked.swap(true, std::sync::atomic::Ordering::SeqCst) {
                        entered.wait();
                        release.wait();
                    }
                    false
                })
                .await
        }
    });
    tokio::task::spawn_blocking(move || entered.wait())
        .await
        .unwrap();

    let token = sign_logout(&logout_claims(&flow.provider.issuer, "op-session-1"));
    let dropped = tokio::time::timeout(std::time::Duration::from_millis(300), flow.backchannel_logout(&token)).await;
    assert!(dropped.is_err(), "the logout waits while the sessions are in use");
    tokio::task::spawn_blocking(move || release.wait())
        .await
        .unwrap();
    busy.await.unwrap();

    let mut ended = false;
    for _ in 0..100 {
        if !flow
            .session_is_live(&session)
            .await
        {
            ended = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(ended, "the logout ended the session after the provider dropped its request");
}

#[tokio::test]
async fn back_channel_logout_spends_no_sign_in_budget() {
    let _ready = mode::ready_for_test().await;
    let flow = Flow::new().await;

    for _ in 0..=super::throttle::SIGN_IN_REQUESTS_PER_WINDOW {
        refused_as_invalid(
            flow.post_form("/oidc/backchannel-logout", "")
                .await,
        )
        .await;
    }
    assert_eq!(
        flow.get("/oidc/login", None)
            .await
            .status(),
        StatusCode::SEE_OTHER,
        "the browser's sign-in budget is untouched"
    );
}

/// The answer of a dashboard sign-out: `200`, uncached, clearing the session cookie.
async fn sign_out_answer(response: Response<Body>) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(header_value(&response, header::CACHE_CONTROL), "no-store");
    assert!(
        header_value(&response, header::SET_COOKIE).starts_with("__Host-session_token=;"),
        "the session cookie is cleared"
    );
    serde_json::from_str(&body(response).await).unwrap()
}

#[tokio::test]
async fn signing_out_ends_the_session_and_gives_the_providers_sign_out_address() {
    let flow = Flow::with_config(|config| {
        config
            .logout
            .post_logout_redirect_uri = Some("https://gateway.example.com/?signed_out=1".to_string())
    })
    .await;
    let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();

    for (path, sid) in [("/auth/logout", "op-session-1"), ("/oidc/logout", "op-session-2")] {
        let session = flow
            .signed_in_with_sid(sid)
            .await;
        let id_token = flow
            .oidc
            .session_manager
            .validate_session_record(&session)
            .await
            .unwrap()
            .oidc
            .unwrap()
            .id_token
            .unwrap();

        let answer = sign_out_answer(
            flow.sign_out(path, Some(&session))
                .await,
        )
        .await;

        let address = url::Url::parse(
            answer["end_session_url"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert!(
            address
                .as_str()
                .starts_with(&format!(
                    "{}?",
                    flow.provider
                        .end_session_endpoint()
                )),
            "{path}: {address}"
        );
        let query: HashMap<String, String> = address
            .query_pairs()
            .into_owned()
            .collect();
        assert_eq!(query["id_token_hint"], id_token, "{path}: the hint is the session's own ID token");
        assert_eq!(query["client_id"], CLIENT_ID, "{path}");
        assert_eq!(query["post_logout_redirect_uri"], "https://gateway.example.com/?signed_out=1", "{path}");
        assert_eq!(query["state"].len(), 43, "{path}: a fresh random state");
        assert!(
            !flow
                .session_is_live(&session)
                .await,
            "{path}: the dashboard session ended"
        );
        assert!(
            !logs
                .text()
                .contains(&id_token),
            "{path}: the ID token reached the log"
        );
    }
}

#[tokio::test]
async fn without_a_post_logout_address_the_provider_shows_its_own_page() {
    let flow = Flow::new().await;
    let session = flow
        .signed_in_with_sid("op-session-1")
        .await;

    let answer = sign_out_answer(
        flow.sign_out("/oidc/logout", Some(&session))
            .await,
    )
    .await;

    let address = url::Url::parse(
        answer["end_session_url"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert!(
        !address
            .query_pairs()
            .any(|(name, _)| name == "post_logout_redirect_uri")
    );
}

#[tokio::test]
async fn sign_out_stays_local_when_it_is_turned_off_or_the_provider_has_no_sign_out() {
    let flow = Flow::with_config(|config| config.logout.rp_initiated = false).await;
    let session = flow
        .signed_in_with_sid("op-session-1")
        .await;
    assert_eq!(
        sign_out_answer(
            flow.sign_out("/auth/logout", Some(&session))
                .await
        )
        .await,
        json!({})
    );
    assert!(
        !flow
            .session_is_live(&session)
            .await
    );

    let flow = Flow::new().await;
    flow.provider
        .without_end_session();
    let session = flow
        .signed_in_with_sid("op-session-1")
        .await;
    assert_eq!(
        sign_out_answer(
            flow.sign_out("/auth/logout", Some(&session))
                .await
        )
        .await,
        json!({})
    );
    assert!(
        !flow
            .session_is_live(&session)
            .await
    );
}

#[tokio::test]
async fn signing_out_without_a_live_session_still_clears_the_browser() {
    let flow = Flow::new().await;

    for session in [None, Some("not-a-session")] {
        assert_eq!(
            sign_out_answer(
                flow.sign_out("/auth/logout", session)
                    .await
            )
            .await,
            json!({}),
            "{session:?}"
        );
    }
}

#[tokio::test]
async fn an_expired_session_signs_out_locally_only() {
    let flow = Flow::with_parts(|_| {}, Arc::new(SessionManager::with_timeout(0))).await;
    let expired = flow
        .signed_in_with_sid("op-session-1")
        .await;

    let answer = sign_out_answer(
        flow.sign_out("/oidc/logout", Some(&expired))
            .await,
    )
    .await;

    assert_eq!(answer, json!({}), "a timed-out session does not sign the person out of the provider");
}

#[tokio::test]
async fn a_binding_stored_without_its_id_token_signs_out_with_no_hint() {
    let flow = Flow::new().await;
    let session = flow
        .oidc
        .session_manager
        .create_session_with_terms_gate(
            "alice".into(),
            "user-1".into(),
            TermsSessionGate::AllowedAtLogin,
            Some(OidcSessionBinding {
                issuer: flow.provider.issuer.clone(),
                subject: "user-1".to_string(),
                sid: Some("op-session-1".to_string()),
                id_token: None,
            }),
        )
        .await;

    let answer = sign_out_answer(
        flow.sign_out("/oidc/logout", Some(&session))
            .await,
    )
    .await;

    let address = url::Url::parse(
        answer["end_session_url"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let names: Vec<String> = address
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect();
    assert_eq!(names, ["client_id", "state"]);
    assert!(
        !flow
            .session_is_live(&session)
            .await
    );
}

#[tokio::test]
async fn a_session_from_another_provider_never_sends_its_id_token_to_this_one() {
    let flow = Flow::new().await;
    let session = flow
        .oidc
        .session_manager
        .create_session_with_terms_gate(
            "alice".into(),
            "user-1".into(),
            TermsSessionGate::AllowedAtLogin,
            Some(OidcSessionBinding {
                issuer: "https://idp.old.example".to_string(),
                subject: "user-1".to_string(),
                sid: Some("op-session-1".to_string()),
                id_token: Some("the-old-providers-id-token".to_string()),
            }),
        )
        .await;

    assert_eq!(
        sign_out_answer(
            flow.sign_out("/auth/logout", Some(&session))
                .await
        )
        .await,
        json!({})
    );
    assert!(
        !flow
            .session_is_live(&session)
            .await
    );
}

#[tokio::test]
async fn a_provider_that_cannot_be_reached_leaves_the_sign_out_local() {
    let flow = Flow::new().await;
    flow.provider
        .set_discovery_down(true);
    let session = flow
        .oidc
        .session_manager
        .create_session_with_terms_gate(
            "alice".into(),
            "user-1".into(),
            TermsSessionGate::AllowedAtLogin,
            Some(OidcSessionBinding {
                issuer: flow.provider.issuer.clone(),
                subject: "user-1".to_string(),
                sid: None,
                id_token: Some("id-token".to_string()),
            }),
        )
        .await;

    assert_eq!(
        sign_out_answer(
            flow.sign_out("/auth/logout", Some(&session))
                .await
        )
        .await,
        json!({})
    );
    assert!(
        !flow
            .session_is_live(&session)
            .await
    );
}
