//! The `target_https` and `target_source_auth` credential rules on the direct path: in `warn` a
//! surface with an http Target and no caller authentication still sends its Target credential;
//! in `enforce` the credential is withheld and `target.auth.fallback` decides the request.

use super::helpers::{self, GatewayHarness};
use super::target_auth_provider_e2e::write_secret;
use crate::config::credential_policy::{CredentialPolicyConfig, RuleMode};
use serde_json::json;
use std::sync::atomic::Ordering;

const CREDENTIAL: &str = "target-credential-value";

/// The status the caller gets, the credential header the Target received (`None` when it was
/// not called or got no credential), and whether the Target was called.
async fn forward_with_policy(
    policy: CredentialPolicyConfig,
    fallback: &str,
) -> (u16, Option<String>, bool) {
    let h = GatewayHarness::start(|_, gw_config, bootstrap| {
        write_secret(bootstrap, "target-key", CREDENTIAL);
        bootstrap.credential_policy = policy;
        let mut surface = helpers::build_minimal_channel();
        surface.target.auth = Some(
            serde_json::from_value(json!({
                "method": {"static_secret": {
                    "secret_id": "target-key", "header_name": "X-Target-Key", "header_format": "{value}"
                }},
                "fallback": fallback
            }))
            .unwrap(),
        );
        gw_config.surfaces = vec![surface];
    })
    .await;

    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","method":"message/send","id":1,"params":{}}"#)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    if status == 502 {
        let body = response.text().await.unwrap();
        assert!(body.contains("Target authentication failed"), "{body}");
    }
    let called = h
        .mock
        .request_count
        .load(Ordering::SeqCst)
        > 0;
    let credential = h
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .and_then(|request| {
            request
                .headers
                .into_iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("x-target-key"))
                .map(|(_, value)| value)
        });
    (status, credential, called)
}

fn enforcing(
    target_https: RuleMode,
    target_source_auth: RuleMode,
) -> CredentialPolicyConfig {
    CredentialPolicyConfig {
        target_https,
        target_source_auth,
        ..CredentialPolicyConfig::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn warn_sends_the_credential_to_an_http_target_of_a_surface_that_checks_no_caller() {
    assert_eq!(
        forward_with_policy(CredentialPolicyConfig::default(), "reject").await,
        (200, Some(CREDENTIAL.to_string()), true)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn enforced_target_https_with_reject_refuses_the_request_before_the_target() {
    assert_eq!(forward_with_policy(enforcing(RuleMode::Enforce, RuleMode::Warn), "reject").await, (502, None, false));
}

#[tokio::test(flavor = "multi_thread")]
async fn enforced_target_https_with_passthrough_forwards_without_the_credential() {
    assert_eq!(
        forward_with_policy(enforcing(RuleMode::Enforce, RuleMode::Warn), "passthrough").await,
        (200, None, true)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn enforced_target_source_auth_with_reject_refuses_the_request_before_the_target() {
    assert_eq!(forward_with_policy(enforcing(RuleMode::Warn, RuleMode::Enforce), "reject").await, (502, None, false));
}

#[tokio::test(flavor = "multi_thread")]
async fn enforced_target_source_auth_with_passthrough_forwards_without_the_credential() {
    assert_eq!(
        forward_with_policy(enforcing(RuleMode::Warn, RuleMode::Enforce), "passthrough").await,
        (200, None, true)
    );
}
