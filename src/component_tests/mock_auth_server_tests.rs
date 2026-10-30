//! Behaviour of the in-process authorization server and of the test-mode seam
//! that lets the production validators reach it.

use std::time::Duration;

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::{Value, json};

use super::helpers::mock_auth_server::{
    CLIENT_CREDENTIALS_GRANT, DiscoveryDocs, Endpoint, Fault, IssuerShape, JWT_BEARER_GRANT, JwtBearerClient,
    MockAuthServer, OVERSIZED_BODY_BYTES,
};
use super::helpers::oidc_keys::{KeyKind, SigningFixture};
use super::helpers::test_mode::TestModeEnv;
use crate::egress::{EgressError, bdd_egress_allowlist, pinned_configured_client};
use crate::url_validation::validate_oauth_endpoint_url;

type Scenario<'a> = (&'a str, Option<&'a str>, Option<&'a str>, Option<&'a str>);

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn get(url: &str) -> (u16, Vec<u8>) {
    let response = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (
        status,
        response
            .bytes()
            .await
            .unwrap()
            .to_vec(),
    )
}

async fn get_json(url: &str) -> (u16, Value) {
    let (status, body) = get(url).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

async fn post_form(
    url: &str,
    fields: &[(&str, &str)],
    basic: Option<(&str, &str)>,
) -> (u16, Value) {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields)
        .finish();
    let mut request = reqwest::Client::new()
        .post(url)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body);
    if let Some((id, secret)) = basic {
        request = request.basic_auth(id, Some(secret));
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    (
        status,
        response
            .json()
            .await
            .unwrap_or(Value::Null),
    )
}

fn jwt_client(
    iss: &str,
    sub: &str,
    key: &SigningFixture,
) -> JwtBearerClient {
    JwtBearerClient {
        iss: iss.to_string(),
        sub: sub.to_string(),
        keys: vec![key.clone()],
    }
}

fn assertion_claims(
    server: &MockAuthServer,
    iss: &str,
    sub: &str,
) -> Value {
    json!({
        "iss": iss,
        "sub": sub,
        "aud": server.token_endpoint(),
        "iat": now(),
        "exp": now() + 300,
        "jti": uuid::Uuid::new_v4().to_string(),
    })
}

async fn exchange(
    server: &MockAuthServer,
    assertion: &str,
) -> (u16, Value) {
    post_form(&server.token_endpoint(), &[("grant_type", JWT_BEARER_GRANT), ("assertion", assertion)], None).await
}

fn decoding_key_for(
    jwks: &Value,
    kid: &str,
) -> Option<(DecodingKey, Algorithm)> {
    let set: JwkSet = serde_json::from_value(jwks.clone()).unwrap();
    let jwk = set.find(kid)?;
    let alg = if jwk.common.key_algorithm == Some(jsonwebtoken::jwk::KeyAlgorithm::ES256) {
        Algorithm::ES256
    } else {
        Algorithm::RS256
    };
    Some((DecodingKey::from_jwk(jwk).unwrap(), alg))
}

fn verify_with_jwks(
    token: &str,
    jwks: &Value,
) -> Option<Value> {
    let kid = jsonwebtoken::decode_header(token)
        .ok()?
        .kid?;
    let (key, alg) = decoding_key_for(jwks, &kid)?;
    let mut validation = Validation::new(alg);
    validation.set_audience(&["mock-resource"]);
    jsonwebtoken::decode::<Value>(token, &key, &validation)
        .ok()
        .map(|data| data.claims)
}

#[tokio::test]
async fn discovery_documents_carry_the_configured_issuer_for_every_shape() {
    let shapes = [
        IssuerShape::Origin,
        IssuerShape::TrailingSlash,
        IssuerShape::Path("/tenant/a"),
        IssuerShape::Path("/tenant/a/"),
    ];
    for shape in shapes {
        let server = MockAuthServer::builder()
            .issuer_shape(shape)
            .start()
            .await;
        for url in [server.rfc8414_metadata_url(), server.openid_configuration_url()] {
            let (status, doc) = get_json(&url).await;
            assert_eq!(status, 200, "{shape:?} {url}");
            assert_eq!(doc["issuer"], server.issuer(), "{shape:?} {url}");
            assert_eq!(doc["token_endpoint"], server.token_endpoint());
            assert_eq!(doc["jwks_uri"], server.jwks_uri());
        }
    }
}

#[tokio::test]
async fn issuer_shapes_match_the_standard_url_construction() {
    let origin = MockAuthServer::start().await;
    assert!(!origin.issuer().ends_with('/'));
    assert_eq!(origin.rfc8414_metadata_url(), format!("{}/.well-known/oauth-authorization-server", origin.origin()));

    let slash = MockAuthServer::builder()
        .issuer_shape(IssuerShape::TrailingSlash)
        .start()
        .await;
    assert_eq!(slash.issuer(), format!("{}/", slash.origin()));
    assert_eq!(slash.openid_configuration_url(), format!("{}/.well-known/openid-configuration", slash.origin()));

    let path = MockAuthServer::builder()
        .issuer_shape(IssuerShape::Path("/tenant/a"))
        .start()
        .await;
    assert_eq!(path.issuer(), format!("{}/tenant/a", path.origin()));
    assert_eq!(
        path.rfc8414_metadata_url(),
        format!("{}/.well-known/oauth-authorization-server/tenant/a", path.origin())
    );
    assert_eq!(path.openid_configuration_url(), format!("{}/tenant/a/.well-known/openid-configuration", path.origin()));
    let (status, _) = get_json(&format!("{}/.well-known/openid-configuration/tenant/a", path.origin())).await;
    assert_eq!(status, 200, "the path-insertion form of OpenID discovery is served too");
}

#[tokio::test]
async fn a_provider_can_serve_only_one_discovery_document() {
    let rfc_only = MockAuthServer::builder()
        .discovery(DiscoveryDocs::Rfc8414Only)
        .start()
        .await;
    assert_eq!(
        get_json(&rfc_only.rfc8414_metadata_url())
            .await
            .0,
        200
    );
    assert_eq!(
        get_json(&rfc_only.openid_configuration_url())
            .await
            .0,
        404
    );

    let oidc_only = MockAuthServer::builder()
        .discovery(DiscoveryDocs::OpenIdOnly)
        .start()
        .await;
    assert_eq!(
        get_json(&oidc_only.rfc8414_metadata_url())
            .await
            .0,
        404
    );
    assert_eq!(
        get_json(&oidc_only.openid_configuration_url())
            .await
            .0,
        200
    );
}

#[tokio::test]
async fn jwks_publishes_rsa_and_ec_keys_and_rotation_replaces_or_overlaps_them() {
    let server = MockAuthServer::start().await;
    let (_, jwks) = get_json(&server.jwks_uri()).await;
    let kinds: Vec<String> = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| {
            key["kty"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(kinds, ["RSA", "EC"]);
    assert_eq!(server.published_kids(), ["rs256-0", "es256-0"]);

    let old_token = server
        .signing_key()
        .sign(&json!({"aud": "mock-resource", "exp": now() + 60}));
    assert!(verify_with_jwks(&old_token, &jwks).is_some());

    server.rotate_keys(true);
    let (_, overlap) = get_json(&server.jwks_uri()).await;
    assert_eq!(server.published_kids(), ["rs256-0", "es256-0", "rs256-1", "es256-1"]);
    assert!(verify_with_jwks(&old_token, &overlap).is_some(), "the retired key is still published");
    assert_eq!(server.signing_key().kid, "rs256-1");

    let server = MockAuthServer::start().await;
    server.rotate_keys(false);
    let (_, replaced) = get_json(&server.jwks_uri()).await;
    assert_eq!(server.published_kids(), ["rs256-1", "es256-1"]);
    assert!(verify_with_jwks(&old_token, &replaced).is_none(), "the retired key is gone");
    let new_token = server
        .signing_key()
        .sign(&json!({"aud": "mock-resource", "exp": now() + 60}));
    assert!(verify_with_jwks(&new_token, &replaced).is_some());
}

#[tokio::test]
async fn an_es256_signing_server_issues_es256_tokens() {
    let server = MockAuthServer::builder()
        .signing_alg(Algorithm::ES256)
        .start()
        .await;
    server.register_client("c", "s");
    let (status, body) =
        post_form(&server.token_endpoint(), &[("grant_type", CLIENT_CREDENTIALS_GRANT)], Some(("c", "s"))).await;
    assert_eq!(status, 200);
    let token = body["access_token"]
        .as_str()
        .unwrap();
    assert_eq!(
        jsonwebtoken::decode_header(token)
            .unwrap()
            .alg,
        Algorithm::ES256
    );
    let (_, jwks) = get_json(&server.jwks_uri()).await;
    assert!(verify_with_jwks(token, &jwks).is_some());
    assert_eq!(server.signing_key().kind(), KeyKind::Ec);
}

#[tokio::test]
async fn client_credentials_issues_a_signed_token_for_basic_and_post_auth() {
    let server = MockAuthServer::start().await;
    server.register_client("agent-1", "s3cret");

    let (status, body) = post_form(
        &server.token_endpoint(),
        &[("grant_type", CLIENT_CREDENTIALS_GRANT), ("scope", "read write"), ("audience", "https://api.example")],
        Some(("agent-1", "s3cret")),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "read write");
    let token = body["access_token"]
        .as_str()
        .unwrap();
    let payload: Value = serde_json::from_slice(&base64_decode(
        token
            .split('.')
            .nth(1)
            .unwrap(),
    ))
    .unwrap();
    assert_eq!(payload["iss"], server.issuer());
    assert_eq!(payload["sub"], "agent-1");
    assert_eq!(payload["aud"], "https://api.example");
    assert_eq!(payload["scope"], "read write");

    let (status, body) = post_form(
        &server.token_endpoint(),
        &[("grant_type", CLIENT_CREDENTIALS_GRANT), ("client_id", "agent-1"), ("client_secret", "s3cret")],
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert!(body["access_token"].is_string());
    assert_eq!(server.token_request_count(), 2);
}

fn base64_decode(part: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .unwrap()
}

#[tokio::test]
async fn client_credentials_rejects_unknown_clients_and_unsupported_grants() {
    let server = MockAuthServer::start().await;
    server.register_client("agent-1", "s3cret");

    let (status, body) =
        post_form(&server.token_endpoint(), &[("grant_type", CLIENT_CREDENTIALS_GRANT)], Some(("agent-1", "wrong")))
            .await;
    assert_eq!((status, body["error"].as_str()), (401, Some("invalid_client")));

    let (status, body) = post_form(&server.token_endpoint(), &[("grant_type", CLIENT_CREDENTIALS_GRANT)], None).await;
    assert_eq!((status, body["error"].as_str()), (401, Some("invalid_client")));

    let (status, body) =
        post_form(&server.token_endpoint(), &[("grant_type", "password")], Some(("agent-1", "s3cret"))).await;
    assert_eq!((status, body["error"].as_str()), (400, Some("unsupported_grant_type")));

    let (status, _) = get_json(&server.token_endpoint()).await;
    assert_eq!(status, 405);
}

#[tokio::test]
async fn jwt_bearer_accepts_a_valid_assertion_for_rs256_and_es256_clients() {
    let server = MockAuthServer::start().await;
    let rsa = SigningFixture::rs256(1).with_kid("client-rsa");
    let ec = SigningFixture::es256(1).with_kid("client-ec");
    server.register_jwt_client(jwt_client("gateway-rsa", "agent-rsa", &rsa));
    server.register_jwt_client(jwt_client("gateway-ec", "agent-ec", &ec));

    for (key, iss, sub) in [(&rsa, "gateway-rsa", "agent-rsa"), (&ec, "gateway-ec", "agent-ec")] {
        let assertion = key.sign(&assertion_claims(&server, iss, sub));
        let (status, body) = exchange(&server, &assertion).await;
        assert_eq!(status, 200, "{iss}: {body}");
        let (_, jwks) = get_json(&server.jwks_uri()).await;
        let claims = verify_with_jwks(
            body["access_token"]
                .as_str()
                .unwrap(),
            &jwks,
        )
        .unwrap();
        assert_eq!(claims["sub"], sub);
    }
    assert_eq!(server.token_request_count(), 2);
    let accepted: Vec<(Value, Value)> = server
        .accepted_assertions()
        .iter()
        .map(|claims| (claims["iss"].clone(), claims["sub"].clone()))
        .collect();
    assert_eq!(accepted, vec![(json!("gateway-rsa"), json!("agent-rsa")), (json!("gateway-ec"), json!("agent-ec"))]);
}

#[tokio::test]
async fn jwt_bearer_rejects_each_invalid_assertion_with_its_own_reason() {
    let server = MockAuthServer::start().await;
    let key = SigningFixture::es256(1).with_kid("client-ec");
    let other = SigningFixture::es256(0).with_kid("client-ec");
    server.register_jwt_client(jwt_client("gateway", "agent", &key));
    let good = |mutate: &dyn Fn(&mut Value)| {
        let mut claims = assertion_claims(&server, "gateway", "agent");
        mutate(&mut claims);
        claims
    };

    let mut no_kid = key.header();
    no_kid.kid = None;
    let mut wrong_kid = key.header();
    wrong_kid.kid = Some("not-registered".into());

    let cases: Vec<(&str, String)> = vec![
        ("missing kid", key.sign_with_header(no_kid, &good(&|_| {}))),
        ("unknown kid", key.sign_with_header(wrong_kid, &good(&|_| {}))),
        ("bad signature", other.sign(&good(&|_| {}))),
        ("unknown issuer", key.sign(&good(&|c| c["iss"] = json!("someone-else")))),
        ("sub mismatch", key.sign(&good(&|c| c["sub"] = json!("impostor")))),
        ("audience mismatch", key.sign(&good(&|c| c["aud"] = json!("https://elsewhere.example/token")))),
        (
            "missing required claim",
            key.sign(&good(&|c| {
                c.as_object_mut()
                    .unwrap()
                    .remove("aud");
            })),
        ),
        (
            "assertion expired",
            key.sign(&good(&|c| {
                c["exp"] = json!(now() - 10);
                c["iat"] = json!(now() - 400);
            })),
        ),
        (
            "assertion lifetime too long",
            key.sign(&good(&|c| {
                c["exp"] = json!(now() + 7200);
            })),
        ),
        (
            "assertion issued in the future",
            key.sign(&good(&|c| {
                c["iat"] = json!(now() + 5000);
                c["exp"] = json!(now() + 5300);
            })),
        ),
        (
            "assertion lifetime too long",
            key.sign(&good(&|c| {
                c["iat"] = json!(now() - 30);
                c["exp"] = json!(now() + 3600 + 500);
            })),
        ),
        ("audience mismatch", key.sign(&good(&|c| c["aud"] = json!(server.issuer())))),
        (
            "missing jti",
            key.sign(&good(&|c| {
                c.as_object_mut()
                    .unwrap()
                    .remove("jti");
            })),
        ),
    ];
    let sent = cases.len();
    for (expected, assertion) in cases {
        let (status, body) = exchange(&server, &assertion).await;
        assert_eq!(status, 400, "{expected}: {body}");
        assert_eq!(body["error"], "invalid_grant", "{expected}");
        assert_eq!(body["error_description"], expected);
    }
    assert_eq!(server.token_request_count(), sent);
    assert!(
        server
            .accepted_assertions()
            .is_empty(),
        "a refused assertion is never recorded as accepted"
    );
}

#[tokio::test]
async fn jwt_bearer_rejects_a_replayed_jti() {
    let server = MockAuthServer::start().await;
    let key = SigningFixture::rs256(1).with_kid("k");
    server.register_jwt_client(jwt_client("gateway", "agent", &key));

    let assertion = key.sign(&assertion_claims(&server, "gateway", "agent"));
    assert_eq!(
        exchange(&server, &assertion)
            .await
            .0,
        200
    );
    let (status, body) = exchange(&server, &assertion).await;
    assert_eq!((status, body["error_description"].as_str()), (400, Some("jti replayed")));
    assert_eq!(
        server
            .accepted_assertions()
            .len(),
        1
    );
}

#[tokio::test]
async fn the_issuer_url_is_an_audience_only_when_the_mock_opts_in() {
    let server = MockAuthServer::builder()
        .accept_issuer_audience(true)
        .start()
        .await;
    let key = SigningFixture::rs256(1).with_kid("k");
    server.register_jwt_client(jwt_client("gateway", "agent", &key));

    let mut claims = assertion_claims(&server, "gateway", "agent");
    claims["aud"] = json!(server.issuer());
    assert_eq!(
        exchange(&server, &key.sign(&claims))
            .await
            .0,
        200
    );
}

#[tokio::test]
async fn faults_make_each_endpoint_answer_404_oversized_or_with_a_mismatched_issuer() {
    let server = MockAuthServer::start().await;
    server.register_client("c", "s");
    let urls = [(Endpoint::Discovery, server.rfc8414_metadata_url()), (Endpoint::Jwks, server.jwks_uri())];

    for (endpoint, url) in &urls {
        server.set_fault(*endpoint, Fault::NotFound);
        assert_eq!(get(url).await.0, 404, "{endpoint:?}");
        server.set_fault(*endpoint, Fault::Oversized);
        let (status, body) = get(url).await;
        assert_eq!(status, 200);
        assert!(body.len() > OVERSIZED_BODY_BYTES, "{endpoint:?}");
        server.set_fault(*endpoint, Fault::None);
        assert_eq!(get(url).await.0, 200, "{endpoint:?} recovers");
    }

    server.set_fault(Endpoint::Token, Fault::NotFound);
    let (status, _) =
        post_form(&server.token_endpoint(), &[("grant_type", CLIENT_CREDENTIALS_GRANT)], Some(("c", "s"))).await;
    assert_eq!(status, 404);
    server.set_fault(Endpoint::Token, Fault::Oversized);
    let (status, _) =
        post_form(&server.token_endpoint(), &[("grant_type", CLIENT_CREDENTIALS_GRANT)], Some(("c", "s"))).await;
    assert_eq!(status, 200);

    server.clear_faults();
    server.set_fault(Endpoint::Discovery, Fault::IssuerMismatch);
    let (_, doc) = get_json(&server.rfc8414_metadata_url()).await;
    assert_ne!(doc["issuer"], server.issuer());
    assert_eq!(doc["issuer"], format!("{}/impostor", server.issuer()));

    server.set_fault(Endpoint::Token, Fault::IssuerMismatch);
    let (_, body) =
        post_form(&server.token_endpoint(), &[("grant_type", CLIENT_CREDENTIALS_GRANT)], Some(("c", "s"))).await;
    let payload: Value = serde_json::from_slice(&base64_decode(
        body["access_token"]
            .as_str()
            .unwrap()
            .split('.')
            .nth(1)
            .unwrap(),
    ))
    .unwrap();
    assert_eq!(payload["iss"], format!("{}/impostor", server.issuer()));
}

#[tokio::test]
async fn the_request_log_records_each_request_without_credentials() {
    let server = MockAuthServer::start().await;
    server.register_client("agent-1", "s3cret-value");

    get(&server.openid_configuration_url()).await;
    get(&server.jwks_uri()).await;
    post_form(
        &server.token_endpoint(),
        &[("grant_type", CLIENT_CREDENTIALS_GRANT), ("scope", "read")],
        Some(("agent-1", "s3cret-value")),
    )
    .await;
    post_form(&server.token_endpoint(), &[("grant_type", CLIENT_CREDENTIALS_GRANT)], Some(("agent-1", "bad"))).await;
    get(&format!("{}/nowhere", server.origin())).await;

    assert_eq!(server.request_count(Endpoint::Discovery), 1);
    assert_eq!(server.request_count(Endpoint::Jwks), 1);
    assert_eq!(server.request_count(Endpoint::Token), 2);
    assert_eq!(server.token_request_count(), 2);

    let log = server.requests();
    assert_eq!(log.len(), 5);
    let token_entries: Vec<_> = log
        .iter()
        .filter(|e| e.endpoint == Some(Endpoint::Token))
        .collect();
    assert_eq!(token_entries[0].status, 200);
    assert_eq!(
        token_entries[0]
            .grant_type
            .as_deref(),
        Some(CLIENT_CREDENTIALS_GRANT)
    );
    assert_eq!(
        token_entries[0]
            .client_id
            .as_deref(),
        Some("agent-1")
    );
    assert_eq!(
        token_entries[0]
            .scope
            .as_deref(),
        Some("read")
    );
    assert_eq!(token_entries[1].status, 401);
    assert_eq!(log[4].endpoint, None);
    assert_eq!(log[4].status, 404);
    assert!(!format!("{log:?}").contains("s3cret-value"));
}

#[tokio::test]
async fn test_mode_admits_the_loopback_mock_to_the_oauth_and_egress_validators() {
    let server = MockAuthServer::builder()
        .issuer_shape(IssuerShape::Path("/tenant/a"))
        .start()
        .await;
    let _env = TestModeEnv::enabled_for(&server);

    for url in
        [server.token_endpoint(), server.jwks_uri(), server.rfc8414_metadata_url(), server.openid_configuration_url()]
    {
        let accepted = validate_oauth_endpoint_url(&url).unwrap_or_else(|e| panic!("{url}: {e}"));
        assert_eq!(accepted.as_str(), url);
    }
    assert!(validate_oauth_endpoint_url(&format!("{}/other", server.origin())).is_err(), "unlisted path stays blocked");

    let allowlist = bdd_egress_allowlist();
    let (client, target) =
        pinned_configured_client(&server.openid_configuration_url(), Duration::from_secs(5), allowlist.as_deref())
            .expect("allow-listed loopback discovery is pinned");
    assert_eq!(
        target.addrs[0]
            .ip()
            .to_string(),
        "127.0.0.1"
    );
    let doc: Value = client
        .get(server.openid_configuration_url())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(doc["issuer"], server.issuer());
}

#[tokio::test]
async fn the_seam_is_inert_without_test_mode() {
    let server = MockAuthServer::start().await;
    let egress = server.egress_allowlist();
    let oauth = server.oauth_endpoint_allowlist();

    let scenarios: [Scenario; 5] = [
        ("test mode unset", None, Some(&egress), Some(&oauth)),
        ("test mode false", Some("false"), Some(&egress), Some(&oauth)),
        ("test mode numeric", Some("1"), Some(&egress), Some(&oauth)),
        ("test mode on, allowlists unset", Some("true"), None, None),
        ("test mode on, allowlists blank", Some("true"), Some("  "), Some("")),
    ];
    for (name, mode, egress_list, oauth_list) in scenarios {
        let _env = TestModeEnv::with(mode, egress_list, oauth_list);
        let url = server.token_endpoint();

        let oauth_error = validate_oauth_endpoint_url(&url).expect_err(name);
        assert!(!oauth_error.is_empty(), "{name}");

        let allowlist = bdd_egress_allowlist();
        assert_eq!(allowlist, None, "{name}: the egress allowlist is not read");
        let egress_error =
            pinned_configured_client(&url, Duration::from_secs(5), allowlist.as_deref()).expect_err(name);
        assert!(matches!(egress_error, EgressError::Blocked(_)), "{name}: {egress_error:?}");
    }
}

#[tokio::test]
async fn test_mode_never_admits_cloud_metadata() {
    let metadata = "http://169.254.169.254/latest/meta-data/";
    let _env = TestModeEnv::enabled(metadata, metadata);
    assert!(validate_oauth_endpoint_url(metadata).is_err());
    let allowlist = bdd_egress_allowlist();
    assert!(matches!(
        pinned_configured_client(metadata, Duration::from_secs(5), allowlist.as_deref()),
        Err(EgressError::Blocked(_))
    ));
}

#[test]
fn the_guard_restores_the_previous_environment() {
    let lock = TestModeEnv::lock();
    unsafe {
        std::env::set_var("AG_TEST_MODE", "prior");
        std::env::set_var("AG_BDD_EGRESS_ALLOWLIST", "http://prior.example");
        std::env::remove_var("AG_BDD_OAUTH_ENDPOINT_ALLOWLIST");
    }
    let env = TestModeEnv::with_lock(lock, Some("true"), None, Some("http://127.0.0.1:1/token"));
    assert_eq!(std::env::var("AG_TEST_MODE").as_deref(), Ok("true"));
    assert_eq!(std::env::var("AG_BDD_EGRESS_ALLOWLIST").ok(), None);
    assert_eq!(std::env::var("AG_BDD_OAUTH_ENDPOINT_ALLOWLIST").as_deref(), Ok("http://127.0.0.1:1/token"));
    let _lock = env.restore();
    assert_eq!(std::env::var("AG_TEST_MODE").as_deref(), Ok("prior"));
    assert_eq!(std::env::var("AG_BDD_EGRESS_ALLOWLIST").as_deref(), Ok("http://prior.example"));
    assert_eq!(std::env::var("AG_BDD_OAUTH_ENDPOINT_ALLOWLIST").ok(), None);
    unsafe {
        std::env::remove_var("AG_TEST_MODE");
        std::env::remove_var("AG_BDD_EGRESS_ALLOWLIST");
    }
}
