//! Step bindings for the Security Token Service token endpoint
//! (`/oauth2/token`) — RFC 8693 token exchange and ID-JAG issuance.

use cucumber::{given, then, when};
use serde_json::Value;

use crate::world::{RecordedResponse, SurfaceWorld};

const GRANT_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const GRANT_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const SUBJECT_TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
const REQUESTED_ID_JAG: &str = "urn:ietf:params:oauth:token-type:id-jag";
const SUBJECT_ISSUER: &str = "https://bdd-idp.example";
/// The identity API is mounted under `/api` in the BDD gateway, so the token
/// endpoint route `/oauth2/token` resolves at `/api/oauth2/token`.
const TOKEN_ENDPOINT: &str = "/api/oauth2/token";

// ── Given helpers ─────────────────────────────────────────────────────────────

/// Register a `Static` JWT verification strategy for the subject issuer so the
/// gateway can verify the identity assertions the agent presents.
async fn ensure_subject_strategy(world: &mut SurfaceWorld) {
    crate::steps::when::ensure_admin_session(world).await;
    let admin = world
        .admin_client
        .clone()
        .expect("admin client must exist");
    let response = admin
        .send_recorded_json(
            reqwest::Method::POST,
            "/v1/jwt-verification-strategies",
            Some(&serde_json::json!({
                "name": "BDD subject IdP",
                "expected_issuer": SUBJECT_ISSUER,
                "jwks_source": {
                    "type": "static",
                    "jwks": [crate::bdd_support::jwt::public_jwk()],
                },
            })),
        )
        .await
        .unwrap_or_else(|error| panic!("register subject verification strategy: {error}"));
    assert!(
        response.status == 201 || response.status == 409,
        "subject strategy setup expected 201/409, got {} body {}",
        response.status,
        response.body
    );
}

/// Seed a managed connection (STS client) for `agent`, backed by a stored client
/// secret, allowing the given audiences (empty = any) and optionally ID-JAG.
async fn create_managed_connection(
    world: &mut SurfaceWorld,
    agent: &str,
    allowed_audiences: Vec<String>,
    issue_id_jag: bool,
) {
    create_managed_connection_full(world, agent, allowed_audiences, Vec::new(), issue_id_jag, true).await;
}

/// Seed a managed connection with full control over allowed scopes, ID-JAG
/// permission, and whether a client secret is configured. A connection created
/// with `with_secret = false` has no `client_secret_ref`, so the gateway must
/// reject it fail-closed at authentication.
async fn create_managed_connection_full(
    world: &mut SurfaceWorld,
    agent: &str,
    allowed_audiences: Vec<String>,
    allowed_scopes: Vec<String>,
    issue_id_jag: bool,
    with_secret: bool,
) {
    crate::steps::when::ensure_admin_session(world).await;
    let admin = world
        .admin_client
        .clone()
        .expect("admin client must exist");

    let mut connection = serde_json::json!({
        "client_id": agent,
        "name": format!("BDD agent {agent}"),
        "allowed_audiences": allowed_audiences,
        "allowed_scopes": allowed_scopes,
        "allowed_subject_token_types": [],
        "allow_impersonation": false,
        "issue_id_jag": issue_id_jag,
    });

    if with_secret {
        let secret_id = format!("sts-secret-{agent}");
        let secret_value = format!("bdd-secret-{agent}");
        let secret_response = admin
            .send_recorded_json(
                reqwest::Method::POST,
                "/api/v1/secrets/new",
                Some(&serde_json::json!({
                    "name": format!("STS client secret for {agent}"),
                    "secret_id": secret_id,
                    "description": "BDD STS client secret",
                    "value": secret_value,
                    "secret_type": "ApiKey",
                    "tags": ["bdd"],
                })),
            )
            .await
            .unwrap_or_else(|error| panic!("create STS client secret: {error}"));
        assert!(
            secret_response.status == 201 || secret_response.status == 409,
            "STS client secret setup expected 201/409, got {} body {}",
            secret_response.status,
            secret_response.body
        );
        connection["client_secret_ref"] = serde_json::Value::String(secret_id);
        world
            .sts_client_secrets
            .insert(agent.to_string(), secret_value);
    }

    let connection_response = admin
        .send_recorded_json(reqwest::Method::POST, "/v1/sts/clients", Some(&connection))
        .await
        .unwrap_or_else(|error| panic!("create managed connection: {error}"));
    assert_eq!(
        connection_response.status, 201,
        "managed connection creation expected 201, got {} body {}",
        connection_response.status, connection_response.body
    );
}

// ── When helper ───────────────────────────────────────────────────────────────

/// Drive one `POST /oauth2/token` exchange as `agent`, presenting the held
/// identity assertion and authenticating with HTTP Basic client credentials.
async fn exchange_token(
    world: &mut SurfaceWorld,
    agent: &str,
    requested_token_type: Option<&str>,
    audience: Option<&str>,
) {
    let assertion = world
        .sts_assertions
        .get(agent)
        .cloned()
        .expect("agent must hold an identity assertion");
    exchange_subject_token(world, agent, assertion, requested_token_type, audience).await;
}

/// Drive one `POST /oauth2/token` exchange as `agent` presenting `subject_token`,
/// authenticating with HTTP Basic client credentials.
async fn exchange_subject_token(
    world: &mut SurfaceWorld,
    agent: &str,
    subject_token: String,
    requested_token_type: Option<&str>,
    audience: Option<&str>,
) {
    crate::steps::when::ensure_gateway_running(world).await;
    let port = world
        .infra
        .as_ref()
        .expect("gateway infra must be running")
        .gateway_port;
    let url = format!("http://127.0.0.1:{port}{TOKEN_ENDPOINT}");

    let secret = world
        .sts_client_secrets
        .get(agent)
        .cloned()
        .unwrap_or_default();

    let mut form = vec![
        ("grant_type".to_string(), GRANT_TOKEN_EXCHANGE.to_string()),
        ("subject_token".to_string(), subject_token),
        ("subject_token_type".to_string(), SUBJECT_TOKEN_TYPE_JWT.to_string()),
    ];
    if let Some(requested) = requested_token_type {
        form.push(("requested_token_type".to_string(), requested.to_string()));
    }
    if let Some(aud) = audience {
        form.push(("audience".to_string(), aud.to_string()));
    }

    let response = crate::bdd_support::caller::post_form(&reqwest::Client::new(), &url, &form, Some((agent, &secret)))
        .await
        .unwrap_or_else(|error| panic!("token exchange request: {error}"));

    world.caller_response = Some(RecordedResponse {
        status: response.status,
        headers: response.headers,
        body: response.body,
    });
}

/// POST an already-built form to the token endpoint as `agent` (HTTP Basic
/// client authentication) and return the raw recorded response.
async fn post_token_form(
    world: &SurfaceWorld,
    agent: &str,
    form: &[(String, String)],
) -> crate::bdd_support::caller::RecordedHttpResponse {
    let port = world
        .infra
        .as_ref()
        .expect("gateway infra must be running")
        .gateway_port;
    let url = format!("http://127.0.0.1:{port}{TOKEN_ENDPOINT}");
    let secret = world
        .sts_client_secrets
        .get(agent)
        .cloned()
        .unwrap_or_default();
    crate::bdd_support::caller::post_form(&reqwest::Client::new(), &url, form, Some((agent, &secret)))
        .await
        .unwrap_or_else(|error| panic!("token endpoint request: {error}"))
}

/// Build a token-exchange form requesting an ID-JAG for `audience`, optionally
/// constraining `scope`.
fn id_jag_issue_form(
    assertion: String,
    audience: &str,
    scope: Option<&str>,
) -> Vec<(String, String)> {
    let mut form = vec![
        ("grant_type".to_string(), GRANT_TOKEN_EXCHANGE.to_string()),
        ("subject_token".to_string(), assertion),
        ("subject_token_type".to_string(), SUBJECT_TOKEN_TYPE_JWT.to_string()),
        ("requested_token_type".to_string(), REQUESTED_ID_JAG.to_string()),
        ("audience".to_string(), audience.to_string()),
    ];
    if let Some(scope) = scope {
        form.push(("scope".to_string(), scope.to_string()));
    }
    form
}

/// Decode (without verifying) the claims of a compact JWT / ID-JAG.
fn token_claims(token: &str) -> Value {
    use base64::Engine as _;
    let payload = token
        .split('.')
        .nth(1)
        .expect("token must have a payload segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("token payload should be base64url encoded");
    serde_json::from_slice(&bytes).expect("token payload should be JSON")
}

/// Decode (without verifying) the `iss` claim of a compact JWT / ID-JAG.
fn token_issuer(token: &str) -> String {
    token_claims(token)
        .get("iss")
        .and_then(|value| value.as_str())
        .expect("token must carry an iss claim")
        .to_string()
}

/// Register a JWT verification strategy so the gateway trusts the ID-JAGs it
/// issued itself. In this single-gateway loopback the same gateway is both the
/// ID-JAG issuer (IdP) and the redeeming resource AS, so redemption's signature
/// check needs a strategy for the gateway's own issuer, backed by its JWKS.
async fn ensure_gateway_self_trust(
    world: &mut SurfaceWorld,
    gateway_did: &str,
) {
    let port = world
        .infra
        .as_ref()
        .expect("gateway infra must be running")
        .gateway_port;
    let jwks_url = format!("http://127.0.0.1:{port}/api/oauth2/jwks.json");
    let jwks: Value = reqwest::Client::new()
        .get(&jwks_url)
        .send()
        .await
        .unwrap_or_else(|error| panic!("fetch gateway jwks: {error}"))
        .json()
        .await
        .unwrap_or_else(|error| panic!("parse gateway jwks: {error}"));
    let keys = jwks
        .get("keys")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));

    crate::steps::when::ensure_admin_session(world).await;
    let admin = world
        .admin_client
        .clone()
        .expect("admin client must exist");
    let response = admin
        .send_recorded_json(
            reqwest::Method::POST,
            "/v1/jwt-verification-strategies",
            Some(&serde_json::json!({
                "name": "BDD gateway self-trust",
                "expected_issuer": gateway_did,
                "jwks_source": { "type": "static", "jwks": keys },
            })),
        )
        .await
        .unwrap_or_else(|error| panic!("register gateway self-trust strategy: {error}"));
    assert!(
        response.status == 201 || response.status == 409,
        "gateway self-trust strategy expected 201/409, got {} body {}",
        response.status,
        response.body
    );
}

/// Discover the gateway's issuer DID (cached on the world). An ID-JAG is only
/// redeemable at the gateway that issued it, so its audience must be this DID;
/// it is learned by issuing a throwaway ID-JAG and reading its `iss`.
async fn gateway_issuer_did(
    world: &mut SurfaceWorld,
    agent: &str,
) -> String {
    if let Some(did) = world
        .gateway_issuer_did
        .clone()
    {
        return did;
    }
    crate::steps::when::ensure_gateway_running(world).await;
    let assertion = world
        .sts_assertions
        .get(agent)
        .cloned()
        .expect("agent must hold an identity assertion");
    let form = id_jag_issue_form(assertion, "urn:sts:bootstrap", None);
    let response = post_token_form(world, agent, &form).await;
    assert_eq!(response.status, 200, "bootstrap ID-JAG issuance failed: {}", response.body);
    let token = response
        .body
        .get("access_token")
        .and_then(|value| value.as_str())
        .expect("bootstrap response must carry an access_token")
        .to_string();
    let did = token_issuer(&token);
    ensure_gateway_self_trust(world, &did).await;
    world.gateway_issuer_did = Some(did.clone());
    did
}

/// Obtain an ID-JAG for `agent` addressed to this gateway (so it is redeemable
/// here), optionally granting `scope`, and store it for later redemption.
async fn obtain_id_jag(
    world: &mut SurfaceWorld,
    agent: &str,
    scope: Option<&str>,
) {
    let audience = gateway_issuer_did(world, agent).await;
    let assertion = world
        .sts_assertions
        .get(agent)
        .cloned()
        .expect("agent must hold an identity assertion");
    let form = id_jag_issue_form(assertion, &audience, scope);
    let response = post_token_form(world, agent, &form).await;
    assert_eq!(response.status, 200, "ID-JAG issuance failed: {}", response.body);
    let token = response
        .body
        .get("access_token")
        .and_then(|value| value.as_str())
        .expect("ID-JAG response must carry an access_token")
        .to_string();
    world
        .sts_id_jags
        .insert(agent.to_string(), token);
}

/// Redeem `owner`'s stored ID-JAG (RFC 7523 `jwt-bearer`) authenticating as
/// `redeemer`, for an access token optionally scoped to `audience`/`scope`.
/// Records the response as the caller response.
async fn redeem_id_jag(
    world: &mut SurfaceWorld,
    redeemer: &str,
    owner: &str,
    audience: Option<&str>,
    scope: Option<&str>,
) {
    crate::steps::when::ensure_gateway_running(world).await;
    let id_jag = world
        .sts_id_jags
        .get(owner)
        .cloned()
        .expect("an ID-JAG must have been obtained first");
    let mut form = vec![("grant_type".to_string(), GRANT_JWT_BEARER.to_string()), ("assertion".to_string(), id_jag)];
    if let Some(audience) = audience {
        form.push(("audience".to_string(), audience.to_string()));
    }
    if let Some(scope) = scope {
        form.push(("scope".to_string(), scope.to_string()));
    }
    let response = post_token_form(world, redeemer, &form).await;
    world.caller_response = Some(RecordedResponse {
        status: response.status,
        headers: response.headers,
        body: response.body,
    });
}

// ── Then helpers ──────────────────────────────────────────────────────────────

fn response_body(world: &SurfaceWorld) -> &Value {
    &world
        .caller_response
        .as_ref()
        .expect("caller response must be set")
        .body
}

/// Decode (without verifying) the claims of the issued `access_token`.
fn issued_token_claims(world: &SurfaceWorld) -> Value {
    token_claims(
        response_body(world)
            .get("access_token")
            .and_then(|value| value.as_str())
            .expect("response must carry an access_token"),
    )
}

fn audience_includes(
    claims: &Value,
    audience: &str,
) -> bool {
    match claims.get("aud") {
        Some(Value::String(single)) => single == audience,
        Some(Value::Array(items)) => items
            .iter()
            .any(|item| item.as_str() == Some(audience)),
        _ => false,
    }
}

// ── Given bindings ────────────────────────────────────────────────────────────

#[given(expr = "the operator has a managed connection for agent {string} allowing audience {string}")]
async fn managed_connection_allowing_audience(
    world: &mut SurfaceWorld,
    agent: String,
    audience: String,
) {
    create_managed_connection(world, &agent, vec![audience], false).await;
}

#[given(expr = "the operator has no managed connection for agent {string}")]
async fn no_managed_connection(
    world: &mut SurfaceWorld,
    _agent: String,
) {
    crate::steps::when::ensure_gateway_running(world).await;
}

#[given(expr = "the operator has a managed connection for agent {string} that cannot issue ID-JAG")]
async fn managed_connection_cannot_issue_id_jag(
    world: &mut SurfaceWorld,
    agent: String,
) {
    create_managed_connection(world, &agent, Vec::new(), false).await;
}

#[given(expr = "the operator has a managed connection for agent {string} that can issue ID-JAG")]
async fn managed_connection_can_issue_id_jag(
    world: &mut SurfaceWorld,
    agent: String,
) {
    create_managed_connection(world, &agent, Vec::new(), true).await;
}

/// Give `agent` an identity assertion from the subject IdP for `subject`,
/// valid for `lifetime_secs`.
async fn hold_identity_assertion(
    world: &mut SurfaceWorld,
    agent: String,
    subject: String,
    lifetime_secs: u64,
) {
    ensure_subject_strategy(world).await;
    let now = crate::bdd_support::jwt::now_secs();
    let assertion = crate::bdd_support::jwt::sign_jwt(serde_json::json!({
        "iss": SUBJECT_ISSUER,
        "sub": subject,
        "iat": now,
        "exp": now + lifetime_secs,
    }));
    world
        .sts_assertions
        .insert(agent, assertion);
}

#[given(expr = "agent {string} holds an identity assertion for subject {string}")]
async fn agent_holds_identity_assertion(
    world: &mut SurfaceWorld,
    agent: String,
    subject: String,
) {
    hold_identity_assertion(world, agent, subject, 3600).await;
}

#[given(expr = "agent {string} holds an identity assertion for subject {string} that expires in {int} seconds")]
async fn agent_holds_expiring_identity_assertion(
    world: &mut SurfaceWorld,
    agent: String,
    subject: String,
    lifetime_secs: u64,
) {
    hold_identity_assertion(world, agent, subject, lifetime_secs).await;
}

#[given(
    expr = "the operator has a managed connection for agent {string} that can issue ID-JAG allowing scopes {string}"
)]
async fn managed_connection_can_issue_id_jag_with_scopes(
    world: &mut SurfaceWorld,
    agent: String,
    scopes: String,
) {
    let allowed_scopes = scopes
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    create_managed_connection_full(world, &agent, Vec::new(), allowed_scopes, true, true).await;
}

#[given(expr = "the operator has a managed connection for agent {string} with no client secret")]
async fn managed_connection_without_secret(
    world: &mut SurfaceWorld,
    agent: String,
) {
    create_managed_connection_full(world, &agent, Vec::new(), Vec::new(), false, false).await;
}

#[given(expr = "agent {string} has obtained an ID-JAG redeemable at the gateway")]
async fn agent_obtained_id_jag(
    world: &mut SurfaceWorld,
    agent: String,
) {
    obtain_id_jag(world, &agent, None).await;
}

#[given(expr = "agent {string} has obtained an ID-JAG granting scope {string}")]
async fn agent_obtained_id_jag_with_scope(
    world: &mut SurfaceWorld,
    agent: String,
    scope: String,
) {
    obtain_id_jag(world, &agent, Some(&scope)).await;
}

#[given(expr = "agent {string} has redeemed the ID-JAG for a token scoped to audience {string}")]
async fn agent_has_redeemed_id_jag(
    world: &mut SurfaceWorld,
    agent: String,
    audience: String,
) {
    redeem_id_jag(world, &agent, &agent, Some(&audience), None).await;
}

#[given(expr = "agent {string} has exchanged the identity assertion for a token scoped to audience {string}")]
async fn agent_has_exchanged_identity_assertion(
    world: &mut SurfaceWorld,
    agent: String,
    audience: String,
) {
    exchange_token(world, &agent, None, Some(&audience)).await;
    let body = response_body(world);
    let token = body
        .get("access_token")
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| panic!("token exchange must issue a token, got body {body}"))
        .to_string();
    world
        .sts_issued_tokens
        .insert(agent, token);
}

// ── When bindings ─────────────────────────────────────────────────────────────

#[when(expr = "agent {string} exchanges the identity assertion for a token scoped to audience {string}")]
async fn exchange_scoped(
    world: &mut SurfaceWorld,
    agent: String,
    audience: String,
) {
    exchange_token(world, &agent, None, Some(&audience)).await;
}

#[when(expr = "agent {string} exchanges the identity assertion for a token")]
async fn exchange_plain(
    world: &mut SurfaceWorld,
    agent: String,
) {
    exchange_token(world, &agent, None, None).await;
}

#[when(expr = "agent {string} exchanges the ID-JAG issued to agent {string} for a token")]
async fn exchange_other_agents_id_jag(
    world: &mut SurfaceWorld,
    agent: String,
    owner: String,
) {
    let id_jag = world
        .sts_id_jags
        .get(&owner)
        .cloned()
        .expect("an ID-JAG must have been obtained first");
    exchange_subject_token(world, &agent, id_jag, None, None).await;
}

#[when(expr = "agent {string} exchanges the issued token for a token scoped to audience {string}")]
async fn exchange_issued_token(
    world: &mut SurfaceWorld,
    agent: String,
    audience: String,
) {
    let token = world
        .sts_issued_tokens
        .get(&agent)
        .cloned()
        .expect("agent must have exchanged a token first");
    exchange_subject_token(world, &agent, token, None, Some(&audience)).await;
}

#[when(expr = "agent {string} requests an ID-JAG for audience {string}")]
async fn request_id_jag(
    world: &mut SurfaceWorld,
    agent: String,
    audience: String,
) {
    exchange_token(world, &agent, Some(REQUESTED_ID_JAG), Some(&audience)).await;
}

#[when(expr = "agent {string} redeems the ID-JAG for a token scoped to audience {string}")]
async fn redeem_scoped(
    world: &mut SurfaceWorld,
    agent: String,
    audience: String,
) {
    redeem_id_jag(world, &agent, &agent, Some(&audience), None).await;
}

#[when(expr = "agent {string} redeems the same ID-JAG again")]
async fn redeem_again(
    world: &mut SurfaceWorld,
    agent: String,
) {
    redeem_id_jag(world, &agent, &agent, None, None).await;
}

#[when(expr = "agent {string} redeems the ID-JAG issued to agent {string}")]
async fn redeem_other_agents_id_jag(
    world: &mut SurfaceWorld,
    redeemer: String,
    owner: String,
) {
    redeem_id_jag(world, &redeemer, &owner, None, None).await;
}

#[when(expr = "agent {string} redeems the ID-JAG requesting scope {string}")]
async fn redeem_requesting_scope(
    world: &mut SurfaceWorld,
    agent: String,
    scope: String,
) {
    redeem_id_jag(world, &agent, &agent, None, Some(&scope)).await;
}

// ── Then bindings ─────────────────────────────────────────────────────────────

#[then(expr = "the issued token names subject {string}")]
fn issued_token_names_subject(
    world: &mut SurfaceWorld,
    subject: String,
) {
    let claims = issued_token_claims(world);
    assert_eq!(
        claims
            .get("sub")
            .and_then(|value| value.as_str()),
        Some(subject.as_str()),
        "expected issued token sub {subject}, got claims {claims}"
    );
}

#[then(expr = "the issued token names agent {string} as the delegating actor")]
fn issued_token_names_actor(
    world: &mut SurfaceWorld,
    agent: String,
) {
    let claims = issued_token_claims(world);
    let actor = claims
        .get("act")
        .and_then(|act| act.get("sub"))
        .and_then(|value| value.as_str());
    assert_eq!(actor, Some(agent.as_str()), "expected issued token act.sub {agent}, got claims {claims}");
}

#[then(expr = "the issued token is scoped to audience {string}")]
fn issued_token_scoped_to_audience(
    world: &mut SurfaceWorld,
    audience: String,
) {
    let claims = issued_token_claims(world);
    assert!(
        audience_includes(&claims, &audience),
        "expected issued token aud to include {audience}, got claims {claims}"
    );
}

#[then(expr = "the response is an {string} error")]
fn response_is_error(
    world: &mut SurfaceWorld,
    code: String,
) {
    let body = response_body(world);
    assert_eq!(
        body.get("error")
            .and_then(|value| value.as_str()),
        Some(code.as_str()),
        "expected OAuth error {code}, got body {body}"
    );
}

#[then(expr = "no token is issued")]
fn no_token_issued(world: &mut SurfaceWorld) {
    let body = response_body(world);
    assert!(
        body.get("access_token")
            .is_none(),
        "expected no access_token in the response, got body {body}"
    );
}

#[then(expr = "the issued token is an ID-JAG bound to audience {string}")]
fn issued_token_is_id_jag(
    world: &mut SurfaceWorld,
    audience: String,
) {
    let issued_type = response_body(world)
        .get("issued_token_type")
        .and_then(|value| value.as_str())
        .map(|s| s.to_string());
    assert_eq!(
        issued_type.as_deref(),
        Some(REQUESTED_ID_JAG),
        "expected issued_token_type id-jag, got {issued_type:?}"
    );
    let claims = issued_token_claims(world);
    assert!(audience_includes(&claims, &audience), "expected ID-JAG aud {audience}, got claims {claims}");
}

#[then(expr = "the issued token grants only scope {string}")]
fn issued_token_grants_only_scope(
    world: &mut SurfaceWorld,
    scope: String,
) {
    let claims = issued_token_claims(world);
    assert_eq!(
        claims
            .get("scope")
            .and_then(|value| value.as_str()),
        Some(scope.as_str()),
        "expected issued token scope {scope}, got claims {claims}"
    );
}

#[then(expr = "the issued token expires no later than the identity assertion of agent {string}")]
fn issued_token_expires_no_later_than_identity_assertion(
    world: &mut SurfaceWorld,
    agent: String,
) {
    let assertion = token_claims(
        world
            .sts_assertions
            .get(&agent)
            .expect("agent must hold an identity assertion"),
    );
    let issued = issued_token_claims(world);
    let expiry = |claims: &Value| {
        claims
            .get("exp")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("token must carry exp, got claims {claims}"))
    };
    assert!(
        expiry(&issued) <= expiry(&assertion),
        "expected issued token exp {} to be no later than the identity assertion exp {}",
        expiry(&issued),
        expiry(&assertion)
    );
}
