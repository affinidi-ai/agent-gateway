//! The provider's signed tokens. The ID token check (OpenID Connect Core 1.0 section 3.1.3.7):
//! the signature against the provider's published keys, then the issuer, audience, authorized
//! party, expiry, issue time, nonce, subject and session id. The logout token check (Back-Channel
//! Logout 1.0 section 2.6): the same signature, issuer and audience, then its type, issue time,
//! event, subject or session, and a `jti` never seen before.

use dashmap::DashMap;
use jsonwebtoken::{Algorithm, Header, Validation, decode, decode_header};
use serde_json::{Map, Value};

use super::config::OidcConfig;
use crate::auth::session::OidcSessionBinding;
use crate::jwt_bearer::JwksClient;
use crate::jwt_bearer::errors::JwtBearerError;

/// Clock skew allowed on `exp` and `iat`.
const LEEWAY_SECS: u64 = 60;
/// The longest `sub`, `sid` or `jti` accepted.
const MAX_IDENTIFIER_CLAIM_LEN: usize = 255;
/// The event a logout token must carry.
const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";
/// Most logout token ids remembered at once; at the cap the one that would be forgotten soonest
/// is dropped.
const MAX_SEEN_LOGOUT_TOKENS: usize = 10_000;

/// A verified ID token: the account it names, the provider's session id when it gives one, and
/// all its claims. Its `Debug` output names the subject and claim names only, never claim values.
pub struct VerifiedIdToken {
    pub subject: String,
    pub sid: Option<String>,
    pub claims: Map<String, Value>,
}

impl std::fmt::Debug for VerifiedIdToken {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("VerifiedIdToken")
            .field("subject", &self.subject)
            .field(
                "claims",
                &self
                    .claims
                    .keys()
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Why an ID token or a logout token was not accepted. The detail names the check that failed,
/// for the log; it never contains the token.
#[derive(Debug)]
pub enum TokenFailure {
    /// The provider's published keys could not be fetched.
    KeysUnavailable(String),
    /// No published key matches the token's `kid`, and the keys were fetched again too recently
    /// to look for a key published since.
    KeyNotFoundDuringCooldown(String),
    /// The token did not pass a check.
    Invalid(String),
}

impl std::fmt::Display for TokenFailure {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::KeysUnavailable(detail) | Self::KeyNotFoundDuringCooldown(detail) | Self::Invalid(detail) => {
                f.write_str(detail)
            }
        }
    }
}

/// A verified logout token: what it signs out, and its `jti`.
#[derive(Debug)]
pub struct VerifiedLogoutToken {
    pub target: LogoutTarget,
    pub jti: String,
}

/// What a verified logout token signs out: one provider session (`sid`), or every session of one
/// account (`sub`).
#[derive(Debug, PartialEq, Eq)]
pub struct LogoutTarget {
    pub subject: Option<String>,
    pub sid: Option<String>,
}

impl LogoutTarget {
    /// Whether a session bound to `binding` is one this logout ends: the same issuer, and the
    /// same `sid` (and `sub`, when the token gives both), or, for a token with only `sub`, the
    /// same account. A session whose ID token had no `sid` cannot be told apart from the
    /// account's other provider sessions, so a token with `sid` ends it when its `sub` names the
    /// account.
    pub fn matches(
        &self,
        issuer: &str,
        binding: &OidcSessionBinding,
    ) -> bool {
        let same_account = self
            .subject
            .as_ref()
            .is_some_and(|subject| subject == &binding.subject);
        binding.issuer == issuer
            && match (&self.sid, &binding.sid) {
                (Some(sid), Some(bound)) => {
                    sid == bound
                        && self
                            .subject
                            .as_ref()
                            .is_none_or(|subject| subject == &binding.subject)
                }
                (Some(_), None) | (None, _) => same_account,
            }
    }
}

/// Logout token ids already used, each kept until its token would no longer be accepted, so a
/// captured logout token cannot be replayed.
#[derive(Default)]
pub struct SeenLogoutTokens {
    ids: DashMap<String, i64>,
}

impl SeenLogoutTokens {
    /// Record `jti` until `until` (a Unix time), that second included. False when it is already
    /// recorded. The entry API makes two copies of one token racing each other record it once.
    fn remember(
        &self,
        jti: &str,
        until: i64,
        now: i64,
    ) -> bool {
        self.ids
            .retain(|_, kept_until| *kept_until >= now);
        if self.ids.len() >= MAX_SEEN_LOGOUT_TOKENS && !self.ids.contains_key(jti) {
            // Collect the key first so no shard lock is held across the remove. `jti` itself is
            // never the one dropped, so a replay is refused at the cap too.
            let soonest = self
                .ids
                .iter()
                .filter(|entry| entry.key() != jti)
                .min_by_key(|entry| *entry.value())
                .map(|entry| entry.key().clone());
            if let Some(key) = soonest {
                self.ids.remove(&key);
            }
        }
        match self
            .ids
            .entry(jti.to_string())
        {
            dashmap::Entry::Occupied(_) => false,
            dashmap::Entry::Vacant(slot) => {
                slot.insert(until);
                true
            }
        }
    }

    /// Forget `jti`, so the provider can send its logout token again.
    pub fn forget(
        &self,
        jti: &str,
    ) {
        self.ids.remove(jti);
    }
}

/// Verify an ID token from the token endpoint, issued for the sign-in whose nonce is
/// `expected_nonce`. A token without `kid` matches only a published key without one.
pub async fn verify_id_token(
    token: &str,
    config: &OidcConfig,
    jwks: &JwksClient,
    jwks_uri: &str,
    expected_nonce: &str,
) -> Result<VerifiedIdToken, TokenFailure> {
    let (_, claims) = signed_claims(token, config, jwks, jwks_uri, &["exp", "iss", "aud", "sub"]).await?;
    check_claims(&claims, config, expected_nonce, chrono::Utc::now().timestamp()).map_err(TokenFailure::Invalid)?;
    Ok(VerifiedIdToken {
        subject: string_claim(&claims, "sub").unwrap_or_default(),
        sid: string_claim(&claims, "sid"),
        claims,
    })
}

/// Verify a logout token the provider posted, and record its `jti` so it works once. The `jti`
/// is recorded only once every other check has passed, so tokens that do not verify cannot fill
/// the record.
pub async fn verify_logout_token(
    token: &str,
    config: &OidcConfig,
    jwks: &JwksClient,
    jwks_uri: &str,
    seen: &SeenLogoutTokens,
) -> Result<VerifiedLogoutToken, TokenFailure> {
    let (header, claims) = signed_claims(token, config, jwks, jwks_uri, &["exp", "iss", "aud"]).await?;
    check_logout_type(&header).map_err(TokenFailure::Invalid)?;
    let now = chrono::Utc::now().timestamp();
    let (target, jti, remember_until) =
        check_logout_claims(&claims, &config.client_id, now).map_err(TokenFailure::Invalid)?;
    if !seen.remember(&jti, remember_until, now) {
        return Err(TokenFailure::Invalid("jti was already used".to_string()));
    }
    Ok(VerifiedLogoutToken { target, jti })
}

/// Check the header's algorithm against `id_token_signing_algs`, the signature against the
/// provider's keys, `iss`, `aud`, `exp`, `nbf` when present, and that the registered claims in `required` are
/// present. Returns the header and claims. Keys are cached under their `jwks_uri`, so a key set
/// the provider moves is read afresh rather than matched against the old one.
async fn signed_claims(
    token: &str,
    config: &OidcConfig,
    jwks: &JwksClient,
    jwks_uri: &str,
    required: &[&str],
) -> Result<(Header, Map<String, Value>), TokenFailure> {
    let header = decode_header(token).map_err(|e| TokenFailure::Invalid(format!("unreadable header: {e}")))?;
    if !config
        .id_token_signing_algs
        .contains(&header.alg)
    {
        return Err(TokenFailure::Invalid(format!("algorithm {:?} is not in id_token_signing_algs", header.alg)));
    }
    let jwk = jwks
        .get_key(
            jwks_uri,
            jwks_uri,
            header
                .kid
                .as_deref()
                .unwrap_or_default(),
        )
        .await
        .map_err(|e| match e {
            JwtBearerError::KeyNotFound(_) => TokenFailure::Invalid(format!("no published key matches: {e}")),
            JwtBearerError::KeyNotFoundDuringCooldown(_) => TokenFailure::KeyNotFoundDuringCooldown(e.to_string()),
            _ => TokenFailure::KeysUnavailable(format!("signing key unavailable: {e}")),
        })?;
    if let Some(key_alg) = &jwk.alg
        && key_alg
            .parse::<Algorithm>()
            .ok()
            != Some(header.alg)
    {
        return Err(TokenFailure::Invalid(format!("the signing key is for {key_alg}, not {:?}", header.alg)));
    }
    if jwk
        .key_use
        .as_deref()
        .is_some_and(|key_use| key_use != "sig")
    {
        return Err(TokenFailure::Invalid("the signing key is not published for signatures".to_string()));
    }
    let key = crate::jwt_bearer::validator::decoding_key_from_jwk(&jwk)
        .map_err(|e| TokenFailure::Invalid(format!("signing key unusable: {e}")))?;

    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[&config.issuer]);
    validation.set_audience(&[&config.client_id]);
    validation.set_required_spec_claims(required);
    validation.leeway = LEEWAY_SECS;
    validation.validate_nbf = true;
    let claims = decode::<Map<String, Value>>(token, &key, &validation)
        .map_err(|e| TokenFailure::Invalid(format!("{e}")))?
        .claims;
    Ok((header, claims))
}

fn string_claim(
    claims: &Map<String, Value>,
    name: &str,
) -> Option<String> {
    claims
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// An optional claim that, when present, must be a string of 1 to 255 characters.
fn short_string_claim(
    claims: &Map<String, Value>,
    name: &str,
) -> Result<Option<String>, String> {
    match claims.get(name) {
        None => Ok(None),
        Some(Value::String(value)) if !value.is_empty() && value.len() <= MAX_IDENTIFIER_CLAIM_LEN => {
            Ok(Some(value.clone()))
        }
        Some(_) => Err(format!("{name} must be a string of 1 to {MAX_IDENTIFIER_CLAIM_LEN} characters")),
    }
}

/// A logout token's `typ`, when present, is `logout+jwt`, in any case, with or without the
/// `application/` prefix (Back-Channel Logout 1.0 section 2.4).
fn check_logout_type(header: &Header) -> Result<(), String> {
    match header
        .typ
        .as_deref()
        .map(str::to_ascii_lowercase)
    {
        None => Ok(()),
        Some(typ) if typ == "logout+jwt" || typ == "application/logout+jwt" => Ok(()),
        Some(typ) => Err(format!("typ is {typ:?}, not logout+jwt")),
    }
}

/// The logout token checks `jsonwebtoken` does not make. Returns what to sign out, the `jti`,
/// and until when to remember it: while its `exp`, plus the leeway, still accepts it.
fn check_logout_claims(
    claims: &Map<String, Value>,
    client_id: &str,
    now: i64,
) -> Result<(LogoutTarget, String, i64), String> {
    check_issued_at(claims, now)?;
    let expires_at = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or("exp is missing or not a whole number")?;
    check_authorized_party(claims, client_id)?;
    if claims.contains_key("nonce") {
        return Err("a logout token must not carry a nonce".to_string());
    }
    if !claims
        .get("events")
        .and_then(Value::as_object)
        .and_then(|events| events.get(BACKCHANNEL_LOGOUT_EVENT))
        .is_some_and(Value::is_object)
    {
        return Err("events does not hold the back-channel logout event".to_string());
    }
    let target = LogoutTarget {
        subject: short_string_claim(claims, "sub")?,
        sid: short_string_claim(claims, "sid")?,
    };
    if target.subject.is_none() && target.sid.is_none() {
        return Err("neither sub nor sid is present".to_string());
    }
    let jti = short_string_claim(claims, "jti")?.ok_or("jti is missing")?;
    Ok((target, jti, expires_at.saturating_add(LEEWAY_SECS as i64)))
}

/// `iat` must be present and not ahead of `now` by more than the leeway.
fn check_issued_at(
    claims: &Map<String, Value>,
    now: i64,
) -> Result<(), String> {
    let issued_at = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or("iat is missing")?;
    if issued_at > now + LEEWAY_SECS as i64 {
        return Err("iat is in the future".to_string());
    }
    Ok(())
}

/// `azp`, when present, must be this client, and a token with several audiences must have it.
fn check_authorized_party(
    claims: &Map<String, Value>,
    client_id: &str,
) -> Result<(), String> {
    let several_audiences = claims
        .get("aud")
        .and_then(Value::as_array)
        .is_some_and(|audiences| audiences.len() > 1);
    match claims.get("azp") {
        Some(Value::String(azp)) if azp == client_id => Ok(()),
        Some(_) => Err("azp is not this client".to_string()),
        None if several_audiences => Err("azp is missing for a token with several audiences".to_string()),
        None => Ok(()),
    }
}

/// The checks `jsonwebtoken` does not make: `iat`, `azp`, `nonce` and the shape of `sub` and
/// `sid`.
fn check_claims(
    claims: &Map<String, Value>,
    config: &OidcConfig,
    expected_nonce: &str,
    now: i64,
) -> Result<(), String> {
    check_issued_at(claims, now)?;
    check_authorized_party(claims, &config.client_id)?;

    if claims
        .get("nonce")
        .and_then(Value::as_str)
        != Some(expected_nonce)
    {
        return Err("nonce does not match this sign-in".to_string());
    }

    if short_string_claim(claims, "sub")?.is_none() {
        return Err(format!("sub must be a string of 1 to {MAX_IDENTIFIER_CLAIM_LEN} characters"));
    }
    short_string_claim(claims, "sid").map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::oidc::test_support::{
        CLIENT_ID, CLIENT_SECRET, KEY_A_KID, KEY_A_PEM, KEY_B_KID, KEY_B_PEM, StubProvider, config_for,
        id_token_claims, logout_claims, sign, sign_logout, sign_logout_with,
    };
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::json;

    async fn verify(
        provider: &StubProvider,
        token: &str,
    ) -> Result<VerifiedIdToken, String> {
        let config = config_for(&provider.issuer);
        verify_id_token(token, &config, &JwksClient::new(), &provider.jwks_uri(), "nonce-1")
            .await
            .map_err(|failure| failure.to_string())
    }

    #[tokio::test]
    async fn a_token_signed_by_the_provider_is_accepted() {
        let provider = StubProvider::start().await;
        let token = provider.id_token(id_token_claims(&provider.issuer, "nonce-1"));

        let verified = verify(&provider, &token)
            .await
            .unwrap();

        assert_eq!(verified.subject, "user-1");
        assert_eq!(verified.claims["org_id"], "org_123");
    }

    #[tokio::test]
    async fn a_token_signed_by_another_key_is_refused() {
        let provider = StubProvider::start().await;
        let forged = sign(KEY_B_PEM, Some(KEY_A_KID), &id_token_claims(&provider.issuer, "nonce-1"));

        let refused = verify(&provider, &forged)
            .await
            .unwrap_err();

        assert!(refused.contains("InvalidSignature"), "{refused}");
    }

    #[tokio::test]
    async fn a_token_with_an_unsigned_or_symmetric_algorithm_is_refused() {
        let provider = StubProvider::start().await;
        let claims = id_token_claims(&provider.issuer, "nonce-1");
        let payload = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            serde_json::to_vec(&claims).unwrap(),
        );
        let unsigned = format!("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.{payload}.");
        assert!(
            verify(&provider, &unsigned)
                .await
                .unwrap_err()
                .contains("unreadable header"),
            "alg none is not even a known algorithm"
        );

        let hs256 = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(CLIENT_SECRET.as_bytes()),
        )
        .unwrap();
        assert!(
            verify(&provider, &hs256)
                .await
                .unwrap_err()
                .contains("HS256 is not in id_token_signing_algs")
        );
    }

    #[tokio::test]
    async fn an_asymmetric_algorithm_outside_the_allowed_list_is_refused() {
        let provider = StubProvider::start().await;
        let mut config = config_for(&provider.issuer);
        config.id_token_signing_algs = vec![Algorithm::EdDSA];
        let token = provider.id_token(id_token_claims(&provider.issuer, "nonce-1"));

        let refused = verify_id_token(&token, &config, &JwksClient::new(), &provider.jwks_uri(), "nonce-1")
            .await
            .unwrap_err();

        assert!(
            matches!(&refused, TokenFailure::Invalid(detail) if detail.contains("ES256 is not in id_token_signing_algs")),
            "{refused:?}"
        );
        assert_eq!(provider.jwks_fetches(), 0, "the algorithm is refused before any key is fetched");
    }

    #[tokio::test]
    async fn a_key_published_for_another_algorithm_is_refused() {
        let provider = StubProvider::start().await;
        provider.set_jwks(json!({ "keys": [provider.jwk_a_with_alg("ES384")] }));
        let token = provider.id_token(id_token_claims(&provider.issuer, "nonce-1"));

        let refused = verify(&provider, &token)
            .await
            .unwrap_err();

        assert!(refused.contains("the signing key is for ES384"), "{refused}");
    }

    #[tokio::test]
    async fn a_key_published_for_encryption_is_refused() {
        let provider = StubProvider::start().await;
        let mut key = provider.jwk_a_with_alg("ES256");
        key["use"] = json!("enc");
        provider.set_jwks(json!({ "keys": [key] }));
        let token = provider.id_token(id_token_claims(&provider.issuer, "nonce-1"));

        let refused = verify(&provider, &token)
            .await
            .unwrap_err();

        assert!(refused.contains("not published for signatures"), "{refused}");
    }

    #[tokio::test]
    async fn keys_that_cannot_be_fetched_are_told_apart_from_a_token_that_does_not_verify() {
        let provider = StubProvider::start().await;
        let config = config_for(&provider.issuer);
        let token = provider.id_token(id_token_claims(&provider.issuer, "nonce-1"));

        let unavailable = verify_id_token(
            &token,
            &config,
            &JwksClient::new(),
            &format!("{}/no-such-jwks", provider.issuer),
            "nonce-1",
        )
        .await
        .unwrap_err();
        assert!(matches!(unavailable, TokenFailure::KeysUnavailable(_)), "{unavailable:?}");

        let unknown_key = sign(KEY_B_PEM, Some(KEY_B_KID), &id_token_claims(&provider.issuer, "nonce-1"));
        let invalid = verify_id_token(&unknown_key, &config, &JwksClient::new(), &provider.jwks_uri(), "nonce-1")
            .await
            .unwrap_err();
        assert!(matches!(invalid, TokenFailure::Invalid(_)), "{invalid:?}");
    }

    #[tokio::test]
    async fn an_unknown_key_id_refetches_the_keys_once_so_rotation_works() {
        let provider = StubProvider::start().await;
        let config = config_for(&provider.issuer);
        let jwks = JwksClient::new();
        let first = provider.id_token(id_token_claims(&provider.issuer, "nonce-1"));
        verify_id_token(&first, &config, &jwks, &provider.jwks_uri(), "nonce-1")
            .await
            .unwrap();

        provider.rotate_to_key_b();
        let rotated = sign(KEY_B_PEM, Some(KEY_B_KID), &id_token_claims(&provider.issuer, "nonce-1"));
        verify_id_token(&rotated, &config, &jwks, &provider.jwks_uri(), "nonce-1")
            .await
            .unwrap();

        assert_eq!(provider.jwks_fetches(), 2, "one fetch at first use, one for the new key id");
    }

    #[tokio::test]
    async fn keys_moved_to_another_address_are_read_there_even_under_a_known_key_id() {
        let provider = StubProvider::start().await;
        let moved = StubProvider::start().await;
        moved.publish_key_b_as_key_a();
        let config = config_for(&provider.issuer);
        let jwks = JwksClient::new();
        let first = provider.id_token(id_token_claims(&provider.issuer, "nonce-1"));
        verify_id_token(&first, &config, &jwks, &provider.jwks_uri(), "nonce-1")
            .await
            .unwrap();

        let signed_with_b = sign(KEY_B_PEM, Some(KEY_A_KID), &id_token_claims(&provider.issuer, "nonce-2"));
        let verified = verify_id_token(&signed_with_b, &config, &jwks, &moved.jwks_uri(), "nonce-2")
            .await
            .unwrap();

        assert_eq!(verified.subject, "user-1");
        assert_eq!(moved.jwks_fetches(), 1, "the new address is fetched, not matched against the old keys");
    }

    #[tokio::test]
    async fn a_token_without_a_key_id_matches_only_a_key_published_without_one() {
        let provider = StubProvider::start().await;
        let unkeyed = sign(KEY_A_PEM, None, &id_token_claims(&provider.issuer, "nonce-1"));

        let refused = verify(&provider, &unkeyed)
            .await
            .unwrap_err();
        assert!(refused.contains("no published key matches"), "{refused}");

        provider.set_jwks(json!({ "keys": [provider.jwk_a_without_kid()] }));
        let verified = verify(&provider, &unkeyed)
            .await
            .unwrap();
        assert_eq!(verified.subject, "user-1");
    }

    #[test]
    fn a_verified_token_never_shows_claim_values_in_debug_output() {
        let verified = VerifiedIdToken {
            subject: "user-1".to_string(),
            sid: Some("op-session-1".to_string()),
            claims: id_token_claims("https://idp.example.com", "nonce-1")
                .as_object()
                .unwrap()
                .clone(),
        };

        let shown = format!("{verified:?}");
        assert!(shown.contains("org_id"), "{shown}");
        assert!(!shown.contains("org_123") && !shown.contains("alice@example.com"), "{shown}");
    }

    #[tokio::test]
    async fn the_standard_claims_are_checked() {
        let provider = StubProvider::start().await;
        let now = chrono::Utc::now().timestamp();
        for (change, expected) in [
            (json!({ "iss": "https://other.example" }), "InvalidIssuer"),
            (json!({ "aud": "another-client" }), "InvalidAudience"),
            (json!({ "exp": now - 120 }), "ExpiredSignature"),
            (json!({ "sub": null }), "sub"),
        ] {
            let mut claims = id_token_claims(&provider.issuer, "nonce-1");
            for (name, value) in change.as_object().unwrap() {
                if value.is_null() {
                    claims
                        .as_object_mut()
                        .unwrap()
                        .remove(name);
                } else {
                    claims[name] = value.clone();
                }
            }
            let refused = verify(&provider, &provider.id_token(claims))
                .await
                .unwrap_err();
            assert!(refused.contains(expected), "{change}: {refused}");
        }
    }

    #[tokio::test]
    async fn a_token_not_yet_valid_beyond_the_leeway_is_refused() {
        let provider = StubProvider::start().await;
        let now = chrono::Utc::now().timestamp();
        let with_nbf = |nbf: i64| {
            let mut claims = id_token_claims(&provider.issuer, "nonce-1");
            claims["nbf"] = json!(nbf);
            provider.id_token(claims)
        };

        let refused = verify(&provider, &with_nbf(now + 300))
            .await
            .unwrap_err();
        let within_leeway = verify(&provider, &with_nbf(now + 30)).await;

        assert!(refused.contains("ImmatureSignature"), "{refused}");
        assert!(within_leeway.is_ok(), "{within_leeway:?}");
    }

    fn checked(change: Value) -> Result<(), String> {
        let config = config_for("https://idp.example.com");
        let mut claims = id_token_claims("https://idp.example.com", "nonce-1");
        for (name, value) in change.as_object().unwrap() {
            if value.is_null() {
                claims
                    .as_object_mut()
                    .unwrap()
                    .remove(name);
            } else {
                claims[name] = value.clone();
            }
        }
        let claims = claims
            .as_object()
            .unwrap()
            .clone();
        check_claims(&claims, &config, "nonce-1", chrono::Utc::now().timestamp())
    }

    #[test]
    fn the_nonce_must_be_this_sign_ins() {
        assert!(checked(json!({})).is_ok());
        for nonce in [json!("nonce-2"), json!(null), json!(7)] {
            assert!(
                checked(json!({ "nonce": nonce }))
                    .unwrap_err()
                    .contains("nonce"),
                "{nonce}"
            );
        }
    }

    #[test]
    fn several_audiences_need_this_client_as_the_authorized_party() {
        assert!(
            checked(json!({ "aud": [CLIENT_ID, "other"] }))
                .unwrap_err()
                .contains("azp is missing")
        );
        assert!(checked(json!({ "aud": [CLIENT_ID, "other"], "azp": CLIENT_ID })).is_ok());
        assert!(checked(json!({ "aud": [CLIENT_ID] })).is_ok(), "one audience needs no azp");
        assert!(
            checked(json!({ "azp": "other" }))
                .unwrap_err()
                .contains("azp is not this client")
        );
    }

    #[test]
    fn the_token_must_not_be_issued_in_the_future() {
        let now = chrono::Utc::now().timestamp();
        assert!(checked(json!({ "iat": now + 30 })).is_ok(), "within the leeway");
        assert!(
            checked(json!({ "iat": now + 600 }))
                .unwrap_err()
                .contains("future")
        );
        assert!(
            checked(json!({ "iat": null }))
                .unwrap_err()
                .contains("iat is missing")
        );
    }

    #[test]
    fn the_subject_must_be_a_short_non_empty_string() {
        assert!(checked(json!({ "sub": "" })).is_err());
        assert!(checked(json!({ "sub": "x".repeat(256) })).is_err());
        assert!(checked(json!({ "sub": 42 })).is_err());
        assert!(checked(json!({ "sub": "x".repeat(255) })).is_ok());
    }

    #[test]
    fn an_id_token_sid_must_be_a_short_non_empty_string_when_present() {
        assert!(checked(json!({ "sid": "op-session-1" })).is_ok());
        assert!(checked(json!({ "sid": "x".repeat(255) })).is_ok());
        for sid in [json!(""), json!("x".repeat(256)), json!(7), json!(["op-session-1"])] {
            assert!(
                checked(json!({ "sid": sid }))
                    .unwrap_err()
                    .contains("sid must be a string of 1 to 255 characters"),
                "{sid}"
            );
        }
    }

    #[tokio::test]
    async fn a_verified_id_token_gives_its_provider_session() {
        let provider = StubProvider::start().await;
        let mut claims = id_token_claims(&provider.issuer, "nonce-1");
        claims["sid"] = json!("op-session-1");

        let with_sid = verify(&provider, &provider.id_token(claims))
            .await
            .unwrap();
        let without_sid = verify(&provider, &provider.id_token(id_token_claims(&provider.issuer, "nonce-1")))
            .await
            .unwrap();

        assert_eq!(with_sid.sid.as_deref(), Some("op-session-1"));
        assert_eq!(without_sid.sid, None);
    }

    fn binding(sid: Option<&str>) -> OidcSessionBinding {
        OidcSessionBinding {
            issuer: "https://idp.example.com".to_string(),
            subject: "user-1".to_string(),
            sid: sid.map(str::to_string),
            id_token: None,
        }
    }

    fn target(
        subject: Option<&str>,
        sid: Option<&str>,
    ) -> LogoutTarget {
        LogoutTarget {
            subject: subject.map(str::to_string),
            sid: sid.map(str::to_string),
        }
    }

    #[test]
    fn a_logout_by_sid_ends_that_provider_session_and_by_sub_every_session_of_the_account() {
        let issuer = "https://idp.example.com";
        let by_sid = target(None, Some("op-1"));
        assert!(by_sid.matches(issuer, &binding(Some("op-1"))));
        assert!(!by_sid.matches(issuer, &binding(Some("op-2"))));
        assert!(!by_sid.matches(issuer, &binding(None)), "a sid alone cannot name a session without one");
        assert!(!by_sid.matches("https://other.example", &binding(Some("op-1"))), "another issuer's session");

        let by_both = target(Some("user-1"), Some("op-1"));
        assert!(by_both.matches(issuer, &binding(Some("op-1"))));
        assert!(!by_both.matches(issuer, &binding(Some("op-2"))));
        assert!(by_both.matches(issuer, &binding(None)), "the account's session without a sid");
        assert!(!target(Some("user-2"), Some("op-1")).matches(issuer, &binding(Some("op-1"))));

        let by_sub = target(Some("user-1"), None);
        assert!(by_sub.matches(issuer, &binding(Some("op-1"))));
        assert!(by_sub.matches(issuer, &binding(None)));
        assert!(!target(Some("user-2"), None).matches(issuer, &binding(Some("op-1"))));
    }

    #[test]
    fn a_logout_token_id_works_once_until_its_token_would_no_longer_be_accepted() {
        let seen = SeenLogoutTokens::default();

        assert!(seen.remember("jti-1", 1_000, 500));
        assert!(!seen.remember("jti-1", 1_000, 600), "a replay is refused");
        assert!(seen.remember("jti-2", 1_000, 600), "another token is not");
        assert!(seen.remember("jti-1", 2_000, 1_001), "forgotten once its token is no longer accepted");

        seen.forget("jti-1");
        assert!(seen.remember("jti-1", 2_000, 1_001), "a forgotten id can be sent again");
    }

    #[test]
    fn a_logout_token_id_is_remembered_through_the_last_second_its_token_is_accepted() {
        let seen = SeenLogoutTokens::default();

        assert!(seen.remember("jti-1", 1_000, 900));
        assert!(!seen.remember("jti-1", 1_000, 1_000), "the token is still accepted in that second");
        assert!(seen.remember("jti-1", 1_000, 1_001), "forgotten once the token is no longer accepted");
    }

    #[test]
    fn at_the_cap_the_logout_token_id_forgotten_soonest_makes_room() {
        let seen = SeenLogoutTokens::default();
        for index in 0..MAX_SEEN_LOGOUT_TOKENS {
            assert!(seen.remember(&format!("jti-{index}"), 100_000 + index as i64, 0));
        }

        assert!(seen.remember("newest", 200_000, 0));

        assert_eq!(seen.ids.len(), MAX_SEEN_LOGOUT_TOKENS);
        assert!(!seen.remember("jti-1", 300_000, 0), "a remembered id is refused at the cap, soonest or not");
        assert_eq!(seen.ids.len(), MAX_SEEN_LOGOUT_TOKENS);
        assert!(seen.remember("jti-0", 300_000, 0), "the one forgotten soonest was dropped");
    }

    #[test]
    fn concurrent_copies_of_one_logout_token_are_recorded_once() {
        let seen = std::sync::Arc::new(SeenLogoutTokens::default());
        let accepted = std::thread::scope(|scope| {
            let copies: Vec<_> = (0..16)
                .map(|_| {
                    let seen = seen.clone();
                    scope.spawn(move || seen.remember("jti-race", 2_000, 1_000))
                })
                .collect();
            copies
                .into_iter()
                .filter_map(|copy| copy.join().ok())
                .filter(|accepted| *accepted)
                .count()
        });

        assert_eq!(accepted, 1);
    }

    fn logout_checked(change: Value) -> Result<(LogoutTarget, String, i64), String> {
        let mut claims = logout_claims("https://idp.example.com", "op-1");
        for (name, value) in change.as_object().unwrap() {
            if value.is_null() {
                claims
                    .as_object_mut()
                    .unwrap()
                    .remove(name);
            } else {
                claims[name] = value.clone();
            }
        }
        check_logout_claims(claims.as_object().unwrap(), CLIENT_ID, chrono::Utc::now().timestamp())
    }

    #[test]
    fn a_logout_token_must_carry_the_event_a_subject_or_session_and_an_id() {
        let (target, jti, _) = logout_checked(json!({ "jti": "jti-1" })).unwrap();
        assert_eq!(
            target,
            LogoutTarget {
                subject: Some("user-1".to_string()),
                sid: Some("op-1".to_string())
            }
        );
        assert_eq!(jti, "jti-1");
        assert!(logout_checked(json!({ "sub": null })).is_ok(), "sid alone");
        assert!(logout_checked(json!({ "sid": null })).is_ok(), "sub alone");

        let event = "http://schemas.openid.net/event/backchannel-logout";
        for (change, expected) in [
            (json!({ "events": null }), "events"),
            (json!({ "events": { "http://schemas.openid.net/event/other": {} } }), "events"),
            (json!({ "events": { event: true } }), "events"),
            (json!({ "events": [event] }), "events"),
            (json!({ "nonce": "n" }), "nonce"),
            (json!({ "sub": null, "sid": null }), "neither sub nor sid"),
            (json!({ "sid": "" }), "sid must be a string"),
            (json!({ "sub": "x".repeat(256) }), "sub must be a string"),
            (json!({ "jti": null }), "jti is missing"),
            (json!({ "jti": 7 }), "jti must be a string"),
            (json!({ "iat": null }), "iat is missing"),
            (json!({ "iat": chrono::Utc::now().timestamp() + 600 }), "iat is in the future"),
            (json!({ "azp": "another-client" }), "azp is not this client"),
            (json!({ "aud": [CLIENT_ID, "other"] }), "azp is missing"),
        ] {
            let refused = logout_checked(change.clone()).unwrap_err();
            assert!(refused.contains(expected), "{change}: {refused}");
        }
    }

    #[test]
    fn a_logout_token_needs_exp_and_its_id_is_remembered_until_exp_and_the_leeway() {
        let now = chrono::Utc::now().timestamp();

        for exp in [json!(null), json!("soon"), json!(1.5)] {
            let refused = logout_checked(json!({ "exp": exp })).unwrap_err();
            assert_eq!(refused, "exp is missing or not a whole number", "{exp}");
        }

        let (_, _, remember_until) = logout_checked(json!({ "exp": now + 120, "iat": now - 400 })).unwrap();
        assert_eq!(remember_until, now + 120 + LEEWAY_SECS as i64, "until exp and its leeway");

        let (_, _, remember_until) = logout_checked(json!({ "exp": i64::MAX })).unwrap();
        assert_eq!(remember_until, i64::MAX, "an exp at the end of time does not overflow");
    }

    #[test]
    fn a_logout_token_type_is_logout_jwt_with_or_without_its_media_type_prefix() {
        let typed = |typ: Option<&str>| {
            let mut header = Header::new(Algorithm::ES256);
            header.typ = typ.map(str::to_string);
            check_logout_type(&header)
        };

        for typ in [None, Some("logout+jwt"), Some("Logout+JWT"), Some("application/logout+jwt")] {
            assert!(typed(typ).is_ok(), "{typ:?}");
        }
        for typ in ["JWT", "at+jwt", "application/jwt", "logout"] {
            assert!(
                typed(Some(typ))
                    .unwrap_err()
                    .contains("not logout+jwt"),
                "{typ}"
            );
        }
    }

    async fn verify_logout(
        provider: &StubProvider,
        jwks: &JwksClient,
        seen: &SeenLogoutTokens,
        token: &str,
    ) -> Result<VerifiedLogoutToken, TokenFailure> {
        verify_logout_token(token, &config_for(&provider.issuer), jwks, &provider.jwks_uri(), seen).await
    }

    #[tokio::test]
    async fn a_signed_logout_token_is_accepted_once() {
        let provider = StubProvider::start().await;
        let (jwks, seen) = (JwksClient::new(), SeenLogoutTokens::default());
        let token = sign_logout(&logout_claims(&provider.issuer, "op-1"));

        let verified = verify_logout(&provider, &jwks, &seen, &token)
            .await
            .unwrap();
        assert_eq!(
            verified.target,
            LogoutTarget {
                subject: Some("user-1".to_string()),
                sid: Some("op-1".to_string())
            }
        );

        let replayed = verify_logout(&provider, &jwks, &seen, &token)
            .await
            .unwrap_err();
        assert!(matches!(&replayed, TokenFailure::Invalid(detail) if detail == "jti was already used"), "{replayed:?}");
    }

    #[tokio::test]
    async fn an_id_token_or_a_forged_or_misaddressed_token_is_not_a_logout_token() {
        let provider = StubProvider::start().await;
        let (jwks, seen) = (JwksClient::new(), SeenLogoutTokens::default());
        let claims = logout_claims(&provider.issuer, "op-1");
        let mut with_nonce = claims.clone();
        with_nonce["nonce"] = json!("n");
        let signed_with_type = |typ: Option<&str>, claims: &Value| {
            let mut header = Header::new(Algorithm::ES256);
            header.kid = Some(KEY_A_KID.to_string());
            header.typ = typ.map(str::to_string);
            jsonwebtoken::encode(&header, claims, &EncodingKey::from_ec_pem(KEY_A_PEM.as_bytes()).unwrap()).unwrap()
        };
        let mut misaddressed = claims.clone();
        misaddressed["aud"] = json!("another-client");
        let mut other_issuer = claims.clone();
        other_issuer["iss"] = json!("https://other.example");
        let mut expired = claims.clone();
        expired["exp"] = json!(chrono::Utc::now().timestamp() - 120);
        let mut not_yet_valid = claims.clone();
        not_yet_valid["nbf"] = json!(chrono::Utc::now().timestamp() + 300);

        for (token, expected) in [
            (provider.id_token(id_token_claims(&provider.issuer, "nonce-1")), "not logout+jwt"),
            (signed_with_type(None, &id_token_claims(&provider.issuer, "nonce-1")), "nonce"),
            (signed_with_type(None, &with_nonce), "nonce"),
            (sign_logout(&with_nonce), "nonce"),
            (signed_with_type(Some("JWT"), &claims), "not logout+jwt"),
            (sign_logout_with(KEY_B_PEM, Some(KEY_A_KID), &claims), "InvalidSignature"),
            (sign_logout(&misaddressed), "InvalidAudience"),
            (sign_logout(&other_issuer), "InvalidIssuer"),
            (sign_logout(&expired), "ExpiredSignature"),
            (sign_logout(&not_yet_valid), "ImmatureSignature"),
            ("not-a-token".to_string(), "unreadable header"),
        ] {
            let refused = verify_logout(&provider, &jwks, &seen, &token)
                .await
                .unwrap_err();
            assert!(
                matches!(&refused, TokenFailure::Invalid(detail) if detail.contains(expected)),
                "{expected}: {refused:?}"
            );
        }
        assert!(seen.ids.is_empty(), "no refused token's jti is recorded");
    }

    #[tokio::test]
    async fn a_logout_token_whose_key_cannot_be_looked_for_is_unchecked_rather_than_invalid() {
        let provider = StubProvider::start().await;
        let (jwks, seen) = (JwksClient::new(), SeenLogoutTokens::default());
        verify_logout(&provider, &jwks, &seen, &sign_logout(&logout_claims(&provider.issuer, "op-1")))
            .await
            .unwrap();
        let made_up = sign_logout_with(KEY_A_PEM, Some("made-up"), &logout_claims(&provider.issuer, "op-1"));
        let refused = verify_logout(&provider, &jwks, &seen, &made_up)
            .await
            .unwrap_err();
        assert!(matches!(refused, TokenFailure::Invalid(_)), "a key the provider does not publish: {refused:?}");

        provider.rotate_to_key_b();
        let rotated = sign_logout_with(KEY_B_PEM, Some(KEY_B_KID), &logout_claims(&provider.issuer, "op-1"));
        let cooling = verify_logout(&provider, &jwks, &seen, &rotated)
            .await
            .unwrap_err();

        assert!(matches!(cooling, TokenFailure::KeyNotFoundDuringCooldown(_)), "{cooling:?}");
        assert_eq!(provider.jwks_fetches(), 2, "no fetch during the cooldown");
        assert!(seen.ids.len() == 1, "only the accepted token is recorded");
    }
}
