//! Caller keys: a stable key per caller and surface that a surface's Target can encrypt that
//! caller's data with, derived from a secret the Target's own operator does not hold.
//!
//! On a surface with `caller_key`, a request whose caller presented a JWT verified on that
//! request reaches the Target with the key in the configured header: HKDF-SHA256 with the
//! secret's bytes as the input key, `agent-gateway-caller-key-v2` as the salt and [`info`] as
//! the info, 32 bytes, base64url without padding. The info binds the key to the surface, to
//! where the keys that verified the token come from and the audiences it was accepted against
//! ([`JwtVerification`]), and to the token's `iss` and the first of `identity_claims` it carries
//! as a non-empty string. No other caller gets a key, and no header of the caller key family
//! ([`crate::config::caller_key::is_caller_key_header`]) a caller sends is ever forwarded.

use std::sync::Arc;

use base64::Engine;
use hkdf::Hkdf;
use serde_json::Value;
use sha2::Sha256;
use tracing::warn;
use zeroize::Zeroizing;

use crate::config::agent_surface::AgentSurface;
use crate::config::caller_key::{CallerKeyConfig, long_enough};
use crate::secrets::SecretsStore;
use crate::source_auth::{AuthenticatedIdentity, JwtVerification};

const SALT: &[u8] = b"agent-gateway-caller-key-v2";

/// What names a caller for its key: how its token was verified, the token's issuer, and the
/// identity claim with its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyedCaller<'a> {
    pub verification: &'a JwtVerification,
    pub issuer: &'a str,
    pub claim: &'a str,
    pub value: &'a str,
}

impl<'a> KeyedCaller<'a> {
    /// The caller a verified JWT `identity` names under `identity_claims`: how it was verified,
    /// its `iss` and the first of those claims it carries as a non-empty string. `None` for any
    /// other identity, or a token whose key source is not known, without a non-empty string
    /// `iss`, or without any such claim.
    pub(crate) fn of(
        identity: &'a AuthenticatedIdentity,
        identity_claims: &'a [String],
    ) -> Option<Self> {
        let verification = identity
            .jwt_verification()
            .filter(|verification| {
                !verification
                    .key_source
                    .is_empty()
            })?;
        let claims = identity.jwt_claims()?;
        let issuer = non_empty_string(claims.get("iss"))?;
        identity_claims
            .iter()
            .find_map(|claim| {
                Some(Self {
                    verification,
                    issuer,
                    claim,
                    value: non_empty_string(claims.get(claim.as_str()))?,
                })
            })
    }
}

/// A claim value that can name a caller: a string, and not empty, which would name every
/// caller without one.
fn non_empty_string(value: Option<&Value>) -> Option<&str> {
    value?
        .as_str()
        .filter(|text| !text.is_empty())
}

/// The HKDF info of `caller` on surface `surface_id`: seven fields, each preceded by its length
/// in bytes as a 4-byte big-endian integer, so no field can be read as part of another. They
/// are the surface id, the key source, the audience claim, the audiences, the token's `iss`,
/// the identity claim's name and its value. The audiences field is the audiences, sorted and
/// without duplicates, each preceded by its own 4-byte length.
fn info(
    surface_id: &str,
    caller: KeyedCaller<'_>,
) -> Option<Vec<u8>> {
    fn push(
        into: &mut Vec<u8>,
        field: &[u8],
    ) -> Option<()> {
        into.extend_from_slice(
            &u32::try_from(field.len())
                .ok()?
                .to_be_bytes(),
        );
        into.extend_from_slice(field);
        Some(())
    }
    let mut audiences = Vec::new();
    for audience in &caller.verification.audiences {
        push(&mut audiences, audience.as_bytes())?;
    }
    let mut info = Vec::new();
    for field in [
        surface_id.as_bytes(),
        caller
            .verification
            .key_source
            .as_bytes(),
        caller
            .verification
            .audience_claim
            .as_bytes(),
        &audiences,
        caller.issuer.as_bytes(),
        caller.claim.as_bytes(),
        caller.value.as_bytes(),
    ] {
        push(&mut info, field)?;
    }
    Some(info)
}

/// The caller key of `caller` on surface `surface_id` under `secret`.
pub(crate) fn derive(
    secret: &[u8],
    surface_id: &str,
    caller: KeyedCaller<'_>,
) -> Option<String> {
    let info = info(surface_id, caller)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(SALT), secret)
        .expand(&info, key.as_mut())
        .ok()?;
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.as_ref()))
}

/// Why a caller key secret could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unreadable {
    NoStore,
    StoreFailed,
    Missing,
    OutsideTenant,
    TooShort,
}

impl Unreadable {
    fn reason(self) -> &'static str {
        match self {
            Self::NoStore => "no secrets store",
            Self::StoreFailed => "the secrets store failed",
            Self::Missing => "no such secret",
            Self::OutsideTenant => "the secret is outside the surface's tenant",
            Self::TooShort => "the secret is too short",
        }
    }

    /// The `reason` label of `agent_gateway_caller_key_secret_unreadable_total`.
    fn label(self) -> &'static str {
        match self {
            Self::NoStore => "no_store",
            Self::StoreFailed => "store_failed",
            Self::Missing => "missing",
            Self::OutsideTenant => "outside_tenant",
            Self::TooShort => "too_short",
        }
    }
}

/// The value of `config`'s secret, when `surface` may use it and it is long enough.
async fn read_secret(
    surface: &AgentSurface,
    config: &CallerKeyConfig,
    secrets: Option<&Arc<dyn SecretsStore>>,
) -> Result<Zeroizing<String>, Unreadable> {
    let secret = secrets
        .ok_or(Unreadable::NoStore)?
        .get_by_secret_id(&config.secret_id)
        .await
        .map_err(|_| Unreadable::StoreFailed)?
        .ok_or(Unreadable::Missing)?;
    if !crate::tenancy::can_reference_with_rule(
        surface.tenant_id.as_deref(),
        secret.tenant_id.as_deref(),
        crate::config::credential_policy::credential_policy().tenant_credential_isolation,
    ) {
        return Err(Unreadable::OutsideTenant);
    }
    let value = Zeroizing::new(secret.value);
    if !long_enough(&value) {
        return Err(Unreadable::TooShort);
    }
    Ok(value)
}

/// Whether a caller key sent to `endpoint` would cross the network in clear: an `http` URL.
pub(crate) fn sent_in_clear(endpoint: &str) -> bool {
    url::Url::parse(endpoint.trim()).is_ok_and(|url| url.scheme() == "http")
}

/// Whether the caller key may go to `endpoint` under `credential_policy.target_https`, by the
/// test a Target credential is held to ([`crate::config::target_auth_rules::is_https_target`]):
/// always to an `https` URL, and to any other endpoint only while the rule is not `enforce`.
/// An `http` Target is logged once per surface, variant and mode; another endpoint, such as a
/// `fabric://` or `proxy://` one, never carries the key out in clear and is not logged.
fn target_https_allows(
    surface_id: &str,
    endpoint: &str,
    mode: crate::config::credential_policy::RuleMode,
) -> bool {
    static WARNED: std::sync::LazyLock<dashmap::DashSet<String>> = std::sync::LazyLock::new(Default::default);
    if crate::config::target_auth_rules::is_https_target(endpoint) {
        return true;
    }
    let enforced = mode.is_enforced();
    if !sent_in_clear(endpoint) {
        return !enforced;
    }
    let variant = crate::observability::policy_audit::current_request_variant();
    let leg = format!(
        "{surface_id}\n{}\n{enforced}",
        variant
            .as_deref()
            .unwrap_or_default()
    );
    if WARNED.insert(leg) {
        if enforced {
            warn!(
                surface_id = %surface_id,
                surface_variant = variant.as_deref(),
                "Caller key withheld: the Target is not https and credential_policy.target_https is enforce"
            );
        } else {
            warn!(
                surface_id = %surface_id,
                surface_variant = variant.as_deref(),
                "Caller key sent to a Target that is not https; it will be withheld once credential_policy.target_https is enforce"
            );
        }
    }
    !enforced
}

/// The caller key header, name and value, for a request on `surface` from `identity` to the
/// Target at `endpoint`: only on a surface with `caller_key`, from a caller whose JWT was
/// verified on this request and names it, and to a Target that is not an `https` URL only
/// while `credential_policy.target_https` is not `enforce`. When the secret cannot be read the
/// request goes on without it, and a warning names the surface.
pub(crate) async fn caller_key_header(
    surface: &AgentSurface,
    endpoint: &str,
    identity: Option<&AuthenticatedIdentity>,
    secrets: Option<&Arc<dyn SecretsStore>>,
) -> Option<(String, String)> {
    let config = surface.caller_key.as_ref()?;
    let caller = KeyedCaller::of(identity?, &config.identity_claims)?;
    if !target_https_allows(
        &surface.surface_id,
        endpoint,
        crate::config::credential_policy::credential_policy().target_https,
    ) {
        return None;
    }
    let secret = match read_secret(surface, config, secrets).await {
        Ok(secret) => secret,
        Err(unreadable) => {
            warn!(
                surface = %surface.surface_id,
                reason = unreadable.reason(),
                "Forwarding without the caller key: its secret cannot be read"
            );
            crate::metrics::backends::prometheus::track_caller_key_secret_unreadable(
                &surface.surface_id,
                unreadable.label(),
            );
            return None;
        }
    };
    let key = derive(secret.as_bytes(), &surface.surface_id, caller)?;
    Some((config.header.clone(), key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::{CreateSecretRequest, FilesystemSecretsStore};

    const SECRET: &str = "0123456789abcdef0123456789abcdef";
    const JWKS_URI: &str = "https://idp.example/.well-known/jwks.json";
    /// The key of `alice` on `surface-1` under [`SECRET`], verified by [`idp_verification`].
    const ALICE_KEY: &str = "MHijA8kX963zxv0YWe5I42GRLQLyVJvNzGd4nWsw7QQ";

    fn strategy(jwks_source: Value) -> crate::jwt_bearer::models::JwtVerificationStrategy {
        serde_json::from_value(serde_json::json!({
            "id": "idp", "name": "IdP", "expected_issuer": "https://idp.example",
            "jwks_source": jwks_source,
            "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
        }))
        .expect("strategy parses")
    }

    fn remote(jwks_uri: &str) -> crate::jwt_bearer::models::JwtVerificationStrategy {
        strategy(serde_json::json!({ "type": "remote", "jwks_uri": jwks_uri }))
    }

    fn inline(x: &str) -> crate::jwt_bearer::models::JwtVerificationStrategy {
        strategy(serde_json::json!({ "type": "static", "jwks": [
            { "kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": x }
        ] }))
    }

    fn verified_by(
        strategy: &crate::jwt_bearer::models::JwtVerificationStrategy,
        audiences: &[&str],
    ) -> JwtVerification {
        let audiences: Vec<String> = audiences
            .iter()
            .map(|audience| audience.to_string())
            .collect();
        JwtVerification::of(strategy, &audiences, crate::jwt_bearer::models::AudienceClaim::Aud)
    }

    fn idp_verification() -> JwtVerification {
        verified_by(&remote(JWKS_URI), &["https://agent.example", "api://memory"])
    }

    fn jwt_verified_by(
        claims: Value,
        verification: JwtVerification,
    ) -> AuthenticatedIdentity {
        AuthenticatedIdentity::JwtBearer {
            subject: claims["sub"]
                .as_str()
                .unwrap_or("<none>")
                .to_string(),
            principal_claim: "sub".to_string(),
            claims,
            verification,
            strategy_id: None,
        }
    }

    fn jwt(claims: Value) -> AuthenticatedIdentity {
        jwt_verified_by(claims, idp_verification())
    }

    fn alice() -> AuthenticatedIdentity {
        jwt(serde_json::json!({ "iss": "https://idp.example", "sub": "alice" }))
    }

    fn surface(
        surface_id: &str,
        caller_key: Value,
    ) -> AgentSurface {
        serde_json::from_value(serde_json::json!({
            "surface_id": surface_id,
            "name": surface_id,
            "access_point": { "listen_address": "0.0.0.0:9000", "route": "/agent", "protocol": "a2a" },
            "target": { "endpoint": "https://agent.example" },
            "caller_key": caller_key,
        }))
        .expect("surface parses")
    }

    /// A secrets store holding each `(secret_id, value, tenant_id)`.
    async fn store(secrets: &[(&str, &str, Option<&str>)]) -> (tempfile::TempDir, Arc<dyn SecretsStore>) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FilesystemSecretsStore::new_async(
            dir.path()
                .to_str()
                .expect("utf-8 path"),
        )
        .await
        .expect("secrets store");
        for (secret_id, value, tenant_id) in secrets {
            store
                .create(CreateSecretRequest {
                    tenant_id: tenant_id.map(String::from),
                    name: secret_id.to_string(),
                    secret_id: secret_id.to_string(),
                    description: None,
                    value: value.to_string(),
                    secret_type: "General".to_string(),
                    tags: vec![],
                })
                .await
                .expect("secret created");
        }
        (dir, Arc::new(store))
    }

    async fn header_for(
        surface: &AgentSurface,
        identity: Option<&AuthenticatedIdentity>,
        secrets: &[(&str, &str, Option<&str>)],
    ) -> Option<(String, String)> {
        let (_dir, secrets) = store(secrets).await;
        caller_key_header(surface, &surface.target.endpoint, identity, Some(&secrets)).await
    }

    /// RFC 5869 HKDF-SHA256 computed independently of the `hkdf` crate, from HMAC-SHA256:
    /// PRK = HMAC(salt, ikm), OKM = T(1) = HMAC(PRK, info || 0x01), the first 32 bytes.
    fn reference_key(
        secret: &[u8],
        info: &[u8],
    ) -> String {
        use hmac::{Hmac, Mac};
        let mut extract = Hmac::<Sha256>::new_from_slice(b"agent-gateway-caller-key-v2").expect("any key length");
        extract.update(secret);
        let prk = extract
            .finalize()
            .into_bytes();
        let mut expand = Hmac::<Sha256>::new_from_slice(&prk).expect("any key length");
        expand.update(info);
        expand.update(&[1]);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expand.finalize().into_bytes())
    }

    /// Inputs: secret `0123456789abcdef0123456789abcdef` (32 ASCII bytes), surface id
    /// `surface-1`, key source `jwks_uri:https://idp.example/.well-known/jwks.json`, audience
    /// claim `aud`, audiences `https://agent.example` and `api://memory` (sorted:
    /// `api://memory`, `https://agent.example`), `iss` `https://idp.example`, claim `sub` =
    /// `alice`. The info is written out byte by byte below, each field after its 4-byte
    /// big-endian length.
    #[test]
    fn a_caller_key_matches_hkdf_sha256_of_the_documented_inputs() {
        let verification = idp_verification();
        assert_eq!(verification.key_source, "jwks_uri:https://idp.example/.well-known/jwks.json");
        assert_eq!(verification.audiences, ["api://memory", "https://agent.example"]);
        let caller = KeyedCaller {
            verification: &verification,
            issuer: "https://idp.example",
            claim: "sub",
            value: "alice",
        };
        let mut expected_info = Vec::new();
        expected_info.extend_from_slice(b"\x00\x00\x00\x09surface-1");
        expected_info.extend_from_slice(b"\x00\x00\x00\x32jwks_uri:https://idp.example/.well-known/jwks.json");
        expected_info.extend_from_slice(b"\x00\x00\x00\x03aud");
        expected_info
            .extend_from_slice(b"\x00\x00\x00\x29\x00\x00\x00\x0capi://memory\x00\x00\x00\x15https://agent.example");
        expected_info.extend_from_slice(b"\x00\x00\x00\x13https://idp.example");
        expected_info.extend_from_slice(b"\x00\x00\x00\x03sub");
        expected_info.extend_from_slice(b"\x00\x00\x00\x05alice");
        assert_eq!(info("surface-1", caller), Some(expected_info.clone()));
        let derived = derive(SECRET.as_bytes(), "surface-1", caller).expect("32 bytes derive");
        assert_eq!(derived, reference_key(SECRET.as_bytes(), &expected_info));
        assert_eq!(derived, ALICE_KEY);
        assert_eq!(derived.len(), 43, "32 bytes are 43 base64url characters without padding");
    }

    #[test]
    fn a_caller_key_is_stable_and_differs_by_caller_issuer_claim_surface_and_secret() {
        let verification = idp_verification();
        let key = |secret: &str, surface_id: &str, issuer: &str, claim: &str, value: &str| {
            let caller = KeyedCaller {
                verification: &verification,
                issuer,
                claim,
                value,
            };
            derive(secret.as_bytes(), surface_id, caller).expect("derives")
        };
        let base = key(SECRET, "surface-1", "https://idp.example", "sub", "alice");
        assert_eq!(base, key(SECRET, "surface-1", "https://idp.example", "sub", "alice"));
        let others = [
            key(SECRET, "surface-1", "https://idp.example", "sub", "bob"),
            key(SECRET, "surface-2", "https://idp.example", "sub", "alice"),
            key(SECRET, "surface-1", "https://other-idp.example", "sub", "alice"),
            key(SECRET, "surface-1", "https://idp.example", "oid", "alice"),
            key("fedcba9876543210fedcba9876543210", "surface-1", "https://idp.example", "sub", "alice"),
        ];
        for other in &others {
            assert_ne!(&base, other);
        }
    }

    /// The key of `alice` from `https://idp.example` on `surface-1`, as `verification` verified
    /// her token.
    fn alice_key_verified_by(verification: &JwtVerification) -> String {
        let caller = KeyedCaller {
            verification,
            issuer: "https://idp.example",
            claim: "sub",
            value: "alice",
        };
        derive(SECRET.as_bytes(), "surface-1", caller).expect("derives")
    }

    /// Whoever can edit the verification strategy can point it at a key set of their own and
    /// sign a token claiming the real `iss` and any `sub`; the key that token gets is not the
    /// victim's.
    #[test]
    fn the_same_issuer_and_subject_verified_by_another_key_source_get_another_key() {
        let real = alice_key_verified_by(&idp_verification());
        let substituted_uri = alice_key_verified_by(&verified_by(
            &remote("https://attacker.example/.well-known/jwks.json"),
            &["https://agent.example", "api://memory"],
        ));
        assert_ne!(real, substituted_uri);

        let real_inline = verified_by(&inline("xMjCoPwAtNcNFrwDLMlggNGrTdN0LAd_kxjJGWg8jZU"), &["api://memory"]);
        let other_inline = verified_by(&inline("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"), &["api://memory"]);
        assert!(
            real_inline
                .key_source
                .starts_with("inline_jwks:sha256:")
        );
        assert_ne!(real_inline.key_source, other_inline.key_source);
        assert_ne!(alice_key_verified_by(&real_inline), alice_key_verified_by(&other_inline));
        assert_eq!(
            alice_key_verified_by(&real_inline),
            alice_key_verified_by(&verified_by(
                &inline("xMjCoPwAtNcNFrwDLMlggNGrTdN0LAd_kxjJGWg8jZU"),
                &["api://memory"]
            )),
            "the same inline key set gives the same key"
        );
    }

    #[test]
    fn an_inline_key_source_is_the_sha256_of_the_canonical_key_set() {
        use sha2::Digest;
        let canonical =
            br#"[{"crv":"Ed25519","kid":"k1","kty":"OKP","x":"xMjCoPwAtNcNFrwDLMlggNGrTdN0LAd_kxjJGWg8jZU"}]"#;
        assert_eq!(
            verified_by(&inline("xMjCoPwAtNcNFrwDLMlggNGrTdN0LAd_kxjJGWg8jZU"), &[]).key_source,
            format!("inline_jwks:sha256:{}", hex::encode(Sha256::digest(canonical)))
        );
    }

    #[test]
    fn adding_an_audience_changes_the_key_and_reordering_them_does_not() {
        let strategy = remote(JWKS_URI);
        let base = alice_key_verified_by(&verified_by(&strategy, &["https://agent.example", "api://memory"]));
        assert_eq!(base, ALICE_KEY);
        assert_eq!(
            base,
            alice_key_verified_by(&verified_by(&strategy, &["api://memory", "https://agent.example", "api://memory"])),
            "order and duplicates do not count"
        );
        assert_ne!(
            base,
            alice_key_verified_by(&verified_by(
                &strategy,
                &["https://agent.example", "api://memory", "api://other-app"]
            ))
        );
        assert_ne!(base, alice_key_verified_by(&verified_by(&strategy, &["https://agent.example"])));
        let mut by_client = verified_by(&strategy, &["https://agent.example", "api://memory"]);
        by_client.audience_claim = "azp".to_string();
        assert_ne!(base, alice_key_verified_by(&by_client), "another audience claim");
    }

    #[test]
    fn a_field_never_reads_as_part_of_another() {
        let verification = idp_verification();
        let split = |issuer, value| {
            info(
                "surface-1",
                KeyedCaller {
                    verification: &verification,
                    issuer,
                    claim: "sub",
                    value,
                },
            )
        };
        assert_ne!(split("https://idp.example\0\0\0\x03sub", "alice"), split("https://idp.example", "alice"));
        let joined = |audiences: &[&str]| {
            let mut verification = idp_verification();
            verification.audiences = audiences
                .iter()
                .map(|audience| audience.to_string())
                .collect();
            alice_key_verified_by(&verification)
        };
        assert_ne!(joined(&["a\0b"]), joined(&["a", "b"]));
    }

    #[test]
    fn a_token_whose_key_source_is_not_known_names_no_caller() {
        let sub = vec!["sub".to_string()];
        let claims = serde_json::json!({ "iss": "https://idp.example", "sub": "alice" });
        assert!(KeyedCaller::of(&jwt(claims.clone()), &sub).is_some());
        assert_eq!(KeyedCaller::of(&jwt_verified_by(claims, JwtVerification::default()), &sub), None);
    }

    #[test]
    fn the_first_identity_claim_the_token_carries_as_a_string_names_the_caller() {
        let claims = |claims: &[&str]| {
            claims
                .iter()
                .map(|claim| claim.to_string())
                .collect::<Vec<_>>()
        };
        let token = jwt(serde_json::json!({
            "iss": "https://idp.example",
            "sub": "alice",
            "oid": "o-1",
            "uid": 42,
            "groups": ["a"],
            "email": "",
        }));
        let named = |order: &[&str]| {
            let order = claims(order);
            KeyedCaller::of(&token, &order).map(|caller| (caller.claim.to_string(), caller.value.to_string()))
        };
        assert_eq!(named(&["oid", "sub"]), Some(("oid".to_string(), "o-1".to_string())));
        assert_eq!(named(&["sub", "oid"]), Some(("sub".to_string(), "alice".to_string())));
        assert_eq!(
            named(&["uid", "groups", "email", "missing", "sub"]),
            Some(("sub".to_string(), "alice".to_string()))
        );
        assert_eq!(named(&["uid", "groups", "email", "missing"]), None);
    }

    #[test]
    fn a_token_without_a_usable_issuer_names_no_caller() {
        let sub = vec!["sub".to_string()];
        for claims in [
            serde_json::json!({ "sub": "alice" }),
            serde_json::json!({ "iss": "", "sub": "alice" }),
            serde_json::json!({ "iss": 7, "sub": "alice" }),
        ] {
            assert_eq!(KeyedCaller::of(&jwt(claims.clone()), &sub), None, "{claims}");
        }
    }

    #[tokio::test]
    async fn a_verified_jwt_caller_gets_its_key_in_the_configured_header() {
        let secrets = [("caller-keys", SECRET, None)];
        let configured = surface("surface-1", serde_json::json!({ "secret_id": "caller-keys" }));
        let first = header_for(&configured, Some(&alice()), &secrets).await;
        let second = header_for(&configured, Some(&alice()), &secrets).await;
        assert_eq!(
            first,
            Some(("x-caller-key".to_string(), "MHijA8kX963zxv0YWe5I42GRLQLyVJvNzGd4nWsw7QQ".to_string()))
        );
        assert_eq!(first, second, "one caller's key is stable across requests");

        let renamed =
            surface("surface-1", serde_json::json!({ "secret_id": "caller-keys", "header": "x-caller-key-memory" }));
        assert_eq!(
            header_for(&renamed, Some(&alice()), &secrets).await,
            Some(("x-caller-key-memory".to_string(), "MHijA8kX963zxv0YWe5I42GRLQLyVJvNzGd4nWsw7QQ".to_string()))
        );
    }

    #[tokio::test]
    async fn shared_key_anonymous_and_other_callers_get_no_key() {
        let secrets = [("caller-keys", SECRET, None)];
        let configured = surface("surface-1", serde_json::json!({ "secret_id": "caller-keys" }));
        let callers = [
            AuthenticatedIdentity::ApiKey {
                key_name: "shared".to_string(),
                provider_agent_id: None,
            },
            AuthenticatedIdentity::ApiKey {
                key_name: "issued".to_string(),
                provider_agent_id: Some("agent-1".to_string()),
            },
            AuthenticatedIdentity::DidAuth {
                did: "did:example:alice".to_string(),
            },
        ];
        for caller in &callers {
            assert_eq!(header_for(&configured, Some(caller), &secrets).await, None, "{caller:?}");
        }
        assert_eq!(header_for(&configured, None, &secrets).await, None, "anonymous or unverified");
    }

    #[tokio::test]
    async fn an_mtls_caller_gets_no_key() {
        let configured = surface("surface-1", serde_json::json!({ "secret_id": "caller-keys" }));
        let mtls = AuthenticatedIdentity::Mtls {
            principal: "alice".to_string(),
            fingerprint: "ab".repeat(32),
            subject_dn: "CN=alice".to_string(),
            issuer_dn: "CN=Partner CA".to_string(),
            trust_anchor_fingerprint: "cd".repeat(32),
            sans: crate::source_auth::models::MtlsSans {
                uri: vec!["spiffe://partner.example/alice".to_string()],
                ..Default::default()
            },
            source: crate::source_auth::models::PeerCertSource::DirectTls,
        };
        assert_eq!(header_for(&configured, Some(&mtls), &[("caller-keys", SECRET, None)]).await, None);
    }

    #[tokio::test]
    async fn a_surface_without_caller_key_sends_none() {
        let secrets = [("caller-keys", SECRET, None)];
        let mut plain = surface("surface-1", serde_json::json!({ "secret_id": "caller-keys" }));
        plain.caller_key = None;
        assert_eq!(header_for(&plain, Some(&alice()), &secrets).await, None);
    }

    #[tokio::test]
    async fn an_unreadable_secret_is_counted_by_reason_and_a_readable_one_is_not() {
        let surface_id = format!("surface-{}", uuid::Uuid::new_v4());
        let configured = surface(&surface_id, serde_json::json!({ "secret_id": "caller-keys" }));
        let count = |reason: &str| {
            crate::metrics::backends::prometheus::CALLER_KEY_SECRET_UNREADABLE
                .with_label_values(&[surface_id.as_str(), reason])
                .get()
        };
        assert!(
            header_for(&configured, Some(&alice()), &[])
                .await
                .is_none()
        );
        assert!(
            header_for(&configured, Some(&alice()), &[("caller-keys", "short", None)])
                .await
                .is_none()
        );
        assert!(
            header_for(&configured, Some(&alice()), &[("caller-keys", SECRET, None)])
                .await
                .is_some()
        );
        assert_eq!((count("missing"), count("too_short"), count("no_store")), (1, 1, 0));
    }

    #[tokio::test]
    async fn an_unreadable_secret_sends_no_key() {
        let configured = surface("surface-1", serde_json::json!({ "secret_id": "caller-keys" }));
        assert_eq!(
            caller_key_header(&configured, "https://agent.example", Some(&alice()), None).await,
            None,
            "no store"
        );
        let short = "0123456789abcdef0123456789abcde";
        for (secrets, why) in [
            (&[][..], "no such secret"),
            (&[("caller-keys", short, None)][..], "a secret of 31 bytes"),
            (&[("caller-keys", SECRET, Some("tenant-b"))][..], "a tenant's secret on an appliance-wide surface"),
        ] {
            assert_eq!(header_for(&configured, Some(&alice()), secrets).await, None, "{why}");
        }
        let mut tenant_surface = configured.clone();
        tenant_surface.tenant_id = Some("tenant-a".to_string());
        assert_eq!(
            header_for(&tenant_surface, Some(&alice()), &[("caller-keys", SECRET, Some("tenant-b"))]).await,
            None,
            "another tenant's secret"
        );
        assert!(
            header_for(&tenant_surface, Some(&alice()), &[("caller-keys", SECRET, Some("tenant-a"))])
                .await
                .is_some(),
            "the surface's own tenant's secret"
        );
    }

    #[test]
    fn only_an_http_target_receives_the_key_in_clear() {
        assert!(sent_in_clear("http://agent.example/a2a"));
        assert!(sent_in_clear(" HTTP://agent.example "));
        for endpoint in [
            "https://agent.example",
            "fabric://did:example:peer/surface",
            "proxy://memory",
            "a2a-proxy://agent",
            "not a url",
        ] {
            assert!(!sent_in_clear(endpoint), "{endpoint}");
        }
    }

    #[test]
    fn target_https_withholds_the_key_from_an_http_target_only_under_enforce() {
        use crate::config::credential_policy::RuleMode;
        assert!(target_https_allows("surface-https", "https://agent.example", RuleMode::Enforce));
        assert!(target_https_allows("surface-https", "https://agent.example", RuleMode::Warn));
        assert!(!target_https_allows("surface-http", "http://agent.example", RuleMode::Enforce));
        assert!(
            !target_https_allows("surface-http", "http://agent.example", RuleMode::Enforce),
            "withheld on every request, not only the first"
        );
        assert!(target_https_allows("surface-http", "http://agent.example", RuleMode::Warn));
    }

    /// The key is held to the test a Target credential is: under `enforce` only an `https` URL
    /// with a host receives it.
    #[test]
    fn target_https_withholds_the_key_from_every_endpoint_a_target_credential_is_withheld_from() {
        use crate::config::credential_policy::RuleMode;
        for endpoint in ["fabric://gateway/surface", "proxy://memory", "a2a-proxy://agent", "not a url", "https://"] {
            assert!(
                !crate::config::target_auth_rules::is_https_target(endpoint),
                "a Target credential is withheld from {endpoint}"
            );
            assert!(!target_https_allows("surface-other", endpoint, RuleMode::Enforce), "{endpoint}");
            assert!(target_https_allows("surface-other", endpoint, RuleMode::Warn), "{endpoint}");
        }
    }
}
