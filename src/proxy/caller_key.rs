//! Caller keys: a stable key per caller and surface that a surface's Target can encrypt that
//! caller's data with, derived from a secret the Target's own operator does not hold.
//!
//! On a surface with `caller_key`, a request whose caller presented a JWT verified on that
//! request reaches the Target with the key in the configured header:
//! HKDF-SHA256 with the secret's bytes as the input key, `agent-gateway-caller-key-v1` as the
//! salt and `surface id, 0x00, iss, 0x00, claim name, 0x00, claim value` as the info, 32 bytes,
//! base64url without padding. The claim is the first of `identity_claims` the token carries as
//! a non-empty string. No other caller gets a key, and a caller's own header of that name, or
//! of any name a stored surface's `caller_key` uses, is never forwarded.

use std::sync::{Arc, LazyLock};

use base64::Engine;
use dashmap::DashMap;
use hkdf::Hkdf;
use serde_json::Value;
use sha2::Sha256;
use tracing::warn;
use zeroize::Zeroizing;

use crate::config::agent_surface::AgentSurface;
use crate::config::caller_key::{CallerKeyConfig, DEFAULT_CALLER_KEY_HEADER, MIN_SECRET_BYTES};
use crate::config::target_auth_rules::same_header_name;
use crate::secrets::SecretsStore;
use crate::source_auth::AuthenticatedIdentity;

const SALT: &[u8] = b"agent-gateway-caller-key-v1";

/// The caller key header each stored surface's `caller_key` names, by surface id.
static CONFIGURED_HEADERS: LazyLock<DashMap<String, String>> = LazyLock::new(DashMap::new);

/// Note the caller key header `surface` names, or that it names none.
pub(crate) fn record_surface(surface: &AgentSurface) {
    match surface.caller_key.as_ref() {
        Some(config) => {
            CONFIGURED_HEADERS.insert(surface.surface_id.clone(), config.header.clone());
        }
        None => forget_surface(&surface.surface_id),
    }
}

/// Forget the caller key header of a deleted surface.
pub(crate) fn forget_surface(surface_id: &str) {
    CONFIGURED_HEADERS.remove(surface_id);
}

/// Whether `name` is a caller key header: the default, or one a stored surface's `caller_key`
/// names, compared without regard to case or to `_` against `-`, since some servers read both
/// spellings as one. Only the gateway sets these, so a caller's copy is never forwarded.
pub fn is_caller_key_header(name: &str) -> bool {
    same_header_name(name, DEFAULT_CALLER_KEY_HEADER)
        || CONFIGURED_HEADERS
            .iter()
            .any(|entry| same_header_name(name, entry.value()))
}

/// What names a caller for its key: the token's issuer and the identity claim with its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyedCaller<'a> {
    pub issuer: &'a str,
    pub claim: &'a str,
    pub value: &'a str,
}

impl<'a> KeyedCaller<'a> {
    /// The caller a verified JWT `identity` names under `identity_claims`: its `iss` and the
    /// first of those claims it carries as a usable string. `None` for any other identity, or a
    /// token without a usable `iss` or any such claim.
    pub(crate) fn of(
        identity: &'a AuthenticatedIdentity,
        identity_claims: &'a [String],
    ) -> Option<Self> {
        let claims = identity.jwt_claims()?;
        let issuer = usable_string(claims.get("iss"))?;
        identity_claims
            .iter()
            .find_map(|claim| {
                Some(Self {
                    issuer,
                    claim,
                    value: usable_string(claims.get(claim.as_str()))?,
                })
            })
    }
}

/// A claim value that can name a caller: a string, not empty, which would name every caller
/// without one, and without NUL, which separates the fields of the info.
fn usable_string(value: Option<&Value>) -> Option<&str> {
    value?
        .as_str()
        .filter(|text| !text.is_empty() && !text.contains('\0'))
}

/// The caller key of `caller` on surface `surface_id` under `secret`.
pub(crate) fn derive(
    secret: &[u8],
    surface_id: &str,
    caller: KeyedCaller<'_>,
) -> Option<String> {
    let info = [surface_id, caller.issuer, caller.claim, caller.value].join("\0");
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(SALT), secret)
        .expand(info.as_bytes(), key.as_mut())
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
    if value.len() < MIN_SECRET_BYTES {
        return Err(Unreadable::TooShort);
    }
    Ok(value)
}

/// The caller key header, name and value, for a request on `surface` from `identity`: only on
/// a surface with `caller_key`, from a caller whose JWT was verified on this request and names
/// it. When the secret cannot be read the request goes on without it, and a warning names the
/// surface.
pub(crate) async fn caller_key_header(
    surface: &AgentSurface,
    identity: Option<&AuthenticatedIdentity>,
    secrets: Option<&Arc<dyn SecretsStore>>,
) -> Option<(String, String)> {
    let config = surface.caller_key.as_ref()?;
    let caller = KeyedCaller::of(identity?, &config.identity_claims)?;
    let secret = match read_secret(surface, config, secrets).await {
        Ok(secret) => secret,
        Err(unreadable) => {
            warn!(
                surface = %surface.surface_id,
                reason = unreadable.reason(),
                "Forwarding without the caller key: its secret cannot be read"
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

    fn jwt(claims: Value) -> AuthenticatedIdentity {
        AuthenticatedIdentity::JwtBearer {
            subject: claims["sub"]
                .as_str()
                .unwrap_or("<none>")
                .to_string(),
            principal_claim: "sub".to_string(),
            claims,
        }
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
        caller_key_header(surface, identity, Some(&secrets)).await
    }

    /// RFC 5869 HKDF-SHA256 computed independently of the `hkdf` crate, from HMAC-SHA256:
    /// PRK = HMAC(salt, ikm), OKM = T(1) = HMAC(PRK, info || 0x01), the first 32 bytes.
    fn reference_key(
        secret: &[u8],
        info: &[u8],
    ) -> String {
        use hmac::{Hmac, Mac};
        let mut extract = Hmac::<Sha256>::new_from_slice(b"agent-gateway-caller-key-v1").expect("any key length");
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
    /// `surface-1`, `iss` `https://idp.example`, claim `sub` = `alice`. Info is
    /// `surface-1\0https://idp.example\0sub\0alice`.
    #[test]
    fn a_caller_key_matches_hkdf_sha256_of_the_documented_inputs() {
        let caller = KeyedCaller {
            issuer: "https://idp.example",
            claim: "sub",
            value: "alice",
        };
        let derived = derive(SECRET.as_bytes(), "surface-1", caller).expect("32 bytes derive");
        assert_eq!(derived, reference_key(SECRET.as_bytes(), b"surface-1\0https://idp.example\0sub\0alice"));
        assert_eq!(derived, "_gfJk16BtniPoTKJ7mn5nYKby4Gmbw7sxgLohCnKI34");
        assert_eq!(derived.len(), 43, "32 bytes are 43 base64url characters without padding");
    }

    #[test]
    fn a_caller_key_is_stable_and_differs_by_caller_issuer_claim_surface_and_secret() {
        let key = |secret: &str, surface_id: &str, issuer: &str, claim: &str, value: &str| {
            derive(secret.as_bytes(), surface_id, KeyedCaller { issuer, claim, value }).expect("derives")
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
            "nul": "a\u{0}b",
        }));
        let named = |order: &[&str]| {
            let order = claims(order);
            KeyedCaller::of(&token, &order).map(|caller| (caller.claim.to_string(), caller.value.to_string()))
        };
        assert_eq!(named(&["oid", "sub"]), Some(("oid".to_string(), "o-1".to_string())));
        assert_eq!(named(&["sub", "oid"]), Some(("sub".to_string(), "alice".to_string())));
        assert_eq!(
            named(&["uid", "groups", "email", "nul", "missing", "sub"]),
            Some(("sub".to_string(), "alice".to_string()))
        );
        assert_eq!(named(&["uid", "groups", "email", "nul", "missing"]), None);
    }

    #[test]
    fn a_token_without_a_usable_issuer_names_no_caller() {
        let sub = vec!["sub".to_string()];
        for claims in [
            serde_json::json!({ "sub": "alice" }),
            serde_json::json!({ "iss": "", "sub": "alice" }),
            serde_json::json!({ "iss": 7, "sub": "alice" }),
            serde_json::json!({ "iss": "https://idp\u{0}.example", "sub": "alice" }),
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
            Some(("x-caller-key".to_string(), "_gfJk16BtniPoTKJ7mn5nYKby4Gmbw7sxgLohCnKI34".to_string()))
        );
        assert_eq!(first, second, "one caller's key is stable across requests");

        let renamed =
            surface("surface-1", serde_json::json!({ "secret_id": "caller-keys", "header": "x-user-vault-key" }));
        assert_eq!(
            header_for(&renamed, Some(&alice()), &secrets).await,
            Some(("x-user-vault-key".to_string(), "_gfJk16BtniPoTKJ7mn5nYKby4Gmbw7sxgLohCnKI34".to_string()))
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
    async fn a_surface_without_caller_key_sends_none() {
        let secrets = [("caller-keys", SECRET, None)];
        let mut plain = surface("surface-1", serde_json::json!({ "secret_id": "caller-keys" }));
        plain.caller_key = None;
        assert_eq!(header_for(&plain, Some(&alice()), &secrets).await, None);
    }

    #[tokio::test]
    async fn an_unreadable_secret_sends_no_key() {
        let configured = surface("surface-1", serde_json::json!({ "secret_id": "caller-keys" }));
        assert_eq!(caller_key_header(&configured, Some(&alice()), None).await, None, "no store");
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
    fn the_default_and_every_stored_surfaces_caller_key_header_are_caller_key_headers() {
        for name in ["x-caller-key", "X-Caller-Key", "x_caller_key"] {
            assert!(is_caller_key_header(name), "{name}");
        }
        let header = "x-caller-key-registry-test";
        assert!(!is_caller_key_header(header));
        record_surface(&surface(
            "caller-key-registry-test",
            serde_json::json!({ "secret_id": "caller-keys", "header": header }),
        ));
        assert!(is_caller_key_header(header));
        assert!(is_caller_key_header("X_Caller_Key_Registry_Test"));
        assert!(!is_caller_key_header("x-caller-key-registry"));
        forget_surface("caller-key-registry-test");
        assert!(!is_caller_key_header(header));

        let mut renamed = surface(
            "caller-key-registry-rename-test",
            serde_json::json!({ "secret_id": "caller-keys", "header": "x-caller-key-before-rename" }),
        );
        record_surface(&renamed);
        renamed.caller_key = None;
        record_surface(&renamed);
        assert!(!is_caller_key_header("x-caller-key-before-rename"), "a surface that drops caller_key");
    }
}
