//! Grants by binding: the delegated credentials of external consent.
//!
//! A grant is keyed by the binding it serves and whose account it is: the
//! tenant, the surface, the hop (a Transit Point's id), the credential provider
//! and the principal, which is [`OWNER_PRINCIPAL`] for a grant every caller of
//! the binding uses, or a caller's identity hash. No agent DID is involved, so
//! a grant never crosses surfaces, hops or tenants.
//!
//! A record's id is derived from its key alone ([`GrantKey::record_id`]), so a
//! lookup is one read and one decrypt, never a scan. Grants are kept apart from
//! the agent-keyed [`super::DelegationToken`] records, in their own directory
//! of the vault, and only while at-rest encryption is active.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::storage::filesystem::StorableEntity;

/// The principal of a grant every caller of its binding uses.
pub const OWNER_PRINCIPAL: &str = "owner";

/// The directory of the vault that holds grants, excluded from storage exports.
pub const GRANTS_DIRECTORY: &str = "delegated_grants";

const RECORD_ID_LABEL: &[u8] = b"agent-gateway/delegated-grant-id/v1";
const RECORD_ID_PREFIX: &str = "grant-";

/// The vault refuses to store or read a grant while at-rest encryption is not
/// active.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("Delegated grants are kept only while at-rest encryption is enabled with a key")]
pub struct EncryptionRequired;

/// The vault refuses to store or release a grant while the identity hash
/// pepper was generated for this process: a grant's id derives from it, so the
/// next restart would orphan the grant.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("Delegated grants are kept only while AG_IDENTITY_HASH_PEPPER sets the identity hash pepper")]
pub struct EphemeralPepper;

/// What a grant is stored and found under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantKey {
    /// The tenant of the surface and the provider; `None` for an untenanted surface.
    pub tenant_id: Option<String>,
    /// The surface whose hop the grant serves.
    pub surface_id: String,
    /// The hop: a Transit Point's id.
    pub hop: String,
    /// The credential provider's record id.
    pub credential_provider_id: String,
    /// [`OWNER_PRINCIPAL`], or a caller's identity hash.
    pub principal: String,
}

impl GrantKey {
    /// The key of the one grant every caller of a binding uses.
    pub fn owner(
        tenant_id: Option<&str>,
        surface_id: &str,
        hop: &str,
        credential_provider_id: &str,
    ) -> Self {
        Self {
            tenant_id: tenant_id.map(str::to_string),
            surface_id: surface_id.to_string(),
            hop: hop.to_string(),
            credential_provider_id: credential_provider_id.to_string(),
            principal: OWNER_PRINCIPAL.to_string(),
        }
    }

    /// The key of one caller's grant. `None` unless `identity_hash` is an
    /// identity hash: 64 lowercase hex digits, so no caller's key is ever the
    /// owner's.
    pub fn caller(
        tenant_id: Option<&str>,
        surface_id: &str,
        hop: &str,
        credential_provider_id: &str,
        identity_hash: &str,
    ) -> Option<Self> {
        let is_identity_hash = identity_hash.len() == 64
            && identity_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        is_identity_hash.then(|| Self {
            principal: identity_hash.to_string(),
            ..Self::owner(tenant_id, surface_id, hop, credential_provider_id)
        })
    }

    /// The grant's record id: `grant-` and the lowercase hex HMAC-SHA256, under
    /// a key derived from the identity hash pepper, of the RFC 8785 JSON array
    /// `[tenant, surface, hop, provider, principal]`. It reveals nothing of the
    /// key, and gateways sharing the pepper derive the same id.
    pub fn record_id(&self) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let canonical = serde_json_canonicalizer::to_vec(&(
            self.tenant_id.as_deref(),
            self.surface_id.as_str(),
            self.hop.as_str(),
            self.credential_provider_id
                .as_str(),
            self.principal.as_str(),
        ))
        .expect("a tuple of strings is canonical JSON");
        let key = crate::identity::credential_identity::derived_key(RECORD_ID_LABEL);
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC key");
        mac.update(&canonical);
        format!("{RECORD_ID_PREFIX}{}", hex::encode(mac.finalize().into_bytes()))
    }
}

/// A grant stored for one binding and principal.
#[derive(Clone, Serialize, Deserialize)]
pub struct DelegatedGrant {
    /// [`GrantKey::record_id`] of the grant's key.
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub surface_id: String,
    pub hop: String,
    pub credential_provider_id: String,
    pub principal: String,
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(default = "default_token_type")]
    pub token_type: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
}

fn default_token_type() -> String {
    "Bearer".to_string()
}

impl std::fmt::Debug for DelegatedGrant {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        formatter
            .debug_struct("DelegatedGrant")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("surface_id", &self.surface_id)
            .field("hop", &self.hop)
            .field("credential_provider_id", &self.credential_provider_id)
            .field("principal", &self.principal)
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self
                    .refresh_token
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .field("token_type", &self.token_type)
            .field("scopes", &self.scopes)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("last_used_at", &self.last_used_at)
            .finish()
    }
}

impl StorableEntity for DelegatedGrant {
    fn id(&self) -> &str {
        &self.id
    }
}

impl DelegatedGrant {
    /// The key the grant is stored under.
    pub fn key(&self) -> GrantKey {
        GrantKey {
            tenant_id: self.tenant_id.clone(),
            surface_id: self.surface_id.clone(),
            hop: self.hop.clone(),
            credential_provider_id: self
                .credential_provider_id
                .clone(),
            principal: self.principal.clone(),
        }
    }

    /// Whether the access token has expired. A grant with no expiry never does.
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .is_some_and(|expires_at| Utc::now() >= expires_at)
    }
}

/// A stored grant, and the grant of the same key it replaced, whose tokens the
/// caller revokes.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct StoredGrant {
    pub grant: DelegatedGrant,
    pub replaced: Option<DelegatedGrant>,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn key() -> GrantKey {
        GrantKey::owner(Some("tenant-a"), "surface", "transit-point-id", "provider")
    }

    pub(crate) fn grant(
        key: &GrantKey,
        access_token: &str,
    ) -> DelegatedGrant {
        let now = Utc::now();
        DelegatedGrant {
            id: String::new(),
            tenant_id: key.tenant_id.clone(),
            surface_id: key.surface_id.clone(),
            hop: key.hop.clone(),
            credential_provider_id: key
                .credential_provider_id
                .clone(),
            principal: key.principal.clone(),
            access_token: access_token.to_string(),
            refresh_token: Some(format!("{access_token}-refresh")),
            token_type: "Bearer".to_string(),
            scopes: vec!["read".to_string()],
            expires_at: Some(now + chrono::Duration::hours(1)),
            created_at: now,
            updated_at: now,
            last_used_at: None,
        }
    }

    #[test]
    fn a_record_id_is_fixed_by_the_whole_key_and_reveals_none_of_it() {
        let base = key();
        let id = base.record_id();
        assert_eq!(id, key().record_id());
        assert!(id.starts_with("grant-"), "{id}");
        assert_eq!(id.len(), "grant-".len() + 64);
        for part in ["tenant-a", "surface", "transit-point-id", "provider", "owner"] {
            assert!(!id.contains(part), "{id} shows {part}");
        }
        let caller = "a".repeat(64);
        let others = [
            GrantKey {
                tenant_id: None,
                ..base.clone()
            },
            GrantKey {
                tenant_id: Some(String::new()),
                ..base.clone()
            },
            GrantKey {
                tenant_id: Some("tenant-b".into()),
                ..base.clone()
            },
            GrantKey {
                surface_id: "other-surface".into(),
                ..base.clone()
            },
            GrantKey {
                hop: "other-transit-point".into(),
                ..base.clone()
            },
            GrantKey {
                credential_provider_id: "other-provider".into(),
                ..base.clone()
            },
            GrantKey::caller(Some("tenant-a"), "surface", "transit-point-id", "provider", &caller).unwrap(),
        ];
        let mut ids: Vec<String> = others
            .iter()
            .map(GrantKey::record_id)
            .collect();
        ids.push(id);
        let count = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), count, "every key has its own id");
    }

    #[test]
    fn the_parts_of_a_key_cannot_be_shifted_into_one_another() {
        let shifted = GrantKey {
            surface_id: "surface:transit-point-id".into(),
            hop: String::new(),
            ..key()
        };
        assert_ne!(shifted.record_id(), key().record_id());
    }

    #[test]
    fn only_an_identity_hash_names_a_caller() {
        let hash = "0123456789abcdef".repeat(4);
        let caller = GrantKey::caller(None, "surface", "hop", "provider", &hash).unwrap();
        assert_eq!(caller.principal, hash);
        for principal in ["owner", "sha256:user", "", &hash.to_uppercase(), &hash[..63], &format!("{hash}0")] {
            assert!(GrantKey::caller(None, "surface", "hop", "provider", principal).is_none(), "{principal}");
        }
    }

    #[test]
    fn a_grants_debug_output_never_shows_its_tokens() {
        let grant = grant(&key(), "secret-access");
        let shown = format!("{grant:?}");
        assert!(!shown.contains("secret-access"), "{shown}");
        assert!(shown.contains("[REDACTED]"));
    }

    #[test]
    fn a_grant_expires_at_its_expiry_and_never_without_one() {
        let mut grant = grant(&key(), "access");
        assert!(!grant.is_expired());
        grant.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        assert!(grant.is_expired());
        grant.expires_at = None;
        assert!(!grant.is_expired());
    }
}
