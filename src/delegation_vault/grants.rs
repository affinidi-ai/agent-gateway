//! Grants by binding: the delegated credentials of external consent.
//!
//! A grant is keyed by the binding it serves and whose account it is: the
//! tenant, the surface, the hop (a Transit Point's id), the credential provider
//! and the principal, which is [`OWNER_PRINCIPAL`] for a grant every caller of
//! the binding uses, or a caller's identity hash. No agent DID is involved, so
//! a grant never crosses surfaces, hops or tenants.
//!
//! A record's id is derived from its key alone ([`GrantKey::record_id`]), so a
//! lookup is one read and one decrypt, never a scan. The id starts with a tag
//! of its provider and a tag of its binding ([`GrantBinding`]), so the grants
//! of one binding, or of one provider, are found by their file names, and
//! removing them reads and decrypts no other grant: an unreadable grant blocks
//! only its own binding. Grants are kept apart from the agent-keyed
//! [`super::DelegationToken`] records, in their own directory of the vault,
//! and only while at-rest encryption is active.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::storage::filesystem::StorableEntity;

/// The principal of a grant every caller of its binding uses.
pub const OWNER_PRINCIPAL: &str = "owner";

/// The directory of the vault that holds grants, excluded from storage exports.
pub const GRANTS_DIRECTORY: &str = "delegated_grants";

/// The file in [`GRANTS_DIRECTORY`] that holds [`pepper_fingerprint`] of the
/// pepper the grants there were written under.
pub const PEPPER_FINGERPRINT_FILE: &str = "pepper-fingerprint";

const RECORD_ID_LABEL: &[u8] = b"agent-gateway/delegated-grant-id/v1";
const PROVIDER_TAG_LABEL: &[u8] = b"agent-gateway/delegated-grant-provider/v1";
const BINDING_TAG_LABEL: &[u8] = b"agent-gateway/delegated-grant-binding/v1";
const PEPPER_FINGERPRINT_LABEL: &[u8] = b"agent-gateway/delegated-grant-pepper-fingerprint/v1";
const RECORD_ID_PREFIX: &str = "grant-";
/// Hex digits of a provider or binding tag.
const TAG_DIGITS: usize = 32;
/// Hex digits of the last part of a record id, the HMAC of the whole key.
const KEY_DIGITS: usize = 64;

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

/// The grants stored were written under another identity hash pepper than this
/// gateway's: their ids, and the tags that file them by binding, derive from
/// it. Until the pepper they were written under is restored, or they are
/// purged, the vault neither stores nor releases a grant, and no binding's
/// grants can be found to remove them.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error(
    "The delegated grants stored were written under another identity hash pepper (AG_IDENTITY_HASH_PEPPER); restore \
     the pepper they were written under, or purge them"
)]
pub struct PepperMismatch;

/// Why a stored grant cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnreadableReason {
    /// At-rest encryption is off, so an encrypted grant cannot be decrypted.
    EncryptionOff,
    /// The record cannot be decrypted with the current key, or parsed.
    Undecryptable,
}

impl std::fmt::Display for UnreadableReason {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::EncryptionOff => "at-rest encryption is off",
            Self::Undecryptable => "it cannot be decrypted with the current key or parsed",
        })
    }
}

/// A stored grant that cannot be read, so it can be neither revoked nor
/// removed with its binding or provider. Only removals that need this grant
/// are refused; an operator can purge it by its id without reading it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Delegated grant {grant_id} cannot be read: {reason}")]
pub struct UnreadableGrant {
    pub grant_id: String,
    pub reason: UnreadableReason,
}

/// Which of a binding's grants an operation concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Principals {
    /// The one grant every caller uses, [`OWNER_PRINCIPAL`]'s.
    Owner,
    /// Every caller's own grant.
    Callers,
    /// Both.
    All,
}

/// The binding a grant serves: everything of its key but the principal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GrantBinding {
    pub tenant_id: Option<String>,
    pub surface_id: String,
    pub hop: String,
    pub credential_provider_id: String,
}

impl GrantBinding {
    pub fn new(
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
        }
    }

    /// What every record id of the binding's grants starts with: the
    /// provider's prefix ([`provider_record_id_prefix`]), then a tag of the
    /// binding, the first 32 hex digits of an HMAC-SHA256, under a key derived
    /// from the identity hash pepper, of the RFC 8785 JSON array
    /// `[tenant, surface, hop, provider]`, then `-`.
    pub fn record_id_prefix(&self) -> String {
        let tag = keyed_hex(
            BINDING_TAG_LABEL,
            &(
                self.tenant_id.as_deref(),
                self.surface_id.as_str(),
                self.hop.as_str(),
                self.credential_provider_id
                    .as_str(),
            ),
        );
        format!("{}{}-", provider_record_id_prefix(&self.credential_provider_id), &tag[..TAG_DIGITS])
    }

    /// The record id of the binding's owner grant.
    pub fn owner_record_id(&self) -> String {
        GrantKey::owner(self.tenant_id.as_deref(), &self.surface_id, &self.hop, &self.credential_provider_id)
            .record_id()
    }

    /// Whether `id`, a record id under this binding's prefix, is one of the
    /// grants `principals` names.
    pub fn names(
        &self,
        principals: Principals,
        id: &str,
    ) -> bool {
        match principals {
            Principals::All => true,
            Principals::Owner => id == self.owner_record_id(),
            Principals::Callers => id != self.owner_record_id(),
        }
    }
}

/// What every record id of the grants made with one credential provider
/// starts with: `grant-`, then a tag of the provider's record id, the first 32
/// hex digits of an HMAC-SHA256 under a key derived from the identity hash
/// pepper, then `-`.
pub fn provider_record_id_prefix(credential_provider_id: &str) -> String {
    let tag = keyed_hex(PROVIDER_TAG_LABEL, &(credential_provider_id,));
    format!("{RECORD_ID_PREFIX}{}-", &tag[..TAG_DIGITS])
}

/// Whether `id` has the shape of a grant's record id: `grant-`, a provider tag,
/// a binding tag and the key's HMAC, in lowercase hex, joined by `-`.
pub fn is_record_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix(RECORD_ID_PREFIX) else {
        return false;
    };
    let parts: Vec<&str> = rest.split('-').collect();
    let lowercase_hex = |part: &str, digits: usize| {
        part.len() == digits
            && part
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    matches!(parts.as_slice(), [provider, binding, key]
        if lowercase_hex(provider, TAG_DIGITS) && lowercase_hex(binding, TAG_DIGITS) && lowercase_hex(key, KEY_DIGITS))
}

/// A fingerprint of the identity hash pepper: the lowercase hex HMAC-SHA256,
/// under a key derived from the pepper, of a fixed label. It tells whether two
/// gateways, or two runs, share the pepper, and reveals nothing of it.
pub fn pepper_fingerprint() -> String {
    keyed_hex(PEPPER_FINGERPRINT_LABEL, &("delegated grants",))
}

/// The lowercase hex HMAC-SHA256, under the key derived from the pepper for
/// `label`, of `parts` as RFC 8785 JSON.
fn keyed_hex(
    label: &[u8],
    parts: &impl Serialize,
) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let canonical = serde_json_canonicalizer::to_vec(parts).expect("a tuple of strings is canonical JSON");
    let key = crate::identity::credential_identity::derived_key(label);
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC key");
    mac.update(&canonical);
    hex::encode(mac.finalize().into_bytes())
}

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

    /// The binding the grant serves.
    pub fn binding(&self) -> GrantBinding {
        GrantBinding::new(self.tenant_id.as_deref(), &self.surface_id, &self.hop, &self.credential_provider_id)
    }

    /// The grant's record id: its binding's [`GrantBinding::record_id_prefix`],
    /// then the lowercase hex HMAC-SHA256, under a key derived from the
    /// identity hash pepper, of the RFC 8785 JSON array
    /// `[tenant, surface, hop, provider, principal]`. It reveals nothing of the
    /// key beyond which grants share a provider or a binding, and gateways
    /// sharing the pepper derive the same id.
    pub fn record_id(&self) -> String {
        let key = keyed_hex(
            RECORD_ID_LABEL,
            &(
                self.tenant_id.as_deref(),
                self.surface_id.as_str(),
                self.hop.as_str(),
                self.credential_provider_id
                    .as_str(),
                self.principal.as_str(),
            ),
        );
        format!(
            "{}{key}",
            self.binding()
                .record_id_prefix()
        )
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
        assert!(is_record_id(&id), "{id}");
        assert_eq!(id.len(), "grant-".len() + 32 + 1 + 32 + 1 + 64);
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

    /// A grant's record id is filed under its provider, then its binding, so the
    /// grants of one binding or one provider are found by name alone.
    #[test]
    fn a_record_id_is_filed_under_its_provider_and_then_its_binding() {
        let caller =
            GrantKey::caller(Some("tenant-a"), "surface", "transit-point-id", "provider", &"a".repeat(64)).unwrap();
        let binding = key().binding();
        assert_eq!(caller.binding(), binding);
        for id in [key().record_id(), caller.record_id()] {
            assert!(id.starts_with(&binding.record_id_prefix()), "{id}");
            assert!(id.starts_with(&provider_record_id_prefix("provider")), "{id}");
        }
        assert_eq!(binding.owner_record_id(), key().record_id());
        assert!(binding.names(Principals::Owner, &key().record_id()));
        assert!(!binding.names(Principals::Owner, &caller.record_id()));
        assert!(binding.names(Principals::Callers, &caller.record_id()));
        assert!(!binding.names(Principals::Callers, &key().record_id()));
        for other in [
            GrantKey {
                tenant_id: Some("tenant-b".into()),
                ..key()
            },
            GrantKey {
                surface_id: "other-surface".into(),
                ..key()
            },
            GrantKey {
                hop: "other-transit-point".into(),
                ..key()
            },
        ] {
            let id = other.record_id();
            assert!(!id.starts_with(&binding.record_id_prefix()), "{other:?}");
            assert!(id.starts_with(&provider_record_id_prefix("provider")), "{other:?}");
        }
        let other_provider = GrantKey {
            credential_provider_id: "other-provider".into(),
            ..key()
        };
        assert!(
            !other_provider
                .record_id()
                .starts_with(&provider_record_id_prefix("provider"))
        );
        assert!(!is_record_id("grant-../../etc"));
        assert!(!is_record_id(PEPPER_FINGERPRINT_FILE));
        assert!(!is_record_id(&format!("grant-{}", "a".repeat(64))));
    }

    #[test]
    fn the_pepper_fingerprint_names_the_pepper_and_reveals_none_of_it() {
        crate::identity::credential_identity::configure_pepper_bytes_for_tests(&[7; 32]);
        let first = pepper_fingerprint();
        assert_eq!(first, pepper_fingerprint());
        assert_eq!(first.len(), 64);
        assert!(!first.contains(&hex::encode([7u8; 32])));
        crate::identity::credential_identity::configure_pepper_bytes_for_tests(&[8; 32]);
        assert_ne!(first, pepper_fingerprint());
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
