//! Grants by binding: the delegated credentials of external consent.
//!
//! A grant is keyed by the binding it serves and whose account it is: the
//! tenant, the surface, the hop (a Transit Point's id, or
//! [`ACCESS_POINT_TARGET_HOP`] for the surface's Access Point Target), the
//! credential provider and the principal, which is [`OWNER_PRINCIPAL`] for a
//! grant every caller of the binding uses, or a caller's identity hash. No
//! agent DID is involved, so a grant never crosses surfaces, hops or tenants.
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

/// The hop of the grants of a surface's Access Point Target, whose binding is
/// the surface's `outbound_credentials` with `consent_mode: external`. No
/// Transit Point with external consent may take it as its id.
pub const ACCESS_POINT_TARGET_HOP: &str = "target";

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
const CONNECT_ID_PREFIX: &str = "connect-";
/// Hex digits of a provider or binding tag.
const TAG_DIGITS: usize = 32;
/// Hex digits of the last part of a record id, the HMAC of the whole key, and
/// of the random part of a connect id.
const KEY_DIGITS: usize = 64;
/// Hex digits of the principal tag of a connect id.
const PRINCIPAL_TAG_DIGITS: usize = 16;
/// Hex digits of the expiry, in Unix seconds, of a connect id.
const EXPIRY_DIGITS: usize = 16;
const CONNECT_PRINCIPAL_TAG_LABEL: &[u8] = b"agent-gateway/pending-connect-principal/v1";

/// How long before its access token expires a grant is refreshed, at least.
const REFRESH_SKEW_SECS: i64 = 60;
/// A grant is refreshed once less than this fraction of its access token's
/// life is left, when that is longer than [`REFRESH_SKEW_SECS`].
const REFRESH_LIFE_DIVISOR: i32 = 10;
/// The first wait before a grant whose refresh failed is refreshed again; it
/// doubles with each failure in a row, up to [`REFRESH_BACKOFF_MAX_SECS`].
const REFRESH_BACKOFF_SECS: i64 = 30;
const REFRESH_BACKOFF_MAX_SECS: i64 = 900;

fn lowercase_hex(
    part: &str,
    digits: usize,
) -> bool {
    part.len() == digits
        && part
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A new pending connect's id for the grant `key`, open until `expires_at`:
/// its [`GrantKey::connect_id_prefix`], the expiry in Unix seconds as 16
/// lowercase hex digits, then 64 random hex digits. The connects open for a
/// binding, and for one principal of it, are counted from their file names
/// alone.
pub fn new_connect_id(
    key: &GrantKey,
    expires_at: DateTime<Utc>,
) -> String {
    use rand::RngCore as _;
    let mut random = [0u8; 32];
    rand::rng().fill_bytes(&mut random);
    let expiry = u64::try_from(expires_at.timestamp()).unwrap_or_default();
    format!("{}{expiry:016x}-{}", key.connect_id_prefix(), hex::encode(random))
}

/// Whether `id` has the shape of a pending connect's id: `connect-`, a binding
/// tag, a principal tag, an expiry and 64 random hex digits, in lowercase,
/// joined by `-`.
pub fn is_connect_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix(CONNECT_ID_PREFIX) else {
        return false;
    };
    matches!(rest.split('-').collect::<Vec<_>>().as_slice(), [binding, principal, expiry, random]
        if lowercase_hex(binding, TAG_DIGITS)
            && lowercase_hex(principal, PRINCIPAL_TAG_DIGITS)
            && lowercase_hex(expiry, EXPIRY_DIGITS)
            && lowercase_hex(random, KEY_DIGITS))
}

/// When the connect with id `id` expires, as its id says, if it is a
/// connect's id.
pub fn connect_expiry(id: &str) -> Option<DateTime<Utc>> {
    if !is_connect_id(id) {
        return None;
    }
    let expiry = id.rsplit('-').nth(1)?;
    let seconds = i64::try_from(u64::from_str_radix(expiry, 16).ok()?).ok()?;
    DateTime::from_timestamp(seconds, 0)
}

/// The vault refuses to store or read a grant while at-rest encryption is not
/// active.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("Delegated grants are kept only while at-rest encryption is enabled with a key")]
pub struct EncryptionRequired;

/// A revocation the vault kept cannot be read now, as when at-rest encryption
/// is off or its record fails to decrypt: whoever needs every kept revocation
/// of a provider must wait until it can be.
#[derive(Debug, Clone, thiserror::Error)]
#[error("A kept revocation {revocation_id} cannot be read")]
pub struct UnreadableKeptRevocation {
    pub revocation_id: String,
}

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
        format!("{}{}-", provider_record_id_prefix(&self.credential_provider_id), self.tag())
    }

    /// What the id of every pending connect of the binding starts with:
    /// `connect-`, the binding's tag, then `-`.
    pub fn connect_id_prefix(&self) -> String {
        format!("{CONNECT_ID_PREFIX}{}-", self.tag())
    }

    /// The first 32 hex digits of an HMAC-SHA256, under a key derived from the
    /// identity hash pepper, of the RFC 8785 JSON array
    /// `[tenant, surface, hop, provider]`.
    fn tag(&self) -> String {
        let mut tag = keyed_hex(
            BINDING_TAG_LABEL,
            &(
                self.tenant_id.as_deref(),
                self.surface_id.as_str(),
                self.hop.as_str(),
                self.credential_provider_id
                    .as_str(),
            ),
        );
        tag.truncate(TAG_DIGITS);
        tag
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
    /// The hop: a Transit Point's id, or [`ACCESS_POINT_TARGET_HOP`].
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

    /// What the id of every pending connect for this grant starts with: its
    /// binding's [`GrantBinding::connect_id_prefix`], then a tag of the
    /// principal, the first 16 hex digits of an HMAC-SHA256, under a key
    /// derived from the identity hash pepper, of the RFC 8785 JSON array
    /// `[tenant, surface, hop, provider, principal]`, then `-`.
    pub fn connect_id_prefix(&self) -> String {
        let mut tag = keyed_hex(
            CONNECT_PRINCIPAL_TAG_LABEL,
            &(
                self.tenant_id.as_deref(),
                self.surface_id.as_str(),
                self.hop.as_str(),
                self.credential_provider_id
                    .as_str(),
                self.principal.as_str(),
            ),
        );
        tag.truncate(PRINCIPAL_TAG_DIGITS);
        format!(
            "{}{tag}-",
            self.binding()
                .connect_id_prefix()
        )
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
    /// The scopes the token holds, as the authorization server last named
    /// them; when it named none, the ones asked for at the connect, or those
    /// held before at a refresh.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// The scopes the connect asked for, which the person consented to; every
    /// refresh asks again for those of them the grant still holds. `None` for
    /// a grant that does not record them, whose [`Self::scopes`] stand for them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_scopes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// When the person connected, which is when they consented: a refresh
    /// keeps it, and a new connect makes a new grant.
    pub created_at: DateTime<Utc>,
    /// When the consent ends: `created_at` plus the time limit in force at the
    /// connect. `None` for a grant connected under no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_expires_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    /// When the access token was obtained, by the connect or the last
    /// refresh; the grant's `created_at` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refreshed_at: Option<DateTime<Utc>>,
    /// When the last refresh failed, for a grant whose refresh has failed
    /// since its access token was obtained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_failed_at: Option<DateTime<Utc>>,
    /// How many refreshes in a row have failed.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub refresh_failures: u32,
    /// When a failed refresh may be tried again; unset after a failure that
    /// is never retried, whose grant needs a new connect once it expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_retry_at: Option<DateTime<Utc>>,
    /// How many refreshes the authorization server refused, by an answer
    /// other than `invalid_grant`, since the last that succeeded.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub refresh_refusals: u32,
    /// The vendor account the grant is for: the `sub` of the OpenID Connect
    /// ID token its connect obtained, issued by the provider's issuer for its
    /// client; `None` when the connect obtained none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor_subject: Option<String>,
}

/// How a failed refresh is recorded on its grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailedRefresh {
    /// Tried again after a wait: nothing says the grant is dead.
    Retried,
    /// Tried again after a wait, and counted as the authorization server
    /// refusing the grant's refresh, by an answer other than `invalid_grant`.
    Refused,
    /// Never tried again: the grant needs a new connect once its access
    /// token expires.
    Abandoned,
}

fn is_zero(value: &u32) -> bool {
    *value == 0
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
            .field("requested_scopes", &self.requested_scopes)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .field("consent_expires_at", &self.consent_expires_at)
            .field("updated_at", &self.updated_at)
            .field("last_used_at", &self.last_used_at)
            .field("refreshed_at", &self.refreshed_at)
            .field("refresh_failed_at", &self.refresh_failed_at)
            .field("refresh_failures", &self.refresh_failures)
            .field("refresh_retry_at", &self.refresh_retry_at)
            .field("refresh_refusals", &self.refresh_refusals)
            .field(
                "vendor_subject",
                &self
                    .vendor_subject
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl StorableEntity for DelegatedGrant {
    fn id(&self) -> &str {
        &self.id
    }
}

/// The tokens an authorization server answered a token request with.
pub struct ObtainedTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// The scopes granted.
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl DelegatedGrant {
    /// A grant for `key` of `tokens`, obtained at `now`. Its record id is set
    /// when it is stored.
    pub fn new(
        key: &GrantKey,
        tokens: ObtainedTokens,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            id: String::new(),
            tenant_id: key.tenant_id.clone(),
            surface_id: key.surface_id.clone(),
            hop: key.hop.clone(),
            credential_provider_id: key
                .credential_provider_id
                .clone(),
            principal: key.principal.clone(),
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            token_type: default_token_type(),
            scopes: tokens.scopes,
            requested_scopes: None,
            expires_at: tokens.expires_at,
            created_at: now,
            consent_expires_at: None,
            updated_at: now,
            last_used_at: None,
            refreshed_at: Some(now),
            refresh_failed_at: None,
            refresh_failures: 0,
            refresh_retry_at: None,
            refresh_refusals: 0,
            vendor_subject: None,
        }
    }

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

    /// The scopes the person consented to: those the connect asked for.
    pub fn scopes_asked_for(&self) -> &[String] {
        self.requested_scopes
            .as_deref()
            .unwrap_or(&self.scopes)
    }

    /// Whether the access token has expired. A grant with no expiry never does.
    pub fn is_expired(&self) -> bool {
        self.is_expired_at(Utc::now())
    }

    fn is_expired_at(
        &self,
        now: DateTime<Utc>,
    ) -> bool {
        self.expires_at
            .is_some_and(|expires_at| now >= expires_at)
    }

    /// When the access token was obtained.
    pub fn obtained_at(&self) -> DateTime<Utc> {
        self.refreshed_at
            .unwrap_or(self.created_at)
    }

    /// Whether the grant is due a refresh at `now`: its access token expires
    /// in under a minute, or with under a tenth of its life left, whichever
    /// comes first. A grant with no expiry is never due.
    pub fn refresh_due_at(
        &self,
        now: DateTime<Utc>,
    ) -> bool {
        let Some(expires_at) = self.expires_at else {
            return false;
        };
        let life = expires_at - self.obtained_at();
        let skew = std::cmp::max(chrono::Duration::seconds(REFRESH_SKEW_SECS), life / REFRESH_LIFE_DIVISOR);
        now >= expires_at - skew
    }

    /// Whether a refresh may be tried at `now`: its last refresh did not fail,
    /// or failed in a way that is retried and its wait is over.
    pub fn refresh_permitted_at(
        &self,
        now: DateTime<Utc>,
    ) -> bool {
        match (self.refresh_failed_at, self.refresh_retry_at) {
            (None, _) => true,
            (Some(_), Some(retry_at)) => now >= retry_at,
            (Some(_), None) => false,
        }
    }

    /// Whether the last refresh failed in a way that is never retried, so the
    /// grant needs a new connect once its access token expires.
    pub fn refresh_abandoned(&self) -> bool {
        self.refresh_failed_at
            .is_some()
            && self
                .refresh_retry_at
                .is_none()
    }

    /// Record a refresh that failed at `now`: retried after a wait that
    /// doubles with each failure in a row, up to [`REFRESH_BACKOFF_MAX_SECS`],
    /// or, when abandoned, never. A refusal is counted as such.
    pub fn record_refresh_failure(
        &mut self,
        now: DateTime<Utc>,
        failure: FailedRefresh,
    ) {
        self.refresh_failures = self
            .refresh_failures
            .saturating_add(1);
        if failure == FailedRefresh::Refused {
            self.refresh_refusals = self
                .refresh_refusals
                .saturating_add(1);
        }
        self.refresh_failed_at = Some(now);
        self.refresh_retry_at = (failure != FailedRefresh::Abandoned).then(|| {
            let doublings = self
                .refresh_failures
                .saturating_sub(1)
                .min(10);
            let wait = REFRESH_BACKOFF_SECS
                .saturating_mul(1 << doublings)
                .min(REFRESH_BACKOFF_MAX_SECS);
            now + chrono::Duration::seconds(wait)
        });
    }

    /// Whether the authorization server has refused the grant's refresh
    /// `limit` times or more since it last succeeded, so a call that cannot
    /// use the grant asks for a new connect.
    pub fn refused_too_often(
        &self,
        limit: u32,
    ) -> bool {
        self.refresh_refusals >= limit
    }

    /// Whether the grant's access token expired more than `days` days before
    /// `now` and its refresh has failed since it was obtained.
    pub fn failing_for(
        &self,
        now: DateTime<Utc>,
        days: i64,
    ) -> bool {
        self.refresh_failed_at
            .is_some()
            && now
                .checked_sub_signed(chrono::Duration::days(days))
                .is_some_and(|then| self.is_expired_at(then))
    }

    /// The grant's state as the management API reports it: `refresh_failed`
    /// once a refresh has failed since its access token was obtained, else
    /// `live`.
    pub fn state(&self) -> &'static str {
        if self
            .refresh_failed_at
            .is_some()
        {
            "refresh_failed"
        } else {
            "live"
        }
    }

    /// Whether a release at `now` records the grant's use: it has none
    /// recorded, or the last is at least [`USE_RECORD_INTERVAL_SECS`] old, so a
    /// busy Transit Point does not rewrite its grant on every call.
    pub fn use_is_due(
        &self,
        now: DateTime<Utc>,
    ) -> bool {
        self.last_used_at
            .is_none_or(|last| now - last >= chrono::Duration::seconds(USE_RECORD_INTERVAL_SECS))
    }
}

/// How old a grant's last recorded use must be before a release records it
/// again.
pub const USE_RECORD_INTERVAL_SECS: i64 = 3600;

/// A stored grant, and the grant of the same key it replaced, whose tokens the
/// caller revokes.
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
        DelegatedGrant::new(
            key,
            ObtainedTokens {
                access_token: access_token.to_string(),
                refresh_token: Some(format!("{access_token}-refresh")),
                scopes: vec!["read".to_string()],
                expires_at: Some(now + chrono::Duration::hours(1)),
            },
            now,
        )
    }

    /// A grant is due a refresh a minute before its access token expires, or
    /// with a tenth of its life left, whichever is earlier; never without an
    /// expiry.
    #[test]
    fn a_grant_is_due_a_refresh_a_minute_or_a_tenth_of_its_life_before_it_expires() {
        let now = Utc::now();
        let mut grant = grant(&key(), "access");
        grant.refreshed_at = Some(now);
        grant.expires_at = Some(now + chrono::Duration::hours(1));
        assert!(!grant.refresh_due_at(now));
        assert!(!grant.refresh_due_at(now + chrono::Duration::minutes(53)));
        assert!(grant.refresh_due_at(now + chrono::Duration::minutes(54)), "a tenth of an hour is six minutes");
        grant.expires_at = Some(now + chrono::Duration::seconds(300));
        assert!(!grant.refresh_due_at(now + chrono::Duration::seconds(239)));
        assert!(grant.refresh_due_at(now + chrono::Duration::seconds(240)), "at least a minute");
        grant.expires_at = None;
        assert!(!grant.refresh_due_at(now + chrono::Duration::days(365)));
    }

    /// A failed refresh is retried after a wait that doubles with each failure
    /// in a row, up to fifteen minutes, or never, when it cannot be retried.
    #[test]
    fn a_failed_refresh_waits_longer_each_time_or_is_never_retried() {
        let now = Utc::now();
        let mut grant = grant(&key(), "access");
        assert!(grant.refresh_permitted_at(now));
        assert_eq!(grant.state(), "live");
        let mut waits = Vec::new();
        for _ in 0..7 {
            grant.record_refresh_failure(now, FailedRefresh::Retried);
            waits.push(
                (grant
                    .refresh_retry_at
                    .unwrap()
                    - now)
                    .num_seconds(),
            );
        }
        assert_eq!(waits, [30, 60, 120, 240, 480, 900, 900]);
        assert!(!grant.refresh_permitted_at(now + chrono::Duration::seconds(899)));
        assert!(grant.refresh_permitted_at(now + chrono::Duration::seconds(900)));
        assert!(!grant.refresh_abandoned());
        assert_eq!(grant.state(), "refresh_failed");
        grant.record_refresh_failure(now, FailedRefresh::Abandoned);
        assert!(grant.refresh_abandoned());
        assert!(!grant.refresh_permitted_at(now + chrono::Duration::days(1)));
    }

    /// Refusals of a grant's refresh are counted, and only those: a failure
    /// that says nothing of the grant, such as an unreachable endpoint, is
    /// not. The wait between refreshes stays at most fifteen minutes however
    /// many fail.
    #[test]
    fn refusals_of_a_refresh_are_counted_and_the_wait_stays_bounded() {
        let now = Utc::now();
        let mut grant = grant(&key(), "access");
        grant.record_refresh_failure(now, FailedRefresh::Refused);
        grant.record_refresh_failure(now, FailedRefresh::Retried);
        grant.record_refresh_failure(now, FailedRefresh::Refused);
        assert_eq!(grant.refresh_refusals, 2);
        assert_eq!(grant.refresh_failures, 3);
        for _ in 0..100 {
            grant.record_refresh_failure(now, FailedRefresh::Refused);
        }
        assert_eq!(grant.refresh_refusals, 102);
        assert_eq!(
            (grant
                .refresh_retry_at
                .unwrap()
                - now)
                .num_seconds(),
            900
        );
        grant.refresh_failures = u32::MAX;
        grant.refresh_refusals = u32::MAX;
        grant.record_refresh_failure(now, FailedRefresh::Refused);
        assert_eq!(grant.refresh_refusals, u32::MAX);
        assert_eq!(
            (grant
                .refresh_retry_at
                .unwrap()
                - now)
                .num_seconds(),
            900
        );
    }

    #[test]
    fn a_grants_use_is_recorded_at_most_once_an_interval() {
        let now = Utc::now();
        let mut used = grant(&key(), "access");
        assert!(used.use_is_due(now), "a grant never used");
        used.last_used_at = Some(now - chrono::Duration::seconds(USE_RECORD_INTERVAL_SECS - 1));
        assert!(!used.use_is_due(now), "one used within the interval");
        used.last_used_at = Some(now - chrono::Duration::seconds(USE_RECORD_INTERVAL_SECS));
        assert!(used.use_is_due(now), "one whose last use is an interval old");
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

    /// A pending connect's id is filed under its binding and its principal,
    /// names when it expires, has 256 random bits after that, and reveals
    /// nothing of the binding or the principal.
    #[test]
    fn a_connect_id_is_filed_under_its_binding_and_principal_and_is_otherwise_random() {
        let binding = key().binding();
        let expires_at = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let first = new_connect_id(&key(), expires_at);
        assert_ne!(first, new_connect_id(&key(), expires_at));
        assert!(first.starts_with(&binding.connect_id_prefix()), "{first}");
        assert!(first.starts_with(&key().connect_id_prefix()), "{first}");
        assert!(is_connect_id(&first), "{first}");
        assert_eq!(connect_expiry(&first), Some(expires_at));
        assert_eq!(first.len(), "connect-".len() + 32 + 1 + 16 + 1 + 16 + 1 + 64);
        for part in ["tenant-a", "surface", "transit-point-id", "provider", "owner"] {
            assert!(!first.contains(part), "{first} shows {part}");
        }
        let other = GrantKey {
            hop: "other-hop".into(),
            ..key()
        };
        assert!(!new_connect_id(&other, expires_at).starts_with(&binding.connect_id_prefix()));
        let caller =
            GrantKey::caller(Some("tenant-a"), "surface", "transit-point-id", "provider", &"c".repeat(64)).unwrap();
        let theirs = new_connect_id(&caller, expires_at);
        assert!(theirs.starts_with(&binding.connect_id_prefix()), "the same binding");
        assert!(!theirs.starts_with(&key().connect_id_prefix()), "another principal");
        assert!(!is_connect_id(&key().record_id()));
        assert!(!is_connect_id("connect-../../etc"));
        assert!(!is_connect_id(&first.to_uppercase()));
        assert_eq!(connect_expiry("connect-../../etc"), None);
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
