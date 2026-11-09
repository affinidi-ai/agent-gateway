//! Revocations that wait, kept so they are delayed, never lost.
//!
//! At a provider whose revocation ends the person's whole authorization, a
//! removed grant is revoked only once no other grant of the same vendor
//! account uses that authorization. When the vault cannot tell, the removed
//! grant is kept here, encrypted, and the daily sweep decides again
//! ([`Deferral::AuthorizationInUse`]).
//!
//! Every other removed grant is kept here too, while its revocation runs
//! ([`Deferral::Pending`]): one in flight when the gateway stops, or that
//! could not reach its vendor, is tried again when the gateway starts and by
//! the daily sweep, a bounded number of times.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::credential_providers::CredentialProvider;
use crate::delegation_vault::grants::DelegatedGrant;
use crate::storage::filesystem::StorableEntity;

/// The directory of the vault that holds deferred revocations. Excluded from
/// storage exports.
pub const DEFERRED_REVOCATIONS_DIRECTORY: &str = "delegated_grant_revocations";

const ID_PREFIX: &str = "revocation-";
const ID_DIGITS: usize = 32;

/// Why a revocation waits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Deferral {
    /// The vault could not tell whether another grant of the vendor account
    /// uses the authorization its revocation would end; the daily sweep
    /// decides.
    #[default]
    AuthorizationInUse,
    /// The revocation is under way, or could not reach its vendor: it is
    /// tried again when the gateway starts and by the daily sweep.
    Pending,
}

/// A removed grant whose revocation waits.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeferredRevocation {
    /// `revocation-` and 32 random lowercase hex digits.
    pub id: String,
    /// The grant removed, whose tokens are still to be revoked.
    pub grant: DelegatedGrant,
    pub deferred_at: DateTime<Utc>,
    #[serde(default)]
    pub deferral: Deferral,
    /// How many times a pending revocation could not reach its vendor.
    #[serde(default)]
    pub attempts: u32,
    /// The grant's provider as it was when the revocation was kept, so the
    /// revocation can still be decided once the provider is deleted. Holds
    /// secret references, never secret values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<CredentialProvider>,
}

impl std::fmt::Debug for DeferredRevocation {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        formatter
            .debug_struct("DeferredRevocation")
            .field("id", &self.id)
            .field("grant", &self.grant)
            .field("deferred_at", &self.deferred_at)
            .field("deferral", &self.deferral)
            .field("attempts", &self.attempts)
            .field(
                "provider",
                &self
                    .provider
                    .as_ref()
                    .map(|provider| &provider.id),
            )
            .finish()
    }
}

impl StorableEntity for DeferredRevocation {
    fn id(&self) -> &str {
        &self.id
    }
}

impl DeferredRevocation {
    /// A revocation of `grant` that waits for `deferral`, under a new random
    /// id.
    pub fn new(
        grant: DelegatedGrant,
        now: DateTime<Utc>,
        deferral: Deferral,
    ) -> Self {
        use rand::RngCore as _;
        let mut random = [0u8; ID_DIGITS / 2];
        rand::rng().fill_bytes(&mut random);
        Self {
            id: format!("{ID_PREFIX}{}", hex::encode(random)),
            grant,
            deferred_at: now,
            deferral,
            attempts: 0,
            provider: None,
        }
    }

    /// This revocation, keeping `provider` to decide it with once the
    /// provider is deleted.
    pub fn with_provider(
        mut self,
        provider: Option<CredentialProvider>,
    ) -> Self {
        self.provider = provider;
        self
    }
}

/// Whether `id` has the shape of a deferred revocation's id.
pub(super) fn is_deferred_revocation_id(id: &str) -> bool {
    id.strip_prefix(ID_PREFIX)
        .is_some_and(|random| {
            random.len() == ID_DIGITS
                && random
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}
