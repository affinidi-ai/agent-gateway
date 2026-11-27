//! Single use of agent presentations. Each admitted presentation proof is
//! recorded in the single-use store ([`Namespace::VpProof`], held in memory)
//! for [`RECORD_SECS`] from its claim, longer than any proof verified at the
//! claim stays valid, so the same proof is refused when it is presented again.
//! Claims are bounded by a total limit and a per-holder limit, both counted on
//! this node.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use chrono::Utc;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::verifier::VP_CLOCK_SKEW_SECS;
use super::vp_issuer::VP_LIFETIME_MINUTES;
use crate::storage::single_use::{self, Namespace};

/// How long a holder's claim counts against its limit.
const HOLDER_WINDOW_SECS: u64 = 420;

/// How long a claim records its proofs: the VP lifetime plus the clock skew on
/// each side.
pub(crate) const RECORD_SECS: u64 = (VP_LIFETIME_MINUTES * 60 + 2 * VP_CLOCK_SKEW_SECS).unsigned_abs();

/// How many expired records and ended windows a claim prunes beyond its own
/// key count.
const PRUNE_PER_CLAIM: usize = 64;

/// The `flow` label of a presentation refused at an Access Point.
pub const FLOW_ACCESS_POINT: &str = "access_point";
/// The `flow` label of a presentation refused on a Fabric request.
pub const FLOW_FABRIC_REQUEST: &str = "fabric_request";
/// The `flow` label of a presentation refused on a Fabric answer.
pub const FLOW_FABRIC_ANSWER: &str = "fabric_answer";
/// The `flow` label of a presentation refused at the token exchange.
pub const FLOW_STS: &str = "sts";

/// The replay key of one presentation proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VpReplayKey {
    digest: [u8; 32],
}

/// The proofs of the presentations a verify result covers, and the holder
/// they are counted against: the first holder added.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Presented {
    holder: Option<String>,
    keys: Vec<VpReplayKey>,
}

impl Presented {
    pub fn new(
        holder: &str,
        keys: Vec<VpReplayKey>,
    ) -> Self {
        Self {
            holder: Some(holder.to_string()),
            keys,
        }
    }

    pub fn add(
        &mut self,
        other: &Self,
    ) {
        if self.holder.is_none() {
            self.holder
                .clone_from(&other.holder);
        }
        self.keys
            .extend_from_slice(&other.keys);
    }
}

/// Why a presentation refuses the request that carries it, rather than
/// leaving the request without an identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PresentationRefusal {
    #[error(transparent)]
    Receiver(#[from] crate::identity::VpDomainRefusal),
    #[error("the presentation was already used at this gateway")]
    Replay,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("the presentation proof has no proofValue or jws to key it by")]
pub struct NoReplayKey;

/// The replay key of a verified presentation's `proof`: SHA-256 of its
/// `proofValue`, or of its `jws` when it has no `proofValue`.
pub fn replay_key(proof: &Value) -> Result<VpReplayKey, NoReplayKey> {
    let signature = match proof.get("proofValue") {
        Some(proof_value) => proof_value.as_str(),
        None => proof
            .get("jws")
            .and_then(Value::as_str),
    }
    .filter(|signature| !signature.is_empty())
    .ok_or(NoReplayKey)?;
    Ok(VpReplayKey {
        digest: Sha256::digest(signature.as_bytes()).into(),
    })
}

/// The proofs one claim recorded. [`VpReplay::release`] takes it to forget
/// them; dropping it keeps them recorded.
#[derive(Debug)]
pub struct VpAdmission {
    keys: Vec<[u8; 32]>,
}

/// Why a claim of a request's presentation proofs was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VpRefusal {
    /// A proof is already recorded and has not expired.
    Duplicate,
    /// The single-use store could not record (503).
    Unavailable,
    /// This node holds as many records as the total limit allows (503).
    TotalLimit,
    /// The holder is over its own limit (429).
    HolderLimit,
}

impl VpRefusal {
    pub fn refusal_reason(self) -> VpRefusalReason {
        match self {
            Self::Duplicate => VpRefusalReason::Replay,
            Self::Unavailable => VpRefusalReason::StoreUnavailable,
            Self::TotalLimit => VpRefusalReason::LimitTotal,
            Self::HolderLimit => VpRefusalReason::LimitHolder,
        }
    }
}

/// Why an agent presentation was refused, as counted by
/// `vp_presentation_refused_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VpRefusalReason {
    Replay,
    DomainMissing,
    DomainWrong,
    DomainLabel,
    Lifetime,
    StoreUnavailable,
    LimitTotal,
    LimitHolder,
}

impl VpRefusalReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Replay => "replay",
            Self::DomainMissing => "domain_missing",
            Self::DomainWrong => "domain_wrong",
            Self::DomainLabel => "domain_label",
            Self::Lifetime => "lifetime",
            Self::StoreUnavailable => "store_unavailable",
            Self::LimitTotal => "limit_total",
            Self::LimitHolder => "limit_holder",
        }
    }
}

impl From<crate::identity::VpDomainRefusal> for VpRefusalReason {
    fn from(refusal: crate::identity::VpDomainRefusal) -> Self {
        use crate::identity::VpDomainRefusal;
        match refusal {
            VpDomainRefusal::Missing => Self::DomainMissing,
            VpDomainRefusal::Label => Self::DomainLabel,
            VpDomainRefusal::Unparseable | VpDomainRefusal::Wrong => Self::DomainWrong,
        }
    }
}

impl VpRefusalReason {
    /// The reason a verification failed with `error`, when it failed for the
    /// presentation's receiver or lifetime.
    pub fn of(error: &anyhow::Error) -> Option<Self> {
        if let Some(refusal) = error.downcast_ref::<crate::identity::VpDomainRefusal>() {
            return Some((*refusal).into());
        }
        error
            .is::<super::verifier::VpLifetimeRefusal>()
            .then_some(Self::Lifetime)
    }
}

/// Counts an agent presentation refused on `flow` for `reason`.
pub fn track_refusal(
    flow: &'static str,
    reason: VpRefusalReason,
) {
    crate::metrics::backends::prometheus::track_vp_presentation_refused(flow, reason.as_str());
}

/// Counts a verification on `flow` that failed with `error`, when it failed
/// for the presentation's receiver or lifetime.
pub fn track_verify_refusal(
    flow: &'static str,
    error: &anyhow::Error,
) {
    if let Some(reason) = VpRefusalReason::of(error) {
        track_refusal(flow, reason);
    }
}

/// A request admitted with the proofs of the presentations it carries. A
/// request that carries none holds an empty admission, which releases
/// nothing. Clones share the admission, which is released at most once.
#[derive(Clone, Debug)]
pub struct Admitted(Arc<Mutex<Option<VpAdmission>>>);

impl Admitted {
    /// Forgets the proofs this admission recorded, so the caller can present
    /// them again.
    pub fn release(&self) {
        let admission = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let (Some(admission), Some(replay)) = (admission, global()) {
            replay.release(admission);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none()
    }
}

/// Claims the proofs of `presented` once for the request, counting a refusal
/// on `flow`. A request that presented nothing is admitted without a claim.
pub async fn admit(
    flow: &'static str,
    presented: &Presented,
) -> Result<Admitted, VpRefusal> {
    let Some(holder) = presented
        .holder
        .as_deref()
        .filter(|_| !presented.keys.is_empty())
    else {
        return Ok(Admitted(Arc::new(Mutex::new(None))));
    };
    let Some(replay) = global() else {
        tracing::error!("Refusing an agent presentation: the replay record is not open");
        track_refusal(flow, VpRefusalReason::StoreUnavailable);
        return Err(VpRefusal::Unavailable);
    };
    let admission = replay
        .claim(flow, &presented.keys, holder)
        .await?;
    Ok(Admitted(Arc::new(Mutex::new(Some(admission)))))
}

static REPLAY: OnceLock<VpReplay> = OnceLock::new();

/// Opens this process's replay record. It is opened once; later calls keep it.
pub fn install() {
    REPLAY.get_or_init(|| VpReplay::new(VpReplayLimits::default()));
}

#[cfg(test)]
pub(crate) fn install_for_tests() {
    install();
}

fn global() -> Option<&'static VpReplay> {
    REPLAY.get()
}

/// How many proof records this node holds at once, and how many one holder
/// may claim within [`HOLDER_WINDOW_SECS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VpReplayLimits {
    pub total: usize,
    pub per_holder: usize,
}

impl Default for VpReplayLimits {
    fn default() -> Self {
        Self {
            total: 250_000,
            per_holder: 25_000,
        }
    }
}

pub struct VpReplay {
    limits: VpReplayLimits,
    budget: Mutex<Budget>,
}

/// A claim's reserved keys, of which the first `recorded` are in the store.
/// Dropped before the claim completes, as when its future is cancelled, it
/// forgets those records and unreserves the keys.
struct PendingClaim<'a> {
    replay: &'a VpReplay,
    keys: Vec<[u8; 32]>,
    recorded: usize,
}

impl Drop for PendingClaim<'_> {
    fn drop(&mut self) {
        if !self.keys.is_empty() {
            self.replay
                .forget(&self.keys[..self.recorded], &self.keys);
        }
    }
}

impl VpReplay {
    pub fn new(limits: VpReplayLimits) -> Self {
        Self {
            limits,
            budget: Mutex::new(Budget::default()),
        }
    }

    /// Records each of `keys` once for `holder`, counting a refusal on `flow`.
    /// Admitted only when every key is a first use; otherwise nothing stays
    /// recorded.
    pub async fn claim(
        &self,
        flow: &'static str,
        keys: &[VpReplayKey],
        holder: &str,
    ) -> Result<VpAdmission, VpRefusal> {
        self.claim_at(flow, keys, holder, unix_now())
            .await
    }

    pub(crate) async fn claim_at(
        &self,
        flow: &'static str,
        keys: &[VpReplayKey],
        holder: &str,
        now: u64,
    ) -> Result<VpAdmission, VpRefusal> {
        let outcome = self
            .claim_keys(keys, holder, now)
            .await;
        if let Err(refusal) = outcome {
            track_refusal(flow, refusal.refusal_reason());
        }
        outcome
    }

    async fn claim_keys(
        &self,
        keys: &[VpReplayKey],
        holder: &str,
        now: u64,
    ) -> Result<VpAdmission, VpRefusal> {
        let keys = deduplicate(keys);
        if keys.is_empty() {
            tracing::error!("Refusing an agent presentation with no proof to record");
            return Err(VpRefusal::Unavailable);
        }
        let Some(expires_at) = now.checked_add(RECORD_SECS) else {
            tracing::error!("Refusing an agent presentation: its record expiry is out of range");
            return Err(VpRefusal::Unavailable);
        };
        let store = match single_use::global() {
            Ok(store) => store,
            Err(error) => {
                tracing::error!(%error, "Refusing an agent presentation: the single-use store is not open");
                return Err(VpRefusal::Unavailable);
            }
        };
        let holder: [u8; 32] = Sha256::digest(holder.as_bytes()).into();
        self.reserve(&keys, &holder, now, expires_at)?;
        let mut pending = PendingClaim {
            replay: self,
            keys,
            recorded: 0,
        };
        while pending.recorded < pending.keys.len() {
            let digest = pending.keys[pending.recorded];
            match store
                .record_unique(Namespace::VpProof, &digest, expires_at, now)
                .await
            {
                Ok(true) => pending.recorded += 1,
                Ok(false) => return Err(VpRefusal::Duplicate),
                Err(error) => {
                    tracing::error!(%error, "Refusing an agent presentation the single-use store could not record");
                    return Err(VpRefusal::Unavailable);
                }
            }
        }
        Ok(VpAdmission {
            keys: std::mem::take(&mut pending.keys),
        })
    }

    /// Forgets the proofs `admission` recorded, so their next use is a first
    /// use.
    pub fn release(
        &self,
        admission: VpAdmission,
    ) {
        self.forget(&admission.keys, &admission.keys);
    }

    /// Forgets `recorded` in the store, then unreserves `reserved`.
    fn forget(
        &self,
        recorded: &[[u8; 32]],
        reserved: &[[u8; 32]],
    ) {
        if let Ok(store) = single_use::global() {
            for digest in recorded {
                store.forget_in_background(Namespace::VpProof, digest);
            }
        }
        self.unreserve(reserved);
    }

    /// Counts `keys` against the limits for `holder`, or refuses them all.
    fn reserve(
        &self,
        keys: &[[u8; 32]],
        holder: &[u8; 32],
        now: u64,
        expires_at: u64,
    ) -> Result<(), VpRefusal> {
        let mut budget = self.lock();
        budget.prune(now, PRUNE_PER_CLAIM.saturating_add(keys.len()));
        let mut refused = budget.refusal(keys, holder, self.limits);
        if matches!(refused, Some(VpRefusal::TotalLimit | VpRefusal::HolderLimit)) {
            budget.prune(now, usize::MAX);
            refused = budget.refusal(keys, holder, self.limits);
        }
        if refused.is_none() {
            for digest in keys {
                budget.insert(digest, expires_at, holder, now);
            }
        }
        budget.publish();
        refused.map_or(Ok(()), Err)
    }

    fn unreserve(
        &self,
        keys: &[[u8; 32]],
    ) {
        let mut budget = self.lock();
        for digest in keys {
            budget.forget(digest);
        }
        budget.publish();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Budget> {
        self.budget
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// Each proof digest once.
fn deduplicate(keys: &[VpReplayKey]) -> Vec<[u8; 32]> {
    let mut digests: Vec<[u8; 32]> = keys
        .iter()
        .map(|key| key.digest)
        .collect();
    digests.sort_unstable();
    digests.dedup();
    digests
}

/// This node's count of live proof records, and of each holder's claims
/// within [`HOLDER_WINDOW_SECS`]. Holders are counted by the SHA-256 of their
/// identifier.
#[derive(Default)]
struct Budget {
    expiries: HashMap<[u8; 32], u64>,
    by_expiry: BTreeSet<(u64, [u8; 32])>,
    windows: HashMap<[u8; 32], ([u8; 32], u64)>,
    by_window_end: BTreeSet<(u64, [u8; 32])>,
    per_holder: HashMap<[u8; 32], usize>,
}

impl Budget {
    /// Why claiming `keys` for `holder` is refused, if it is.
    fn refusal(
        &self,
        keys: &[[u8; 32]],
        holder: &[u8; 32],
        limits: VpReplayLimits,
    ) -> Option<VpRefusal> {
        if keys.iter().any(|digest| {
            self.expiries
                .contains_key(digest)
        }) {
            Some(VpRefusal::Duplicate)
        } else if self.expiries.len() + keys.len() > limits.total {
            Some(VpRefusal::TotalLimit)
        } else if self.claims_of(holder) + keys.len() > limits.per_holder {
            Some(VpRefusal::HolderLimit)
        } else {
            None
        }
    }

    fn claims_of(
        &self,
        holder: &[u8; 32],
    ) -> usize {
        self.per_holder
            .get(holder)
            .copied()
            .unwrap_or(0)
    }

    fn insert(
        &mut self,
        digest: &[u8; 32],
        expires_at: u64,
        holder: &[u8; 32],
        now: u64,
    ) {
        self.forget(digest);
        let window_ends = now.saturating_add(HOLDER_WINDOW_SECS);
        self.expiries
            .insert(*digest, expires_at);
        self.by_expiry
            .insert((expires_at, *digest));
        self.windows
            .insert(*digest, (*holder, window_ends));
        self.by_window_end
            .insert((window_ends, *digest));
        *self
            .per_holder
            .entry(*holder)
            .or_default() += 1;
    }

    /// Drops up to `limit` records expired at `now` and up to `limit` claims
    /// whose window ended. Any left over are dropped by later claims.
    fn prune(
        &mut self,
        now: u64,
        limit: usize,
    ) {
        for _ in 0..limit {
            match self.by_expiry.first() {
                Some(&(expires_at, digest)) if expires_at <= now => self.forget_record(&digest),
                _ => break,
            }
        }
        for _ in 0..limit {
            match self.by_window_end.first() {
                Some(&(window_ends, digest)) if window_ends <= now => self.forget_window(&digest),
                _ => break,
            }
        }
    }

    fn forget(
        &mut self,
        digest: &[u8; 32],
    ) {
        self.forget_record(digest);
        self.forget_window(digest);
    }

    fn forget_record(
        &mut self,
        digest: &[u8; 32],
    ) {
        if let Some(expires_at) = self.expiries.remove(digest) {
            self.by_expiry
                .remove(&(expires_at, *digest));
        }
    }

    fn forget_window(
        &mut self,
        digest: &[u8; 32],
    ) {
        let Some((holder, window_ends)) = self.windows.remove(digest) else {
            return;
        };
        self.by_window_end
            .remove(&(window_ends, *digest));
        if let Some(count) = self
            .per_holder
            .get_mut(&holder)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_holder
                    .remove(&holder);
            }
        }
    }

    fn publish(&self) {
        crate::metrics::backends::prometheus::set_vp_proof_records(
            i64::try_from(self.expiries.len()).unwrap_or(i64::MAX),
        );
    }
}

fn unix_now() -> u64 {
    u64::try_from(Utc::now().timestamp()).unwrap_or(0)
}
