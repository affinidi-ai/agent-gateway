//! Per-peer and per-tenant shares of the tables every Fabric peer uses: the
//! capability offers and probes and the `Open` replay records.
//!
//! Until a table is half full any peer may add to it, so a single busy peer is
//! not capped while the table has room. From then on one peer may hold an
//! eighth of it, and the peers of one tenant half of it together, so neither a
//! single peer nor one tenant's peers can fill a table and get every other peer
//! refused. The tenant share applies only while other tenants' peers, or peers
//! whose Remote gateway record has no tenant, hold entries too. A peer whose
//! record has no tenant counts only against its own share and the capacity.

use std::collections::HashMap;
use std::hash::Hash;

const PEER_SHARE_DIVISOR: usize = 8;
const TENANT_SHARE_DIVISOR: usize = 2;
/// The shares apply once a table holds this fraction of its capacity.
const SHARED_FROM_DIVISOR: usize = 2;

/// The peer an entry is held for, and the tenant that owns the peer's Remote
/// gateway record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShareOwner {
    pub peer_did: String,
    pub tenant_id: Option<String>,
}

/// The limit that refused an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShareLimit {
    Total,
    Peer,
    Tenant,
}

impl ShareLimit {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Total => "total",
            Self::Peer => "per_peer",
            Self::Tenant => "per_tenant",
        }
    }
}

/// A map whose entries are counted per peer and per tenant. Every change goes
/// through its methods, which keep the counts in step with the entries.
pub(crate) struct SharedTable<K, V> {
    capacity: usize,
    entries: HashMap<K, (ShareOwner, V)>,
    per_peer: HashMap<String, usize>,
    per_tenant: HashMap<String, usize>,
}

impl<K: Eq + Hash, V> SharedTable<K, V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::new(),
            per_peer: HashMap::new(),
            per_tenant: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn get(
        &self,
        key: &K,
    ) -> Option<&V> {
        self.entries
            .get(key)
            .map(|(_, value)| value)
    }

    pub fn get_mut(
        &mut self,
        key: &K,
    ) -> Option<&mut V> {
        self.entries
            .get_mut(key)
            .map(|(_, value)| value)
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut V)> {
        self.entries
            .iter_mut()
            .map(|(key, (_, value))| (key, value))
    }

    pub fn contains_key(
        &self,
        key: &K,
    ) -> bool {
        self.entries.contains_key(key)
    }

    /// Whether one more entry for `owner` fits the capacity and, once the
    /// table is half full, its shares.
    pub fn admits(
        &self,
        owner: &ShareOwner,
    ) -> Result<(), ShareLimit> {
        let held = self.entries.len();
        if held >= self.capacity {
            return Err(ShareLimit::Total);
        }
        if held < share(self.capacity, SHARED_FROM_DIVISOR) {
            return Ok(());
        }
        if count(&self.per_peer, &owner.peer_did) >= share(self.capacity, PEER_SHARE_DIVISOR) {
            return Err(ShareLimit::Peer);
        }
        if let Some(tenant_id) = &owner.tenant_id {
            let tenant_held = count(&self.per_tenant, tenant_id);
            if tenant_held < held && tenant_held >= share(self.capacity, TENANT_SHARE_DIVISOR) {
                return Err(ShareLimit::Tenant);
            }
        }
        Ok(())
    }

    /// Adds an entry when the capacity and the owner's shares admit it. An
    /// entry already under `key` is removed first.
    pub fn insert(
        &mut self,
        key: K,
        owner: ShareOwner,
        value: V,
    ) -> Result<(), ShareLimit> {
        self.remove(&key);
        self.admits(&owner)?;
        *self
            .per_peer
            .entry(owner.peer_did.clone())
            .or_default() += 1;
        if let Some(tenant_id) = &owner.tenant_id {
            *self
                .per_tenant
                .entry(tenant_id.clone())
                .or_default() += 1;
        }
        self.entries
            .insert(key, (owner, value));
        Ok(())
    }

    pub fn remove(
        &mut self,
        key: &K,
    ) -> Option<V> {
        let (owner, value) = self.entries.remove(key)?;
        release(&mut self.per_peer, &mut self.per_tenant, &owner);
        Some(value)
    }

    pub fn retain(
        &mut self,
        mut keep: impl FnMut(&K, &V) -> bool,
    ) {
        let (per_peer, per_tenant) = (&mut self.per_peer, &mut self.per_tenant);
        self.entries
            .retain(|key, (owner, value)| {
                let kept = keep(key, value);
                if !kept {
                    release(per_peer, per_tenant, owner);
                }
                kept
            });
    }
}

fn share(
    capacity: usize,
    divisor: usize,
) -> usize {
    (capacity / divisor).max(1)
}

fn count(
    counts: &HashMap<String, usize>,
    key: &str,
) -> usize {
    counts
        .get(key)
        .copied()
        .unwrap_or_default()
}

fn release(
    per_peer: &mut HashMap<String, usize>,
    per_tenant: &mut HashMap<String, usize>,
    owner: &ShareOwner,
) {
    decrement(per_peer, &owner.peer_did);
    if let Some(tenant_id) = &owner.tenant_id {
        decrement(per_tenant, tenant_id);
    }
}

fn decrement(
    counts: &mut HashMap<String, usize>,
    key: &str,
) {
    if let Some(held) = counts.get_mut(key) {
        *held = held.saturating_sub(1);
        if *held == 0 {
            counts.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(
        peer: &str,
        tenant: Option<&str>,
    ) -> ShareOwner {
        ShareOwner {
            peer_did: format!("did:example:{peer}"),
            tenant_id: tenant.map(str::to_string),
        }
    }

    #[test]
    fn one_peer_may_fill_half_the_table_and_then_only_other_peers_add() {
        let mut table = SharedTable::new(16);
        for key in 0..8 {
            assert_eq!(table.insert(key, owner("alpha", None), ()), Ok(()), "entry {key} of a half-empty table");
        }
        assert_eq!(table.insert(8, owner("alpha", None), ()), Err(ShareLimit::Peer));
        for (key, peer) in [(8, "bravo"), (9, "bravo")] {
            assert_eq!(table.insert(key, owner(peer, None), ()), Ok(()));
        }
        assert_eq!(table.insert(10, owner("bravo", None), ()), Err(ShareLimit::Peer), "a peer's eighth applies now");
        assert_eq!(table.insert(10, owner("charlie", None), ()), Ok(()));
        assert_eq!(table.len(), 11);
    }

    #[test]
    fn a_tenant_share_applies_only_while_others_hold_entries() {
        let mut table = SharedTable::new(16);
        let mut key = 0;
        for peer in ["a1", "a2", "a3", "a4", "a5"] {
            for _ in 0..2 {
                assert_eq!(
                    table.insert(key, owner(peer, Some("tenant-a")), ()),
                    Ok(()),
                    "one tenant's peers alone are held only by their own shares"
                );
                key += 1;
            }
        }
        assert_eq!(table.insert(key, owner("b1", Some("tenant-b")), ()), Ok(()));
        key += 1;
        assert_eq!(table.insert(key, owner("a6", Some("tenant-a")), ()), Err(ShareLimit::Tenant));
        assert_eq!(table.insert(key, owner("b2", Some("tenant-b")), ()), Ok(()));
        assert_eq!(table.insert(key + 1, owner("appliance", None), ()), Ok(()));
        assert_eq!(table.insert(key + 2, owner("a6", Some("tenant-a")), ()), Err(ShareLimit::Tenant));
    }

    #[test]
    fn untenanted_peers_count_against_no_tenant_share() {
        let mut table = SharedTable::new(16);
        for (key, peer) in ["p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "p10"]
            .into_iter()
            .enumerate()
        {
            assert_eq!(table.insert(key, owner(peer, None), ()), Ok(()));
        }
        assert!(table.per_tenant.is_empty());
    }

    #[test]
    fn the_capacity_still_bounds_the_table() {
        let mut table = SharedTable::new(4);
        for (key, peer) in ["a", "b", "c", "d"]
            .into_iter()
            .enumerate()
        {
            assert_eq!(table.insert(key, owner(peer, None), ()), Ok(()));
        }
        assert_eq!(table.insert(4, owner("e", None), ()), Err(ShareLimit::Total));
    }

    #[test]
    fn removed_and_expired_entries_free_their_owners_share() {
        let mut table = SharedTable::new(4);
        table
            .insert(0, owner("alpha", Some("t")), 10)
            .unwrap();
        table
            .insert(1, owner("alpha", Some("t")), 20)
            .unwrap();
        assert_eq!(table.insert(2, owner("alpha", Some("t")), 30), Err(ShareLimit::Peer));

        assert_eq!(table.remove(&0), Some(10));
        assert_eq!(table.insert(2, owner("alpha", Some("t")), 30), Ok(()));

        table.retain(|_, value| *value > 20);
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(&2), Some(&30));
        assert_eq!(table.insert(3, owner("alpha", Some("t")), 40), Ok(()));
        assert!(
            table
                .per_tenant
                .get("t")
                .is_some_and(|held| *held == 2)
        );
    }

    #[test]
    fn replacing_an_entry_does_not_count_it_twice() {
        let mut table = SharedTable::new(16);
        for value in 0..5 {
            assert_eq!(table.insert(7, owner("alpha", None), value), Ok(()));
        }
        assert_eq!(table.len(), 1);
        assert_eq!(
            table
                .per_peer
                .get("did:example:alpha"),
            Some(&1)
        );
    }
}
