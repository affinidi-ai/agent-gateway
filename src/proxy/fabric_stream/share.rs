//! Per-peer and per-tenant shares of the tables every Fabric peer uses: the
//! capability offers and probes and the `Open` replay records.
//!
//! One peer may hold an eighth of a table, and the peers of one tenant half of
//! it together, so neither a single peer nor one tenant's peers can fill a
//! table and get every other peer refused. A peer whose Remote gateway record
//! has no tenant counts only against its own share and the table's capacity.

use std::collections::HashMap;
use std::hash::Hash;

const PEER_SHARE_DIVISOR: usize = 8;
const TENANT_SHARE_DIVISOR: usize = 2;

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

    pub fn contains_key(
        &self,
        key: &K,
    ) -> bool {
        self.entries.contains_key(key)
    }

    /// Whether one more entry for `owner` fits the capacity and its shares.
    pub fn admits(
        &self,
        owner: &ShareOwner,
    ) -> Result<(), ShareLimit> {
        if self.entries.len() >= self.capacity {
            return Err(ShareLimit::Total);
        }
        if count(&self.per_peer, &owner.peer_did) >= share(self.capacity, PEER_SHARE_DIVISOR) {
            return Err(ShareLimit::Peer);
        }
        if let Some(tenant_id) = &owner.tenant_id
            && count(&self.per_tenant, tenant_id) >= share(self.capacity, TENANT_SHARE_DIVISOR)
        {
            return Err(ShareLimit::Tenant);
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
    fn a_full_peer_share_refuses_only_that_peer() {
        let mut table = SharedTable::new(16);
        for key in 0..2 {
            assert_eq!(table.insert(key, owner("alpha", None), ()), Ok(()));
        }
        assert_eq!(table.insert(2, owner("alpha", None), ()), Err(ShareLimit::Peer));
        assert_eq!(table.insert(2, owner("bravo", None), ()), Ok(()));
        assert_eq!(table.len(), 3);
    }

    #[test]
    fn a_full_tenant_share_refuses_that_tenants_other_peers_but_not_other_tenants() {
        let mut table = SharedTable::new(16);
        let mut key = 0;
        for peer in ["a1", "a2", "a3", "a4"] {
            for _ in 0..2 {
                assert_eq!(table.insert(key, owner(peer, Some("tenant-a")), ()), Ok(()));
                key += 1;
            }
        }
        assert_eq!(table.insert(key, owner("a5", Some("tenant-a")), ()), Err(ShareLimit::Tenant));
        assert_eq!(table.insert(key, owner("b1", Some("tenant-b")), ()), Ok(()));
        assert_eq!(table.insert(key + 1, owner("appliance", None), ()), Ok(()));
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
        let mut table = SharedTable::new(16);
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
