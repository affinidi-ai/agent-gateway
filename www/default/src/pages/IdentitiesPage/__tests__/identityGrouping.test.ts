import { changedClaimKeys, groupIdentities, GroupableIdentity } from '../identityGrouping';

const managed = (overrides: Partial<GroupableIdentity> & { did: string }): GroupableIdentity => ({
  group_key: 'surface:s1',
  identity_hash: 'hash-1',
  credential_principal: { kind: 'certificate', id: 'cert-1', name: 'NITROGEN' },
  agent_identity: { team: 'billing' },
  ...overrides,
});

describe('groupIdentities', () => {
  it('groups managed identities per surface with the most recently active as primary', () => {
    const older = managed({
      did: 'did:key:old',
      created_at: '2026-01-01T00:00:00Z',
      last_used_at: '2026-01-02T00:00:00Z',
    });
    const latest = managed({
      did: 'did:key:new',
      created_at: '2026-02-01T00:00:00Z',
      last_used_at: '2026-03-01T00:00:00Z',
    });

    const groups = groupIdentities([latest, older]);

    expect(groups).toHaveLength(1);
    expect(groups[0].key).toBe('surface:s1');
    expect(groups[0].primary.did).toBe('did:key:new');
    expect(groups[0].members.map(m => m.did)).toEqual(['did:key:new', 'did:key:old']);
  });

  it('falls back to created_at when an identity has never been used', () => {
    const used = managed({ did: 'did:key:a', created_at: '2026-01-01T00:00:00Z' });
    const fresh = managed({ did: 'did:key:b', created_at: '2026-04-01T00:00:00Z' });

    expect(groupIdentities([used, fresh])[0].primary.did).toBe('did:key:b');
  });

  it('lists DID, credential and claim changes in chronological order', () => {
    const first = managed({ did: 'did:key:1', created_at: '2026-01-01T00:00:00Z' });
    const second = managed({
      did: 'did:key:2',
      created_at: '2026-02-01T00:00:00Z',
      credential_principal: { kind: 'api_key', id: 'key-9', name: 'OXYGEN' },
      identity_hash: 'hash-2',
    });
    const third = managed({
      did: 'did:key:2b',
      created_at: '2026-03-01T00:00:00Z',
      credential_principal: { kind: 'api_key', id: 'key-9', name: 'OXYGEN' },
      identity_hash: 'hash-2',
      agent_identity: { team: 'payments', region: 'eu' },
    });

    const [group] = groupIdentities([third, first, second]);

    expect(group.changes).toHaveLength(2);
    expect(group.changes[0]).toMatchObject({
      at: '2026-02-01T00:00:00Z',
      kinds: ['did', 'credential'],
      changedClaims: [],
    });
    expect(group.changes[0].previous.did).toBe('did:key:1');
    expect(group.changes[0].current.did).toBe('did:key:2');
    expect(group.changes[1]).toMatchObject({
      kinds: ['did', 'claims'],
      changedClaims: ['region', 'team'],
    });
  });

  it('records no change between identical consecutive members', () => {
    const a = managed({ did: 'did:key:same', created_at: '2026-01-01T00:00:00Z' });
    const b = managed({ did: 'did:key:same', created_at: '2026-01-02T00:00:00Z' });

    expect(groupIdentities([a, b])[0].changes).toEqual([]);
  });

  it('keeps callers one row per DID', () => {
    const groups = groupIdentities([
      { did: 'did:web:a', group_key: 'did:did:web:a' },
      { did: 'did:web:b', group_key: 'did:did:web:b' },
    ]);

    expect(groups.map(g => g.key)).toEqual(['did:did:web:a', 'did:did:web:b']);
    expect(groups.every(g => g.members.length === 1 && g.changes.length === 0)).toBe(true);
  });

  it('groups by DID when the backend sends no group_key', () => {
    const groups = groupIdentities([{ did: 'did:web:a' }, { did: 'did:web:b' }]);

    expect(groups.map(g => g.key)).toEqual(['did:did:web:a', 'did:did:web:b']);
    expect(groups.map(g => g.primary.did)).toEqual(['did:web:a', 'did:web:b']);
  });

  it('returns no groups for no identities', () => {
    expect(groupIdentities([])).toEqual([]);
  });
});

describe('changedClaimKeys', () => {
  it('ignores key order inside nested values', () => {
    expect(changedClaimKeys({ a: { x: 1, y: 2 } }, { a: { y: 2, x: 1 } })).toEqual([]);
  });

  it('reports added, removed and modified keys', () => {
    expect(changedClaimKeys({ a: 1, b: 2 }, { b: 3, c: 4 })).toEqual(['a', 'b', 'c']);
  });

  it('treats missing claim maps as empty', () => {
    expect(changedClaimKeys(undefined, { a: 1 })).toEqual(['a']);
    expect(changedClaimKeys(undefined, undefined)).toEqual([]);
  });
});
