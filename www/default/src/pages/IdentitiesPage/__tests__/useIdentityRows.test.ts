import { renderHook } from '@testing-library/react';
import type { Identity, TrustRecorderState } from '../../../types';
import { useIdentityRows } from '../useIdentityRows';
import type { RecorderFilter } from '../recorderFilter';

const identity = (did: string, state?: TrustRecorderState, name = did): Identity => ({
  name,
  did,
  identity_hash: `hash-${did}`,
  created_at: '2026-01-01T00:00:00Z',
  ...(state ? { trust_recorder: { state, reason: null, last_attempt_at: null, entries: [] } } : {}),
});

const rows = (
  identities: Identity[],
  options: { searchTerm?: string; recorderFilter?: RecorderFilter } = {}
) =>
  renderHook(() =>
    useIdentityRows({
      identities,
      searchTerm: options.searchTerm ?? '',
      recorderFilter: options.recorderFilter,
    })
  ).result.current;

const dids = (view: ReturnType<typeof rows>) => view.filteredIdentities.map(i => i.did);

describe('useIdentityRows recorder status', () => {
  const all = [
    identity('did:a', 'recorded', 'alpha'),
    identity('did:b', 'failed', 'beta'),
    identity('did:c', 'not_attempted', 'gamma'),
    identity('did:d', undefined, 'delta'),
  ];

  it('reports whether any identity carries a recorder status', () => {
    expect(rows(all).hasRecorderStatus).toBe(true);
    expect(rows([identity('did:d')]).hasRecorderStatus).toBe(false);
  });

  it('keeps every identity with the default filter', () => {
    expect(dids(rows(all))).toEqual(['did:a', 'did:b', 'did:c', 'did:d']);
  });

  it('narrows to one state', () => {
    expect(dids(rows(all, { recorderFilter: 'failed' }))).toEqual(['did:b']);
  });

  it('narrows to identities without a recorder', () => {
    expect(dids(rows(all, { recorderFilter: 'none' }))).toEqual(['did:d']);
  });

  it('combines with the search term', () => {
    expect(dids(rows(all, { recorderFilter: 'recorded', searchTerm: 'alpha' }))).toEqual(['did:a']);
    expect(dids(rows(all, { recorderFilter: 'recorded', searchTerm: 'beta' }))).toEqual([]);
    expect(dids(rows(all, { recorderFilter: 'none', searchTerm: 'delta' }))).toEqual(['did:d']);
  });

  it('ignores the filter when no identity has a recorder', () => {
    const plain = [identity('did:x'), identity('did:y')];
    expect(dids(rows(plain, { recorderFilter: 'recorded' }))).toEqual(['did:x', 'did:y']);
  });
});

describe('useIdentityRows managed surfaces', () => {
  const shared: Identity = {
    ...identity('did:shared'),
    origin: 'managed',
    channel_config_id: 's-delta',
    channel_name: 'delta',
    managed_surfaces: [
      { surface_id: 's-alpha', surface_name: 'alpha' },
      { surface_id: 's-bravo', surface_name: 'bravo' },
    ],
  };
  const single: Identity = {
    ...identity('did:single'),
    origin: 'managed',
    surface_id: 's-charlie',
    surface_name: 'charlie',
    managed_surfaces: [{ surface_id: 's-charlie', surface_name: 'charlie' }],
  };

  it('links every managed surface of a shared managed DID, not its last-used surface', () => {
    expect(rows([shared]).surfaceLinksFor(shared)).toEqual([
      { id: 's-alpha', name: 'alpha' },
      { id: 's-bravo', name: 'bravo' },
    ]);
  });

  it('links the one surface of a single-surface DID', () => {
    expect(rows([single]).surfaceLinksFor(single)).toEqual([{ id: 's-charlie', name: 'charlie' }]);
  });

  it('links no surface for a managed DID without a live managed surface', () => {
    const orphan: Identity = {
      ...identity('did:orphan'),
      origin: 'managed',
      channel_config_id: 's-delta',
      channel_name: 'delta',
    };
    expect(rows([orphan]).surfaceLinksFor(orphan)).toEqual([]);
    expect(rows([orphan]).surfaceLinkFor(orphan)).toBeNull();
  });

  it('keeps the last-used surface link for a row that is not managed', () => {
    const legacy: Identity = {
      ...identity('did:legacy'),
      channel_config_id: 's-delta',
      channel_name: 'delta',
    };
    expect(rows([legacy]).surfaceLinksFor(legacy)).toEqual([{ id: 's-delta', name: 'delta' }]);
  });

  it('finds a shared managed DID by any of its surface names', () => {
    expect(dids(rows([shared, single], { searchTerm: 'bravo' }))).toEqual(['did:shared']);
  });

  it('has no unnamed-only filter or count', () => {
    const view = rows([shared, identity('did:anon')]);
    expect(view).not.toHaveProperty('unnamedCount');
    expect(dids(view)).toEqual(['did:shared', 'did:anon']);
  });
});
