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
      showUnnamedOnly: false,
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
