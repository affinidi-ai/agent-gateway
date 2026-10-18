import { appReducer, initialState } from '../AppContext';
import type { TrustRecorderStatus } from '../../types';

const recorder = (overrides: Partial<TrustRecorderStatus> = {}): TrustRecorderStatus => ({
  state: 'not_attempted',
  reason: null,
  last_attempt_at: null,
  entries: [],
  ...overrides,
});

const identity = (did: string, trust_recorder?: TrustRecorderStatus) => ({
  did,
  name: did,
  identity_hash: `hash-${did}`,
  created_at: '2026-01-01T00:00:00Z',
  ...(trust_recorder ? { trust_recorder } : {}),
});

const stateWith = (identities: unknown[]) =>
  appReducer(initialState, {
    type: 'SET_DASHBOARD_STATS',
    payload: {
      view: 'global',
      stats: { identities, total_identities: identities.length } as never,
    },
  });

const applyIdentities = (
  state: ReturnType<typeof stateWith>,
  changes: { added?: unknown[]; updated?: unknown[] }
) =>
  appReducer(state, {
    type: 'APPLY_DASHBOARD_DELTA',
    payload: { view: 'global', delta: { timestamp: 1, changes: { identities: changes } } },
  });

const identitiesOf = (state: ReturnType<typeof stateWith>) =>
  (state.globalState.stats?.identities ?? []) as Array<ReturnType<typeof identity>>;

describe('appReducer identity deltas carry the Trust Recorder status', () => {
  it('applies a changed state, attempt time and entries on an existing identity', () => {
    const before = stateWith([identity('did:a', recorder()), identity('did:b', recorder())]);
    const next = recorder({
      state: 'partial',
      last_attempt_at: '2026-02-01T00:00:00Z',
      entries: [
        {
          trust_registry_id: 'reg-1',
          state: 'partial',
          reason: 'rejected',
          created: 1,
          already_existed: 0,
          failed: 2,
        },
      ],
    });

    const after = applyIdentities(before, { updated: [identity('did:a', next)] });

    const [a, b] = identitiesOf(after);
    expect(a.trust_recorder).toEqual(next);
    expect(b.trust_recorder).toEqual(recorder());
  });

  it('applies a change that only moves the attempt time', () => {
    const before = stateWith([
      identity('did:a', recorder({ state: 'failed', last_attempt_at: '2026-02-01T00:00:00Z' })),
    ]);

    const after = applyIdentities(before, {
      updated: [
        identity('did:a', recorder({ state: 'failed', last_attempt_at: '2026-02-02T00:00:00Z' })),
      ],
    });

    expect(identitiesOf(after)[0].trust_recorder?.last_attempt_at).toBe('2026-02-02T00:00:00Z');
  });

  it('drops the status when an updated identity no longer carries one', () => {
    const before = stateWith([identity('did:a', recorder({ state: 'recorded' }))]);

    const after = applyIdentities(before, { updated: [identity('did:a')] });

    expect(identitiesOf(after)[0]).not.toHaveProperty('trust_recorder');
  });

  it('adds a new identity with its status', () => {
    const before = stateWith([identity('did:a')]);

    const after = applyIdentities(before, {
      added: [identity('did:new', recorder({ state: 'skipped', reason: 'no_surface_issuer' }))],
    });

    const added = identitiesOf(after).find(i => i.did === 'did:new');
    expect(added?.trust_recorder).toEqual(
      recorder({ state: 'skipped', reason: 'no_surface_issuer' })
    );
    expect(identitiesOf(after)).toHaveLength(2);
  });
});
