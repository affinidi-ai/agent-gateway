import type { TrustRecorderState, TrustRecorderStatus } from '../../../types';
import {
  RECORDER_FILTER_OPTIONS,
  isRecorderFilter,
  matchesRecorderFilter,
} from '../recorderFilter';

const withState = (state: TrustRecorderState): { trust_recorder: TrustRecorderStatus } => ({
  trust_recorder: { state, reason: null, last_attempt_at: null, entries: [] },
});

describe('recorderFilter', () => {
  it('offers the options in the documented order', () => {
    expect(RECORDER_FILTER_OPTIONS.map(option => option.label)).toEqual([
      'All',
      'Recorded',
      'Partly recorded',
      'Failed',
      'Skipped',
      'Not attempted yet',
      'No recorder',
    ]);
  });

  it('matches everything for All, with or without a recorder', () => {
    expect(matchesRecorderFilter(withState('failed'), 'all')).toBe(true);
    expect(matchesRecorderFilter({}, 'all')).toBe(true);
  });

  it.each<TrustRecorderState>(['recorded', 'partial', 'failed', 'skipped', 'not_attempted'])(
    'matches only %s identities for the %s option',
    state => {
      const others = (
        ['recorded', 'partial', 'failed', 'skipped', 'not_attempted'] as const
      ).filter(other => other !== state);
      expect(matchesRecorderFilter(withState(state), state)).toBe(true);
      others.forEach(other => {
        expect(matchesRecorderFilter(withState(other), state)).toBe(false);
      });
      expect(matchesRecorderFilter({}, state)).toBe(false);
    }
  );

  it('matches only identities without the field for No recorder', () => {
    expect(matchesRecorderFilter({}, 'none')).toBe(true);
    expect(matchesRecorderFilter({ trust_recorder: undefined }, 'none')).toBe(true);
    expect(matchesRecorderFilter(withState('recorded'), 'none')).toBe(false);
    expect(matchesRecorderFilter(withState('not_attempted'), 'none')).toBe(false);
  });

  it('recognises only offered filter values', () => {
    expect(isRecorderFilter('none')).toBe(true);
    expect(isRecorderFilter('partial')).toBe(true);
    expect(isRecorderFilter('bogus')).toBe(false);
  });
});
