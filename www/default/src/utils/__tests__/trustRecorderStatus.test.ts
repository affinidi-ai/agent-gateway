import type { TrustRecorderReason, TrustRecorderState } from '../../types';
import {
  TRUST_RECORDER_STATES,
  formatTrustRecorderAttemptTime,
  formatTrustRecorderCounts,
  sumTrustRecorderCounts,
  trustRecorderAttemptTime,
  trustRecorderReasonText,
  trustRecorderStateLabel,
  trustRecorderStateTone,
} from '../trustRecorderStatus';

describe('trustRecorderStatus', () => {
  it.each<[TrustRecorderState, string]>([
    ['recorded', 'Recorded'],
    ['partial', 'Partly recorded'],
    ['failed', 'Failed'],
    ['skipped', 'Skipped'],
    ['not_attempted', 'Not attempted yet'],
  ])('labels %s as %s', (state, label) => {
    expect(trustRecorderStateLabel(state)).toBe(label);
  });

  it('covers every state with a distinct label', () => {
    const labels = TRUST_RECORDER_STATES.map(trustRecorderStateLabel);
    expect(TRUST_RECORDER_STATES).toHaveLength(5);
    expect(new Set(labels).size).toBe(5);
  });

  it.each<[TrustRecorderState, string]>([
    ['recorded', 'success'],
    ['partial', 'warning'],
    ['failed', 'danger'],
    ['skipped', 'secondary'],
    ['not_attempted', 'light'],
  ])('uses the %s tone for %s', (state, tone) => {
    expect(trustRecorderStateTone(state)).toBe(tone);
  });

  it('falls back to the raw value for a state the dashboard does not know', () => {
    expect(trustRecorderStateLabel('brand_new' as TrustRecorderState)).toBe('brand_new');
    expect(trustRecorderStateTone('brand_new' as TrustRecorderState)).toBe('secondary');
  });

  it.each<[TrustRecorderReason, string]>([
    ['registry_not_found', 'Trust registry not found'],
    ['registry_not_connected', 'Trust registry not connected'],
    ['no_surface_issuer', 'Surface has no Issuer'],
    ['no_response', 'No response from the registry'],
    ['rejected', 'Registry rejected the record'],
    ['error', 'Registry error'],
  ])('describes reason %s', (reason, text) => {
    expect(trustRecorderReasonText(reason)).toBe(text);
  });

  it('has no reason text when there is no reason', () => {
    expect(trustRecorderReasonText(null)).toBeNull();
  });

  it('formats and sums counts', () => {
    expect(formatTrustRecorderCounts({ created: 2, already_existed: 1, failed: 0 })).toBe(
      'created 2, already existed 1, failed 0'
    );
    const entry = (created: number, already_existed: number, failed: number) => ({
      trust_registry_id: 'r',
      state: 'recorded' as const,
      reason: null,
      created,
      already_existed,
      failed,
    });
    expect(sumTrustRecorderCounts([entry(1, 2, 3), entry(4, 5, 6)])).toEqual({
      created: 5,
      already_existed: 7,
      failed: 9,
    });
    expect(sumTrustRecorderCounts([])).toEqual({ created: 0, already_existed: 0, failed: 0 });
  });

  describe('attempt time', () => {
    it('has no attempt time when never attempted or unparseable', () => {
      expect(trustRecorderAttemptTime({ last_attempt_at: null })).toBeNull();
      expect(trustRecorderAttemptTime({ last_attempt_at: 'not a date' })).toBeNull();
    });

    it('gives a relative and an absolute time', () => {
      const at = new Date(Date.now() - 5 * 60 * 1000).toISOString();
      const time = trustRecorderAttemptTime({ last_attempt_at: at });
      expect(time?.relative).toBe('5 minutes ago');
      expect(time?.absolute).toEqual(expect.stringContaining(String(new Date(at).getFullYear())));
    });

    it('joins relative and absolute, collapsing them when identical', () => {
      expect(formatTrustRecorderAttemptTime({ relative: '5 minutes ago', absolute: 'May 1' })).toBe(
        '5 minutes ago (May 1)'
      );
      expect(formatTrustRecorderAttemptTime({ relative: 'May 1', absolute: 'May 1' })).toBe(
        'May 1'
      );
    });
  });
});
