import type {
  TrustRecorderEntryOutcome,
  TrustRecorderReason,
  TrustRecorderState,
  TrustRecorderStatus,
} from '../types';
import { formatDateTime, timeAgo } from './stringUtils';

export type TrustRecorderTone = 'success' | 'warning' | 'danger' | 'secondary' | 'light';

const STATE_LABELS: Record<TrustRecorderState, string> = {
  recorded: 'Recorded',
  partial: 'Partly recorded',
  failed: 'Failed',
  skipped: 'Skipped',
  not_attempted: 'Not attempted yet',
};

const STATE_TONES: Record<TrustRecorderState, TrustRecorderTone> = {
  recorded: 'success',
  partial: 'warning',
  failed: 'danger',
  skipped: 'secondary',
  not_attempted: 'light',
};

const REASON_TEXT: Record<TrustRecorderReason, string> = {
  registry_not_found: 'Trust registry not found',
  registry_not_connected: 'Trust registry not connected',
  no_surface_issuer: 'Surface has no Issuer',
  no_response: 'No response from the registry',
  rejected: 'Registry rejected the record',
  error: 'Registry error',
};

export const TRUST_RECORDER_STATES = Object.keys(STATE_LABELS) as TrustRecorderState[];

export const trustRecorderStateLabel = (state: TrustRecorderState): string =>
  STATE_LABELS[state] ?? state;

export const trustRecorderStateTone = (state: TrustRecorderState): TrustRecorderTone =>
  STATE_TONES[state] ?? 'secondary';

export const trustRecorderReasonText = (reason: TrustRecorderReason | null): string | null =>
  reason ? (REASON_TEXT[reason] ?? reason) : null;

export interface TrustRecorderCounts {
  created: number;
  already_existed: number;
  failed: number;
}

export const formatTrustRecorderCounts = (counts: TrustRecorderCounts): string =>
  `created ${counts.created}, already existed ${counts.already_existed}, failed ${counts.failed}`;

export const sumTrustRecorderCounts = (
  entries: ReadonlyArray<TrustRecorderEntryOutcome>
): TrustRecorderCounts =>
  entries.reduce<TrustRecorderCounts>(
    (total, entry) => ({
      created: total.created + entry.created,
      already_existed: total.already_existed + entry.already_existed,
      failed: total.failed + entry.failed,
    }),
    { created: 0, already_existed: 0, failed: 0 }
  );

export interface TrustRecorderAttemptTime {
  relative: string;
  absolute: string;
}

export const trustRecorderAttemptTime = (
  status: Pick<TrustRecorderStatus, 'last_attempt_at'>
): TrustRecorderAttemptTime | null => {
  const at = status.last_attempt_at;
  if (!at || Number.isNaN(new Date(at).getTime())) return null;
  return { relative: timeAgo(at), absolute: formatDateTime(at, true) };
};

export const formatTrustRecorderAttemptTime = (time: TrustRecorderAttemptTime): string =>
  time.relative === time.absolute ? time.absolute : `${time.relative} (${time.absolute})`;
