import type { Identity, TrustRecorderState } from '../../types';
import { trustRecorderStateLabel } from '../../utils/trustRecorderStatus';

export type RecorderFilter = 'all' | TrustRecorderState | 'none';

export const RECORDER_FILTER_OPTIONS: ReadonlyArray<{ value: RecorderFilter; label: string }> = [
  { value: 'all', label: 'All' },
  { value: 'recorded', label: trustRecorderStateLabel('recorded') },
  { value: 'partial', label: trustRecorderStateLabel('partial') },
  { value: 'failed', label: trustRecorderStateLabel('failed') },
  { value: 'skipped', label: trustRecorderStateLabel('skipped') },
  { value: 'not_attempted', label: trustRecorderStateLabel('not_attempted') },
  { value: 'none', label: 'No recorder' },
];

export const isRecorderFilter = (value: string): value is RecorderFilter =>
  RECORDER_FILTER_OPTIONS.some(option => option.value === value);

export const matchesRecorderFilter = (
  identity: Pick<Identity, 'trust_recorder'>,
  filter: RecorderFilter
): boolean => {
  if (filter === 'all') return true;
  if (filter === 'none') return !identity.trust_recorder;
  return identity.trust_recorder?.state === filter;
};
