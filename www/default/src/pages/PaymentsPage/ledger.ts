import type { PaymentLedgerRow, PaymentOutcome } from '../../types';

export const UNCONFIRMED_NOTE =
  'Payment taken or unconfirmed - retry the same request with the same credential within 2 minutes';

export const OUTCOME_META: Record<
  PaymentOutcome,
  {
    label: string;
    tone: 'success' | 'info' | 'warning' | 'danger' | 'secondary';
    color: string;
    note?: string;
  }
> = {
  paid: { label: 'Paid', tone: 'success', color: '--success' },
  challenge: { label: 'Challenge', tone: 'info', color: '--info' },
  held: { label: 'Held', tone: 'warning', color: '--warning' },
  rejected: { label: 'Rejected', tone: 'danger', color: '--danger' },
  unavailable: { label: 'Unavailable', tone: 'secondary', color: '--gray-500' },
  unconfirmed: {
    label: 'Unconfirmed',
    tone: 'warning',
    color: '--accent-purple',
    note: UNCONFIRMED_NOTE,
  },
  authorized: {
    label: 'Authorized',
    tone: 'info',
    color: '--info',
    note: 'Funds are held until the Target delivers, then captured; they are voided if it does not.',
  },
  voided: {
    label: 'Voided',
    tone: 'secondary',
    color: '--gray-500',
    note: 'The Target did not deliver, so the held funds were released without a charge.',
  },
  capture_failed: {
    label: 'Capture failed',
    tone: 'danger',
    color: '--danger',
    note: 'The Target delivered, but capturing the held funds failed. Reconcile it in agent-pay.',
  },
};

export function rowDate(row: Pick<PaymentLedgerRow, 'created_at'>): Date | null {
  const v = row.created_at;
  const d = typeof v === 'number' ? new Date(v * 1000) : new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function formatLedgerAmount(row: Pick<PaymentLedgerRow, 'amount' | 'currency'>): string {
  if (!row.amount) return '—';
  return row.currency ? `${row.amount} ${row.currency}` : row.amount;
}

export interface OutcomeBucket {
  start: number;
  counts: Record<PaymentOutcome, number>;
}

const emptyCounts = (): Record<PaymentOutcome, number> => ({
  paid: 0,
  challenge: 0,
  held: 0,
  rejected: 0,
  unavailable: 0,
  unconfirmed: 0,
  authorized: 0,
  voided: 0,
  capture_failed: 0,
});

export const MAX_BUCKETS = 500;

/**
 * Groups rows into consecutive `bucketSeconds` windows, oldest first, with empty
 * windows filled. When the rows span more than `MAX_BUCKETS` windows, the newest
 * ones are kept.
 */
export function bucketByOutcome(rows: PaymentLedgerRow[], bucketSeconds: number): OutcomeBucket[] {
  const size = bucketSeconds * 1000;
  const byStart = new Map<number, Record<PaymentOutcome, number>>();
  for (const row of rows) {
    const d = rowDate(row);
    if (!d || !(row.outcome in OUTCOME_META)) continue;
    const start = Math.floor(d.getTime() / size) * size;
    const counts = byStart.get(start) ?? emptyCounts();
    counts[row.outcome] += 1;
    byStart.set(start, counts);
  }
  if (byStart.size === 0) return [];
  const starts = Array.from(byStart.keys());
  const last = Math.max(...starts);
  const first = Math.max(Math.min(...starts), last - (MAX_BUCKETS - 1) * size);
  const out: OutcomeBucket[] = [];
  for (let s = first; s <= last; s += size) {
    out.push({ start: s, counts: byStart.get(s) ?? emptyCounts() });
  }
  return out;
}
