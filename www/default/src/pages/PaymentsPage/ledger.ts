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
