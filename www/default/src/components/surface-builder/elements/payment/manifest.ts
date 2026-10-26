import type {
  PaymentInstrument,
  PaymentManifest,
  PaymentMoney,
  PaymentPoint,
} from '../../../../types';

export const formatMoney = (m?: PaymentMoney): string =>
  m && m.amount ? `${m.amount} ${m.unit}`.trim() : '—';

const instrumentLabel = (i: PaymentInstrument): string => {
  switch (i?.type) {
    case 'card':
      return 'card';
    case 'wallet':
      return i.kind;
    case 'networkToken':
      return `${i.network} network token`;
    case 'crypto':
      return i.network ? `crypto on ${i.network}` : 'crypto';
    default:
      return 'unknown';
  }
};

export function describePointDetail(point: PaymentPoint): string {
  const d = point.detail;
  if (d?.kind === 'onChain') return `${d.scheme} on ${d.network}`;
  if (d?.kind === 'settled') return `${d.provider} · ${instrumentLabel(d.instrument)}`;
  return '';
}

const pointKey = (p: PaymentPoint) => `${p.id}|${p.protocol}|${p.credential}`;

/** Differences in price or payment points between the saved snapshot and the live manifest. */
export function manifestDrift(snapshot: PaymentManifest, live: PaymentManifest): string[] {
  const out: string[] = [];
  if (
    snapshot.amount?.amount !== live.amount?.amount ||
    snapshot.amount?.unit !== live.amount?.unit
  ) {
    out.push(`Price changed from ${formatMoney(snapshot.amount)} to ${formatMoney(live.amount)}`);
  }
  const before = new Set((snapshot.payment_points ?? []).map(pointKey));
  const after = new Set((live.payment_points ?? []).map(pointKey));
  const added = (live.payment_points ?? []).filter(p => !before.has(pointKey(p)));
  const removed = (snapshot.payment_points ?? []).filter(p => !after.has(pointKey(p)));
  if (added.length > 0) out.push(`New payment methods: ${added.map(p => p.label).join(', ')}`);
  if (removed.length > 0) {
    out.push(`Removed payment methods: ${removed.map(p => p.label).join(', ')}`);
  }
  return out;
}
