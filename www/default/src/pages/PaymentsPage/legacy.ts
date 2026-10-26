export interface LegacyPaymentRow {
  key: string;
  protocol: 'x402' | 'mpp';
  surface: string;
  status: string;
  amount: string;
  created_at?: number;
}

type Raw = Record<string, unknown>;

const text = (v: unknown): string =>
  typeof v === 'string' || typeof v === 'number' ? String(v) : '';

const timestamp = (v: unknown): number | undefined => (typeof v === 'number' ? v : undefined);

const dollars = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD',
  minimumFractionDigits: 2,
  maximumFractionDigits: 6,
});

/**
 * An x402 amount, which the gateway stores in the token's smallest unit, scaled by the
 * token's decimals and shown in dollars. Without usable decimals the raw amount is shown.
 */
export function formatTokenAmount(amount: unknown, decimals: unknown): string {
  const units = text(amount);
  if (!units) return '—';
  if (!/^\d+$/.test(units) || typeof decimals !== 'number' || !Number.isInteger(decimals)) {
    return units;
  }
  if (decimals < 0) return units;
  const digits = units.padStart(decimals + 1, '0');
  const whole = digits.slice(0, digits.length - decimals);
  const fraction = digits.slice(digits.length - decimals);
  return dollars.format(Number(fraction ? `${whole}.${fraction}` : whole));
}

/** An MPP amount, already in major units, with its ISO currency code (USD when absent). */
export function formatMajorAmount(amount: unknown, currency: unknown): string {
  const value = text(amount);
  if (!value) return '—';
  const n = parseFloat(value);
  if (Number.isNaN(n)) return value;
  const code = (text(currency) || 'usd').toUpperCase();
  try {
    return new Intl.NumberFormat('en-US', { style: 'currency', currency: code }).format(n);
  } catch {
    return `${n.toFixed(2)} ${code}`;
  }
}

/**
 * One row per x402 transaction. The listing returns a verification and a settlement
 * summary for each settled transaction, both carrying the transaction id as
 * `correlation_id`; the settlement, when there is one, gives the current status.
 */
export function mergeX402Payments(payments: Raw[]): LegacyPaymentRow[] {
  const byTransaction = new Map<string, Raw[]>();
  payments.forEach((p, i) => {
    const key = text(p.correlation_id) || text(p.tx_hash) || text(p.id) || String(i);
    byTransaction.set(key, [...(byTransaction.get(key) ?? []), p]);
  });
  return Array.from(byTransaction, ([key, parts]) => {
    const verification = parts.find(p => p.type === 'verification');
    const settlement = parts.find(p => p.type === 'settlement');
    const summary = verification ?? parts[0];
    const current = settlement ?? summary;
    return {
      key: `x402-${key}`,
      protocol: 'x402' as const,
      surface: text(summary.channel_name) || text(summary.surface_id) || '—',
      status: text(current.status) || text(current.type) || '—',
      amount: formatTokenAmount(summary.amount, summary.decimals),
      created_at: timestamp(summary.created_at),
    };
  });
}

export async function fetchLegacyPayments(
  fetcher: (url: string) => Promise<Response>
): Promise<LegacyPaymentRow[]> {
  const read = async (url: string): Promise<Raw | null> => {
    try {
      const res = await fetcher(url);
      return res.ok ? await res.json() : null;
    } catch {
      return null;
    }
  };
  const [x402, mpp] = await Promise.all([
    read('/api/admin/x402/payments/all?limit=200'),
    read('/api/admin/mpp/transactions?limit=200'),
  ]);
  const list = (v: unknown): Raw[] => (Array.isArray(v) ? (v as Raw[]) : []);
  const rows: LegacyPaymentRow[] = [
    ...mergeX402Payments(list(x402?.payments)),
    ...list(mpp?.transactions).map((t, i) => ({
      key: `mpp-${text(t.id) || i}`,
      protocol: 'mpp' as const,
      surface: text(t.channel_name) || text(t.surface_id) || '—',
      status: text(t.status) || '—',
      amount: formatMajorAmount(t.amount, t.currency),
      created_at: timestamp(t.created_at),
    })),
  ];
  return rows.sort((a, b) => (b.created_at ?? 0) - (a.created_at ?? 0));
}
