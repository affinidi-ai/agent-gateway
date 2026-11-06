import { useCallback, useEffect, useRef, useState } from 'react';
import { apiClient } from '../../api';
import type { PaymentLedgerRow } from '../../types';

/** One ledger row read from the server. `reload` asks again and keeps the row shown meanwhile. */
export function usePaymentRow(paymentId: string) {
  const [row, setRow] = useState<PaymentLedgerRow | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const latest = useRef(0);

  const load = useCallback(async () => {
    const request = ++latest.current;
    setLoading(true);
    setError(null);
    try {
      const next = await apiClient.getPayment(paymentId);
      if (request === latest.current) setRow(next);
    } catch (err) {
      if (request === latest.current) setError(err instanceof Error ? err.message : String(err));
    } finally {
      if (request === latest.current) setLoading(false);
    }
  }, [paymentId]);

  useEffect(() => {
    setRow(null);
    load();
    return () => {
      latest.current += 1;
    };
  }, [load]);

  return { row, error, loading, reload: load };
}
