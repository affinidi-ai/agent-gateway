import { useCallback, useEffect, useRef, useState } from 'react';
import { apiClient } from '../../api';
import type { PaymentLedgerRow, PaymentOutcome } from '../../types';
import { fetchLegacyPayments, type LegacyPaymentRow } from './legacy';

export const LEDGER_LIMIT = 500;

interface Filters {
  surfaceId?: string;
  outcome: PaymentOutcome | '';
}

/**
 * The ledger page for the current filters plus the legacy rows. A response only
 * counts while it belongs to the latest request, so a slow answer to an earlier
 * filter never overwrites the rows, the error or the loading state of a later one.
 * When a refresh fails the rows of the same filter stay and `stale` is set; rows
 * of an earlier filter are dropped, so they never pass for the new filter's.
 */
export function usePaymentLedger({ surfaceId, outcome }: Filters) {
  const [rows, setRows] = useState<PaymentLedgerRow[]>([]);
  const [total, setTotal] = useState(0);
  const [legacyRows, setLegacyRows] = useState<LegacyPaymentRow[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stale, setStale] = useState(false);
  const loadedFilter = useRef('');
  const latest = useRef(0);

  const refresh = useCallback(async () => {
    const request = ++latest.current;
    const filterKey = `${surfaceId ?? ''}|${outcome}`;
    setRefreshing(true);
    setError(null);
    try {
      const [page, legacy] = await Promise.all([
        apiClient.listPayments({
          limit: LEDGER_LIMIT,
          surface_id: surfaceId,
          outcome: outcome || undefined,
        }),
        fetchLegacyPayments(url => apiClient.fetch(url)),
      ]);
      if (request !== latest.current) return;
      loadedFilter.current = filterKey;
      setStale(false);
      setRows(page.payments);
      setTotal(page.total);
      setLegacyRows(legacy);
    } catch (err) {
      if (request === latest.current) {
        setError(err instanceof Error ? err.message : 'Failed to load payments');
        if (loadedFilter.current === filterKey) {
          setStale(true);
        } else {
          setRows([]);
          setTotal(0);
          setStale(false);
        }
      }
    } finally {
      if (request === latest.current) setRefreshing(false);
    }
  }, [surfaceId, outcome]);

  useEffect(() => {
    refresh();
    return () => {
      latest.current += 1;
    };
  }, [refresh]);

  const dismissError = useCallback(() => setError(null), []);

  return { rows, total, legacyRows, refreshing, stale, error, dismissError, refresh };
}
