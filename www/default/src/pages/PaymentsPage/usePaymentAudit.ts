import { useCallback, useEffect, useRef, useState } from 'react';
import { apiClient } from '../../api';
import type { PaymentAuditPage, PaymentAuditQuery } from '../../types';

export const AUDIT_PAGE_SIZE = 50;

const EMPTY: PaymentAuditPage = {
  events: [],
  total: 0,
  page: 1,
  page_size: AUDIT_PAGE_SIZE,
  total_pages: 1,
};

/** One page of the payment audit trail for `query`; only the latest request writes the page. */
export function usePaymentAudit(query: PaymentAuditQuery) {
  const [page, setPage] = useState<PaymentAuditPage>(EMPTY);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const latest = useRef(0);
  const key = JSON.stringify(query);

  const refresh = useCallback(async () => {
    const request = ++latest.current;
    setLoading(true);
    setError(null);
    try {
      const next = await apiClient.listPaymentAudit({
        page_size: AUDIT_PAGE_SIZE,
        ...(JSON.parse(key) as PaymentAuditQuery),
      });
      if (request === latest.current) setPage(next);
    } catch (err) {
      if (request === latest.current) {
        setPage(EMPTY);
        setError(err instanceof Error ? err.message : 'Failed to load the audit trail');
      }
    } finally {
      if (request === latest.current) setLoading(false);
    }
  }, [key]);

  useEffect(() => {
    refresh();
    return () => {
      latest.current += 1;
    };
  }, [refresh]);

  return { page, loading, error, refresh };
}
