import { useCallback, useEffect, useState } from 'react';
import { apiClient } from '../../api';

/**
 * Resolves a payment gateway id to its name, from one `GET /payment-gateways`.
 * An id the list does not name, or a list that cannot be read, stays the id.
 */
export function usePaymentGatewayNames(): (id: string) => string {
  const [names, setNames] = useState<Map<string, string>>(new Map());

  useEffect(() => {
    let cancelled = false;
    apiClient
      .listPaymentGateways()
      .then(gateways => {
        if (!cancelled) {
          setNames(new Map(gateways.filter(g => g.name).map(g => [g.id, g.name])));
        }
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, []);

  return useCallback((id: string) => names.get(id) ?? id, [names]);
}
