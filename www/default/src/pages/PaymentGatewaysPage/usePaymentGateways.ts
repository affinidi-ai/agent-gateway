import { useCallback, useEffect, useState } from 'react';
import { apiClient } from '../../api';
import { getErrorMessage } from '../../utils/apiError';
import type { GatewayListItem } from '../../utils/gateways';

/** Whether a payment gateway matches the Connections filter: name, description, id or DID. */
export function matchesPaymentGateway(gateway: GatewayListItem, term: string): boolean {
  const needle = term.trim().toLowerCase();
  if (!needle) return true;
  return [gateway.name, gateway.description, gateway.id, gateway.did].some(
    value => typeof value === 'string' && value.toLowerCase().includes(needle)
  );
}

/** The payment gateways (`GET /payment-gateways`), with delete. */
export function usePaymentGateways() {
  const [gateways, setGateways] = useState<GatewayListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      setLoading(true);
      setLoadError(null);
      setGateways(await apiClient.listPaymentGateways());
    } catch (err) {
      setGateways([]);
      setLoadError(getErrorMessage(err, 'Failed to load payment gateways'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  /** Deletes a payment gateway; rejects with the gateway's reason, such as a 409 while it is in use. */
  const remove = useCallback(
    async (id: string) => {
      await apiClient.delete(`/payment-gateways/${encodeURIComponent(id)}`);
      await reload();
    },
    [reload]
  );

  return { gateways, loading, loadError, reload, remove };
}
