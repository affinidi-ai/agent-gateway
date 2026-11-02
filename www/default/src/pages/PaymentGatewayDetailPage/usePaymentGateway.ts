import { useCallback, useEffect, useState } from 'react';
import { apiClient } from '../../api';
import { getErrorMessage } from '../../utils/apiError';
import type { GatewayListItem } from '../../utils/gateways';

/** One payment gateway (`GET /payment-gateways/{id}`), with updates through `PUT`. */
export function usePaymentGateway(id: string) {
  const [gateway, setGateway] = useState<GatewayListItem | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      setLoading(true);
      setLoadError(null);
      const { data } = await apiClient.get<GatewayListItem>(
        `/payment-gateways/${encodeURIComponent(id)}`
      );
      setGateway(data);
    } catch (err) {
      setGateway(null);
      setLoadError(getErrorMessage(err, 'Failed to load the payment gateway'));
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    reload();
  }, [reload]);

  /** Saves the given fields; rejects with the gateway's reason, such as a 409 while it is in use. */
  const update = useCallback(
    async (fields: Partial<Pick<GatewayListItem, 'name' | 'description' | 'status'>>) => {
      const { data } = await apiClient.put<GatewayListItem>(
        `/payment-gateways/${encodeURIComponent(id)}`,
        fields
      );
      setGateway(prev => (prev ? { ...prev, ...data } : data));
    },
    [id]
  );

  return { gateway, loading, loadError, reload, update };
}
