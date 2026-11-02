import { apiClient } from '../../api';
import { getErrorMessage } from '../../utils/apiError';

export interface PingResult {
  ok: boolean;
  message: string;
}

/** Pings a payment gateway over the fabric and says how it went. */
export async function pingPaymentGateway(id: string, name: string): Promise<PingResult> {
  try {
    const { data } = await apiClient.post<{
      success?: boolean;
      round_trip_ms?: number;
      message?: string;
    }>(`/payment-gateways/${encodeURIComponent(id)}/ping`);
    return data?.success
      ? { ok: true, message: `Ping to "${name}" successful (${data.round_trip_ms}ms)` }
      : { ok: false, message: `Ping to "${name}" failed: ${data?.message || 'no answer'}` };
  } catch (err) {
    return { ok: false, message: getErrorMessage(err, `Failed to ping "${name}"`) };
  }
}
