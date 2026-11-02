import { useCallback, useEffect, useState } from 'react';
import { apiClient, type ApiError } from '../../api';
import type { GatewayInfo } from '../../types';

/** Why a payment gateway's info could not be read. */
export type GatewayInfoProblem = 'unreachable' | 'not-payment' | 'failed';

export const GATEWAY_INFO_PROBLEM_TEXT: Record<GatewayInfoProblem, string> = {
  unreachable: 'agent-pay is not reachable yet. It may still be connecting.',
  'not-payment':
    'This gateway answered, but not as a payment gateway. Check that the link came from agent-pay and that agent-pay is up to date.',
  failed: 'Could not read what this payment gateway offers.',
};

/** 503: not connected or no answer; 502: answered, but is not a payment gateway. */
export function gatewayInfoProblem(err: unknown): GatewayInfoProblem {
  const status = (err as Partial<ApiError> | null)?.status;
  if (status === 503) return 'unreachable';
  if (status === 502) return 'not-payment';
  return 'failed';
}

export interface PaymentGatewayInfoState {
  info: GatewayInfo | null;
  loading: boolean;
  problem: GatewayInfoProblem | null;
  reload: () => void;
}

interface Loaded {
  info: GatewayInfo | null;
  loading: boolean;
  problem: GatewayInfoProblem | null;
}

/** What a payment gateway offers (`GET /payment-gateways/{id}/info`), read while `enabled`. */
export function usePaymentGatewayInfo(gatewayId: string, enabled = true): PaymentGatewayInfoState {
  const [state, setState] = useState<Loaded>({
    info: null,
    loading: enabled && !!gatewayId,
    problem: null,
  });
  const [tick, setTick] = useState(0);

  useEffect(() => {
    if (!enabled || !gatewayId) {
      setState({ info: null, loading: false, problem: null });
      return;
    }
    let cancelled = false;
    setState(prev => ({ ...prev, loading: true }));
    apiClient
      .getPaymentGatewayInfo(gatewayId)
      .then(info => {
        if (cancelled) return;
        const isPayment = info?.role === 'payment';
        setState({
          info: isPayment ? info : null,
          loading: false,
          problem: isPayment ? null : 'not-payment',
        });
      })
      .catch((err: unknown) => {
        if (!cancelled) setState({ info: null, loading: false, problem: gatewayInfoProblem(err) });
      });
    return () => {
      cancelled = true;
    };
  }, [gatewayId, enabled, tick]);

  const reload = useCallback(() => setTick(t => t + 1), []);
  return { ...state, reload };
}
