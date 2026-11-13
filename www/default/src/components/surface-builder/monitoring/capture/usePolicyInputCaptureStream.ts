import { useEffect, useRef, useState } from 'react';

/** One policy evaluation the gateway captured while policy input capture was on. */
export interface CapturedPolicyInput {
  id: number;
  timestamp: Date;
  plane: string;
  engine: string;
  slot: string;
  transitPoint?: string;
  surfaceVariant?: string;
  decision: 'allow' | 'deny' | 'error' | string;
  reason?: string;
  input: unknown;
}

export const MAX_POLICY_INPUTS = 20;

/**
 * Subscribes to `policy_input_captured` ws-message custom events for the surface
 * `configId` and keeps the last `MAX_POLICY_INPUTS`, newest first. Nothing is
 * kept while `paused`.
 */
export function usePolicyInputCaptureStream(configId: string, paused: boolean) {
  const [captures, setCaptures] = useState<CapturedPolicyInput[]>([]);
  const pausedRef = useRef(paused);
  const nextId = useRef(0);

  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  useEffect(() => {
    const handler = (event: Event) => {
      const data = (event as CustomEvent).detail;
      if (!data || data.type !== 'policy_input_captured' || data.config_id !== configId) return;
      if (pausedRef.current) return;
      const capture: CapturedPolicyInput = {
        id: nextId.current++,
        timestamp: new Date(data.timestamp || Date.now()),
        plane: data.plane,
        engine: data.engine,
        slot: data.slot,
        transitPoint: data.transit_point,
        surfaceVariant: data.surface_variant,
        decision: data.decision,
        reason: data.reason,
        input: data.input,
      };
      setCaptures(prev => [capture, ...prev.slice(0, MAX_POLICY_INPUTS - 1)]);
    };
    window.addEventListener('ws-message', handler);
    return () => window.removeEventListener('ws-message', handler);
  }, [configId]);

  return { captures, clear: () => setCaptures([]) };
}
