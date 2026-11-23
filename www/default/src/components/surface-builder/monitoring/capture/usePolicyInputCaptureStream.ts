import { useEffect, useRef, useState } from 'react';

/** A policy definition a captured evaluation ran. */
export interface CapturedPolicy {
  id?: string;
  name?: string;
  version?: number;
}

/** One policy evaluation the gateway captured while policy input capture was on. */
export interface CapturedPolicyInput {
  id: number;
  timestamp: Date;
  plane: string;
  engine: string;
  slot: string;
  transitPoint?: string;
  surfaceVariant?: string;
  /** The policy definitions the slot evaluated. */
  policies: CapturedPolicy[];
  /** The id of the policy that denied, when the slot evaluates several. */
  decidedBy?: string;
  decision: 'allow' | 'deny' | 'error' | string;
  reason?: string;
  input: unknown;
}

export const MAX_POLICY_INPUTS = 50;

/**
 * Subscribes to `policy_input_captured` ws-message custom events for the surface
 * `configId` and keeps the last `MAX_POLICY_INPUTS`, newest first, and counts the
 * evaluations `policy_input_skipped` says the gateway dropped for this dashboard.
 * The payload stream's Pause doesn't apply: every evaluation of a listen is kept.
 */
export function usePolicyInputCaptureStream(configId: string) {
  const [captures, setCaptures] = useState<CapturedPolicyInput[]>([]);
  const [skipped, setSkipped] = useState(0);
  const nextId = useRef(0);

  useEffect(() => {
    const handler = (event: Event) => {
      const data = (event as CustomEvent).detail;
      if (!data || data.config_id !== configId) return;
      if (data.type === 'policy_input_skipped') {
        const count = Number(data.skipped);
        if (Number.isFinite(count) && count > 0) setSkipped(total => total + count);
        return;
      }
      if (data.type !== 'policy_input_captured') return;
      const capture: CapturedPolicyInput = {
        id: nextId.current++,
        timestamp: new Date(data.timestamp || Date.now()),
        plane: data.plane,
        engine: data.engine,
        slot: data.slot,
        transitPoint: data.transit_point,
        surfaceVariant: data.surface_variant,
        policies: Array.isArray(data.policies) ? data.policies : [],
        decidedBy: data.decided_by,
        decision: data.decision,
        reason: data.reason,
        input: data.input,
      };
      setCaptures(prev => [capture, ...prev.slice(0, MAX_POLICY_INPUTS - 1)]);
    };
    window.addEventListener('ws-message', handler);
    return () => window.removeEventListener('ws-message', handler);
  }, [configId]);

  return {
    captures,
    skipped,
    clear: () => {
      setCaptures([]);
      setSkipped(0);
    },
  };
}
