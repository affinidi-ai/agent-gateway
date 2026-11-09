import type { AgentSurface } from '../../api';

export interface PaymentGatewayUse {
  surfaceId: string;
  name: string;
  /** The base surface charges through the gateway. */
  base: boolean;
  /** Aliases of the variants whose override charges through the gateway. */
  variants: string[];
}

const chargesThrough = (policy: unknown, gatewayId: string): boolean => {
  const p = policy as { type?: unknown; payment_gateway_id?: unknown } | null | undefined;
  return p?.type === 'agent_pay' && p.payment_gateway_id === gatewayId;
};

const overridePolicy = (overrides: unknown): unknown =>
  (overrides as { target?: { payment_policy?: unknown } } | null | undefined)?.target
    ?.payment_policy;

/** The surfaces whose agent-pay policy, or a variant's override of it, names the gateway. */
export function surfacesUsingPaymentGateway(
  surfaces: AgentSurface[],
  gatewayId: string
): PaymentGatewayUse[] {
  return surfaces.flatMap(surface => {
    const base = chargesThrough(surface.target?.payment_policy, gatewayId);
    const variants = (surface.variants ?? [])
      .filter(variant => chargesThrough(overridePolicy(variant.overrides), gatewayId))
      .map(variant => variant.alias);
    return base || variants.length > 0
      ? [{ surfaceId: surface.surface_id, name: surface.name, base, variants }]
      : [];
  });
}
