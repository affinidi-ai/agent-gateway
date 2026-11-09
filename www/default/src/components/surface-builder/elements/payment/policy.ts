import { normaliseA2aFilters, normaliseMcpTriggers } from './triggers';
import type { PaymentNodeConfig } from './types';

export const nonEmpty = (v: unknown): v is string => typeof v === 'string' && v.trim() !== '';

export const PAYMENT_TIMEOUT_DEFAULT_MS = 15000;
export const PAYMENT_TIMEOUT_MIN_MS = 1000;
export const PAYMENT_TIMEOUT_MAX_MS = 120000;

// A card or wallet charge goes over the fabric to agent-pay and then to the provider, which
// often takes several seconds. Below this the gateway can stop waiting after the payment was
// taken, and the caller gets "payment not confirmed" instead of the paid answer.
export const PAYMENT_TIMEOUT_SHORT_MS = 5000;

export const PAYMENT_TIMEOUT_SHORT_MESSAGE = `Below ${PAYMENT_TIMEOUT_SHORT_MS} ms a card or wallet payment can be taken after the gateway stops waiting, and the caller is told the payment is not confirmed.`;

/** True for a valid timeout short enough to cut off a slow but successful payment. */
export const isTimeoutShort = (v: unknown): boolean =>
  isTimeoutValid(v) &&
  v !== undefined &&
  v !== null &&
  v !== '' &&
  Number(v) < PAYMENT_TIMEOUT_SHORT_MS;

export const PAYMENT_TIMEOUT_MESSAGE = `Timeout must be a whole number of milliseconds from ${PAYMENT_TIMEOUT_MIN_MS} to ${PAYMENT_TIMEOUT_MAX_MS}.`;

export const LEGACY_PAYMENT_MESSAGE =
  'Local x402/MPP is no longer supported. This surface returns 503 until it is pointed at an agent-pay surface.';

export const DISABLED_LEGACY_PAYMENT_MESSAGE =
  'This surface has a disabled local payment policy that charges nothing. It is kept as-is until you select an agent-pay surface.';

const isLocalX402 = (slice: Record<string, unknown>) =>
  slice.type === 'x402' && (slice.provider === undefined || slice.provider === 'local');

/**
 * How the dashboard treats a stored `payment_policy`: `agent_pay` (also the
 * enabled `x402` + `provider: agent_pay` shape), `unsupported` for an enabled
 * local x402 or MPP policy, and `preserved` for anything else (a disabled
 * legacy policy), which charges nothing and is saved back unchanged.
 */
export function classifyPaymentPolicy(
  slice: Record<string, unknown>
): 'agent_pay' | 'unsupported' | 'preserved' {
  if (slice.type === 'agent_pay') return 'agent_pay';
  const enabled = slice.enabled !== false;
  if (enabled && slice.type === 'x402' && slice.provider === 'agent_pay') return 'agent_pay';
  if (enabled && (isLocalX402(slice) || slice.type === 'mpp')) return 'unsupported';
  return 'preserved';
}

/** A preserved policy stays in effect until the operator picks an agent-pay surface. */
export const keepsPreservedPolicy = (config: PaymentNodeConfig | undefined): boolean =>
  !!config?.preserved_policy &&
  !nonEmpty(config.payment_gateway_id) &&
  !nonEmpty(config.payment_surface_id);

/** An empty timeout is valid and means the default; a value must be a whole number inside the gateway's range. */
export const isTimeoutValid = (v: unknown): boolean => {
  if (v === undefined || v === null || v === '') return true;
  const n = Number(v);
  return Number.isInteger(n) && n >= PAYMENT_TIMEOUT_MIN_MS && n <= PAYMENT_TIMEOUT_MAX_MS;
};

/** The timeout to send, or undefined when it is empty or the gateway would refuse it. */
export const sendableTimeout = (v: unknown): number | undefined =>
  v === undefined || v === null || v === '' || !isTimeoutValid(v) ? undefined : Number(v);

/** Strips the legacy local-payment fields and keeps the triggers. */
export function migrateLegacyPaymentConfig(config: PaymentNodeConfig): PaymentNodeConfig {
  const original = config?.original ?? {};
  const next: PaymentNodeConfig = {};
  const mcp = normaliseMcpTriggers(original.mcp_payment_triggers);
  if (mcp) next.mcp_payment_triggers = mcp;
  const a2a = normaliseA2aFilters(original.a2a_method_filters);
  if (a2a) next.a2a_method_filters = a2a;
  if (original.require_all === true) next.require_all = true;
  return next;
}
