import type { A2AMethodFilter, McpPaymentTriggers, PaymentManifest } from '../../../../types';

/** The Payment node's config as its panel reads and writes it. */
export interface PaymentNodeConfig {
  payment_gateway_id?: string;
  payment_surface_id?: string;
  mcp_payment_triggers?: McpPaymentTriggers;
  a2a_method_filters?: A2AMethodFilter[];
  require_all?: boolean;
  timeout_ms?: number;
  share_payer_email?: boolean;
  /** Written by the server on save; shown for the saved selection and never sent. */
  manifest_snapshot?: PaymentManifest;
  /** A local x402 or MPP policy, kept as-is until the operator migrates it. */
  unsupported_legacy?: 'x402' | 'mpp';
  original?: Record<string, unknown>;
  /** A disabled local policy, saved back unchanged. */
  preserved_policy?: Record<string, unknown>;
}
