import * as Cap from '../capabilities';
import type { NodeDefinition } from '../types';
import type { AgentPayPaymentPolicy, PaymentManifest } from '../../../../types';
import PaymentPanel from './PaymentPanel';
import PaymentTriggersEditor from './PaymentTriggersEditor';
import { DOCS_URL } from '../../../../config/docs';
import {
  mcpMatchHasNoPatterns,
  normaliseA2aFilters,
  normaliseMcpTriggers,
  questionableMcpPatterns,
} from './triggers';
import {
  LEGACY_PAYMENT_MESSAGE,
  PAYMENT_TIMEOUT_MESSAGE,
  PAYMENT_TIMEOUT_SHORT_MESSAGE,
  classifyPaymentPolicy,
  isTimeoutShort,
  isTimeoutValid,
  keepsPreservedPolicy,
  nonEmpty,
  sendableTimeout,
} from './policy';
import type { PaymentNodeConfig } from './types';

const configuresAgentPay = (c: PaymentNodeConfig | undefined): boolean =>
  !c?.unsupported_legacy && !keepsPreservedPolicy(c);

export const paymentDefinition: NodeDefinition = {
  type: 'payment',
  label: 'Payment',
  description: 'Charge callers through agent-pay (MCP/A2A only)',
  icon: '$',
  paletteIcon: 'fa-dollar-sign',
  color: '#1cc88a',
  shape: 'circle',
  defaultRadius: 14,
  resizable: true,
  resizeRange: { min: 16, max: 60 },
  draggable: true,
  containedInSurface: false,
  edgeConstrained: false,
  xWeight: 0.65,
  stage: 'middleware',
  cardinality: 'multi',
  paletteCategory: 'policy',
  paletteOrder: 2,
  dropMode: 'edge',
  directionality: 'request',
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: {
    dropOnEdge: [Cap.PAYMENT_TARGET],
  },
  help: {
    title: 'Payment',
    docLink: DOCS_URL.paymentElement,
    bodyHtml: `
      <p>Charge callers for selected tools or methods on this Surface.
      The Gateway decides <em>whether</em> a request is chargeable;
      a connected <strong>agent-pay</strong> gateway takes the payment
      over the Fabric.</p>
      <p><strong>Payment surface:</strong> pick the agent-pay gateway and
      one of its payment surfaces. The surface id may carry a
      <code>$alias</code> to address one of its variants, for example
      <code>premium$eu</code>.</p>
      <p><strong>Price and payment methods</strong> come from the
      agent-pay manifest. The Gateway keeps a snapshot for display;
      agent-pay stays authoritative for the price.</p>
      <p><strong>Triggers:</strong></p>
      <ul>
        <li><strong>MCP</strong>: charge every tool call, only tools whose
        name matches a regex, or every tool except the matches. With no
        trigger set, every tool call is charged. Free methods such as
        <code>tools/list</code> are never charged.</li>
        <li><strong>A2A</strong>: choose which methods are charged, with
        optional texts a message must contain. With no text, every message
        is charged. With no filters set, <code>message/send</code> and
        <code>message/stream</code> are charged.</li>
        <li><strong>Charge every request</strong> ignores the triggers.</li>
      </ul>
      <p><strong>Held payments:</strong> when agent-pay holds a payment for
      review, the caller gets <code>202</code> over HTTP or the
      <code>PAYMENT_PENDING</code> error over MCP/A2A, with the case id.</p>
    `,
  },
  incompleteReason: (c: PaymentNodeConfig | undefined) => {
    if (c?.unsupported_legacy) return 'Local x402/MPP is no longer supported';
    if (keepsPreservedPolicy(c)) return null;
    if (!nonEmpty(c?.payment_gateway_id)) return 'Select a payment gateway';
    if (!nonEmpty(c?.payment_surface_id)) return 'Select a payment surface';
    return null;
  },
  featureDependencies: [
    {
      description: 'Payment only available for MCP/A2A',
      condition: (_c, ctx) => !!ctx.protocol && ctx.protocol !== 'mcp' && ctx.protocol !== 'a2a',
      check: () => false,
      severity: 'error',
      message: 'Payment requires MCP or A2A protocol',
    },
    {
      description: 'Local x402/MPP is no longer supported',
      condition: c => !!c?.unsupported_legacy,
      check: () => false,
      severity: 'error',
      message: LEGACY_PAYMENT_MESSAGE,
    },
    {
      description: 'Agent-pay requires a gateway and surface',
      condition: configuresAgentPay,
      check: c => nonEmpty(c?.payment_gateway_id) && nonEmpty(c?.payment_surface_id),
      severity: 'error',
      message: 'Select a connected payment gateway and its payment surface',
    },
    {
      description: 'An MCP Match trigger needs a pattern',
      condition: (c, ctx) =>
        ctx.protocol === 'mcp' && configuresAgentPay(c) && c?.require_all !== true,
      check: c => !mcpMatchHasNoPatterns(c?.mcp_payment_triggers),
      severity: 'error',
      message:
        'MCP payment triggers: "Charge tools matching regex" needs at least one pattern. Add one, or choose "All tools".',
    },
    {
      description: 'MCP trigger patterns the browser could not check',
      condition: configuresAgentPay,
      check: c => questionableMcpPatterns(c).length === 0,
      severity: 'warning',
      message:
        'Some MCP trigger patterns may not be accepted by the gateway. It checks them when you save.',
    },
    {
      description: 'Timeout must be a whole number of milliseconds the gateway accepts',
      condition: configuresAgentPay,
      check: c => isTimeoutValid(c?.timeout_ms),
      severity: 'error',
      message: PAYMENT_TIMEOUT_MESSAGE,
    },
    {
      description: 'Timeout leaves time for a card or wallet payment to finish',
      condition: configuresAgentPay,
      check: c => !isTimeoutShort(c?.timeout_ms),
      severity: 'warning',
      message: PAYMENT_TIMEOUT_SHORT_MESSAGE,
    },
  ],
  ConfigPanel: PaymentPanel,
  FullscreenPanel: PaymentTriggersEditor,
  payloadPath: 'target.payment_policy',
  defaultConfig: () => ({}),
  summary: (c: PaymentNodeConfig | undefined) => {
    if (c?.unsupported_legacy) return `unsupported (local ${c.unsupported_legacy})`;
    if (keepsPreservedPolicy(c)) return 'disabled';
    const amount = c?.manifest_snapshot?.amount;
    if (amount && nonEmpty(amount.amount)) return `agent-pay · ${amount.amount} ${amount.unit}`;
    return nonEmpty(c?.payment_gateway_id) && nonEmpty(c?.payment_surface_id) ? 'agent-pay' : null;
  },
  buildPayload: ctx => {
    const pc: PaymentNodeConfig | undefined = ctx.firstNodeOfType('payment')?.config;
    if (!pc) return undefined;
    if (pc.unsupported_legacy && pc.original && typeof pc.original === 'object') {
      return [{ path: 'target.payment_policy', value: pc.original }];
    }
    if (keepsPreservedPolicy(pc)) {
      return [{ path: 'target.payment_policy', value: pc.preserved_policy }];
    }
    if (!nonEmpty(pc.payment_gateway_id) || !nonEmpty(pc.payment_surface_id)) return undefined;
    const value: AgentPayPaymentPolicy = {
      type: 'agent_pay',
      payment_gateway_id: pc.payment_gateway_id.trim(),
      payment_surface_id: pc.payment_surface_id.trim(),
    };
    const mcp = normaliseMcpTriggers(pc.mcp_payment_triggers);
    if (mcp) value.mcp_payment_triggers = mcp;
    const a2a = normaliseA2aFilters(pc.a2a_method_filters);
    if (a2a) value.a2a_method_filters = a2a;
    if (pc.require_all === true) value.require_all = true;
    const timeout = sendableTimeout(pc.timeout_ms);
    if (timeout !== undefined) value.timeout_ms = timeout;
    if (pc.share_payer_email === true) value.share_payer_email = true;
    return [{ path: 'target.payment_policy', value }];
  },
  configFromPayload: (raw: unknown): PaymentNodeConfig => {
    if (!raw || typeof raw !== 'object') return {};
    const slice = raw as Record<string, unknown>;
    const kind = classifyPaymentPolicy(slice);
    if (kind === 'unsupported') {
      return {
        unsupported_legacy: slice.type === 'mpp' ? 'mpp' : 'x402',
        original: slice,
      };
    }
    if (kind === 'preserved') return { preserved_policy: slice };
    const config: PaymentNodeConfig = {
      payment_gateway_id:
        typeof slice.payment_gateway_id === 'string' ? slice.payment_gateway_id : '',
      payment_surface_id:
        typeof slice.payment_surface_id === 'string' ? slice.payment_surface_id : '',
    };
    const mcp = normaliseMcpTriggers(slice.mcp_payment_triggers);
    if (mcp) config.mcp_payment_triggers = mcp;
    const a2a = normaliseA2aFilters(slice.a2a_method_filters);
    if (a2a) config.a2a_method_filters = a2a;
    if (slice.require_all === true) config.require_all = true;
    if (typeof slice.timeout_ms === 'number') config.timeout_ms = slice.timeout_ms;
    if (slice.share_payer_email === true) config.share_payer_email = true;
    if (slice.manifest_snapshot && typeof slice.manifest_snapshot === 'object') {
      config.manifest_snapshot = slice.manifest_snapshot as PaymentManifest;
    }
    return config;
  },
};
