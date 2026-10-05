import * as Cap from '../capabilities';
import type { NodeDefinition } from '../types';
import PaymentPanel from './PaymentPanel';
import PaymentFullscreen from './PaymentFullscreen';
import { DOCS_URL } from '../../../../config/docs';

/**
 * Payment element — x402 paywall.
 *
 * Config shape mirrors the backend `X402Config` (see `src/config/types.rs`):
 *   { enabled, verification_mode, settlement_mode, supported_schemes,
 *     supported_networks, payment_requirements, rpc_endpoints,
 *     min_confirmations, accept_mempool_tx, facilitator_url,
 *     facilitator_gateway_id, settlement_gateway_id, mcp_payment_triggers,
 *     a2a_method_filters }
 *
 * The `type: 'x402'` discriminator is added at `buildPayload` time.
 */
export const paymentDefinition: NodeDefinition = {
  type: 'payment',
  label: 'Payment',
  description: 'x402 paywall or MPP (MCP/A2A only)',
  icon: '\u0024',
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
      <p>Attach a <strong>payment requirement</strong> to specific tools
      or methods on this Surface. The Gateway intercepts matching
      requests and demands a verifiable payment receipt before
      forwarding them upstream. Returns a 402 challenge on the first
      miss; once the caller settles the receipt is verified and the
      request flows through.</p>
      <p>Two protocols are supported via the <em>Payment Protocol</em>
      selector once enabled:</p>
      <ul>
        <li><strong>x402</strong>: open blockchain-payment protocol
        with verification / settlement modes, networks, RPC endpoints
        and protocol-specific triggers. Heavy config in the fullscreen
        editor.</li>
        <li><strong>MPP</strong> — Machine Payments Protocol
        (draft-httpauth-payment-00). Realm, HMAC secret key, payment
        methods (JSON) and challenge TTL are inline; Stripe card key,
        on-chain verification posture, and MCP/A2A triggers are in the
        fullscreen editor.</li>
      </ul>
      <p><strong>Where it docks:</strong> the request edge into the
      Target.</p>
      <p><strong>Protocol-specific triggers:</strong></p>
      <ul>
        <li><strong>MCP</strong>: list the tool names that are paid.
        Anything else passes free.</li>
        <li><strong>A2A</strong>: list method-name filters. Other
        methods pass free.</li>
        <li>Payment is unsupported on AP2 / DIDComm.</li>
      </ul>
      <p><strong>Auto-pay (outbound):</strong> MPP auto-pay, for when
      this Surface CALLS an MPP-protected fabric target, is configured
      on the Managed Agent node — independent of which protocol this
      Surface itself accepts.</p>
    `,
  },
  incompleteReason: c => {
    if (!c?.enabled) return 'Enable to configure payment policy';
    if (c.provider === 'agent_pay') {
      if (!c.payment_gateway_id) return 'Select a payment gateway';
      if (!c.payment_surface_id) return 'Enter the payment surface id';
      return null;
    }
    if (c.payment_kind === 'mpp') {
      if (!c.mpp_realm) return 'MPP realm is required';
      if (!c.mpp_secret_key) return 'MPP secret key is required';
      return null;
    }
    if (!Array.isArray(c.payment_requirements) || c.payment_requirements.length === 0) {
      return 'x402 payment options are required';
    }
    return null;
  },
  featureDependencies: [
    {
      description: 'Payment only available for MCP/A2A',
      condition: (c, ctx) =>
        !!c?.enabled && !!ctx.protocol && ctx.protocol !== 'mcp' && ctx.protocol !== 'a2a',
      check: () => false,
      severity: 'error',
      message: 'Payment requires MCP or A2A protocol',
    },
    {
      description: 'Agent-Pay delegation requires a gateway and surface',
      condition: c => !!c?.enabled && c.provider === 'agent_pay',
      check: c =>
        typeof c.payment_gateway_id === 'string' &&
        c.payment_gateway_id.trim() !== '' &&
        typeof c.payment_surface_id === 'string' &&
        c.payment_surface_id.trim() !== '',
      severity: 'error',
      message: 'Select a connected payment gateway and enter its payment surface id',
    },
    {
      description: 'MCP payments need a trigger mode',
      condition: (c, ctx) => ctx.protocol === 'mcp' && !!c?.enabled && c.provider !== 'agent_pay',
      check: c => {
        const triggers =
          c.payment_kind === 'mpp' ? c.mpp_mcp_payment_triggers : c.mcp_payment_triggers;
        if (!triggers || typeof triggers !== 'object') return false;
        if (triggers.mode === 'all') return true;
        return (
          Array.isArray(triggers.patterns) &&
          triggers.patterns.some((p: any) => typeof p === 'string' && p.trim() !== '')
        );
      },
      severity: 'error',
      message:
        'MCP payment triggers: choose "All tools" or provide at least one regex pattern for match/exclude mode',
    },
    {
      description: 'A2A payments need method filters',
      condition: (c, ctx) =>
        ctx.protocol === 'a2a' &&
        !!c?.enabled &&
        c.payment_kind !== 'mpp' &&
        c.provider !== 'agent_pay',
      check: c => Array.isArray(c.a2a_method_filters) && c.a2a_method_filters.length > 0,
      severity: 'warning',
      message: 'A2A protocol requires method filters to activate payment',
    },
    {
      description: 'External facilitator requires URL',
      condition: c =>
        !!c?.enabled &&
        c.payment_kind !== 'mpp' &&
        (c.verification_mode === 'external_facilitator' ||
          c.settlement_mode === 'external_facilitator'),
      check: c => typeof c.facilitator_url === 'string' && c.facilitator_url.trim() !== '',
      severity: 'warning',
      message: 'External facilitator mode requires a facilitator URL',
    },
    {
      description: 'Fabric gateway facilitator requires gateway selection',
      condition: c =>
        !!c?.enabled &&
        c.payment_kind !== 'mpp' &&
        (c.verification_mode === 'fabric_gateway' || c.settlement_mode === 'fabric_gateway'),
      check: c =>
        typeof c.facilitator_gateway_id === 'string' && c.facilitator_gateway_id.trim() !== '',
      severity: 'warning',
      message: 'Fabric gateway facilitator requires a connected gateway',
    },
    {
      description: 'MPP requires realm and secret key',
      condition: c => !!c?.enabled && c.payment_kind === 'mpp',
      check: c =>
        typeof c.mpp_realm === 'string' &&
        c.mpp_realm.trim() !== '' &&
        typeof c.mpp_secret_key === 'string' &&
        c.mpp_secret_key.trim() !== '',
      severity: 'error',
      message: 'MPP requires both a realm and a secret key',
    },
    {
      description: 'MPP card method requires a Stripe secret key',
      condition: c => !!c?.enabled && c.payment_kind === 'mpp',
      check: c => {
        const raw = c.mpp_payment_methods;
        let methods: any[] = [];
        if (Array.isArray(raw)) methods = raw;
        else if (typeof raw === 'string' && raw.trim()) {
          try {
            methods = JSON.parse(raw);
          } catch {
            methods = [];
          }
        }
        const hasCard =
          Array.isArray(methods) &&
          methods.some(
            (m: any) =>
              typeof m?.method === 'string' && ['card', 'stripe'].includes(m.method.toLowerCase())
          );
        if (!hasCard) return true;
        return typeof c.mpp_stripe_secret_key === 'string' && c.mpp_stripe_secret_key.trim() !== '';
      },
      severity: 'warning',
      message:
        'A card/stripe payment method is configured but no Stripe secret key is set — open "Configure MPP…" to add one',
    },
    {
      description: 'MPP A2A payments need method filters',
      condition: (c, ctx) => ctx.protocol === 'a2a' && !!c?.enabled && c.payment_kind === 'mpp',
      check: c => Array.isArray(c.mpp_a2a_method_filters) && c.mpp_a2a_method_filters.length > 0,
      severity: 'warning',
      message:
        'No A2A method filters configured — MPP will not charge for any A2A request on this surface',
    },
    {
      description: 'x402 requires at least one payment requirement',
      condition: c => !!c?.enabled && c.payment_kind !== 'mpp' && c.provider !== 'agent_pay',
      check: c => Array.isArray(c.payment_requirements) && c.payment_requirements.length > 0,
      severity: 'error',
      message: 'x402 payment is enabled but no payment options are defined',
    },
    {
      description: 'Every x402 requirement needs a recipient',
      condition: c =>
        !!c?.enabled &&
        c.payment_kind !== 'mpp' &&
        Array.isArray(c.payment_requirements) &&
        c.payment_requirements.length > 0,
      check: c =>
        (c.payment_requirements as any[]).every(
          r => typeof r?.recipient_id === 'string' && r.recipient_id.trim() !== ''
        ),
      severity: 'error',
      message: 'Each x402 payment option must select a recipient address',
    },
    {
      description: 'Every x402 requirement needs a positive amount',
      condition: c =>
        !!c?.enabled &&
        c.payment_kind !== 'mpp' &&
        Array.isArray(c.payment_requirements) &&
        c.payment_requirements.length > 0,
      check: c =>
        (c.payment_requirements as any[]).every(r => {
          const n = parseFloat(String(r?.amount ?? ''));
          return Number.isFinite(n) && n > 0;
        }),
      severity: 'error',
      message: 'Each x402 payment option must set a charge amount greater than zero',
    },
  ],
  ConfigPanel: PaymentPanel,
  FullscreenPanel: PaymentFullscreen,
  payloadPath: 'target.payment_policy',
  defaultConfig: () => ({
    enabled: false,
  }),
  summary: c =>
    c?.enabled
      ? c?.provider === 'agent_pay'
        ? c?.payment_kind === 'mpp'
          ? 'agent-pay (mpp)'
          : 'agent-pay (x402)'
        : c?.payment_kind === 'mpp'
          ? 'mpp'
          : 'x402'
      : null,
  buildPayload: ctx => {
    const node = ctx.firstNodeOfType('payment');
    const pc = node?.config;
    if (!pc?.enabled) return undefined;
    const slices: Array<{ path: string; value: any }> = [];
    const kind: 'x402' | 'mpp' = pc.payment_kind === 'mpp' ? 'mpp' : 'x402';

    // Model B: delegate the whole paywall to a remote payment gateway. Emit
    // only the delegation pointer; the remote surface owns everything else.
    // `delegated_rail` is informational (audit/config clarity) only — the
    // fabric relay itself is protocol-agnostic — so it is omitted entirely
    // for the x402 default, matching the backend's byte-compat serialization.
    if (pc.provider === 'agent_pay') {
      const gw = (pc.payment_gateway_id || '').trim();
      const ch = (pc.payment_surface_id || '').trim();
      if (!gw || !ch) return undefined;
      slices.push({
        path: 'target.payment_policy',
        value: {
          type: 'x402',
          enabled: true,
          provider: 'agent_pay',
          payment_gateway_id: gw,
          payment_surface_id: ch,
          ...(kind === 'mpp' ? { delegated_rail: 'mpp' } : {}),
        },
      });
      return slices;
    }

    if (kind === 'x402') {
      const value: Record<string, any> = { type: 'x402', enabled: true };
      // Skip MPP-only fields and the meta `payment_kind` discriminator
      // so they don't leak into the x402 wire payload.
      const skipKeys = new Set([
        'enabled',
        'payment_kind',
        'mpp_realm',
        'mpp_secret_key',
        'mpp_challenge_ttl',
        'mpp_payment_methods',
        'mpp_mcp_payment_triggers',
        'mpp_a2a_method_filters',
        'mpp_stripe_secret_key',
        'mpp_crypto_verification_mode',
        'mpp_min_confirmations',
        'mpp_verification_timeout_ms',
        'mpp_rpc_endpoints',
        'mpp_auto_pay',
        'mpp_auto_pay_max_amount',
      ]);
      for (const [k, v] of Object.entries(pc)) {
        if (skipKeys.has(k)) continue;
        if (v === undefined || v === null) continue;
        if (k === 'mcp_payment_triggers' && v && typeof v === 'object') {
          const t: any = v;
          if (t.mode === 'all') {
            value[k] = { mode: 'all' };
          } else if (t.mode === 'match' || t.mode === 'exclude') {
            const patterns = Array.isArray(t.patterns)
              ? t.patterns.filter((p: any) => typeof p === 'string' && p.trim())
              : [];
            value[k] = { mode: t.mode, patterns };
          }
          continue;
        }
        if (k === 'payment_requirements' && Array.isArray(v)) {
          // Normalise each requirement so the wire payload contains
          // exactly one recipient field and no client-supplied wallet
          // address. The server resolves `pay_to` from `recipient_id`
          // against the global x402 recipient list, and serde rejects
          // a payload that carries both `recipientId` and
          // `recipient_id` as a duplicate field.
          value[k] = v.map((req: any) => {
            if (!req || typeof req !== 'object') return req;
            const { recipientId, recipient_id, payTo: _payTo, pay_to: _pay_to, ...rest } = req;
            const recipient =
              (typeof recipient_id === 'string' && recipient_id) ||
              (typeof recipientId === 'string' && recipientId) ||
              '';
            return { ...rest, recipient_id: recipient };
          });
          continue;
        }
        value[k] = v;
      }
      slices.push({ path: 'target.payment_policy', value });
    } else {
      // MPP: project the panel form fields onto the backend MppConfig
      // shape. Empty / invalid fields are dropped so the wire payload
      // stays clean.
      const realm = (pc.mpp_realm || '').trim();
      const secret = (pc.mpp_secret_key || '').trim();
      if (!realm || !secret) {
        // Cannot persist a half-configured MPP policy; drop the slice
        // entirely rather than emit invalid JSON. Inline validation in
        // the panel surfaces the missing fields.
        return undefined;
      }
      const value: Record<string, any> = {
        type: 'mpp',
        enabled: true,
        realm,
        secret_key: secret,
      };
      const ttl = parseInt(pc.mpp_challenge_ttl, 10);
      if (Number.isFinite(ttl) && ttl > 0) value.challenge_ttl_seconds = ttl;
      const methodsRaw = pc.mpp_payment_methods;
      let methods: any = null;
      if (Array.isArray(methodsRaw)) {
        methods = methodsRaw;
      } else if (typeof methodsRaw === 'string' && methodsRaw.trim()) {
        try {
          methods = JSON.parse(methodsRaw);
        } catch {
          methods = null;
        }
      }
      if (Array.isArray(methods) && methods.length > 0) {
        value.payment_methods = methods;
      }
      const triggers = pc.mpp_mcp_payment_triggers;
      if (triggers && typeof triggers === 'object' && typeof triggers.mode === 'string') {
        if (triggers.mode === 'all') {
          value.mcp_payment_triggers = { mode: 'all' };
        } else if (triggers.mode === 'match' || triggers.mode === 'exclude') {
          const patterns = Array.isArray(triggers.patterns)
            ? triggers.patterns.filter((p: any) => typeof p === 'string' && p.trim())
            : [];
          value.mcp_payment_triggers = { mode: triggers.mode, patterns };
        }
      }
      const a2aFilters = pc.mpp_a2a_method_filters;
      if (Array.isArray(a2aFilters) && a2aFilters.length > 0) {
        value.a2a_method_filters = a2aFilters;
      }
      const stripeKey = (pc.mpp_stripe_secret_key || '').trim();
      if (stripeKey) value.stripe_secret_key = stripeKey;
      const verificationMode = pc.mpp_crypto_verification_mode;
      if (
        typeof verificationMode === 'string' &&
        ['passthrough', 'onchain', 'signature', 'full'].includes(verificationMode)
      ) {
        value.crypto_verification_mode = verificationMode;
      }
      const minConfirmations = parseInt(pc.mpp_min_confirmations, 10);
      if (Number.isFinite(minConfirmations) && minConfirmations >= 0) {
        value.min_confirmations = minConfirmations;
      }
      const verificationTimeout = parseInt(pc.mpp_verification_timeout_ms, 10);
      if (Number.isFinite(verificationTimeout) && verificationTimeout > 0) {
        value.verification_timeout_ms = verificationTimeout;
      }
      const rpcRaw = pc.mpp_rpc_endpoints;
      let rpcEndpoints: any = null;
      if (rpcRaw && typeof rpcRaw === 'object') {
        rpcEndpoints = rpcRaw;
      } else if (typeof rpcRaw === 'string' && rpcRaw.trim()) {
        try {
          rpcEndpoints = JSON.parse(rpcRaw);
        } catch {
          rpcEndpoints = null;
        }
      }
      if (rpcEndpoints && typeof rpcEndpoints === 'object' && !Array.isArray(rpcEndpoints)) {
        value.rpc_endpoints = rpcEndpoints;
      }
      slices.push({ path: 'target.payment_policy', value });
    }

    // mpp_auto_pay / mpp_auto_pay_max_amount are siblings of payment_policy
    // on the Surface Target — they apply when the surface CALLS an MPP
    // endpoint, regardless of whether THIS surface accepts MPP/x402.
    if (pc.mpp_auto_pay) {
      slices.push({ path: 'target.mpp_auto_pay', value: true });
      const max = (pc.mpp_auto_pay_max_amount || '').toString().trim();
      if (max) slices.push({ path: 'target.mpp_auto_pay_max_amount', value: max });
    }

    return slices;
  },
  configFromPayload: slice => {
    if (!slice || typeof slice !== 'object') return { enabled: false };
    if (slice.type === 'x402') {
      const { type: _t, ...rest } = slice;
      // Normalise requirements on load: backend serialises with the
      // camelCase `recipientId` (serde rename) and includes a resolved
      // `payTo` for display, but the editor state should only ever
      // carry `recipient_id` so re-saves don't end up with both keys
      // (serde rejects that as a duplicate field).
      if (Array.isArray(rest.payment_requirements)) {
        rest.payment_requirements = rest.payment_requirements.map((req: any) => {
          if (!req || typeof req !== 'object') return req;
          const { recipientId, recipient_id, payTo: _payTo, pay_to: _pay_to, ...r } = req;
          const recipient =
            (typeof recipient_id === 'string' && recipient_id) ||
            (typeof recipientId === 'string' && recipientId) ||
            '';
          return { ...r, recipient_id: recipient };
        });
      }
      return {
        ...rest,
        enabled: rest.enabled !== false,
        // `type` is always the literal "x402" wire tag, even when
        // `provider === 'agent_pay'` delegates to a remote MPP surface —
        // recover the operator's rail choice from `delegated_rail` so the
        // "Delegated Payment Protocol" selector reflects it on reload.
        payment_kind:
          rest.provider === 'agent_pay' && rest.delegated_rail === 'mpp' ? 'mpp' : 'x402',
      };
    }
    if (slice.type === 'mpp') {
      return {
        enabled: slice.enabled !== false,
        payment_kind: 'mpp',
        mpp_realm: slice.realm || '',
        mpp_secret_key: slice.secret_key || '',
        mpp_challenge_ttl: slice.challenge_ttl_seconds ?? '',
        mpp_payment_methods: Array.isArray(slice.payment_methods)
          ? JSON.stringify(slice.payment_methods, null, 2)
          : '',
        mpp_mcp_payment_triggers: slice.mcp_payment_triggers ?? undefined,
        mpp_a2a_method_filters: Array.isArray(slice.a2a_method_filters)
          ? slice.a2a_method_filters
          : undefined,
        mpp_stripe_secret_key: slice.stripe_secret_key || '',
        mpp_crypto_verification_mode: slice.crypto_verification_mode || 'passthrough',
        mpp_min_confirmations: slice.min_confirmations ?? 0,
        mpp_verification_timeout_ms: slice.verification_timeout_ms ?? 10000,
        mpp_rpc_endpoints:
          slice.rpc_endpoints && typeof slice.rpc_endpoints === 'object'
            ? JSON.stringify(slice.rpc_endpoints, null, 2)
            : '',
      };
    }
    return { enabled: false };
  },
};
