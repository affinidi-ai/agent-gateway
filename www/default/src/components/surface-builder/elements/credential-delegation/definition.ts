import * as Cap from '../capabilities';
import type { NodeDefinition, PayloadSlice } from '../types';
import type { CanvasNode } from '../../SurfaceCanvas';
import {
  outboundCredentialApiToForm,
  outboundCredentialFormToApi,
  type OutboundCredentialFormRow,
} from '../_shared/OutboundCredentialsListSection';
import CredentialDelegationPanel from './CredentialDelegationPanel';
import CredentialDelegationFullscreenPanel from './CredentialDelegationFullscreenPanel';
import { DOCS_URL } from '../../../../config/docs';

/**
 * Credential Delegation — drops on the Managed Agent → External arrow.
 *
 * Owns the `outbound_credentials` (surface root) slice — the list of
 * outbound credential bindings injected when the MA forwards a request
 * upstream. Workload Binding is a separate, Transit-Point-scoped element
 * (`workload-binding`) and is no longer configured here.
 *
 * Requires that the surface has source authentication (caller-auth) AND
 * an agent identity (any configured identity element) — without those the
 * gateway cannot bind tokens. The panel surfaces the missing-feature
 * warnings via `featureDependencies`.
 */
export const credentialDelegationDefinition: NodeDefinition = {
  type: 'credential-delegation',
  label: 'Credential Delegation',
  description: 'Inject outbound credentials for upstream calls.',
  icon: '\uf2c2', // fa-id-card
  paletteIcon: 'fa-id-card',
  color: '#f6c23e',
  shape: 'circle',
  defaultRadius: 14,
  resizable: true,
  resizeRange: { min: 16, max: 36 },
  draggable: true,
  containedInSurface: false,
  edgeConstrained: false,
  xWeight: 0.75,
  stage: 'middleware',
  cardinality: 'singleton',
  paletteCategory: 'enhancement',
  paletteOrder: 5,
  dropMode: 'edge',
  directionality: 'request',
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: { dropOnEdge: [Cap.CREDENTIAL_TARGET] },
  help: {
    title: 'Credential Delegation',
    docLink: DOCS_URL.outboundBindingElements,
    bodyHtml: `
      <p>Configure how the Managed Agent forwards credentials upstream.
      Drops on the Managed Agent → External arrow.</p>
      <p><strong>Outbound Credential Delegation</strong>: bind one or
      more credential providers (OAuth Authorization Code, OAuth Client
      Credentials, static API Key). On each outbound request the gateway
      injects a cached token, or signals <code>consent_required</code>
      back to the caller when no token is available.</p>
      <p><strong>Requirements:</strong> Source authentication and an
      agent identity must be configured on the surface, since credential
      delegation binds tokens to an authenticated user and a managed
      agent workload.</p>
    `,
  },
  incompleteReason: c => {
    const rows = Array.isArray(c?.outbound_credentials_form)
      ? (c.outbound_credentials_form as OutboundCredentialFormRow[])
      : [];
    if (rows.length === 0) {
      return 'Add at least one outbound credential binding';
    }
    for (const r of rows) {
      if (!r.credential_provider_id) {
        return 'Select a credential provider for every outbound binding';
      }
      if (r.inject_as_type === 'custom_header' && !(r.inject_as_custom_name ?? '').trim()) {
        return 'Set the custom header name on every outbound binding that uses one';
      }
      if (r.inject_as_type === 'meta' && !(r.inject_as_meta_field ?? '').trim()) {
        return 'Set the meta field name on every outbound binding that uses one';
      }
    }
    return null;
  },
  defaultConfig: () => ({
    outbound_credentials_form: [],
  }),
  ConfigPanel: CredentialDelegationPanel,
  FullscreenPanel: CredentialDelegationFullscreenPanel,
  summary: c => {
    const rows = Array.isArray(c?.outbound_credentials_form)
      ? (c.outbound_credentials_form as OutboundCredentialFormRow[])
      : [];
    const bits: string[] = [];
    if (rows.length > 0) bits.push(`${rows.length} binding${rows.length === 1 ? '' : 's'}`);
    return bits.length > 0 ? bits.join(' · ') : null;
  },
  featureDependencies: [
    {
      description: 'Credential delegation requires source authentication',
      condition: c => {
        const rows = Array.isArray(c?.outbound_credentials_form)
          ? (c.outbound_credentials_form as OutboundCredentialFormRow[])
          : [];
        return rows.length > 0;
      },
      check: (_c, ctx) => surfaceHasSourceAuth(ctx.allNodes),
      severity: 'error',
      message:
        'Source Authentication required. Add a Caller Context element with a configured method: credential delegation needs authenticated callers to bind tokens to a user identity.',
    },
    {
      description: 'Credential delegation requires an agent identity',
      condition: c => {
        const rows = Array.isArray(c?.outbound_credentials_form)
          ? (c.outbound_credentials_form as OutboundCredentialFormRow[])
          : [];
        return rows.length > 0;
      },
      check: (_c, ctx) => surfaceHasAgentIdentity(ctx.allNodes),
      severity: 'error',
      message:
        'Agent Identity required. Add a configured Identity element so the gateway can bind tokens to a specific agent workload.',
    },
  ],
  /**
   * Hydrate from a saved payload. The slot walker passes the
   * `outbound_credentials` array as `slice`.
   */
  configFromPayload: slice => {
    const rows: OutboundCredentialFormRow[] = Array.isArray(slice)
      ? (slice as any[])
          .map(outboundCredentialApiToForm)
          .filter((r): r is OutboundCredentialFormRow => r !== null)
      : [];
    return { outbound_credentials_form: rows };
  },
  buildPayload: ctx => {
    const node = ctx.firstNodeOfType('credential-delegation');
    if (!node) return undefined;
    const c = node.config ?? {};
    const slices: PayloadSlice[] = [];
    const rows = Array.isArray(c.outbound_credentials_form)
      ? (c.outbound_credentials_form as OutboundCredentialFormRow[])
      : [];
    if (rows.length > 0) {
      const apiBindings = rows.map(outboundCredentialFormToApi).filter((b: any) => b !== undefined);
      if (apiBindings.length > 0) {
        slices.push({ path: 'outbound_credentials', value: apiBindings });
      }
    }
    return slices.length > 0 ? slices : undefined;
  },
};

/**
 * True when the surface has a Caller Context element with a configured
 * authentication method. Mirrors the channel-editor `hasSourceAuth`
 * check.
 */
export function surfaceHasSourceAuth(nodes: CanvasNode[]): boolean {
  return nodes.some(n => n.type === 'caller-auth' && !!n.config?.method_type);
}

/**
 * True when the surface has a managed agent identity the gateway can
 * use to sign delegated tokens / workload-binding VPs. Mirrors the
 * channel-editor `hasManagedIdentity` check (`!!formData.managed_identity`)
 * but adapted to the surface model where the agent's DID lives on the
 * Managed Agent (`didwebvh_enabled`) and per-edge identity slots
 * (`identity_slots.*` / `transit.points[*].managed_identity`) carry the
 * runtime identity object.
 *
 * Any one of the following satisfies the rule:
 *   - The Managed Agent has DID:webvh enabled (`config.didwebvh_enabled`),
 *     or MCP identity extraction enabled (`config.mcp_identity_enabled`).
 *   - At least one Identity element is configured with a non-empty
 *     `type` (covers protected / external / per-TP managed-identity
 *     slots — they all emit `identity` nodes).
 */
export function surfaceHasAgentIdentity(nodes: CanvasNode[]): boolean {
  if (
    nodes.some(
      n => n.type === 'target' && (!!n.config?.didwebvh_enabled || !!n.config?.mcp_identity_enabled)
    )
  ) {
    return true;
  }
  return nodes.some(n => n.type === 'identity' && !!n.config?.type);
}
