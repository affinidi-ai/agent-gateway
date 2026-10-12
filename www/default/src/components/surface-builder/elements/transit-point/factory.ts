import * as Cap from '../capabilities';
import { registry } from '../registry';
import { networkingConfigToWire } from '../networking/definition';
import { rateLimitConfigToWire } from '../rate-limit/definition';
import type { NodeDefinition, Protocol } from '../types';
import type { SurfaceNodeType } from '../nodeTypes';
import { urlError } from '../validators';
import TransitPointPanel from './TransitPointPanel';
import { transitCredentialsFormToApi } from '../_shared/TransitCredentialBindingSection';
import { identityConfigToWire } from '../identity/definition';
import { workloadBindingFormToApi } from '../workload-binding/config';
import { getCachedOutboundListenAddresses } from '../access-point/defaults';
import { headerMetadataMappingToWire } from '../metadata-extraction/definition';
import { mcpToolGatingConfigToWire } from '../mcp-tool-gating/definition';
import { DOCS_URL } from '../../../../config/docs';

/**
 * Pattern that a transit point alias MUST match. Mirrors the backend
 * `TransitPoint::ALIAS_PATTERN` so derived values the UI sends are
 * always accepted by the API.
 */
export const TRANSIT_POINT_ALIAS_PATTERN = /^[a-z][a-z0-9-]{0,62}$/;

/**
 * Slugify a free-form name into a backend-valid alias, or return null
 * if the input contains nothing usable. Used to auto-derive the alias
 * from the TP's friendly `name` so users never have to type it.
 */
export function slugifyAlias(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  const slug = input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 63)
    .replace(/^[^a-z]+/, '');
  return slug.length > 0 && TRANSIT_POINT_ALIAS_PATTERN.test(slug) ? slug : null;
}

/**
 * Derive a guaranteed-valid alias from a TP's name and stable id.
 * Falls back to a short id-prefix when the name slugifies to nothing
 * (or is empty), so the backend always receives a non-empty alias.
 */
export function deriveTransitPointAlias(name: unknown, id: unknown): string {
  const fromName = slugifyAlias(name);
  if (fromName) return fromName;
  const idStr = typeof id === 'string' ? id.replace(/[^a-z0-9]/gi, '').toLowerCase() : '';
  const suffix = idStr.slice(0, 8) || Math.random().toString(36).slice(2, 10);
  return `tp-${suffix}`;
}

/**
 * Generate a stable UUID for a brand-new transit point. Uses
 * `crypto.randomUUID` when available (all evergreen browsers + Node
 * 19+) and falls back to a v4-shaped hex string built from
 * `Math.random` for the rare environments without it (older Jest
 * jsdom). The fallback is good enough for IDs that the backend will
 * either accept verbatim or replace with its own UUID on save.
 */
export function newTransitPointId(): string {
  const c: any = typeof crypto !== 'undefined' ? crypto : undefined;
  if (c && typeof c.randomUUID === 'function') return c.randomUUID();
  const hex = (n: number) =>
    Math.floor(Math.random() * Math.pow(16, n))
      .toString(16)
      .padStart(n, '0');
  return `${hex(8)}-${hex(4)}-4${hex(3)}-${(8 + Math.floor(Math.random() * 4)).toString(16)}${hex(3)}-${hex(12)}`;
}

interface TransitPointVariantOpts {
  type: SurfaceNodeType;
  protocol: Protocol;
  /** Suffix for label, e.g. "A2A". */
  label: string;
  /** Color for the node body. */
  color: string;
  /** Palette ordering — lower numbers appear first. */
  paletteOrder: number;
  /**
   * The single registered TP definition that owns the cross-cutting
   * `transit.points[]` payload aggregation. Other variants set this to
   * false so we don't get duplicate (or only-last-wins) `transit` slices
   * from `deepMergePath`.
   */
  isPayloadCoordinator?: boolean;
  /**
   * Hide this variant's creation entry from the palette while keeping
   * full display/edit support for nodes of this type already on a
   * surface (e.g. an experimental protocol that's no longer offered
   * for new drops). See `NodeDefinition.hiddenFromPalette`.
   */
  hiddenFromPalette?: boolean;
}

/**
 * Factory for the per-protocol Transit Point definitions. Every variant
 * shares the same panel, capabilities, validation, and cross-cutting
 * payload aggregation — only the type id, label, color, palette order,
 * and bound protocol differ.
 */
export function makeTransitPointDefinition(opts: TransitPointVariantOpts): NodeDefinition {
  const { type, protocol, label, color, paletteOrder, isPayloadCoordinator, hiddenFromPalette } =
    opts;
  return {
    type,
    label: `Transit Point (${label})`,
    description: `Outbound ${label} transit (gateway-to-gateway or external)`,
    icon: '\uf074', // fa-shuffle (matches paletteIcon)
    paletteIcon: 'fa-shuffle',
    color,
    shape: 'circle',
    defaultRadius: 26,
    resizable: true,
    resizeRange: { min: 18, max: 40 },
    draggable: true,
    containedInSurface: false,
    edgeConstrained: true,
    xWeight: 0.85,
    stage: 'egress',
    cardinality: 'multi',
    paletteCategory: 'transitPoints',
    paletteOrder,
    dropMode: 'canvas',
    isTransitPoint: true,
    ...(hiddenFromPalette ? { hiddenFromPalette: true } : {}),
    getProtocol: () => protocol,
    help: {
      title: `Transit Point (${label})`,
      docLink: DOCS_URL.transitPoints,
      bodyHtml: `
      <p>An <strong>outbound</strong> route the Managed Agent can call
      out through: a controlled, observable, policy-gated path to an
      external destination instead of opening raw connections. Drop one
      Transit Point per outbound destination; the canvas can hold
      many.</p>
      <p>This variant speaks <strong>${label}</strong>. Each Transit
      Point is its own mini-pipeline. You can drop Policy, Payment,
      Networking, Rate Limit, Metadata Extraction (A2A / AP2 header
      mapping only) or Trust Registry checks on its edges, and they
      apply just to that route rather than the main Target.</p>
      <p><strong>Routing target:</strong></p>
      <ul>
        <li><strong>External URL</strong>: the route calls a regular
        HTTPS / agent endpoint.</li>
        <li><strong>Gateway-to-gateway</strong>: chain through another
        Agent Gateway over the Fabric.</li>
      </ul>
      <p><strong>Per-route settings</strong> (set on the node itself):</p>
      <ul>
        <li><strong>Name</strong>: friendly label, also used as the
        routing key and in metrics.</li>
        <li><strong>Target authentication</strong>: credentials
        presented to the destination.</li>
        <li><strong>Transit credentials</strong>: user-consented
        credential injection (OAuth-style) per provider.</li>
        <li><strong>Require transit token</strong>: demand a signed
        transit token from the caller before routing through this
        route.</li>
        <li><strong>Listen address / path</strong>: choose the outbound
        listener for this route.</li>
      </ul>
    `,
    },
    provides: [
      Cap.EGRESS_CAPABLE,
      Cap.SURFACE_PERIMETER,
      Cap.MIDDLEWARE_SLOT,
      Cap.POLICY_TARGET,
      Cap.PAYMENT_TARGET,
      Cap.NETWORKING_TARGET,
      Cap.CREDENTIAL_TARGET,
      ...(protocol === 'a2a' || protocol === 'ap2' ? [Cap.METADATA_TARGET] : []),
      Cap.RATE_LIMIT_TARGET,
      Cap.TRUST_REGISTRY_TARGET,
      Cap.EXTENSION_TARGET,
      Cap.IDENTITY_TARGET,
      Cap.WORKLOAD_BINDING_TARGET,
      Cap.NPC_CONNECTABLE,
      Cap.CONFIGURABLE,
      Cap.ATTACHES_TO_EGRESS,
    ],
    requires: {},
    incompleteReason: config => {
      if (!config.listen_address) return 'Outbound listener address is required';
      if (!config.target_endpoint) return 'Target endpoint is required';
      return null;
    },
    validate: c => {
      const errs: Array<{ field?: string; message: string }> = [];
      const e = urlError('target_endpoint', c.target_endpoint, 'Target endpoint');
      if (e) errs.push(e);
      return errs;
    },
    // A transit point's listen address must be an actual outbound listener
    // URL, not just any non-empty string — a stale/inbound address resolves
    // to no outbound listener at runtime, so the TP silently registers no
    // route. These run live on every canvas render (unlike the snapshot
    // `configured` flag), so they fault the node as soon as the routing
    // config cache is warm. When the cache has not loaded yet the rules
    // don't apply, avoiding a false positive.
    featureDependencies: [
      {
        description: 'Transit point listen address must be a configured outbound listener',
        condition: c => {
          const outbound = getCachedOutboundListenAddresses();
          const listen = typeof c.listen_address === 'string' ? c.listen_address.trim() : '';
          return outbound !== null && outbound.length > 0 && listen.length > 0;
        },
        check: c => {
          const outbound = getCachedOutboundListenAddresses() ?? [];
          const listen = typeof c.listen_address === 'string' ? c.listen_address.trim() : '';
          return outbound.includes(listen);
        },
        severity: 'error',
        message:
          'Listen address is not a configured outbound listener. Pick one from the dropdown.',
      },
      {
        description: 'Transit point requires at least one configured outbound listener',
        condition: c => {
          const outbound = getCachedOutboundListenAddresses();
          const listen = typeof c.listen_address === 'string' ? c.listen_address.trim() : '';
          return outbound !== null && outbound.length === 0 && listen.length > 0;
        },
        check: () => false,
        severity: 'error',
        message:
          'No outbound listener is configured. Add an outbound listener before using a transit point.',
      },
      {
        description: 'OAuth Client Credentials auth is not yet wired through the proxy runtime',
        condition: c => c?.auth_type === 'oauth_client_credentials',
        check: () => false,
        severity: 'error',
        message:
          'OAuth Client Credentials is not yet supported. The selection will be dropped on save. Pick Bearer, API Key, or Custom Header.',
      },
    ],
    ConfigPanel: TransitPointPanel,
    summary: c =>
      c?.target_endpoint
        ? `${c.name || c.alias || 'unnamed'} → ${c.target_endpoint} (${protocol})`
        : null,
    getListViewInfo: c => ({
      name: c?.name || c?.alias || undefined,
      extras: [c?.target_endpoint || '—', protocol],
    }),
    buildPayload: !isPayloadCoordinator
      ? undefined
      : ctx => {
          // Coordinator-only: aggregate every transit-point variant into a
          // single `transit.points[]` slice. Querying via the registry
          // helper keeps protocol additions zero-cost here.
          const tpTypes = registry.transitPointTypes();
          const transitNodes = ctx.allNodes.filter(n =>
            tpTypes.includes(n.type as SurfaceNodeType)
          );
          if (transitNodes.length === 0) return undefined;
          const transit: any = {
            sign_requests: true,
            transit_token_mode: 'embedded',
            points: (() => {
              // Pre-derive aliases with collision dedupe so the backend's
              // per-surface uniqueness check never rejects auto-generated
              // values from two TPs sharing a name.
              const taken = new Set<string>();
              const aliasFor = (c: any): string => {
                const explicit =
                  typeof c.alias === 'string' && TRANSIT_POINT_ALIAS_PATTERN.test(c.alias.trim())
                    ? c.alias.trim()
                    : null;
                let candidate = explicit ?? deriveTransitPointAlias(c.name, c.id);
                if (!taken.has(candidate)) {
                  taken.add(candidate);
                  return candidate;
                }
                for (let i = 2; i < 1000; i++) {
                  const trimmed = candidate.slice(0, 63 - String(i).length - 1);
                  const next = `${trimmed}-${i}`;
                  if (!taken.has(next)) {
                    taken.add(next);
                    return next;
                  }
                }
                taken.add(candidate);
                return candidate;
              };
              return transitNodes.map(tp => {
                const c = tp.config ?? {};
                const tpProtocol = registry.getProtocolForType(tp.type) ?? protocol;
                // Per-TP policies live as separate canvas nodes parented
                // to this TP. The TP factory owns the entire
                // `transit.points[]` slice so it folds them in here
                // (rather than the policy element trying to write into
                // an array index).
                const policyNodes = ctx.allNodes.filter(
                  n => n.type === 'policy' && n.parentId === tp.id
                );
                const reqPolicy = policyNodes.find(p => (p.direction ?? 'request') === 'request');
                const respPolicy = policyNodes.find(p => p.direction === 'response');
                const reqPolicyId = reqPolicy?.config?.policy_definition_id;
                const respPolicyId = respPolicy?.config?.policy_definition_id;
                // Per-TP networking: same per-TP-node ownership pattern as policy.
                // The networking element's own buildPayload skips TP-parented
                // nodes so we have the only writer here.
                const networkingNode = ctx.allNodes.find(
                  n => n.type === 'networking' && n.parentId === tp.id
                );
                const networking = networkingConfigToWire(networkingNode?.config);
                // Per-TP rate limit: same per-TP-node ownership pattern as networking.
                // The rate-limit element's own buildPayload skips TP-parented
                // nodes so we have the only writer here.
                const rateLimitNode = ctx.allNodes.find(
                  n => n.type === 'rate-limit' && n.parentId === tp.id
                );
                const rateLimit = rateLimitConfigToWire(rateLimitNode?.config);
                // Per-TP managed identity (MA→TP request slot): the identity
                // element parents to this TP and the TP factory owns the
                // `managed_identity` slice. The identity element's own
                // buildPayload skips TP-parented nodes.
                const identityNode = ctx.allNodes.find(
                  n => n.type === 'identity' && n.parentId === tp.id
                );
                const managedIdentity = identityConfigToWire(identityNode?.config);
                // Per-TP workload binding (MA→TP request slot): the
                // workload-binding element parents to this TP and the TP
                // factory owns the `workload_binding` slice. The element
                // has no buildPayload of its own.
                const workloadBindingNode = ctx.allNodes.find(
                  n => n.type === 'workload-binding' && n.parentId === tp.id
                );
                const workloadBinding = workloadBindingFormToApi(workloadBindingNode?.config);
                // Per-TP MCP tool gating (MA→TP response slot): the gating
                // element parents to this TP and the TP factory owns the
                // `mcp_tool_gating` slice. The element's own buildPayload
                // skips TP-parented nodes so this is the only writer.
                const mcpToolGatingNode = ctx.allNodes.find(
                  n => n.type === 'mcp-tool-gating' && n.parentId === tp.id
                );
                const mcpToolGating = mcpToolGatingConfigToWire(mcpToolGatingNode?.config);
                const credentials = transitCredentialsFormToApi(c.transit_credentials);
                const headerMetadataNode = ctx.allNodes.find(
                  n => n.type === 'metadata-extraction' && n.parentId === tp.id
                );
                const headerMetadataMapping =
                  tpProtocol === 'a2a' || tpProtocol === 'ap2'
                    ? headerMetadataMappingToWire(
                        headerMetadataNode?.config?.header_metadata_mapping
                      )
                    : undefined;
                const listenAddress =
                  typeof c.listen_address === 'string' && c.listen_address.trim().length > 0
                    ? c.listen_address.trim()
                    : undefined;
                const listenPath =
                  typeof c.listen_path === 'string' && c.listen_path.trim().length > 0
                    ? c.listen_path.trim()
                    : undefined;
                // Per-TP agent card location override. Only A2A/AP2 destinations
                // serve an agent card, so the override is meaningless (and
                // dropped) for other protocols. Independent of the access
                // point's own override — a TP and its AP can resolve cards
                // from different locations.
                const agentCardPath =
                  (tpProtocol === 'a2a' || tpProtocol === 'ap2') &&
                  typeof c.agent_card_path === 'string' &&
                  c.agent_card_path.trim().length > 0
                    ? c.agent_card_path.trim()
                    : undefined;
                return {
                  id: c.id || newTransitPointId(),
                  alias: aliasFor(c),
                  ...(c.name ? { name: c.name } : {}),
                  target_endpoint: c.target_endpoint || '',
                  protocol: tpProtocol,
                  ...(listenAddress ? { listen_address: listenAddress } : {}),
                  ...(listenPath ? { listen_path: listenPath } : {}),
                  ...(agentCardPath ? { agent_card_path: agentCardPath } : {}),
                  ...(headerMetadataMapping
                    ? { header_metadata_mapping: headerMetadataMapping }
                    : {}),
                  require_transit_token: c.require_transit_token !== false,
                  ...(typeof c.target_endpoint === 'string' &&
                  c.target_endpoint.startsWith('fabric://') &&
                  c.fabric_delegated_credentials === true
                    ? { fabric_delegated_credentials: true }
                    : {}),
                  ...(() => {
                    // Project the panel's auth_* fields onto the
                    // backend `TargetAuthConfig` shape (externally-tagged
                    // method enum). Empty / "none" auth is omitted so
                    // the surface JSON stays clean. Today only
                    // `static_secret` is wired through; the panel maps
                    // its bearer / api_key / custom_header presets onto
                    // header_name + header_format pairs that the proxy
                    // injects verbatim.
                    const t = c.auth_type;
                    if (!t || t === 'none') return {};
                    const secretId = typeof c.auth_secret === 'string' ? c.auth_secret.trim() : '';
                    if (!secretId) return {};
                    let headerName: string;
                    let headerFormat: string;
                    switch (t) {
                      case 'bearer':
                        headerName = 'Authorization';
                        headerFormat =
                          (typeof c.auth_header_format === 'string' &&
                            c.auth_header_format.trim()) ||
                          'Bearer {value}';
                        break;
                      case 'api_key':
                        headerName =
                          (typeof c.auth_header_name === 'string' && c.auth_header_name.trim()) ||
                          'X-API-Key';
                        headerFormat =
                          (typeof c.auth_header_format === 'string' &&
                            c.auth_header_format.trim()) ||
                          '{value}';
                        break;
                      case 'custom_header':
                        headerName =
                          (typeof c.auth_header_name === 'string' && c.auth_header_name.trim()) ||
                          'X-Auth';
                        headerFormat =
                          (typeof c.auth_header_format === 'string' &&
                            c.auth_header_format.trim()) ||
                          '{value}';
                        break;
                      default:
                        // Methods the runtime cannot inject yet (e.g.
                        // oauth_client_credentials) are dropped here
                        // rather than emitting an invalid wire shape.
                        return {};
                    }
                    return {
                      target_auth: {
                        method: {
                          static_secret: {
                            secret_id: secretId,
                            header_name: headerName,
                            header_format: headerFormat,
                          },
                        },
                        fallback: c.auth_fallback === 'passthrough' ? 'passthrough' : 'reject',
                      },
                    };
                  })(),
                  ...(reqPolicyId
                    ? {
                        policy: {
                          policy_definition_id: reqPolicyId,
                          ...(reqPolicy?.config?.require_agent_context
                            ? { require_agent_context: true }
                            : {}),
                        },
                      }
                    : {}),
                  ...(respPolicyId
                    ? {
                        response_policy: {
                          policy_definition_id: respPolicyId,
                        },
                      }
                    : {}),
                  ...(networking ? { networking } : {}),
                  ...(rateLimit ? { rate_limit: rateLimit } : {}),
                  ...(managedIdentity ? { managed_identity: managedIdentity } : {}),
                  ...(workloadBinding ? { workload_binding: workloadBinding } : {}),
                  ...(mcpToolGating ? { mcp_tool_gating: mcpToolGating } : {}),
                  ...(credentials ? { transit_credentials: credentials } : {}),
                };
              });
            })(),
          };
          return [{ path: 'transit', value: transit }];
        },
  };
}
