import * as Cap from '../capabilities';
import type { NodeDefinition, PayloadSlice } from '../types';
import CallerAuthPanel from './CallerAuthPanel';
import CallerAuthFullscreen from './CallerAuthFullscreen';
import { DOCS_URL } from '../../../../config/docs';
import {
  discoveryProblems,
  protectedResourcePayload,
  readProtectedResource,
  resourceMissesRoute,
} from './protectedResource';
import {
  allMethodConfigs,
  buildMethod,
  methodConfigFromPayload,
  methodIncompleteReason,
  methodSelectionProblems,
  readAdditionalMethods,
} from './methods';

const usesDiscovery = (c: Record<string, unknown>): boolean =>
  c.method_type === 'jwt_bearer' && readProtectedResource(c.protected_resource) !== null;

/**
 * Caller Context Extraction — promotes the AP-side `caller_authentication`
 * sub-editor to a first-class canvas element so it shows up next to the
 * Access Point and is countable in the surface summary.
 *
 * Writes `access_point.caller_authentication.methods`: the element's own
 * config is the first method and `additional_methods` the rest, in order.
 * The gateway verifies each request with the first method whose credential
 * it carries, so each method reads its own credential location.
 */
export const callerAuthDefinition: NodeDefinition = {
  type: 'caller-auth',
  label: 'Caller Context',
  description:
    'Extracts caller authentication context from inbound callers (JWT, API key, DID Auth, mTLS)',
  icon: '\uf084', // fa-key
  paletteIcon: 'fa-key',
  color: '#1cc88a',
  shape: 'circle',
  defaultRadius: 14,
  resizable: true,
  resizeRange: { min: 16, max: 36 },
  draggable: true,
  containedInSurface: false,
  edgeConstrained: false,
  xWeight: 0.15,
  stage: 'middleware',
  cardinality: 'singleton',
  paletteCategory: 'policy',
  paletteOrder: 0,
  dropMode: 'edge',
  directionality: 'request',
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: {
    dropOnEdge: [Cap.PIPELINE_SOURCE],
  },
  help: {
    title: 'Caller Context',
    docLink: DOCS_URL.callerContextElement,
    bodyHtml: `
      <p>Extracts caller authentication context from inbound call <em>before</em> any policy or
      payment gate runs. Drops on the caller → access-point arrow.
      Singleton: one element per Surface, holding one or more methods.</p>
      <p>With several methods, each caller uses the one its credential
      belongs to: the gateway verifies a request with the first method, in
      the configured order, whose credential the request carries, and never
      retries a rejected credential with another method. Each method must
      read its own header (or the client certificate). Policy sees which
      method verified the caller as <code>input.source_auth.method</code>.</p>
      <p>Without this element every caller is treated as anonymous. The
      element does not refuse a request on its own: a missing or invalid
      credential reaches policy as <code>source_auth.method == "failed"</code>.
      Add a policy that denies unverified callers to require credentials.</p>
      <p><strong>Methods:</strong></p>
      <ul>
        <li><strong>JWT bearer</strong>: verify a signed JWT against a
        configured verification strategy (issuer, JWKS / public key,
        audience, claims). Pick the strategy from the dashboard's JWT
        verification strategy list.</li>
        <li><strong>API key</strong>: compare against a stored secret
        (Vault / config); fast, no network round-trip.</li>
        <li><strong>API key provider</strong>: delegate verification to
        a remote agent (the &ldquo;provider&rdquo;) addressed by agent id.</li>
        <li><strong>DID Auth</strong>: verify a DID-based credential
        presented by the caller.</li>
        <li><strong>mTLS</strong>: trust the TLS-terminated client
        certificate; no extra payload header required. (Currently disabled
        for new configuration.)</li>
      </ul>
      <p><strong>Extraction</strong> picks where the credential lives
      (HTTP header or protocol-specific field) and which name to read.
      Defaults to <code>Authorization</code> header for JWT bearer.</p>
      <p>JWT bearer authentication can optionally forward the validated token
      header unchanged to the directly managed target.</p>
      <p>On an MCP surface, JWT bearer authentication can also publish
      <strong>authorization server discovery</strong>: protected resource
      metadata naming the authorization servers, so an MCP client finds where
      to get a token for this resource.</p>
    `,
  },
  incompleteReason: c => {
    const primary = methodIncompleteReason(c);
    if (primary) return primary;
    const extras = readAdditionalMethods(c);
    for (const [position, extra] of extras.entries()) {
      const reason = methodIncompleteReason(extra);
      if (reason) return `Method ${position + 2}: ${reason}`;
    }
    return null;
  },
  validate: c => [...discoveryProblems(c ?? {}), ...methodSelectionProblems(c)],
  featureDependencies: [
    {
      description: 'Authorization server discovery requires an MCP Access Point',
      condition: c => usesDiscovery(c ?? {}),
      check: (_c, ctx) => ctx.protocol === 'mcp',
      severity: 'error',
      message: 'Authorization server discovery requires an MCP Access Point',
    },
    {
      description: 'The discovery resource path is the Access Point route',
      condition: c => usesDiscovery(c ?? {}),
      check: (c, ctx) =>
        !resourceMissesRoute(
          readProtectedResource(c?.protected_resource)?.resource ?? '',
          ctx.accessPoint?.route
        ),
      severity: 'error',
      message: "The discovery resource URL's path must be the Access Point route exactly",
    },
  ],
  ConfigPanel: CallerAuthPanel,
  FullscreenPanel: CallerAuthFullscreen,
  payloadPath: 'access_point.caller_authentication',
  defaultConfig: () => ({
    method_type: 'jwt_bearer',
    extraction_source: 'http_header',
    extraction_field: 'Authorization',
    jwt_token_header: 'Authorization',
    jwt_token_scheme: 'Bearer',
    jwt_forward_header: false,
  }),
  summary: c => {
    const methods = allMethodConfigs(c);
    return methods.length > 0
      ? methods.map(m => String(m.method_type).replace(/_/g, ' ')).join(' + ')
      : null;
  },
  buildPayload: ctx => {
    const node = ctx.firstNodeOfType('caller-auth');
    if (!node) return undefined;
    const c = node.config ?? {};
    if (!c.method_type) return undefined;

    const methods = allMethodConfigs(c).map(m => buildMethod(m, ctx.surfaceMeta.surface_id));
    if (methods.some(m => m === undefined)) return undefined;

    const discovery =
      c.method_type === 'jwt_bearer' ? readProtectedResource(c.protected_resource) : null;
    const slices: PayloadSlice[] = [
      {
        path: 'access_point.caller_authentication',
        value: {
          methods,
          ...(discovery ? { protected_resource: protectedResourcePayload(discovery) } : {}),
        },
      },
    ];
    return slices;
  },
  /**
   * Reverse the wire shape into the flat panel fields: the first method on
   * the element itself, the rest as `additional_methods`.
   * `protected_resource` is always set, to `null` when the payload has none,
   * so a stale copy in the canvas blob never brings back a removed setting.
   */
  configFromPayload: slice => {
    const [first, ...rest] = Array.isArray(slice?.methods) ? slice.methods : [];
    if (!first) return slice ?? {};
    return {
      ...methodConfigFromPayload(first),
      protected_resource:
        first.type === 'jwt_bearer' ? readProtectedResource(slice.protected_resource) : null,
      additional_methods: rest.map(methodConfigFromPayload),
    };
  },
};
