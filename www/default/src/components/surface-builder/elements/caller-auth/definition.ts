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
  buildMethod,
  defaultMethodConfig,
  firstMethodWithDiscovery,
  methodConfigFromPayload,
  methodIncompleteReason,
  methodSelectionProblems,
  readMethods,
} from './methods';

const usesDiscovery = (c: Record<string, unknown>): boolean =>
  readMethods(c)[0]?.method_type === 'jwt_bearer' &&
  readProtectedResource(c.protected_resource) !== null;

const isOnFailure = (v: unknown): v is 'reject' | 'continue' => v === 'reject' || v === 'continue';

/**
 * Caller Context Extraction — promotes the AP-side `caller_authentication`
 * sub-editor to a first-class canvas element so it shows up next to the
 * Access Point and is countable in the surface summary.
 *
 * Writes `access_point.caller_authentication.methods` from the element's
 * `methods`, in order, and `protected_resource` with the first method. The
 * gateway verifies each request with the method whose credential it carries,
 * so each method reads its own credential location, and a request carrying
 * credentials for several methods fails source authentication.
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
      belongs to. The first, primary, method checks a request that carries
      no credential, and a request carrying credentials for more than one
      method fails source authentication; a rejected credential is never retried with another
      method. Each method must read its own header (or the client
      certificate). Policy sees which method verified the caller as
      <code>input.source_auth.method</code>.</p>
      <p>A closed Access Point (<strong>Public access</strong> off) is not
      ready for external access until it has this element, or on an MCP
      surface an authorization resource (<code>mcp_http.authorization</code>):
      until then it answers every caller with <code>503</code>, and the
      Access Point shows "Not ready for external access". It turns on as
      soon as a save adds one. A ready closed Access Point refuses a caller
      whose credential is missing or invalid with <code>401</code>. A public
      Access Point, or a surface without the Public access setting, forwards
      such callers to policy as <code>source_auth.method == "failed"</code>;
      add a policy that denies unverified callers to require credentials
      there.</p>
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
    const methods = readMethods(c);
    if (methods.length === 0) return 'Authentication method must be selected';
    for (const [position, method] of methods.entries()) {
      const reason = methodIncompleteReason(method);
      if (reason) return methods.length > 1 ? `Method ${position + 1}: ${reason}` : reason;
    }
    return null;
  },
  validate: c => [
    ...discoveryProblems(firstMethodWithDiscovery(c) as Record<string, unknown>),
    ...methodSelectionProblems(c),
  ],
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
  defaultConfig: () => ({ methods: [defaultMethodConfig('jwt_bearer')] }),
  summary: c => {
    const methods = readMethods(c);
    return methods.length > 0
      ? methods.map(m => String(m.method_type).replace(/_/g, ' ')).join(' + ')
      : null;
  },
  buildPayload: ctx => {
    const node = ctx.firstNodeOfType('caller-auth');
    if (!node) return undefined;
    const c = node.config ?? {};
    const configured = readMethods(c);
    if (configured.length === 0) return undefined;

    const methods = configured.map(m => buildMethod(m, ctx.surfaceMeta.surface_id));
    if (methods.some(m => m === undefined)) return undefined;

    const discovery =
      configured[0].method_type === 'jwt_bearer'
        ? readProtectedResource(c.protected_resource)
        : null;
    const slices: PayloadSlice[] = [
      {
        path: 'access_point.caller_authentication',
        value: {
          methods,
          ...(discovery ? { protected_resource: protectedResourcePayload(discovery) } : {}),
          ...(isOnFailure(c.on_failure) ? { on_failure: c.on_failure } : {}),
        },
      },
    ];
    return slices;
  },
  /**
   * Reverse the wire shape into the panel's `methods`, each in the flat
   * method shape. `protected_resource` is always set, to `null` when the
   * payload has none, so a stale copy in the canvas blob never brings back a
   * removed setting.
   */
  configFromPayload: slice => {
    const stored = Array.isArray(slice?.methods) ? slice.methods : [];
    if (stored.length === 0) return slice ?? {};
    return {
      methods: stored.map(methodConfigFromPayload),
      protected_resource:
        stored[0].type === 'jwt_bearer' ? readProtectedResource(slice.protected_resource) : null,
      on_failure: isOnFailure(slice.on_failure) ? slice.on_failure : undefined,
    };
  },
};
