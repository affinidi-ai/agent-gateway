import * as Cap from '../capabilities';
import type { NodeDefinition, PayloadSlice } from '../types';
import CallerAuthPanel from './CallerAuthPanel';
import CallerAuthFullscreen from './CallerAuthFullscreen';
import { DOCS_URL } from '../../../../config/docs';

/**
 * Caller Context Extraction — promotes the AP-side `caller_authentication`
 * sub-editor to a first-class canvas element so it shows up next to the
 * Access Point and is countable in the surface summary.
 *
 * Writes to `access_point.caller_authentication.methods[0]`. The Vec
 * exists in the type but the runtime currently consumes only the first
 * entry; the panel exposes only one method to mirror that.
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
      Singleton: one auth method per Surface.</p>
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
    `,
  },
  incompleteReason: c => {
    if (!c.method_type) return 'Authentication method must be selected';
    if (c.method_type === 'jwt_bearer' && !c.jwt_strategy_id)
      return 'JWT strategy must be selected';
    if (c.method_type === 'api_key' && !c.api_key_secret_id)
      return 'API key secret must be selected';
    if (c.method_type === 'mtls' && !c.mtls_certificate_id)
      return 'mTLS certificate must be selected';
    return null;
  },
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
  summary: c => (c?.method_type ? c.method_type.replace(/_/g, ' ') : null),
  buildPayload: ctx => {
    const node = ctx.firstNodeOfType('caller-auth');
    if (!node) return undefined;
    const c = node.config ?? {};
    if (!c.method_type) return undefined;

    const extraction = {
      source: c.extraction_source || 'http_header',
      ...(c.extraction_source === 'http_header'
        ? { field: c.extraction_field || 'Authorization' }
        : {}),
    };

    let method: any = null;
    switch (c.method_type) {
      case 'jwt_bearer':
        if (!c.jwt_strategy_id) return undefined;
        method = {
          type: 'jwt_bearer',
          jwt_verification_strategy_id: c.jwt_strategy_id,
          audiences: Array.isArray(c.audiences) ? c.audiences : [],
          token_header: (c.jwt_token_header ?? 'Authorization').trim() || 'Authorization',
          token_scheme: (c.jwt_token_scheme ?? 'Bearer').trim(),
          forward_header: c.jwt_forward_header === true,
        };
        break;
      case 'api_key':
        if (!c.api_key_secret_id) return undefined;
        method = {
          type: 'api_key',
          extraction,
          secret_id: c.api_key_secret_id,
        };
        break;
      case 'api_key_provider': {
        const agentId = ctx.surfaceMeta.surface_id;
        if (!agentId) return undefined;
        method = {
          type: 'api_key_provider',
          extraction,
          agent_id: agentId,
        };
        break;
      }
      case 'did_auth':
        method = {
          type: 'did_auth',
          extraction,
        };
        break;
      case 'mtls':
        if (!c.mtls_certificate_id) return undefined;
        method = {
          type: 'mtls',
          trust: {
            type: 'pinned',
            certificate_ids: [c.mtls_certificate_id],
          },
          identity_binding: { type: 'fingerprint' },
          allowed_subjects: [],
          allow_forwarded: true,
        };
        break;
      default:
        return undefined;
    }

    const slices: PayloadSlice[] = [
      {
        path: 'access_point.caller_authentication',
        value: { methods: [method] },
      },
    ];
    return slices;
  },
  /**
   * Reverse the wire shape into the flat panel fields. The runtime
   * always reads only the first method, so we only hydrate methods[0].
   */
  configFromPayload: slice => {
    const m = slice?.methods?.[0];
    if (!m) return slice ?? {};
    const out: any = { method_type: m.type };
    if (m.extraction) {
      out.extraction_source = m.extraction.source;
      if (m.extraction.field) out.extraction_field = m.extraction.field;
    }
    if (m.type === 'jwt_bearer') {
      if (m.jwt_verification_strategy_id) out.jwt_strategy_id = m.jwt_verification_strategy_id;
      else if (m.strategy_id) out.jwt_strategy_id = m.strategy_id; // legacy
      if (Array.isArray(m.audiences)) out.audiences = m.audiences;
      out.jwt_token_header = m.token_header ?? 'Authorization';
      out.jwt_token_scheme = m.token_scheme ?? 'Bearer';
      out.jwt_forward_header = m.forward_header === true;
    }
    if (m.type === 'api_key' && m.secret_id) out.api_key_secret_id = m.secret_id;
    if (m.type === 'mtls') {
      // New shape: pinned trust carrying certificate_ids[0].
      const ids = m.trust?.type === 'pinned' ? m.trust.certificate_ids : undefined;
      if (Array.isArray(ids) && ids.length > 0) out.mtls_certificate_id = ids[0];
      // Legacy shape compatibility ({type:'mtls',certificate_id}).
      else if (m.certificate_id) out.mtls_certificate_id = m.certificate_id;
    }
    return out;
  },
};
