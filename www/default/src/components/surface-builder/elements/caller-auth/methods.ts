import type { CallerAuthMethodType } from './methodOptions';
import { readProtectedResource } from './protectedResource';

/** The gateway's refusal of a JWT Bearer method after the first beside discovery. */
export const LATER_JWT_BEARER_BESIDE_DISCOVERY =
  'Authorization server discovery allows JWT Bearer only as the first caller authentication method: the discovery audience and challenge belong to that method';

/**
 * One caller authentication method in the caller-auth element's flat panel
 * shape (`method_type`, `jwt_strategy_id`, `extraction_field`, …).
 */
export interface CallerAuthMethodConfig {
  method_type?: CallerAuthMethodType;
  jwt_strategy_id?: string;
  audiences?: string[];
  jwt_token_header?: string;
  jwt_token_scheme?: string;
  jwt_forward_header?: boolean;
  extraction_source?: 'http_header' | 'mcp_meta' | 'a2a_extension';
  extraction_field?: string;
  api_key_secret_id?: string;
  mtls_certificate_id?: string;
  protected_resource?: unknown;
}

/**
 * The caller-auth element's config: its methods, the first being the primary
 * method, which checks a request carrying no credential, and the
 * authorization server discovery setting, which belongs to the primary. A
 * request carrying credentials for several methods fails source
 * authentication. An older canvas
 * stored the first method's fields on the element itself and the rest as
 * `additional_methods`; {@link readMethods} still reads that shape.
 */
export interface CallerAuthConfig extends CallerAuthMethodConfig {
  methods?: CallerAuthMethodConfig[];
  additional_methods?: CallerAuthMethodConfig[];
}

export function readMethods(config: CallerAuthConfig | undefined): CallerAuthMethodConfig[] {
  if (Array.isArray(config?.methods)) return config.methods;
  if (!config?.method_type) return [];
  const {
    methods: _methods,
    additional_methods,
    protected_resource: _discovery,
    ...first
  } = config;
  return [first, ...(Array.isArray(additional_methods) ? additional_methods : [])];
}

/** Whether authorization server discovery is on, which needs a JWT Bearer first method. */
export function discoveryIsOn(config: CallerAuthConfig | undefined): boolean {
  return (
    readMethods(config)[0]?.method_type === 'jwt_bearer' &&
    readProtectedResource(config?.protected_resource) !== null
  );
}

/** The first method with the discovery setting, as the discovery rules read it. */
export function firstMethodWithDiscovery(
  config: CallerAuthConfig | undefined
): CallerAuthMethodConfig {
  return { ...readMethods(config)[0], protected_resource: config?.protected_resource };
}

export const CALLER_AUTH_METHOD_SHORT_LABEL: Record<CallerAuthMethodType, string> = {
  jwt_bearer: 'JWT',
  api_key: 'API Key',
  api_key_provider: 'API Key provider',
  did_auth: 'DID Auth',
  mtls: 'mTLS',
};

export function defaultMethodConfig(
  type: CallerAuthMethodType,
  current: CallerAuthMethodConfig = {}
): CallerAuthMethodConfig {
  switch (type) {
    case 'jwt_bearer':
      return {
        method_type: 'jwt_bearer',
        jwt_strategy_id: current.jwt_strategy_id || '',
        audiences: Array.isArray(current.audiences) ? current.audiences : [],
        jwt_token_header: current.jwt_token_header || 'Authorization',
        jwt_token_scheme: current.jwt_token_scheme ?? 'Bearer',
        jwt_forward_header: current.jwt_forward_header === true,
      };
    case 'api_key':
    case 'api_key_provider':
      return {
        method_type: type,
        extraction_source: current.extraction_source || 'http_header',
        extraction_field: current.extraction_field || 'X-API-Key',
      };
    case 'did_auth':
      return {
        method_type: 'did_auth',
        extraction_source: current.extraction_source || 'http_header',
        extraction_field: current.extraction_field || 'X-Session-Token',
      };
    case 'mtls':
      return { method_type: 'mtls', mtls_certificate_id: current.mtls_certificate_id || '' };
  }
}

export function methodIncompleteReason(method: CallerAuthMethodConfig): string | null {
  if (!method.method_type) return 'Authentication method must be selected';
  if (method.method_type === 'jwt_bearer' && !method.jwt_strategy_id)
    return 'JWT strategy must be selected';
  if (method.method_type === 'api_key' && !method.api_key_secret_id)
    return 'API key secret must be selected';
  if (method.method_type === 'mtls' && !method.mtls_certificate_id)
    return 'mTLS certificate must be selected';
  return null;
}

/**
 * Where a method reads the caller's credential. The gateway selects the
 * method by the credential a request carries, so each method needs its own.
 */
export function credentialLocation(method: CallerAuthMethodConfig): string {
  if (method.method_type === 'mtls') return 'the client certificate';
  if (method.method_type === 'jwt_bearer') {
    return `the '${((method.jwt_token_header ?? 'Authorization').trim() || 'Authorization').toLowerCase()}' header`;
  }
  if (method.extraction_source === 'mcp_meta') return 'MCP _meta';
  if (method.extraction_source === 'a2a_extension') return 'the A2A message extension';
  return `the '${(method.extraction_field || 'Authorization').trim().toLowerCase()}' header`;
}

const readsRequestBody = (method: CallerAuthMethodConfig) =>
  method.method_type !== 'jwt_bearer' &&
  method.method_type !== 'mtls' &&
  (method.extraction_source === 'mcp_meta' || method.extraction_source === 'a2a_extension');

/**
 * Why the method at `position` cannot be saved beside the others, or `null`:
 * the gateway selects a method by the credential a request carries, so each
 * method reads its own location and only a sole method reads the body.
 */
export function methodConflict(
  methods: CallerAuthMethodConfig[],
  position: number,
  discoveryOn = false
): string | null {
  const method = methods[position];
  if (discoveryOn && position > 0 && method.method_type === 'jwt_bearer') {
    return LATER_JWT_BEARER_BESIDE_DISCOVERY;
  }
  const location = credentialLocation(method);
  if (methods.length > 1 && readsRequestBody(method)) {
    return `Method ${position + 1} reads ${location}; with more than one method, each must read a header or the client certificate`;
  }
  const earlier = methods
    .slice(0, position)
    .findIndex(other => credentialLocation(other) === location);
  if (earlier >= 0) {
    return `Methods ${earlier + 1} and ${position + 1} both read ${location}; each method needs its own credential location`;
  }
  if (
    method.method_type === 'did_auth' &&
    methods.slice(0, position).some(other => other.method_type === 'did_auth')
  ) {
    return 'At most one DID Auth method';
  }
  return null;
}

/** The first problem of the method at `position`: incomplete, or in conflict. */
export function methodProblem(
  methods: CallerAuthMethodConfig[],
  position: number,
  discoveryOn = false
): string | null {
  return (
    methodIncompleteReason(methods[position]) ?? methodConflict(methods, position, discoveryOn)
  );
}

export function methodSelectionProblems(config: CallerAuthConfig | undefined) {
  const methods = readMethods(config);
  const discoveryOn = discoveryIsOn(config);
  return methods
    .map((_, position) => methodConflict(methods, position, discoveryOn))
    .filter((message): message is string => message !== null)
    .map(message => ({ field: 'methods', message }));
}

/** The runtime `SourceAuthConfig` for one method, or `undefined` while incomplete. */
export function buildMethod(c: CallerAuthMethodConfig, surfaceId: string | undefined): any {
  const extraction = {
    source: c.extraction_source || 'http_header',
    ...(c.extraction_source === 'http_header'
      ? { field: c.extraction_field || 'Authorization' }
      : {}),
  };
  switch (c.method_type) {
    case 'jwt_bearer':
      if (!c.jwt_strategy_id) return undefined;
      return {
        type: 'jwt_bearer',
        jwt_verification_strategy_id: c.jwt_strategy_id,
        audiences: Array.isArray(c.audiences) ? c.audiences : [],
        token_header: (c.jwt_token_header ?? 'Authorization').trim() || 'Authorization',
        token_scheme: (c.jwt_token_scheme ?? 'Bearer').trim(),
        forward_header: c.jwt_forward_header === true,
      };
    case 'api_key':
      if (!c.api_key_secret_id) return undefined;
      return { type: 'api_key', extraction, secret_id: c.api_key_secret_id };
    case 'api_key_provider':
      if (!surfaceId) return undefined;
      return { type: 'api_key_provider', extraction, agent_id: surfaceId };
    case 'did_auth':
      return { type: 'did_auth', extraction };
    case 'mtls':
      if (!c.mtls_certificate_id) return undefined;
      return {
        type: 'mtls',
        trust: { type: 'pinned', certificate_ids: [c.mtls_certificate_id] },
        identity_binding: { type: 'fingerprint' },
        allowed_subjects: [],
        allow_forwarded: true,
      };
    default:
      return undefined;
  }
}

/** The flat panel fields for one runtime `SourceAuthConfig`. */
export function methodConfigFromPayload(m: any): CallerAuthMethodConfig {
  const out: CallerAuthMethodConfig = { method_type: m.type };
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
}
