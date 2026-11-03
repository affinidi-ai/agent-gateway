/**
 * Target authentication from a credential provider: the `credential_provider` method of
 * the gateway's `TargetAuthConfig`, shared by the Managed Agent and Transit Points.
 */

/** Provider types that issue a token without a user: the ones target auth can use. */
export const TARGET_AUTH_PROVIDER_TYPES = [
  'oauth2_client_credentials',
  'oauth2_jwt_bearer',
  'oauth2_client_credentials_jwt_auth',
  'api_key',
];

export const PROVIDER_TARGET_AUTH_DEFAULTS = {
  headerName: 'Authorization',
  headerFormat: 'Bearer {value}',
};

export interface ProviderTargetAuth {
  providerId: string;
  headerName: string;
  headerFormat: string;
  fallback: 'reject' | 'passthrough';
  scopes?: string[];
}

/** Splits a space-separated scopes input into scopes. */
export function parseScopes(input: unknown): string[] {
  return typeof input === 'string' ? input.split(/\s+/).filter(Boolean) : [];
}

export function isTargetAuthProviderType(providerType: unknown): boolean {
  return typeof providerType === 'string' && TARGET_AUTH_PROVIDER_TYPES.includes(providerType);
}

/** The wire `target_auth` of a provider method, or undefined when no provider is picked. */
export function providerTargetAuthToApi(auth: ProviderTargetAuth) {
  const providerId = auth.providerId.trim();
  if (!providerId) return undefined;
  return {
    method: {
      credential_provider: {
        provider_id: providerId,
        header_name: auth.headerName.trim() || PROVIDER_TARGET_AUTH_DEFAULTS.headerName,
        header_format: auth.headerFormat.trim() || PROVIDER_TARGET_AUTH_DEFAULTS.headerFormat,
        ...(auth.scopes ? { scopes: auth.scopes } : {}),
      },
    },
    fallback: auth.fallback === 'passthrough' ? 'passthrough' : 'reject',
  };
}

/** The provider method of a stored `target_auth`, or null for any other method. */
export function providerTargetAuthFromApi(targetAuth: unknown): ProviderTargetAuth | null {
  if (!targetAuth || typeof targetAuth !== 'object') return null;
  const { method, fallback } = targetAuth as { method?: unknown; fallback?: unknown };
  const provider =
    method && typeof method === 'object'
      ? (method as { credential_provider?: Record<string, unknown> }).credential_provider
      : undefined;
  if (!provider || typeof provider.provider_id !== 'string') return null;
  return {
    providerId: provider.provider_id,
    headerName:
      typeof provider.header_name === 'string'
        ? provider.header_name
        : PROVIDER_TARGET_AUTH_DEFAULTS.headerName,
    headerFormat:
      typeof provider.header_format === 'string'
        ? provider.header_format
        : PROVIDER_TARGET_AUTH_DEFAULTS.headerFormat,
    fallback: fallback === 'passthrough' ? 'passthrough' : 'reject',
    scopes: Array.isArray(provider.scopes)
      ? provider.scopes.filter((scope): scope is string => typeof scope === 'string')
      : [],
  };
}

/** What a surface stored for a Target authentication, kept to save it unchanged. */
export const STORED_TARGET_AUTH_KEY = '_stored_target_auth';

export interface StoredTargetAuth {
  endpoint: string;
  auth: Record<string, unknown> | null;
}

export function storedTargetAuth(endpoint: unknown, auth: unknown): StoredTargetAuth {
  return {
    endpoint: typeof endpoint === 'string' ? endpoint : '',
    auth: auth && typeof auth === 'object' ? (auth as Record<string, unknown>) : null,
  };
}

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/**
 * The edited Target authentication laid over the stored one, so a field the editor does not
 * show (`target_identifier`, an unknown key) survives the save. A method of another kind than
 * the stored one replaces it; empty scopes are left out, which clears stored ones.
 */
export function mergeTargetAuth(
  stored: Record<string, unknown> | null | undefined,
  edited: Record<string, unknown>
): Record<string, unknown> {
  const storedMethod = record(stored?.method);
  const editedMethod = record(edited.method);
  if (!stored || !storedMethod || !editedMethod) return withoutEmptyScopes(edited);
  const kind = Object.keys(editedMethod)[0];
  const storedInner = record(storedMethod[kind]);
  const editedInner = record(editedMethod[kind]);
  const method =
    storedInner && editedInner ? { [kind]: { ...storedInner, ...editedInner } } : editedMethod;
  return withoutEmptyScopes({ ...stored, ...edited, method });
}

function withoutEmptyScopes(auth: Record<string, unknown>): Record<string, unknown> {
  const method = record(auth.method);
  const provider = record(method?.credential_provider);
  if (!method || !provider || !Array.isArray(provider.scopes) || provider.scopes.length > 0) {
    return auth;
  }
  const { scopes: _empty, ...rest } = provider;
  void _empty;
  return { ...auth, method: { ...method, credential_provider: rest } };
}

/** The edited auth merged onto the stored one; `undefined` when the edit has no auth. */
export function mergedTargetAuth(
  stored: StoredTargetAuth | undefined,
  edited: Record<string, unknown> | undefined
): Record<string, unknown> | undefined {
  return edited ? mergeTargetAuth(stored?.auth, edited) : undefined;
}

export interface TargetAuthFieldProblems {
  headerName?: string;
  headerFormat?: string;
  endpoint?: string;
}

export const RESERVED_HEADERS = [
  'Host',
  'Content-Length',
  'Transfer-Encoding',
  'Connection',
  'Keep-Alive',
  'Proxy-Connection',
  'Proxy-Authorization',
  'Proxy-Authenticate',
  'TE',
  'Upgrade',
  'Trailer',
  'Trailers',
  'X-Transit-Token',
  'X-Gateway-Fabric-Hops',
  'X-Caller-Did',
  'X-Caller-Identity-Source',
  'X-Caller-Dna-Uai',
  'X-Gateway-Did',
  'X-Did-Identity',
  'X-Did-Signed-Identity',
  'X-Gateway-Trace-Id',
  'X-Mirrored-Request',
  'Mcp-Session-Id',
];

export const TARGET_AUTH_HTTPS_PROBLEM =
  'Target authentication sends a credential, so its Target must be an https URL';
export const MA_CALLER_CHECK_PROBLEM =
  'Target authentication sends a credential, so it needs source authentication on the Access Point';
export const TP_CALLER_CHECK_PROBLEM =
  'Target authentication sends a credential, so it needs a Transit Point that authenticates its callers';

export function headerNameProblem(name: string): string | null {
  if (!name || !/^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/.test(name)) {
    return 'Header name must be an HTTP header name';
  }
  const reserved = RESERVED_HEADERS.find(r => r.toLowerCase() === name.toLowerCase());
  return reserved ? `Header name must not be the reserved header ${reserved}` : null;
}

export function headerFormatProblem(format: string): string | null {
  if (/[\r\n\0]/.test(format)) return 'Header format must not contain CR, LF or NUL';
  return format.split('{value}').length - 1 === 1
    ? null
    : 'Header format must contain {value} exactly once';
}

/** An `https://` URL with a host: `fabric://`, `a2a-proxy://`, `proxy://` and `http://` are not. */
export function isHttpsTarget(endpoint: string): boolean {
  try {
    const url = new URL(endpoint.trim());
    return url.protocol === 'https:' && url.hostname !== '';
  } catch {
    return false;
  }
}

/** The header name and format a wire `target_auth` sends, or null when it sends none. */
export function targetAuthHeader(
  auth: unknown
): { headerName: string; headerFormat: string } | null {
  const method = record(record(auth)?.method);
  const inner = record(method?.static_secret) ?? record(method?.credential_provider);
  if (!inner) return null;
  return {
    headerName: typeof inner.header_name === 'string' ? inner.header_name : '',
    headerFormat: typeof inner.header_format === 'string' ? inner.header_format : '',
  };
}

/**
 * The rules a Target authentication meets on its own: the header it sets, its value format and
 * an https Target. A setting equal to the stored one, on the same endpoint, is not refused by
 * the gateway, so it is reported only as a warning.
 */
export function targetAuthFieldProblems(auth: unknown, endpoint: string): TargetAuthFieldProblems {
  const header = targetAuthHeader(auth);
  if (!header) return {};
  return {
    headerName: headerNameProblem(header.headerName) ?? undefined,
    headerFormat: headerFormatProblem(header.headerFormat) ?? undefined,
    endpoint: isHttpsTarget(endpoint) ? undefined : TARGET_AUTH_HTTPS_PROBLEM,
  };
}

/** Whether the gateway keeps this setting as stored: same Target endpoint and same auth. */
export function isStoredTargetAuth(
  stored: StoredTargetAuth | undefined,
  auth: unknown,
  endpoint: string
): boolean {
  return (
    !!stored?.auth &&
    stored.endpoint === endpoint &&
    JSON.stringify(sortKeys(stored.auth)) === JSON.stringify(sortKeys(auth))
  );
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  const object = record(value);
  if (!object) return value;
  return Object.fromEntries(
    Object.keys(object)
      .sort()
      .map(key => [key, sortKeys(object[key])])
  );
}
