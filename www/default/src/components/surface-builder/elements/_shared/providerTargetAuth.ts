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

/**
 * A header name or format without the spaces and tabs typed around it. A line break or NUL
 * stays, so the header rules report one that a stored setting has.
 */
export function trimSpaces(value: string): string {
  return value.replace(/^[ \t]+|[ \t]+$/g, '');
}

/** A stored header name or format as the form holds it: `fallback` only when none is stored. */
export function storedHeaderValue(value: unknown, fallback: string): string {
  return typeof value === 'string' ? value : fallback;
}

/**
 * What a save sends for a header field the form holds blank: `fallback`, or the blank the stored
 * setting already had, so the header rules report it and no save replaces it unseen.
 */
export function blankHeaderValue(storedValue: unknown, fallback: string): string {
  return typeof storedValue === 'string' && !trimSpaces(storedValue) ? storedValue : fallback;
}

/**
 * The wire `target_auth` of a provider method, or undefined when no provider is picked.
 * `storedMethod` is the stored setting's method, whose blank header name or format is kept.
 */
export function providerTargetAuthToApi(
  auth: ProviderTargetAuth,
  storedMethod?: Record<string, unknown> | null
) {
  const providerId = auth.providerId.trim();
  if (!providerId) return undefined;
  return {
    method: {
      credential_provider: {
        provider_id: providerId,
        header_name:
          trimSpaces(auth.headerName) ||
          blankHeaderValue(storedMethod?.header_name, PROVIDER_TARGET_AUTH_DEFAULTS.headerName),
        header_format:
          trimSpaces(auth.headerFormat) ||
          blankHeaderValue(storedMethod?.header_format, PROVIDER_TARGET_AUTH_DEFAULTS.headerFormat),
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
    headerName: storedHeaderValue(provider.header_name, PROVIDER_TARGET_AUTH_DEFAULTS.headerName),
    headerFormat: storedHeaderValue(
      provider.header_format,
      PROVIDER_TARGET_AUTH_DEFAULTS.headerFormat
    ),
    fallback: fallback === 'passthrough' ? 'passthrough' : 'reject',
    scopes: Array.isArray(provider.scopes)
      ? provider.scopes.filter((scope): scope is string => typeof scope === 'string')
      : [],
  };
}

/** What a surface stored for a Target authentication, kept to save it unchanged. */
export const STORED_TARGET_AUTH_KEY = '_stored_target_auth';

export interface StoredTargetAuth {
  auth: Record<string, unknown> | null;
}

export function storedTargetAuth(auth: unknown): StoredTargetAuth {
  return { auth: record(auth) };
}

export function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/** `object` without `key`. */
export function omitKey<T extends Record<string, unknown>>(
  object: T,
  key: string
): Record<string, unknown> {
  return Object.fromEntries(Object.entries(object).filter(([name]) => name !== key));
}

/** The method of a wire `target_auth` the editor can show, or null for any other method. */
export function knownTargetAuthMethod(auth: unknown): Record<string, unknown> | null {
  const { method } = record(auth) ?? {};
  if (method === 'static_secret') return record(auth);
  const tagged = record(method);
  return record(tagged?.static_secret) ?? record(tagged?.credential_provider);
}

const CREDENTIAL_ID_KEYS = ['secret_id', 'provider_id'];

/**
 * The edited Target authentication laid over the stored one, so a field the editor does not
 * show (`target_identifier`, an unknown key) survives the save. That holds only while the edit
 * keeps the stored credential: a method of another kind, another secret or another provider
 * replaces the stored setting, so nothing unseen follows a credential it was not set for. Empty
 * scopes are left out, which clears stored ones.
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
  const sameCredential =
    !!storedInner &&
    !!editedInner &&
    CREDENTIAL_ID_KEYS.every(key => storedInner[key] === editedInner[key]);
  if (!sameCredential) return withoutEmptyScopes(edited);
  const method = { [kind]: { ...storedInner, ...editedInner } };
  return withoutEmptyScopes({ ...stored, ...edited, method });
}

function withoutEmptyScopes(auth: Record<string, unknown>): Record<string, unknown> {
  const method = record(auth.method);
  const provider = record(method?.credential_provider);
  if (!method || !provider || !Array.isArray(provider.scopes) || provider.scopes.length > 0) {
    return auth;
  }
  return { ...auth, method: { ...method, credential_provider: omitKey(provider, 'scopes') } };
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

export const UNKNOWN_METHOD_NOTE =
  'This Target authentication uses a method the editor cannot show. It is kept as stored until you choose another';
export const PASSTHROUGH_NOTE =
  'The fallback passes a request through without the credential when the credential cannot be resolved';

/** Whether two header names are the same to the gateway: any letter case, `_` read as `-`. */
export function sameHeaderName(a: string, b: string): boolean {
  const fold = (name: string) => name.toLowerCase().replace(/_/g, '-');
  return fold(a) === fold(b);
}

export function headerNameProblem(name: string): string | null {
  if (!name || !/^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/.test(name)) {
    return 'Header name must be an HTTP header name';
  }
  const reserved = RESERVED_HEADERS.find(header => sameHeaderName(header, name));
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

/** The leg a Target authentication is on: the Managed Agent's Target, or a Transit Point's. */
export type TargetAuthLeg = 'managed-agent' | 'transit-point';

/**
 * Whether the gateway decides the https rule from something the editor cannot see: the Managed
 * Agent's `proxy://` Target meets it when its MCP proxy's `base_url` is https. A Transit Point's
 * target endpoint is checked as it is written.
 */
function httpsDecidedElsewhere(endpoint: string, leg: TargetAuthLeg): boolean {
  return leg === 'managed-agent' && endpoint.trim().toLowerCase().startsWith('proxy://');
}

/**
 * The rules a Target authentication meets on its own: the header it sets, its value format and
 * an https Target.
 */
export function targetAuthFieldProblems(
  auth: unknown,
  endpoint: string,
  leg: TargetAuthLeg
): TargetAuthFieldProblems {
  const header = targetAuthHeader(auth);
  if (!header) return {};
  const https = isHttpsTarget(endpoint) || httpsDecidedElsewhere(endpoint, leg);
  return {
    headerName: headerNameProblem(header.headerName) ?? undefined,
    headerFormat: headerFormatProblem(header.headerFormat) ?? undefined,
    endpoint: https ? undefined : TARGET_AUTH_HTTPS_PROBLEM,
  };
}

/** A wire value as JSON with its object keys in one order, so equal values compare equal. */
export function stableJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

export interface TargetAuthProblems {
  /** What blocks the save, by form field. */
  errors: Record<string, string>;
  /** Breaches of a rule the gateway refuses only while that rule is `enforce`. */
  advisories: string[];
  /** Advice with no gateway rule behind it. */
  notes: string[];
}

export const noTargetAuthProblems = (): TargetAuthProblems => ({
  errors: {},
  advisories: [],
  notes: [],
});

/**
 * Sorts what `targetAuthFieldProblems` finds for one leg. A header name or format problem blocks
 * the save, under the form field `fields` names, a stored one the operator did not edit
 * included: the gateway refuses it on every save. A Target that is not https is an advisory, and
 * a passthrough fallback is a note.
 */
export function classifyTargetAuthProblems(
  auth: Record<string, unknown>,
  endpoint: string,
  leg: TargetAuthLeg,
  fields: { headerName: string; headerFormat: string }
): TargetAuthProblems {
  const result = noTargetAuthProblems();
  const problems = targetAuthFieldProblems(auth, endpoint, leg);
  if (problems.endpoint) result.advisories.push(problems.endpoint);
  if (auth.fallback === 'passthrough') result.notes.push(PASSTHROUGH_NOTE);
  const found: Array<[string, string | undefined]> = [
    [fields.headerName, problems.headerName],
    [fields.headerFormat, problems.headerFormat],
  ];
  for (const [field, message] of found) {
    if (message) result.errors[field] = message;
  }
  return result;
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
