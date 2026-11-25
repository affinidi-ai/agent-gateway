import {
  STORED_TARGET_AUTH_KEY,
  StoredTargetAuth,
  TP_CALLER_CHECK_PROBLEM,
  TargetAuthProblems,
  UNKNOWN_METHOD_NOTE,
  blankHeaderValue,
  classifyTargetAuthProblems,
  knownTargetAuthMethod,
  mergedTargetAuth,
  noTargetAuthProblems,
  parseScopes,
  providerTargetAuthFromApi,
  providerTargetAuthToApi,
  record,
  storedHeaderValue,
  trimSpaces,
} from '../_shared/providerTargetAuth';
import { authenticatesCallers } from './callerAuth';

/** A Transit Point's Target authentication form, as its node config holds it. */
export interface TransitPointTargetAuthForm {
  target_endpoint?: unknown;
  auth_type?: unknown;
  auth_secret?: unknown;
  auth_provider_id?: unknown;
  auth_header_name?: unknown;
  auth_header_format?: unknown;
  auth_scopes?: unknown;
  auth_fallback?: unknown;
  [STORED_TARGET_AUTH_KEY]?: StoredTargetAuth;
  [key: string]: unknown;
}

type Form = TransitPointTargetAuthForm | null | undefined;

/** The form's keys, which come only from the stored surface and never from the canvas data. */
export const TRANSIT_POINT_TARGET_AUTH_FORM_KEYS: ReadonlyArray<keyof TransitPointTargetAuthForm> =
  [
    'auth_type',
    'auth_secret',
    'auth_provider_id',
    'auth_header_name',
    'auth_header_format',
    'auth_scopes',
    'auth_fallback',
  ];

function text(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function untrimmed(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

function header(value: unknown): string {
  return trimSpaces(untrimmed(value));
}

function editedTargetAuth(c: TransitPointTargetAuthForm): Record<string, unknown> | undefined {
  const type = c.auth_type;
  if (!type || type === 'none') return undefined;
  const storedMethod = knownTargetAuthMethod(c[STORED_TARGET_AUTH_KEY]?.auth);
  if (type === 'credential_provider') {
    return providerTargetAuthToApi(
      {
        providerId: untrimmed(c.auth_provider_id),
        headerName: untrimmed(c.auth_header_name),
        headerFormat: untrimmed(c.auth_header_format),
        fallback: c.auth_fallback === 'passthrough' ? 'passthrough' : 'reject',
        scopes: c.auth_scopes === undefined ? undefined : parseScopes(c.auth_scopes),
      },
      storedMethod
    );
  }
  const name = (fallback: string) =>
    header(c.auth_header_name) || blankHeaderValue(storedMethod?.header_name, fallback);
  const format = (fallback: string) =>
    header(c.auth_header_format) || blankHeaderValue(storedMethod?.header_format, fallback);
  const secretId = text(c.auth_secret);
  if (!secretId) return undefined;
  let headerName: string;
  let headerFormat: string;
  switch (type) {
    case 'bearer':
      headerName = 'Authorization';
      headerFormat = format('Bearer {value}');
      break;
    case 'api_key':
      headerName = name('X-API-Key');
      headerFormat = format('{value}');
      break;
    case 'custom_header':
      headerName = name('X-Auth');
      headerFormat = format('{value}');
      break;
    default:
      return undefined;
  }
  return {
    method: {
      static_secret: { secret_id: secretId, header_name: headerName, header_format: headerFormat },
    },
    fallback: c.auth_fallback === 'passthrough' ? 'passthrough' : 'reject',
  };
}

/** The panel's auth type for a stored static secret, so opening the panel keeps its header. */
export function staticSecretAuthType(
  headerName: string,
  headerFormat: string
): 'bearer' | 'api_key' | 'custom_header' {
  if (headerFormat.startsWith('Bearer ') && headerName === 'Authorization') {
    return 'bearer';
  }
  if (headerName === 'X-API-Key' || headerName.toLowerCase().includes('api-key')) {
    return 'api_key';
  }
  return 'custom_header';
}

/**
 * The auth form fields the panel shows for a stored `target_auth`, or null for a method it
 * cannot show. The panel writes them only with the operator's first edit.
 */
export function storedTransitPointAuthForm(targetAuth: unknown): Record<string, unknown> | null {
  const ta = record(targetAuth);
  if (!ta) return null;
  const provider = providerTargetAuthFromApi(ta);
  if (provider) {
    return {
      auth_type: 'credential_provider',
      auth_provider_id: provider.providerId,
      auth_header_name: provider.headerName,
      auth_header_format: provider.headerFormat,
      auth_fallback: provider.fallback,
      auth_scopes: (provider.scopes ?? []).join(' '),
    };
  }
  const ss =
    record(record(ta.method)?.static_secret) ?? (ta.method === 'static_secret' ? ta : null);
  if (!ss) return null;
  const headerName = storedHeaderValue(ss.header_name, 'Authorization');
  const headerFormat = storedHeaderValue(ss.header_format, '{value}');
  return {
    auth_type: staticSecretAuthType(headerName, headerFormat),
    auth_secret: ss.secret_id || '',
    auth_header_name: headerName,
    auth_header_format: headerFormat,
    auth_fallback: ta.fallback || 'reject',
  };
}

/**
 * The Transit Point's wire `target_auth`. A Transit Point whose auth form was never edited
 * sends the stored one unchanged, whatever its method; an edited one is laid over the stored
 * one, so a field the panel does not show survives. `undefined` when none is set.
 */
export function transitPointTargetAuth(c: Form): Record<string, unknown> | undefined {
  const stored = c?.[STORED_TARGET_AUTH_KEY];
  if (!c?.auth_type) return stored?.auth ?? undefined;
  return mergedTargetAuth(stored, editedTargetAuth(c));
}

/**
 * What is wrong with the Transit Point's Target authentication. A header name or format problem
 * blocks the save, in a stored setting too: the gateway refuses it on every save. A target
 * endpoint that is not https, `proxy://` included, or a Transit Point that authenticates no
 * caller, is an advisory: the gateway refuses it only while `target_https` or
 * `target_source_auth` is `enforce`.
 */
export function transitPointTargetAuthProblems(c: Form): TargetAuthProblems {
  const auth = transitPointTargetAuth(c);
  if (!c || !auth) return noTargetAuthProblems();
  const result = classifyTargetAuthProblems(auth, untrimmed(c.target_endpoint), 'transit-point', {
    headerName: 'auth_header_name',
    headerFormat: 'auth_header_format',
  });
  if (!authenticatesCallers(c)) result.advisories.push(TP_CALLER_CHECK_PROBLEM);
  if (!knownTargetAuthMethod(auth)) result.notes.push(UNKNOWN_METHOD_NOTE);
  return result;
}
