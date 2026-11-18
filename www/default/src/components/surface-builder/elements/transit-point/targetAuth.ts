import {
  STORED_TARGET_AUTH_KEY,
  StoredTargetAuth,
  TP_CALLER_CHECK_PROBLEM,
  TargetAuthProblems,
  UNKNOWN_METHOD_NOTE,
  classifyTargetAuthProblems,
  knownTargetAuthMethod,
  mergedTargetAuth,
  noTargetAuthProblems,
  parseScopes,
  providerTargetAuthToApi,
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
  if (type === 'credential_provider') {
    return providerTargetAuthToApi({
      providerId: untrimmed(c.auth_provider_id),
      headerName: untrimmed(c.auth_header_name),
      headerFormat: untrimmed(c.auth_header_format),
      fallback: c.auth_fallback === 'passthrough' ? 'passthrough' : 'reject',
      scopes: c.auth_scopes === undefined ? undefined : parseScopes(c.auth_scopes),
    });
  }
  const secretId = text(c.auth_secret);
  if (!secretId) return undefined;
  let headerName: string;
  let headerFormat: string;
  switch (type) {
    case 'bearer':
      headerName = 'Authorization';
      headerFormat = header(c.auth_header_format) || 'Bearer {value}';
      break;
    case 'api_key':
      headerName = header(c.auth_header_name) || 'X-API-Key';
      headerFormat = header(c.auth_header_format) || '{value}';
      break;
    case 'custom_header':
      headerName = header(c.auth_header_name) || 'X-Auth';
      headerFormat = header(c.auth_header_format) || '{value}';
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
 * The Transit Point's wire `target_auth`. A Transit Point whose auth form was never opened
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
