import {
  STORED_TARGET_AUTH_KEY,
  StoredTargetAuth,
  TP_CALLER_CHECK_PROBLEM,
  isStoredTargetAuth,
  mergedTargetAuth,
  parseScopes,
  providerTargetAuthToApi,
  targetAuthFieldProblems,
} from '../_shared/providerTargetAuth';
import { authenticatesCallers } from './callerAuth';

function text(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function editedTargetAuth(c: any): Record<string, unknown> | undefined {
  const type = c.auth_type;
  if (!type || type === 'none') return undefined;
  if (type === 'credential_provider') {
    return providerTargetAuthToApi({
      providerId: typeof c.auth_provider_id === 'string' ? c.auth_provider_id : '',
      headerName: typeof c.auth_header_name === 'string' ? c.auth_header_name : '',
      headerFormat: typeof c.auth_header_format === 'string' ? c.auth_header_format : '',
      fallback: c.auth_fallback,
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
      headerFormat = text(c.auth_header_format) || 'Bearer {value}';
      break;
    case 'api_key':
      headerName = text(c.auth_header_name) || 'X-API-Key';
      headerFormat = text(c.auth_header_format) || '{value}';
      break;
    case 'custom_header':
      headerName = text(c.auth_header_name) || 'X-Auth';
      headerFormat = text(c.auth_header_format) || '{value}';
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
 * sends the stored one unchanged; an edited one is laid over the stored one, so a field the
 * panel does not show survives. `undefined` when none is set.
 */
export function transitPointTargetAuth(c: any): Record<string, unknown> | undefined {
  const stored: StoredTargetAuth | undefined = c?.[STORED_TARGET_AUTH_KEY];
  if (!c?.auth_type) return stored?.auth ?? undefined;
  return mergedTargetAuth(stored, editedTargetAuth(c));
}

export interface TransitPointTargetAuthProblems {
  errors: Record<string, string>;
  warnings: string[];
}

/**
 * What is wrong with the Transit Point's Target authentication. A setting the gateway keeps as
 * stored (same auth, same endpoint) only warns; a new or changed one blocks the save.
 */
export function transitPointTargetAuthProblems(c: any): TransitPointTargetAuthProblems {
  const result: TransitPointTargetAuthProblems = { errors: {}, warnings: [] };
  const auth = transitPointTargetAuth(c);
  if (!auth) return result;
  const endpoint = typeof c.target_endpoint === 'string' ? c.target_endpoint : '';
  const problems = targetAuthFieldProblems(auth, endpoint);
  const found: Array<[string, string | undefined]> = [
    ['auth_header_name', problems.headerName],
    ['auth_header_format', problems.headerFormat],
    ['auth_https', problems.endpoint],
    ['auth_callers', authenticatesCallers(c) ? undefined : TP_CALLER_CHECK_PROBLEM],
  ];
  const kept = isStoredTargetAuth(c[STORED_TARGET_AUTH_KEY], auth, endpoint);
  for (const [field, message] of found) {
    if (!message) continue;
    if (kept) result.warnings.push(message);
    else result.errors[field] = message;
  }
  return result;
}
