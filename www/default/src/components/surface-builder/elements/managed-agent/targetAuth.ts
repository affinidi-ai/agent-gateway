import {
  STORED_TARGET_AUTH_KEY,
  StoredTargetAuth,
  isStoredTargetAuth,
  mergedTargetAuth,
  parseScopes,
  providerTargetAuthToApi,
  targetAuthFieldProblems,
} from '../_shared/providerTargetAuth';

export function inferAuthType(headerName: string, headerFormat: string): string {
  if (headerFormat.startsWith('Bearer ')) return 'bearer';
  if (headerFormat.startsWith('Basic ')) return 'basic';
  return headerName === 'X-API-Key' ? 'api_key' : 'custom';
}

/**
 * The Managed Agent's wire `target.auth`: the edited fields laid over the stored one, so a field
 * the editor does not show survives. `undefined` when none is set.
 */
export function managedAgentTargetAuth(c: any): Record<string, unknown> | undefined {
  if (!c?.target_auth_enabled) return undefined;
  const stored: StoredTargetAuth | undefined = c[STORED_TARGET_AUTH_KEY];
  let edited: Record<string, unknown> | undefined;
  if (c.target_auth_source === 'provider') {
    edited = providerTargetAuthToApi({
      providerId: c.target_auth_provider_id || '',
      headerName: c.target_auth_header_name || '',
      headerFormat: c.target_auth_header_format || '',
      fallback: c.target_auth_fallback,
      scopes: parseScopes(c.target_auth_scopes),
    });
  } else if (c.target_auth_secret_id) {
    edited = {
      method: {
        static_secret: {
          secret_id: c.target_auth_secret_id,
          header_name: c.target_auth_header_name || 'Authorization',
          header_format: c.target_auth_header_format || '{value}',
        },
      },
      fallback: c.target_auth_fallback || 'reject',
    };
  }
  if (!edited) return undefined;
  const type = c.target_auth_type || 'bearer';
  const method = edited.method as Record<string, Record<string, string>>;
  const inner = method.static_secret ?? method.credential_provider;
  const unchanged = inferAuthType(inner.header_name, inner.header_format) === type;
  if (stored?.auth?.auth_type === undefined && stored?.auth && unchanged) {
    return mergedTargetAuth(stored, edited);
  }
  return mergedTargetAuth(stored, { ...edited, auth_type: type });
}

export interface TargetAuthProblems {
  errors: Record<string, string>;
  warnings: string[];
  advisories: string[];
}

/**
 * What is wrong with the Managed Agent's Target authentication. A header name or format
 * problem in a new or changed setting blocks the save; the same problem in a setting the
 * gateway keeps as stored (same auth, same endpoint) only warns. A Target that is not https
 * is an advisory: the gateway refuses it only while `target_https` is `enforce`.
 */
export function managedAgentTargetAuthProblems(c: any): TargetAuthProblems {
  const result: TargetAuthProblems = { errors: {}, warnings: [], advisories: [] };
  if (!c?.target_auth_enabled) return result;
  if (c.target_auth_source === 'provider' && !String(c.target_auth_provider_id || '').trim()) {
    result.errors.target_auth_provider_id =
      'Pick the credential provider whose token authenticates this Managed Agent';
    return result;
  }
  const endpoint = typeof c.endpoint === 'string' ? c.endpoint : '';
  const auth = managedAgentTargetAuth(c);
  const problems = targetAuthFieldProblems(auth, endpoint);
  const found: Array<[string, string | undefined]> = [
    ['target_auth_header_name', problems.headerName],
    ['target_auth_header_format', problems.headerFormat],
  ];
  if (problems.endpoint) result.advisories.push(problems.endpoint);
  const kept = isStoredTargetAuth(c[STORED_TARGET_AUTH_KEY], auth, endpoint);
  for (const [field, message] of found) {
    if (!message) continue;
    if (kept) result.warnings.push(message);
    else result.errors[field] = message;
  }
  return result;
}
