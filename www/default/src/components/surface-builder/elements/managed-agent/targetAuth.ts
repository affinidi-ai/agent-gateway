import {
  MA_CALLER_CHECK_PROBLEM,
  STORED_TARGET_AUTH_KEY,
  StoredTargetAuth,
  TargetAuthProblems,
  UNKNOWN_METHOD_NOTE,
  blankHeaderValue,
  classifyTargetAuthProblems,
  knownTargetAuthMethod,
  mergedTargetAuth,
  noTargetAuthProblems,
  parseScopes,
  providerTargetAuthToApi,
} from '../_shared/providerTargetAuth';

/** The Managed Agent's Target authentication form, as its node config holds it. */
export interface ManagedAgentTargetAuthForm {
  endpoint?: unknown;
  target_auth_enabled?: unknown;
  target_auth_source?: unknown;
  target_auth_secret_id?: unknown;
  target_auth_provider_id?: unknown;
  target_auth_header_name?: unknown;
  target_auth_header_format?: unknown;
  target_auth_scopes?: unknown;
  target_auth_fallback?: unknown;
  target_auth_type?: unknown;
  [STORED_TARGET_AUTH_KEY]?: StoredTargetAuth;
}

type Form = ManagedAgentTargetAuthForm | null | undefined;

/** The form's keys, which come only from the stored surface and never from the canvas data. */
export const MANAGED_AGENT_TARGET_AUTH_FORM_KEYS: ReadonlyArray<keyof ManagedAgentTargetAuthForm> =
  [
    'target_auth_enabled',
    'target_auth_source',
    'target_auth_secret_id',
    'target_auth_provider_id',
    'target_auth_header_name',
    'target_auth_header_format',
    'target_auth_scopes',
    'target_auth_fallback',
    'target_auth_type',
  ];

function text(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

export function inferAuthType(headerName: string, headerFormat: string): string {
  if (headerFormat.startsWith('Bearer ')) return 'bearer';
  if (headerFormat.startsWith('Basic ')) return 'basic';
  return headerName === 'X-API-Key' ? 'api_key' : 'custom';
}

function editedTargetAuth(c: ManagedAgentTargetAuthForm): Record<string, unknown> | undefined {
  const storedMethod = knownTargetAuthMethod(c[STORED_TARGET_AUTH_KEY]?.auth);
  if (c.target_auth_source === 'provider') {
    return providerTargetAuthToApi(
      {
        providerId: text(c.target_auth_provider_id),
        headerName: text(c.target_auth_header_name),
        headerFormat: text(c.target_auth_header_format),
        fallback: c.target_auth_fallback === 'passthrough' ? 'passthrough' : 'reject',
        scopes: parseScopes(c.target_auth_scopes),
      },
      storedMethod
    );
  }
  if (!c.target_auth_secret_id) return undefined;
  return {
    method: {
      static_secret: {
        secret_id: c.target_auth_secret_id,
        header_name:
          text(c.target_auth_header_name) ||
          blankHeaderValue(storedMethod?.header_name, 'Authorization'),
        header_format:
          text(c.target_auth_header_format) ||
          blankHeaderValue(storedMethod?.header_format, '{value}'),
      },
    },
    fallback: c.target_auth_fallback || 'reject',
  };
}

/**
 * The Managed Agent's wire `target.auth`: the edited fields laid over the stored one, so a field
 * the editor does not show survives. A stored method the editor cannot show is sent unchanged
 * until the operator chooses a secret or a provider. `undefined` when none is set.
 */
export function managedAgentTargetAuth(c: Form): Record<string, unknown> | undefined {
  if (!c?.target_auth_enabled) return undefined;
  const stored = c[STORED_TARGET_AUTH_KEY];
  const edited = editedTargetAuth(c);
  if (!edited) {
    return stored?.auth && !knownTargetAuthMethod(stored.auth) ? stored.auth : undefined;
  }
  const type = text(c.target_auth_type) || 'bearer';
  const method = edited.method as Record<string, Record<string, string>>;
  const inner = method.static_secret ?? method.credential_provider;
  const unchanged = inferAuthType(inner.header_name, inner.header_format) === type;
  if (stored?.auth?.auth_type === undefined && stored?.auth && unchanged) {
    return mergedTargetAuth(stored, edited);
  }
  return mergedTargetAuth(stored, { ...edited, auth_type: type });
}

export interface ManagedAgentSurroundings {
  /** Whether the Access Point checks its callers; leave out when that is not known. */
  accessPointChecksCallers?: boolean;
}

/**
 * What is wrong with the Managed Agent's Target authentication. A header name or format
 * problem blocks the save, in a stored setting too: the gateway refuses it on every save. A
 * Target that is not https, or an Access Point that checks no caller, is an advisory: the
 * gateway refuses it only while `target_https` or `target_source_auth` is `enforce`.
 */
export function managedAgentTargetAuthProblems(
  c: Form,
  { accessPointChecksCallers }: ManagedAgentSurroundings = {}
): TargetAuthProblems {
  if (!c?.target_auth_enabled) return noTargetAuthProblems();
  if (c.target_auth_source === 'provider' && !text(c.target_auth_provider_id).trim()) {
    return {
      ...noTargetAuthProblems(),
      errors: {
        target_auth_provider_id:
          'Pick the credential provider whose token authenticates this Managed Agent',
      },
    };
  }
  const auth = managedAgentTargetAuth(c);
  if (!auth) return noTargetAuthProblems();
  const result = classifyTargetAuthProblems(auth, text(c.endpoint), 'managed-agent', {
    headerName: 'target_auth_header_name',
    headerFormat: 'target_auth_header_format',
  });
  if (accessPointChecksCallers === false) result.advisories.push(MA_CALLER_CHECK_PROBLEM);
  if (!knownTargetAuthMethod(auth)) result.notes.push(UNKNOWN_METHOD_NOTE);
  return result;
}
