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
  };
}
