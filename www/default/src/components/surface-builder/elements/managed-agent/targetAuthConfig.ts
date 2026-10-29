import {
  buildCredentialProviderAuth,
  parseScopes,
  type CredentialInjection,
  type CredentialProviderAuthFields,
  type TargetAuthFallback,
  type TargetAuthWire,
} from '../../../../utils/targetAuth';

export const CREDENTIAL_PROVIDER_AUTH_TYPE = 'credential_provider';
export const PRESERVED_AUTH_TYPE = 'preserved';

type Config = Record<string, any>;

export function credentialProviderFieldsFromConfig(c: Config): CredentialProviderAuthFields {
  const injectAs: CredentialInjection =
    c.target_auth_inject_as === 'custom_header'
      ? {
          type: 'custom_header',
          name: typeof c.target_auth_inject_name === 'string' ? c.target_auth_inject_name : '',
          format:
            typeof c.target_auth_inject_format === 'string' ? c.target_auth_inject_format : '',
        }
      : { type: 'bearer_header' };
  const fallback: TargetAuthFallback =
    c.target_auth_fallback === 'passthrough' ? 'passthrough' : 'reject';
  return {
    credentialProviderId:
      typeof c.target_auth_credential_provider_id === 'string'
        ? c.target_auth_credential_provider_id
        : '',
    scopes: parseScopes(typeof c.target_auth_scopes === 'string' ? c.target_auth_scopes : ''),
    injectAs,
    fallback,
  };
}

export function targetAuthFromConfig(c: Config): TargetAuthWire | null {
  if (!c.target_auth_enabled) return null;
  if (c.target_auth_type === PRESERVED_AUTH_TYPE) {
    return c.target_auth_raw && typeof c.target_auth_raw === 'object' ? c.target_auth_raw : null;
  }
  if (c.target_auth_type === CREDENTIAL_PROVIDER_AUTH_TYPE) {
    const fields = credentialProviderFieldsFromConfig(c);
    return fields.credentialProviderId ? buildCredentialProviderAuth(fields) : null;
  }
  if (!c.target_auth_secret_id) return null;
  return {
    method: {
      static_secret: {
        secret_id: c.target_auth_secret_id,
        header_name: c.target_auth_header_name || 'Authorization',
        header_format: c.target_auth_header_format || '{value}',
      },
    },
    auth_type: c.target_auth_type || 'bearer',
    fallback: c.target_auth_fallback || 'reject',
  };
}
