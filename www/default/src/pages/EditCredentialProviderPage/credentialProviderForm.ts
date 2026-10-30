export type CredentialProviderType =
  | 'oauth2_authorization_code'
  | 'oauth2_client_credentials'
  | 'oauth2_jwt_bearer'
  | 'oauth2_client_credentials_jwt_auth'
  | 'api_key';

export type JwtSigningAlgorithm = 'RS256' | 'PS256' | 'ES256';

export interface JwtFormFields {
  jwt_signing_key_secret_ref: string;
  jwt_certificate_secret_ref: string;
  jwt_signing_algorithm: JwtSigningAlgorithm | '';
  jwt_audience: string;
  jwt_key_id: string;
  jwt_issuer: string;
  jwt_subject: string;
}

export const EMPTY_JWT_FIELDS: JwtFormFields = {
  jwt_signing_key_secret_ref: '',
  jwt_certificate_secret_ref: '',
  jwt_signing_algorithm: '',
  jwt_audience: '',
  jwt_key_id: '',
  jwt_issuer: '',
  jwt_subject: '',
};

/** Signing algorithms per type, the default first. */
export const JWT_ALGORITHMS: Partial<Record<CredentialProviderType, JwtSigningAlgorithm[]>> = {
  oauth2_jwt_bearer: ['RS256', 'ES256'],
  oauth2_client_credentials_jwt_auth: ['PS256', 'RS256'],
};

export interface ProviderTypeFields {
  tokenEndpoint: boolean;
  clientId: boolean;
  clientSecret: boolean;
  jwt: boolean;
  jwtIssuer: boolean;
  jwtCertificate: boolean;
}

/** Which inputs a provider type uses. */
export function providerTypeFields(type: CredentialProviderType): ProviderTypeFields {
  switch (type) {
    case 'oauth2_authorization_code':
    case 'oauth2_client_credentials':
      return {
        tokenEndpoint: true,
        clientId: true,
        clientSecret: true,
        jwt: false,
        jwtIssuer: false,
        jwtCertificate: false,
      };
    case 'oauth2_jwt_bearer':
      return {
        tokenEndpoint: true,
        clientId: false,
        clientSecret: false,
        jwt: true,
        jwtIssuer: true,
        jwtCertificate: false,
      };
    case 'oauth2_client_credentials_jwt_auth':
      return {
        tokenEndpoint: true,
        clientId: true,
        clientSecret: false,
        jwt: true,
        jwtIssuer: false,
        jwtCertificate: true,
      };
    case 'api_key':
      return {
        tokenEndpoint: false,
        clientId: false,
        clientSecret: false,
        jwt: false,
        jwtIssuer: false,
        jwtCertificate: false,
      };
  }
}

export interface ProviderFormValues extends JwtFormFields {
  provider_type: CredentialProviderType;
  token_endpoint: string;
  client_id_secret_ref: string;
  client_secret_secret_ref: string;
  api_key_secret_ref: string;
}

/** The first missing required field of the form, as the message to show, or null. */
export function missingProviderField(form: ProviderFormValues): string | null {
  const fields = providerTypeFields(form.provider_type);
  if (fields.tokenEndpoint && !form.token_endpoint.trim()) {
    return 'Token endpoint is required for OAuth providers.';
  }
  if (fields.clientId && !form.client_id_secret_ref) {
    return 'Client ID secret is required for OAuth providers.';
  }
  if (fields.clientSecret && !form.client_secret_secret_ref) {
    return 'Client Secret secret is required for OAuth providers.';
  }
  if (fields.jwtIssuer && !form.jwt_issuer.trim()) {
    return 'Issuer is required for JWT Bearer providers.';
  }
  if (fields.jwt && !form.jwt_signing_key_secret_ref) {
    return 'Signing key secret is required.';
  }
  if (fields.jwtCertificate && !form.jwt_certificate_secret_ref) {
    return 'Certificate secret is required.';
  }
  if (form.provider_type === 'api_key' && !form.api_key_secret_ref) {
    return 'API Key secret is required.';
  }
  return null;
}

/**
 * The request fields for the type's client credentials and signed JWT. A field the type
 * does not use is sent empty, which the gateway reads as cleared, so switching a provider
 * to Client Credentials JWT drops its client secret.
 */
export function providerCredentialFields(
  form: ProviderFormValues
): Record<string, string | undefined> {
  const fields = providerTypeFields(form.provider_type);
  const value = (enabled: boolean, raw: string) => (enabled ? raw.trim() : '');
  const body: Record<string, string | undefined> = {};
  if (fields.tokenEndpoint) body.token_endpoint = form.token_endpoint.trim();
  if (fields.clientId) body.client_id_secret_ref = form.client_id_secret_ref;
  if (fields.tokenEndpoint) {
    body.client_secret_secret_ref = value(fields.clientSecret, form.client_secret_secret_ref);
  }
  if (form.provider_type === 'api_key') body.api_key_secret_ref = form.api_key_secret_ref;
  body.jwt_signing_key_secret_ref = value(fields.jwt, form.jwt_signing_key_secret_ref);
  body.jwt_certificate_secret_ref = value(fields.jwtCertificate, form.jwt_certificate_secret_ref);
  body.jwt_audience = value(fields.jwt, form.jwt_audience);
  body.jwt_key_id = value(fields.jwt, form.jwt_key_id);
  body.jwt_issuer = value(fields.jwtIssuer, form.jwt_issuer);
  body.jwt_subject = value(fields.jwtIssuer, form.jwt_subject);
  // An algorithm left over from the other JWT type is dropped, so the gateway default applies.
  const algorithm = form.jwt_signing_algorithm;
  body.jwt_signing_algorithm =
    algorithm && JWT_ALGORITHMS[form.provider_type]?.includes(algorithm) ? algorithm : undefined;
  return body;
}

/** The JWT fields of a loaded provider record. */
export function jwtFieldsOf(data: Record<string, unknown>): JwtFormFields {
  const text = (key: keyof JwtFormFields) =>
    typeof data[key] === 'string' ? (data[key] as string) : '';
  const algorithm = data.jwt_signing_algorithm;
  return {
    jwt_signing_key_secret_ref: text('jwt_signing_key_secret_ref'),
    jwt_certificate_secret_ref: text('jwt_certificate_secret_ref'),
    jwt_signing_algorithm:
      algorithm === 'RS256' || algorithm === 'PS256' || algorithm === 'ES256' ? algorithm : '',
    jwt_audience: text('jwt_audience'),
    jwt_key_id: text('jwt_key_id'),
    jwt_issuer: text('jwt_issuer'),
    jwt_subject: text('jwt_subject'),
  };
}

export const PROVIDER_TYPE_LABELS: Record<CredentialProviderType, string> = {
  oauth2_authorization_code: 'Authorization Code',
  oauth2_client_credentials: 'Client Credentials',
  oauth2_jwt_bearer: 'JWT Bearer',
  oauth2_client_credentials_jwt_auth: 'Client Credentials JWT',
  api_key: 'API Key',
};
