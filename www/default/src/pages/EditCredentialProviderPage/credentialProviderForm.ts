export type CredentialProviderType =
  | 'oauth2_authorization_code'
  | 'oauth2_client_credentials'
  | 'oauth2_jwt_bearer'
  | 'oauth2_client_credentials_jwt_auth'
  | 'api_key';

export type ClientAuthentication = '' | 'none' | 'client_secret_basic' | 'client_secret_post';

export const CLIENT_AUTHENTICATION_LABELS: Record<Exclude<ClientAuthentication, ''>, string> = {
  none: 'Client ID only',
  client_secret_basic: 'HTTP Basic',
  client_secret_post: 'Form body',
};

const CLIENT_AUTHENTICATIONS: ClientAuthentication[] = [
  'none',
  'client_secret_basic',
  'client_secret_post',
];

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

/**
 * Which inputs a provider type uses. A JWT Bearer provider uses client pickers only as its
 * client authentication needs them.
 */
export function providerTypeFields(
  type: CredentialProviderType,
  clientAuthentication: ClientAuthentication = ''
): ProviderTypeFields {
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
        clientId: clientAuthentication !== '',
        clientSecret:
          clientAuthentication === 'client_secret_basic' ||
          clientAuthentication === 'client_secret_post',
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
  client_authentication: ClientAuthentication;
}

/** The first missing required field of the form, as the message to show, or null. */
export function missingProviderField(form: ProviderFormValues): string | null {
  const fields = providerTypeFields(form.provider_type, form.client_authentication);
  if (fields.tokenEndpoint && !form.token_endpoint.trim()) {
    return 'Token endpoint is required for OAuth providers.';
  }
  const jwtBearer = form.provider_type === 'oauth2_jwt_bearer';
  if (fields.clientId && !form.client_id_secret_ref) {
    return jwtBearer
      ? 'Client ID secret is required for this client authentication.'
      : 'Client ID secret is required for OAuth providers.';
  }
  if (fields.clientSecret && !form.client_secret_secret_ref) {
    return jwtBearer
      ? 'Client Secret secret is required for HTTP Basic and Form body.'
      : 'Client Secret secret is required for OAuth providers.';
  }
  if (fields.jwtIssuer && !form.jwt_issuer.trim()) {
    return 'Issuer is required for JWT Bearer providers.';
  }
  if (fields.jwtIssuer && !form.jwt_subject.trim()) {
    return 'Subject is required for JWT Bearer providers.';
  }
  if (fields.jwt && !form.jwt_signing_key_secret_ref) {
    return 'Signing key secret is required.';
  }
  if (form.provider_type === 'api_key' && !form.api_key_secret_ref) {
    return 'API Key secret is required.';
  }
  return null;
}

/**
 * True when the type signs a JWT whose header names its key by neither a certificate
 * thumbprint (`x5t#S256`) nor a key ID (`kid`), so the OAuth server must guess the key.
 */
export function jwtKeyUnidentified(
  form: JwtFormFields & { provider_type: CredentialProviderType }
): boolean {
  const fields = providerTypeFields(form.provider_type);
  return (
    fields.jwt &&
    !form.jwt_key_id.trim() &&
    !(fields.jwtCertificate && form.jwt_certificate_secret_ref)
  );
}

/** Hosts of the Microsoft identity platform, public and national clouds. */
const ENTRA_HOSTS = new Set([
  'login.microsoftonline.com',
  'login.microsoftonline.us',
  'login.microsoftonline.de',
  'login.partner.microsoftonline.cn',
  'login.chinacloudapi.cn',
  'login.windows.net',
  'sts.windows.net',
]);

/**
 * What decides whether a provider's token requests carry its `resource`: an external consent
 * provider (one with an `issuer`) leaves it out when `send_resource` is `false`; every other
 * provider sends it whenever it is set.
 */
export interface ResourceSending {
  issuer?: string | null;
  send_resource?: boolean;
}

/**
 * True when the provider's token requests send `resource` to a Microsoft identity platform
 * v2.0 token endpoint, which rejects the parameter (AADSTS901002). A v1.0 endpoint accepts it.
 */
export function entraRejectsResource(
  tokenEndpoint: string,
  resource: string | null | undefined,
  sending: ResourceSending = {}
): boolean {
  if (!resource?.trim()) return false;
  if (sending.issuer && sending.send_resource === false) return false;
  try {
    const url = new URL(tokenEndpoint);
    return ENTRA_HOSTS.has(url.hostname.toLowerCase()) && url.pathname.includes('/oauth2/v2.0/');
  } catch {
    return false;
  }
}

/**
 * Why an Entra v2.0 provider that sends `resource` fails, and what to do instead. An external
 * consent provider needs its resource, which is fixed, so it is re-created without sending it.
 */
export function entraResourceMessage(resource: string, sending: ResourceSending = {}): string {
  if (sending.issuer) {
    return (
      `This provider sends resource "${resource}" to a Microsoft identity platform v2.0 ` +
      'token endpoint, which rejects it (AADSTS901002), so every connect and refresh will ' +
      'fail. Its resource is required and cannot change: re-create the provider with ' +
      'send_resource set to false, which leaves resource out of its token requests and keeps ' +
      'it as the only place its grants may go.'
    );
  }
  return (
    `This provider sets resource "${resource}", which the Microsoft identity platform v2.0 ` +
    'token endpoint rejects (AADSTS901002), so every token request will fail. Put the ' +
    `audience in the scopes as "${resource}/.default" and clear resource through the API.`
  );
}

/**
 * The request fields for the type's client credentials and signed JWT. A field the type
 * does not use is sent empty, which the gateway reads as cleared, so switching a provider
 * to Client Credentials JWT drops its client secret.
 */
export function providerCredentialFields(
  form: ProviderFormValues
): Record<string, string | undefined> {
  const fields = providerTypeFields(form.provider_type, form.client_authentication);
  const value = (enabled: boolean, raw: string) => (enabled ? raw.trim() : '');
  const body: Record<string, string | undefined> = {};
  if (fields.tokenEndpoint) body.token_endpoint = form.token_endpoint.trim();
  body.client_authentication =
    form.provider_type === 'oauth2_jwt_bearer' ? form.client_authentication : '';
  if (fields.clientId || form.provider_type === 'oauth2_jwt_bearer') {
    body.client_id_secret_ref = value(fields.clientId, form.client_id_secret_ref);
  }
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

/** The client authentication of a loaded provider record, empty when unset. */
export function clientAuthenticationOf(data: Record<string, unknown>): ClientAuthentication {
  return CLIENT_AUTHENTICATIONS.find(method => method === data.client_authentication) ?? '';
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

/**
 * The request that edits an external consent provider, one with an `issuer`: only the
 * fields that stay editable, since the gateway refuses a change to any other.
 */
export function externalProviderUpdate(form: {
  name: string;
  description: string;
  default_scopes: string;
  token_refresh_enabled: boolean;
}): Record<string, unknown> {
  return {
    name: form.name.trim(),
    description: form.description.trim() || undefined,
    default_scopes: form.default_scopes
      .split(/[,\s]+/)
      .map(scope => scope.trim())
      .filter(Boolean),
    token_refresh_enabled: form.token_refresh_enabled,
  };
}

/** Whether `host` is an https address, the only kind the gateway takes in a callback URL. */
export function isHttpsAddress(host: string): boolean {
  try {
    return new URL(host).protocol === 'https:';
  } catch {
    return false;
  }
}

/** The consent confirmation inputs, prefixed so they never share a name with the provider's own. */
export interface ConsentConfirmationFormFields {
  consent_confirmation_enabled: boolean;
  /** Whether the loaded provider has the setting; false for a new one. */
  consent_confirmation_stored: boolean;
  cc_client_id_secret_ref: string;
  cc_client_secret_secret_ref: string;
  cc_authorization_endpoint: string;
  cc_token_endpoint: string;
  cc_jwt_verification_strategy_id: string;
  cc_id_token_principal_claim: string;
}

export const EMPTY_CONSENT_CONFIRMATION_FIELDS: ConsentConfirmationFormFields = {
  consent_confirmation_enabled: false,
  consent_confirmation_stored: false,
  cc_client_id_secret_ref: '',
  cc_client_secret_secret_ref: '',
  cc_authorization_endpoint: '',
  cc_token_endpoint: '',
  cc_jwt_verification_strategy_id: '',
  cc_id_token_principal_claim: '',
};

/** The consent confirmation inputs of a loaded provider record. */
export function consentConfirmationFieldsOf(
  data: Record<string, unknown>
): ConsentConfirmationFormFields {
  const setting = data.consent_confirmation;
  if (!setting || typeof setting !== 'object') return EMPTY_CONSENT_CONFIRMATION_FIELDS;
  const stored = setting as Record<string, unknown>;
  const text = (key: string) => (typeof stored[key] === 'string' ? (stored[key] as string) : '');
  return {
    consent_confirmation_enabled: true,
    consent_confirmation_stored: true,
    cc_client_id_secret_ref: text('client_id_secret_ref'),
    cc_client_secret_secret_ref: text('client_secret_secret_ref'),
    cc_authorization_endpoint: text('authorization_endpoint'),
    cc_token_endpoint: text('token_endpoint'),
    cc_jwt_verification_strategy_id: text('jwt_verification_strategy_id'),
    cc_id_token_principal_claim: text('id_token_principal_claim'),
  };
}

/** The first missing required consent confirmation field, as the message to show, or null. */
export function missingConsentConfirmationField(
  form: ConsentConfirmationFormFields
): string | null {
  if (!form.cc_client_id_secret_ref) return 'Login Client ID is required for consent confirmation.';
  if (!form.cc_client_secret_secret_ref) {
    return 'Login Client Secret is required for consent confirmation.';
  }
  if (!form.cc_authorization_endpoint.trim()) {
    return 'Login Authorization Endpoint is required for consent confirmation.';
  }
  if (!form.cc_token_endpoint.trim()) {
    return 'Login Token Endpoint is required for consent confirmation.';
  }
  if (!form.cc_jwt_verification_strategy_id) {
    return 'JWT verification strategy is required for consent confirmation.';
  }
  return null;
}

/**
 * The `consent_confirmation` to send: the setting while the switch is on for a legacy consent
 * provider, `null` to clear a stored one that is switched off or no longer applies, and
 * `undefined` (left out of the request, so the gateway keeps what it has) otherwise.
 */
export function consentConfirmationField(
  form: ConsentConfirmationFormFields,
  usesConsentFlow: boolean
): Record<string, string> | null | undefined {
  if (usesConsentFlow && form.consent_confirmation_enabled) {
    const claim = form.cc_id_token_principal_claim.trim();
    return {
      client_id_secret_ref: form.cc_client_id_secret_ref,
      client_secret_secret_ref: form.cc_client_secret_secret_ref,
      authorization_endpoint: form.cc_authorization_endpoint.trim(),
      token_endpoint: form.cc_token_endpoint.trim(),
      jwt_verification_strategy_id: form.cc_jwt_verification_strategy_id,
      ...(claim ? { id_token_principal_claim: claim } : {}),
    };
  }
  return form.consent_confirmation_stored ? null : undefined;
}

/** The consent confirmation sign-in's redirect URI: the provider's Callback URL plus `/confirm`. */
export function consentConfirmationRedirectUri(callbackUrl: string): string {
  return callbackUrl ? `${callbackUrl}/confirm` : '';
}

/**
 * The callback URL of an authorization code provider: `host` followed by the path the
 * gateway stored for it (`storedPath`). A provider not yet created has none: the gateway
 * builds its path from the provider's id when it creates it.
 */
export function callbackUrlFor(host: string, storedPath: string): string {
  return storedPath ? `${host}${storedPath}` : '';
}

/** What `callbackUrlToSave` builds the callback URL from, by name. */
export interface CallbackUrlInputs {
  storedUrl: string;
  host: string;
  storedPath: string;
}

/**
 * The callback URL to save: the stored one, reverse proxy prefix and all, while the chosen
 * `host` is still its host; otherwise the URL `callbackUrlFor` builds.
 */
export function callbackUrlToSave({ storedUrl, host, storedPath }: CallbackUrlInputs): string {
  try {
    const stored = new URL(storedUrl);
    if (
      stored.origin === new URL(host).origin &&
      stored.protocol === 'https:' &&
      storedPath !== '' &&
      stored.pathname.endsWith(storedPath)
    ) {
      return storedUrl;
    }
  } catch {
    // no stored URL, or one that does not parse: build it
  }
  return callbackUrlFor(host, storedPath);
}
