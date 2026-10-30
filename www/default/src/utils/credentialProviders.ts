import { parseScopes } from './targetAuth';

export type CredentialProviderType =
  | 'oauth2_authorization_code'
  | 'oauth2_client_credentials'
  | 'oauth2_jwt_bearer'
  | 'api_key';

export type ProviderUse = 'target_authentication' | 'legacy_delegation';

type SigningAlgorithm = 'RS256' | 'ES256';

type ClientRefs = 'required' | 'optional' | 'none';

export interface ProviderTypeCapabilities {
  label: string;
  optionLabel: string;
  badgeClass: string;
  clientRefs: ClientRefs;
  authorizationEndpoint: boolean;
  tokenEndpoint: boolean;
  callback: boolean;
  apiKey: boolean;
  signingKey: boolean;
  tokenRefresh: boolean;
  additionalParams: boolean;
  uses: Record<ProviderUse, boolean>;
}

export const PROVIDER_TYPE_CAPABILITIES: Record<CredentialProviderType, ProviderTypeCapabilities> =
  {
    oauth2_authorization_code: {
      label: 'Authorization Code',
      optionLabel: 'OAuth 2.0, Authorization Code (3-legged, user consent)',
      badgeClass: 'text-bg-info',
      clientRefs: 'required',
      authorizationEndpoint: true,
      tokenEndpoint: true,
      callback: true,
      apiKey: false,
      signingKey: false,
      tokenRefresh: true,
      additionalParams: true,
      uses: { target_authentication: false, legacy_delegation: true },
    },
    oauth2_client_credentials: {
      label: 'Client Credentials',
      optionLabel: 'OAuth 2.0, Client Credentials (2-legged, machine-to-machine)',
      badgeClass: 'text-bg-primary',
      clientRefs: 'required',
      authorizationEndpoint: false,
      tokenEndpoint: true,
      callback: false,
      apiKey: false,
      signingKey: false,
      tokenRefresh: true,
      additionalParams: true,
      uses: { target_authentication: true, legacy_delegation: true },
    },
    oauth2_jwt_bearer: {
      label: 'JWT Bearer',
      optionLabel: 'OAuth 2.0, JWT Bearer grant (RFC 7523, signed assertion)',
      badgeClass: 'text-bg-success',
      clientRefs: 'optional',
      authorizationEndpoint: false,
      tokenEndpoint: true,
      callback: false,
      apiKey: false,
      signingKey: true,
      tokenRefresh: false,
      additionalParams: false,
      uses: { target_authentication: true, legacy_delegation: true },
    },
    api_key: {
      label: 'API Key',
      optionLabel: 'API Key (static secret)',
      badgeClass: 'text-bg-warning',
      clientRefs: 'none',
      authorizationEndpoint: false,
      tokenEndpoint: false,
      callback: false,
      apiKey: true,
      signingKey: false,
      tokenRefresh: true,
      additionalParams: true,
      uses: { target_authentication: true, legacy_delegation: true },
    },
  };

export const PROVIDER_TYPES = Object.keys(PROVIDER_TYPE_CAPABILITIES) as CredentialProviderType[];

export function isCredentialProviderType(value: unknown): value is CredentialProviderType {
  return typeof value === 'string' && value in PROVIDER_TYPE_CAPABILITIES;
}

export function providerTypeLabel(type: string): string {
  return isCredentialProviderType(type) ? PROVIDER_TYPE_CAPABILITIES[type].label : type;
}

export function providerTypeBadgeClass(type: string): string {
  return isCredentialProviderType(type)
    ? PROVIDER_TYPE_CAPABILITIES[type].badgeClass
    : 'text-bg-secondary';
}

export function providerPermits(type: string, use: ProviderUse): boolean {
  return isCredentialProviderType(type) && PROVIDER_TYPE_CAPABILITIES[type].uses[use];
}

export function filterProvidersForUse<T extends { provider_type?: string }>(
  providers: T[],
  use: ProviderUse
): T[] {
  return providers.filter(p => providerPermits(p.provider_type ?? '', use));
}

export function keptProviderLabel(
  providers: Array<{ id: string; name: string; provider_type?: string }>,
  id: string
): string {
  const kept = providers.find(p => p.id === id);
  return kept
    ? `${kept.name} (${providerTypeLabel(kept.provider_type ?? '')}, not usable here)`
    : `${id} (not in list)`;
}

export interface CredentialProviderForm {
  name: string;
  provider_id: string;
  provider_type: CredentialProviderType;
  authorization_endpoint: string;
  token_endpoint: string;
  client_id_secret_ref: string;
  client_secret_secret_ref: string;
  api_key_secret_ref: string;
  signing_key_secret_ref: string;
  signing_algorithm: SigningAlgorithm;
  assertion_issuer: string;
  subject: string;
  key_id: string;
  audience: string;
  default_scopes: string;
  token_refresh_enabled: boolean;
  additional_params: string;
  description: string;
  callback_host: string;
}

export const EMPTY_PROVIDER_FORM: CredentialProviderForm = {
  name: '',
  provider_id: '',
  provider_type: 'oauth2_authorization_code',
  authorization_endpoint: '',
  token_endpoint: '',
  client_id_secret_ref: '',
  client_secret_secret_ref: '',
  api_key_secret_ref: '',
  signing_key_secret_ref: '',
  signing_algorithm: 'RS256',
  assertion_issuer: '',
  subject: '',
  key_id: '',
  audience: '',
  default_scopes: '',
  token_refresh_enabled: true,
  additional_params: '',
  description: '',
  callback_host: '',
};

const str = (v: unknown): string => (typeof v === 'string' ? v : '');

export function providerSecretRefs(data: Record<string, unknown>): string[] {
  const jwtBearer =
    data.jwt_bearer && typeof data.jwt_bearer === 'object'
      ? (data.jwt_bearer as Record<string, unknown>)
      : {};
  return [
    data.client_id_secret_ref,
    data.client_secret_secret_ref,
    data.api_key_secret_ref,
    jwtBearer.signing_key_secret_ref,
  ].filter((ref): ref is string => typeof ref === 'string' && ref !== '');
}

export type ProvidersUsingSecret = { ok: true; names: string[] } | { ok: false };

/**
 * Names the credential providers that reference `secretId`. The list API leaves secret
 * references out, so each provider is read on its own.
 */
export async function providersUsingSecret(
  fetcher: (url: string) => Promise<Response>,
  secretId: string
): Promise<ProvidersUsingSecret> {
  try {
    const list = await fetcher('/api/v1/credential-providers');
    if (!list.ok) return { ok: false };
    const items = (await list.json()) as Array<{ id: string; name: string }>;
    const providers = await Promise.all(
      items.map(async item => {
        const response = await fetcher(
          `/api/v1/credential-providers/${encodeURIComponent(item.id)}`
        );
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return { name: item.name, refs: providerSecretRefs(await response.json()) };
      })
    );
    return {
      ok: true,
      names: providers.filter(provider => provider.refs.includes(secretId)).map(p => p.name),
    };
  } catch {
    return { ok: false };
  }
}

export function unknownProviderType(data: Record<string, unknown>): string | null {
  const raw = data.provider_type;
  return typeof raw === 'string' && !isCredentialProviderType(raw) ? raw : null;
}

export function providerFormFromWire(
  data: Record<string, unknown>,
  callbackHost: string
): CredentialProviderForm {
  const jwtBearer =
    data.jwt_bearer && typeof data.jwt_bearer === 'object'
      ? (data.jwt_bearer as Record<string, unknown>)
      : {};
  return {
    name: str(data.name),
    provider_id: str(data.provider_id),
    provider_type: isCredentialProviderType(data.provider_type)
      ? data.provider_type
      : EMPTY_PROVIDER_FORM.provider_type,
    authorization_endpoint: str(data.authorization_endpoint),
    token_endpoint: str(data.token_endpoint),
    client_id_secret_ref: str(data.client_id_secret_ref),
    client_secret_secret_ref: str(data.client_secret_secret_ref),
    api_key_secret_ref: str(data.api_key_secret_ref),
    signing_key_secret_ref: str(jwtBearer.signing_key_secret_ref),
    signing_algorithm: jwtBearer.signing_algorithm === 'ES256' ? 'ES256' : 'RS256',
    assertion_issuer: str(jwtBearer.assertion_issuer),
    subject: str(jwtBearer.assertion_subject),
    key_id: str(jwtBearer.key_id),
    audience: str(jwtBearer.audience),
    default_scopes: Array.isArray(data.default_scopes) ? data.default_scopes.join(', ') : '',
    token_refresh_enabled:
      typeof data.token_refresh_enabled === 'boolean' ? data.token_refresh_enabled : true,
    additional_params:
      data.additional_params && typeof data.additional_params === 'object'
        ? JSON.stringify(data.additional_params, null, 2)
        : '',
    description: str(data.description),
    callback_host: callbackHost,
  };
}

export function deriveProviderId(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

export const GOOGLE_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';

/**
 * The token endpoint after a Provider Type change. A new provider whose endpoint the operator has
 * not edited gets Google's endpoint when it becomes JWT Bearer, and loses that prefill again when
 * it changes to another type.
 */
export function tokenEndpointForType(
  form: CredentialProviderForm,
  nextType: CredentialProviderType,
  mayPrefill: boolean
): string {
  if (!mayPrefill) return form.token_endpoint;
  if (nextType === 'oauth2_jwt_bearer') {
    return form.token_endpoint.trim() ? form.token_endpoint : GOOGLE_TOKEN_ENDPOINT;
  }
  return form.token_endpoint === GOOGLE_TOKEN_ENDPOINT ? '' : form.token_endpoint;
}

function isValidAudience(audience: string): boolean {
  let bytes = 0;
  for (const ch of audience) {
    const code = ch.codePointAt(0)!;
    if (/\s/.test(ch) || code < 0x20 || (code >= 0x7f && code <= 0x9f)) return false;
    bytes += code < 0x80 ? 1 : code < 0x800 ? 2 : code < 0x10000 ? 3 : 4;
  }
  return bytes <= 512;
}

export function validateProviderForm(form: CredentialProviderForm): string | null {
  if (!form.name.trim()) return 'Name is required.';
  const caps = PROVIDER_TYPE_CAPABILITIES[form.provider_type];
  if (!form.provider_id.trim()) {
    return caps.callback
      ? 'Callback URL Route is required.'
      : 'Name must contain at least one letter or number.';
  }
  if (caps.tokenEndpoint && !form.token_endpoint.trim()) {
    return 'Token endpoint is required for OAuth providers.';
  }
  if (caps.clientRefs === 'required') {
    if (!form.client_id_secret_ref) return 'Client ID secret is required for OAuth providers.';
    if (!form.client_secret_secret_ref) {
      return 'Client Secret secret is required for OAuth providers.';
    }
  }
  if (caps.apiKey && !form.api_key_secret_ref) return 'API Key secret is required.';
  if (caps.signingKey) {
    if (!form.signing_key_secret_ref) return 'Signing key secret is required.';
    if (!form.assertion_issuer.trim()) return 'Assertion issuer is required.';
    if (form.audience.trim() && !isValidAudience(form.audience.trim())) {
      return 'Audience must be at most 512 bytes, with no spaces or control characters.';
    }
    if (form.client_id_secret_ref && !form.client_secret_secret_ref) {
      return 'Client Secret secret is required when a Client ID secret is set.';
    }
    if (form.client_secret_secret_ref && !form.client_id_secret_ref) {
      return 'Client ID secret is required when a Client Secret secret is set.';
    }
  }
  if (form.additional_params.trim()) {
    try {
      JSON.parse(form.additional_params);
    } catch {
      return 'Additional Parameters must be valid JSON.';
    }
  }
  return null;
}

export function buildProviderBody(
  form: CredentialProviderForm,
  callbackPathPrefix: string | null,
  isNew = true
): Record<string, unknown> {
  const caps = PROVIDER_TYPE_CAPABILITIES[form.provider_type];
  const body: Record<string, unknown> = {
    name: form.name.trim(),
    provider_id: form.provider_id.trim(),
    provider_type: form.provider_type,
    default_scopes: parseScopes(form.default_scopes),
    token_refresh_enabled: form.token_refresh_enabled,
    description: form.description.trim() || (isNew ? undefined : null),
  };
  if (caps.tokenEndpoint) body.token_endpoint = form.token_endpoint.trim();
  if (
    caps.clientRefs === 'required' ||
    (caps.clientRefs === 'optional' && form.client_id_secret_ref)
  ) {
    body.client_id_secret_ref = form.client_id_secret_ref;
    body.client_secret_secret_ref = form.client_secret_secret_ref;
  } else if (!isNew) {
    body.client_id_secret_ref = null;
    body.client_secret_secret_ref = null;
  }
  if (caps.apiKey && form.api_key_secret_ref) body.api_key_secret_ref = form.api_key_secret_ref;
  else if (!caps.apiKey && !isNew) body.api_key_secret_ref = null;
  if (caps.signingKey) {
    const jwtBearer: Record<string, string> = {
      signing_key_secret_ref: form.signing_key_secret_ref,
      signing_algorithm: form.signing_algorithm,
      assertion_issuer: form.assertion_issuer.trim(),
    };
    if (form.subject.trim()) jwtBearer.assertion_subject = form.subject.trim();
    if (form.key_id.trim()) jwtBearer.key_id = form.key_id.trim();
    if (form.audience.trim()) jwtBearer.audience = form.audience.trim();
    body.jwt_bearer = jwtBearer;
  }
  const authorizationEndpoint = form.authorization_endpoint.trim();
  if (isNew) {
    if (authorizationEndpoint) body.authorization_endpoint = authorizationEndpoint;
  } else {
    body.authorization_endpoint = (caps.authorizationEndpoint && authorizationEndpoint) || null;
  }
  const rawParams = form.additional_params.trim();
  if (!isNew) {
    body.additional_params = caps.additionalParams && rawParams ? JSON.parse(rawParams) : {};
  } else if (rawParams) {
    const params = JSON.parse(rawParams) as Record<string, string>;
    if (Object.keys(params).length > 0) body.additional_params = params;
  }
  if (caps.callback && form.callback_host && callbackPathPrefix !== null) {
    body.callback_url = `${form.callback_host}${callbackPathPrefix}/${encodeURIComponent(form.provider_id.trim())}`;
  }
  return body;
}
