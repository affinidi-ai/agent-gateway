export type CredentialInjection =
  | { type: 'bearer_header' }
  | { type: 'custom_header'; name: string; format: string };

export type TargetAuthFallback = 'reject' | 'passthrough';

export interface StaticSecretMethod {
  static_secret: { secret_id: string; header_name: string; header_format: string };
}

export interface CredentialProviderMethod {
  credential_provider: {
    credential_provider_id: string;
    scopes?: string[];
    inject_as?: CredentialInjection;
  };
}

export interface TargetAuthWire {
  method: StaticSecretMethod | CredentialProviderMethod | string | Record<string, unknown>;
  auth_type?: string;
  target_identifier?: string | null;
  fallback?: string;
}

export interface CredentialProviderAuthFields {
  credentialProviderId: string;
  scopes: string[];
  injectAs: CredentialInjection;
  fallback: TargetAuthFallback;
}

export type ParsedTargetAuth =
  | {
      kind: 'static_secret';
      secretId: string;
      headerName: string;
      headerFormat: string;
      authType?: string;
      fallback: string;
    }
  | ({ kind: 'credential_provider' } & CredentialProviderAuthFields)
  | { kind: 'unsupported'; raw: TargetAuthWire };

export const DEFAULT_INJECTION: CredentialInjection = { type: 'bearer_header' };

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

const asString = (v: unknown): string => (typeof v === 'string' ? v : '');

const PROVIDER_KEYS = ['credential_provider_id', 'scopes', 'inject_as'];
const INJECTION_KEYS: Record<string, string[]> = {
  bearer_header: ['type'],
  custom_header: ['type', 'name', 'format'],
};
const FORBIDDEN_HEADER_NAMES = ['host', 'content-length', 'transfer-encoding', 'connection'];

const onlyKeys = (value: Record<string, unknown>, allowed: string[]): boolean =>
  Object.keys(value).every(k => allowed.includes(k));

function isModelledProvider(cp: Record<string, unknown>): boolean {
  if (!onlyKeys(cp, PROVIDER_KEYS)) return false;
  if (cp.scopes !== undefined) {
    if (!Array.isArray(cp.scopes) || !cp.scopes.every(s => typeof s === 'string')) return false;
  }
  if (cp.inject_as === undefined) return true;
  if (!isRecord(cp.inject_as)) return false;
  const allowed = INJECTION_KEYS[asString(cp.inject_as.type)];
  return allowed !== undefined && onlyKeys(cp.inject_as, allowed);
}

export function parseInjection(raw: unknown): CredentialInjection {
  if (isRecord(raw) && raw.type === 'custom_header') {
    return { type: 'custom_header', name: asString(raw.name), format: asString(raw.format) };
  }
  return DEFAULT_INJECTION;
}

export function parseScopes(text: string): string[] {
  const seen = new Set<string>();
  for (const s of text.split(/[,\s]+/)) {
    if (s.trim()) seen.add(s.trim());
  }
  return Array.from(seen);
}

export function parseTargetAuth(auth: unknown): ParsedTargetAuth | null {
  if (!isRecord(auth)) return null;
  const raw = auth as unknown as TargetAuthWire;
  const method = auth.method;
  const fallback = asString(auth.fallback) || 'reject';
  if (isRecord(method) && isRecord(method.static_secret)) {
    const ss = method.static_secret;
    return {
      kind: 'static_secret',
      secretId: asString(ss.secret_id),
      headerName: asString(ss.header_name) || 'Authorization',
      headerFormat: asString(ss.header_format) || '{value}',
      authType: typeof auth.auth_type === 'string' ? auth.auth_type : undefined,
      fallback,
    };
  }
  if (method === 'static_secret') {
    return {
      kind: 'static_secret',
      secretId: asString(auth.secret_id),
      headerName: asString(auth.header_name) || 'Authorization',
      headerFormat: asString(auth.header_format) || '{value}',
      authType: typeof auth.auth_type === 'string' ? auth.auth_type : undefined,
      fallback,
    };
  }
  if (
    isRecord(method) &&
    isRecord(method.credential_provider) &&
    onlyKeys(method, ['credential_provider']) &&
    isModelledProvider(method.credential_provider)
  ) {
    const cp = method.credential_provider;
    return {
      kind: 'credential_provider',
      credentialProviderId: asString(cp.credential_provider_id),
      scopes: Array.isArray(cp.scopes)
        ? cp.scopes.filter((s): s is string => typeof s === 'string')
        : [],
      injectAs: parseInjection(cp.inject_as),
      fallback: fallback === 'passthrough' ? 'passthrough' : 'reject',
    };
  }
  return { kind: 'unsupported', raw };
}

export function buildCredentialProviderAuth(f: CredentialProviderAuthFields): TargetAuthWire {
  return {
    method: {
      credential_provider: {
        credential_provider_id: f.credentialProviderId,
        ...(f.scopes.length > 0 ? { scopes: f.scopes } : {}),
        inject_as: f.injectAs,
      },
    },
    fallback: f.fallback,
  };
}

export function injectionHeaderName(injectAs: CredentialInjection): string {
  return injectAs.type === 'custom_header' ? injectAs.name.trim() : 'Authorization';
}

export type CredentialProviderAuthField = 'provider' | 'name' | 'format';

export interface CredentialProviderAuthProblem {
  field: CredentialProviderAuthField;
  message: string;
}

export function credentialProviderAuthProblem(
  f: CredentialProviderAuthFields
): CredentialProviderAuthProblem | null {
  if (!f.credentialProviderId.trim()) {
    return { field: 'provider', message: 'Select a credential provider.' };
  }
  if (f.injectAs.type === 'custom_header') {
    if (!f.injectAs.name.trim()) return { field: 'name', message: 'Enter the header name.' };
    if (!f.injectAs.format.includes('{value}')) {
      return { field: 'format', message: 'The header format must contain {value}.' };
    }
    const name = f.injectAs.name.trim();
    if (FORBIDDEN_HEADER_NAMES.includes(name.toLowerCase())) {
      return { field: 'name', message: `${name} cannot be used as the header name.` };
    }
  }
  return null;
}

export function credentialProviderAuthError(f: CredentialProviderAuthFields): string | null {
  return credentialProviderAuthProblem(f)?.message ?? null;
}

export const PRESERVED_AUTH_PICK = 'preserved';

export function hasPreservedTargetAuth(config: Record<string, unknown>): boolean {
  if (config.auth_type) return false;
  const kind = parseTargetAuth(config.target_auth)?.kind;
  return kind === 'unsupported' || kind === 'credential_provider';
}

export function hasUnpickedTargetAuth(config: Record<string, unknown>): boolean {
  return !config.auth_type && parseTargetAuth(config.target_auth) !== null;
}
