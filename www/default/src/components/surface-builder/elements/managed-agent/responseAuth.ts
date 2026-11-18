import type { MtlsTrust } from '../../../../types';

export interface ApiKeyResponseAuth {
  api_key: { header_name: string; secret_id: string };
}

export interface MtlsResponseAuth {
  mtls: { server_trust: MtlsTrust; client_certificate_id?: string };
}

/** `target.response_auth` in its wire shape. */
export type ResponseAuth = ApiKeyResponseAuth | MtlsResponseAuth;

export type ResponseAuthMethod = 'off' | 'api_key' | 'mtls' | 'unsupported';

export const DEFAULT_RESPONSE_AUTH_HEADER = 'X-Agent-Key';

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Whether `endpoint` is a URL with one of `protocols` and a host, read as the
 * gateway's Response authentication rules read it: trimmed, scheme in any case.
 */
function hasProtocol(endpoint: unknown, protocols: string[]): boolean {
  if (typeof endpoint !== 'string') return false;
  try {
    const url = new URL(endpoint.trim());
    return protocols.includes(url.protocol) && url.host !== '';
  } catch {
    return false;
  }
}

/** Whether `endpoint` is a Target Response authentication can be set on: an http or https URL. */
export function isResponseAuthTarget(endpoint: unknown): boolean {
  return hasProtocol(endpoint, ['http:', 'https:']);
}

export function isHttpsTarget(endpoint: unknown): boolean {
  return hasProtocol(endpoint, ['https:']);
}

/** The method a stored or edited `response_auth` uses; a shape the panel cannot read is `unsupported`. */
export function responseAuthMethod(value: unknown): ResponseAuthMethod {
  if (!isObject(value)) return 'off';
  const keys = Object.keys(value);
  if (keys.length === 1 && keys[0] === 'api_key' && isObject(value.api_key)) return 'api_key';
  if (keys.length === 1 && keys[0] === 'mtls' && isObject(value.mtls)) return 'mtls';
  return 'unsupported';
}

export function newResponseAuth(method: 'api_key' | 'mtls'): ResponseAuth {
  return method === 'api_key'
    ? { api_key: { header_name: DEFAULT_RESPONSE_AUTH_HEADER, secret_id: '' } }
    : { mtls: { server_trust: { type: 'pinned', certificate_ids: [] } } };
}

/** The certificate ids the server trust names. */
export function trustCertificateIds(trust: MtlsTrust): string[] {
  const ids = trust.type === 'pinned' ? trust.certificate_ids : trust.ca_certificate_ids;
  return Array.isArray(ids) ? ids : [];
}

export function withTrustCertificateIds(trust: MtlsTrust, ids: string[]): MtlsTrust {
  return trust.type === 'pinned'
    ? { ...trust, certificate_ids: ids }
    : { ...trust, ca_certificate_ids: ids };
}

/**
 * What blocks a save of `value` on a Target at `endpoint`, as the gateway's
 * save rules do. Nothing is checked on a Target that is not http(s), since
 * the setting is not sent for one.
 */
export function responseAuthProblems(endpoint: unknown, value: unknown): string[] {
  if (!isResponseAuthTarget(endpoint)) return [];
  const method = responseAuthMethod(value);
  if (method === 'api_key') {
    const { header_name, secret_id } = (value as ApiKeyResponseAuth).api_key;
    const problems: string[] = [];
    if (!String(header_name ?? '').trim()) problems.push('Enter the response header name');
    if (!String(secret_id ?? '').trim()) problems.push('Select the secret holding the key');
    return problems;
  }
  if (method === 'mtls') {
    const { server_trust } = (value as MtlsResponseAuth).mtls;
    const problems: string[] = [];
    if (!isHttpsTarget(endpoint)) problems.push('mTLS needs an https:// Target');
    if (!isObject(server_trust) || trustCertificateIds(server_trust).length === 0) {
      problems.push(
        server_trust?.type === 'ca'
          ? 'Select at least one CA certificate'
          : 'Select at least one server certificate'
      );
    }
    return problems;
  }
  return [];
}

/**
 * The `target.response_auth` a save sends: the panel's value, a stored one
 * the operator did not edit included, verbatim on an http(s) Target; `null`
 * once switched off or when the Target is no longer http(s), since the
 * gateway keeps a stored one a `PUT` leaves out; left out when there is none.
 */
export function responseAuthToWire(endpoint: unknown, value: unknown): unknown {
  if (value === null) return null;
  if (isObject(value)) return isResponseAuthTarget(endpoint) ? value : null;
  return undefined;
}

const FIELD_WORDS: Array<[string, string]> = [
  ['.api_key.header_name', 'The response header'],
  ['.mtls.server_trust', 'The trusted server certificate'],
  ['.mtls.client_certificate_id', 'The client certificate'],
  ['.mtls', 'mTLS'],
  ['', 'Response authentication'],
];

function fieldPrefix(variant?: string): string {
  return variant ? `variants['${variant}'].target.response_auth` : 'target.response_auth';
}

/** `message` with the gateway's field name for this view's setting in plain words, or null when it names another. */
function inPlainWords(message: string, variant?: string): string | null {
  const prefix = fieldPrefix(variant);
  const at = message.indexOf(prefix);
  if (at < 0 || (!variant && message.slice(0, at).endsWith('.'))) return null;
  const rest = message.slice(at + prefix.length);
  const [field, words] = FIELD_WORDS.find(([f]) => rest.startsWith(f))!;
  return `${words}${rest.slice(field.length)}`.replace(/\s*\(400\)$/, '');
}

/** The gateway's reason for refusing the last save of this view's Response authentication, in plain words. */
export function responseAuthSaveError(
  error: string | null | undefined,
  variant?: string
): string | null {
  return error ? inPlainWords(error, variant) : null;
}

/** The last save's `Warning` messages about this view's Response authentication, in plain words. */
export function responseAuthWarnings(warnings: readonly string[], variant?: string): string[] {
  return warnings.map(w => inPlainWords(w, variant)).filter((w): w is string => w !== null);
}
