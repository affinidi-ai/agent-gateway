/**
 * Who can call a Transit Point: the dashboard's side of the gateway's rules.
 *
 * A Transit Point authenticates its callers with a transit token, a resource
 * access token (`mcp_http.authorization`, set through the API) or its own
 * `source_auth`. One that does none of them must say so with
 * `allow_unauthenticated_callers`, or the gateway refuses the save. These
 * helpers apply the same rules to the node's config before the save, mirroring
 * `TransitPoint::unenforceable_caller_authentication` and
 * `TransitPoint::validate_caller_authentication` in `src/config/agent_surface.rs`.
 *
 * The node config holds `source_auth` in its wire shape, as the gateway
 * returns it, so a stored one round-trips through a save untouched.
 */

/** A Transit Point's `source_auth` as the gateway stores it. */
export interface TransitSourceAuth {
  /** A string for every method the gateway knows; anything else is kept as stored. */
  type?: unknown;
  [key: string]: unknown;
}

/** The ways the panel lets an operator authenticate a Transit Point's callers. */
export type CallerAuthChoice = 'none' | 'api_key' | 'api_key_provider' | 'jwt_bearer' | 'mtls';

export const DEFAULT_API_KEY_HEADER = 'X-API-Key';

export const NO_CALLER_AUTH_PROBLEM =
  'This Transit Point would serve anyone who can reach it. Keep the transit token on, choose how callers authenticate, or mark it open to any caller.';

export const OPEN_WITH_AUTH_PROBLEM =
  'Open to any caller cannot be combined with the transit token or a caller authentication method. Turn one of them off.';

export const SOURCE_AUTH_WITH_RESOURCE_TOKEN_PROBLEM =
  'This Transit Point also sets a resource access token (set through the API). Keep one way to authenticate callers: remove the resource access token through the API, or choose no caller authentication here.';

export { parseWarningHeader, joinWarnings } from '../../../../utils/warningHeader';

type Config = Record<string, unknown> | null | undefined;

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function text(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

/**
 * The Transit Point's `source_auth`, or null when it has none. A stored one
 * whose `type` cannot be read still counts as set, so it is shown and kept.
 */
export function readSourceAuth(config: Config): TransitSourceAuth | null {
  return asRecord(config?.source_auth) as TransitSourceAuth | null;
}

/** Whether the Transit Point sets a resource access token (`mcp_http.authorization`). */
export function hasResourceToken(config: Config): boolean {
  const http = asRecord(config?.mcp_http);
  return !!http && http.authorization != null && http.authorization !== false;
}

/** Whether the Transit Point requires a transit token (the default). */
export function requiresTransitToken(config: Config): boolean {
  return config?.require_transit_token !== false;
}

/** Whether the Transit Point is marked open to any caller. */
export function isOpenToAnyCaller(config: Config): boolean {
  return config?.allow_unauthenticated_callers === true;
}

/** Whether the Transit Point authenticates its callers in any of the three ways. */
export function authenticatesCallers(config: Config): boolean {
  return requiresTransitToken(config) || hasResourceToken(config) || readSourceAuth(config) != null;
}

/** What the caller authentication select shows for a stored `source_auth`. */
export function callerAuthChoice(config: Config): CallerAuthChoice | 'unsupported' {
  const sourceAuth = readSourceAuth(config);
  if (!sourceAuth) return 'none';
  switch (sourceAuth.type) {
    case 'api_key':
    case 'api_key_provider':
    case 'jwt_bearer':
    case 'mtls':
      return sourceAuth.type as CallerAuthChoice;
    default:
      return 'unsupported';
  }
}

/** The header an API key `source_auth` reads, when it reads one. */
export function apiKeyHeader(sourceAuth: TransitSourceAuth | null): string {
  const extraction = asRecord(sourceAuth?.extraction);
  return extraction?.source === 'http_header' ? text(extraction.field) : '';
}

/** A fresh `source_auth` for a method the operator picked. */
export function newSourceAuth(
  choice: Exclude<CallerAuthChoice, 'none' | 'mtls'>,
  providerAgentId: string
): TransitSourceAuth {
  switch (choice) {
    case 'api_key':
      return {
        type: 'api_key',
        extraction: { source: 'http_header', field: DEFAULT_API_KEY_HEADER },
        secret_id: '',
      };
    case 'api_key_provider':
      return {
        type: 'api_key_provider',
        extraction: { source: 'http_header', field: DEFAULT_API_KEY_HEADER },
        agent_id: providerAgentId,
      };
    case 'jwt_bearer':
      return {
        type: 'jwt_bearer',
        jwt_verification_strategy_id: '',
        audiences: [],
        token_header: 'Authorization',
        token_scheme: 'Bearer',
        forward_header: false,
      };
  }
}

/**
 * Why a stored `source_auth` cannot be saved, in plain words, or null. These
 * are the refusals the gateway makes for a Transit Point's `source_auth`.
 */
export function sourceAuthProblem(sourceAuth: TransitSourceAuth | null): string | null {
  if (!sourceAuth) return null;
  // A `source_auth` with no readable type was set through the API and is kept.
  if (typeof sourceAuth.type !== 'string') return null;
  switch (sourceAuth.type) {
    case 'api_key':
      if (!apiKeyHeader(sourceAuth)) {
        return 'Name the HTTP header callers send their API key in. A Transit Point cannot read it from the message body.';
      }
      return text(sourceAuth.secret_id)
        ? null
        : 'Choose the secret that holds the accepted API keys.';
    case 'api_key_provider':
      if (!apiKeyHeader(sourceAuth)) {
        return 'Name the HTTP header callers send their API key in. A Transit Point cannot read it from the message body.';
      }
      return text(sourceAuth.agent_id)
        ? null
        : 'The API key provider needs the agent it validates keys for.';
    case 'jwt_bearer': {
      if (sourceAuth.forward_header === true) {
        return 'A Transit Point cannot forward the caller token to its target. Turn off forwarding.';
      }
      if (!text(sourceAuth.jwt_verification_strategy_id)) {
        return "Choose the JWT verification strategy that checks the callers' tokens.";
      }
      if (!text(sourceAuth.token_header)) {
        return 'Name the header callers send their token in, such as Authorization.';
      }
      if (!text(sourceAuth.token_scheme)) {
        return 'Name the scheme callers send their token with, such as Bearer.';
      }
      const audiences = Array.isArray(sourceAuth.audiences) ? sourceAuth.audiences : [];
      return audiences.some(a => text(a))
        ? null
        : 'Name the audience this Transit Point accepts, so a token issued for another service, such as the Access Point, is refused.';
    }
    case 'mtls': {
      const trust = asRecord(sourceAuth.trust);
      const ids = trust?.type === 'ca' ? trust.ca_certificate_ids : trust?.certificate_ids;
      const trusted = Array.isArray(ids) && ids.some(id => text(id));
      return trust && (trust.type === 'ca' || trust.type === 'pinned') && !trusted
        ? 'The mTLS method trusts no certificate. Set the certificates it trusts through the API, or choose another method.'
        : null;
    }
    default:
      return 'DID Auth is not supported on a Transit Point. Choose an API key, a JWT or no caller authentication.';
  }
}

/**
 * Everything that stops this Transit Point from being saved, in plain words.
 * Empty when the gateway would accept it.
 */
export function callerAuthProblems(config: Config): string[] {
  const problems: string[] = [];
  const sourceAuth = readSourceAuth(config);
  if (!sourceAuth) {
    if (!authenticatesCallers(config) && !isOpenToAnyCaller(config)) {
      problems.push(NO_CALLER_AUTH_PROBLEM);
    }
  } else {
    if (hasResourceToken(config)) problems.push(SOURCE_AUTH_WITH_RESOURCE_TOKEN_PROBLEM);
    const problem = sourceAuthProblem(sourceAuth);
    if (problem) problems.push(problem);
  }
  if (isOpenToAnyCaller(config) && authenticatesCallers(config)) {
    problems.push(OPEN_WITH_AUTH_PROBLEM);
  }
  return problems;
}

function ipv6Octets(host: string): number[] | null {
  const [head, tail = ''] = host.split('::');
  const half = (part: string) => (part ? part.split(':') : []);
  const front = half(head);
  const back = host.includes('::') ? half(tail) : [];
  const missing = 8 - front.length - back.length;
  if (missing < 0 || (!host.includes('::') && front.length !== 8)) return null;
  const groups = [...front, ...Array(host.includes('::') ? missing : 0).fill('0'), ...back];
  if (groups.length !== 8) return null;
  const out: number[] = [];
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(group)) return null;
    const value = parseInt(group, 16);
    out.push(value >> 8, value & 0xff);
  }
  return out;
}

function thisHostAddress(host: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    const [a, b, c, d] = host.split('.').map(Number);
    return a === 127 || (a === 0 && b === 0 && c === 0 && d === 0);
  }
  if (host.startsWith('[') && host.endsWith(']')) {
    const octets = ipv6Octets(host.slice(1, -1));
    if (!octets) return false;
    const mapped =
      octets.slice(0, 10).every(o => o === 0) && octets[10] === 255 && octets[11] === 255;
    const v4 = mapped ? octets.slice(12) : null;
    if (v4) return v4[0] === 127 || v4.every(o => o === 0);
    const leading = octets.slice(0, 15).every(o => o === 0);
    return leading && (octets[15] === 0 || octets[15] === 1);
  }
  return false;
}

/**
 * Whether callers on other hosts can use `url`: its host is not `localhost` or a
 * loopback or unspecified address. A private or link-local address counts, as
 * does any other host name and a URL that does not parse. Mirrors the
 * gateway's `reachable_from_other_hosts`; an empty URL is not reachable.
 */
export function reachableFromOtherHosts(url: unknown): boolean {
  const value = text(url);
  if (!value) return false;
  let host: string;
  try {
    host = new URL(value).hostname.toLowerCase();
  } catch {
    return true;
  }
  if (!host) return true;
  if (host === 'localhost' || host.endsWith('.localhost')) return false;
  return !thisHostAddress(host);
}

/**
 * The warning for a Transit Point that serves callers it does not authenticate
 * on a URL other hosts reach, or null. The dashboard sees the listener's
 * external URL; the gateway also counts bind addresses and shared-domain
 * inbound listeners, so a save can answer with a warning this does not predict.
 */
export function exposureWarning(config: Config, alias: string): string | null {
  if (!isOpenToAnyCaller(config) || authenticatesCallers(config)) return null;
  const url = text(config?.listen_address);
  if (!reachableFromOtherHosts(url)) return null;
  return `Transit Point '${alias}' serves callers it does not authenticate and is reachable from other hosts: ${url}`;
}

/**
 * The save warnings that name the Transit Point with this alias, in the base
 * surface or, with `variant`, in that variant. The gateway words a variant's
 * as `Transit Point 'x' in variant 'v' ...` and the base's without it.
 */
export function warningsForTransitPoint(
  warnings: readonly string[],
  alias: string,
  variant?: string
): string[] {
  if (!alias) return [];
  const prefix = `Transit Point '${alias}'`;
  const inVariant = `${prefix} in variant '`;
  return warnings.filter(w => {
    if (variant) return w.startsWith(`${inVariant}${variant}'`);
    return w.startsWith(prefix) && !w.startsWith(inVariant);
  });
}

/**
 * The gateway's reason for refusing a save of the Transit Point with this alias,
 * in plain words, or null when the error names another. The gateway words it
 * `transit.points[0]: Transit Point 'x' ...`, and for a variant
 * `variant 'v' transit.points[0]: ...`.
 */
export function transitPointSaveError(
  error: string | null | undefined,
  alias: string
): string | null {
  if (!error || !alias || !error.includes(`Transit Point '${alias}'`)) return null;
  return error
    .replace(/^(?:variant '[^']*' )?transit\.points\[\d+\]:\s*/, '')
    .replace(/\s*\(400\)$/, '');
}

/**
 * The fields a save warning is about. A shown warning goes once any of them
 * changes, since the warning no longer describes what the operator sees.
 */
export function callerAuthSignature(config: Config): string {
  return JSON.stringify([
    config?.require_transit_token,
    config?.allow_unauthenticated_callers,
    config?.source_auth ?? null,
    config?.listen_address,
    config?.alias,
    config?.name,
  ]);
}

/**
 * The wire fields a Transit Point's caller authentication writes. A `source_auth`
 * the operator turned off is sent as `null`, which removes the stored one (a
 * PUT that left it out would keep it). `allow_unauthenticated_callers` is sent
 * only while the Transit Point authenticates no caller, since the gateway
 * refuses it beside one; an explicit `false` is sent when the operator turned
 * it off, so the stored marking does not return.
 */
export function callerAuthToWire(config: Config): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const sourceAuth = readSourceAuth(config);
  if (sourceAuth) out.source_auth = sourceAuth;
  else if (config && 'source_auth' in config && config.source_auth === null) out.source_auth = null;
  if (isOpenToAnyCaller(config) && !authenticatesCallers(config)) {
    out.allow_unauthenticated_callers = true;
  } else if (config?.allow_unauthenticated_callers === false) {
    out.allow_unauthenticated_callers = false;
  }
  return out;
}
