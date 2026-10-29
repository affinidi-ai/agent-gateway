import type { AgentSurface } from '../../../../api';
import type { Protocol } from '../types';

/**
 * Authorization server discovery (`caller_authentication.protected_resource`):
 * the RFC 9728 metadata an MCP Access Point publishes so a client finds where
 * to get a token. These helpers mirror the gateway's save-time rules in
 * `src/protocols/protected_resource.rs` and `validate_protected_resource` in
 * `src/config/agent_surface.rs`, so the editor flags a setting the gateway
 * refuses before the save is sent.
 *
 * Without that setting, an Access Point whose only method is JWT Bearer with
 * required scopes derives its declaration from the strategy's pinned
 * authorization server (`src/source_auth/declaration.rs`). The derived helpers
 * below mirror its strip reasons as advice; the gateway saves such a surface
 * either way and reports the outcome.
 */
export interface ProtectedResourceSetting {
  resource: string;
  authorization_servers: string[];
  scopes: string[];
}

export const MAX_AUTHORIZATION_SERVERS = 8;
const MAX_AUTHORIZATION_SERVER_BYTES = 2048;
const MAX_RESOURCE_BYTES = 4096;
const MAX_SCOPES = 128;
const OAUTH_SCOPE_TOKEN = /^[\x21\x23-\x5b\x5d-\x7e]{1,256}$/;
const ASCII_GRAPHIC = /^[\x21-\x7e]+$/;

/** Fields the discovery checks report errors under. */
export const DISCOVERY_FIELDS = {
  rules: 'protected_resource',
  resource: 'protected_resource.resource',
  authorizationServers: 'protected_resource.authorization_servers',
  scopes: 'protected_resource.scopes',
} as const;

export interface DiscoveryProblem {
  field: string;
  message: string;
}

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/** The setting held in a caller-auth config or a stored `caller_authentication`, or null. */
export function readProtectedResource(value: unknown): ProtectedResourceSetting | null {
  const record = asRecord(value);
  if (!record) return null;
  return {
    resource: typeof record.resource === 'string' ? record.resource : '',
    authorization_servers: stringList(record.authorization_servers),
    scopes: stringList(record.scopes),
  };
}

/** The wire shape the gateway stores; `scopes` is left out when empty. */
export function protectedResourcePayload(setting: ProtectedResourceSetting): {
  resource: string;
  authorization_servers: string[];
  scopes?: string[];
} {
  return {
    resource: setting.resource,
    authorization_servers: [...setting.authorization_servers],
    ...(setting.scopes.length > 0 ? { scopes: [...setting.scopes] } : {}),
  };
}

function parseUrl(value: string): URL | null {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function hasCredentialsQueryOrFragment(value: string, parsed: URL): boolean {
  return !!parsed.username || !!parsed.password || value.includes('?') || value.includes('#');
}

/** Why `resource` is not a canonical https URL the gateway accepts, or null. */
export function resourceProblem(resource: string): string | null {
  if (!resource) return 'Enter the resource URL';
  const parsed = parseUrl(resource);
  if (
    !parsed ||
    resource.length > MAX_RESOURCE_BYTES ||
    parsed.protocol !== 'https:' ||
    !parsed.hostname ||
    hasCredentialsQueryOrFragment(resource, parsed)
  ) {
    return 'The resource must be an https URL without credentials, query or fragment';
  }
  if (parsed.href !== resource) return `Write the resource in its canonical form: ${parsed.href}`;
  return null;
}

/** Why `issuer` is not an authorization server the gateway accepts, or null. */
export function authorizationServerProblem(issuer: string): string | null {
  const parsed = parseUrl(issuer);
  if (
    !parsed ||
    issuer.length > MAX_AUTHORIZATION_SERVER_BYTES ||
    !ASCII_GRAPHIC.test(issuer) ||
    parsed.protocol !== 'https:' ||
    !parsed.hostname ||
    hasCredentialsQueryOrFragment(issuer, parsed)
  ) {
    return 'An authorization server must be an https issuer URL without credentials, query or fragment';
  }
  return null;
}

/** Why `scope` is not an OAuth scope token, or null. */
export function scopeProblem(scope: string): string | null {
  return OAUTH_SCOPE_TOKEN.test(scope)
    ? null
    : 'A scope is 1 to 256 printable characters without spaces, quotes or backslashes';
}

/** True when the JWT Bearer method sends the token in the `Authorization` header, as `buildPayload` writes it. */
export function readsAuthorizationHeader(config: Record<string, unknown>): boolean {
  const header = typeof config.jwt_token_header === 'string' ? config.jwt_token_header : '';
  return (header.trim() || 'Authorization').toLowerCase() === 'authorization';
}

/**
 * True when the JWT Bearer method expects the `Bearer` scheme exactly, as
 * `buildPayload` writes it: the gateway matches the scheme as written.
 */
export function usesBearerScheme(config: Record<string, unknown>): boolean {
  const scheme = typeof config.jwt_token_scheme === 'string' ? config.jwt_token_scheme : 'Bearer';
  return scheme === 'Bearer';
}

/**
 * Every problem the gateway would refuse the discovery setting of a
 * caller-auth config for, in field order. Empty when discovery is off or the
 * method is not JWT Bearer, whose payload carries no setting. `strategyIssuer`
 * is the expected issuer of the selected JWT verification strategy, when known:
 * the authorization servers must be exactly that issuer.
 */
export function discoveryProblems(
  config: Record<string, unknown>,
  strategyIssuer?: string
): DiscoveryProblem[] {
  const setting = readProtectedResource(config.protected_resource);
  if (!setting || config.method_type !== 'jwt_bearer') return [];
  const problems: DiscoveryProblem[] = [];
  if (!readsAuthorizationHeader(config) || !usesBearerScheme(config)) {
    problems.push({
      field: DISCOVERY_FIELDS.rules,
      message:
        'Authorization server discovery needs the token in the Authorization header with the Bearer scheme',
    });
  }
  if (config.jwt_forward_header === true) {
    problems.push({
      field: DISCOVERY_FIELDS.rules,
      message:
        "Authorization server discovery cannot forward the caller's token to the managed agent",
    });
  }
  if (stringList(config.audiences).length > 0) {
    problems.push({
      field: DISCOVERY_FIELDS.rules,
      message:
        'Authorization server discovery needs Accepted Audiences to be empty: the token audience must be the resource URL',
    });
  }
  const resourceError = resourceProblem(setting.resource);
  if (resourceError) problems.push({ field: DISCOVERY_FIELDS.resource, message: resourceError });
  const servers = setting.authorization_servers;
  if (servers.length === 0 || servers.length > MAX_AUTHORIZATION_SERVERS) {
    problems.push({
      field: DISCOVERY_FIELDS.authorizationServers,
      message: `List 1 to ${MAX_AUTHORIZATION_SERVERS} authorization servers`,
    });
  } else {
    const invalid = servers.map(authorizationServerProblem).find(Boolean);
    if (invalid) {
      problems.push({ field: DISCOVERY_FIELDS.authorizationServers, message: invalid });
    } else if (new Set(servers).size !== servers.length) {
      problems.push({
        field: DISCOVERY_FIELDS.authorizationServers,
        message: 'List each authorization server once',
      });
    } else if (strategyIssuer && (servers.length !== 1 || servers[0] !== strategyIssuer)) {
      problems.push({
        field: DISCOVERY_FIELDS.authorizationServers,
        message: `List only ${strategyIssuer}, the issuer the JWT verification strategy trusts: tokens from any other server are refused`,
      });
    }
  }
  const scopeError =
    setting.scopes.length > MAX_SCOPES
      ? `List at most ${MAX_SCOPES} scopes`
      : setting.scopes.map(scopeProblem).find(Boolean);
  if (scopeError) problems.push({ field: DISCOVERY_FIELDS.scopes, message: scopeError });
  return problems;
}

/** True when the resource URL's path is not the Access Point route exactly. */
export function resourceMissesRoute(resource: string, route: unknown): boolean {
  if (typeof route !== 'string' || !route) return false;
  const parsed = parseUrl(resource);
  return !!parsed && parsed.pathname !== route;
}

/**
 * The resource to suggest: the public origin of the Access Point's listener
 * followed by its route. Empty when the listener is not an https URL or no
 * route is set, so the operator writes it.
 */
export function suggestedResource(listenAddress: unknown, route: unknown): string {
  if (typeof listenAddress !== 'string' || typeof route !== 'string' || !route.startsWith('/')) {
    return '';
  }
  const listener = parseUrl(listenAddress);
  if (!listener || listener.protocol !== 'https:') return '';
  const composed = parseUrl(`${listener.origin}${route}`);
  return composed ? composed.href : '';
}

/** The resource a variant advertises: the surface resource with `$<alias>`. */
export function variantResource(resource: string, alias: string): string {
  return `${resource}$${alias}`;
}

/**
 * The failed-save message when it is about this discovery setting: a
 * `protected_resource` rule, or a resource-ownership refusal naming this
 * resource or one of its variants. Null otherwise.
 */
export function discoverySaveError(
  error: string | null | undefined,
  resource: string | undefined
): string | null {
  if (!error) return null;
  if (error.includes('caller_authentication.protected_resource')) return error;
  const named = /^MCP resource '([^']*)'/.exec(error)?.[1];
  if (named && resource && (named === resource || named.startsWith(`${resource}$`))) return error;
  return null;
}

/** The protocols whose Access Point can declare its authorization server. */
export const DECLARING_PROTOCOLS: readonly Protocol[] = ['a2a', 'ap2', 'mcp'];

export function declaresOn(protocol: Protocol | undefined): boolean {
  return !!protocol && DECLARING_PROTOCOLS.includes(protocol);
}

/** The fields of a JWT verification strategy a derived declaration reads. */
export interface DeclarationStrategy {
  id: string;
  expected_issuer?: string;
  jwks_source?: unknown;
  authorization_server?: unknown;
}

export type StrategyPin =
  | { state: 'pinned'; issuer: string }
  | { state: 'not_pinned' }
  | { state: 'static_jwks' }
  | { state: 'mismatch'; issuer: string };

/**
 * The authorization server a derived declaration names: the strategy's pinned
 * issuer, while the pin still matches its expected issuer and JWKS URI.
 */
export function strategyPin(strategy: DeclarationStrategy): StrategyPin {
  const source = asRecord(strategy.jwks_source);
  if (source?.type === 'static') return { state: 'static_jwks' };
  const pin = asRecord(strategy.authorization_server);
  const issuer = typeof pin?.issuer === 'string' ? pin.issuer : '';
  if (!issuer) return { state: 'not_pinned' };
  const jwksUri = typeof source?.jwks_uri === 'string' ? source.jwks_uri : undefined;
  const issuerMoved =
    typeof strategy.expected_issuer === 'string' && issuer !== strategy.expected_issuer;
  const jwksMoved = jwksUri !== undefined && pin?.jwks_uri !== jwksUri;
  return issuerMoved || jwksMoved ? { state: 'mismatch', issuer } : { state: 'pinned', issuer };
}

export type DerivedNoteCode = 'custom_token_header' | 'forwards_caller_token' | 'audience_missing';

export interface DerivedNote {
  code: DerivedNoteCode;
  message: string;
}

/**
 * Why the JWT Bearer settings keep a derived declaration from being made, in
 * the gateway's order. `accessPointUrl` is the resource the gateway reported
 * for the route edited; the audience is checked only when it is known.
 */
export function derivedDeclarationNotes(
  config: Record<string, unknown>,
  accessPointUrl?: string | null
): DerivedNote[] {
  const notes: DerivedNote[] = [];
  const header = typeof config.jwt_token_header === 'string' ? config.jwt_token_header : '';
  const scheme = typeof config.jwt_token_scheme === 'string' ? config.jwt_token_scheme : 'Bearer';
  if (
    (header.trim() || 'Authorization').toLowerCase() !== 'authorization' ||
    scheme.trim().toLowerCase() !== 'bearer'
  ) {
    notes.push({
      code: 'custom_token_header',
      message:
        'The token must arrive in the Authorization header with the Bearer scheme for this Access Point to declare its authorization server.',
    });
  }
  if (config.jwt_forward_header === true) {
    notes.push({
      code: 'forwards_caller_token',
      message:
        "Forwarding the caller's token to the managed agent keeps this Access Point from declaring its authorization server.",
    });
  }
  if (accessPointUrl && !stringList(config.audiences).includes(accessPointUrl)) {
    notes.push({
      code: 'audience_missing',
      message:
        'Add the Access Point URL to Accepted Audiences so this Access Point declares its authorization server.',
    });
  }
  return notes;
}

/** The entry of the route edited: the base for no alias, otherwise that variant. */
export function declarationForVariant<T extends { variant: string | null }>(
  declarations: readonly T[],
  alias: string | undefined
): T | undefined {
  return declarations.find(d => d.variant === (alias ?? null));
}

function storedCallerAuthentication(accessPoint: unknown): Record<string, unknown> | null {
  return asRecord(asRecord(accessPoint)?.caller_authentication);
}

function dropsSetting(stored: unknown, next: unknown): boolean {
  const before = storedCallerAuthentication(stored);
  const after = storedCallerAuthentication(next);
  return !!before?.protected_resource && !!after && after.protected_resource == null;
}

function variantAccessPoints(surface: Partial<AgentSurface>): Map<string, unknown> {
  const out = new Map<string, unknown>();
  for (const variant of surface.variants ?? []) {
    out.set(variant.id, asRecord(variant.overrides)?.access_point);
  }
  return out;
}

export interface ProtectedResourceRemovals {
  base: boolean;
  variantIds: string[];
}

/**
 * The stored discovery settings a save would leave out of a
 * `caller_authentication` it still sends. A PUT that omits the setting keeps
 * the stored one, so these must be removed explicitly.
 */
export function protectedResourceRemovals(
  stored: Partial<AgentSurface>,
  next: Partial<AgentSurface>
): ProtectedResourceRemovals {
  const nextVariants = variantAccessPoints(next);
  const variantIds: string[] = [];
  variantAccessPoints(stored).forEach((accessPoint, id) => {
    if (nextVariants.has(id) && dropsSetting(accessPoint, nextVariants.get(id))) {
      variantIds.push(id);
    }
  });
  return { base: dropsSetting(stored.access_point, next.access_point), variantIds };
}

function withoutSetting(accessPoint: unknown): Record<string, unknown> {
  const record = asRecord(accessPoint) ?? {};
  return {
    ...record,
    caller_authentication: { ...storedCallerAuthentication(record), protected_resource: null },
  };
}

/**
 * The save payload with `protected_resource: null` in each
 * `caller_authentication` that leaves out a stored discovery setting, so the
 * PUT removes it in the same request as the rest of the edit: a failed save
 * changes nothing.
 */
export function withDroppedProtectedResourcesRemoved(
  stored: Partial<AgentSurface>,
  next: Partial<AgentSurface>
): Partial<AgentSurface> {
  const removals = protectedResourceRemovals(stored, next);
  return {
    ...next,
    ...(removals.base
      ? { access_point: withoutSetting(next.access_point) as AgentSurface['access_point'] }
      : {}),
    ...(removals.variantIds.length > 0
      ? {
          variants: (next.variants ?? []).map(variant =>
            removals.variantIds.includes(variant.id)
              ? {
                  ...variant,
                  overrides: {
                    ...variant.overrides,
                    access_point: withoutSetting(variant.overrides?.access_point),
                  },
                }
              : variant
          ),
        }
      : {}),
  };
}
