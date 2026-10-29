import { parseSurfaceDeclarations, type SurfaceDeclaration } from './surfaceDeclarations';

export const CARD_FETCH_STATUSES = ['ok', 'failed', 'not_served'] as const;
export type CardFetchStatus = (typeof CARD_FETCH_STATUSES)[number];

export const CARD_FETCH_CAUSES = [
  'needs_token',
  'auth_failed',
  'forbidden',
  'not_found',
  'redirected',
  'upstream_error',
  'unreachable',
  'timeout',
  'too_large',
  'invalid_card',
  'blocked_by_egress',
  'proxy_unavailable',
  'identity_failed',
  'rewrite_failed',
] as const;
export type CardFetchCause = (typeof CARD_FETCH_CAUSES)[number];

export const CARD_AUTH_KINDS = [
  'none',
  'static_secret',
  'credential_provider',
  'credential_lookup',
  'remote_gateway',
] as const;
export type CardAuthKind = (typeof CARD_AUTH_KINDS)[number];

export const CARD_AUTH_RESULTS = ['not_configured', 'sent', 'not_sent', 'failed'] as const;
export type CardAuthResult = (typeof CARD_AUTH_RESULTS)[number];

export const CARD_AUTH_FAILURES = [
  'secret_unavailable',
  'provider_not_found',
  'token_unavailable',
  'forbidden',
  'unsupported',
  'invalid_header',
  'outside_target_base',
  'header_conflict',
] as const;
export type CardAuthFailure = (typeof CARD_AUTH_FAILURES)[number];

export const UNSUPPORTED_REASONS = ['not_a2a', 'not_running'] as const;
export type CardUnsupportedReason = (typeof UNSUPPORTED_REASONS)[number];

export interface CardFetch {
  status: CardFetchStatus;
  cause: CardFetchCause | null;
  http_status: number | null;
  duration_ms: number;
}

export interface CardAuthReport {
  kind: CardAuthKind;
  result: CardAuthResult;
  provider_name: string | null;
  token_expires_at: string | null;
  failure: CardAuthFailure | null;
}

export interface CallerCardFetch {
  status: CardFetchStatus;
  cause: CardFetchCause | null;
  http_status: number | null;
  at: string | null;
}

export type CardJson = Record<string, unknown>;

export interface UnsupportedAgentCardPreview {
  supported: false;
  surface_id: string;
  unsupported_reason: CardUnsupportedReason;
}

export interface SupportedAgentCardPreview {
  supported: true;
  surface_id: string;
  generated: boolean;
  served_url: string | null;
  source_url: string | null;
  source_url_query_hidden: boolean;
  fetched_at: string | null;
  cached: boolean;
  fetch: CardFetch;
  auth: CardAuthReport;
  payment_required: boolean;
  outcome: SurfaceDeclaration | null;
  before: CardJson | null;
  after: CardJson | null;
  before_bytes: number | null;
  after_bytes: number | null;
  display_limit_bytes: number;
  last_caller_fetch: CallerCardFetch | null;
}

export type AgentCardPreview = UnsupportedAgentCardPreview | SupportedAgentCardPreview;

export const DEFAULT_DISPLAY_LIMIT_BYTES = 262144;

export type RefreshResult =
  | { kind: 'ok'; preview: AgentCardPreview }
  | { kind: 'rate_limited' }
  | { kind: 'forbidden' }
  | { kind: 'error' };

type Fetcher = (url: string, init?: RequestInit) => Promise<Response>;

const isRecord = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v);
const asString = (v: unknown): string | null => (typeof v === 'string' ? v : null);
const asNumber = (v: unknown): number | null =>
  typeof v === 'number' && Number.isFinite(v) ? v : null;
const asBool = (v: unknown): boolean => v === true;

function oneOf<T extends string>(list: readonly T[], v: unknown): T | null {
  return typeof v === 'string' && (list as readonly string[]).includes(v) ? (v as T) : null;
}

function parseFetch(raw: unknown): CardFetch | null {
  if (!isRecord(raw)) return null;
  const status = oneOf(CARD_FETCH_STATUSES, raw.status);
  if (!status) return null;
  const cause =
    raw.cause === null || raw.cause === undefined ? null : oneOf(CARD_FETCH_CAUSES, raw.cause);
  if (raw.cause !== null && raw.cause !== undefined && !cause) return null;
  if ((status === 'ok') !== (cause === null)) return null;
  return {
    status,
    cause,
    http_status: asNumber(raw.http_status),
    duration_ms: asNumber(raw.duration_ms) ?? 0,
  };
}

function parseAuth(raw: unknown): CardAuthReport | null {
  if (!isRecord(raw)) return null;
  const kind = oneOf(CARD_AUTH_KINDS, raw.kind);
  const result = oneOf(CARD_AUTH_RESULTS, raw.result);
  if (!kind || !result) return null;
  const failure =
    raw.failure === null || raw.failure === undefined
      ? null
      : oneOf(CARD_AUTH_FAILURES, raw.failure);
  if (raw.failure !== null && raw.failure !== undefined && !failure) return null;
  return {
    kind,
    result,
    provider_name: asString(raw.provider_name),
    token_expires_at: asString(raw.token_expires_at),
    failure,
  };
}

function parseCallerFetch(raw: unknown): CallerCardFetch | null {
  if (!isRecord(raw)) return null;
  const status = oneOf(CARD_FETCH_STATUSES, raw.status);
  if (!status) return null;
  const cause = oneOf(CARD_FETCH_CAUSES, raw.cause);
  return { status, cause, http_status: asNumber(raw.http_status), at: asString(raw.at) };
}

function parseOutcome(raw: unknown): SurfaceDeclaration | null {
  if (!isRecord(raw)) return null;
  return parseSurfaceDeclarations({ declarations: [raw] }).declarations[0] ?? null;
}

export function parseAgentCardPreview(body: unknown): AgentCardPreview | null {
  if (!isRecord(body)) return null;
  const surface_id = asString(body.surface_id);
  if (surface_id === null) return null;
  if (body.supported === false) {
    const unsupported_reason = oneOf(UNSUPPORTED_REASONS, body.unsupported_reason);
    return unsupported_reason ? { supported: false, surface_id, unsupported_reason } : null;
  }
  if (body.supported !== true) return null;
  const fetch = parseFetch(body.fetch);
  const auth = parseAuth(body.auth);
  if (!fetch || !auth) return null;
  return {
    supported: true,
    surface_id,
    generated: asBool(body.generated),
    served_url: asString(body.served_url),
    source_url: asString(body.source_url),
    source_url_query_hidden: asBool(body.source_url_query_hidden),
    fetched_at: asString(body.fetched_at),
    cached: asBool(body.cached),
    fetch,
    auth,
    payment_required: asBool(body.payment_required),
    outcome: parseOutcome(body.outcome),
    before: isRecord(body.before) ? body.before : null,
    after: isRecord(body.after) ? body.after : null,
    before_bytes: asNumber(body.before_bytes),
    after_bytes: asNumber(body.after_bytes),
    display_limit_bytes: asNumber(body.display_limit_bytes) ?? DEFAULT_DISPLAY_LIMIT_BYTES,
    last_caller_fetch: parseCallerFetch(body.last_caller_fetch),
  };
}

const cardUrl = (surfaceId: string) =>
  `/api/v1/surfaces/${encodeURIComponent(surfaceId)}/agent-card`;

export async function fetchAgentCardPreview(
  fetcher: Fetcher,
  surfaceId: string
): Promise<AgentCardPreview | null> {
  try {
    const response = await fetcher(cardUrl(surfaceId));
    if (!response.ok) return null;
    return parseAgentCardPreview(await response.json());
  } catch {
    return null;
  }
}

export async function refreshAgentCardPreview(
  fetcher: Fetcher,
  surfaceId: string
): Promise<RefreshResult> {
  try {
    const response = await fetcher(`${cardUrl(surfaceId)}/refresh`, { method: 'POST' });
    if (response.status === 429) return { kind: 'rate_limited' };
    if (response.status === 403) return { kind: 'forbidden' };
    if (!response.ok) return { kind: 'error' };
    const preview = parseAgentCardPreview(await response.json());
    return preview ? { kind: 'ok', preview } : { kind: 'error' };
  } catch {
    return { kind: 'error' };
  }
}

export function safeHttpUrl(value: unknown): string | null {
  if (typeof value !== 'string' || value.trim() === '') return null;
  try {
    const url = new URL(value);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    if (url.username || url.password) return null;
    return url.href;
  } catch {
    return null;
  }
}

export const CARD_FETCH_CAUSE_LABEL: Record<CardFetchCause, string> = {
  needs_token: 'Needs a token',
  auth_failed: 'Sign-in failed',
  forbidden: 'Refused',
  not_found: 'No card found',
  redirected: 'Redirected',
  upstream_error: 'Agent error',
  unreachable: 'Unreachable',
  timeout: 'Timed out',
  too_large: 'Card too large',
  invalid_card: 'Not an agent card',
  blocked_by_egress: 'Address not resolvable or not allowed',
  proxy_unavailable: 'A2A proxy unavailable',
  identity_failed: 'Identity failed',
  rewrite_failed: 'Rewrite failed',
};

export const CARD_FETCH_CAUSE_TEXT: Record<CardFetchCause, string> = {
  needs_token:
    'The agent asked for a token (HTTP 401) and the gateway sent none. Set Target Authentication on the Managed Agent.',
  auth_failed: 'The gateway could not get its credential, so it did not ask the agent.',
  forbidden:
    'The agent refused the gateway (HTTP 403). Its token may lack a scope or role the agent needs.',
  not_found: 'The agent has no card at this URL (HTTP {s}). Check the agent card location.',
  redirected:
    'The agent redirected the card request. The gateway does not follow redirects when it sends a credential. Set the agent card location to the final URL.',
  upstream_error: 'The agent answered HTTP {s}. Check the agent logs, then Refresh.',
  unreachable: 'The gateway could not reach the agent. Check the endpoint URL and the network.',
  timeout: 'The agent did not answer in time. Check that the agent is running, then Refresh.',
  too_large: "The agent's card is larger than the gateway accepts. Shrink the agent card.",
  invalid_card: "The agent's answer is not a JSON agent card. Check the agent card location.",
  blocked_by_egress:
    "The gateway could not resolve the agent's host name, or it resolves to a cloud metadata address, which the gateway never calls. Check the endpoint host name and DNS from the gateway host, then Refresh.",
  proxy_unavailable: 'The A2A proxy behind this surface is missing or disabled.',
  identity_failed:
    "The gateway could not attach the agent's identity to the card. Check the gateway logs, then Refresh.",
  rewrite_failed:
    "The gateway could not rewrite the card's URLs and security. Check the gateway logs, then Refresh.",
};

export const AUTH_FAILED_ACTION_TEXT = 'Check Target Authentication on the Managed Agent.';

export const CARD_REJECTED_CREDENTIAL_TEXT =
  "The agent rejected the gateway's credential (HTTP 401). Check the provider's scopes and audience.";

export const AUTH_FAILURE_TEXT: Record<CardAuthFailure, string> = {
  secret_unavailable: 'A secret the credential needs is missing.',
  provider_not_found: 'The credential provider no longer exists.',
  token_unavailable: 'The provider did not issue a token.',
  forbidden: 'The credential belongs to another tenant.',
  unsupported: 'This provider type cannot sign in to a Target.',
  invalid_header: 'The credential does not form a valid header.',
  outside_target_base: 'The card URL is outside the Target base.',
  header_conflict: "Another header already uses the credential's header name.",
};

export function describeFetchFailure(fetch: {
  cause: CardFetchCause | null;
  http_status: number | null;
}): string | null {
  if (!fetch.cause) return null;
  const label = CARD_FETCH_CAUSE_LABEL[fetch.cause];
  return fetch.http_status !== null ? `${label} — HTTP ${fetch.http_status}` : label;
}

export function describeFetchCause(fetch: CardFetch, auth: CardAuthReport): string {
  const cause = fetch.cause;
  if (!cause) return '';
  if (cause === 'auth_failed') {
    if (auth.result === 'sent') return CARD_REJECTED_CREDENTIAL_TEXT;
    const reason = auth.failure ? AUTH_FAILURE_TEXT[auth.failure] : null;
    return [CARD_FETCH_CAUSE_TEXT.auth_failed, reason, AUTH_FAILED_ACTION_TEXT]
      .filter(Boolean)
      .join(' ');
  }
  const text = CARD_FETCH_CAUSE_TEXT[cause];
  if (!text.includes('{s}')) return text;
  if (fetch.http_status !== null) return text.replace('{s}', String(fetch.http_status));
  return cause === 'not_found'
    ? 'The agent has no card at this URL. Check the agent card location.'
    : 'The agent answered with an error status. Check the agent logs, then Refresh.';
}

export function formatRelativeTime(iso: string | null, now: number = Date.now()): string | null {
  if (!iso) return null;
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return null;
  const seconds = Math.max(0, Math.round((now - then) / 1000));
  if (seconds < 10) return 'just now';
  if (seconds < 60) return `${seconds} seconds ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return minutes === 1 ? '1 minute ago' : `${minutes} minutes ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return hours === 1 ? '1 hour ago' : `${hours} hours ago`;
  const days = Math.round(hours / 24);
  return days === 1 ? '1 day ago' : `${days} days ago`;
}

export function formatLocalTime(iso: string | null): string | null {
  if (!iso) return null;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? null : date.toLocaleString();
}

export function describeCardAuth(auth: CardAuthReport): string {
  if (auth.kind === 'remote_gateway') return 'The remote gateway signs in';
  if (auth.kind === 'none' || auth.result === 'not_configured') return 'No Target Authentication';
  if (auth.result === 'failed') return 'Credential not obtained';
  if (auth.result !== 'sent') return 'No credential sent';
  if (auth.kind === 'static_secret') return 'Static secret';
  if (auth.kind === 'credential_lookup') return 'Looked-up credential';
  const name = auth.provider_name ?? 'Credential provider';
  const expires = formatLocalTime(auth.token_expires_at);
  return expires ? `${name}, token valid until ${expires}` : name;
}

export const CARD_FETCH_STATUS_LABEL: Record<CardFetchStatus, string> = {
  ok: 'OK',
  failed: 'Failing',
  not_served: 'Not served',
};
