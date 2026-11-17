import { formatDateTime, topAndTail } from '../../utils/stringUtils';
import { CONSENT_LIMIT_RANGE, takesConsent } from '../../utils/consentLimit';

/** An agent-keyed vault token as `GET /api/v1/delegation-vault` lists it; never a secret. */
export interface DelegationToken {
  id: string;
  agent_did: string;
  user_identity_hash: string;
  credential_provider_id: string;
  provider_id: string;
  token_type: string;
  scopes: string[];
  expires_at: string | null;
  consent_granted_at: string;
  /** When the consent ends under its time limit; absent without one. */
  consent_expires_at?: string | null;
  last_used_at: string | null;
  created_at: string;
  updated_at: string;
  is_expired: boolean;
  can_refresh: boolean;
}

/** What the credential tabs read of a provider in `GET /api/v1/credential-providers`. */
export interface ProviderSummary {
  id: string;
  name: string;
  provider_type?: string;
  token_refresh_enabled?: boolean;
  /** Set once the provider takes no new consent. */
  deactivated_at?: string | null;
}

/** A token's provider by its name, else by its `provider_id` when the provider is unknown. */
export function providerName(
  token: Pick<DelegationToken, 'credential_provider_id' | 'provider_id'>,
  providers: Record<string, Pick<ProviderSummary, 'name'>>
): string {
  return providers[token.credential_provider_id]?.name ?? token.provider_id;
}

/** Where a stored consent stands against its time limit. */
export type ConsentState = 'unlimited' | 'limited' | 'ending_soon' | 'ended';

/** A consent that ends within this long is shown as ending soon. */
const ENDING_SOON_MS = 24 * 60 * 60 * 1000;

const MINUTE_MS = 60 * 1000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

/** The end of a consent as the vault reports it; `null` for one without a time limit. */
export function consentEnd(consentExpiresAt: string | null | undefined): Date | null {
  if (!consentExpiresAt) return null;
  const end = new Date(consentExpiresAt);
  return Number.isNaN(end.getTime()) ? null : end;
}

export function consentState(end: Date | null, now: Date): ConsentState {
  if (!end) return 'unlimited';
  const left = end.getTime() - now.getTime();
  if (left <= 0) return 'ended';
  return left <= ENDING_SOON_MS ? 'ending_soon' : 'limited';
}

/**
 * Whether an agent can still act under a delegation: its consent has not ended, and its access
 * token is valid or can be refreshed.
 */
export function isActiveDelegation(
  token: Pick<DelegationToken, 'consent_expires_at' | 'is_expired' | 'can_refresh'>,
  now: Date
): boolean {
  if (consentState(consentEnd(token.consent_expires_at), now) === 'ended') return false;
  return !token.is_expired || token.can_refresh;
}

/**
 * The time limit that applies to a consent, in seconds: from its consent time to the end the vault
 * reports, which is the sooner one when the limit was shortened since. `null` for a consent
 * without a time limit.
 */
export function consentLimitSecs(
  token: Pick<DelegationToken, 'consent_granted_at' | 'consent_expires_at'>
): number | null {
  const end = consentEnd(token.consent_expires_at);
  const granted = new Date(token.consent_granted_at).getTime();
  if (!end || Number.isNaN(granted)) return null;
  const secs = Math.round((end.getTime() - granted) / 1000);
  return secs > 0 ? secs : null;
}

/** What limiting one consent to a time after it was given would do. */
export type LimitOutcome =
  /** No limit the gateway takes was given. */
  | { kind: 'invalid' }
  /** The consent is already older than the limit: ending it now is a revoke. */
  | { kind: 'already_older' }
  /** The consent already ends at `end`, at the limit's end or before it. */
  | { kind: 'not_sooner'; end: Date }
  /** The consent would end at `end`, sooner than it does now. */
  | { kind: 'ends'; end: Date };

/**
 * What limiting the consent of `token` to `limitSecs` after it was given would do at `now`, by
 * the rule the gateway applies: a limit only brings the end forward, to a time still ahead.
 */
export function limitOutcome(
  token: Pick<DelegationToken, 'consent_granted_at' | 'consent_expires_at'>,
  limitSecs: number | null,
  now: Date
): LimitOutcome {
  const granted = new Date(token.consent_granted_at).getTime();
  if (limitSecs === null || Number.isNaN(granted)) return { kind: 'invalid' };
  const end = new Date(granted + limitSecs * 1000);
  if (end.getTime() <= now.getTime()) return { kind: 'already_older' };
  const current = consentEnd(token.consent_expires_at);
  return current && end.getTime() >= current.getTime()
    ? { kind: 'not_sooner', end: current }
    : { kind: 'ends', end };
}

/** What the limit panel says a limit would do, before anything is sent. */
export function limitOutcomeText(
  outcome: LimitOutcome,
  consentGrantedAt: string,
  now: Date
): string {
  switch (outcome.kind) {
    case 'invalid':
      return `Enter a whole number from ${CONSENT_LIMIT_RANGE}.`;
    case 'already_older':
      return 'This consent is already older than that. Use Revoke to end it now.';
    case 'not_sooner':
      return `It already ends ${formatDateTime(outcome.end, true)}. A limit only brings the end forward.`;
    case 'ends':
      return `Consent given ${formatDateTime(consentGrantedAt, true)}. With this limit it ends ${formatDateTime(outcome.end, true)} (${timeLeft(outcome.end, now)}).`;
  }
}

/**
 * Whether a token is a person's delegation and not a service token, which is one of a provider
 * nobody consents to. A token whose provider is unknown counts, since its provider may only be
 * unreadable.
 */
export function isPersonsDelegation(
  token: Pick<DelegationToken, 'credential_provider_id'>,
  providers: Record<string, Pick<ProviderSummary, 'provider_type'>>
): boolean {
  const type = providers[token.credential_provider_id]?.provider_type;
  return !type || takesConsent(type);
}

/**
 * Whether an operator can limit a delegation: a consent a person gave, to an Authorization Code
 * provider, that an agent can still act under.
 */
export function canLimitConsent(
  token: Pick<DelegationToken, 'consent_expires_at' | 'is_expired' | 'can_refresh'>,
  provider: Pick<ProviderSummary, 'provider_type'> | undefined,
  now: Date
): boolean {
  return takesConsent(provider?.provider_type) && isActiveDelegation(token, now);
}

/**
 * Whether the gateway renews a delegation's access token by itself: its provider refreshes
 * tokens, a refresh token is stored, and the consent has not ended.
 */
export function renewsAutomatically(
  token: Pick<DelegationToken, 'can_refresh' | 'consent_expires_at'>,
  provider: Pick<ProviderSummary, 'token_refresh_enabled'> | undefined,
  now: Date
): boolean {
  if (!provider?.token_refresh_enabled || !token.can_refresh) return false;
  return consentState(consentEnd(token.consent_expires_at), now) !== 'ended';
}

const DID_WEB = 'did:web:';

/** Control and invisible formatting characters, which can reorder or hide what a name shows. */
const UNPRINTABLE = /[\p{Cc}\p{Cf}]/u;

/**
 * A `did:web` part as it is shown: its port's `%3A` as `:`. `null` for a part that holds any
 * other escape or an unprintable character, since decoding it could show a name the DID does
 * not spell.
 */
function shownDidWebPart(part: string): string | null {
  const shown = part.replace(/%3A/gi, ':');
  return !shown || shown.includes('%') || UNPRINTABLE.test(shown) ? null : shown;
}

/**
 * An agent's DID as both tabs show it: a `did:web` DID as its whole web address, the host and
 * any path ("pr-reviewer.example.com", "agents.example.com/tenants/sales"), never cut; any other
 * DID, and a `did:web` one with an escape other than its port's, shortened in the middle. The
 * full DID belongs in the tooltip.
 */
export function agentName(did: string): string {
  const parts = did.startsWith(DID_WEB)
    ? did.slice(DID_WEB.length).split(':').map(shownDidWebPart)
    : [];
  return parts.length > 0 && parts.every(part => part !== null)
    ? parts.join('/')
    : topAndTail(did, 12, 12);
}

/** Whether `token` matches `term`, a trimmed lower-case search over what the tabs show of it. */
export function matchesSearch(
  token: DelegationToken,
  providers: Record<string, Pick<ProviderSummary, 'name'>>,
  term: string
): boolean {
  return (
    !term ||
    providerName(token, providers).toLowerCase().includes(term) ||
    token.provider_id.toLowerCase().includes(term) ||
    token.agent_did.toLowerCase().includes(term) ||
    agentName(token.agent_did).toLowerCase().includes(term) ||
    token.user_identity_hash.toLowerCase().includes(term) ||
    token.scopes.some(scope => scope.toLowerCase().includes(term))
  );
}

/** A token's status on the Credential Tokens tab, and the tone of the badge that shows it. */
export interface TokenStatus {
  label: string;
  tone: 'success' | 'warning' | 'danger' | 'secondary';
}

/**
 * The consent's state while it is ending or has ended; otherwise the access token's own:
 * active, expired but refreshable, or expired.
 */
export function tokenStatus(
  token: Pick<DelegationToken, 'consent_expires_at' | 'is_expired' | 'can_refresh'>,
  now: Date
): TokenStatus {
  const consent = consentState(consentEnd(token.consent_expires_at), now);
  if (consent === 'ended') return { label: 'Consent ended', tone: 'secondary' };
  if (consent === 'ending_soon') return { label: 'Ending soon', tone: 'warning' };
  if (token.is_expired) {
    return token.can_refresh
      ? { label: 'Expired (refreshable)', tone: 'warning' }
      : { label: 'Expired', tone: 'danger' };
  }
  return { label: 'Active', tone: 'success' };
}

/** The end of a token's consent as the list says it: "Ends <date> (in 3 hours)". */
export function consentEndSentence(
  token: Pick<DelegationToken, 'consent_expires_at'>,
  now: Date
): string {
  const end = consentEnd(token.consent_expires_at);
  if (!end) return 'No time limit';
  const date = formatDateTime(end, true);
  return consentState(end, now) === 'ended'
    ? `Ended ${date}`
    : `Ends ${date} (${timeLeft(end, now)})`;
}

/** The end of a token's consent as a value, the date first: "<date> (in 3 hours)". */
export function consentEndValue(
  token: Pick<DelegationToken, 'consent_expires_at'>,
  now: Date
): string {
  const end = consentEnd(token.consent_expires_at);
  if (!end) return 'No time limit';
  const date = formatDateTime(end, true);
  return consentState(end, now) === 'ended' ? `${date} (ended)` : `${date} (${timeLeft(end, now)})`;
}

/** A time the vault reports as the tabs show it, or a dash for one it does not have. */
export function shownTime(value: string | null | undefined): string {
  return value ? formatDateTime(value, true) : '—';
}

/** The confirm of revoking every delegation of a user, which says how many (`count`) it ends. */
export function revokeAllLabel(count: number): string {
  return count === 1 ? "Revoke this user's only delegation?" : `Revoke all ${count} for this user?`;
}

/** How long until `end`, in the largest unit that has passed whole: "in 3 hours", "in 12 days". */
export function timeLeft(end: Date, now: Date): string {
  const left = end.getTime() - now.getTime();
  if (left < MINUTE_MS) return 'in under a minute';
  const [count, unit] =
    left < HOUR_MS
      ? [Math.floor(left / MINUTE_MS), 'minute']
      : left < 2 * DAY_MS
        ? [Math.floor(left / HOUR_MS), 'hour']
        : [Math.floor(left / DAY_MS), 'day'];
  return `in ${count} ${unit}${count === 1 ? '' : 's'}`;
}
