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
