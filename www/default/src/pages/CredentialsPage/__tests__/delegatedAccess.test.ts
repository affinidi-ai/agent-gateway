import {
  agentName,
  canLimitConsent,
  consentEnd,
  consentEndSentence,
  consentEndValue,
  consentLimitSecs,
  consentState,
  isActiveDelegation,
  isPersonsDelegation,
  limitOutcome,
  limitOutcomeText,
  matchesSearch,
  renewsAutomatically,
  revokeAllLabel,
  timeLeft,
  tokenStatus,
} from '../delegatedAccess';
import { formatDateTime } from '../../../utils/stringUtils';

const NOW = new Date('2026-11-13T10:00:00Z');
const after = (ms: number) => new Date(NOW.getTime() + ms);
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

describe('delegated access consent end', () => {
  it('reads the end the vault reports, and none when there is no limit', () => {
    expect(consentEnd('2026-11-13T16:00:00Z')).toEqual(new Date('2026-11-13T16:00:00Z'));
    expect(consentEnd(null)).toBeNull();
    expect(consentEnd(undefined)).toBeNull();
    expect(consentEnd('')).toBeNull();
    expect(consentEnd('not a time')).toBeNull();
  });

  it('tells a consent that ended from one ending within a day and one that lasts longer', () => {
    expect(consentState(null, NOW)).toBe('unlimited');
    expect(consentState(after(-1), NOW)).toBe('ended');
    expect(consentState(after(0), NOW)).toBe('ended');
    expect(consentState(after(1), NOW)).toBe('ending_soon');
    expect(consentState(after(DAY), NOW)).toBe('ending_soon');
    expect(consentState(after(DAY + 1), NOW)).toBe('limited');
  });

  it('counts a delegation as active while its consent lasts and its token can be used', () => {
    const delegation = (
      is_expired: boolean,
      can_refresh: boolean,
      consent_expires_at?: string
    ) => ({ is_expired, can_refresh, consent_expires_at });
    const later = after(HOUR).toISOString();
    const earlier = after(-HOUR).toISOString();
    expect(isActiveDelegation(delegation(false, false), NOW)).toBe(true);
    expect(isActiveDelegation(delegation(false, true, later), NOW)).toBe(true);
    expect(isActiveDelegation(delegation(true, true, later), NOW)).toBe(true);
    expect(isActiveDelegation(delegation(true, false, later), NOW)).toBe(false);
    expect(isActiveDelegation(delegation(false, true, earlier), NOW)).toBe(false);
    expect(isActiveDelegation(delegation(true, false), NOW)).toBe(false);
  });

  it('says how long is left in the largest whole unit', () => {
    expect(timeLeft(after(30_000), NOW)).toBe('in under a minute');
    expect(timeLeft(after(MINUTE), NOW)).toBe('in 1 minute');
    expect(timeLeft(after(59 * MINUTE), NOW)).toBe('in 59 minutes');
    expect(timeLeft(after(HOUR), NOW)).toBe('in 1 hour');
    expect(timeLeft(after(3 * HOUR + 20 * MINUTE), NOW)).toBe('in 3 hours');
    expect(timeLeft(after(47 * HOUR), NOW)).toBe('in 47 hours');
    expect(timeLeft(after(2 * DAY), NOW)).toBe('in 2 days');
    expect(timeLeft(after(12 * DAY + 5 * HOUR), NOW)).toBe('in 12 days');
  });

  it('reads the limit a consent was given under from its start and end', () => {
    const limited = (granted: Date, ends?: Date | string) => ({
      consent_granted_at: granted.toISOString(),
      consent_expires_at: ends instanceof Date ? ends.toISOString() : ends,
    });
    expect(consentLimitSecs(limited(after(-2 * HOUR), after(4 * HOUR)))).toBe(21_600);
    expect(consentLimitSecs(limited(after(-HOUR), after(30 * DAY - HOUR + 1)))).toBe(2_592_000);
    expect(consentLimitSecs(limited(after(-HOUR)))).toBeNull();
    expect(consentLimitSecs(limited(after(-HOUR), 'not a time'))).toBeNull();
    expect(consentLimitSecs(limited(after(HOUR), after(HOUR)))).toBeNull();
    expect(
      consentLimitSecs({ consent_granted_at: 'not a time', consent_expires_at: NOW.toISOString() })
    ).toBeNull();
  });

  it('renews a token only while the provider refreshes, a refresh token is kept and the consent lasts', () => {
    const delegation = (can_refresh: boolean, consent_expires_at?: string) => ({
      can_refresh,
      consent_expires_at,
    });
    const refreshing = { token_refresh_enabled: true };
    const later = after(HOUR).toISOString();
    expect(renewsAutomatically(delegation(true), refreshing, NOW)).toBe(true);
    expect(renewsAutomatically(delegation(true, later), refreshing, NOW)).toBe(true);
    expect(renewsAutomatically(delegation(false, later), refreshing, NOW)).toBe(false);
    expect(
      renewsAutomatically(delegation(true, later), { token_refresh_enabled: false }, NOW)
    ).toBe(false);
    expect(renewsAutomatically(delegation(true, later), {}, NOW)).toBe(false);
    expect(renewsAutomatically(delegation(true, later), undefined, NOW)).toBe(false);
    expect(renewsAutomatically(delegation(true, after(-HOUR).toISOString()), refreshing, NOW)).toBe(
      false
    );
  });

  it('says what limiting one consent would do: bring its end forward, or nothing', () => {
    const consent = {
      consent_granted_at: after(-HOUR).toISOString(),
      consent_expires_at: after(5 * HOUR).toISOString(),
    };
    const unlimited = { consent_granted_at: after(-HOUR).toISOString() };

    expect(limitOutcome(consent, 7_200, NOW)).toEqual({ kind: 'ends', end: after(HOUR) });
    expect(limitOutcome(unlimited, 7_200, NOW)).toEqual({ kind: 'ends', end: after(HOUR) });
    expect(limitOutcome(consent, 21_600, NOW)).toEqual({
      kind: 'not_sooner',
      end: after(5 * HOUR),
    });
    expect(limitOutcome(consent, 86_400, NOW)).toEqual({
      kind: 'not_sooner',
      end: after(5 * HOUR),
    });
    expect(limitOutcome(consent, 3_600, NOW)).toEqual({ kind: 'already_older' });
    expect(limitOutcome(consent, 1_800, NOW)).toEqual({ kind: 'already_older' });
    expect(limitOutcome(consent, null, NOW)).toEqual({ kind: 'invalid' });
    expect(limitOutcome({ consent_granted_at: 'not a time' }, 7_200, NOW)).toEqual({
      kind: 'invalid',
    });
  });

  it('lets an operator limit only a consent a person gave that an agent can still act under', () => {
    const consented = { provider_type: 'oauth2_authorization_code' };
    const active = { is_expired: false, can_refresh: true };

    expect(canLimitConsent(active, consented, NOW)).toBe(true);
    expect(
      canLimitConsent({ ...active, consent_expires_at: after(HOUR).toISOString() }, consented, NOW)
    ).toBe(true);
    expect(
      canLimitConsent({ ...active, consent_expires_at: after(-1).toISOString() }, consented, NOW)
    ).toBe(false);
    expect(canLimitConsent({ is_expired: true, can_refresh: false }, consented, NOW)).toBe(false);
    expect(canLimitConsent(active, { provider_type: 'oauth2_client_credentials' }, NOW)).toBe(
      false
    );
    expect(canLimitConsent(active, undefined, NOW)).toBe(false);
  });

  it('shows the raw DID, shortened, when decoding it could show another name', () => {
    const spoofed = 'did:web:evil.example:%E2%80%AEmoc.knab-doog';
    expect(agentName(spoofed)).toBe('did:web:evil...oc.knab-doog');
    expect(agentName('did:web:host.example:a%2Fb')).toBe('did:web:host.example:a%2Fb');
    expect(agentName('did:web:odd%zz.example.com')).toBe('did:web:odd%zz.example.com');
    expect(agentName('did:web:host.example:pa\u202Eth-of-a-longer-name')).toBe(
      'did:web:host...-longer-name'
    );
  });

  it('finds a token by its provider, agent, user or scope', () => {
    const token = {
      id: 't1',
      agent_did: 'did:web:PR-Reviewer.example.com',
      user_identity_hash: 'sha256:ABCDEF',
      credential_provider_id: 'cp-scm',
      provider_id: 'scm',
      token_type: 'Bearer',
      scopes: ['repo', 'read:org'],
      expires_at: null,
      consent_granted_at: NOW.toISOString(),
      last_used_at: null,
      created_at: NOW.toISOString(),
      updated_at: NOW.toISOString(),
      is_expired: false,
      can_refresh: true,
    };
    const providers = { 'cp-scm': { name: 'Source Control' } };

    for (const term of ['', 'source control', 'scm', 'pr-reviewer', 'abcdef', 'read:org']) {
      expect(matchesSearch(token, providers, term)).toBe(true);
    }
    expect(matchesSearch(token, providers, 'salesforce')).toBe(false);
    expect(matchesSearch(token, {}, 'source control')).toBe(false);
  });

  it('finds a token by the name its agent is shown under', () => {
    const token = (agent_did: string) => ({
      id: 't1',
      agent_did,
      user_identity_hash: 'sha256:abcdef',
      credential_provider_id: 'cp-scm',
      provider_id: 'scm',
      token_type: 'Bearer',
      scopes: [],
      expires_at: null,
      consent_granted_at: NOW.toISOString(),
      last_used_at: null,
      created_at: NOW.toISOString(),
      updated_at: NOW.toISOString(),
      is_expired: false,
      can_refresh: true,
    });

    expect(
      matchesSearch(
        token('did:web:Agents.example.com:tenants:sales'),
        {},
        'agents.example.com/tenants'
      )
    ).toBe(true);
    expect(matchesSearch(token('did:web:localhost%3A8443'), {}, 'localhost:8443')).toBe(true);
    expect(matchesSearch(token('did:web:localhost%3A8443'), {}, 'localhost/8443')).toBe(false);
  });

  it('says in words what a limit on one consent would do', () => {
    const granted = after(-HOUR).toISOString();
    const shown = (time: Date | string) => formatDateTime(time, true);

    expect(limitOutcomeText({ kind: 'ends', end: after(HOUR) }, granted, NOW)).toBe(
      `Consent given ${shown(granted)}. With this limit it ends ${shown(after(HOUR))} (in 1 hour).`
    );
    expect(limitOutcomeText({ kind: 'ends', end: after(HOUR - 1) }, granted, NOW)).toBe(
      `Consent given ${shown(granted)}. With this limit it ends ${shown(after(HOUR - 1))} (in 59 minutes).`
    );
    expect(limitOutcomeText({ kind: 'not_sooner', end: after(5 * HOUR) }, granted, NOW)).toBe(
      `It already ends ${shown(after(5 * HOUR))}. A limit only brings the end forward.`
    );
    expect(limitOutcomeText({ kind: 'already_older' }, granted, NOW)).toBe(
      'This consent is already older than that. Use Revoke to end it now.'
    );
    expect(limitOutcomeText({ kind: 'invalid' }, granted, NOW)).toBe(
      'Enter a whole number from 1 minute to 365 days.'
    );
  });

  it("counts a token as a person's delegation unless its provider is one nobody consents to", () => {
    const providers = {
      'cp-github': { provider_type: 'oauth2_authorization_code' },
      'cp-service': { provider_type: 'oauth2_client_credentials' },
      'cp-untyped': {},
    };
    const of = (credential_provider_id: string) => ({ credential_provider_id });

    expect(isPersonsDelegation(of('cp-github'), providers)).toBe(true);
    expect(isPersonsDelegation(of('cp-service'), providers)).toBe(false);
    expect(isPersonsDelegation(of('cp-untyped'), providers)).toBe(true);
    expect(isPersonsDelegation(of('cp-deleted'), providers)).toBe(true);
  });

  it('gives a token the status of its consent first, then of its access token', () => {
    const live = { is_expired: false, can_refresh: true };
    const ends = (ms: number) => ({ consent_expires_at: after(ms).toISOString() });

    expect(tokenStatus(live, NOW)).toEqual({ label: 'Active', tone: 'success' });
    expect(tokenStatus({ ...live, ...ends(2 * DAY) }, NOW)).toEqual({
      label: 'Active',
      tone: 'success',
    });
    expect(tokenStatus({ ...live, ...ends(HOUR) }, NOW)).toEqual({
      label: 'Ending soon',
      tone: 'warning',
    });
    expect(tokenStatus({ ...live, ...ends(-1) }, NOW)).toEqual({
      label: 'Consent ended',
      tone: 'secondary',
    });
    expect(tokenStatus({ is_expired: true, can_refresh: true }, NOW)).toEqual({
      label: 'Expired (refreshable)',
      tone: 'warning',
    });
    expect(tokenStatus({ is_expired: true, can_refresh: false }, NOW)).toEqual({
      label: 'Expired',
      tone: 'danger',
    });
  });

  it('says when a consent ends, as a sentence for the list and as a value for the detail', () => {
    const soon = { consent_expires_at: after(3 * HOUR + 5 * MINUTE).toISOString() };
    const over = { consent_expires_at: after(-HOUR).toISOString() };

    expect(consentEndSentence(soon, NOW)).toMatch(/^Ends .+ \(in 3 hours\)$/);
    expect(consentEndValue(soon, NOW)).toMatch(/^(?!Ends).+ \(in 3 hours\)$/);
    expect(consentEndSentence(over, NOW)).toMatch(/^Ended \S/);
    expect(consentEndValue(over, NOW)).toMatch(/ \(ended\)$/);
    expect(consentEndSentence({}, NOW)).toBe('No time limit');
    expect(consentEndValue({}, NOW)).toBe('No time limit');
  });

  it('says how many delegations a revoke-all ends', () => {
    expect(revokeAllLabel(1)).toBe("Revoke this user's only delegation?");
    expect(revokeAllLabel(2)).toBe('Revoke all 2 for this user?');
  });

  it('names a did:web agent by its whole web address and shortens any other DID', () => {
    expect(agentName('did:web:pr-reviewer.example.com')).toBe('pr-reviewer.example.com');
    expect(agentName('did:web:agents.example.com:tenants:sales:crm-assistant')).toBe(
      'agents.example.com/tenants/sales/crm-assistant'
    );
    expect(agentName('did:web:localhost%3A8443')).toBe('localhost:8443');
    expect(agentName('did:web:localhost%3a8443:agents')).toBe('localhost:8443/agents');
    expect(agentName('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK')).toBe(
      'did:key:z6Mk...pbnnEGta2doK'
    );
    expect(agentName('did:web:')).toBe('did:web:');
    expect(agentName('did:web:example.com::path')).toBe('did:web:example.com::path');
  });
});
