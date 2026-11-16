import {
  agentName,
  consentEnd,
  consentState,
  isActiveDelegation,
  timeLeft,
} from '../delegatedAccess';

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

  it('names a did:web agent by its whole web address and shortens any other DID', () => {
    expect(agentName('did:web:pr-reviewer.example.com')).toBe('pr-reviewer.example.com');
    expect(agentName('did:web:agents.example.com:tenants:sales:crm-assistant')).toBe(
      'agents.example.com/tenants/sales/crm-assistant'
    );
    expect(agentName('did:web:localhost%3A8443')).toBe('localhost:8443');
    expect(agentName('did:web:odd%zz.example.com')).toBe('odd%zz.example.com');
    expect(agentName('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK')).toBe(
      'did:key:z6Mk...pbnnEGta2doK'
    );
    expect(agentName('did:web:')).toBe('did:web:');
    expect(agentName('did:web:example.com::path')).toBe('did:web:example.com::path');
  });
});
