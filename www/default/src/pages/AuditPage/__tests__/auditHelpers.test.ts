import {
  CATEGORY_OPTIONS,
  DELEGATION_CATEGORIES,
  DELEGATION_ENDED_CATEGORIES,
  auditLogPath,
  categoryBadgeClass,
  categoryLabel,
} from '../auditHelpers';

describe('categoryLabel', () => {
  it.each([
    ['identity_binding_verified', 'Identity Binding Verified'],
    ['identity_binding_failed', 'Identity Binding Failed'],
    ['token_refreshed', 'Token Refreshed'],
    ['consent_expired', 'Consent Expired'],
    ['consent_limited', 'Consent Limited'],
    ['policy_input_capture_started', 'Policy Input Capture Started'],
    ['policy_input_capture_stopped', 'Policy Input Capture Stopped'],
  ])('labels %s as %s', (name, label) => {
    expect(categoryLabel(name)).toBe(label);
  });

  it.each([
    ['some_new_event', 'Some New Event'],
    ['auth_failed', 'Auth Failed'],
    ['mcp_proxy_pin_changed', 'MCP Proxy Pin Changed'],
    ['vp_audit_note', 'VP Audit Note'],
  ])('names an event it has no label for, %s, in title case', (name, label) => {
    expect(categoryLabel(name)).toBe(label);
  });
});

describe('policy input capture records in the Audit Log', () => {
  it('offers the start and stop of a capture as filters', () => {
    const offered: string[] = CATEGORY_OPTIONS.map(option => option.value);
    expect(offered).toContain('policy_input_capture_started');
    expect(offered).toContain('policy_input_capture_stopped');
  });
});

describe('credential delegation records in the Audit Log', () => {
  it('offers every delegation category as a filter', () => {
    const offered: string[] = CATEGORY_OPTIONS.map(option => option.value);
    for (const category of DELEGATION_CATEGORIES) {
      expect(offered).toContain(category);
    }
    for (const category of DELEGATION_ENDED_CATEGORIES) {
      expect(DELEGATION_CATEGORIES).toContain(category);
    }
  });

  it('offers no category for the delegation events the gateway only logs', () => {
    const logged = [
      'token_injected',
      'token_refreshed',
      'refresh_failed',
      'consent_required',
      'token_not_found',
    ];
    const offered: string[] = CATEGORY_OPTIONS.map(option => option.value);
    for (const category of logged) {
      expect(offered).not.toContain(category);
      expect(DELEGATION_CATEGORIES).not.toContain(category);
    }
    expect([...DELEGATION_CATEGORIES]).toEqual([
      'consent_granted',
      'consent_expired',
      'consent_limited',
      'token_revoked',
      'user_tokens_revoked',
    ]);
    expect(offered).toContain('consent_limited');
  });

  it('still names a record of a logged event that an older gateway audited', () => {
    expect(categoryLabel('token_injected')).toBe('Token Injected');
    expect(categoryLabel('consent_required')).toBe('Consent Required');
  });

  it('marks an expired consent as a warning, not as a refusal', () => {
    expect(categoryBadgeClass('consent_expired')).toBe('badge-warning');
    expect(categoryBadgeClass('consent_limited')).toBe('badge-warning');
    expect(categoryBadgeClass('token_revoked')).toBe('badge-danger');
    expect(categoryBadgeClass('user_tokens_revoked')).toBe('badge-danger');
  });

  it('builds the path the page reads its category and text filters from', () => {
    expect(auditLogPath([])).toBe('/audit');
    expect(auditLogPath(DELEGATION_ENDED_CATEGORIES)).toBe(
      '/audit?category=consent_expired%2Ctoken_revoked%2Cuser_tokens_revoked'
    );
    const path = auditLogPath(['token_revoked'], 'sha256:abc def');
    expect(path).toBe('/audit?filter=sha256%3Aabc+def&category=token_revoked');
    const read = new URLSearchParams(path.split('?')[1]);
    expect(read.get('filter')).toBe('sha256:abc def');
    expect(read.get('category')).toBe('token_revoked');
  });
});
