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
  ])('labels %s as %s', (name, label) => {
    expect(categoryLabel(name)).toBe(label);
  });

  it('falls back to the raw name with spaces for an unknown event', () => {
    expect(categoryLabel('some_new_event')).toBe('some new event');
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

  it('marks an expired consent as a warning, not as a refusal', () => {
    expect(categoryBadgeClass('consent_expired')).toBe('badge-warning');
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
