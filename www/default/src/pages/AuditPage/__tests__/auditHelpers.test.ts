import { categoryLabel } from '../auditHelpers';

describe('categoryLabel', () => {
  it.each([
    ['identity_binding_verified', 'Identity Binding Verified'],
    ['identity_binding_failed', 'Identity Binding Failed'],
    ['token_refreshed', 'Token Refreshed'],
  ])('labels %s as %s', (name, label) => {
    expect(categoryLabel(name)).toBe(label);
  });

  it('falls back to the raw name with spaces for an unknown event', () => {
    expect(categoryLabel('some_new_event')).toBe('some new event');
  });
});
