import { isA2aLegacyCompatibilityOn } from '../a2aLegacyCompatibility';

describe('isA2aLegacyCompatibilityOn', () => {
  it('is on when there are no flags or the flag is unset', () => {
    expect(isA2aLegacyCompatibilityOn(undefined)).toBe(true);
    expect(isA2aLegacyCompatibilityOn(null)).toBe(true);
    expect(isA2aLegacyCompatibilityOn({})).toBe(true);
    expect(isA2aLegacyCompatibilityOn({ metrics: false })).toBe(true);
  });

  it('follows an explicit value', () => {
    expect(isA2aLegacyCompatibilityOn({ a2a_legacy_compatibility: true })).toBe(true);
    expect(isA2aLegacyCompatibilityOn({ a2a_legacy_compatibility: false })).toBe(false);
  });
});
