import { surfaceVariantAlias, surfaceVariantLabel } from '../surfaceVariant';

describe('surfaceVariant', () => {
  it('gives a configured alias and nothing for the values the gateway writes itself', () => {
    expect(surfaceVariantAlias('beta')).toBe('beta');
    expect(surfaceVariantAlias('_base_')).toBeUndefined();
    expect(surfaceVariantAlias('_unknown_')).toBeUndefined();
    expect(surfaceVariantAlias(undefined)).toBeUndefined();
    expect(surfaceVariantAlias(null)).toBeUndefined();
    expect(surfaceVariantAlias('')).toBeUndefined();
  });

  it('labels the base surface and an unknown variant in words', () => {
    expect(surfaceVariantLabel('beta')).toBe('beta');
    expect(surfaceVariantLabel('_base_')).toBe('Base surface');
    expect(surfaceVariantLabel('_unknown_')).toBe('Unknown variant');
    expect(surfaceVariantLabel(undefined)).toBeUndefined();
  });
});
