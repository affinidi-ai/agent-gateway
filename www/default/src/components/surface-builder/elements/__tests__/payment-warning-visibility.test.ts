import { shouldShowDependencyWarnings } from '../../dependencyWarningVisibility';

describe('Payment dependency warning visibility', () => {
  it('hides Payment setup warnings before a Save attempt', () => {
    expect(shouldShowDependencyWarnings('payment', false)).toBe(false);
  });

  it('shows Payment setup warnings after a Save attempt', () => {
    expect(shouldShowDependencyWarnings('payment', true)).toBe(true);
  });

  it('keeps dependency warnings visible for other elements', () => {
    expect(shouldShowDependencyWarnings('policy', false)).toBe(true);
  });

  it('keeps x402 setup warnings hidden while editing a partial template', () => {
    expect(shouldShowDependencyWarnings('payment', false)).toBe(false);
  });
});
