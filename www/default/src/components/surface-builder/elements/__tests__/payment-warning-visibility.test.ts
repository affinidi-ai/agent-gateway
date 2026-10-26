import { shouldShowDependencyWarnings } from '../../dependencyWarningVisibility';

describe('Payment dependency warning visibility', () => {
  it('hides Payment setup warnings before a Save attempt', () => {
    expect(shouldShowDependencyWarnings('payment', false)).toBe(false);
    expect(shouldShowDependencyWarnings('payment', false, { payment_gateway_id: 'gw' })).toBe(
      false
    );
  });

  it('shows Payment setup warnings after a Save attempt', () => {
    expect(shouldShowDependencyWarnings('payment', true)).toBe(true);
  });

  it('keeps dependency warnings visible for other elements', () => {
    expect(shouldShowDependencyWarnings('policy', false)).toBe(true);
  });

  it('always shows the error for an unsupported local payment policy', () => {
    expect(shouldShowDependencyWarnings('payment', false, { unsupported_legacy: 'x402' })).toBe(
      true
    );
    expect(shouldShowDependencyWarnings('payment', false, { unsupported_legacy: 'mpp' })).toBe(
      true
    );
  });
});
