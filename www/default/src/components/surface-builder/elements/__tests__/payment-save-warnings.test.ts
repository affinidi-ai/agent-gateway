import { saveWarningMessages, showSaveWarnings } from '../payment/saveWarnings';
import { showToast } from '../../../../utils/toaster';

jest.mock('../../../../utils/toaster', () => ({ showToast: jest.fn() }));

beforeEach(() => jest.clearAllMocks());

describe('saveWarningMessages', () => {
  it('shows the message of each warning object, trimmed', () => {
    expect(
      saveWarningMessages([{ code: 'payment_unverified', message: '  agent-pay unreachable ' }])
    ).toEqual(['agent-pay unreachable']);
  });

  it('falls back to the code when there is no message', () => {
    expect(saveWarningMessages([{ code: 'payment_unverified' }])).toEqual(['payment_unverified']);
    expect(saveWarningMessages([{ code: 'x', message: '  ' }])).toEqual(['x']);
  });

  it('skips entries that carry neither', () => {
    expect(saveWarningMessages([null, {}, 'payment_unverified', { code: '' }])).toEqual([]);
  });

  it('returns nothing when there are no warnings', () => {
    expect(saveWarningMessages(undefined)).toEqual([]);
    expect(saveWarningMessages([])).toEqual([]);
    expect(saveWarningMessages('payment_unverified')).toEqual([]);
  });
});

describe('showSaveWarnings', () => {
  it('raises one lasting toast per warning', () => {
    showSaveWarnings([
      { code: 'a', message: 'first' },
      { code: 'b', message: 'second' },
    ]);

    expect(showToast).toHaveBeenCalledTimes(2);
    expect(showToast).toHaveBeenNthCalledWith(1, 'error', 'first', {
      autoRemove: true,
      duration: 8000,
    });
    expect(showToast).toHaveBeenNthCalledWith(2, 'error', 'second', {
      autoRemove: true,
      duration: 8000,
    });
  });

  it('raises nothing without warnings', () => {
    showSaveWarnings(undefined);
    expect(showToast).not.toHaveBeenCalled();
  });
});
