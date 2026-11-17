import { act, renderHook, waitFor } from '@testing-library/react';
import { apiClient } from '../../../api';
import { useConsentImpact } from '../useConsentImpact';

jest.mock('../../../api', () => ({
  apiClient: { fetch: jest.fn() },
}));

const mockFetch = apiClient.fetch as jest.Mock;

describe('useConsentImpact', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ active_consents: 3, ending_consents: 2 }),
    });
  });

  it('asks about the provider the id names, with the id encoded', async () => {
    const { result } = renderHook(() => useConsentImpact('a b/c', 3_600, undefined));

    await waitFor(() => expect(result.current).toBe(2));
    expect(mockFetch).toHaveBeenCalledWith(
      '/api/v1/credential-providers/a%20b%2Fc/consent-impact?max_consent_age_secs=3600'
    );
  });

  describe('with the clock held', () => {
    beforeEach(() => jest.useFakeTimers());
    afterEach(() => jest.useRealTimers());

    const passes = (ms: number) =>
      act(async () => {
        jest.advanceTimersByTime(ms);
      });

    it('asks only once the limit has stayed unchanged for 400 ms, and then about the last one', async () => {
      const { result, rerender } = renderHook(({ secs }) => useConsentImpact('p1', secs, 21_600), {
        initialProps: { secs: 3_600 },
      });
      await passes(399);
      expect(mockFetch).not.toHaveBeenCalled();

      rerender({ secs: 7_200 });
      await passes(399);
      expect(mockFetch).not.toHaveBeenCalled();
      expect(result.current).toBeNull();

      await passes(1);
      expect(mockFetch.mock.calls).toEqual([
        ['/api/v1/credential-providers/p1/consent-impact?max_consent_age_secs=7200'],
      ]);
      expect(result.current).toBe(2);
    });

    it('forgets the answer as soon as the limit changes again', async () => {
      const { result, rerender } = renderHook(({ secs }) => useConsentImpact('p1', secs, 21_600), {
        initialProps: { secs: 3_600 },
      });
      await passes(400);
      expect(result.current).toBe(2);

      rerender({ secs: 7_200 });

      expect(result.current).toBeNull();
    });

    it.each(['.', '..'])(
      'never asks with the id %p, which would leave the provider path',
      async id => {
        const { result } = renderHook(() => useConsentImpact(id, 3_600, undefined));

        await passes(10_000);
        expect(mockFetch).not.toHaveBeenCalled();
        expect(result.current).toBeNull();
      }
    );
  });
});
