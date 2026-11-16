import { renderHook, waitFor } from '@testing-library/react';
import { apiClient } from '../../../api';
import { useConsentImpact } from '../useConsentImpact';

jest.mock('../../../api', () => ({
  apiClient: { fetch: jest.fn() },
}));

const mockFetch = apiClient.fetch as jest.Mock;
const pause = () => new Promise(resolve => setTimeout(resolve, 600));

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

  it.each(['.', '..'])(
    'never asks with the id %p, which would leave the provider path',
    async id => {
      const { result } = renderHook(() => useConsentImpact(id, 3_600, undefined));

      await pause();
      expect(mockFetch).not.toHaveBeenCalled();
      expect(result.current).toBeNull();
    }
  );
});
