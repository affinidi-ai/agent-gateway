import { apiClient } from './api';
import type { TrustRecorderStatus } from './types';

const fetchMock = jest.fn();

beforeEach(() => {
  fetchMock.mockReset();
  global.fetch = fetchMock;
});

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

describe('getSurfaceTrustRecorderStatus', () => {
  it('returns the status the gateway reports for the surface', async () => {
    const status: TrustRecorderStatus = {
      state: 'partial',
      reason: 'rejected',
      last_attempt_at: '2026-02-01T00:00:00Z',
      entries: [
        {
          trust_registry_id: 'reg-1',
          state: 'partial',
          reason: 'rejected',
          created: 1,
          already_existed: 2,
          failed: 3,
        },
      ],
    };
    fetchMock.mockResolvedValue(jsonResponse({ status }));

    await expect(apiClient.getSurfaceTrustRecorderStatus('surface/1')).resolves.toEqual(status);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/surfaces/surface%2F1/trust-recorder-status');
  });

  it('returns null when nothing has been attempted yet', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ status: null }));

    await expect(apiClient.getSurfaceTrustRecorderStatus('surface-1')).resolves.toBeNull();
  });

  it('returns null when the body has no status key', async () => {
    fetchMock.mockResolvedValue(jsonResponse({}));

    await expect(apiClient.getSurfaceTrustRecorderStatus('surface-1')).resolves.toBeNull();
  });

  it('rejects when the gateway answers with an error', async () => {
    const consoleError = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    fetchMock.mockResolvedValue(new Response('nope', { status: 500, statusText: 'Server Error' }));

    await expect(apiClient.getSurfaceTrustRecorderStatus('surface-1')).rejects.toThrow();
    consoleError.mockRestore();
  });
});
