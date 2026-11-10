import { renderHook, waitFor } from '@testing-library/react';
import { apiClient } from '../../../../../api';
import { useApiKeySecrets } from '../useCallerAuthOptions';

jest.mock('../../../../../api', () => ({ apiClient: { get: jest.fn(), fetch: jest.fn() } }));

const get = apiClient.get as jest.Mock;

beforeEach(() => get.mockReset());

test('offers a secret of any type, those of type ApiKey first', async () => {
  get.mockResolvedValue({
    data: [
      { id: 's1', secret_id: 'partner-keys', name: 'Partner keys', secret_type: 'General' },
      { id: 's2', secret_id: 'agent-keys', name: 'Agent keys', secret_type: 'ApiKey' },
      { id: 's3', secret_id: 'legacy-keys', name: 'Legacy keys' },
      { id: 's4', secret_id: 'ops-token', name: 'Ops token', secret_type: 'Token' },
    ],
  });

  const { result } = renderHook(() => useApiKeySecrets(true));

  await waitFor(() => expect(result.current.loading).toBe(false));
  expect(result.current.secrets.map(s => s.secret_id)).toEqual([
    'agent-keys',
    'partner-keys',
    'legacy-keys',
    'ops-token',
  ]);
  expect(get).toHaveBeenCalledWith('/secrets/');
});

test('offers no secrets when they cannot be listed', async () => {
  get.mockRejectedValue(new Error('Forbidden (403)'));

  const { result } = renderHook(() => useApiKeySecrets(true));

  await waitFor(() => expect(get).toHaveBeenCalled());
  await waitFor(() => expect(result.current.loading).toBe(false));
  expect(result.current.secrets).toEqual([]);
});

test('does not load secrets while disabled', () => {
  const { result } = renderHook(() => useApiKeySecrets(false));

  expect(get).not.toHaveBeenCalled();
  expect(result.current.secrets).toEqual([]);
});
