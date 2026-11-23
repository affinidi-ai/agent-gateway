import { renderHook, waitFor } from '@testing-library/react';
import { apiClient } from '../../../../../api';
import { useApiKeySecrets, useCertificates } from '../useCallerAuthOptions';

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

test('offers only the active certificates once they are listed', async () => {
  get.mockResolvedValue({
    data: [
      { id: 'c1', name: 'Agent CA', kind: 'ca', active: true },
      { id: 'c2', name: 'Old leaf', kind: 'client_leaf', active: false },
      { id: 'c3', name: 'Client leaf', kind: 'client_leaf', active: true },
    ],
  });

  const { result } = renderHook(() => useCertificates(true));

  expect(result.current.loaded).toBe(false);
  await waitFor(() => expect(result.current.loaded).toBe(true));
  expect(result.current.loading).toBe(false);
  expect(result.current.failed).toBe(false);
  expect(result.current.certificates.map(c => c.id)).toEqual(['c1', 'c3']);
  expect(get).toHaveBeenCalledWith('/certificates');
});

test('reports a certificate store that cannot be read as failed, with no certificates', async () => {
  get.mockRejectedValue(new Error('Forbidden (403)'));

  const { result } = renderHook(() => useCertificates(true));

  await waitFor(() => expect(result.current.failed).toBe(true));
  expect(result.current.loaded).toBe(true);
  expect(result.current.loading).toBe(false);
  expect(result.current.certificates).toEqual([]);
});

test('does not load certificates while disabled', () => {
  const { result } = renderHook(() => useCertificates(false));

  expect(get).not.toHaveBeenCalled();
  expect(result.current).toEqual({
    certificates: [],
    loading: false,
    loaded: false,
    failed: false,
  });
});
