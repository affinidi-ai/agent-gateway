import { renderHook, waitFor } from '@testing-library/react';
import { apiClient } from '../../api';
import { useApplianceSecrets } from '../useApplianceSecrets';

jest.mock('../../api', () => ({ apiClient: { get: jest.fn() } }));

const get = apiClient.get as jest.Mock;

beforeEach(() => get.mockReset());

test('lists only appliance-wide secrets, which are the ones endpoints can reference', async () => {
  get.mockResolvedValue({
    data: [
      { secret_id: 'slack-hook', name: 'Slack hook' },
      { secret_id: 'team-a-key', name: 'Team A key', tenant_id: 'team-a' },
      { secret_id: 'smtp', name: 'SMTP password', tenant_id: null },
    ],
  });

  const { result } = renderHook(() => useApplianceSecrets());

  await waitFor(() =>
    expect(result.current).toEqual([
      { id: 'slack-hook', name: 'Slack hook' },
      { id: 'smtp', name: 'SMTP password' },
    ])
  );
  expect(get).toHaveBeenCalledWith('/secrets/');
});

test('offers no secrets when they cannot be listed', async () => {
  get.mockRejectedValue(new Error('Forbidden (403)'));

  const { result } = renderHook(() => useApplianceSecrets());

  await waitFor(() => expect(get).toHaveBeenCalled());
  expect(result.current).toEqual([]);
});
