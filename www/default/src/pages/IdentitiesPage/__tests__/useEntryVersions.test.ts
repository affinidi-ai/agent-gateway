import { renderHook, waitFor } from '@testing-library/react';
import { apiClient } from '../../../api';
import type { Identity } from '../../../types';
import { useEntryVersions } from '../useEntryVersions';

jest.mock('../../../api', () => ({
  apiClient: { getIdentityRotations: jest.fn() },
}));

const getIdentityRotations = apiClient.getIdentityRotations as jest.Mock;

const member = (hash: string): Identity =>
  ({
    identity_hash: hash,
    did: `did:example:${hash}`,
    created_at: '2026-01-01T00:00:00Z',
    rotation_count: 1,
  }) as Identity;

describe('useEntryVersions', () => {
  beforeEach(() => {
    getIdentityRotations.mockReset();
  });

  it('aborts the other members fetches when one member fetch fails', async () => {
    const signals: AbortSignal[] = [];
    getIdentityRotations.mockImplementation((hash: string, signal: AbortSignal) => {
      signals.push(signal);
      return hash === 'bad' ? Promise.reject(new Error('boom')) : new Promise(() => undefined);
    });
    const members = [member('good'), member('bad')];

    const { result } = renderHook(() => useEntryVersions(members, members[0].did));

    await waitFor(() => expect(result.current.status).toBe('error'));
    expect(result.current).toMatchObject({ message: 'boom' });
    expect(signals).toHaveLength(2);
    expect(signals.every(signal => signal.aborted)).toBe(true);
  });

  it('keeps the fetch running while every member fetch succeeds', async () => {
    const signals: AbortSignal[] = [];
    getIdentityRotations.mockImplementation((_hash: string, signal: AbortSignal) => {
      signals.push(signal);
      return Promise.resolve([]);
    });
    const members = [member('a'), member('b')];

    const { result } = renderHook(() => useEntryVersions(members, members[0].did));

    await waitFor(() => expect(result.current.status).toBe('ready'));
    expect(signals.some(signal => signal.aborted)).toBe(false);
  });
});
