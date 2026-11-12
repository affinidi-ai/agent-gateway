import { apiClient } from './api';
import type { CredentialRotation } from './types';

const fetchMock = jest.fn();

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

const rotation = (day: number): CredentialRotation => ({
  rotated_at: `2026-01-${String(day).padStart(2, '0')}T00:00:00Z`,
});

const base = '/api/v1/identities/by-hash/a%2Fb/rotations?limit=1000';

beforeEach(() => {
  fetchMock.mockReset();
  global.fetch = fetchMock;
  sessionStorage.clear();
  jest.spyOn(console, 'error').mockImplementation(() => undefined);
});

afterEach(() => {
  jest.restoreAllMocks();
});

describe('getIdentityRotations', () => {
  it('returns a history that fits one page with one request, with the session token', async () => {
    sessionStorage.setItem('session_token', 'tok');
    fetchMock.mockResolvedValue(
      json({ rotations: [rotation(1), rotation(2)], total: 2, start: 0 })
    );

    await expect(apiClient.getIdentityRotations('a/b')).resolves.toEqual([
      rotation(1),
      rotation(2),
    ]);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(base);
    expect(init.headers.Authorization).toBe('Bearer tok');
  });

  it('pages back with `before` until the first rotation, oldest first', async () => {
    fetchMock
      .mockResolvedValueOnce(json({ rotations: [rotation(5), rotation(6)], total: 6, start: 4 }))
      .mockResolvedValueOnce(json({ rotations: [rotation(3), rotation(4)], total: 6, start: 2 }))
      .mockResolvedValueOnce(json({ rotations: [rotation(1), rotation(2)], total: 6, start: 0 }));

    const rotations = await apiClient.getIdentityRotations('a/b');

    expect(rotations.map(r => r.rotated_at)).toEqual(
      [1, 2, 3, 4, 5, 6].map(d => rotation(d).rotated_at)
    );
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      base,
      `${base}&before=4`,
      `${base}&before=2`,
    ]);
  });

  it('returns an empty history as an empty list', async () => {
    fetchMock.mockResolvedValue(json({ rotations: [], total: 0, start: 0 }));

    await expect(apiClient.getIdentityRotations('a/b')).resolves.toEqual([]);
  });

  it('rejects a page that does not move back instead of looping', async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve(json({ rotations: [rotation(2)], total: 2, start: 1 }))
    );

    await expect(apiClient.getIdentityRotations('a/b')).rejects.toThrow(
      'inconsistent rotation history'
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('stops paging back once the signal aborts', async () => {
    const controller = new AbortController();
    fetchMock.mockImplementation((_url: string, init: RequestInit) => {
      if (init.signal?.aborted) {
        return Promise.reject(new DOMException('The operation was aborted.', 'AbortError'));
      }
      controller.abort();
      return Promise.resolve(json({ rotations: [rotation(3)], total: 3, start: 2 }));
    });

    await expect(apiClient.getIdentityRotations('a/b', controller.signal)).rejects.toMatchObject({
      name: 'AbortError',
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('rejects an unknown identity with its status', async () => {
    fetchMock.mockResolvedValue(json({ error: 'not_found', message: 'Identity not found' }, 404));

    await expect(apiClient.getIdentityRotations('a/b')).rejects.toMatchObject({ status: 404 });
  });
});
