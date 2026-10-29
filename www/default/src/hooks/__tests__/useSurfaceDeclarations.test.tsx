import { renderHook, waitFor } from '@testing-library/react';
import { useSurfaceDeclarations } from '../useSurfaceDeclarations';

const mockFetch = jest.fn();
jest.mock('../../api', () => ({
  apiClient: { fetch: (...args: unknown[]) => mockFetch(...args) },
}));

const reply = (ok: boolean, body: unknown) => ({ ok, json: async () => body });

beforeEach(() => jest.clearAllMocks());

describe('useSurfaceDeclarations', () => {
  it('stays idle without a surface id', () => {
    const { result } = renderHook(() => useSurfaceDeclarations(undefined));
    expect(result.current).toEqual({ status: 'idle' });
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('loads the current declarations and warnings', async () => {
    mockFetch.mockResolvedValue(
      reply(true, {
        declarations: [
          { variant: null, outcome: 'declare', reason: null, resource: 'https://gw/a' },
        ],
        warnings: [{ code: 'additional_audiences', message: 'm', path: null, variant: null }],
      })
    );
    const { result } = renderHook(() => useSurfaceDeclarations('s1'));
    expect(result.current.status).toBe('loading');
    await waitFor(() => expect(result.current.status).toBe('ready'));
    if (result.current.status !== 'ready') throw new Error('not ready');
    expect(result.current.declarations[0].outcome).toBe('declare');
    expect(result.current.warnings[0].code).toBe('additional_audiences');
  });

  it('reads again when the refresh key changes', async () => {
    mockFetch.mockResolvedValue(reply(true, { declarations: [], warnings: [] }));
    const { result, rerender } = renderHook(({ k }) => useSurfaceDeclarations('s1', k), {
      initialProps: { k: 0 },
    });
    await waitFor(() => expect(result.current.status).toBe('ready'));
    rerender({ k: 1 });
    await waitFor(() => expect(mockFetch).toHaveBeenCalledTimes(2));
  });

  it('reports unavailable when the gateway refuses', async () => {
    mockFetch.mockResolvedValue(reply(false, {}));
    const { result } = renderHook(() => useSurfaceDeclarations('s1'));
    await waitFor(() => expect(result.current.status).toBe('unavailable'));
  });

  it('reports unavailable when the request fails', async () => {
    mockFetch.mockRejectedValue(new Error('offline'));
    const { result } = renderHook(() => useSurfaceDeclarations('s1'));
    await waitFor(() => expect(result.current.status).toBe('unavailable'));
  });

  it('returns to idle when the surface id goes away', async () => {
    mockFetch.mockResolvedValue(reply(true, { declarations: [], warnings: [] }));
    const { result, rerender } = renderHook(
      ({ id }: { id: string | undefined }) => useSurfaceDeclarations(id),
      { initialProps: { id: 's1' as string | undefined } }
    );
    await waitFor(() => expect(result.current.status).toBe('ready'));
    rerender({ id: undefined });
    await waitFor(() => expect(result.current).toEqual({ status: 'idle' }));
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});
