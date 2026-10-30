import { act, renderHook, waitFor } from '@testing-library/react';
import { useAgentCardPreview } from '../useAgentCardPreview';
import { AFTER_CARD, failedBody, previewBody } from '../../utils/agentCardTestFixtures';

const mockFetch = jest.fn();
jest.mock('../../api', () => ({
  apiClient: { fetch: (...args: unknown[]) => mockFetch(...args) },
}));

const reply = (status: number, body: unknown) => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => body,
});

const deferred = <T,>() => {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>(r => {
    resolve = r;
  });
  return { promise, resolve };
};

beforeEach(() => jest.resetAllMocks());

describe('useAgentCardPreview', () => {
  it('stays idle without a surface id', () => {
    const { result } = renderHook(() => useAgentCardPreview(undefined));
    expect(result.current.state).toEqual({ status: 'idle' });
    expect(result.current.lastServed).toBeNull();
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('loads the preview and remembers the served card', async () => {
    mockFetch.mockResolvedValue(reply(200, previewBody()));
    const { result } = renderHook(() => useAgentCardPreview('s-123'));
    expect(result.current.state.status).toBe('loading');
    await waitFor(() => expect(result.current.state.status).toBe('ready'));
    if (result.current.state.status !== 'ready') throw new Error('not ready');
    const { preview } = result.current.state;
    expect(preview.supported && preview.fetch.status).toBe('ok');
    expect(result.current.lastServed).toEqual({
      card: AFTER_CARD,
      fetchedAt: '2026-10-23T10:00:00Z',
    });
    expect(mockFetch).toHaveBeenCalledWith('/api/v1/surfaces/s-123/agent-card', undefined);
  });

  it('remembers no served card when the first fetch fails', async () => {
    mockFetch.mockResolvedValue(reply(200, failedBody('needs_token', 401)));
    const { result } = renderHook(() => useAgentCardPreview('s-123'));
    await waitFor(() => expect(result.current.state.status).toBe('ready'));
    expect(result.current.lastServed).toBeNull();
  });

  it('reports unavailable when the read fails, and retries on reload', async () => {
    mockFetch.mockResolvedValueOnce(reply(500, {}));
    const { result } = renderHook(() => useAgentCardPreview('s-123'));
    await waitFor(() => expect(result.current.state.status).toBe('unavailable'));
    mockFetch.mockResolvedValueOnce(reply(200, previewBody()));
    act(() => result.current.reload());
    await waitFor(() => expect(result.current.state.status).toBe('ready'));
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('reports unavailable when the gateway has no preview endpoint', async () => {
    mockFetch.mockResolvedValue(reply(404, { error: 'not found' }));
    const { result } = renderHook(() => useAgentCardPreview('s-123'));
    await waitFor(() => expect(result.current.state.status).toBe('unavailable'));
    expect(result.current.lastServed).toBeNull();
  });

  it('reads again when the refresh key changes', async () => {
    mockFetch.mockResolvedValue(reply(200, previewBody()));
    const { result, rerender } = renderHook(({ k }) => useAgentCardPreview('s-123', k), {
      initialProps: { k: 0 },
    });
    await waitFor(() => expect(result.current.state.status).toBe('ready'));
    rerender({ k: 1 });
    await waitFor(() => expect(mockFetch).toHaveBeenCalledTimes(2));
  });

  it('refreshes through the POST route and keeps the last served card on a failure', async () => {
    mockFetch.mockResolvedValueOnce(reply(200, previewBody()));
    const { result } = renderHook(() => useAgentCardPreview('s-123'));
    await waitFor(() => expect(result.current.state.status).toBe('ready'));

    const pending = deferred<ReturnType<typeof reply>>();
    mockFetch.mockReturnValueOnce(pending.promise);
    let outcome: Promise<unknown> | undefined;
    act(() => {
      outcome = result.current.refresh();
    });
    expect(result.current.refreshing).toBe(true);
    await act(async () => {
      pending.resolve(reply(200, failedBody('timeout', null)));
      await outcome;
    });
    expect(result.current.refreshing).toBe(false);
    if (result.current.state.status !== 'ready') throw new Error('not ready');
    const { preview } = result.current.state;
    expect(preview.supported && preview.fetch.cause).toBe('timeout');
    expect(result.current.lastServed?.card).toEqual(AFTER_CARD);
    expect(mockFetch).toHaveBeenLastCalledWith('/api/v1/surfaces/s-123/agent-card/refresh', {
      method: 'POST',
    });
  });

  it('replaces the remembered card after a successful refresh', async () => {
    mockFetch.mockResolvedValueOnce(reply(200, previewBody()));
    const { result } = renderHook(() => useAgentCardPreview('s-123'));
    await waitFor(() => expect(result.current.state.status).toBe('ready'));
    const newer = { ...AFTER_CARD, name: 'Renamed agent' };
    mockFetch.mockResolvedValueOnce(
      reply(200, previewBody({ after: newer, fetched_at: '2026-10-23T10:05:00Z' }))
    );
    await act(async () => {
      await result.current.refresh();
    });
    expect(result.current.lastServed).toEqual({ card: newer, fetchedAt: '2026-10-23T10:05:00Z' });
  });

  it('keeps the shown snapshot when a refresh is rate limited', async () => {
    mockFetch.mockResolvedValueOnce(reply(200, previewBody()));
    const { result } = renderHook(() => useAgentCardPreview('s-123'));
    await waitFor(() => expect(result.current.state.status).toBe('ready'));
    mockFetch.mockResolvedValueOnce(reply(429, {}));
    let kind = '';
    await act(async () => {
      kind = (await result.current.refresh()).kind;
    });
    expect(kind).toBe('rate_limited');
    expect(result.current.refreshing).toBe(false);
    expect(result.current.state.status).toBe('ready');
  });

  it('reports a forbidden refresh', async () => {
    mockFetch.mockResolvedValueOnce(reply(200, previewBody()));
    const { result } = renderHook(() => useAgentCardPreview('s-123'));
    await waitFor(() => expect(result.current.state.status).toBe('ready'));
    mockFetch.mockResolvedValueOnce(reply(403, {}));
    let kind = '';
    await act(async () => {
      kind = (await result.current.refresh()).kind;
    });
    expect(kind).toBe('forbidden');
    expect(result.current.state.status).toBe('ready');
  });

  it('ignores an answer for a surface that is no longer shown', async () => {
    const first = deferred<ReturnType<typeof reply>>();
    mockFetch.mockReturnValueOnce(first.promise);
    mockFetch.mockResolvedValueOnce(reply(200, previewBody({ surface_id: 's-2' })));
    const { result, rerender } = renderHook(({ id }) => useAgentCardPreview(id), {
      initialProps: { id: 's-1' },
    });
    rerender({ id: 's-2' });
    await waitFor(() => expect(result.current.state.status).toBe('ready'));
    await act(async () => {
      first.resolve(reply(200, previewBody({ surface_id: 's-1' })));
    });
    if (result.current.state.status !== 'ready') throw new Error('not ready');
    expect(result.current.state.preview.surface_id).toBe('s-2');
  });

  it('does not carry a served card over to another surface', async () => {
    mockFetch.mockResolvedValueOnce(reply(200, previewBody()));
    const { result, rerender } = renderHook(({ id }) => useAgentCardPreview(id), {
      initialProps: { id: 's-1' },
    });
    await waitFor(() => expect(result.current.lastServed).not.toBeNull());
    mockFetch.mockResolvedValueOnce(reply(200, failedBody('timeout', null)));
    rerender({ id: 's-2' });
    expect(result.current.lastServed).toBeNull();
    await waitFor(() => expect(result.current.state.status).toBe('ready'));
    expect(result.current.lastServed).toBeNull();
  });

  it('drops a refresh answer that arrives after the surface changed', async () => {
    mockFetch.mockResolvedValueOnce(reply(200, previewBody({ surface_id: 's-1' })));
    const { result, rerender } = renderHook(({ id }) => useAgentCardPreview(id), {
      initialProps: { id: 's-1' },
    });
    await waitFor(() => expect(result.current.state.status).toBe('ready'));

    const pending = deferred<ReturnType<typeof reply>>();
    mockFetch.mockReturnValueOnce(pending.promise);
    let outcome: Promise<{ kind: string }> = Promise.resolve({ kind: '' });
    act(() => {
      outcome = result.current.refresh();
    });
    mockFetch.mockResolvedValueOnce(
      reply(200, { ...failedBody('timeout', null), surface_id: 's-2' })
    );
    rerender({ id: 's-2' });
    await waitFor(() => expect(result.current.state.status).toBe('ready'));

    let kind = '';
    await act(async () => {
      pending.resolve(
        reply(200, previewBody({ surface_id: 's-1', after: { ...AFTER_CARD, name: 'Stale' } }))
      );
      kind = (await outcome).kind;
    });
    expect(kind).toBe('stale');
    if (result.current.state.status !== 'ready') throw new Error('not ready');
    expect(result.current.state.preview.surface_id).toBe('s-2');
    expect(result.current.lastServed).toBeNull();
    expect(result.current.refreshing).toBe(false);
  });

  it('drops a refresh answer that arrives after the refresh key changed', async () => {
    mockFetch.mockResolvedValueOnce(reply(200, previewBody()));
    const { result, rerender } = renderHook(({ k }) => useAgentCardPreview('s-123', k), {
      initialProps: { k: 0 },
    });
    await waitFor(() => expect(result.current.state.status).toBe('ready'));

    const pending = deferred<ReturnType<typeof reply>>();
    mockFetch.mockReturnValueOnce(pending.promise);
    let outcome: Promise<{ kind: string }> = Promise.resolve({ kind: '' });
    act(() => {
      outcome = result.current.refresh();
    });
    mockFetch.mockResolvedValueOnce(
      reply(200, previewBody({ fetched_at: '2026-10-23T10:07:00Z' }))
    );
    rerender({ k: 1 });
    await waitFor(() => {
      if (result.current.state.status !== 'ready') throw new Error('not ready');
      expect(
        result.current.state.preview.supported && result.current.state.preview.fetched_at
      ).toBe('2026-10-23T10:07:00Z');
    });

    let kind = '';
    await act(async () => {
      pending.resolve(reply(200, failedBody('timeout', null)));
      kind = (await outcome).kind;
    });
    expect(kind).toBe('stale');
    if (result.current.state.status !== 'ready') throw new Error('not ready');
    const { preview } = result.current.state;
    expect(preview.supported && preview.fetch.status).toBe('ok');
    expect(result.current.lastServed?.fetchedAt).toBe('2026-10-23T10:07:00Z');
    expect(result.current.refreshing).toBe(false);
  });

  it('reports a refresh that ends after unmount as stale without updating state', async () => {
    mockFetch.mockResolvedValueOnce(reply(200, previewBody()));
    const errors = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    const { result, unmount } = renderHook(() => useAgentCardPreview('s-123'));
    await waitFor(() => expect(result.current.state.status).toBe('ready'));

    const pending = deferred<ReturnType<typeof reply>>();
    mockFetch.mockReturnValueOnce(pending.promise);
    let outcome: Promise<{ kind: string }> = Promise.resolve({ kind: '' });
    act(() => {
      outcome = result.current.refresh();
    });
    unmount();
    pending.resolve(reply(500, {}));
    expect((await outcome).kind).toBe('stale');
    expect(errors).not.toHaveBeenCalled();
    errors.mockRestore();
  });

  it('cannot refresh without a surface id', async () => {
    const { result } = renderHook(() => useAgentCardPreview(undefined));
    let kind = '';
    await act(async () => {
      kind = (await result.current.refresh()).kind;
    });
    expect(kind).toBe('error');
    expect(mockFetch).not.toHaveBeenCalled();
  });
});
