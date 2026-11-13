import { apiClient } from './api';

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

describe('setSurfacePolicyInputCapture', () => {
  it('PUTs the minutes and returns when logging stops', async () => {
    const state = { surface_id: 'surface/1', policy_input_capture_until: '2026-02-01T00:15:00Z' };
    fetchMock.mockResolvedValue(jsonResponse(state));

    await expect(apiClient.setSurfacePolicyInputCapture('surface/1', 15)).resolves.toEqual(state);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/v1/surfaces/surface%2F1/policy-input-capture');
    expect(init.method).toBe('PUT');
    expect(JSON.parse(init.body)).toEqual({ minutes: 15 });
  });

  it('rejects when the gateway refuses the minutes', async () => {
    const consoleError = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    fetchMock.mockResolvedValue(new Response('out of range', { status: 400 }));

    await expect(apiClient.setSurfacePolicyInputCapture('surface-1', 90)).rejects.toThrow();
    consoleError.mockRestore();
  });
});

describe('clearSurfacePolicyInputCapture', () => {
  it('DELETEs and returns the cleared state', async () => {
    const state = { surface_id: 'surface/1', policy_input_capture_until: null };
    fetchMock.mockResolvedValue(jsonResponse(state));

    await expect(apiClient.clearSurfacePolicyInputCapture('surface/1')).resolves.toEqual(state);

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/v1/surfaces/surface%2F1/policy-input-capture');
    expect(init.method).toBe('DELETE');
  });

  it('rejects when the gateway answers with an error', async () => {
    const consoleError = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    fetchMock.mockResolvedValue(new Response('nope', { status: 403 }));

    await expect(apiClient.clearSurfacePolicyInputCapture('surface-1')).rejects.toThrow();
    consoleError.mockRestore();
  });
});
