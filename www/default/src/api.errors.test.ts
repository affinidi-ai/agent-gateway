import { ApiError, apiClient } from './api';

const fetchMock = jest.fn();

beforeEach(() => {
  fetchMock.mockReset();
  global.fetch = fetchMock;
  jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks();
});

test('a failed request throws an ApiError carrying its status', async () => {
  fetchMock.mockResolvedValue(
    new Response(JSON.stringify({ error: 'Forbidden' }), {
      status: 403,
      statusText: 'Forbidden',
      headers: { 'Content-Type': 'application/json' },
    })
  );

  const error = await apiClient.get('/users').catch((e: unknown) => e);

  expect(error).toBeInstanceOf(ApiError);
  expect(error).toBeInstanceOf(Error);
  expect((error as ApiError).status).toBe(403);
});
