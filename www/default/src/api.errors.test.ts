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

test('a failed request carries the error code of its body', async () => {
  fetchMock.mockResolvedValue(
    new Response(JSON.stringify({ error: 'payment_manifest_not_found' }), {
      status: 404,
      statusText: 'Not Found',
      headers: { 'Content-Type': 'application/json' },
    })
  );

  const error = await apiClient.get('/surfaces/s-1/payment-manifest').catch((e: unknown) => e);

  expect(error).toBeInstanceOf(ApiError);
  expect((error as ApiError).status).toBe(404);
  expect((error as ApiError).code).toBe('payment_manifest_not_found');
});
