import { apiClient, TERMS_ACCEPTANCE_REQUIRED_EVENT, TERMS_OPERATIONAL_FAILURE_EVENT } from './api';

const fetchMock = jest.fn();

beforeEach(() => {
  fetchMock.mockReset();
  global.fetch = fetchMock;
});

test('signals the app when a protected request requires Terms acceptance', async () => {
  const listener = jest.fn();
  window.addEventListener(TERMS_ACCEPTANCE_REQUIRED_EVENT, listener);
  fetchMock.mockResolvedValue(
    new Response(JSON.stringify({ code: 'TERMS_ACCEPTANCE_REQUIRED' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    })
  );

  await apiClient.fetch('/api/v1/settings');

  expect(listener).toHaveBeenCalledTimes(1);
  window.removeEventListener(TERMS_ACCEPTANCE_REQUIRED_EVENT, listener);
});

test('signals the app only for the exact Terms operational failure response', async () => {
  const listener = jest.fn();
  window.addEventListener(TERMS_OPERATIONAL_FAILURE_EVENT, listener);
  fetchMock
    .mockResolvedValueOnce(
      new Response(JSON.stringify({ code: 'TERMS_OPERATIONAL_FAILURE' }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' },
      })
    )
    .mockResolvedValueOnce(
      new Response(JSON.stringify({ code: 'OTHER_FAILURE' }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' },
      })
    );

  await apiClient.fetch('/api/v1/settings');
  await apiClient.fetch('/api/v1/settings');

  expect(listener).toHaveBeenCalledTimes(1);
  window.removeEventListener(TERMS_OPERATIONAL_FAILURE_EVENT, listener);
});
