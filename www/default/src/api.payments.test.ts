import { apiClient, sessionManager } from './api';
import type { PaymentLedgerRow } from './types';

const fetchMock = jest.fn();

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

const row: PaymentLedgerRow = {
  id: 'p-1',
  created_at: 1_700_000_000,
  surface_id: 'weather',
  payment_gateway_id: 'gw-pay',
  payment_surface_id: 'pay-ch',
  outcome: 'held',
  case_id: 'case-77',
  latency_ms: 42,
  case_status: { status: 'capture_failed', checked_at: '2026-10-20T10:00:00Z' },
};

let expireSession: jest.SpyInstance;

beforeEach(() => {
  fetchMock.mockReset();
  global.fetch = fetchMock;
  sessionStorage.clear();
  expireSession = jest.spyOn(sessionManager, 'expireSession').mockImplementation(() => undefined);
  jest.spyOn(console, 'error').mockImplementation(() => undefined);
});

afterEach(() => {
  jest.restoreAllMocks();
});

describe('listPayments', () => {
  it('asks the ledger for the filtered page with the session token', async () => {
    sessionStorage.setItem('session_token', 'tok');
    fetchMock.mockResolvedValue(json({ payments: [row], total: 9 }));

    const page = await apiClient.listPayments({
      surface_id: 'weather',
      outcome: 'held',
      limit: 500,
    });

    expect(page).toEqual({ payments: [row], total: 9 });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/admin/payments?surface_id=weather&outcome=held&limit=500');
    expect(init.headers.Authorization).toBe('Bearer tok');
  });

  it('sends no query string without filters, and tolerates a malformed body', async () => {
    fetchMock.mockResolvedValue(json({ payments: 'nope', total: 'many' }));

    await expect(apiClient.listPayments()).resolves.toEqual({ payments: [], total: 0 });
    expect(fetchMock.mock.calls[0][0]).toBe('/api/admin/payments');
  });

  it('expires the session on a 401 instead of showing a plain error', async () => {
    fetchMock.mockResolvedValue(new Response('', { status: 401 }));

    await expect(apiClient.listPayments()).rejects.toThrow('Session expired');

    expect(expireSession).toHaveBeenCalledTimes(1);
  });

  it('rejects another failure with its status, code and server message', async () => {
    fetchMock.mockResolvedValue(
      json(
        { error: 'Forbidden', code: 'permission_denied', details: 'payments.view is required' },
        403
      )
    );

    await expect(apiClient.listPayments()).rejects.toMatchObject({
      status: 403,
      code: 'permission_denied',
      message: 'payments.view is required (403)',
    });
    expect(expireSession).not.toHaveBeenCalled();
  });
});

describe('getPayment', () => {
  it('reads one row, with the case status of a held payment', async () => {
    fetchMock.mockResolvedValue(json(row));

    await expect(apiClient.getPayment('p/1 x')).resolves.toEqual(row);

    expect(fetchMock.mock.calls[0][0]).toBe('/api/admin/payments/p%2F1%20x');
  });

  it('expires the session on a 401', async () => {
    fetchMock.mockResolvedValue(new Response('', { status: 401 }));

    await expect(apiClient.getPayment('p-1')).rejects.toThrow('Session expired');

    expect(expireSession).toHaveBeenCalledTimes(1);
  });

  it('rejects a missing row with its status', async () => {
    fetchMock.mockResolvedValue(json({ error: 'Payment not found' }, 404));

    await expect(apiClient.getPayment('gone')).rejects.toMatchObject({
      status: 404,
      message: 'Payment not found (404)',
    });
    expect(expireSession).not.toHaveBeenCalled();
  });
});

describe('getPaymentManifest', () => {
  it('expires the session on a 401', async () => {
    fetchMock.mockResolvedValue(new Response('', { status: 401 }));

    await expect(apiClient.getPaymentManifest('gw-pay', 'pay-ch')).rejects.toThrow(
      'Session expired'
    );

    expect(expireSession).toHaveBeenCalledTimes(1);
  });
});

describe('payment audit, summary and breaker', () => {
  it('asks for the filtered audit page and fills a malformed body with defaults', async () => {
    fetchMock.mockResolvedValueOnce(
      json({ events: [{ timestamp: 't' }], total: 1, page: 1, page_size: 25, total_pages: 1 })
    );
    const page = await apiClient.listPaymentAudit({
      surface_id: 'weather',
      stage: 'failed',
      trace_id: '',
      page: 2,
      page_size: 25,
    });
    expect(fetchMock.mock.calls[0][0]).toBe(
      '/api/admin/payments/audit?surface_id=weather&stage=failed&page=2&page_size=25'
    );
    expect(page.total).toBe(1);

    fetchMock.mockResolvedValueOnce(json({ events: 'nope' }));
    await expect(apiClient.listPaymentAudit()).resolves.toEqual({
      events: [],
      total: 0,
      page: 1,
      page_size: 50,
      total_pages: 1,
    });
    expect(fetchMock.mock.calls[1][0]).toBe('/api/admin/payments/audit');
  });

  it('asks for a surface summary over the given hours', async () => {
    fetchMock.mockResolvedValue(json({ since: 's', total: 3, counts: { paid: 3 } }));
    await expect(apiClient.getPaymentSummary('weather', 24)).resolves.toEqual({
      since: 's',
      total: 3,
      counts: { paid: 3 },
    });
    expect(fetchMock.mock.calls[0][0]).toBe(
      '/api/admin/payments/summary?hours=24&surface_id=weather'
    );
  });

  it('asks for a breaker by its encoded payment gateway id', async () => {
    fetchMock.mockResolvedValue(
      json({
        payment_gateway_id: 'gw/1',
        state: 'open',
        consecutive_failures: 5,
        retry_after_secs: 12,
        failures_to_open: 5,
        open_secs: 30,
      })
    );
    const breaker = await apiClient.getPaymentBreaker('gw/1');
    expect(breaker.state).toBe('open');
    expect(fetchMock.mock.calls[0][0]).toBe('/api/admin/payments/breakers/gw%2F1');
  });
});
