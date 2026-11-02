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

describe('payment gateways', () => {
  it('lists the payment gateways and treats a non-list body as none', async () => {
    fetchMock.mockResolvedValueOnce(json([{ id: 'gw-pay', name: 'Agent Pay' }]));
    await expect(apiClient.listPaymentGateways()).resolves.toEqual([
      { id: 'gw-pay', name: 'Agent Pay' },
    ]);
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/payment-gateways');

    fetchMock.mockResolvedValueOnce(json({ error: 'unexpected' }));
    await expect(apiClient.listPaymentGateways()).resolves.toEqual([]);
  });

  it('reads the gateway info and rejects a peer that is not a payment gateway with 502', async () => {
    const info = {
      info_version: '1',
      role: 'payment',
      protocols: ['x402'],
      payment_methods: [],
      payable_count: 1,
      units: ['USDC'],
    };
    fetchMock.mockResolvedValueOnce(json(info));
    await expect(apiClient.getPaymentGatewayInfo('gw/1')).resolves.toEqual(info);
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/payment-gateways/gw%2F1/info');

    fetchMock.mockResolvedValueOnce(new Response('not a payment gateway', { status: 502 }));
    await expect(apiClient.getPaymentGatewayInfo('gw-1')).rejects.toMatchObject({ status: 502 });
  });

  it('posts the payment role and surfaces a 409 refusal as text', async () => {
    fetchMock.mockResolvedValueOnce(json({ id: 'gw-1', role: 'payment' }));
    await expect(apiClient.setGatewayPaymentRole('gw-1')).resolves.toMatchObject({
      role: 'payment',
    });
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/gateways/gw-1/payment-role');
    expect(fetchMock.mock.calls[0][1].method).toBe('POST');

    fetchMock.mockResolvedValueOnce(
      new Response('1 surface(s) route to this gateway over fabric://', { status: 409 })
    );
    await expect(apiClient.setGatewayPaymentRole('gw-1')).rejects.toMatchObject({
      status: 409,
      message: '1 surface(s) route to this gateway over fabric:// (409)',
    });
  });
});
