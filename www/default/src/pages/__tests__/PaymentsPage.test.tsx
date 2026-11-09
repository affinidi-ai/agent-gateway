import React from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import PaymentsPage from '../PaymentsPage';
import { OUTCOME_META } from '../PaymentsPage/ledger';
import { apiClient } from '../../api';
import { PAYMENT_OUTCOMES } from '../../types';
import type { PaymentCaseStatus, PaymentLedgerPage, PaymentLedgerRow } from '../../types';

jest.mock('../../api', () => ({
  apiClient: {
    fetch: jest.fn(),
    listPayments: jest.fn(),
    getPayment: jest.fn(),
    listPaymentGateways: jest.fn(),
  },
}));

let mockFlags: Record<string, boolean> = { agent_pay_delegation: true };

jest.mock('../../context/AppContext', () => ({
  useApp: () => ({ state: { settings: { feature_flags: mockFlags } } }),
}));

const mockFetch = apiClient.fetch as jest.Mock;
const mockList = apiClient.listPayments as jest.Mock;
const mockGet = apiClient.getPayment as jest.Mock;
const mockGateways = apiClient.listPaymentGateways as jest.Mock;

const row = (over: Partial<PaymentLedgerRow>): PaymentLedgerRow => ({
  id: 'p-1',
  created_at: 1_700_000_000,
  surface_id: 'weather',
  payment_gateway_id: 'gw-pay',
  payment_surface_id: 'pay-ch',
  outcome: 'paid',
  rail: 'x402',
  amount: '0.01',
  currency: 'USDC',
  resource: 'get_forecast',
  latency_ms: 42,
  ...over,
});

const paid = row({ id: 'p-1', receipt_reference: 'rcpt-1', vc_fingerprint: 'fp-1' });
const held = row({ id: 'p-2', outcome: 'held', case_id: 'case-77', rail: undefined });

const ok = (body: unknown) => Promise.resolve({ ok: true, json: () => Promise.resolve(body) });

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

interface LegacyData {
  x402?: Array<Record<string, unknown>>;
  mpp?: Array<Record<string, unknown>>;
}

function mockApi({ x402 = [], mpp = [] }: LegacyData = {}) {
  mockList.mockImplementation(({ outcome }: { outcome?: string }) =>
    Promise.resolve({
      payments: [paid, held].filter(r => !outcome || r.outcome === outcome),
      total: 2,
    })
  );
  mockGet.mockResolvedValue({ ...paid, remote_status: 200, trace_id: 'trace-1' });
  mockFetch.mockImplementation((url: string) => {
    if (url.startsWith('/api/admin/x402/payments/all')) return ok({ payments: x402 });
    if (url.startsWith('/api/admin/mpp/transactions')) return ok({ transactions: mpp });
    return Promise.reject(new Error(`unexpected ${url}`));
  });
}

const renderPage = (path = '/x402payments') =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <PaymentsPage />
    </MemoryRouter>
  );

beforeEach(() => {
  jest.resetAllMocks();
  mockGateways.mockResolvedValue([]);
  mockFlags = { agent_pay_delegation: true };
});

describe('PaymentsPage', () => {
  it('lists ledger rows with a held badge carrying the case id', async () => {
    mockApi();
    renderPage();

    expect(await screen.findByTestId('payments-row-p-1')).toHaveTextContent('Paid');
    expect(screen.getByTestId('payments-row-p-1')).toHaveTextContent('get_forecast');
    expect(screen.getByTestId('payments-row-p-1')).toHaveTextContent('0.01 USDC');
    expect(screen.getByTestId('payments-row-p-2')).toHaveTextContent('Held');
    expect(screen.getByTestId('payments-held-case-p-2')).toHaveTextContent('case-77');
    expect(screen.queryByTestId('payments-held-case-p-1')).not.toBeInTheDocument();
    expect(screen.getByTestId('payments-surface-link-p-1')).toHaveAttribute(
      'href',
      '/surfaces/weather'
    );
    expect(mockList).toHaveBeenCalledWith({
      limit: 500,
      surface_id: undefined,
      outcome: undefined,
    });
  });

  it('filters by outcome on the server', async () => {
    mockApi();
    renderPage();
    await screen.findByTestId('payments-row-p-2');

    fireEvent.change(screen.getByTestId('payments-outcome-filter'), { target: { value: 'held' } });

    await waitFor(() => expect(screen.queryByTestId('payments-row-p-1')).not.toBeInTheDocument());
    expect(screen.getByTestId('payments-row-p-2')).toBeInTheDocument();
    expect(mockList).toHaveBeenLastCalledWith({
      limit: 500,
      surface_id: undefined,
      outcome: 'held',
    });
  });

  it('filters the loaded rows by the search text', async () => {
    mockApi();
    renderPage();
    await screen.findByTestId('payments-row-p-1');

    fireEvent.change(screen.getByTestId('payments-filter-input'), { target: { value: 'case-77' } });

    expect(screen.queryByTestId('payments-row-p-1')).not.toBeInTheDocument();
    expect(screen.getByTestId('payments-row-p-2')).toBeInTheDocument();
  });

  it('passes a surface filter from the URL', async () => {
    mockApi();
    renderPage('/x402payments?surface_id=weather');

    expect(await screen.findByTestId('payments-surface-filter')).toHaveTextContent('weather');
    expect(mockList).toHaveBeenCalledWith({
      limit: 500,
      surface_id: 'weather',
      outcome: undefined,
    });
  });

  it('opens the detail modal with receipt, fingerprint and remote status', async () => {
    mockApi();
    renderPage();

    fireEvent.click(await screen.findByTestId('payments-details-button-p-1'));

    const modal = await screen.findByTestId('payments-detail-modal');
    await waitFor(() => expect(modal).toHaveTextContent('rcpt-1'));
    expect(mockGet).toHaveBeenCalledWith('p-1');
    expect(modal).toHaveTextContent('fp-1');
    expect(modal).toHaveTextContent('trace-1');
    expect(modal).toHaveTextContent('42 ms');
    expect(modal).toHaveTextContent(/Remote status\s*200/);
    expect(screen.queryByTestId('payments-detail-case-status')).not.toBeInTheDocument();

    fireEvent.click(screen.getByTestId('payments-detail-close-button'));
    expect(screen.queryByTestId('payments-detail-modal')).not.toBeInTheDocument();
  });

  it('shows the settlement of a held authorization and a price mismatch in the details', async () => {
    mockApi();
    mockGet.mockResolvedValue({
      ...paid,
      outcome: 'authorized',
      amount: '0.75',
      currency: 'USD',
      price_mismatch: true,
      quoted_amount: '0.50',
      quoted_currency: 'USD',
      authorization_id: 'auth-9',
      capture_deadline: '2030-01-02T03:04:05Z',
      settle_intent: 'capture',
      settle_attempts: 2,
      superseded_by: 'p-8',
      reconcile_failed: true,
    });
    renderPage();

    fireEvent.click(await screen.findByTestId('payments-details-button-p-1'));

    expect(await screen.findByTestId('payments-detail-authorization-id')).toHaveTextContent(
      'auth-9'
    );
    expect(screen.getByTestId('payments-detail-capture-deadline')).toHaveTextContent(
      new Date('2030-01-02T03:04:05Z').toLocaleString()
    );
    expect(screen.getByTestId('payments-detail-settle-intent')).toHaveTextContent(
      'Capture (2 attempts)'
    );
    expect(screen.getByTestId('payments-detail-settlement-status')).toHaveTextContent(
      'Reconciliation gave up'
    );
    expect(screen.getByTestId('payments-detail-price-mismatch')).toHaveTextContent(
      '0.75 USD charged, 0.50 USD quoted'
    );
    expect(screen.getByTestId('payments-detail-superseded-by')).toHaveTextContent('p-8');
    expect(screen.getByTestId('payments-detail-reconcile-failed')).toHaveTextContent(
      'Reconcile failed'
    );
  });

  it('shows no settlement fields for a payment captured at once', async () => {
    mockApi();
    renderPage();

    fireEvent.click(await screen.findByTestId('payments-details-button-p-1'));

    await waitFor(() =>
      expect(screen.getByTestId('payments-detail-modal')).toHaveTextContent('rcpt-1')
    );
    for (const id of [
      'authorization-id',
      'capture-deadline',
      'settle-intent',
      'settlement-status',
      'price-mismatch',
      'superseded-by',
      'reconcile-failed',
    ]) {
      expect(screen.queryByTestId(`payments-detail-${id}`)).not.toBeInTheDocument();
    }
  });

  it('closes the detail modal from its header button', async () => {
    mockApi();
    renderPage();

    fireEvent.click(await screen.findByTestId('payments-details-button-p-1'));
    await screen.findByTestId('payments-detail-modal');
    fireEvent.click(screen.getByTestId('payments-detail-dismiss-button'));

    expect(screen.queryByTestId('payments-detail-modal')).not.toBeInTheDocument();
  });

  it('hides the legacy list when the old endpoints are empty', async () => {
    mockApi();
    renderPage();
    await screen.findByTestId('payments-row-p-1');

    expect(screen.queryByTestId('payments-legacy-panel')).not.toBeInTheDocument();
    expect(screen.queryByRole('tab')).not.toBeInTheDocument();
    expect(screen.queryByText('Audit trail')).not.toBeInTheDocument();
  });

  it('shows the empty state when the ledger is empty', async () => {
    mockApi();
    mockList.mockResolvedValue({ payments: [], total: 0 });
    renderPage();

    expect(await screen.findByText('No payments yet')).toBeInTheDocument();
  });

  it('shows an error when the ledger cannot be loaded, and dismisses it', async () => {
    mockApi();
    mockList.mockRejectedValue(new Error('Forbidden'));
    renderPage();

    expect(await screen.findByTestId('payments-error-alert')).toHaveTextContent('Forbidden');

    fireEvent.click(screen.getByTestId('payments-error-dismiss-button'));
    expect(screen.queryByTestId('payments-error-alert')).not.toBeInTheDocument();
  });
});

describe('PaymentsPage — payment gateway names', () => {
  it('names the payment gateway in the row and the details', async () => {
    mockApi();
    mockGateways.mockResolvedValue([{ id: 'gw-pay', name: 'Agent Pay' }]);
    renderPage();

    await waitFor(() =>
      expect(screen.getByTestId('payments-gateway-p-1')).toHaveTextContent(
        'via pay-ch on Agent Pay'
      )
    );
    expect(screen.getByTestId('payments-gateway-p-1')).toHaveAttribute('title', 'gw-pay');
    expect(mockGateways).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByTestId('payments-details-button-p-1'));
    expect(await screen.findByTestId('payments-detail-gateway')).toHaveTextContent('Agent Pay');
  });

  it('falls back to the id when the gateway is not listed or the list fails', async () => {
    mockApi();
    mockGateways.mockRejectedValue(new Error('Forbidden (403)'));
    renderPage();

    expect(await screen.findByTestId('payments-gateway-p-1')).toHaveTextContent(
      'via pay-ch on gw-pay'
    );
    fireEvent.click(screen.getByTestId('payments-details-button-p-1'));
    expect(await screen.findByTestId('payments-detail-gateway')).toHaveTextContent('gw-pay');
    expect(screen.queryByTestId('payments-error-alert')).not.toBeInTheDocument();
  });
});

describe('PaymentsPage — filters and failed refreshes', () => {
  it('says no payments match a filter instead of that there are none yet', async () => {
    mockApi();
    mockList.mockResolvedValue({ payments: [], total: 0 });
    renderPage();
    expect(await screen.findByText('No payments yet')).toBeInTheDocument();

    fireEvent.change(screen.getByTestId('payments-outcome-filter'), {
      target: { value: 'rejected' },
    });

    expect(await screen.findByText('No payments match this filter')).toBeInTheDocument();
    expect(screen.queryByText('No payments yet')).not.toBeInTheDocument();
    expect(screen.getByText(/There are no Rejected payments\./)).toBeInTheDocument();
  });

  it('names the surface in the empty state of a surface filter', async () => {
    mockApi();
    mockList.mockResolvedValue({ payments: [], total: 0 });
    renderPage('/x402payments?surface_id=weather');

    expect(await screen.findByText('No payments match this filter')).toBeInTheDocument();
    expect(screen.getByText(/There are no payments for surface weather\./)).toBeInTheDocument();
  });

  it('marks the rows as out of date when a refresh of the same filter fails', async () => {
    mockApi();
    renderPage();
    await screen.findByTestId('payments-row-p-1');
    expect(screen.queryByTestId('payments-stale-note')).not.toBeInTheDocument();

    mockList.mockRejectedValue(new Error('Gateway down'));
    fireEvent.click(screen.getByTestId('payments-refresh-button'));

    expect(await screen.findByTestId('payments-error-alert')).toHaveTextContent('Gateway down');
    expect(screen.getByTestId('payments-stale-note')).toBeInTheDocument();
    expect(screen.getByTestId('payments-row-p-1')).toBeInTheDocument();

    mockList.mockResolvedValue({ payments: [paid], total: 1 });
    fireEvent.click(screen.getByTestId('payments-refresh-button'));
    await waitFor(() =>
      expect(screen.queryByTestId('payments-stale-note')).not.toBeInTheDocument()
    );
  });

  it('drops the rows of the previous filter when the new filter fails to load', async () => {
    mockApi();
    renderPage();
    await screen.findByTestId('payments-row-p-1');

    mockList.mockRejectedValue(new Error('Gateway down'));
    fireEvent.change(screen.getByTestId('payments-outcome-filter'), { target: { value: 'held' } });

    expect(await screen.findByTestId('payments-error-alert')).toBeInTheDocument();
    expect(screen.queryByTestId('payments-row-p-1')).not.toBeInTheDocument();
    expect(screen.queryByTestId('payments-row-p-2')).not.toBeInTheDocument();
    expect(screen.queryByTestId('payments-stale-note')).not.toBeInTheDocument();
  });
});

describe('PaymentsPage — unconfirmed outcome', () => {
  const unconfirmed = row({ id: 'p-9', outcome: 'unconfirmed' });
  const note =
    'Payment taken or unconfirmed - retry the same request with the same credential within 2 minutes';

  it('offers it as a filter and asks the server for it', async () => {
    mockApi();
    renderPage();
    await screen.findByTestId('payments-row-p-1');

    const options = within(screen.getByTestId('payments-outcome-filter'))
      .getAllByRole('option')
      .map(o => o.textContent);
    expect(options).toContain('Unconfirmed');

    fireEvent.change(screen.getByTestId('payments-outcome-filter'), {
      target: { value: 'unconfirmed' },
    });
    await waitFor(() =>
      expect(mockList).toHaveBeenLastCalledWith({
        limit: 500,
        surface_id: undefined,
        outcome: 'unconfirmed',
      })
    );
  });

  it('shows the row with its label and the retry advice in the details', async () => {
    mockApi();
    mockList.mockResolvedValue({ payments: [unconfirmed], total: 1 });
    mockGet.mockResolvedValue(unconfirmed);
    renderPage();

    expect(await screen.findByTestId('payments-row-p-9')).toHaveTextContent('Unconfirmed');
    fireEvent.click(screen.getByTestId('payments-details-button-p-9'));

    expect(await screen.findByTestId('payments-detail-outcome-note')).toHaveTextContent(note);
  });

  it('gives other outcomes no such note', async () => {
    mockApi();
    renderPage();
    await screen.findByTestId('payments-row-p-1');
    fireEvent.click(screen.getByTestId('payments-details-button-p-1'));

    await screen.findByTestId('payments-detail-modal');
    await waitFor(() => expect(mockGet).toHaveBeenCalled());
    expect(screen.queryByTestId('payments-detail-outcome-note')).not.toBeInTheDocument();
  });

  it('labels it', () => {
    expect(OUTCOME_META.unconfirmed.label).toBe('Unconfirmed');
    expect(OUTCOME_META.unconfirmed.note).toBe(note);
    expect(PAYMENT_OUTCOMES).toContain('unconfirmed');
  });
});

describe('PaymentsPage — payments held until delivery', () => {
  it('labels authorized, voided and capture_failed rows', () => {
    expect(OUTCOME_META.capture_failed.label).toBe('Capture failed');
    expect(OUTCOME_META.capture_failed.tone).toBe('danger');
    expect(OUTCOME_META.voided.label).toBe('Voided');
    expect(PAYMENT_OUTCOMES).toEqual(
      expect.arrayContaining(['authorized', 'voided', 'capture_failed'])
    );
  });
});

describe('PaymentsPage — overlapping requests', () => {
  const page = (payments: PaymentLedgerRow[]): PaymentLedgerPage => ({
    payments,
    total: payments.length,
  });

  it('ignores an earlier answer that arrives after a later one', async () => {
    mockApi();
    const all = deferred<PaymentLedgerPage>();
    mockList.mockReturnValueOnce(all.promise).mockResolvedValueOnce(page([held]));
    renderPage();

    fireEvent.change(await screen.findByTestId('payments-outcome-filter'), {
      target: { value: 'held' },
    });
    expect(await screen.findByTestId('payments-row-p-2')).toBeInTheDocument();

    await act(async () => {
      all.resolve(page([paid, held]));
    });

    expect(screen.queryByTestId('payments-row-p-1')).not.toBeInTheDocument();
    expect(screen.getByTestId('payments-row-p-2')).toBeInTheDocument();
    expect(screen.getByTestId('payments-outcome-filter')).toHaveValue('held');
  });

  it('keeps Refresh busy until the latest request is done and ignores an earlier failure', async () => {
    mockApi();
    const first = deferred<PaymentLedgerPage>();
    const second = deferred<PaymentLedgerPage>();
    mockList.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    renderPage();

    fireEvent.change(await screen.findByTestId('payments-outcome-filter'), {
      target: { value: 'held' },
    });
    const refresh = screen.getByTestId('payments-refresh-button');
    expect(refresh).toBeDisabled();

    await act(async () => {
      first.reject(new Error('earlier request failed'));
    });
    expect(screen.queryByTestId('payments-error-alert')).not.toBeInTheDocument();
    expect(refresh).toBeDisabled();

    await act(async () => {
      second.resolve(page([held]));
    });
    await waitFor(() => expect(refresh).toBeEnabled());
    expect(screen.getByTestId('payments-row-p-2')).toBeInTheDocument();
    expect(screen.queryByTestId('payments-row-p-1')).not.toBeInTheDocument();
  });

  it('shows the error of the latest request even when an earlier one succeeds later', async () => {
    mockApi();
    const first = deferred<PaymentLedgerPage>();
    mockList.mockReturnValueOnce(first.promise).mockRejectedValueOnce(new Error('Forbidden'));
    renderPage();

    fireEvent.change(await screen.findByTestId('payments-outcome-filter'), {
      target: { value: 'held' },
    });
    expect(await screen.findByTestId('payments-error-alert')).toHaveTextContent('Forbidden');

    await act(async () => {
      first.resolve(page([paid, held]));
    });

    expect(screen.getByTestId('payments-error-alert')).toHaveTextContent('Forbidden');
    expect(screen.queryByTestId('payments-row-p-1')).not.toBeInTheDocument();
  });
});

describe('PaymentsPage — held payment status', () => {
  const report = (status: PaymentCaseStatus, checked_at = '2026-10-20T10:00:00Z') => ({
    status,
    checked_at,
  });
  const heldDetail = (case_status?: PaymentLedgerRow['case_status']) =>
    ({ ...held, ...(case_status ? { case_status } : {}) }) as PaymentLedgerRow;

  const openHeld = async () => {
    renderPage();
    fireEvent.click(await screen.findByTestId('payments-details-button-p-2'));
    return screen.findByTestId('payments-detail-case-status');
  };

  it.each([
    ['held', 'Held', 'Waiting for a reviewer'],
    ['approved', 'Approved', 'the capture is not confirmed yet'],
    ['captured', 'Captured', 'agent-pay captured it'],
    ['rejected', 'Rejected', 'Nothing was taken'],
    ['voided', 'Voided', 'An operator voided this case'],
    [
      'capture_failed',
      'Capture failed',
      'Payment capture failed or is unconfirmed - reconcile before asking the payer to pay again',
    ],
  ] as const)('explains the %s status in plain words', async (status, label, text) => {
    mockApi();
    mockGet.mockResolvedValue(heldDetail(report(status)));

    const caseStatus = await openHeld();

    expect(caseStatus).toHaveTextContent(label);
    expect(within(caseStatus).getByTestId('payments-detail-case-status-text')).toHaveTextContent(
      text
    );
    expect(caseStatus).toHaveTextContent(/Checked .*2026/);
  });

  it('shows the state of the payment now, which can differ from the row outcome', async () => {
    mockApi();
    mockGet.mockResolvedValue(heldDetail(report('captured')));

    const caseStatus = await openHeld();

    expect(screen.getByTestId('payments-detail-modal')).toHaveTextContent('Held');
    expect(caseStatus).toHaveTextContent('Captured');
  });

  it('says so when agent-pay could not be asked', async () => {
    mockApi();
    mockGet.mockResolvedValue(heldDetail());

    const caseStatus = await openHeld();

    expect(caseStatus).toHaveTextContent(/Not available: agent-pay may not be connected/);
    expect(within(caseStatus).getByTestId('payments-detail-refresh-button')).toBeEnabled();
  });

  it('shows a status the page does not know as reported', async () => {
    mockApi();
    mockGet.mockResolvedValue(heldDetail({ status: 'escalated', checked_at: 'soon' } as never));

    const caseStatus = await openHeld();

    expect(caseStatus).toHaveTextContent('escalated');
    expect(caseStatus).toHaveTextContent('a status this page does not know');
    expect(caseStatus).toHaveTextContent('Checked soon');
  });

  it('asks again on Refresh status and keeps the row visible meanwhile', async () => {
    mockApi();
    const again = deferred<PaymentLedgerRow>();
    mockGet
      .mockResolvedValueOnce(heldDetail(report('capture_failed')))
      .mockReturnValueOnce(again.promise);

    const caseStatus = await openHeld();
    expect(caseStatus).toHaveTextContent('Capture failed');

    fireEvent.click(screen.getByTestId('payments-detail-refresh-button'));

    await waitFor(() =>
      expect(screen.getByTestId('payments-detail-refresh-button')).toBeDisabled()
    );
    expect(mockGet).toHaveBeenCalledTimes(2);
    expect(mockGet).toHaveBeenLastCalledWith('p-2');
    expect(screen.getByTestId('payments-detail-case-status')).toHaveTextContent('Capture failed');
    expect(screen.getByTestId('payments-detail-modal')).toHaveTextContent('case-77');

    await act(async () => {
      again.resolve(heldDetail(report('captured', '2026-10-20T10:05:00Z')));
    });

    const refreshed = screen.getByTestId('payments-detail-case-status');
    expect(refreshed).toHaveTextContent('Captured');
    expect(refreshed).not.toHaveTextContent('reconcile');
    expect(screen.getByTestId('payments-detail-refresh-button')).toBeEnabled();
  });

  it('keeps the last status and reports the failure when a refresh fails', async () => {
    mockApi();
    mockGet
      .mockResolvedValueOnce(heldDetail(report('held')))
      .mockRejectedValueOnce(new Error('Gateway unreachable'));

    await openHeld();
    fireEvent.click(screen.getByTestId('payments-detail-refresh-button'));

    expect(await screen.findByTestId('payments-detail-error')).toHaveTextContent(
      'Gateway unreachable'
    );
    expect(screen.getByTestId('payments-detail-case-status')).toHaveTextContent('Held');
    expect(screen.getByTestId('payments-detail-refresh-button')).toBeEnabled();
  });

  it('does not offer a status for a payment that was never held', async () => {
    mockApi();
    mockGet.mockResolvedValue({ ...paid, case_status: report('captured') });
    renderPage();

    fireEvent.click(await screen.findByTestId('payments-details-button-p-1'));

    await screen.findByText('rcpt-1');
    expect(screen.queryByTestId('payments-detail-case-status')).not.toBeInTheDocument();
  });
});

describe('PaymentsPage — legacy rows', () => {
  const verification = (id: string, amount: string, created_at: number) => ({
    type: 'verification',
    id: `${id}_verification`,
    correlation_id: id,
    surface_id: 'old',
    channel_name: 'old-surface',
    status: 'Verified',
    amount,
    decimals: 6,
    asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    created_at,
  });
  const settlement = (id: string, amount: string, created_at: number) => ({
    type: 'settlement',
    id: `${id}_settlement`,
    correlation_id: id,
    surface_id: 'old',
    channel_name: 'old-surface',
    status: 'Completed',
    amount,
    decimals: 6,
    asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    created_at,
    verified_at: created_at,
  });

  it('shows one row per transaction, with its amount in dollars, and counts transactions', async () => {
    mockApi({
      x402: [
        verification('tx-1', '10000', 1_700_000_100),
        settlement('tx-1', '10000', 1_700_000_100),
        verification('tx-2', '2500000', 1_700_000_200),
      ],
      mpp: [
        {
          id: 'm-1',
          channel_name: 'mpp-surface',
          status: 'verified',
          amount: '1.50',
          currency: 'usd',
          created_at: 1_700_000_300,
        },
      ],
    });
    renderPage();

    const panel = await screen.findByTestId('payments-legacy-panel');
    expect(within(panel).getAllByTestId(/^payments-legacy-row-/)).toHaveLength(3);

    const settled = within(panel).getByTestId('payments-legacy-row-x402-tx-1');
    expect(settled).toHaveTextContent('old-surface');
    expect(settled).toHaveTextContent('Completed');
    expect(settled).toHaveTextContent('$0.01');
    expect(settled).not.toHaveTextContent('Verified');
    expect(settled).not.toHaveTextContent('0x8335');
    expect(settled).not.toHaveTextContent('10000');

    const verified = within(panel).getByTestId('payments-legacy-row-x402-tx-2');
    expect(verified).toHaveTextContent('Verified');
    expect(verified).toHaveTextContent('$2.50');

    const mpp = within(panel).getByTestId('payments-legacy-row-mpp-m-1');
    expect(mpp).toHaveTextContent('$1.50');
    expect(within(panel).queryByRole('button')).not.toBeInTheDocument();
  });

  it('orders the rows newest first', async () => {
    mockApi({
      x402: [
        verification('tx-old', '1000000', 1_700_000_000),
        verification('tx-new', '3000000', 1_700_009_000),
      ],
    });
    renderPage();

    const panel = await screen.findByTestId('payments-legacy-panel');
    const keys = within(panel)
      .getAllByTestId(/^payments-legacy-row-/)
      .map(r => r.getAttribute('data-testid'));
    expect(keys).toEqual(['payments-legacy-row-x402-tx-new', 'payments-legacy-row-x402-tx-old']);
  });

  it('shows the legacy rows below the payments list', async () => {
    mockApi({ x402: [verification('tx-1', '10000', 1_700_000_100)] });
    renderPage();

    expect(await screen.findByTestId('payments-legacy-panel')).toBeInTheDocument();
    expect(screen.getByTestId('payments-row-p-1')).toBeInTheDocument();
  });

  it('shows the legacy rows and the payments while agent-pay is off', async () => {
    mockFlags = {};
    mockApi({ x402: [settlement('tx-1', '10000', 1_700_000_100)] });
    renderPage();

    const panel = await screen.findByTestId('payments-legacy-panel');
    expect(within(panel).getByTestId('payments-legacy-row-x402-tx-1')).toHaveTextContent('$0.01');
    expect(screen.getByTestId('payments-row-p-1')).toBeInTheDocument();
  });
});

describe('PaymentsPage — agent-pay flag', () => {
  const emptyLedger = () => {
    mockApi();
    mockList.mockResolvedValue({ payments: [], total: 0 });
  };

  it('points an empty ledger at the Payment element while agent-pay is on', async () => {
    emptyLedger();
    renderPage();

    expect(await screen.findByText('No payments yet')).toBeInTheDocument();
    expect(screen.getByText(/surface with a Payment element/)).toBeInTheDocument();
    expect(screen.queryByText(/agent_pay_delegation/)).not.toBeInTheDocument();
  });

  it('names the flag instead of the Payment element while agent-pay is off', async () => {
    mockFlags = {};
    emptyLedger();
    renderPage();

    expect(await screen.findByText('No payments yet')).toBeInTheDocument();
    expect(screen.getByText(/needs the agent_pay_delegation feature flag/)).toBeInTheDocument();
    expect(screen.queryByText(/surface with a Payment element/)).not.toBeInTheDocument();
  });
});

describe('PaymentsPage — reasons and hidden fields', () => {
  it('shows a refused row its reason as a hint and in its details with the hidden fields', async () => {
    const rejected = row({
      id: 'p-9',
      outcome: 'rejected',
      reason: 'insufficient_funds: card declined',
      trace_id: 'trace-9',
    });
    mockApi();
    mockList.mockResolvedValue({ payments: [rejected, paid], total: 2 });
    mockGet.mockResolvedValue({
      ...rejected,
      idempotency_key: 'idem-1',
      settle_timeout_ms: 1500,
      updated_at: '2026-10-26T10:00:00Z',
      caller_principal: 'hmac-sha256:abc',
    });
    renderPage();

    const hint = await screen.findByTestId('payments-reason-p-9');
    expect(hint).toHaveTextContent('insufficient_funds: card declined');
    expect(hint).toHaveAttribute('title', 'insufficient_funds: card declined');
    expect(screen.queryByTestId('payments-reason-p-1')).not.toBeInTheDocument();

    fireEvent.click(screen.getByTestId('payments-details-button-p-9'));
    expect(await screen.findByTestId('payments-detail-reason')).toHaveTextContent(
      'insufficient_funds: card declined'
    );
    expect(screen.getByTestId('payments-detail-idempotency-key')).toHaveTextContent('idem-1');
    expect(screen.getByTestId('payments-detail-settle-timeout')).toHaveTextContent('1500 ms');
    expect(screen.getByTestId('payments-detail-updated-at')).not.toBeEmptyDOMElement();
    expect(screen.getByTestId('payments-detail-caller-principal')).toHaveTextContent(
      'hmac-sha256:abc'
    );
    expect(screen.getByTestId('payments-detail-modal')).toHaveTextContent('Caller (hashed)');
  });

  it('leaves the hidden fields out of a row without them', async () => {
    mockApi();
    renderPage();
    fireEvent.click(await screen.findByTestId('payments-details-button-p-1'));
    await screen.findByText('rcpt-1');
    for (const id of [
      'payments-detail-reason',
      'payments-detail-idempotency-key',
      'payments-detail-settle-timeout',
      'payments-detail-updated-at',
      'payments-detail-caller-principal',
    ]) {
      expect(screen.queryByTestId(id)).not.toBeInTheDocument();
    }
  });

  it('offers no audit link from a payment with a trace id', async () => {
    mockApi();
    renderPage();
    fireEvent.click(await screen.findByTestId('payments-details-button-p-1'));
    await screen.findByText('rcpt-1');
    expect(screen.queryByTestId('payments-detail-audit-link')).not.toBeInTheDocument();
  });
});
