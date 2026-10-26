import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import SurfacePaymentActivity, { RECENT_ROWS } from '../payment/SurfacePaymentActivity';
import { apiClient } from '../../../../api';

jest.mock('../../../../api', () => ({
  apiClient: {
    getPaymentSummary: jest.fn(),
    listPayments: jest.fn(),
    getPaymentBreaker: jest.fn(),
  },
}));

const mockSummary = apiClient.getPaymentSummary as jest.Mock;
const mockList = apiClient.listPayments as jest.Mock;
const mockBreaker = apiClient.getPaymentBreaker as jest.Mock;

const renderPanel = () =>
  render(
    <MemoryRouter>
      <SurfacePaymentActivity surfaceId="weather" paymentGatewayId="gw-pay" />
    </MemoryRouter>
  );

beforeEach(() => {
  jest.resetAllMocks();
});

describe('SurfacePaymentActivity', () => {
  it('shows the 24 h counts, the breaker and the newest rows, and links to the payments', async () => {
    mockSummary.mockResolvedValue({ since: 's', total: 3, counts: { paid: 2, rejected: 1 } });
    mockList.mockResolvedValue({
      payments: [
        {
          id: 'p-1',
          created_at: 1_700_000_000,
          surface_id: 'weather',
          payment_gateway_id: 'gw-pay',
          payment_surface_id: 'ps',
          outcome: 'rejected',
          reason: 'card declined',
          latency_ms: 3,
        },
      ],
      total: 3,
    });
    mockBreaker.mockResolvedValue({
      payment_gateway_id: 'gw-pay',
      state: 'open',
      consecutive_failures: 5,
      retry_after_secs: 12,
      failures_to_open: 5,
      open_secs: 30,
    });
    renderPanel();

    expect(await screen.findByTestId('surface-payment-count-paid')).toHaveTextContent('Paid 2');
    expect(screen.getByTestId('surface-payment-count-rejected')).toHaveTextContent('Rejected 1');
    expect(screen.queryByTestId('surface-payment-count-held')).not.toBeInTheDocument();
    expect(screen.getByTestId('surface-payment-breaker')).toHaveTextContent('Open retry in 12s');
    expect(screen.getByTestId('surface-payment-activity-link')).toHaveAttribute(
      'href',
      '/payments?surface_id=weather'
    );
    expect(mockSummary).toHaveBeenCalledWith('weather', 24);
    expect(mockList).toHaveBeenCalledWith({ surface_id: 'weather', limit: RECENT_ROWS });
    expect(mockBreaker).toHaveBeenCalledWith('gw-pay');

    expect(screen.queryByTestId('surface-payment-recent')).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId('surface-payment-recent-toggle'));
    expect(screen.getByTestId('surface-payment-recent-p-1')).toHaveTextContent('card declined');
  });

  it('says there were no payments and leaves the breaker out when it cannot be read', async () => {
    mockSummary.mockResolvedValue({ since: 's', total: 0, counts: {} });
    mockList.mockResolvedValue({ payments: [], total: 0 });
    mockBreaker.mockRejectedValue(new Error('not found'));
    renderPanel();

    expect(await screen.findByTestId('surface-payment-activity-empty')).toHaveTextContent(
      'No payments'
    );
    expect(screen.queryByTestId('surface-payment-breaker')).not.toBeInTheDocument();
    expect(screen.queryByTestId('surface-payment-recent-toggle')).not.toBeInTheDocument();
  });

  it('reports a failure to read the ledger', async () => {
    mockSummary.mockRejectedValue(new Error('ledger down'));
    mockList.mockResolvedValue({ payments: [], total: 0 });
    mockBreaker.mockResolvedValue(null);
    renderPanel();

    await waitFor(() =>
      expect(screen.getByTestId('surface-payment-activity-error')).toHaveTextContent('ledger down')
    );
  });
});
