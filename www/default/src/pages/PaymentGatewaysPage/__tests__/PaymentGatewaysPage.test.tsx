import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import PaymentGatewaysPage from '../../PaymentGatewaysPage';
import { ApiError, apiClient } from '../../../api';
import type { GatewayListItem } from '../../../utils/gateways';

let mockPermissions: Record<string, boolean> = {};

jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    hasPermission: (feature: string) => mockPermissions[feature] === true,
  }),
}));

let mockLimitReached = false;

jest.mock('../../../hooks/useLimitGuard', () => ({
  useLimitGuard: () => ({
    guard: (dimension: string, action: () => void) => {
      mockGuardedDimension = dimension;
      if (!mockLimitReached) action();
    },
    balloonNode: null,
  }),
}));

let mockGuardedDimension = '';

jest.mock('../../../api', () => {
  const actual = jest.requireActual('../../../api');
  return {
    ApiError: actual.ApiError,
    apiClient: {
      listPaymentGateways: jest.fn(),
      getPaymentGatewayInfo: jest.fn(),
      delete: jest.fn(),
      post: jest.fn(),
    },
  };
});

const mocked = apiClient as jest.Mocked<typeof apiClient>;

const gateway = (over: Partial<GatewayListItem>): GatewayListItem => ({
  id: 'gw-pay',
  name: 'Agent Pay',
  description: 'Production agent-pay',
  did: 'did:web:pay.example',
  gateway_type: 'remote',
  status: 'active',
  role: 'payment',
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-01T00:00:00Z',
  peer_last_seen_at: null,
  ...over,
});

const ACTIVE = gateway({});
const PENDING = gateway({
  id: 'gw-new',
  name: 'New Pay',
  description: '',
  did: 'did:peer:2.new',
  status: 'awaiting-approval',
});

const INFO = {
  info_version: '1',
  role: 'payment',
  protocols: ['x402'],
  payment_methods: [{ protocol: 'x402', kind: 'onChain', network: 'base' }],
  payable_count: 2,
  units: ['USDC'],
};

const Where: React.FC = () => {
  const location = useLocation();
  return <div data-testid="where">{location.pathname + location.search}</div>;
};

function renderPage(props: React.ComponentProps<typeof PaymentGatewaysPage> = {}) {
  return render(
    <MemoryRouter initialEntries={['/connections?tab=payment-gateways']}>
      <Routes>
        <Route
          path="*"
          element={
            <>
              <PaymentGatewaysPage {...props} />
              <Where />
            </>
          }
        />
      </Routes>
    </MemoryRouter>
  );
}

beforeEach(() => {
  jest.clearAllMocks();
  mockPermissions = {
    'payment_gateways.view': true,
    'payment_gateways.edit': true,
    'payment_gateways.delete': true,
  };
  mocked.listPaymentGateways.mockResolvedValue([ACTIVE, PENDING]);
  mocked.getPaymentGatewayInfo.mockResolvedValue(INFO);
});

describe('PaymentGatewaysPage', () => {
  it('lists the payment gateways with their status and what the active ones offer', async () => {
    renderPage();

    const row = await screen.findByTestId('payment-gateways-row-gw-pay');
    expect(row).toHaveTextContent('Agent Pay');
    expect(row).toHaveTextContent('Production agent-pay');
    expect(within(row).getByTestId('gateway-status-gw-pay')).toHaveTextContent('ACTIVE');
    const offer = await screen.findByTestId('payment-gateways-offer-gw-pay');
    expect(offer).toHaveTextContent('x402');
    expect(offer).toHaveTextContent('base');
    expect(offer).toHaveTextContent('2 payment surfaces');

    const pending = screen.getByTestId('payment-gateways-row-gw-new');
    expect(within(pending).getByTestId('gateway-status-gw-new')).toHaveTextContent(
      'AWAITING APPROVAL'
    );
    expect(mocked.getPaymentGatewayInfo).toHaveBeenCalledTimes(1);
    expect(mocked.getPaymentGatewayInfo).toHaveBeenCalledWith('gw-pay');
  });

  it('keeps the list when the offer cannot be read', async () => {
    mocked.getPaymentGatewayInfo.mockRejectedValue(new ApiError('down (503)', 503));
    renderPage();

    expect(await screen.findByTestId('payment-gateways-offer-error-gw-pay')).toHaveTextContent(
      'Not reachable'
    );
    expect(screen.getByTestId('payment-gateways-row-gw-pay')).toBeInTheDocument();
    expect(screen.queryByTestId('payment-gateways-error-alert')).not.toBeInTheDocument();
  });

  it('warns when an active payment gateway exposes no payment surface', async () => {
    mocked.getPaymentGatewayInfo.mockResolvedValue({ ...INFO, payable_count: 0 });
    renderPage();

    expect(await screen.findByTestId('payment-gateways-offer-empty-gw-pay')).toHaveTextContent(
      'Exposes no payment surface'
    );
  });

  it('offers Verify for a gateway that is not active yet, resuming the wizard', async () => {
    renderPage();

    await screen.findByTestId('payment-gateways-row-gw-new');
    expect(screen.queryByTestId('payment-gateways-verify-button-gw-pay')).not.toBeInTheDocument();
    expect(screen.queryByTestId('payment-gateways-ping-button-gw-new')).not.toBeInTheDocument();

    fireEvent.click(screen.getByTestId('payment-gateways-verify-button-gw-new'));

    expect(screen.getByTestId('where')).toHaveTextContent('/payment-gateways/connect?id=gw-new');
  });

  it('opens the detail page from a row', async () => {
    renderPage();

    fireEvent.click(await screen.findByTestId('payment-gateways-open-button-gw-pay'));

    expect(screen.getByTestId('where')).toHaveTextContent('/payment-gateways/gw-pay');
  });

  it('shows the reason a delete is refused and keeps the row', async () => {
    mocked.delete.mockRejectedValue(
      new ApiError('2 surface(s) take payments through this payment gateway (409)', 409)
    );
    renderPage();

    const button = await screen.findByTestId('payment-gateways-delete-button-gw-pay');
    fireEvent.click(button);
    fireEvent.click(button);

    expect(await screen.findByTestId('payment-gateways-error-alert')).toHaveTextContent(
      '2 surface(s) take payments through this payment gateway (409)'
    );
    expect(mocked.delete).toHaveBeenCalledWith('/payment-gateways/gw-pay');
    expect(screen.getByTestId('payment-gateways-row-gw-pay')).toBeInTheDocument();
  });

  it('deletes and reloads', async () => {
    mocked.delete.mockResolvedValue({ data: {} });
    renderPage();

    const button = await screen.findByTestId('payment-gateways-delete-button-gw-new');
    mocked.listPaymentGateways.mockResolvedValue([ACTIVE]);
    fireEvent.click(button);
    fireEvent.click(button);

    expect(await screen.findByTestId('payment-gateways-success-alert')).toHaveTextContent(
      'Payment gateway "New Pay" deleted'
    );
    await waitFor(() =>
      expect(screen.queryByTestId('payment-gateways-row-gw-new')).not.toBeInTheDocument()
    );
  });

  it('pings an active payment gateway', async () => {
    mocked.post.mockResolvedValue({ data: { success: true, round_trip_ms: 12 } });
    renderPage();

    fireEvent.click(await screen.findByTestId('payment-gateways-ping-button-gw-pay'));

    expect(await screen.findByTestId('payment-gateways-success-alert')).toHaveTextContent(
      'Ping to "Agent Pay" successful (12ms)'
    );
    expect(mocked.post).toHaveBeenCalledWith('/payment-gateways/gw-pay/ping');
  });

  it('hides edit and delete actions from a view-only user', async () => {
    mockPermissions = { 'payment_gateways.view': true };
    renderPage();

    await screen.findByTestId('payment-gateways-row-gw-pay');
    expect(screen.queryByTestId('payment-gateways-connect-button')).not.toBeInTheDocument();
    expect(screen.queryByTestId('payment-gateways-verify-button-gw-new')).not.toBeInTheDocument();
    expect(screen.queryByTestId('payment-gateways-ping-button-gw-pay')).not.toBeInTheDocument();
    expect(screen.queryByTestId('payment-gateways-delete-button-gw-pay')).not.toBeInTheDocument();
    expect(screen.getByTestId('payment-gateways-open-button-gw-pay')).toBeInTheDocument();
  });

  it('filters by the shared search term and reports the counts', async () => {
    const onCountChange = jest.fn();
    renderPage({ externalSearchTerm: 'did:web:pay', onCountChange });

    await screen.findByTestId('payment-gateways-row-gw-pay');
    expect(screen.queryByTestId('payment-gateways-row-gw-new')).not.toBeInTheDocument();
    await waitFor(() => expect(onCountChange).toHaveBeenLastCalledWith(1, 2));
  });

  it('says when nothing matches the search', async () => {
    const onCountChange = jest.fn();
    renderPage({ externalSearchTerm: 'nothing-like-this', onCountChange });

    expect(await screen.findByTestId('payment-gateways-no-match')).toBeInTheDocument();
    await waitFor(() => expect(onCountChange).toHaveBeenLastCalledWith(0, 2));
  });

  it('explains agent-pay and links to the wizard when there is no payment gateway', async () => {
    mocked.listPaymentGateways.mockResolvedValue([]);
    renderPage();

    const empty = await screen.findByTestId('payment-gateways-empty-state');
    expect(empty).toHaveTextContent('agent-pay');
    fireEvent.click(screen.getByTestId('payment-gateways-empty-connect-button'));

    expect(screen.getByTestId('where')).toHaveTextContent('/payment-gateways/connect');
  });

  it('renders the Connect button in the tab banner when given one', async () => {
    const banner = document.createElement('div');
    document.body.appendChild(banner);
    renderPage({ externalSearchTerm: '', actionsContainer: banner });

    await screen.findByTestId('payment-gateways-row-gw-pay');
    expect(within(banner).getByTestId('payment-gateways-connect-button')).toBeInTheDocument();
    fireEvent.click(within(banner).getByTestId('payment-gateways-connect-button'));
    expect(screen.getByTestId('where')).toHaveTextContent('/payment-gateways/connect');
    banner.remove();
  });

  it('does not open the wizard when the payment gateway limit is reached', async () => {
    mockLimitReached = true;
    const banner = document.createElement('div');
    document.body.appendChild(banner);
    renderPage({ externalSearchTerm: '', actionsContainer: banner });

    await screen.findByTestId('payment-gateways-row-gw-pay');
    fireEvent.click(within(banner).getByTestId('payment-gateways-connect-button'));
    expect(mockGuardedDimension).toBe('connections.paymentgateways');
    expect(screen.getByTestId('where')).not.toHaveTextContent('/payment-gateways/connect');
    banner.remove();
    mockLimitReached = false;
  });

  it('shows a failed load', async () => {
    mocked.listPaymentGateways.mockRejectedValue(new Error('Forbidden (403)'));
    renderPage();

    expect(await screen.findByTestId('payment-gateways-error-alert')).toHaveTextContent(
      'Forbidden (403)'
    );
  });
});
