import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import PaymentGatewayDetailPage from '../../PaymentGatewayDetailPage';
import { ApiError, apiClient } from '../../../api';
import { showToast } from '../../../utils/toaster';

let mockPermissions: Record<string, boolean> = {};

jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    hasPermission: (feature: string) => mockPermissions[feature] === true,
  }),
}));

jest.mock('../../../utils/toaster', () => ({ showToast: jest.fn() }));

jest.mock('../../../api', () => {
  const actual = jest.requireActual('../../../api');
  return {
    ApiError: actual.ApiError,
    apiClient: {
      get: jest.fn(),
      put: jest.fn(),
      post: jest.fn(),
      delete: jest.fn(),
      getPaymentGatewayInfo: jest.fn(),
      listSurfaces: jest.fn(),
    },
  };
});

const mocked = apiClient as jest.Mocked<typeof apiClient>;

const GATEWAY = {
  id: 'gw-pay',
  name: 'Agent Pay',
  description: 'Production',
  did: 'did:web:pay.example',
  gateway_type: 'remote',
  status: 'active',
  role: 'payment',
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-02T00:00:00Z',
  peer_last_seen_at: null,
  runtime_status: { status: 'connected' },
};

const MANIFEST = {
  version: '1',
  payable: { id: 'pay-ch', name: 'Premium tools' },
  amount: { amount: '0.05', unit: 'USDC' },
  payment_points: [
    {
      id: 'x402:base',
      label: 'USDC on Base',
      protocol: 'x402',
      credential: 'eip3009_signature',
      detail: { kind: 'onChain', scheme: 'exact', network: 'base', pay_to: '0xabc' },
    },
  ],
};

const Where: React.FC = () => {
  const location = useLocation();
  return <div data-testid="where">{location.pathname + location.search}</div>;
};

function renderPage() {
  render(
    <MemoryRouter initialEntries={['/payment-gateways/gw-pay']}>
      <Routes>
        <Route path="/payment-gateways/:id" element={<PaymentGatewayDetailPage />} />
        <Route path="*" element={<Where />} />
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
  mocked.get.mockImplementation((url: string) => {
    if (url === '/payment-gateways/gw-pay') return Promise.resolve({ data: GATEWAY });
    if (url.startsWith('/payment-gateways/gw-pay/surfaces')) {
      return Promise.resolve({
        data: {
          success: true,
          channels: [
            {
              config_id: 'pay-ch',
              name: 'Premium tools',
              description: 'Paid tools',
              protocol: 'mcp',
              is_payment_surface: true,
              payment_manifest: MANIFEST,
            },
          ],
        },
      });
    }
    return Promise.reject(new Error(`unexpected ${url}`));
  });
  mocked.getPaymentGatewayInfo.mockResolvedValue({
    info_version: '1',
    role: 'payment',
    protocols: ['x402'],
    payment_methods: [],
    payable_count: 1,
    units: ['USDC'],
  });
});

describe('PaymentGatewayDetailPage', () => {
  it('shows the overview with the DID, status and offer', async () => {
    renderPage();

    expect(await screen.findByTestId('payment-gateway-name-input')).toHaveValue('Agent Pay');
    expect(screen.getByTestId('payment-gateway-did')).toHaveTextContent('did:web:pay.example');
    expect(screen.getByTestId('payment-gateway-status')).toHaveTextContent('ACTIVE');
    expect(await screen.findByTestId('payment-gateway-offer')).toHaveTextContent(
      '1 payment surface'
    );
    expect(screen.queryByText(/Publishing/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Global Policy/)).not.toBeInTheDocument();
  });

  it('saves the name and description', async () => {
    mocked.put.mockResolvedValue({ data: { ...GATEWAY, name: 'Agent Pay EU' } });
    renderPage();

    const name = await screen.findByTestId('payment-gateway-name-input');
    expect(screen.getByTestId('payment-gateway-save-button')).toBeDisabled();
    fireEvent.change(name, { target: { value: 'Agent Pay EU' } });
    // eslint-disable-next-line no-console
    fireEvent.click(screen.getByTestId('payment-gateway-save-button'));

    await waitFor(() =>
      expect(mocked.put).toHaveBeenCalledWith('/payment-gateways/gw-pay', {
        name: 'Agent Pay EU',
        description: 'Production',
      })
    );
    await waitFor(() =>
      expect(showToast).toHaveBeenCalledWith('success', 'Payment gateway updated')
    );
    expect(screen.getByTestId('payment-gateway-save-button')).toBeDisabled();
  });

  it('shows why the payment gateway cannot be disabled', async () => {
    mocked.put.mockRejectedValue(
      new ApiError('1 surface(s) take payments through this payment gateway (409)', 409)
    );
    renderPage();

    fireEvent.click(await screen.findByTestId('payment-gateway-toggle-status-button'));

    expect(await screen.findByTestId('payment-gateway-error-alert')).toHaveTextContent(
      '1 surface(s) take payments through this payment gateway (409)'
    );
    expect(mocked.put).toHaveBeenCalledWith('/payment-gateways/gw-pay', { status: 'disabled' });
    expect(screen.getByTestId('payment-gateway-status')).toHaveTextContent('ACTIVE');
  });

  it('shows why the payment gateway cannot be deleted and stays on the page', async () => {
    mocked.delete.mockRejectedValue(
      new ApiError('The payment gateway holds unsettled payments (409)', 409)
    );
    renderPage();

    const button = await screen.findByTestId('payment-gateway-delete-button');
    fireEvent.click(button);
    fireEvent.click(button);

    expect(await screen.findByTestId('payment-gateway-error-alert')).toHaveTextContent(
      'holds unsettled payments (409)'
    );
    expect(screen.getByTestId('page-payment-gateway')).toBeInTheDocument();
  });

  it('deletes and returns to the Payment Gateways tab', async () => {
    mocked.delete.mockResolvedValue({ data: {} });
    renderPage();

    const button = await screen.findByTestId('payment-gateway-delete-button');
    fireEvent.click(button);
    fireEvent.click(button);

    expect(await screen.findByTestId('where')).toHaveTextContent(
      '/connections?tab=payment-gateways'
    );
    expect(mocked.delete).toHaveBeenCalledWith('/payment-gateways/gw-pay');
  });

  it('lists the payment surfaces with their manifests and refreshes uncached', async () => {
    renderPage();

    fireEvent.click(await screen.findByTestId('payment-gateway-tab-surfaces'));

    expect(await screen.findByTestId('payment-gateway-surface-pay-ch')).toHaveTextContent(
      'Paid tools'
    );
    expect(screen.getByTestId('payment-gateway-surface-manifest-pay-ch-amount')).toHaveTextContent(
      '0.05 USDC'
    );
    expect(
      screen.queryByTestId('payment-gateway-surface-manifest-pay-ch-refresh-button')
    ).not.toBeInTheDocument();

    fireEvent.click(screen.getByTestId('payment-gateway-surfaces-refresh-button'));
    await waitFor(() =>
      expect(mocked.get).toHaveBeenCalledWith(
        '/payment-gateways/gw-pay/surfaces?force_refresh=true'
      )
    );
  });

  it('says when agent-pay does not answer for its surfaces', async () => {
    mocked.get.mockImplementation((url: string) =>
      url === '/payment-gateways/gw-pay'
        ? Promise.resolve({ data: GATEWAY })
        : Promise.resolve({ data: { success: false, channels: [], message: 'timeout' } })
    );
    renderPage();

    fireEvent.click(await screen.findByTestId('payment-gateway-tab-surfaces'));

    expect(await screen.findByTestId('payment-gateway-surfaces-error')).toHaveTextContent(
      'did not answer in time'
    );
    expect(screen.queryByTestId('payment-gateway-surfaces-empty')).not.toBeInTheDocument();
  });

  it('links the surfaces that charge through the payment gateway', async () => {
    mocked.listSurfaces.mockResolvedValue([
      {
        surface_id: 'weather',
        name: 'Weather',
        description: '',
        status: 'active',
        tags: [],
        access_point: { listen_address: '0.0.0.0:8443', route: '/w', protocol: 'mcp' },
        target: {
          endpoint: 'https://upstream',
          payment_policy: {
            type: 'agent_pay',
            payment_gateway_id: 'gw-pay',
            payment_surface_id: 'pay-ch',
          },
        },
      },
    ]);
    renderPage();

    fireEvent.click(await screen.findByTestId('payment-gateway-tab-used-by'));

    const link = await screen.findByTestId('payment-gateway-used-by-link-weather');
    expect(link).toHaveAttribute('href', '/surfaces/weather');
    expect(link).toHaveTextContent('Weather');
  });

  it('says no surface uses the payment gateway', async () => {
    mocked.listSurfaces.mockResolvedValue([]);
    renderPage();

    fireEvent.click(await screen.findByTestId('payment-gateway-tab-used-by'));

    expect(await screen.findByTestId('payment-gateway-used-by-empty')).toBeInTheDocument();
  });

  it('pings from the Health tab', async () => {
    mocked.post.mockResolvedValue({ data: { success: false, message: 'no pong' } });
    renderPage();

    fireEvent.click(await screen.findByTestId('payment-gateway-tab-health'));
    fireEvent.click(screen.getByTestId('payment-gateway-ping-button'));

    expect(await screen.findByTestId('payment-gateway-ping-result')).toHaveTextContent(
      'Ping to "Agent Pay" failed: no pong'
    );
    expect(mocked.post).toHaveBeenCalledWith('/payment-gateways/gw-pay/ping');
  });

  it('is read-only for a view-only user', async () => {
    mockPermissions = { 'payment_gateways.view': true };
    renderPage();

    expect(await screen.findByTestId('payment-gateway-name-input')).toBeDisabled();
    expect(screen.queryByTestId('payment-gateway-save-button')).not.toBeInTheDocument();
    expect(screen.queryByTestId('payment-gateway-toggle-status-button')).not.toBeInTheDocument();
    expect(screen.queryByTestId('payment-gateway-delete-button')).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId('payment-gateway-tab-health'));
    expect(screen.queryByTestId('payment-gateway-ping-button')).not.toBeInTheDocument();
  });

  it('points a payment gateway that is not active yet at Verify', async () => {
    mocked.get.mockResolvedValue({ data: { ...GATEWAY, status: 'awaiting-approval' } });
    renderPage();

    expect(await screen.findByTestId('payment-gateway-verify-button')).toHaveAttribute(
      'href',
      '/payment-gateways/connect?id=gw-pay'
    );
    expect(screen.queryByTestId('payment-gateway-toggle-status-button')).not.toBeInTheDocument();
    expect(mocked.getPaymentGatewayInfo).not.toHaveBeenCalled();
  });
});
