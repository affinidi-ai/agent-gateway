import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import AddPaymentGatewayWizardPage from '../../AddPaymentGatewayWizardPage';
import { APPROVAL_POLL_MS } from '../AwaitApprovalStep';
import { VERIFY_RETRY_MS } from '../VerifyPaymentGatewayStep';
import { ApiError, apiClient } from '../../../api';

jest.mock('../../../api', () => {
  const actual = jest.requireActual('../../../api');
  return {
    ApiError: actual.ApiError,
    apiClient: { get: jest.fn(), getPaymentGatewayInfo: jest.fn() },
  };
});

jest.mock('../../../context/AppContext', () => ({
  useApp: () => ({ state: { settings: { feature_flags: {} } } }),
}));

jest.mock(
  '../../../components/gateway-add-via-oob/ConnectStep',
  () =>
    ({
      endpoint,
      name,
      oobLink,
      onConnected,
    }: {
      endpoint: string;
      name: string;
      oobLink: string;
      onConnected: (gateway: { id: string }) => void;
    }) => (
      <div data-testid="stub-connect">
        {endpoint} {name} {oobLink}
        <button onClick={() => onConnected({ id: 'gw-new' })}>connected</button>
      </div>
    )
);

const mockGet = apiClient.get as jest.Mock;
const mockInfo = apiClient.getPaymentGatewayInfo as jest.Mock;

const INFO = {
  info_version: '1',
  role: 'payment',
  protocols: ['x402'],
  payment_methods: [{ protocol: 'x402', kind: 'onChain', network: 'base' }],
  payable_count: 1,
  units: ['USDC'],
};

const record = (status: string) => ({
  id: 'gw-new',
  name: 'Agent Pay',
  description: '',
  did: 'did:peer:2.x',
  gateway_type: 'remote',
  status,
  role: 'payment',
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-01T00:00:00Z',
});

const Where: React.FC = () => {
  const location = useLocation();
  return <div data-testid="where">{location.pathname + location.search}</div>;
};

function renderWizard(path = '/payment-gateways/connect') {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route
          path="*"
          element={
            <>
              <AddPaymentGatewayWizardPage />
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
  mockGet.mockResolvedValue({ data: record('active') });
  mockInfo.mockResolvedValue(INFO);
});

afterEach(() => {
  jest.useRealTimers();
});

describe('AddPaymentGatewayWizardPage', () => {
  it('starts at the details step in payment gateway wording and refuses an empty name', () => {
    renderWizard();

    expect(screen.getByTestId('wizard-step-details')).toHaveTextContent(
      'Enter Payment Gateway Details'
    );
    expect(screen.getByTestId('wizard-progress-step-enter-details')).toHaveClass('active');
    fireEvent.click(screen.getByTestId('wizard-next'));

    expect(screen.getByTestId('wizard-oob-details-error')).toHaveTextContent(
      'Payment gateway name is required'
    );
    expect(screen.queryByTestId('wizard-step-link')).not.toBeInTheDocument();
  });

  it('connects through the payment gateway route, waits for approval, verifies and completes', async () => {
    jest.useFakeTimers();
    mockGet
      .mockResolvedValueOnce({ data: record('awaiting-approval') })
      .mockResolvedValue({ data: record('active') });
    renderWizard();

    fireEvent.change(screen.getByTestId('wizard-oob-name-input'), {
      target: { value: 'Agent Pay' },
    });
    fireEvent.click(screen.getByTestId('wizard-next'));
    fireEvent.change(screen.getByTestId('wizard-oob-link-input'), {
      target: { value: 'https://mediator.example/oob?_oobid=abc' },
    });
    fireEvent.change(screen.getByTestId('wizard-oob-secret-input'), {
      target: { value: 's3cret' },
    });
    fireEvent.click(screen.getByTestId('wizard-next'));

    expect(screen.getByTestId('stub-connect')).toHaveTextContent(
      '/payment-gateways/connect-via-oob Agent Pay https://mediator.example/oob?_oobid=abc'
    );
    fireEvent.click(screen.getByText('connected'));

    expect(await screen.findByTestId('payment-gateway-approval-status')).toHaveTextContent(
      'AWAITING APPROVAL'
    );
    expect(screen.getByTestId('wizard-step-approval')).toHaveTextContent(
      'agent-pay must approve this connection'
    );
    expect(screen.getByTestId('where')).toHaveTextContent('/payment-gateways/connect?id=gw-new');
    expect(mockGet).toHaveBeenCalledWith('/payment-gateways/gw-new');

    await act(async () => {
      jest.advanceTimersByTime(APPROVAL_POLL_MS);
    });

    expect(await screen.findByTestId('payment-gateway-verify-ok')).toBeInTheDocument();
    expect(screen.getByTestId('payment-gateway-verify-offer')).toHaveTextContent('base');
    fireEvent.click(screen.getByTestId('wizard-next'));

    expect(screen.getByTestId('wizard-step-complete')).toHaveTextContent('Payment gateway ready');
    fireEvent.click(screen.getByTestId('wizard-oob-view-button'));
    expect(screen.getByTestId('where')).toHaveTextContent('/payment-gateways/gw-new');
  });

  it('resumes a created payment gateway from ?id= and moves on once it is active', async () => {
    renderWizard('/payment-gateways/connect?id=gw-new');

    expect(await screen.findByTestId('wizard-step-verify')).toBeInTheDocument();
    expect(screen.queryByTestId('wizard-step-details')).not.toBeInTheDocument();
    expect(await screen.findByTestId('payment-gateway-verify-ok')).toBeInTheDocument();
    expect(mockInfo).toHaveBeenCalledWith('gw-new');
  });

  it('says so when the resumed payment gateway no longer exists', async () => {
    mockGet.mockRejectedValue(new ApiError('Gateway not found (404)', 404));
    renderWizard('/payment-gateways/connect?id=gone');

    expect(await screen.findByTestId('payment-gateway-approval-error')).toHaveTextContent(
      'no longer exists'
    );
    fireEvent.click(screen.getByTestId('wizard-cancel'));
    expect(screen.getByTestId('where')).toHaveTextContent('/connections?tab=payment-gateways');
  });

  it('fails verification for a gateway that is not a payment gateway (502)', async () => {
    mockInfo.mockRejectedValue(new ApiError('payment gateway not verified (502)', 502));
    renderWizard('/payment-gateways/connect?id=gw-new');

    const error = await screen.findByTestId('payment-gateway-verify-error');
    expect(error).toHaveTextContent('not as a payment gateway');
    expect(error).toHaveTextContent('agent-pay is up to date');
    expect(error).not.toHaveTextContent('502');
    expect(screen.getByTestId('wizard-next')).toBeDisabled();
  });

  it('retries an unreachable payment gateway (503) until it answers', async () => {
    jest.useFakeTimers();
    mockInfo
      .mockRejectedValueOnce(new ApiError('payment gateway unavailable (503)', 503))
      .mockResolvedValue(INFO);
    renderWizard('/payment-gateways/connect?id=gw-new');

    expect(await screen.findByTestId('payment-gateway-verify-error')).toHaveTextContent(
      'not reachable yet'
    );
    expect(screen.getByTestId('wizard-next')).toBeDisabled();

    await act(async () => {
      jest.advanceTimersByTime(VERIFY_RETRY_MS);
    });

    expect(await screen.findByTestId('payment-gateway-verify-ok')).toBeInTheDocument();
    expect(mockInfo).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId('wizard-next')).toBeEnabled();
  });

  it('warns when agent-pay exposes no payment surface and re-checks on request', async () => {
    mockInfo.mockResolvedValue({ ...INFO, payable_count: 0 });
    renderWizard('/payment-gateways/connect?id=gw-new');

    expect(await screen.findByTestId('payment-gateway-verify-no-surface')).toHaveTextContent(
      'expose a payment surface on the connection point'
    );
    expect(screen.getByTestId('wizard-next')).toBeEnabled();

    mockInfo.mockResolvedValue(INFO);
    fireEvent.click(screen.getByTestId('payment-gateway-verify-recheck-button'));

    expect(await screen.findByTestId('payment-gateway-verify-ok')).toBeInTheDocument();
    expect(screen.queryByTestId('payment-gateway-verify-no-surface')).not.toBeInTheDocument();
    expect(mockInfo).toHaveBeenCalledTimes(2);
  });
});
