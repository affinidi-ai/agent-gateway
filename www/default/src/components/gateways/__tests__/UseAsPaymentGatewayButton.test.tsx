import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import UseAsPaymentGatewayButton, { canBecomePaymentGateway } from '../UseAsPaymentGatewayButton';
import { ApiError, apiClient } from '../../../api';

let mockPermissions: Record<string, boolean> = {};

jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    hasPermission: (feature: string) => mockPermissions[feature] === true,
  }),
}));

jest.mock('../../../utils/toaster', () => ({ showToast: jest.fn() }));

jest.mock('../../../api', () => {
  const actual = jest.requireActual('../../../api');
  return { ApiError: actual.ApiError, apiClient: { setGatewayPaymentRole: jest.fn() } };
});

const setRole = apiClient.setGatewayPaymentRole as jest.Mock;

const peer = { id: 'gw-1', name: 'Partner', gateway_type: 'remote', status: 'active' };

const Where: React.FC = () => {
  const location = useLocation();
  return <div data-testid="where">{location.pathname + location.search}</div>;
};

function renderButton(onError: jest.Mock = jest.fn(), gateway = peer) {
  render(
    <MemoryRouter initialEntries={['/connections?tab=gateways']}>
      <Routes>
        <Route
          path="*"
          element={
            <>
              <UseAsPaymentGatewayButton gateway={gateway} onError={onError} testId="use-pay" />
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
  mockPermissions = { 'gateways.edit': true, 'payment_gateways.edit': true };
  jest.spyOn(window, 'confirm').mockReturnValue(true);
});

afterEach(() => jest.restoreAllMocks());

describe('UseAsPaymentGatewayButton', () => {
  it.each([
    ['gateways.edit', { 'payment_gateways.edit': true }],
    ['payment_gateways.edit', { 'gateways.edit': true }],
  ])('is hidden without %s', (_missing, permissions) => {
    mockPermissions = permissions;
    renderButton();

    expect(screen.queryByTestId('use-pay')).not.toBeInTheDocument();
  });

  it('is offered only for an active remote peer', () => {
    expect(canBecomePaymentGateway(peer)).toBe(true);
    expect(canBecomePaymentGateway({ ...peer, status: 'pending' })).toBe(false);
    expect(canBecomePaymentGateway({ ...peer, gateway_type: 'self' })).toBe(false);
    expect(canBecomePaymentGateway({ ...peer, role: 'payment' })).toBe(false);
  });

  it('does nothing when the confirm is dismissed', () => {
    (window.confirm as jest.Mock).mockReturnValue(false);
    renderButton();

    fireEvent.click(screen.getByTestId('use-pay'));

    expect(window.confirm).toHaveBeenCalledWith(
      expect.stringContaining('moves to Connections → Payment Gateways')
    );
    expect(setRole).not.toHaveBeenCalled();
  });

  it('converts the peer and opens the Payment Gateways tab', async () => {
    setRole.mockResolvedValue({ ...peer, role: 'payment' });
    const onError = jest.fn();
    renderButton(onError);

    fireEvent.click(screen.getByTestId('use-pay'));

    await waitFor(() =>
      expect(screen.getByTestId('where')).toHaveTextContent('/connections?tab=payment-gateways')
    );
    expect(setRole).toHaveBeenCalledWith('gw-1');
    expect(onError).not.toHaveBeenCalled();
  });

  it('shows the gateway refusal and stays put', async () => {
    setRole.mockRejectedValue(
      new ApiError('1 surface(s) route to this gateway over fabric:// (409)', 409)
    );
    const onError = jest.fn();
    renderButton(onError);

    fireEvent.click(screen.getByTestId('use-pay'));

    await waitFor(() =>
      expect(onError).toHaveBeenCalledWith(
        '1 surface(s) route to this gateway over fabric:// (409)'
      )
    );
    expect(screen.getByTestId('where')).toHaveTextContent('/connections?tab=gateways');
    expect(screen.getByTestId('use-pay')).toBeEnabled();
  });
});
