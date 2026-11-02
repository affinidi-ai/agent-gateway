import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import ConnectionsPage from '../ConnectionsPage';

let mockPermissions: Record<string, boolean> = {};

jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    hasPermission: (feature: string) => mockPermissions[feature] === true,
  }),
}));

jest.mock('../GatewaysPage', () => () => <div data-testid="stub-gateways" />);
jest.mock('../MediatorsPage', () => () => <div data-testid="stub-mediators" />);
jest.mock('../TrustRegistriesPage', () => () => <div data-testid="stub-registries" />);
jest.mock(
  '../PaymentGatewaysPage',
  () =>
    ({ actionsContainer }: { actionsContainer?: HTMLElement | null }) => (
      <div data-testid="stub-payment-gateways" data-has-actions={String(!!actionsContainer)} />
    )
);

const Where: React.FC = () => {
  const location = useLocation();
  return <div data-testid="where">{location.search}</div>;
};

function renderPage(path = '/connections') {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route
          path="/connections"
          element={
            <>
              <ConnectionsPage />
              <Where />
            </>
          }
        />
      </Routes>
    </MemoryRouter>
  );
}

const activeTab = () => screen.getByRole('tab', { selected: true }).textContent ?? '';

describe('ConnectionsPage', () => {
  beforeEach(() => {
    mockPermissions = { 'gateways.view': true, 'payment_gateways.view': true };
  });

  it('shows the Payment Gateways tab to a user with payment_gateways.view', () => {
    renderPage();

    expect(screen.getByTestId('connections-tab-payment-gateways')).toHaveTextContent(
      'Payment Gateways'
    );
    expect(activeTab()).toContain('Gateways');
    expect(activeTab()).not.toContain('Payment');
  });

  it('hides the tab without payment_gateways.view', () => {
    mockPermissions = { 'gateways.view': true };
    renderPage();

    expect(screen.queryByTestId('connections-tab-payment-gateways')).not.toBeInTheDocument();
    expect(screen.queryByTestId('stub-payment-gateways')).not.toBeInTheDocument();
  });

  it('opens the tab from ?tab= and hands it the actions banner', () => {
    renderPage('/connections?tab=payment-gateways');

    expect(activeTab()).toContain('Payment Gateways');
    expect(screen.getByTestId('stub-payment-gateways')).toHaveAttribute('data-has-actions', 'true');
  });

  it('falls back to Gateways for ?tab=payment-gateways without the permission', () => {
    mockPermissions = { 'gateways.view': true };
    renderPage('/connections?tab=payment-gateways');

    expect(activeTab()).toContain('Gateways');
    expect(screen.getByTestId('stub-gateways')).toBeInTheDocument();
  });

  it('opens on Payment Gateways for a user who may see only payment gateways', () => {
    mockPermissions = { 'payment_gateways.view': true };
    renderPage('/connections?tab=gateways');

    expect(activeTab()).toContain('Payment Gateways');
    expect(screen.queryByTestId('stub-gateways')).not.toBeInTheDocument();
    expect(screen.getByTestId('stub-payment-gateways')).toBeInTheDocument();
  });

  it('keeps the selected tab in the URL', () => {
    renderPage();

    fireEvent.click(screen.getByTestId('connections-tab-payment-gateways'));

    expect(screen.getByTestId('where')).toHaveTextContent('?tab=payment-gateways');
    expect(activeTab()).toContain('Payment Gateways');
  });
});
