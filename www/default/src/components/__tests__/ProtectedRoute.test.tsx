import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import ProtectedRoute from '../ProtectedRoute';
import { ROUTES } from '../../routes';

let mockPermissions: Record<string, boolean> = {};

jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    loading: false,
    hasPermission: (feature: string) => mockPermissions[feature] === true,
  }),
}));

function renderGuarded(permission: string | readonly string[]) {
  render(
    <MemoryRouter initialEntries={['/guarded']}>
      <Routes>
        <Route
          path="/guarded"
          element={
            <ProtectedRoute permission={permission}>
              <div data-testid="guarded" />
            </ProtectedRoute>
          }
        />
        <Route path={ROUTES.DASHBOARD} element={<div data-testid="dashboard" />} />
      </Routes>
    </MemoryRouter>
  );
}

describe('ProtectedRoute', () => {
  it('renders for a single granted permission', () => {
    mockPermissions = { 'gateways.view': true };
    renderGuarded('gateways.view');
    expect(screen.getByTestId('guarded')).toBeInTheDocument();
  });

  it('renders when any one of several permissions is granted', () => {
    mockPermissions = { 'payment_gateways.view': true };
    renderGuarded(['gateways.view', 'payment_gateways.view']);
    expect(screen.getByTestId('guarded')).toBeInTheDocument();
  });

  it('redirects to the dashboard when none is granted', () => {
    mockPermissions = { 'mediators.view': true };
    renderGuarded(['gateways.view', 'payment_gateways.view']);
    expect(screen.queryByTestId('guarded')).not.toBeInTheDocument();
    expect(screen.getByTestId('dashboard')).toBeInTheDocument();
  });
});
