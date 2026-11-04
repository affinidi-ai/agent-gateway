import React from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Sidebar from '../Sidebar';

let mockPermissions: Record<string, boolean> = {};

jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    hasPermission: (feature: string) => mockPermissions[feature] === true,
  }),
}));

let mockFlags: Record<string, boolean> = {};

jest.mock('../../context/AppContext', () => ({
  useApp: () => ({
    state: { sidebarCollapsed: false, settings: { feature_flags: mockFlags } },
    actions: { toggleSidebar: jest.fn() },
  }),
}));

beforeEach(() => {
  mockFlags = {};
});

function renderSidebar() {
  render(
    <MemoryRouter>
      <Sidebar />
    </MemoryRouter>
  );
}

test('shows Integrations to callers with integrations.view', () => {
  mockPermissions = { 'integrations.view': true };

  renderSidebar();

  expect(screen.getByTestId('nav-integrations')).toHaveAttribute('href', '/integrations');
});

test('hides Integrations from callers without integrations.view', () => {
  mockPermissions = { 'mcp_proxies.view': true, 'audit.view': true };

  renderSidebar();

  expect(screen.queryByTestId('nav-integrations')).not.toBeInTheDocument();
});

test('shows Connections to a payment-gateways-only caller only while agent-pay is on', () => {
  mockPermissions = { 'payment_gateways.view': true };

  mockFlags = { agent_pay_delegation: true };
  const { unmount } = render(
    <MemoryRouter>
      <Sidebar />
    </MemoryRouter>
  );
  expect(screen.getByTestId('nav-connections')).toHaveAttribute('href', '/connections');
  unmount();

  mockFlags = {};
  renderSidebar();
  expect(screen.queryByTestId('nav-connections')).not.toBeInTheDocument();
});

test('shows Payments on payments.view whether agent-pay is on or off', () => {
  mockPermissions = { 'payments.view': true };

  mockFlags = { agent_pay_delegation: true };
  const { unmount } = render(
    <MemoryRouter>
      <Sidebar />
    </MemoryRouter>
  );
  expect(screen.getByTestId('nav-payments')).toHaveAttribute('href', '/payments');
  unmount();

  mockFlags = {};
  renderSidebar();
  expect(screen.getByTestId('nav-payments')).toHaveAttribute('href', '/payments');
});

test('hides Payments from callers without payments.view, even with agent-pay on', () => {
  mockPermissions = { 'payment_gateways.view': true };
  mockFlags = { agent_pay_delegation: true };

  renderSidebar();

  expect(screen.queryByTestId('nav-payments')).not.toBeInTheDocument();
});
