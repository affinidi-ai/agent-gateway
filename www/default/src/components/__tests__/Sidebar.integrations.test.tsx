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

jest.mock('../../context/AppContext', () => ({
  useApp: () => ({
    state: { sidebarCollapsed: false, settings: { feature_flags: {} } },
    actions: { toggleSidebar: jest.fn() },
  }),
}));

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
