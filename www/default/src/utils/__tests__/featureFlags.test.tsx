import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import AgentPayRoute from '../../components/AgentPayRoute';
import { agentPayEnabled, connectionsPermissions } from '../featureFlags';
import type { Settings } from '../../types';

let mockSettings: Partial<Settings> | null = null;

jest.mock('../../context/AppContext', () => ({
  useApp: () => ({ state: { settings: mockSettings } }),
}));

describe('agentPayEnabled', () => {
  it('is on only for an explicit true', () => {
    expect(agentPayEnabled(null)).toBe(false);
    expect(agentPayEnabled({} as Settings)).toBe(false);
    expect(agentPayEnabled({ feature_flags: {} } as Settings)).toBe(false);
    expect(agentPayEnabled({ feature_flags: { agent_pay_delegation: false } } as Settings)).toBe(
      false
    );
    expect(agentPayEnabled({ feature_flags: { agent_pay_delegation: true } } as Settings)).toBe(
      true
    );
  });
});

function renderRoute(path = '/payment-gateways/gw-1') {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route
          path="/payment-gateways/:id"
          element={
            <AgentPayRoute>
              <div data-testid="flagged-page" />
            </AgentPayRoute>
          }
        />
        <Route path="/connections" element={<div data-testid="connections" />} />
        <Route
          path="/payments"
          element={
            <AgentPayRoute fallback="/">
              <div data-testid="payments-page" />
            </AgentPayRoute>
          }
        />
        <Route path="/" element={<div data-testid="dashboard" />} />
      </Routes>
    </MemoryRouter>
  );
}

describe('AgentPayRoute', () => {
  it('renders nothing, and does not redirect, while the settings load', () => {
    mockSettings = null;
    renderRoute();
    expect(screen.queryByTestId('flagged-page')).not.toBeInTheDocument();
    expect(screen.queryByTestId('connections')).not.toBeInTheDocument();
  });

  it('renders the page while agent-pay is on', () => {
    mockSettings = { feature_flags: { agent_pay_delegation: true } };
    renderRoute();
    expect(screen.getByTestId('flagged-page')).toBeInTheDocument();
  });

  it('sends the Payments page to its own fallback while agent-pay is off', () => {
    mockSettings = { feature_flags: {} };
    renderRoute('/payments');
    expect(screen.queryByTestId('payments-page')).not.toBeInTheDocument();
    expect(screen.getByTestId('dashboard')).toBeInTheDocument();
  });

  it('shows the Payments page while agent-pay is on', () => {
    mockSettings = { feature_flags: { agent_pay_delegation: true } };
    renderRoute('/payments');
    expect(screen.getByTestId('payments-page')).toBeInTheDocument();
  });

  it('redirects to Connections while agent-pay is off', () => {
    mockSettings = { feature_flags: {} };
    renderRoute();
    expect(screen.queryByTestId('flagged-page')).not.toBeInTheDocument();
    expect(screen.getByTestId('connections')).toBeInTheDocument();
  });
});

describe('connectionsPermissions', () => {
  it('admits a payment-gateways-only caller only while agent-pay is on', () => {
    expect(connectionsPermissions(true)).toEqual(['gateways.view', 'payment_gateways.view']);
    expect(connectionsPermissions(false)).toEqual(['gateways.view']);
  });
});

describe('the settings used when they cannot be loaded', () => {
  it('load, so pages waiting for them render, with agent-pay off', () => {
    const { FALLBACK_SETTINGS } = jest.requireActual('../../context/AppContext');
    expect(FALLBACK_SETTINGS).not.toBeNull();
    expect(agentPayEnabled(FALLBACK_SETTINGS)).toBe(false);
  });
});
