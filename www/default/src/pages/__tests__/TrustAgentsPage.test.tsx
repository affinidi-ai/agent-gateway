import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import TrustAgentsPage from '../TrustAgentsPage';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({ apiClient: { fetch: jest.fn() } }));
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: () => true }),
}));

const mockFetch = apiClient.fetch as jest.Mock;

const agent = {
  id: 'agent-1',
  name: 'Production agent',
  enabled: true,
  transport: 'https',
  endpoint: 'https://vta.example.com',
  vta_did: 'did:webvh:abc:vta.example.com',
  default_context_id: 'gateway',
  status: 'connected',
  pairing: { state: 'connected' },
  keys: { active: { key_id: 'key-1' } },
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

const respond = (connections: unknown[], status: Record<string, unknown> = {}) =>
  mockFetch.mockImplementation((url: string) =>
    Promise.resolve({
      ok: true,
      json: () =>
        Promise.resolve(
          url.includes('/vta/status')
            ? {
                enabled: false,
                tier: 'local',
                custody_claim: false,
                reserved_origins: [],
                ...status,
              }
            : connections
        ),
    })
  );

const Where: React.FC = () => <div data-testid="where">{useLocation().pathname}</div>;

const mountTab = () =>
  render(
    <MemoryRouter initialEntries={['/connections']}>
      <Routes>
        <Route
          path="*"
          element={
            <>
              <TrustAgentsPage externalSearchTerm="" />
              <Where />
            </>
          }
        />
      </Routes>
    </MemoryRouter>
  );

const INTRO =
  "Connect a Verifiable Trust Agent to sign audit records with a key the gateway doesn't control. Anyone can verify your records without having to trust the gateway, and even if the gateway is compromised, its records can't be forged or altered. You keep full control of the agent.";

beforeEach(() => mockFetch.mockReset());

describe('TrustAgentsPage', () => {
  it('opens with what connecting an agent gives, and no signing banner', async () => {
    respond([agent]);
    mountTab();

    expect(await screen.findByText('Production agent')).toBeInTheDocument();
    expect(screen.getByTestId('trust-agents-intro')).toHaveTextContent(INTRO);
    expect(screen.queryByText(/Signing locally/)).not.toBeInTheDocument();
  });

  it('has Add VTA, which opens the wizard', async () => {
    respond([agent]);
    mountTab();

    await userEvent.click(await screen.findByTestId('trust-agents-connect-button'));

    expect(screen.getByTestId('trust-agents-connect-button')).toHaveTextContent('Add VTA');
    await waitFor(() =>
      expect(screen.getByTestId('where')).toHaveTextContent('/connections/trust-agents/connect')
    );
  });

  it('offers Add VTA when there is no agent yet', async () => {
    respond([]);
    mountTab();

    expect(await screen.findByTestId('trust-agents-empty-connect-button')).toHaveTextContent(
      'Add VTA'
    );
  });

  it("shows the gateway's control key while it holds a rotatable one", async () => {
    respond([agent], {
      control_key: {
        control_did: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        rotation_days: 90,
      },
    });
    mountTab();

    expect(await screen.findByTestId('vta-control-key')).toBeInTheDocument();
  });

  it('says new contexts sign as a did:key when the deployment does', async () => {
    respond([], { context_did_method: 'did_key', context_did_hosting: 'gateway' });
    mountTab();
    expect(await screen.findByTestId('trust-agents-context-did')).toHaveTextContent(
      'New contexts sign as a did:key'
    );
  });

  it('says where a did:webvh is hosted when contexts sign as one', async () => {
    respond([], { context_did_method: 'did_webvh', context_did_hosting: 'gateway' });
    const { unmount } = mountTab();
    const note = await screen.findByTestId('trust-agents-context-did');
    expect(note).toHaveTextContent('did:webvh, hosted by this gateway');
    expect(note).toHaveTextContent('without changing its DID');
    unmount();

    respond([], { context_did_method: 'did_webvh', context_did_hosting: 'vta_server' });
    mountTab();
    expect(await screen.findByTestId('trust-agents-context-did')).toHaveTextContent(
      "on the trust agent's webvh server"
    );
  });

  it('says nothing about context DIDs when the status does not', async () => {
    respond([]);
    mountTab();
    await screen.findByTestId('trust-agents-intro');
    expect(screen.queryByTestId('trust-agents-context-did')).not.toBeInTheDocument();
  });

  it('shows no control key card without one', async () => {
    respond([agent]);
    mountTab();

    await screen.findByText('Production agent');
    expect(screen.queryByTestId('vta-control-key')).not.toBeInTheDocument();
  });
});
