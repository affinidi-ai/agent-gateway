import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import TrustAgentsPage from '../TrustAgentsPage';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({ apiClient: { fetch: jest.fn() } }));
let mockCanEdit = true;
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    hasPermission: (permission: string) => permission !== 'vta_connections.edit' || mockCanEdit,
  }),
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

const OLD_INTRO = 'Connect a Verifiable Trust Agent to sign audit records';

beforeEach(() => {
  mockFetch.mockReset();
  mockCanEdit = true;
});

describe('TrustAgentsPage', () => {
  it('lists the agents with no intro, no context DID note and no Refresh', async () => {
    respond([agent], { context_did_method: 'did_key', context_did_hosting: 'gateway' });
    mountTab();

    expect(await screen.findByText('Production agent')).toBeInTheDocument();
    expect(screen.queryByText(new RegExp(OLD_INTRO))).not.toBeInTheDocument();
    expect(screen.queryByText(/New contexts sign as/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Refresh' })).not.toBeInTheDocument();
    expect(screen.queryByText(/Signing locally/)).not.toBeInTheDocument();
  });

  it('has one Add VTA, which opens the wizard', async () => {
    respond([agent]);
    mountTab();

    const connect = await screen.findByTestId('trust-agents-connect-button');
    expect(connect).toHaveTextContent('Add VTA');
    expect(screen.getAllByRole('button', { name: /Add VTA/ })).toHaveLength(1);
    await userEvent.click(connect);
    await waitFor(() =>
      expect(screen.getByTestId('where')).toHaveTextContent('/connections/trust-agents/connect')
    );
  });

  it('with no agent yet, says to add the first one, links the docs and offers no Add VTA of its own', async () => {
    respond([]);
    mountTab();

    expect(await screen.findByText('Add your first Verifiable Trust Agent')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /View Docs/ })).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /Add VTA/ })).toHaveLength(1);
    expect(screen.queryByText(new RegExp(OLD_INTRO))).not.toBeInTheDocument();
  });

  it('offers no Add VTA to a user who cannot add connections', async () => {
    mockCanEdit = false;
    respond([]);
    mountTab();

    await screen.findByText('Add your first Verifiable Trust Agent');
    expect(screen.queryByRole('button', { name: /Add VTA/ })).not.toBeInTheDocument();
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

  describe('revoking a connection agents were onboarded through', () => {
    const other = { ...agent, id: 'agent-2', name: 'Staging agent' };
    const revokeCalls: string[] = [];

    beforeEach(() => {
      revokeCalls.length = 0;
      mockFetch.mockImplementation((url: string) => {
        if (url.includes('/revoke')) {
          revokeCalls.push(url);
          const acknowledged = url.includes('acknowledge_stranded_agents=true');
          return Promise.resolve(
            acknowledged
              ? { ok: true, status: 200, json: () => Promise.resolve(agent) }
              : {
                  ok: false,
                  status: 409,
                  json: () => Promise.resolve({ error: 'Agents were onboarded through it.' }),
                }
          );
        }
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve(
              url.includes('/vta/status')
                ? { enabled: false, tier: 'local', custody_claim: false, reserved_origins: [] }
                : [agent, other]
            ),
        });
      });
    });

    const revokeButtons = async () => {
      await screen.findByText('Staging agent');
      return screen.getAllByRole('button', { name: 'Revoke' });
    };

    it('acknowledges the stranded agents on the click right after the warning', async () => {
      mountTab();
      const [first] = await revokeButtons();

      await userEvent.click(first);
      await userEvent.click(first);
      await waitFor(() => expect(revokeCalls).toHaveLength(1));
      await userEvent.click(first);

      await waitFor(() => expect(revokeCalls).toHaveLength(2));
      expect(revokeCalls[0]).not.toContain('acknowledge');
      expect(revokeCalls[1]).toContain('acknowledge_stranded_agents=true');
    });

    it('asks the server again once another row was armed in between', async () => {
      mountTab();
      const [first, second] = await revokeButtons();

      await userEvent.click(first);
      await userEvent.click(first);
      await waitFor(() => expect(revokeCalls).toHaveLength(1));
      await userEvent.click(second);
      await userEvent.click(first);
      await userEvent.click(first);

      await waitFor(() => expect(revokeCalls).toHaveLength(2));
      expect(revokeCalls[1]).toContain('agent-1');
      expect(revokeCalls[1]).not.toContain('acknowledge');
    });
  });

  it('shows no control key card without one', async () => {
    respond([agent]);
    mountTab();

    await screen.findByText('Production agent');
    expect(screen.queryByTestId('vta-control-key')).not.toBeInTheDocument();
  });
});
