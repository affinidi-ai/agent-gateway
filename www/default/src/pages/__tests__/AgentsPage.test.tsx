import React from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import AgentsPage from '../AgentsPage';
import { DOCS_URL } from '../../config/docs';
import { AgentListResponse, AgentRecord, apiClient } from '../../api';
import { usePermissions } from '../../context/PermissionsContext';

jest.mock('../../api', () => ({
  apiClient: {
    listAgents: jest.fn(),
  },
}));

jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: jest.fn(),
}));

const mockedListAgents = apiClient.listAgents as jest.Mock;
const mockedUsePermissions = usePermissions as jest.Mock;
const grant = (...permissions: string[]) =>
  mockedUsePermissions.mockReturnValue({
    hasPermission: (permission: string) => permissions.includes(permission),
  });

const LONG_DID = 'did:webvh:QmYAuadF1234567890:agent-gateway1.example.com:surface:abcdef12';

const agent = (overrides: Partial<AgentRecord> = {}): AgentRecord => ({
  id: 'a1',
  name: 'TimeAsker',
  protocol: 'a2a',
  runtime: 'url',
  endpoint: 'http://localhost:9002',
  tags: [],
  surfaces: [{ surface_id: 's1', name: 'RICK' }],
  identities: [{ did: LONG_DID, created_at: '2026-10-22T11:24:02Z', source: 'managed' }],
  trust_registry: { recorded: true },
  last_activity_at: null,
  ...overrides,
});

const list = (...agents: AgentRecord[]): AgentListResponse => ({ agents, window_minutes: 360 });

const renderPage = () =>
  render(
    <MemoryRouter initialEntries={['/agent-registry']}>
      <Routes>
        <Route path="/agent-registry" element={<AgentsPage />} />
        <Route path="/agent-registry/:agentId" element={<div data-testid="details-route" />} />
        <Route path="/surfaces/new" element={<div data-testid="new-surface-route" />} />
        <Route path="/surfaces/:surfaceId" element={<div data-testid="surface-route" />} />
      </Routes>
    </MemoryRouter>
  );

describe('AgentsPage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    grant('surfaces.view', 'surfaces.edit');
  });

  it('lists rows with a count badge and display labels', async () => {
    mockedListAgents.mockResolvedValue(
      list(
        agent(),
        agent({
          id: 'a2',
          name: null,
          surfaces: [{ surface_id: 's2', name: 'Frank 003' }],
          runtime: 'a2a-proxy',
          identities: [],
          trust_registry: { recorded: false },
        })
      )
    );
    renderPage();

    const first = await screen.findByTestId('agents-row-a1');
    expect(within(first).getByText('TimeAsker')).toBeInTheDocument();
    expect(within(first).getByText('Direct')).toBeInTheDocument();
    expect(within(first).getByTestId('agents-protocol-badge')).toHaveTextContent('A2A');
    expect(within(first).getByTestId('agents-protocol-badge')).toHaveClass(
      'badge',
      'text-bg-primary'
    );
    const identities = within(first).getByTestId('agents-identities');
    expect(identities).toHaveTextContent(/^1 identity$/);
    expect(identities).toHaveAttribute('title', LONG_DID);
    const identitiesCount = within(identities).getByTestId('agents-identities-count');
    expect(identitiesCount).toHaveTextContent(/^1$/);
    expect(identitiesCount).toHaveClass('badge', 'text-bg-primary');
    expect(identitiesCount).not.toHaveClass('rounded-pill');
    expect(identitiesCount).not.toHaveClass('small');
    expect(identities).not.toHaveClass('small');
    expect(within(first).getByTestId('agents-trust-recorded')).toHaveTextContent('Recorded');
    expect(within(first).getByTestId('agents-trust-recorded')).toHaveClass('text-bg-success');
    expect(within(first).getByTestId('agents-runtime')).toHaveAttribute(
      'title',
      'The gateway calls the agent URL directly.'
    );
    expect(within(first).getByTestId('agents-runtime')).toHaveTextContent(
      'Direct. The gateway calls the agent URL directly.'
    );
    expect(within(first).getByTestId('agents-runtime')).not.toHaveClass('small');
    expect(within(first).getByTestId('agents-runtime')).not.toHaveClass('badge');
    expect(within(first).getByTestId('agents-runtime')).not.toHaveClass('text-muted');
    expect(within(first).queryByTestId('agents-trust-not-recorded')).not.toBeInTheDocument();
    expect(within(first).getByText('None in last 6h')).toBeInTheDocument();

    expect(within(first).queryByTestId('agents-did')).not.toBeInTheDocument();
    expect(within(first).queryByText(LONG_DID)).not.toBeInTheDocument();
    expect(within(first).getByTestId('agents-name').tagName).toBe('STRONG');
    expect(within(first).queryByTestId('agents-copy-did-button')).not.toBeInTheDocument();

    const second = screen.getByTestId('agents-row-a2');
    const unnamed = within(second).getByTestId('agents-unnamed');
    expect(unnamed).toHaveTextContent('Unnamed agent');
    expect(unnamed.tagName).toBe('STRONG');
    expect(unnamed).not.toHaveClass('text-muted');
    expect(within(second).queryByTestId('agents-name')).not.toBeInTheDocument();
    expect(within(second).getByTestId('agents-no-identity')).toHaveTextContent('No identity');
    expect(within(second).queryByTestId('agents-identities')).not.toBeInTheDocument();
    expect(within(second).getByText('Proxied')).toBeInTheDocument();
    expect(within(second).getByTestId('agents-protocol-badge')).toHaveTextContent(/^A2A$/);
    const notRecorded = within(second).getByTestId('agents-trust-not-recorded');
    expect(notRecorded).toHaveTextContent('Not recorded');
    expect(notRecorded).toHaveClass('badge', 'app-badge', 'app-badge--sm', 'text-bg-secondary');
    expect(notRecorded).not.toHaveClass('badge-none');
    expect(within(second).queryByTestId('agents-trust-recorded')).not.toBeInTheDocument();
    expect(screen.queryByText('a2a-proxy')).not.toBeInTheDocument();
  });

  it('labels last activity with the window the API returns', async () => {
    mockedListAgents.mockResolvedValue({ agents: [agent()], window_minutes: 90 });
    renderPage();
    const row = await screen.findByTestId('agents-row-a1');

    expect(within(row).getByTestId('agents-last-activity')).toHaveTextContent('None in last 90m');
    expect(within(row).queryByText('None in last 6h')).not.toBeInTheDocument();
  });

  it('shows Unnamed agent for an empty name', async () => {
    mockedListAgents.mockResolvedValue(list(agent({ name: '' })));
    renderPage();
    const row = await screen.findByTestId('agents-row-a1');

    expect(within(row).getByTestId('agents-unnamed')).toHaveTextContent(/^Unnamed agent$/);
    expect(within(row).queryByTestId('agents-name')).not.toBeInTheDocument();
    expect(row).toHaveAttribute('aria-label', expect.stringMatching(/^Unnamed agent/));
  });

  it('shows no status column, status filter or dimmed rows', async () => {
    mockedListAgents.mockResolvedValue(list(agent()));
    renderPage();
    const row = await screen.findByTestId('agents-row-a1');

    expect(screen.queryByRole('columnheader', { name: 'Status' })).not.toBeInTheDocument();
    expect(screen.queryByRole('combobox', { name: 'Filter by status' })).not.toBeInTheDocument();
    expect(screen.queryByTestId('agents-status-badge')).not.toBeInTheDocument();
    expect(row).not.toHaveClass('agents-row-dimmed');
    expect(
      within(row).queryByText(/Active|Disabled|Recognised|Authorised/)
    ).not.toBeInTheDocument();
  });

  it('lists every identity of the agent', async () => {
    mockedListAgents.mockResolvedValue(
      list(
        agent({
          identities: [
            { did: 'did:web:a.example', created_at: null, source: 'surface' },
            { did: 'did:web:b.example', created_at: '2026-10-22T11:24:02Z', source: 'managed' },
          ],
        })
      )
    );
    renderPage();
    const row = await screen.findByTestId('agents-row-a1');

    expect(screen.getByRole('columnheader', { name: 'Route' })).toBeInTheDocument();
    expect(screen.queryByRole('columnheader', { name: 'Runtime' })).not.toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: 'Protocol' })).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: 'Identities' })).toBeInTheDocument();
    const identities = within(row).getByTestId('agents-identities');
    expect(identities).toHaveTextContent(/^2 identities$/);
    expect(identities).toHaveAttribute('title', 'did:web:a.example\ndid:web:b.example');
    expect(within(identities).getByTestId('agents-identities-count')).toHaveTextContent(/^2$/);
    expect(within(row).queryByTestId('agents-did')).not.toBeInTheDocument();
    expect(within(row).queryByTestId('agents-copy-did-button')).not.toBeInTheDocument();
    expect(within(row).queryByTestId('agents-no-identity')).not.toBeInTheDocument();
    expect(within(row).queryByText(/other surface/)).not.toBeInTheDocument();
  });

  it('shows No identity as muted text, explained only while surfaces use the agent', async () => {
    mockedListAgents.mockResolvedValue(
      list(
        agent({ identities: [] }),
        agent({ id: 'a2', name: 'Idle', identities: [], surfaces: [] })
      )
    );
    renderPage();
    const used = await screen.findByTestId('agents-row-a1');

    const flagged = within(used).getByTestId('agents-no-identity');
    expect(flagged).toHaveTextContent('No identity');
    expect(flagged).toHaveAttribute('title', 'The surface using this agent has no DID');
    expect(flagged).toHaveClass('text-muted');
    expect(flagged).not.toHaveClass('small');
    expect(flagged).not.toHaveClass('badge');
    expect(flagged.innerHTML).toBe('No identity');

    const idle = within(screen.getByTestId('agents-row-a2')).getByTestId('agents-no-identity');
    expect(idle).toHaveClass('text-muted');
    expect(idle).not.toHaveClass('small');
    expect(idle).not.toHaveClass('badge');
    expect(idle).not.toHaveAttribute('title');
  });

  it('shows the endpoint host under the name', async () => {
    mockedListAgents.mockResolvedValue(
      list(
        agent({ endpoint: 'https://agents.example.com:8443/a2a' }),
        agent({
          id: 'a2',
          endpoint: 'fabric://gw-1/channel-a',
          runtime: 'gateway',
          target_name: 'Acme Gateway',
        }),
        agent({
          id: 'a3',
          endpoint: 'a2a-proxy://proxy-7',
          runtime: 'a2a-proxy',
          target_name: 'Billing Proxy',
        }),
        agent({ id: 'a4', endpoint: 'https://redacted.invalid/a2a' }),
        agent({ id: 'a5', endpoint: 'fabric://gw-2', runtime: 'gateway', target_name: null }),
        agent({ id: 'a6', endpoint: 'a2a-proxy://proxy-8', runtime: 'a2a-proxy', target_name: ' ' })
      )
    );
    renderPage();
    const host = (id: string) =>
      within(screen.getByTestId(`agents-row-${id}`)).queryByTestId('agents-endpoint-host');

    await screen.findByTestId('agents-row-a1');
    expect(host('a1')).toHaveTextContent(/^https:\/\/agents\.example\.com:8443$/);
    expect(host('a2')).toHaveTextContent(/^Acme Gateway\/channel-a$/);
    expect(host('a3')).toHaveTextContent(/^Billing Proxy$/);
    expect(host('a4')).not.toBeInTheDocument();
    expect(host('a5')).toHaveTextContent(/^gw-2$/);
    expect(host('a6')).toHaveTextContent(/^proxy-8$/);
    expect(screen.queryByText(/fabric:\/\/|a2a-proxy:\/\//)).not.toBeInTheDocument();
  });

  it('shows the count and names of the surfaces that use the agent', async () => {
    mockedListAgents.mockResolvedValue(
      list(
        agent({
          surfaces: [
            { surface_id: 's1', name: 'helium' },
            { surface_id: 's 2', name: 'oxygen' },
          ],
        })
      )
    );
    renderPage();
    const row = await screen.findByTestId('agents-row-a1');

    const count = within(row).getByTestId('agents-surfaces-count');
    expect(count).toHaveTextContent('2');
    expect(count).toHaveAttribute('aria-label', '2 surfaces');
    expect(count).not.toHaveClass('small');
    expect(within(row).getByTestId('agents-surfaces')).not.toHaveClass('small');
    expect(within(row).getByTestId('agents-surface-names')).not.toHaveClass('small');
    expect(within(row).getByTestId('agents-surfaces')).toHaveAttribute('title', 'helium, oxygen');
    expect(within(row).getByTestId('agents-surfaces').style.maxWidth).toBe('');
    const surfacesCell = within(row)
      .getAllByRole('cell')
      .find(cell => within(cell).queryByTestId('agents-surfaces'));
    expect(surfacesCell).toHaveStyle({
      maxWidth: '0px',
    });
    expect(within(row).getByTestId('agents-surface-names')).toHaveTextContent('helium, oxygen');
    expect(within(row).queryByRole('link')).not.toBeInTheDocument();
  });

  it('filters by name client-side', async () => {
    mockedListAgents.mockResolvedValue(
      list(
        agent(),
        agent({ id: 'a2', name: 'Treasury', surfaces: [{ surface_id: 's2', name: 'Ops' }] })
      )
    );
    renderPage();
    await screen.findByTestId('agents-row-a1');

    fireEvent.change(screen.getByTestId('agents-filter-input'), { target: { value: 'treas' } });
    expect(screen.queryByTestId('agents-row-a1')).not.toBeInTheDocument();
    expect(screen.getByTestId('agents-row-a2')).toBeInTheDocument();

    fireEvent.change(screen.getByTestId('agents-filter-input'), { target: { value: 'nothing' } });
    expect(screen.getByTestId('agents-no-match')).toBeInTheDocument();
  });

  it('filters by any surface name and by Unnamed agent', async () => {
    mockedListAgents.mockResolvedValue(
      list(
        agent({
          surfaces: [
            { surface_id: 's1', name: 'helium' },
            { surface_id: 's2', name: 'oxygen' },
          ],
        }),
        agent({ id: 'a2', name: null, surfaces: [{ surface_id: 's3', name: 'Ops' }] })
      )
    );
    renderPage();
    await screen.findByTestId('agents-row-a1');
    const input = screen.getByTestId('agents-filter-input');

    fireEvent.change(input, { target: { value: 'oxy' } });
    expect(screen.getByTestId('agents-row-a1')).toBeInTheDocument();
    expect(screen.queryByTestId('agents-row-a2')).not.toBeInTheDocument();

    fireEvent.change(input, { target: { value: 'unnamed' } });
    expect(screen.queryByTestId('agents-row-a1')).not.toBeInTheDocument();
    expect(screen.getByTestId('agents-row-a2')).toBeInTheDocument();
  });

  it('filters by route label', async () => {
    mockedListAgents.mockResolvedValue(
      list(
        agent(),
        agent({
          id: 'a2',
          name: 'Treasury',
          surfaces: [{ surface_id: 's2', name: 'Ops' }],
          runtime: 'gateway',
        })
      )
    );
    renderPage();
    await screen.findByTestId('agents-row-a1');

    fireEvent.change(screen.getByTestId('agents-filter-input'), { target: { value: 'fabric' } });
    expect(screen.queryByTestId('agents-row-a1')).not.toBeInTheDocument();
    expect(screen.getByTestId('agents-row-a2')).toBeInTheDocument();
  });

  it('shows the empty state', async () => {
    mockedListAgents.mockResolvedValue(list());
    renderPage();
    expect(await screen.findByText('Get started with Agents')).toBeInTheDocument();
  });

  it('opens the surface creation flow from the button in the header', async () => {
    mockedListAgents.mockResolvedValue(list());
    renderPage();

    const add = await screen.findByTestId('agents-add-surface-button');
    expect(add.tagName).toBe('BUTTON');
    expect(add).toHaveTextContent('Add Surface');
    fireEvent.click(add);
    expect(await screen.findByTestId('new-surface-route')).toBeInTheDocument();
  });

  it('shows the create surface button in the header when user can edit surfaces', async () => {
    mockedListAgents.mockResolvedValue(list(agent()));
    renderPage();

    const button = await screen.findByTestId('agents-add-surface-button');
    expect(button).toBeInTheDocument();
    expect(button).toHaveTextContent('Add Surface');
  });

  it('hides the create surface button in the header when user cannot edit surfaces', async () => {
    grant('surfaces.view');
    mockedListAgents.mockResolvedValue(list(agent()));
    renderPage();

    expect(await screen.findByTestId('agents-row-a1')).toBeInTheDocument();
    expect(screen.queryByTestId('agents-add-surface-button')).not.toBeInTheDocument();
  });

  it('links to the create first agent docs from the empty state', async () => {
    mockedListAgents.mockResolvedValue(list());
    renderPage();

    const docs = await screen.findByRole('link', { name: /View Docs/ });
    expect(docs).toHaveAttribute('href', DOCS_URL.createFirstAgent);
    expect(docs).toHaveAttribute('target', '_blank');
  });

  it('offers no surface creation button in the header to a user who cannot edit surfaces', async () => {
    grant('surfaces.view');
    mockedListAgents.mockResolvedValue(list());
    renderPage();

    expect(await screen.findByText('Get started with Agents')).toBeInTheDocument();
    expect(screen.queryByTestId('agents-add-surface-button')).not.toBeInTheDocument();
  });

  it('offers no surface creation button in the header while the list failed to load', async () => {
    mockedListAgents.mockRejectedValue(new Error('Internal Server Error'));
    renderPage();

    expect(await screen.findByTestId('agents-load-error')).toBeInTheDocument();
    expect(screen.queryByTestId('agents-add-surface-button')).not.toBeInTheDocument();
  });

  it('shows the error state and retries', async () => {
    mockedListAgents.mockRejectedValueOnce(new Error('Internal Server Error'));
    mockedListAgents.mockResolvedValueOnce(list(agent()));
    renderPage();

    expect(await screen.findByTestId('agents-load-error')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('agents-retry-button'));
    expect(await screen.findByTestId('agents-row-a1')).toBeInTheDocument();
    expect(mockedListAgents).toHaveBeenCalledTimes(2);
  });

  it('opens the details on row click', async () => {
    mockedListAgents.mockResolvedValue(list(agent()));
    renderPage();
    fireEvent.click(await screen.findByTestId('agents-row-a1'));
    expect(screen.getByTestId('details-route')).toBeInTheDocument();
  });

  it('marks each row as a link with a chevron', async () => {
    mockedListAgents.mockResolvedValue(list(agent()));
    renderPage();
    const row = await screen.findByTestId('agents-row-a1');

    expect(row).toHaveAttribute('role', 'link');
    expect(row).toHaveAccessibleName(/\S/);
    expect(within(row).getByTestId('agents-row-chevron')).toBeInTheDocument();
  });
});
