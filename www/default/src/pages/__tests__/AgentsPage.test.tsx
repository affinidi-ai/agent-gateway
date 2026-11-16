import React from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import AgentsPage from '../AgentsPage';
import { AgentListResponse, AgentRecord, apiClient } from '../../api';

jest.mock('../../api', () => ({
  apiClient: {
    listAgents: jest.fn(),
  },
}));

const mockedListAgents = apiClient.listAgents as jest.Mock;

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
        <Route path="/surfaces/:surfaceId" element={<div data-testid="surface-route" />} />
      </Routes>
    </MemoryRouter>
  );

describe('AgentsPage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
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
    expect(screen.getByTestId('agents-count')).toHaveTextContent('2');
    expect(within(first).getByText('TimeAsker')).toBeInTheDocument();
    expect(within(first).getByText('Direct URL')).toBeInTheDocument();
    expect(within(first).getByTestId('agents-protocol-badge')).toHaveTextContent('A2A');
    expect(within(first).getByTestId('agents-trust-recorded')).toHaveTextContent('Recorded');
    expect(within(first).queryByTestId('agents-trust-not-recorded')).not.toBeInTheDocument();
    expect(within(first).getByText('None in last 6h')).toBeInTheDocument();

    const did = within(first).getByTestId('agents-did');
    expect(did).not.toHaveTextContent(LONG_DID);
    expect(did).toHaveTextContent('…');
    expect(did).toHaveAttribute('title', LONG_DID);
    expect(within(first).getByTestId('agents-copy-did-button')).toBeInTheDocument();

    const second = screen.getByTestId('agents-row-a2');
    expect(within(second).getByTestId('agents-unnamed')).toHaveTextContent('Unnamed agent');
    expect(within(second).queryByTestId('agents-name')).not.toBeInTheDocument();
    expect(within(second).getByText('No DID')).toBeInTheDocument();
    expect(within(second).queryByTestId('agents-copy-did-button')).not.toBeInTheDocument();
    expect(within(second).getByText('A2A proxy')).toBeInTheDocument();
    expect(within(second).getByTestId('agents-protocol-badge')).toHaveTextContent('A2A via proxy');
    expect(within(second).getByTestId('agents-trust-not-recorded')).toHaveTextContent(
      'Not recorded'
    );
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

    expect(screen.getByRole('columnheader', { name: 'Identities' })).toBeInTheDocument();
    const dids = within(row).getAllByTestId('agents-did');
    expect(dids.map(d => d.textContent)).toEqual(['did:web:a.example', 'did:web:b.example']);
    expect(within(row).getAllByTestId('agents-copy-did-button')).toHaveLength(2);
    expect(within(row).queryByText('No DID')).not.toBeInTheDocument();
    expect(within(row).queryByText(/other surface/)).not.toBeInTheDocument();
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
    expect(within(row).getByTestId('agents-surfaces')).toHaveAttribute('title', 'helium, oxygen');
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
    expect(screen.getByTestId('agents-count')).toHaveTextContent('1 of 2');

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

  it('filters by runtime label', async () => {
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

    fireEvent.change(screen.getByTestId('agents-filter-input'), { target: { value: 'remote' } });
    expect(screen.queryByTestId('agents-row-a1')).not.toBeInTheDocument();
    expect(screen.getByTestId('agents-row-a2')).toBeInTheDocument();
  });

  it('shows the empty state', async () => {
    mockedListAgents.mockResolvedValue(list());
    renderPage();
    expect(await screen.findByText('No agents yet')).toBeInTheDocument();
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
});
