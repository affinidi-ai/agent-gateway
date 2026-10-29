import React from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import AgentsPage from '../AgentsPage';
import { useApp } from '../../context/AppContext';
import { AgentRecord, apiClient } from '../../api';

jest.mock('../../context/AppContext', () => ({
  useApp: jest.fn(),
}));

jest.mock('../../api', () => ({
  apiClient: {
    listAgents: jest.fn(),
  },
}));

const mockedUseApp = useApp as jest.Mock;
const mockedListAgents = apiClient.listAgents as jest.Mock;

const LONG_DID = 'did:webvh:QmYAuadF1234567890:agent-gateway1.example.com:surface:abcdef12';

const agent = (overrides: Partial<AgentRecord> = {}): AgentRecord => ({
  id: 's1',
  registration: 'unregistered',
  name: 'TimeAsker',
  surface_name: 'RICK',
  status: 'active',
  protocol: 'a2a',
  runtime: 'url',
  endpoint: 'http://localhost:9002',
  tags: [],
  trust_registry: { recognized: true, authorized: false },
  agent_did: LONG_DID,
  did_surface_count: 2,
  identity_created_at: '2026-10-22T11:24:02Z',
  last_activity_at: null,
  ...overrides,
});

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
    mockedUseApp.mockReturnValue({ state: { settings: { metrics_retention: 360 } } });
  });

  it('lists rows with a count badge and display labels', async () => {
    mockedListAgents.mockResolvedValue([
      agent(),
      agent({
        id: 's2',
        name: null,
        surface_name: 'Frank 003',
        runtime: 'a2a-proxy',
        status: 'disabled',
        agent_did: null,
        did_surface_count: 0,
        trust_registry: { recognized: false, authorized: false },
      }),
    ]);
    renderPage();

    const first = await screen.findByTestId('agents-row-s1');
    expect(screen.getByTestId('agents-count')).toHaveTextContent('2');
    expect(within(first).getByText('TimeAsker')).toBeInTheDocument();
    expect(within(first).getByText('Direct URL')).toBeInTheDocument();
    expect(within(first).getByTestId('agents-protocol-badge')).toHaveTextContent('A2A');
    expect(within(first).getByText('Active')).toBeInTheDocument();
    expect(within(first).getByText('Recognised')).toBeInTheDocument();
    expect(within(first).getByText('None in last 6h')).toBeInTheDocument();

    const did = within(first).getByTestId('agents-did');
    expect(did).not.toHaveTextContent(LONG_DID);
    expect(did).toHaveTextContent('…');
    expect(did).toHaveAttribute('title', `${LONG_DID}\nAlso used on 1 other surface`);
    expect(within(first).getByTestId('agents-copy-did-button')).toBeInTheDocument();

    const second = screen.getByTestId('agents-row-s2');
    expect(within(second).getByText('Unnamed agent')).toBeInTheDocument();
    expect(within(second).getByText('No DID')).toBeInTheDocument();
    expect(within(second).queryByTestId('agents-copy-did-button')).not.toBeInTheDocument();
    expect(within(second).getByText('A2A proxy')).toBeInTheDocument();
    expect(within(second).getByTestId('agents-protocol-badge')).toHaveTextContent('A2A via proxy');
    expect(within(second).getByText('Disabled')).toBeInTheDocument();
    expect(within(second).getByText('No Trust Registry')).toBeInTheDocument();
    expect(screen.queryByText('a2a-proxy')).not.toBeInTheDocument();
  });

  it('filters by name client-side', async () => {
    mockedListAgents.mockResolvedValue([
      agent(),
      agent({ id: 's2', name: 'Treasury', surface_name: 'Ops' }),
    ]);
    renderPage();
    await screen.findByTestId('agents-row-s1');

    fireEvent.change(screen.getByTestId('agents-filter-input'), { target: { value: 'treas' } });
    expect(screen.queryByTestId('agents-row-s1')).not.toBeInTheDocument();
    expect(screen.getByTestId('agents-row-s2')).toBeInTheDocument();
    expect(screen.getByTestId('agents-count')).toHaveTextContent('1 of 2');

    fireEvent.change(screen.getByTestId('agents-filter-input'), { target: { value: 'nothing' } });
    expect(screen.getByTestId('agents-no-match')).toBeInTheDocument();
  });

  it('filters by runtime label', async () => {
    mockedListAgents.mockResolvedValue([
      agent(),
      agent({ id: 's2', name: 'Treasury', surface_name: 'Ops', runtime: 'gateway' }),
    ]);
    renderPage();
    await screen.findByTestId('agents-row-s1');

    fireEvent.change(screen.getByTestId('agents-filter-input'), { target: { value: 'remote' } });
    expect(screen.queryByTestId('agents-row-s1')).not.toBeInTheDocument();
    expect(screen.getByTestId('agents-row-s2')).toBeInTheDocument();
  });

  it('filters by status and dims inactive rows', async () => {
    mockedListAgents.mockResolvedValue([
      agent(),
      agent({ id: 's2', name: 'Treasury', status: 'disabled' }),
    ]);
    renderPage();
    await screen.findByTestId('agents-row-s1');
    expect(screen.getByTestId('agents-row-s1')).not.toHaveClass('agents-row-dimmed');
    expect(screen.getByTestId('agents-row-s2')).toHaveClass('agents-row-dimmed');

    const status = screen.getByRole('combobox', { name: 'Filter by status' });
    fireEvent.change(status, { target: { value: 'disabled' } });
    expect(screen.queryByTestId('agents-row-s1')).not.toBeInTheDocument();
    expect(screen.getByTestId('agents-row-s2')).toBeInTheDocument();
    expect(screen.getByTestId('agents-count')).toHaveTextContent('1 of 2');

    fireEvent.change(status, { target: { value: 'active' } });
    expect(screen.getByTestId('agents-row-s1')).toBeInTheDocument();
    expect(screen.queryByTestId('agents-row-s2')).not.toBeInTheDocument();

    fireEvent.change(screen.getByTestId('agents-filter-input'), { target: { value: 'treas' } });
    expect(screen.getByTestId('agents-no-match')).toBeInTheDocument();
  });

  it('shows the empty state', async () => {
    mockedListAgents.mockResolvedValue([]);
    renderPage();
    expect(await screen.findByText('No agents yet')).toBeInTheDocument();
  });

  it('shows the error state and retries', async () => {
    mockedListAgents.mockRejectedValueOnce(new Error('Internal Server Error'));
    mockedListAgents.mockResolvedValueOnce([agent()]);
    renderPage();

    expect(await screen.findByTestId('agents-load-error')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('agents-retry-button'));
    expect(await screen.findByTestId('agents-row-s1')).toBeInTheDocument();
    expect(mockedListAgents).toHaveBeenCalledTimes(2);
  });

  it('opens the details on row click', async () => {
    mockedListAgents.mockResolvedValue([agent()]);
    renderPage();
    fireEvent.click(await screen.findByTestId('agents-row-s1'));
    expect(screen.getByTestId('details-route')).toBeInTheDocument();
  });

  it('links Used by surfaces to the surface without opening the details', async () => {
    mockedListAgents.mockResolvedValue([agent()]);
    renderPage();
    const link = await screen.findByTestId('agents-surface-link');
    expect(link).toHaveTextContent('RICK');
    fireEvent.click(link);
    expect(screen.getByTestId('surface-route')).toBeInTheDocument();
    expect(screen.queryByTestId('details-route')).not.toBeInTheDocument();
  });
});
