import React from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import AgentDetailPage from '../AgentDetailPage';
import { AgentDetails, apiClient } from '../../api';
import { usePermissions } from '../../context/PermissionsContext';

jest.mock('../../api', () => {
  class ApiError extends Error {
    readonly status: number;
    constructor(message: string, httpStatus: number) {
      super(message);
      this.status = httpStatus;
    }
  }
  return {
    ApiError,
    apiClient: {
      getAgent: jest.fn(),
      getAgentCard: jest.fn(),
    },
  };
});

jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: jest.fn(),
}));

const mockedUsePermissions = usePermissions as jest.Mock;
const mockedGetAgent = apiClient.getAgent as jest.Mock;
const mockedGetAgentCard = apiClient.getAgentCard as jest.Mock;

const details = (overrides: Partial<AgentDetails> = {}): AgentDetails => ({
  id: 'a1',
  registration: 'unregistered',
  name: 'TimeAsker',
  protocol: 'a2a',
  runtime: 'gateway',
  endpoint: 'fabric://g1/c1',
  tags: [],
  identities: [
    { did: 'did:web:agent.example.com', created_at: '2026-10-22T11:24:02Z', source: 'managed' },
  ],
  trust_registry: { recorded: true },
  last_activity_at: null,
  surfaces: [{ surface_id: 's1', name: 'RICK', protocol: 'a2a', route: '/agents/rick' }],
  traffic: {
    window_minutes: 360,
    total_requests: 12,
    failed: 2,
    gateway_faults: 1,
    p95_latency_ms: 140,
  },
  ...overrides,
});

const renderPage = () =>
  render(
    <MemoryRouter initialEntries={['/agent-registry/a1']}>
      <Routes>
        <Route path="/agent-registry/:agentId" element={<AgentDetailPage />} />
        <Route path="/agent-registry" element={<div data-testid="list-route" />} />
      </Routes>
    </MemoryRouter>
  );

const openTab = (name: RegExp) => fireEvent.click(screen.getByRole('tab', { name }));

describe('AgentDetailPage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockedUsePermissions.mockReturnValue({ hasPermission: () => true });
  });

  it('shows a remote gateway connection with a link', async () => {
    mockedGetAgent.mockResolvedValue(details());
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Connection/);

    expect(screen.getByTestId('agent-connection-runtime')).toHaveTextContent('Remote gateway');
    expect(screen.getByTestId('agent-connection-gateway-link')).toHaveAttribute(
      'href',
      '/gateways/g1'
    );
    expect(screen.getByTestId('agent-connection-remote-surface')).toHaveTextContent('c1');
  });

  it('shows an A2A proxy without a link when the viewer cannot open it', async () => {
    mockedUsePermissions.mockReturnValue({ hasPermission: () => false });
    mockedGetAgent.mockResolvedValue(details({ runtime: 'a2a-proxy', endpoint: 'a2a-proxy://p1' }));
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Connection/);

    expect(screen.getByTestId('agent-connection-proxy')).toHaveTextContent('p1');
    expect(screen.queryByTestId('agent-connection-proxy-link')).not.toBeInTheDocument();
  });

  it('hides secrets in a URL endpoint', async () => {
    mockedGetAgent.mockResolvedValue(
      details({ runtime: 'url', endpoint: 'https://u:pw@agent.example.com/a2a?token=s3cret' })
    );
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Connection/);

    expect(screen.getByTestId('agent-connection-endpoint')).toHaveTextContent(
      'https://agent.example.com/a2a'
    );
    expect(screen.queryByText(/s3cret|pw@/)).not.toBeInTheDocument();
  });

  it("shows Can't be shown for a redacted endpoint", async () => {
    mockedGetAgent.mockResolvedValue(
      details({ runtime: 'gateway', endpoint: 'fabric://redacted.invalid' })
    );
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Connection/);

    expect(screen.getByTestId('agent-connection-endpoint')).toHaveTextContent("Can't be shown");
    expect(screen.queryByText(/redacted\.invalid/)).not.toBeInTheDocument();
  });

  it('shows the header and Overview values from the agent record', async () => {
    mockedGetAgent.mockResolvedValue(details());
    renderPage();

    expect(await screen.findByTestId('agent-details-name')).toHaveTextContent('TimeAsker');
    const header = screen.getByTestId('agent-details-header');
    expect(within(header).queryByTestId('agent-details-status')).not.toBeInTheDocument();
    expect(within(header).queryByText(/Active|Disabled/)).not.toBeInTheDocument();
    expect(within(header).getByTestId('agents-protocol-badge')).toHaveTextContent(
      'A2A via gateway'
    );
    expect(within(header).getByTestId('agents-protocol-badge')).toHaveAttribute(
      'title',
      'The gateway reaches this agent through a remote gateway'
    );
    expect(within(header).getByTestId('agent-details-runtime')).toHaveTextContent('Remote gateway');
    expect(within(header).queryByRole('button')).not.toBeInTheDocument();
    expect(screen.getByTestId('agent-overview-runtime')).toHaveTextContent('Remote gateway');
    expect(screen.getByTestId('agent-overview-description')).toHaveTextContent('—');
    expect(screen.getByTestId('agent-overview-identity-source')).toHaveTextContent(
      'Managed identity, issued by this gateway. Created'
    );
    expect(screen.getByTestId('agent-overview-identity-source')).toHaveTextContent('2026');
    expect(screen.getByTestId('agents-did')).toHaveTextContent('did:web:agent.example.com');
    expect(screen.getByTestId('agents-trust-recorded')).toHaveTextContent('Recorded');
    expect(screen.queryByTestId('agents-trust-not-recorded')).not.toBeInTheDocument();
    expect(screen.queryByText(/not checked against the Trust Registry/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Recognised|Authorised|other surface/)).not.toBeInTheDocument();
  });

  it('shows Unnamed agent for an agent without a name', async () => {
    mockedGetAgent.mockResolvedValue(details({ name: null }));
    renderPage();
    expect(await screen.findByTestId('agent-details-name')).toHaveTextContent('Unnamed agent');
  });

  it('shows every identity in the Overview, and Not recorded', async () => {
    mockedGetAgent.mockResolvedValue(
      details({
        identities: [
          { did: 'did:web:a.example', created_at: null, source: 'surface' },
          { did: 'did:key:z6Mkb', created_at: '2026-10-22T11:24:02Z', source: 'managed' },
        ],
        trust_registry: { recorded: false },
      })
    );
    renderPage();
    await screen.findByTestId('agent-details-name');

    const items = screen.getAllByTestId('agent-overview-identity');
    expect(items).toHaveLength(2);
    expect(within(items[0]).getByTestId('agents-did')).toHaveTextContent('did:web:a.example');
    expect(within(items[0]).getByTestId('agent-overview-identity-source')).toHaveTextContent(
      /^Set on the surface$/
    );
    expect(within(items[1]).getByTestId('agents-did')).toHaveTextContent('did:key:z6Mkb');
    expect(within(items[1]).getByTestId('agent-overview-identity-source')).toHaveTextContent(
      'Managed identity, issued by this gateway. Created'
    );
    expect(screen.getByText('Identities (2)')).toBeInTheDocument();
    expect(screen.getByTestId('agents-trust-not-recorded')).toHaveTextContent('Not recorded');
    expect(screen.queryByTestId('agents-trust-recorded')).not.toBeInTheDocument();
  });

  it('shows No DID when the agent has no identity', async () => {
    mockedGetAgent.mockResolvedValue(details({ identities: [] }));
    renderPage();
    await screen.findByTestId('agent-details-name');

    expect(screen.getByTestId('agents-no-did')).toHaveTextContent('No DID');
    expect(screen.queryByTestId('agent-overview-identity')).not.toBeInTheDocument();
  });

  it('shows not found for a 404', async () => {
    const { ApiError } = jest.requireMock('../../api');
    mockedGetAgent.mockRejectedValue(new ApiError('Not Found', 404));
    renderPage();
    expect(await screen.findByTestId('agent-not-found')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('agent-back-button'));
    expect(screen.getByTestId('list-route')).toBeInTheDocument();
  });

  it('previews the card as plain text', async () => {
    mockedGetAgent.mockResolvedValue(details());
    mockedGetAgentCard.mockResolvedValue({
      available: true,
      card: {
        name: '<img src=x onerror=alert(1)>',
        description: 'Tells the time',
        url: 'https://evil.example.com',
        version: '1.2.0',
        provider: { organization: 'Acme' },
        capabilities: { streaming: true },
        defaultInputModes: ['text/plain', 42, null],
        skills: [{ id: 'time', name: 'Get time', description: 'Current time' }, 'bogus'],
      },
    });
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Agent Card/);

    const preview = await screen.findByTestId('agent-card-preview');
    expect(screen.getByTestId('agent-card-view-preview')).toHaveAttribute('aria-pressed', 'true');
    expect(screen.queryByTestId('agent-card-json')).not.toBeInTheDocument();
    expect(within(preview).getByTestId('agent-card-preview-name')).toHaveTextContent(
      '<img src=x onerror=alert(1)>'
    );
    expect(within(preview).queryByRole('img')).not.toBeInTheDocument();
    expect(within(preview).queryByRole('link')).not.toBeInTheDocument();
    expect(preview).toHaveTextContent('Tells the time');
    expect(preview).toHaveTextContent('https://evil.example.com');
    expect(preview).toHaveTextContent('1.2.0');
    expect(preview).toHaveTextContent('Acme');
    expect(preview).toHaveTextContent('Yes');
    expect(preview).toHaveTextContent('text/plain, 42');
    expect(within(preview).getByTestId('agent-card-preview-skills')).toHaveTextContent(
      'Skills (1)Get timeCurrent time'
    );
  });

  it('previews a sparse card with fallbacks', async () => {
    mockedGetAgent.mockResolvedValue(details());
    mockedGetAgentCard.mockResolvedValue({ available: true, card: {} });
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Agent Card/);

    const preview = await screen.findByTestId('agent-card-preview');
    expect(within(preview).getByTestId('agent-card-preview-name')).toHaveTextContent(
      'Unnamed agent'
    );
    expect(within(preview).getAllByText('Not set').length).toBe(7);
    expect(within(preview).getByText('No skills listed')).toBeInTheDocument();
  });

  it('shows a non-object card only as JSON', async () => {
    mockedGetAgent.mockResolvedValue(details());
    mockedGetAgentCard.mockResolvedValue({ available: true, card: ['not', 'a', 'card'] });
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Agent Card/);

    expect(await screen.findByTestId('agent-card-preview-empty')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('agent-card-view-json'));
    expect(screen.getByTestId('agent-card-json')).toHaveTextContent('"card"');
  });

  it('shows the card JSON as plain text', async () => {
    mockedGetAgent.mockResolvedValue(details());
    mockedGetAgentCard.mockResolvedValue({
      available: true,
      card: { name: '<img src=x onerror=alert(1)>', url: 'https://evil.example.com' },
    });
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Agent Card/);

    fireEvent.click(await screen.findByTestId('agent-card-view-json'));
    expect(screen.getByTestId('agent-card-view-json')).toHaveAttribute('aria-pressed', 'true');
    expect(screen.queryByTestId('agent-card-preview')).not.toBeInTheDocument();
    const json = screen.getByTestId('agent-card-json');
    expect(json).toHaveTextContent('<img src=x onerror=alert(1)>');
    expect(within(json).queryByRole('img')).not.toBeInTheDocument();
    expect(within(json).queryByRole('link')).not.toBeInTheDocument();
    expect(screen.getByTestId('agent-card-copy-button')).toHaveTextContent('Copy JSON');
  });

  it.each([
    ['unsupported_runtime', "Agent Card isn't available for this runtime"],
    ['no_agent_card', "This agent doesn't publish an Agent Card"],
    [
      'operator_only',
      'Only an appliance operator can read the Agent Card of an agent behind appliance-wide surfaces',
    ],
  ])('shows the %s state', async (reason, text) => {
    mockedGetAgent.mockResolvedValue(details());
    mockedGetAgentCard.mockResolvedValue({ available: false, reason });
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Agent Card/);
    expect(await screen.findByTestId(`agent-card-${reason}`)).toHaveTextContent(text);
  });

  it('retries a failed card load', async () => {
    mockedGetAgent.mockResolvedValue(details());
    mockedGetAgentCard
      .mockRejectedValueOnce(new Error('Bad Gateway'))
      .mockResolvedValueOnce({ available: true, card: { name: 'TimeAsker' } });
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Agent Card/);

    expect(await screen.findByText("Agent Card couldn't be loaded")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('agent-card-retry-button'));
    expect(await screen.findByTestId('agent-card-preview-name')).toHaveTextContent('TimeAsker');
  });

  it('lists every surface without a status', async () => {
    mockedGetAgent.mockResolvedValue(
      details({
        surfaces: [
          { surface_id: 's1', name: 'helium', protocol: 'ap2', route: '/helium' },
          { surface_id: 's2', name: 'oxygen', protocol: 'a2a', route: '/oxygen' },
        ],
      })
    );
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Surfaces \(2\)/);

    const tab = screen.getByTestId('agent-surfaces-tab');
    expect(screen.getByTestId('agent-surfaces-row-s1')).toBeInTheDocument();
    expect(screen.getByTestId('agent-surfaces-row-s2')).toBeInTheDocument();
    const links = within(tab).getAllByTestId('agent-surfaces-link');
    expect(links.map(l => l.textContent)).toEqual(['helium', 'oxygen']);
    expect(links[1]).toHaveAttribute('href', '/surfaces/s2');
    expect(within(tab).getByText('/helium')).toBeInTheDocument();
    expect(within(tab).getByText('/oxygen')).toBeInTheDocument();
    expect(within(tab).queryByRole('columnheader', { name: 'Status' })).not.toBeInTheDocument();
    expect(within(tab).queryByText(/Active|Disabled/)).not.toBeInTheDocument();
  });

  it('labels traffic with the retained window and shows — for 7 days', async () => {
    mockedGetAgent.mockResolvedValue(details());
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Traffic/);

    expect(screen.getByTestId('agent-traffic-requests')).toHaveTextContent('Requests (last 6h)');
    expect(screen.getByTestId('agent-traffic-requests')).toHaveTextContent('12');
    expect(screen.getByTestId('agent-traffic-requests-7d')).toHaveTextContent('—');
    expect(screen.getByTestId('agent-traffic-failed')).toHaveTextContent(
      'Failed requests (last 6h)'
    );
    expect(screen.getByTestId('agent-traffic-failed')).toHaveTextContent('3');
    expect(screen.getByTestId('agent-traffic-p95')).toHaveTextContent('140 ms');
    expect(screen.getByTestId('agent-traffic-by-surface')).toHaveTextContent('RICK');
    expect(screen.getByTestId('agent-traffic-surface-link')).toHaveAttribute(
      'href',
      '/surfaces/s1'
    );
  });

  it('shows no per-surface breakdown for an agent with several surfaces', async () => {
    mockedGetAgent.mockResolvedValue(
      details({
        surfaces: [
          { surface_id: 's1', name: 'helium', protocol: 'ap2', route: '/helium' },
          { surface_id: 's2', name: 'oxygen', protocol: 'a2a', route: '/oxygen' },
        ],
      })
    );
    renderPage();
    await screen.findByTestId('agent-details-name');
    fireEvent.click(screen.getByTestId('agent-tab-traffic'));

    expect(screen.getByTestId('agent-traffic-requests')).toHaveTextContent('12');
    expect(screen.queryByTestId('agent-traffic-by-surface')).not.toBeInTheDocument();
  });
});
