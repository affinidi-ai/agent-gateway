import React from 'react';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom';
import AgentDetailPage from '../AgentDetailPage';
import { AgentDetails, apiClient } from '../../api';
import { usePermissions } from '../../context/PermissionsContext';
import { PageTitleProvider, usePageTitleContext } from '../../context/PageTitleContext';

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

const OpenAgentB: React.FC = () => {
  const navigate = useNavigate();
  return (
    <button
      type="button"
      data-testid="open-agent-b1"
      onClick={() => navigate('/agent-registry/b1')}
    />
  );
};

type Deferred<T> = {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason: unknown) => void;
};

const deferred = <T,>(): Deferred<T> => {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};

const TopbarTitle: React.FC = () => {
  const { title } = usePageTitleContext();
  return <div data-testid="topbar-title">{title ?? ''}</div>;
};

const renderPage = () =>
  render(
    <PageTitleProvider>
      <MemoryRouter initialEntries={['/agent-registry/a1']}>
        <TopbarTitle />
        <OpenAgentB />
        <Routes>
          <Route path="/agent-registry/:agentId" element={<AgentDetailPage />} />
          <Route path="/agent-registry" element={<div data-testid="list-route" />} />
          <Route path="/surfaces/:surfaceId" element={<div data-testid="surface-route" />} />
        </Routes>
      </MemoryRouter>
    </PageTitleProvider>
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

    expect(screen.getByTestId('agent-connection-runtime')).toHaveTextContent('Fabric');
    expect(screen.getByTestId('agent-connection-gateway-link')).toHaveAttribute(
      'href',
      '/gateways/g1'
    );
    expect(screen.getByTestId('agent-connection-remote-surface')).toHaveTextContent('c1');
  });

  it('names the remote gateway, with its id in the tooltip', async () => {
    mockedGetAgent.mockResolvedValue(details({ target_name: 'Acme <b>Gateway</b>' }));
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Connection/);

    const link = screen.getByTestId('agent-connection-gateway-link');
    expect(link).toHaveTextContent(/^Acme <b>Gateway<\/b>$/);
    expect(within(link).getByTitle('g1')).toBeInTheDocument();
  });

  it('names the A2A proxy without a link when the viewer cannot open it', async () => {
    mockedUsePermissions.mockReturnValue({ hasPermission: () => false });
    mockedGetAgent.mockResolvedValue(
      details({ runtime: 'a2a-proxy', endpoint: 'a2a-proxy://p1', target_name: 'Orders proxy' })
    );
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Connection/);

    expect(screen.getByTestId('agent-connection-proxy')).toHaveTextContent(/^Orders proxy$/);
    expect(screen.queryByTestId('agent-connection-proxy-link')).not.toBeInTheDocument();
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
    expect(screen.getByTestId('agent-connection-target')).toHaveTextContent('agent.example.com');
    expect(screen.getByTestId('agent-connection-copy-endpoint')).toBeInTheDocument();
    expect(screen.queryByText(/s3cret|pw@/)).not.toBeInTheDocument();
  });

  it('shows the upstream path ending at the remote gateway', async () => {
    mockedGetAgent.mockResolvedValue(details({ target_name: 'Acme Gateway' }));
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Connection/);

    expect(screen.getByTestId('agent-connection-target')).toHaveTextContent(
      /Remote gateway\s*Acme Gateway/
    );
    expect(screen.getByTestId('agent-connection-description')).toHaveTextContent('remote gateway');
  });

  it('lists every surface with the URL callers use, linking to the surface', async () => {
    mockedGetAgent.mockResolvedValue(
      details({
        surfaces: [
          {
            surface_id: 's1',
            name: 'helium',
            protocol: 'a2a',
            route: '/helium',
            public_url: 'https://gateway.example/helium',
          },
          { surface_id: 's2', name: 'oxygen', protocol: 'a2a', route: '/oxygen', public_url: null },
        ],
      })
    );
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Connection/);

    const helium = screen.getByTestId('agent-connection-surface-s1');
    expect(within(helium).getByTestId('agent-connection-surface-url')).toHaveTextContent(
      'https://gateway.example/helium'
    );
    expect(within(helium).getByTestId('agent-connection-copy-surface-url')).toBeInTheDocument();
    const oxygen = screen.getByTestId('agent-connection-surface-s2');
    expect(within(oxygen).getByTestId('agent-connection-surface-url')).toHaveTextContent(
      '/oxygenNo external URL configured'
    );
    expect(screen.getByTestId('agent-connection-surfaces-hop')).toHaveTextContent('2 surfaces');
    expect(screen.queryByText('This gateway')).not.toBeInTheDocument();
    expect(screen.queryByText('Access Point')).not.toBeInTheDocument();

    fireEvent.click(within(oxygen).getByTestId('agent-connection-surface-link'));
    expect(await screen.findByTestId('surface-route')).toBeInTheDocument();
  });

  it('names the single surface in the path', async () => {
    mockedGetAgent.mockResolvedValue(details());
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Connection/);
    expect(screen.getByTestId('agent-connection-surfaces-hop')).toHaveTextContent('RICK');
  });

  it('says when no surface uses the agent', async () => {
    mockedGetAgent.mockResolvedValue(details({ surfaces: [] }));
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Connection/);
    expect(screen.getByTestId('agent-connection-no-surfaces')).toHaveTextContent(
      'No surface uses this agent.'
    );
  });

  it("shows Can't be shown for a redacted endpoint", async () => {
    mockedGetAgent.mockResolvedValue(
      details({ runtime: 'gateway', endpoint: 'fabric://redacted.invalid' })
    );
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Connection/);

    expect(screen.getByTestId('agent-connection-endpoint')).toHaveTextContent("Can't be shown");
    expect(screen.getByTestId('agent-connection-target')).toHaveTextContent('Hidden');
    expect(screen.queryByText(/redacted\.invalid/)).not.toBeInTheDocument();
  });

  it('shows only the Agent Card, Connection and Traffic tabs, opening on Agent Card', async () => {
    mockedGetAgent.mockResolvedValue(details());
    mockedGetAgentCard.mockResolvedValue({ available: true, card: { name: 'TimeAsker' } });
    renderPage();
    await screen.findByTestId('agent-details-name');

    expect(screen.getAllByRole('tab').map(t => t.textContent?.trim())).toEqual([
      'Agent Card',
      'Connection',
      'Traffic',
    ]);
    expect(screen.getByTestId('agent-tab-agent-card')).toHaveAttribute('aria-selected', 'true');
    expect(await screen.findByTestId('agent-card-preview-name')).toHaveTextContent('TimeAsker');
    expect(screen.queryByTestId('agent-tab-overview')).not.toBeInTheDocument();
    expect(screen.queryByTestId('agent-tab-surfaces')).not.toBeInTheDocument();
  });

  it('shows the header values from the agent record', async () => {
    mockedGetAgent.mockResolvedValue(details());
    renderPage();

    expect(await screen.findByTestId('agent-details-name')).toHaveTextContent('TimeAsker');
    const header = screen.getByTestId('agent-details-header');
    expect(within(header).queryByTestId('agent-details-status')).not.toBeInTheDocument();
    expect(within(header).queryByText(/Active|Disabled/)).not.toBeInTheDocument();
    expect(within(header).getByTestId('agents-protocol-badge')).toHaveTextContent(/^A2A$/);
    expect(within(header).getByTestId('agents-protocol-badge')).not.toHaveAttribute('title');
    expect(within(header).getByTestId('agent-details-runtime')).toHaveTextContent('Fabric');
    expect(within(header).getByTestId('agent-details-runtime')).toHaveClass('agent-route-badge');
    expect(within(header).queryByTestId('agent-details-endpoint-host')).not.toBeInTheDocument();
    expect(within(header).queryByRole('button')).not.toBeInTheDocument();
  });

  it('shows the endpoint host beside Unnamed agent', async () => {
    mockedGetAgent.mockResolvedValue(
      details({ name: null, runtime: 'url', endpoint: 'https://agent.example.com/a2a' })
    );
    renderPage();
    await screen.findByTestId('agent-details-name');
    expect(screen.getByTestId('agent-details-endpoint-host')).toHaveTextContent(
      'https://agent.example.com'
    );
  });

  it('uses one name and style for the route on the Connection tab', async () => {
    mockedGetAgent.mockResolvedValue(details());
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Connection/);

    expect(screen.getByRole('heading', { name: /^Route/ })).toBeInTheDocument();
    expect(screen.queryByText('Upstream')).not.toBeInTheDocument();
    expect(screen.getByTestId('agent-connection-runtime')).toHaveClass('agent-route-badge');
    expect(screen.getByTestId('agent-connection-path')).toHaveAttribute('aria-label', 'Route path');
  });

  it('shows Unnamed agent for an agent without a name', async () => {
    mockedGetAgent.mockResolvedValue(details({ name: null }));
    renderPage();
    expect(await screen.findByTestId('agent-details-name')).toHaveTextContent('Unnamed agent');
    expect(screen.getByTestId('topbar-title')).toHaveTextContent(/^Unnamed agent$/);
  });

  it('names the agent in the top bar and uses an outline back button', async () => {
    mockedGetAgent.mockResolvedValue(details());
    renderPage();
    await screen.findByTestId('agent-details-name');

    expect(screen.getByTestId('topbar-title')).toHaveTextContent(/^TimeAsker$/);
    expect(screen.getByTestId('agent-back-button')).toHaveClass('btn-outline-secondary');
  });

  it('leaves the top bar title to the route when the agent is not found', async () => {
    const { ApiError } = jest.requireMock('../../api');
    mockedGetAgent.mockRejectedValue(new ApiError('Not Found', 404));
    renderPage();
    await screen.findByTestId('agent-not-found');
    expect(screen.getByTestId('topbar-title')).toBeEmptyDOMElement();
  });

  it('shows not found for a 404', async () => {
    const { ApiError } = jest.requireMock('../../api');
    mockedGetAgent.mockRejectedValue(new ApiError('Not Found', 404));
    renderPage();
    expect(await screen.findByTestId('agent-not-found')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('agent-back-button'));
    expect(screen.getByTestId('list-route')).toBeInTheDocument();
  });

  it('shows not found, not the previous agent, after opening a missing agent', async () => {
    const { ApiError } = jest.requireMock('../../api');
    mockedGetAgent.mockImplementation((id: string) =>
      id === 'a1' ? Promise.resolve(details()) : Promise.reject(new ApiError('Not Found', 404))
    );
    renderPage();
    expect(await screen.findByTestId('agent-details-name')).toHaveTextContent('TimeAsker');

    fireEvent.click(screen.getByTestId('open-agent-b1'));

    expect(await screen.findByTestId('agent-not-found')).toBeInTheDocument();
    expect(screen.queryByTestId('agent-details-name')).not.toBeInTheDocument();
  });

  it.each([
    ['response', (late: Deferred<AgentDetails>) => late.resolve(details())],
    ['failure', (late: Deferred<AgentDetails>) => late.reject(new Error('Boom'))],
  ])('ignores a late %s for the previously opened agent', async (_, settle) => {
    const late = deferred<AgentDetails>();
    mockedGetAgent.mockImplementation((id: string) =>
      id === 'a1' ? late.promise : Promise.resolve(details({ id: 'b1', name: 'Oxygen' }))
    );
    renderPage();
    fireEvent.click(screen.getByTestId('open-agent-b1'));
    expect(await screen.findByTestId('agent-details-name')).toHaveTextContent('Oxygen');

    await act(async () => {
      settle(late);
      await late.promise.catch(() => undefined);
    });

    expect(screen.getByTestId('agent-details-name')).toHaveTextContent('Oxygen');
    expect(screen.queryByTestId('agent-load-error')).not.toBeInTheDocument();
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
    expect(within(preview).getByRole('heading', { name: 'Skills (1)' })).toBeInTheDocument();
    expect(within(preview).queryByText('Agent Card')).not.toBeInTheDocument();
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

    expect(await screen.findByTestId('agent-card-preview')).toBeInTheDocument();
    expect(screen.queryByTestId('agent-card-copy-button')).not.toBeInTheDocument();

    fireEvent.click(screen.getByTestId('agent-card-view-json'));
    expect(screen.getByTestId('agent-card-view-json')).toHaveAttribute('aria-pressed', 'true');
    expect(screen.queryByTestId('agent-card-preview')).not.toBeInTheDocument();
    const json = screen.getByTestId('agent-card-json');
    expect(json).toHaveTextContent('<img src=x onerror=alert(1)>');
    expect(within(json).queryByRole('img')).not.toBeInTheDocument();
    expect(within(json).queryByRole('link')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy JSON' })).toBe(
      screen.getByTestId('agent-card-copy-button')
    );
  });

  it('copies the card JSON like the Verifiable Presentation viewer', async () => {
    const writeText = jest.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    mockedGetAgent.mockResolvedValue(details());
    mockedGetAgentCard.mockResolvedValue({ available: true, card: { name: 'TimeAsker' } });
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Agent Card/);
    await screen.findByTestId('agent-card-preview');
    fireEvent.click(screen.getByTestId('agent-card-view-json'));

    const copy = screen.getByTestId('agent-card-copy-button');
    expect(copy).toHaveClass('btn-outline-secondary');
    expect(copy).toHaveTextContent('Copy');
    fireEvent.click(copy);
    expect(writeText).toHaveBeenCalledWith(JSON.stringify({ name: 'TimeAsker' }, null, 2));
    expect(copy).toHaveTextContent('Copied');
  });

  it.each([
    ['fetched', 'Fetched & rewritten by the gateway'],
    ['generated', 'Generated by the A2A proxy'],
    ['remote_gateway', 'Relayed from the remote gateway'],
  ])('names the surface serving the %s card and the source', async (source, text) => {
    mockedGetAgent.mockResolvedValue(details());
    mockedGetAgentCard.mockResolvedValue({
      available: true,
      card: { name: 'TimeAsker' },
      source,
      surface_id: 's1',
      card_surface_ids: ['s1'],
    });
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Agent Card/);

    const row = await screen.findByTestId('agent-card-source');
    expect(row).toHaveTextContent(`Served byRICK·${text}`);
    expect(row).toHaveAttribute('data-source', source);
    expect(screen.getByTestId('agent-card-surface')).toHaveTextContent('RICK');
    expect(screen.queryByTestId('agent-card-surface-select')).not.toBeInTheDocument();
  });

  it('reads the card through the surface picked when several serve it', async () => {
    mockedGetAgent.mockResolvedValue(
      details({
        surfaces: [
          { surface_id: 's1', name: 'helium', protocol: 'a2a', route: '/helium' },
          { surface_id: 's2', name: 'oxygen', protocol: 'a2a', route: '/oxygen' },
        ],
      })
    );
    mockedGetAgentCard.mockImplementation((_id: string, surfaceId?: string) =>
      Promise.resolve({
        available: true,
        card: { name: surfaceId === 's2' ? 'From oxygen' : 'From helium' },
        source: 'fetched',
        surface_id: surfaceId ?? 's1',
        card_surface_ids: ['s1', 's2'],
      })
    );
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Agent Card/);

    expect(await screen.findByTestId('agent-card-preview-name')).toHaveTextContent('From helium');
    expect(mockedGetAgentCard).toHaveBeenLastCalledWith('a1', undefined);
    const select = screen.getByTestId('agent-card-surface-select');
    expect(select).toHaveTextContent('helium');

    fireEvent.click(select);
    fireEvent.click(await screen.findByRole('option', { name: /oxygen/ }));

    expect(await screen.findByText('From oxygen')).toBeInTheDocument();
    expect(mockedGetAgentCard).toHaveBeenLastCalledWith('a1', 's2');
    expect(screen.getByTestId('agent-card-surface-select')).toHaveTextContent('oxygen');
  });

  it('groups what the gateway changed under Added by the gateway', async () => {
    const credential = 'https://fabric.affinidi.io/extensions/agent-identity-credential/v1';
    mockedGetAgent.mockResolvedValue(details());
    mockedGetAgentCard.mockResolvedValue({
      available: true,
      source: 'fetched',
      surface_id: 's1',
      card: {
        name: 'TimeAsker',
        url: 'https://gateway.example/agents/rick',
        capabilities: {
          extensions: [
            {
              uri: credential,
              params: { did: 'did:web:rick.example', verifiablePresentation: '{"x":1}' },
            },
          ],
        },
      },
      upstream_card: {
        name: 'TimeAsker',
        url: 'http://10.0.0.5:9002',
        capabilities: {
          extensions: [{ uri: 'https://fabric.affinidi.io/extensions/agent-identity/v1' }],
        },
      },
    });
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Agent Card/);

    const changes = await screen.findByTestId('agent-card-gateway-changes');
    expect(
      within(changes).getByRole('heading', { name: 'Added by the gateway' })
    ).toBeInTheDocument();
    expect(within(changes).getByTestId('agent-card-gateway-url')).toHaveTextContent(
      'https://gateway.example/agents/rickRewritten from http://10.0.0.5:9002'
    );
    expect(within(changes).getByText('Identity credential')).toBeInTheDocument();
    expect(within(changes).getByTestId('agent-card-gateway-did')).toHaveTextContent(
      'did:web:rick.example'
    );
    expect(within(changes).getByText('Verifiable Presentation')).toBeInTheDocument();
    expect(within(changes).getByTestId('agent-card-gateway-replaced')).toHaveTextContent(
      'https://fabric.affinidi.io/extensions/agent-identity/v1'
    );
    expect(within(changes).queryByTestId('agent-card-gateway-other')).not.toBeInTheDocument();
  });

  it('shows no gateway changes for a card the gateway passed on unchanged', async () => {
    const card = { name: 'TimeAsker', url: 'https://agent.example' };
    mockedGetAgent.mockResolvedValue(details());
    mockedGetAgentCard.mockResolvedValue({
      available: true,
      source: 'remote_gateway',
      card,
      upstream_card: card,
    });
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Agent Card/);

    expect(await screen.findByTestId('agent-card-preview')).toBeInTheDocument();
    expect(screen.queryByTestId('agent-card-gateway-changes')).not.toBeInTheDocument();
  });

  it('highlights the card JSON', async () => {
    mockedGetAgent.mockResolvedValue(details());
    mockedGetAgentCard.mockResolvedValue({ available: true, card: { name: 'TimeAsker' } });
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Agent Card/);
    await screen.findByTestId('agent-card-preview');

    fireEvent.click(screen.getByTestId('agent-card-view-json'));
    const json = screen.getByTestId('agent-card-json');
    expect(json).toHaveClass('vp-json-pre');
    expect(within(json).getByText('"TimeAsker"')).toHaveClass('json-string');
  });

  it('shows no card source the API did not name', async () => {
    mockedGetAgent.mockResolvedValue(details());
    mockedGetAgentCard.mockResolvedValue({ available: true, card: { name: 'TimeAsker' } });
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Agent Card/);

    expect(await screen.findByTestId('agent-card-preview-name')).toHaveTextContent('TimeAsker');
    expect(screen.queryByTestId('agent-card-source')).not.toBeInTheDocument();
  });

  it.each([
    ['not_running', "None of this agent's surfaces is running on this gateway"],
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

  it('labels traffic with the retained window and shows no 7-day card or per-surface breakdown', async () => {
    mockedGetAgent.mockResolvedValue(details());
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Traffic/);

    expect(screen.getByTestId('agent-traffic-requests')).toHaveTextContent('Requests (last 6h)');
    expect(screen.getByTestId('agent-traffic-requests')).toHaveTextContent('12');
    expect(screen.getByTestId('agent-traffic-failed')).toHaveTextContent(
      'Failed requests (last 6h)'
    );
    expect(screen.getByTestId('agent-traffic-failed')).toHaveTextContent('3');
    expect(screen.getByTestId('agent-traffic-p95')).toHaveTextContent('140 ms');
    expect(screen.queryByTestId('agent-traffic-requests-7d')).not.toBeInTheDocument();
    expect(screen.queryByTestId('agent-traffic-by-surface')).not.toBeInTheDocument();
  });

  it('shows one empty state instead of zero cards when there were no requests', async () => {
    mockedGetAgent.mockResolvedValue(
      details({
        traffic: {
          window_minutes: 360,
          total_requests: 0,
          failed: 0,
          gateway_faults: 0,
          p95_latency_ms: null,
        },
      })
    );
    renderPage();
    await screen.findByTestId('agent-details-name');
    openTab(/Traffic/);

    expect(screen.getByTestId('agent-traffic-empty')).toHaveTextContent(
      'No requests in the last 6h'
    );
    expect(screen.queryByTestId('agent-traffic-requests')).not.toBeInTheDocument();
    expect(screen.queryByTestId('agent-traffic-failed')).not.toBeInTheDocument();
  });
});
