import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import CallerAuthFullscreen from '../caller-auth/CallerAuthFullscreen';
import { SurfaceMetaProvider, type SurfaceMetaValue } from '../../SurfaceMetaContext';
import type { CanvasNode, ConfigPanelProps } from '../types';

const mockFetch = jest.fn();
jest.mock('../../../../api', () => ({
  apiClient: { fetch: (...args: unknown[]) => mockFetch(...args), get: jest.fn() },
}));

const ENTRY_URL = 'https://gw.example.com/agents/helpdesk';
const ISSUER = 'https://idp.example.com';
const JWKS = 'https://idp.example.com/jwks';
const AP: CanvasNode = {
  id: 'access-point',
  type: 'access-point',
  label: '',
  configured: true,
  config: { listen_address: 'https://gw.example.com', route: '/agents/helpdesk' },
};

const json = (body: unknown, ok = true, status = ok ? 200 : 500) => ({
  ok,
  status,
  json: async () => body,
  text: async () => '',
});

const strategies = [
  {
    id: 'pinned',
    name: 'Pinned',
    expected_issuer: ISSUER,
    jwks_source: { type: 'remote', jwks_uri: JWKS },
    authorization_server: {
      issuer: ISSUER,
      metadata_url: `${ISSUER}/.well-known/oauth-authorization-server`,
      token_endpoint: `${ISSUER}/token`,
      jwks_uri: JWKS,
      client_secret: 'pinned-secret-value',
    },
  },
  {
    id: 'plain',
    name: 'Plain',
    expected_issuer: ISSUER,
    jwks_source: { type: 'remote', jwks_uri: JWKS },
  },
  {
    id: 'moved',
    name: 'Moved',
    expected_issuer: 'https://new-idp.example.com',
    jwks_source: { type: 'remote', jwks_uri: JWKS },
    authorization_server: { issuer: ISSUER, metadata_url: 'm', jwks_uri: JWKS },
  },
];

let declarations: unknown;

function declarationsOf(entries: Array<Record<string, unknown>>) {
  return { declarations: entries, warnings: [] };
}

beforeEach(() => {
  jest.clearAllMocks();
  declarations = declarationsOf([
    { variant: null, outcome: 'strip', reason: 'audience_missing', resource: ENTRY_URL },
  ]);
  mockFetch.mockImplementation(async (url: string) => {
    if (url === '/api/v1/jwt-verification-strategies') return json(strategies);
    if (url.endsWith('/declarations')) return json(declarations);
    return json({});
  });
});

function renderPanel(
  config: Record<string, unknown>,
  opts: {
    protocol?: ConfigPanelProps['protocol'];
    path?: string;
    meta?: Partial<SurfaceMetaValue>;
  } = {}
) {
  const updateField = jest.fn();
  const updateFields = jest.fn();
  const node: CanvasNode = {
    id: 'caller-auth',
    type: 'caller-auth',
    label: '',
    configured: true,
    config,
  };
  const props: ConfigPanelProps = {
    node,
    config,
    updateField,
    updateFields,
    protocol: opts.protocol ?? 'a2a',
    allNodes: [AP, node],
  };
  const view = render(
    <MemoryRouter initialEntries={[opts.path ?? '/surfaces/s1']}>
      <SurfaceMetaProvider value={(opts.meta ?? {}) as SurfaceMetaValue}>
        <Routes>
          <Route path="/surfaces/new" element={<CallerAuthFullscreen {...props} />} />
          <Route path="/surfaces/:surfaceId" element={<CallerAuthFullscreen {...props} />} />
        </Routes>
      </SurfaceMetaProvider>
    </MemoryRouter>
  );
  return { updateField, updateFields, view };
}

function renderStatefulPanel(initial: Record<string, unknown>) {
  const Stateful: React.FC = () => {
    const [config, setConfig] = React.useState<Record<string, unknown>>(initial);
    const node: CanvasNode = {
      id: 'caller-auth',
      type: 'caller-auth',
      label: '',
      configured: true,
      config,
    };
    const props: ConfigPanelProps = {
      node,
      config,
      updateField: (key: string, value: unknown) => setConfig(c => ({ ...c, [key]: value })),
      updateFields: (fields: Record<string, unknown>) => setConfig(c => ({ ...c, ...fields })),
      protocol: 'a2a',
      allNodes: [AP, node],
    };
    return <CallerAuthFullscreen {...props} />;
  };
  return render(
    <MemoryRouter initialEntries={['/surfaces/s1']}>
      <SurfaceMetaProvider value={{} as SurfaceMetaValue}>
        <Routes>
          <Route path="/surfaces/:surfaceId" element={<Stateful />} />
        </Routes>
      </SurfaceMetaProvider>
    </MemoryRouter>
  );
}

const JWT = {
  method_type: 'jwt_bearer',
  jwt_strategy_id: 'pinned',
  audiences: [] as string[],
  jwt_token_header: 'Authorization',
  jwt_token_scheme: 'Bearer',
  jwt_forward_header: false,
};

const strategiesLoaded = () => screen.findByRole('option', { name: 'Pinned' });

describe('Caller Context labels and failed callers', () => {
  it('labels the strategy select, the audience input and the scope input', async () => {
    renderPanel(JWT);
    await strategiesLoaded();
    expect(screen.getByLabelText(/JWT Verification Strategy/)).toHaveAttribute(
      'id',
      'caller-auth-jwt-strategy'
    );
    expect(screen.getByLabelText('Accepted Audiences')).toHaveAttribute(
      'id',
      'caller-auth-audience-input'
    );
    expect(screen.getByLabelText('Required Scopes')).toHaveAttribute(
      'id',
      'caller-auth-scope-input'
    );
  });

  it('names each audience remove button after its audience', async () => {
    const { updateField } = renderPanel({ ...JWT, audiences: ['api', ENTRY_URL] });
    await strategiesLoaded();
    fireEvent.click(screen.getByRole('button', { name: 'Remove audience api' }));
    expect(updateField).toHaveBeenCalledWith('audiences', [ENTRY_URL]);
    expect(screen.queryByRole('button', { name: 'Remove' })).not.toBeInTheDocument();
  });

  it('states the challenge before policy and no longer promises a 403 for every failure', async () => {
    renderPanel(JWT);
    await strategiesLoaded();
    const intro = screen.getByTestId('caller-auth-jwt-intro');
    expect(intro).toHaveTextContent('a missing or invalid token gets 401 with a challenge');
    expect(intro).toHaveTextContent('403 with insufficient_scope, before policy and payment run');
    expect(intro).toHaveTextContent('Otherwise a failed caller reaches policy');
    expect(screen.queryByText(/403 Forbidden/)).not.toBeInTheDocument();
  });
});

describe('Required scopes', () => {
  it('adds a scope with Enter and names each chip remove button', async () => {
    const { updateFields } = renderPanel({ ...JWT, required_scopes: ['read'] });
    await strategiesLoaded();
    expect(screen.getByRole('button', { name: 'Remove scope read' })).toBeInTheDocument();
    const input = screen.getByLabelText('Required Scopes');
    fireEvent.change(input, { target: { value: 'agent:invoke' } });
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(updateFields).toHaveBeenCalledWith({ required_scopes: ['read', 'agent:invoke'] });
  });

  it('removes a scope', async () => {
    const { updateFields } = renderPanel({ ...JWT, required_scopes: ['read', 'write'] });
    await strategiesLoaded();
    fireEvent.click(screen.getByRole('button', { name: 'Remove scope read' }));
    expect(updateFields).toHaveBeenCalledWith({ required_scopes: ['write'] });
  });

  it('moves focus to the scope input after a scope chip is removed', async () => {
    renderStatefulPanel({ ...JWT, required_scopes: ['read', 'write'] });
    await strategiesLoaded();
    const remove = screen.getByRole('button', { name: 'Remove scope read' });
    remove.focus();
    fireEvent.click(remove);
    expect(screen.queryByRole('button', { name: 'Remove scope read' })).not.toBeInTheDocument();
    expect(screen.getByLabelText('Required Scopes')).toHaveFocus();

    const last = screen.getByRole('button', { name: 'Remove scope write' });
    last.focus();
    fireEvent.click(last);
    expect(screen.queryByRole('list', { name: 'Required scopes' })).not.toBeInTheDocument();
    expect(screen.getByLabelText('Required Scopes')).toHaveFocus();
  });

  it('rejects an invalid or duplicate scope with an announced error tied to the field', async () => {
    const { updateFields } = renderPanel({ ...JWT, required_scopes: ['read'] });
    await strategiesLoaded();
    const input = screen.getByLabelText('Required Scopes');
    fireEvent.change(input, { target: { value: 'two words' } });
    fireEvent.click(screen.getByTestId('caller-auth-scope-add'));
    expect(screen.getByTestId('caller-auth-scope-error')).toHaveTextContent(/cannot contain/);
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input.getAttribute('aria-describedby')).toContain('caller-auth-scope-error');
    fireEvent.change(input, { target: { value: 'read' } });
    fireEvent.click(screen.getByTestId('caller-auth-scope-add'));
    expect(screen.getByTestId('caller-auth-scope-error')).toHaveTextContent(
      'read is already required.'
    );
    expect(updateFields).not.toHaveBeenCalled();
  });

  it('shows the scopes on AP2 and MCP, and hides them on DIDComm', async () => {
    const { view } = renderPanel(JWT, { protocol: 'ap2' });
    await strategiesLoaded();
    expect(screen.getByTestId('caller-auth-scopes')).toBeInTheDocument();
    view.unmount();

    const { view: mcpView } = renderPanel(JWT, { protocol: 'mcp' });
    await strategiesLoaded();
    expect(screen.getByTestId('caller-auth-scopes')).toBeInTheDocument();
    mcpView.unmount();

    renderPanel(JWT, { protocol: 'didcomm' });
    await strategiesLoaded();
    expect(screen.queryByTestId('caller-auth-scopes')).not.toBeInTheDocument();
    expect(screen.queryByTestId('caller-auth-discovery-derived')).not.toBeInTheDocument();
    expect(screen.queryByTestId('caller-auth-outcome')).not.toBeInTheDocument();
  });
});

describe('What the agent card declares', () => {
  it('asks for a required scope before it declares anything', async () => {
    renderPanel(JWT);
    await strategiesLoaded();
    expect(screen.getByTestId('caller-auth-discovery-derived-off')).toHaveTextContent(
      'Add a required scope'
    );
    expect(
      screen.queryByTestId('caller-auth-discovery-derived-authorization-server')
    ).not.toBeInTheDocument();
  });

  it('shows the pinned authorization server, the scopes and the Access Point URL', async () => {
    renderPanel({ ...JWT, required_scopes: ['agent:invoke'], audiences: [ENTRY_URL] });
    await strategiesLoaded();
    expect(
      await screen.findByTestId('caller-auth-discovery-derived-authorization-server')
    ).toHaveTextContent(ISSUER);
    expect(screen.getByTestId('caller-auth-discovery-derived-scopes')).toHaveTextContent(
      'agent:invoke'
    );
    await waitFor(() =>
      expect(screen.getByTestId('caller-auth-discovery-derived-audience')).toHaveTextContent(
        `${ENTRY_URL}Listed in Accepted Audiences.`
      )
    );
    expect(screen.queryByTestId('caller-auth-discovery-add-audience-button')).toBeNull();
    expect(screen.getByText('What the agent card declares')).toBeInTheDocument();
  });

  it('adds the Access Point URL the gateway reported to the audiences in one click', async () => {
    const { updateFields } = renderPanel({
      ...JWT,
      required_scopes: ['agent:invoke'],
      audiences: ['other'],
    });
    fireEvent.click(await screen.findByTestId('caller-auth-discovery-add-audience-button'));
    expect(updateFields).toHaveBeenCalledWith({ audiences: ['other', ENTRY_URL] });
    expect(screen.getByTestId('caller-auth-discovery-derived-note-audience_missing')).toBeVisible();
  });

  it('announces the added audience and moves focus to the confirmation', async () => {
    renderStatefulPanel({ ...JWT, required_scopes: ['agent:invoke'], audiences: ['other'] });
    const add = await screen.findByTestId('caller-auth-discovery-add-audience-button');
    const status = screen.getByTestId('caller-auth-discovery-audience-status');
    expect(status).toHaveAttribute('role', 'status');
    expect(status).toBeEmptyDOMElement();
    add.focus();
    fireEvent.click(add);
    await waitFor(() =>
      expect(screen.getByTestId('caller-auth-discovery-audience-status')).toHaveTextContent(
        'Listed in Accepted Audiences.'
      )
    );
    expect(screen.getByTestId('caller-auth-discovery-audience-status')).toBe(status);
    expect(screen.queryByTestId('caller-auth-discovery-add-audience-button')).toBeNull();
    expect(screen.getByTestId('caller-auth-discovery-audience-listed')).toHaveFocus();
  });

  it('does not take focus when the audience was already listed', async () => {
    renderStatefulPanel({ ...JWT, required_scopes: ['agent:invoke'], audiences: [ENTRY_URL] });
    await screen.findByTestId('caller-auth-discovery-audience-listed');
    expect(document.body).toHaveFocus();
  });

  it('uses the Access Point URL of the variant being edited', async () => {
    declarations = declarationsOf([
      { variant: null, outcome: 'declare', reason: null, resource: ENTRY_URL },
      {
        variant: 'beta',
        outcome: 'strip',
        reason: 'audience_missing',
        resource: `${ENTRY_URL}$beta`,
      },
    ]);
    const { updateFields } = renderPanel(
      { ...JWT, required_scopes: ['agent:invoke'], audiences: [ENTRY_URL] },
      { meta: { activeVariantAlias: 'beta' } }
    );
    fireEvent.click(await screen.findByTestId('caller-auth-discovery-add-audience-button'));
    expect(updateFields).toHaveBeenCalledWith({ audiences: [ENTRY_URL, `${ENTRY_URL}$beta`] });
  });

  it('links to the strategy page when the strategy is not pinned or its pin moved', async () => {
    const { view } = renderPanel({ ...JWT, jwt_strategy_id: 'plain', required_scopes: ['a'] });
    await strategiesLoaded();
    expect(
      await screen.findByTestId('caller-auth-discovery-derived-authorization-server')
    ).toHaveTextContent('The strategy has no pinned authorization server.');
    expect(screen.getByTestId('caller-auth-discovery-strategy-link')).toHaveAttribute(
      'href',
      '/jwt-verification-strategies/plain'
    );
    view.unmount();

    renderPanel({ ...JWT, jwt_strategy_id: 'moved', required_scopes: ['a'] });
    await strategiesLoaded();
    expect(
      await screen.findByTestId('caller-auth-discovery-derived-authorization-server')
    ).toHaveTextContent('no longer matches the strategy');
    expect(screen.getByTestId('caller-auth-discovery-strategy-link')).toHaveAttribute(
      'href',
      '/jwt-verification-strategies/moved'
    );
  });

  it('keeps token forwarding editable and explains that it stops the declaration', async () => {
    const { updateField } = renderPanel({
      ...JWT,
      required_scopes: ['agent:invoke'],
      audiences: [ENTRY_URL],
      jwt_forward_header: true,
    });
    await strategiesLoaded();
    expect(
      await screen.findByTestId('caller-auth-discovery-derived-note-forwards_caller_token')
    ).toHaveTextContent("Forwarding the caller's token");
    const forward = screen.getByTestId('caller-auth-jwt-forward-header-checkbox');
    expect(forward).toBeEnabled();
    fireEvent.click(forward);
    expect(updateField).toHaveBeenCalledWith('jwt_forward_header', false);
    expect(screen.getByLabelText(/Token Header/)).toBeEnabled();
    expect(screen.queryByTestId('caller-auth-discovery-switch')).not.toBeInTheDocument();
  });

  it('notes the audience rule only while the route declares', async () => {
    declarations = declarationsOf([
      { variant: null, outcome: 'declare', reason: null, resource: ENTRY_URL },
    ]);
    const { view } = renderPanel({
      ...JWT,
      required_scopes: ['agent:invoke'],
      audiences: [ENTRY_URL],
    });
    expect(await screen.findByTestId('caller-auth-audiences-declared-note')).toHaveTextContent(
      'only tokens whose audience is the Access Point URL'
    );
    view.unmount();

    declarations = declarationsOf([
      { variant: null, outcome: 'pass_through', reason: null, resource: ENTRY_URL },
    ]);
    renderPanel(JWT);
    await screen.findByText('Upstream card unchanged');
    expect(screen.queryByTestId('caller-auth-audiences-declared-note')).not.toBeInTheDocument();
  });

  it('never shows a secret or token held by the strategy', async () => {
    renderPanel({ ...JWT, required_scopes: ['agent:invoke'], audiences: [ENTRY_URL] });
    await screen.findByTestId('caller-auth-discovery-derived-authorization-server');
    await waitFor(() =>
      expect(mockFetch.mock.calls.some(([u]) => String(u).endsWith('/declarations'))).toBe(true)
    );
    expect(document.body).not.toHaveTextContent('pinned-secret-value');
    expect(document.body).not.toHaveTextContent(`${ISSUER}/token`);
    expect(screen.getByTestId('caller-auth-discovery-derived')).not.toHaveTextContent(JWKS);
  });
});

describe('Agent card outcome chip in the editor', () => {
  it('shows the saved surface outcome with the reason', async () => {
    renderPanel(JWT);
    expect(await screen.findByText('Security removed from card')).toBeInTheDocument();
    expect(screen.getByTestId('caller-auth-outcome-detail')).toHaveTextContent(
      'The Access Point URL is not in Accepted Audiences.'
    );
    expect(mockFetch.mock.calls.some(([u]) => u === '/api/v1/surfaces/s1/declarations')).toBe(true);
  });

  it('asks for a first save on a new surface without calling the gateway', async () => {
    renderPanel(JWT, { path: '/surfaces/new' });
    expect(await screen.findByTestId('caller-auth-outcome-chip')).toHaveTextContent(
      'Outcome shown after the first save'
    );
    await strategiesLoaded();
    expect(mockFetch.mock.calls.some(([u]) => String(u).endsWith('/declarations'))).toBe(false);
  });

  it('says the outcome is unavailable when the gateway cannot compute it', async () => {
    mockFetch.mockImplementation(async (url: string) =>
      url.endsWith('/declarations') ? json({}, false, 404) : json(strategies)
    );
    renderPanel({ ...JWT, required_scopes: ['agent:invoke'] });
    expect(await screen.findByText('Agent card outcome unavailable')).toBeInTheDocument();
    expect(screen.getByTestId('caller-auth-discovery-derived-audience')).toHaveTextContent(
      'The Access Point URL is not available from the gateway yet.'
    );
  });

  it('reads the declarations again when the saved surface changes', async () => {
    const { view } = renderPanel(JWT, { meta: { agentCardRevision: 1 } });
    await screen.findByText('Security removed from card');
    const reads = () =>
      mockFetch.mock.calls.filter(([u]) => String(u).endsWith('/declarations')).length;
    const before = reads();
    declarations = declarationsOf([
      { variant: null, outcome: 'declare', reason: null, resource: ENTRY_URL },
    ]);
    view.rerender(
      <MemoryRouter initialEntries={['/surfaces/s1']}>
        <SurfaceMetaProvider value={{ agentCardRevision: 2 } as SurfaceMetaValue}>
          <Routes>
            <Route
              path="/surfaces/:surfaceId"
              element={
                <CallerAuthFullscreen
                  node={{
                    id: 'caller-auth',
                    type: 'caller-auth',
                    label: '',
                    configured: true,
                    config: JWT,
                  }}
                  config={JWT}
                  updateField={jest.fn()}
                  updateFields={jest.fn()}
                  protocol="a2a"
                  allNodes={[AP]}
                />
              }
            />
          </Routes>
        </SurfaceMetaProvider>
      </MemoryRouter>
    );
    expect(await screen.findByText('Declares OAuth')).toBeInTheDocument();
    expect(reads()).toBe(before + 1);
  });
});
