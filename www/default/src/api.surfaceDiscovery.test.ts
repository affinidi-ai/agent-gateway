import { apiClient, type AgentSurface } from './api';

const fetchMock = jest.fn();

const SETTING = {
  resource: 'https://gateway.example/mcp/alpha',
  authorization_servers: ['https://idp.example/realms/agents'],
  scopes: ['tools'],
};

const SURFACE: AgentSurface = {
  surface_id: 's-1',
  name: 'discovery',
  description: '',
  status: 'active',
  tags: [],
  access_point: {
    listen_address: 'https://gateway.example',
    route: '/mcp/alpha',
    protocol: 'mcp',
    caller_authentication: {
      methods: [{ type: 'jwt_bearer', jwt_verification_strategy_id: 'idp', audiences: [] }],
      protected_resource: SETTING,
    },
  },
  target: {
    endpoint: 'https://tools.example/mcp',
    agent_identity: { type: 'from_jwt_claim', claim: 'sub' },
  },
};

const ok = (body: unknown) =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });

function sent(): { url: string; init: RequestInit; body: Record<string, unknown> } {
  const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
  return { url, init, body: init.body ? JSON.parse(String(init.body)) : {} };
}

beforeEach(() => {
  fetchMock.mockReset();
  global.fetch = fetchMock;
  sessionStorage.setItem('session_token', 'session-1');
});

afterEach(() => sessionStorage.clear());

describe('surface API and authorization server discovery', () => {
  it('sends the setting on a PUT and reads it back unchanged', async () => {
    const { target, ...rest } = SURFACE;
    const { agent_identity, ...backendTarget } = target;
    const stored = {
      ...rest,
      target: { ...backendTarget, identity_injection: { inject_vp: true, ...agent_identity } },
    };
    fetchMock.mockResolvedValue(ok(stored));

    const saved = await apiClient.updateSurface('s-1', SURFACE);

    const { init, body } = sent();
    expect(init.method).toBe('PUT');
    expect(body.access_point).toEqual(SURFACE.access_point);
    expect(saved.access_point.caller_authentication).toEqual(
      SURFACE.access_point.caller_authentication
    );
    expect(saved.target.agent_identity).toEqual(agent_identity);
  });

  it('removes the setting with a JSON Merge Patch that keeps the session', async () => {
    fetchMock.mockResolvedValue(ok(SURFACE));

    await apiClient.patchSurface('s-1', {
      access_point: { caller_authentication: { protected_resource: null } },
    });

    const { url, init, body } = sent();
    expect(url).toBe('/api/v1/surfaces/s-1');
    expect(init.method).toBe('PATCH');
    expect(init.headers).toEqual({
      'Content-Type': 'application/merge-patch+json',
      Authorization: 'Bearer session-1',
    });
    expect(body).toEqual({ access_point: { caller_authentication: { protected_resource: null } } });
  });

  it('patches one variant through its own endpoint', async () => {
    fetchMock.mockResolvedValue(ok(SURFACE));

    await apiClient.patchSurfaceVariant('s-1', 'v/1', {
      overrides: { access_point: { caller_authentication: { protected_resource: null } } },
    });

    const { url, init } = sent();
    expect(url).toBe('/api/v1/surfaces/s-1/variants/v%2F1');
    expect(init.method).toBe('PATCH');
    expect(init.headers).toMatchObject({ 'Content-Type': 'application/merge-patch+json' });
  });

  it('keeps the JSON content type and session on ordinary requests', async () => {
    fetchMock.mockResolvedValue(ok(SURFACE));

    await apiClient.getSurface('s-1');

    expect(sent().init.headers).toEqual({
      'Content-Type': 'application/json',
      Authorization: 'Bearer session-1',
    });
  });
});
