import { apiClient, type AgentSurface } from './api';

const fetchMock = jest.fn();

const SETTING = { resource: 'https://gateway.example/mcp/alpha' };

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

  it('sends a stored authorization server list back unchanged', async () => {
    const stored = {
      ...SETTING,
      authorization_servers: ['https://idp.example/realms/agents'],
      scopes: ['tools'],
    };
    const callerAuthentication = {
      methods: SURFACE.access_point.caller_authentication!.methods,
      protected_resource: stored,
    };
    const surface = {
      ...SURFACE,
      access_point: { ...SURFACE.access_point, caller_authentication: callerAuthentication },
    };
    fetchMock.mockResolvedValue(ok(surface));

    const saved = await apiClient.updateSurface('s-1', surface);

    const { body } = sent();
    expect((body.access_point as any).caller_authentication.protected_resource).toEqual(stored);
    expect(saved.access_point.caller_authentication?.protected_resource).toEqual(stored);
  });

  it('sends a null that removes the setting on the same PUT', async () => {
    fetchMock.mockResolvedValue(ok(SURFACE));

    await apiClient.updateSurface('s-1', {
      ...SURFACE,
      access_point: {
        ...SURFACE.access_point,
        caller_authentication: { methods: [], protected_resource: null },
      },
    });

    const { url, init, body } = sent();
    expect(url).toBe('/api/v1/surfaces/s-1');
    expect(init.method).toBe('PUT');
    expect((body.access_point as any).caller_authentication).toEqual({
      methods: [],
      protected_resource: null,
    });
  });

  it('keeps the setting and required scopes when a save response carries warnings and declarations', async () => {
    const methods = [
      {
        type: 'jwt_bearer',
        jwt_verification_strategy_id: 'idp',
        audiences: [],
        required_scopes: ['tools.call'],
      },
    ];
    const callerAuthentication = { methods, protected_resource: SETTING };
    const declarations = [
      { variant: null, outcome: 'declare', reason: null, resource: SETTING.resource },
    ];
    const warnings = [
      {
        code: 'fail_open_policy',
        message: 'A caller whose token fails reaches policy, and no policy denies it.',
        path: 'access_point.caller_authentication',
        variant: 'beta',
      },
    ];
    fetchMock.mockResolvedValue(
      ok({
        ...SURFACE,
        access_point: { ...SURFACE.access_point, caller_authentication: callerAuthentication },
        warnings,
        declarations,
      })
    );

    const saved = await apiClient.updateSurface('s-1', {
      ...SURFACE,
      access_point: { ...SURFACE.access_point, caller_authentication: callerAuthentication },
    });

    expect(saved.access_point.caller_authentication).toEqual(callerAuthentication);
    expect(saved.declarations).toEqual(declarations);
    expect(saved.warnings).toEqual(warnings);

    fetchMock.mockReset();
    fetchMock.mockResolvedValue(ok(SURFACE));
    await apiClient.updateSurface('s-1', saved);
    const { body } = sent();
    expect((body.access_point as any).caller_authentication).toEqual(callerAuthentication);
    expect(body).not.toHaveProperty('warnings');
    expect(body).not.toHaveProperty('declarations');
  });

  it('reads a save response without warnings or declarations from an older gateway', async () => {
    fetchMock.mockResolvedValue(ok(SURFACE));

    const saved = await apiClient.updateSurface('s-1', SURFACE);

    expect(saved.access_point.caller_authentication).toEqual(
      SURFACE.access_point.caller_authentication
    );
    expect(saved.warnings).toBeUndefined();
    expect(saved.declarations).toBeUndefined();
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
