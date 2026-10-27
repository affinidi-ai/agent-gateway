import { apiClient, type AgentSurface } from '../../../../../api';
import {
  authorizationServerProblem,
  discoveryProblems,
  discoverySaveError,
  protectedResourcePayload,
  protectedResourceRemovals,
  readProtectedResource,
  removeDroppedProtectedResources,
  resourceMissesRoute,
  resourceProblem,
  scopeProblem,
  suggestedResource,
  variantResource,
} from '../protectedResource';

jest.mock('../../../../../api', () => ({
  apiClient: { patchSurface: jest.fn(), patchSurfaceVariant: jest.fn() },
}));

const patchSurface = apiClient.patchSurface as jest.Mock;
const patchSurfaceVariant = apiClient.patchSurfaceVariant as jest.Mock;

const SETTING = {
  resource: 'https://gateway.example/mcp/alpha',
  authorization_servers: ['https://idp.example/realms/agents'],
  scopes: ['tools'],
};

const jwtConfig = (extra: Record<string, unknown> = {}) => ({
  method_type: 'jwt_bearer',
  jwt_strategy_id: 'idp',
  audiences: [],
  jwt_token_header: 'Authorization',
  jwt_token_scheme: 'Bearer',
  jwt_forward_header: false,
  protected_resource: SETTING,
  ...extra,
});

const methods = [{ type: 'jwt_bearer', jwt_verification_strategy_id: 'idp', audiences: [] }];

function surface(
  accessPointAuth: Record<string, unknown> | undefined,
  variants: Array<{ id: string; auth?: Record<string, unknown> }> = []
): Partial<AgentSurface> {
  return {
    access_point: {
      listen_address: 'https://gateway.example',
      route: '/mcp/alpha',
      protocol: 'mcp',
      ...(accessPointAuth ? { caller_authentication: { methods, ...accessPointAuth } } : {}),
    },
    variants: variants.map(v => ({
      id: v.id,
      alias: v.id,
      name: v.id,
      overrides: {
        complete: true,
        access_point: v.auth ? { caller_authentication: { methods, ...v.auth } } : {},
      },
    })),
  };
}

describe('readProtectedResource and protectedResourcePayload', () => {
  it('reads a stored setting and writes it back unchanged', () => {
    const setting = readProtectedResource(SETTING);
    expect(setting).toEqual(SETTING);
    expect(protectedResourcePayload(setting!)).toEqual(SETTING);
  });

  it('defaults missing lists and leaves empty scopes out of the payload', () => {
    const setting = readProtectedResource({ resource: 'https://gateway.example/mcp' });
    expect(setting).toEqual({
      resource: 'https://gateway.example/mcp',
      authorization_servers: [],
      scopes: [],
    });
    expect(protectedResourcePayload(setting!)).toEqual({
      resource: 'https://gateway.example/mcp',
      authorization_servers: [],
    });
  });

  it('reads nothing from null or a non-object', () => {
    expect(readProtectedResource(null)).toBeNull();
    expect(readProtectedResource(undefined)).toBeNull();
    expect(readProtectedResource('https://gateway.example')).toBeNull();
  });
});

describe('field checks', () => {
  it('accepts a canonical https resource and refuses the rest', () => {
    expect(resourceProblem('https://gateway.example/mcp/alpha')).toBeNull();
    expect(resourceProblem('')).toBe('Enter the resource URL');
    expect(resourceProblem('http://gateway.example/mcp')).toMatch(/https URL/);
    expect(resourceProblem('https://gateway.example/mcp?x=1')).toMatch(/query/);
    expect(resourceProblem('https://user:pw@gateway.example/mcp')).toMatch(/credentials/);
    expect(resourceProblem('https://Gateway.Example/mcp')).toBe(
      'Write the resource in its canonical form: https://gateway.example/mcp'
    );
  });

  it('accepts an https issuer and refuses credentials, query, fragment and other schemes', () => {
    expect(authorizationServerProblem('https://idp.example/realms/agents')).toBeNull();
    expect(authorizationServerProblem('https://idp.example')).toBeNull();
    for (const issuer of [
      'http://idp.example',
      'https://user@idp.example',
      'https://idp.example/?tenant=a',
      'https://idp.example/#x',
      'not a url',
      `https://idp.example/${'a'.repeat(2048)}`,
    ]) {
      expect(authorizationServerProblem(issuer)).not.toBeNull();
    }
  });

  it('accepts OAuth scope tokens only', () => {
    expect(scopeProblem('tools')).toBeNull();
    expect(scopeProblem('mcp:tools.read')).toBeNull();
    expect(scopeProblem('two words')).not.toBeNull();
    expect(scopeProblem('quo"te')).not.toBeNull();
    expect(scopeProblem('back\\slash')).not.toBeNull();
    expect(scopeProblem('')).not.toBeNull();
  });
});

describe('discoveryProblems', () => {
  it('has nothing to report for a valid setting, or with discovery off', () => {
    expect(discoveryProblems(jwtConfig())).toEqual([]);
    expect(discoveryProblems(jwtConfig({ protected_resource: null }))).toEqual([]);
    expect(discoveryProblems({ method_type: 'api_key', protected_resource: SETTING })).toEqual([]);
  });

  it('treats an unset token header and scheme as Authorization and Bearer', () => {
    expect(
      discoveryProblems(jwtConfig({ jwt_token_header: undefined, jwt_token_scheme: undefined }))
    ).toEqual([]);
  });

  it('flags the JWT settings the gateway refuses with discovery on', () => {
    const fields = (extra: Record<string, unknown>) =>
      discoveryProblems(jwtConfig(extra)).map(p => p.message);
    expect(fields({ audiences: ['api'] })).toEqual([
      'Authorization server discovery needs Accepted Audiences to be empty: the token audience must be the resource URL',
    ]);
    expect(fields({ jwt_forward_header: true })).toEqual([
      "Authorization server discovery cannot forward the caller's token to the managed agent",
    ]);
    expect(fields({ jwt_token_header: 'X-Token' })).toEqual([
      'Authorization server discovery needs the token in the Authorization header with the Bearer scheme',
    ]);
    expect(fields({ jwt_token_scheme: '' })).toHaveLength(1);
  });

  it('flags a missing, over-long or repeated authorization server list', () => {
    const problems = (servers: string[]) =>
      discoveryProblems(
        jwtConfig({ protected_resource: { ...SETTING, authorization_servers: servers } })
      );
    expect(problems([])).toEqual([
      {
        field: 'protected_resource.authorization_servers',
        message: 'List 1 to 8 authorization servers',
      },
    ]);
    expect(problems(Array.from({ length: 9 }, (_, i) => `https://idp${i}.example`))).toHaveLength(
      1
    );
    expect(problems(['https://idp.example', 'https://idp.example'])).toEqual([
      {
        field: 'protected_resource.authorization_servers',
        message: 'List each authorization server once',
      },
    ]);
  });

  it('flags the resource and scopes under their own fields', () => {
    expect(
      discoveryProblems(
        jwtConfig({ protected_resource: { ...SETTING, resource: '', scopes: ['a b'] } })
      ).map(p => p.field)
    ).toEqual(['protected_resource.resource', 'protected_resource.scopes']);
  });
});

describe('resource helpers', () => {
  it('suggests the https listener origin followed by the route', () => {
    expect(suggestedResource('https://gateway.example', '/mcp/alpha')).toBe(
      'https://gateway.example/mcp/alpha'
    );
    expect(suggestedResource('https://gateway.example:443/', '/mcp/alpha')).toBe(
      'https://gateway.example/mcp/alpha'
    );
    expect(suggestedResource('https://gateway.example:8443', '/mcp')).toBe(
      'https://gateway.example:8443/mcp'
    );
  });

  it('suggests nothing without an https listener or a route', () => {
    expect(suggestedResource('http://localhost:8080', '/mcp')).toBe('');
    expect(suggestedResource('0.0.0.0:8080', '/mcp')).toBe('');
    expect(suggestedResource('https://gateway.example', '')).toBe('');
    expect(suggestedResource(undefined, '/mcp')).toBe('');
  });

  it('derives a variant resource and checks the route', () => {
    expect(variantResource('https://gateway.example/mcp/alpha', 'beta')).toBe(
      'https://gateway.example/mcp/alpha$beta'
    );
    expect(resourceMissesRoute('https://gateway.example/mcp/alpha', '/mcp/alpha')).toBe(false);
    expect(resourceMissesRoute('https://gateway.example/mcp/other', '/mcp/alpha')).toBe(true);
    expect(resourceMissesRoute('https://gateway.example/mcp/other', undefined)).toBe(false);
  });

  it('picks out failed-save messages about this setting', () => {
    const rule =
      'access_point.caller_authentication.protected_resource: requires empty JWT Bearer audiences (400)';
    expect(discoverySaveError(rule, SETTING.resource)).toBe(rule);
    expect(discoverySaveError(`variant 'beta': ${rule}`, undefined)).toBe(
      `variant 'beta': ${rule}`
    );
    const owned = `MCP resource '${SETTING.resource}$beta' is already served by another endpoint (400)`;
    expect(discoverySaveError(owned, SETTING.resource)).toBe(owned);
    expect(
      discoverySaveError(
        "MCP resource 'https://other.example/x' is already served",
        SETTING.resource
      )
    ).toBeNull();
    expect(discoverySaveError('target.endpoint: invalid (400)', SETTING.resource)).toBeNull();
    expect(discoverySaveError(null, SETTING.resource)).toBeNull();
  });
});

describe('removing a stored setting', () => {
  beforeEach(() => {
    patchSurface.mockReset().mockResolvedValue({});
    patchSurfaceVariant.mockReset().mockResolvedValue({});
  });

  it('finds the base and variant settings a save leaves out of the caller authentication it sends', () => {
    const stored = surface({ protected_resource: SETTING }, [
      { id: 'v1', auth: { protected_resource: SETTING } },
      { id: 'v2', auth: { protected_resource: SETTING } },
      { id: 'v3', auth: { protected_resource: SETTING } },
    ]);
    const next = surface({}, [
      { id: 'v1', auth: {} },
      { id: 'v2', auth: { protected_resource: SETTING } },
    ]);
    expect(protectedResourceRemovals(stored, next)).toEqual({ base: true, variantIds: ['v1'] });
  });

  it('removes nothing when the save keeps the setting or sends no caller authentication', () => {
    const stored = surface({ protected_resource: SETTING }, [
      { id: 'v1', auth: { protected_resource: SETTING } },
    ]);
    expect(protectedResourceRemovals(stored, stored)).toEqual({ base: false, variantIds: [] });
    expect(protectedResourceRemovals(stored, surface(undefined, [{ id: 'v1' }]))).toEqual({
      base: false,
      variantIds: [],
    });
    expect(protectedResourceRemovals(surface({}), surface({}))).toEqual({
      base: false,
      variantIds: [],
    });
  });

  it('issues a merge PATCH for the base and one per variant before the save', async () => {
    const stored = surface({ protected_resource: SETTING }, [
      { id: 'v1', auth: { protected_resource: SETTING } },
    ]);
    await expect(
      removeDroppedProtectedResources('s-1', stored, surface({}, [{ id: 'v1', auth: {} }]))
    ).resolves.toBe(true);

    expect(patchSurface).toHaveBeenCalledTimes(1);
    expect(patchSurface).toHaveBeenCalledWith('s-1', {
      access_point: { caller_authentication: { protected_resource: null } },
    });
    expect(patchSurfaceVariant).toHaveBeenCalledTimes(1);
    expect(patchSurfaceVariant).toHaveBeenCalledWith('s-1', 'v1', {
      overrides: { access_point: { caller_authentication: { protected_resource: null } } },
    });
  });

  it('issues no request when nothing was removed', async () => {
    const stored = surface({ protected_resource: SETTING });
    await expect(removeDroppedProtectedResources('s-1', stored, stored)).resolves.toBe(false);
    expect(patchSurface).not.toHaveBeenCalled();
    expect(patchSurfaceVariant).not.toHaveBeenCalled();
  });

  it('stops before the save when a removal is refused', async () => {
    patchSurface.mockRejectedValue(new Error('Surface not found (404)'));
    const stored = surface({ protected_resource: SETTING }, [
      { id: 'v1', auth: { protected_resource: SETTING } },
    ]);
    await expect(
      removeDroppedProtectedResources('s-1', stored, surface({}, [{ id: 'v1', auth: {} }]))
    ).rejects.toThrow('Surface not found (404)');
    expect(patchSurfaceVariant).not.toHaveBeenCalled();
  });
});
