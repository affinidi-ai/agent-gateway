import type { AgentSurface } from '../../../../../api';
import {
  advertisedScopes,
  authorizationServerProblem,
  declarationForVariant,
  declaredAudience,
  declaresOn,
  derivedAuthorizationServer,
  discoveryProblems,
  discoverySaveError,
  discoverySaveErrorField,
  protectedResourcePayload,
  protectedResourceRemovals,
  readProtectedResource,
  resourceMissesRoute,
  resourceProblem,
  rootVariantProblem,
  scopeProblem,
  strategyPin,
  suggestedResource,
  variantResource,
  withDroppedProtectedResourcesRemoved,
  withoutStoredAuthorizationServers,
  withoutStoredScopes,
} from '../protectedResource';

const SETTING = { resource: 'https://gateway.example/mcp/alpha' };

const STORED_SETTING = {
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
  it('keeps absent lists absent and writes only the resource', () => {
    const setting = readProtectedResource(SETTING);
    expect(setting).toEqual({ resource: SETTING.resource });
    expect(setting).not.toHaveProperty('authorization_servers');
    expect(setting).not.toHaveProperty('scopes');
    expect(protectedResourcePayload(setting!)).toStrictEqual({ resource: SETTING.resource });
  });

  it('keeps stored authorization servers and scopes and writes them back unchanged', () => {
    const setting = readProtectedResource(STORED_SETTING);
    expect(setting).toEqual(STORED_SETTING);
    expect(protectedResourcePayload(setting!)).toEqual(STORED_SETTING);
  });

  it('keeps a stored empty list present and leaves empty scopes out of the payload', () => {
    const setting = readProtectedResource({
      resource: SETTING.resource,
      authorization_servers: [],
      scopes: [],
    });
    expect(setting).toEqual({ resource: SETTING.resource, authorization_servers: [], scopes: [] });
    expect(protectedResourcePayload(setting!)).toStrictEqual({
      resource: SETTING.resource,
      authorization_servers: [],
    });
  });

  it('drops a stored authorization server list or extra scopes on request', () => {
    expect(withoutStoredAuthorizationServers(STORED_SETTING)).toStrictEqual({
      resource: STORED_SETTING.resource,
      scopes: ['tools'],
    });
    expect(withoutStoredScopes(STORED_SETTING)).toStrictEqual({
      resource: STORED_SETTING.resource,
      authorization_servers: STORED_SETTING.authorization_servers,
    });
    expect(withoutStoredScopes(withoutStoredAuthorizationServers(STORED_SETTING))).toStrictEqual(
      SETTING
    );
    expect(STORED_SETTING.authorization_servers).toEqual(['https://idp.example/realms/agents']);
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
    expect(fields({ jwt_token_scheme: 'bearer' })).toHaveLength(1);
  });

  it('flags an empty, over-long or repeated stored authorization server list and nothing when it is absent', () => {
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
    expect(problems(['https://idp.example'])).toEqual([]);
    expect(discoveryProblems(jwtConfig({ protected_resource: SETTING }))).toEqual([]);
    expect(
      discoveryProblems(jwtConfig({ protected_resource: SETTING }), 'https://idp.example')
    ).toEqual([]);
  });

  it('flags the resource and scopes under their own fields', () => {
    expect(
      discoveryProblems(
        jwtConfig({ protected_resource: { ...SETTING, resource: '', scopes: ['a b'] } })
      ).map(p => p.field)
    ).toEqual(['protected_resource.resource', 'protected_resource.scopes']);
  });
});

describe('the strategy issuer rule', () => {
  it('flags a stored authorization server that is not the strategy issuer, with the remedy', () => {
    const issuer = 'https://idp.example/realms/agents';
    const servers = (authorization_servers: string[]) =>
      discoveryProblems(
        jwtConfig({ protected_resource: { ...SETTING, authorization_servers } }),
        issuer
      )
        .filter(p => p.field === 'protected_resource.authorization_servers')
        .map(p => p.message);
    expect(servers([issuer])).toEqual([]);
    expect(servers(['https://other.example'])).toEqual([
      `The stored authorization server https://other.example is not the issuer the JWT verification strategy trusts (${issuer}), so the save is refused. Use the strategy's issuer.`,
    ]);
    for (const listed of [
      ['https://other.example', issuer],
      [issuer, 'https://other.example'],
    ]) {
      expect(servers(listed)).toEqual([
        expect.stringContaining('is not the issuer the JWT verification strategy trusts'),
      ]);
    }
    expect(
      discoveryProblems(
        jwtConfig({
          protected_resource: { ...SETTING, authorization_servers: ['https://other.example'] },
        })
      )
    ).toEqual([]);
  });
});

describe('what the gateway advertises', () => {
  const ISSUER = 'https://idp.example/realms/agents';

  it('lists the required scopes first, then each stored extra scope once', () => {
    expect(advertisedScopes(['agent.invoke', 'read'])).toEqual(['agent.invoke', 'read']);
    expect(advertisedScopes(['agent.invoke'], ['tools', 'agent.invoke', 'tools'])).toEqual([
      'agent.invoke',
      'tools',
    ]);
    expect(advertisedScopes([], ['tools'])).toEqual(['tools']);
    expect(advertisedScopes([], [])).toEqual([]);
  });

  it('names the strategy issuer, or nothing without a strategy', () => {
    expect(derivedAuthorizationServer({ id: 'idp', expected_issuer: ISSUER })).toEqual({
      value: ISSUER,
      source: 'strategy',
    });
    expect(derivedAuthorizationServer({ id: 'idp' })).toEqual({ value: null, source: 'none' });
    expect(derivedAuthorizationServer({ id: 'idp', expected_issuer: '' })).toEqual({
      value: null,
      source: 'none',
    });
    expect(derivedAuthorizationServer(undefined)).toEqual({ value: null, source: 'none' });
  });

  it('declares the plain resource on the base and resource$alias on a variant', () => {
    expect(declaredAudience(SETTING.resource)).toBe(SETTING.resource);
    expect(declaredAudience(SETTING.resource, 'beta')).toBe(`${SETTING.resource}$beta`);
    expect(declaredAudience('', undefined)).toBe('');
  });

  it('refuses discovery on a variant of an Access Point at /', () => {
    const message =
      'A variant of an Access Point at / has no resource of its own. Move the Access Point off /, or turn authorization server discovery off for this variant.';
    expect(rootVariantProblem('/', 'beta')).toBe(message);
    expect(rootVariantProblem('', 'beta')).toBe(message);
    expect(rootVariantProblem('/a', 'beta')).toBeNull();
    expect(rootVariantProblem('/', undefined)).toBeNull();
    expect(rootVariantProblem('', undefined)).toBeNull();
    expect(rootVariantProblem('/a', undefined)).toBeNull();
    expect(rootVariantProblem(undefined, 'beta')).toBeNull();
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
    const generic = `Resource '${SETTING.resource}' is already served by another endpoint (400)`;
    expect(discoverySaveError(generic, SETTING.resource)).toBe(generic);
    const variant = `resource '${SETTING.resource}$beta' is already served (400)`;
    expect(discoverySaveError(variant, SETTING.resource)).toBe(variant);
    expect(
      discoverySaveError(
        "MCP resource 'https://other.example/x' is already served",
        SETTING.resource
      )
    ).toBeNull();
    const othersResource = "Resource 'https://other.example/x' is already served";
    expect(discoverySaveError(othersResource, SETTING.resource)).toBeNull();
    expect(discoverySaveError('target.endpoint: invalid (400)', SETTING.resource)).toBeNull();
    expect(discoverySaveError(null, SETTING.resource)).toBeNull();
  });

  it('routes a refused save to the field it names', () => {
    const prefix = 'access_point.caller_authentication.protected_resource: ';
    const resourceMismatch = `${prefix}MCP resource must match the configured public origin and endpoint path`;
    const servers = `${prefix}authorization_servers must be exactly ["https://as/"], the issuer the JWT verification strategy trusts, or be omitted: the gateway advertises that issuer`;
    const scopes = `${prefix}MCP authorization scopes must be bounded OAuth scope tokens`;
    const audiences = `${prefix}requires empty JWT Bearer audiences: tokens must name the protected resource of the route they call as their audience`;
    const header = `${prefix}requires a first caller authentication method of JWT Bearer reading the Authorization header with the Bearer scheme`;
    const rootVariant = `variant 'beta': ${prefix}a variant of an Access Point at / is not reachable at a resource of its own`;
    const owned = `MCP resource '${SETTING.resource}' is already served (400)`;
    const issuer = `${prefix}the JWT verification strategy's expected_issuer "did:web:as.example" is not an issuer URL protected resource metadata can name: an https URL, or an http one for a strategy no tenant owns`;
    const protocol = `${prefix}requires an MCP, A2A or AP2 Access Point`;

    expect(discoverySaveErrorField(resourceMismatch)).toBe('resource');
    expect(discoverySaveErrorField(servers)).toBe('authorizationServers');
    expect(discoverySaveErrorField(scopes)).toBe('scopes');
    expect(discoverySaveErrorField(audiences)).toBe('rules');
    expect(discoverySaveErrorField(header)).toBe('rules');
    expect(discoverySaveErrorField(rootVariant)).toBe('resource');
    expect(discoverySaveErrorField(owned)).toBe('resource');
    expect(discoverySaveErrorField(issuer)).toBeNull();
    expect(discoverySaveErrorField(protocol)).toBeNull();
    expect(discoverySaveErrorField('JWT verification strategy not found')).toBeNull();
  });
});

describe('removing a stored setting', () => {
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

  it('sends null for the base and each variant setting the save leaves out', () => {
    const stored = surface({ protected_resource: SETTING }, [
      { id: 'v1', auth: { protected_resource: SETTING } },
      { id: 'v2', auth: { protected_resource: SETTING } },
    ]);
    const next = surface({}, [
      { id: 'v1', auth: {} },
      { id: 'v2', auth: { protected_resource: SETTING } },
    ]);

    const payload = withDroppedProtectedResourcesRemoved(stored, next);

    expect(payload.access_point?.caller_authentication).toEqual({
      methods,
      protected_resource: null,
    });
    expect(payload.access_point?.route).toBe('/mcp/alpha');
    expect(payload.variants?.[0].overrides).toEqual({
      complete: true,
      access_point: { caller_authentication: { methods, protected_resource: null } },
    });
    expect(payload.variants?.[1]).toBe(next.variants?.[1]);
    expect(next.access_point?.caller_authentication).toEqual({ methods });
  });

  it('sends the save unchanged when nothing was removed', () => {
    const stored = surface({ protected_resource: SETTING }, [
      { id: 'v1', auth: { protected_resource: SETTING } },
    ]);
    expect(withDroppedProtectedResourcesRemoved(stored, stored)).toEqual(stored);
    const withoutCallerAuthentication = surface(undefined, [{ id: 'v1' }]);
    expect(withDroppedProtectedResourcesRemoved(stored, withoutCallerAuthentication)).toEqual(
      withoutCallerAuthentication
    );
  });
});

describe('declaring protocols and strategy pins', () => {
  const ISSUER = 'https://idp.example/realms/agents';
  const JWKS = 'https://idp.example/realms/agents/certs';
  const strategy = (extra: Record<string, unknown> = {}) => ({
    id: 'idp',
    expected_issuer: ISSUER,
    jwks_source: { type: 'remote', jwks_uri: JWKS },
    authorization_server: { issuer: ISSUER, metadata_url: 'm', jwks_uri: JWKS },
    ...extra,
  });

  it('declares on A2A, AP2 and MCP only', () => {
    expect(declaresOn('a2a')).toBe(true);
    expect(declaresOn('ap2')).toBe(true);
    expect(declaresOn('mcp')).toBe(true);
    expect(declaresOn('didcomm')).toBe(false);
    expect(declaresOn(undefined)).toBe(false);
  });

  it('names the pinned issuer while the pin matches the strategy', () => {
    expect(strategyPin(strategy())).toEqual({ state: 'pinned', issuer: ISSUER });
  });

  it('flags an unpinned, moved or static-key strategy', () => {
    expect(strategyPin(strategy({ authorization_server: undefined }))).toEqual({
      state: 'not_pinned',
    });
    expect(strategyPin(strategy({ authorization_server: { metadata_url: 'm' } }))).toEqual({
      state: 'not_pinned',
    });
    expect(strategyPin(strategy({ expected_issuer: 'https://other.example' }))).toEqual({
      state: 'mismatch',
      issuer: ISSUER,
    });
    expect(
      strategyPin(
        strategy({ jwks_source: { type: 'remote', jwks_uri: 'https://idp.example/new' } })
      )
    ).toEqual({ state: 'mismatch', issuer: ISSUER });
    expect(strategyPin(strategy({ jwks_source: { type: 'static', jwks: [] } }))).toEqual({
      state: 'static_jwks',
    });
  });

  it('picks the entry of the route edited', () => {
    const entries = [
      { variant: null, outcome: 'declare' },
      { variant: 'beta', outcome: 'strip' },
    ];
    expect(declarationForVariant(entries, undefined)).toBe(entries[0]);
    expect(declarationForVariant(entries, 'beta')).toBe(entries[1]);
    expect(declarationForVariant(entries, 'gamma')).toBeUndefined();
  });
});
