import { registry } from '../index';
import type { SurfaceContext } from '../types';
import {
  callerAuthProblems,
  callerAuthSignature,
  callerAuthToWire,
  exposureWarning,
  NO_CALLER_AUTH_PROBLEM,
  OPEN_WITH_AUTH_PROBLEM,
  reachableFromOtherHosts,
  transitPointSaveError,
  warningsForTransitPoint,
} from '../transit-point/callerAuth';
import { joinWarnings, parseWarningHeader } from '../../../../utils/warningHeader';

function makeCtx(nodes: any[], surfaceId?: string): SurfaceContext {
  return {
    protocol: 'a2a',
    surfaceMeta: { name: 'tp-caller-auth', tags: [], status: 'active', surface_id: surfaceId },
    allNodes: nodes,
    nodesOfType: type => nodes.filter(n => n.type === type),
    firstNodeOfType: type => nodes.find(n => n.type === type),
  };
}

const apiKey = {
  type: 'api_key',
  extraction: { source: 'http_header', field: 'X-API-Key' },
  secret_id: 'partner-keys',
};

const jwt = {
  type: 'jwt_bearer',
  jwt_verification_strategy_id: 'idp',
  audiences: ['https://crm.example.com'],
  token_header: 'Authorization',
  token_scheme: 'Bearer',
  forward_header: false,
};

const baseNodes = [
  { id: 'ap', type: 'access-point', label: 'AP', configured: true, config: { route: '/api' } },
  {
    id: 'tg',
    type: 'target',
    label: 'T',
    configured: true,
    config: { endpoint: 'http://x.example' },
  },
];

const tpNode = (config: Record<string, unknown>) => ({
  id: 'tp-1',
  type: 'transit-point-a2a',
  label: '',
  configured: true,
  config: {
    id: 'tp-uuid',
    name: 'crm',
    target_endpoint: 'https://upstream.example.com',
    ...config,
  },
});

const pointOf = (config: Record<string, unknown>) =>
  (registry.buildPayload(makeCtx([...baseNodes, tpNode(config)])) as any).transit.points[0];

describe('the save rules the gateway enforces, applied before the save', () => {
  it('accepts a Transit Point that requires the transit token, the default', () => {
    expect(callerAuthProblems({})).toEqual([]);
  });

  it('refuses one that authenticates no caller and is not marked open', () => {
    expect(callerAuthProblems({ require_transit_token: false })).toEqual([NO_CALLER_AUTH_PROBLEM]);
  });

  it('accepts one marked open, or one with its own caller authentication', () => {
    expect(
      callerAuthProblems({ require_transit_token: false, allow_unauthenticated_callers: true })
    ).toEqual([]);
    expect(callerAuthProblems({ require_transit_token: false, source_auth: apiKey })).toEqual([]);
    expect(callerAuthProblems({ require_transit_token: false, source_auth: jwt })).toEqual([]);
  });

  it('treats a resource access token as caller authentication', () => {
    expect(
      callerAuthProblems({ require_transit_token: false, mcp_http: { authorization: { x: 1 } } })
    ).toEqual([]);
  });

  it('refuses the open marking beside the transit token or a method', () => {
    expect(callerAuthProblems({ allow_unauthenticated_callers: true })).toEqual([
      OPEN_WITH_AUTH_PROBLEM,
    ]);
    expect(
      callerAuthProblems({
        require_transit_token: false,
        source_auth: apiKey,
        allow_unauthenticated_callers: true,
      })
    ).toEqual([OPEN_WITH_AUTH_PROBLEM]);
  });

  it('refuses source_auth beside a resource access token', () => {
    const problems = callerAuthProblems({
      require_transit_token: false,
      source_auth: apiKey,
      mcp_http: { authorization: { x: 1 } },
    });
    expect(problems).toHaveLength(1);
    expect(problems[0]).toMatch(/resource access token/);
  });

  it.each([
    ['an API key with no secret', { ...apiKey, secret_id: '' }, /secret/],
    [
      'an API key read from outside an HTTP header',
      { ...apiKey, extraction: { source: 'mcp_meta', field: 'k' } },
      /header/,
    ],
    ['a JWT with no strategy', { ...jwt, jwt_verification_strategy_id: '' }, /strategy/],
    ['a JWT with no audience', { ...jwt, audiences: [' '] }, /audience/],
    ['a JWT that forwards the token', { ...jwt, forward_header: true }, /forward/],
    [
      'DID Auth',
      { type: 'did_auth', extraction: { source: 'http_header', field: 'x' } },
      /DID Auth/,
    ],
  ])('refuses %s', (_name, source_auth, reason) => {
    const problems = callerAuthProblems({ require_transit_token: false, source_auth });
    expect(problems).toHaveLength(1);
    expect(problems[0]).toMatch(reason);
  });

  it('blocks the surface save and faults the node through the element validation', () => {
    const errors = registry.getValidationErrors('transit-point-a2a', {
      target_endpoint: 'https://upstream.example.com',
      require_transit_token: false,
    });
    expect(errors.map(e => e.message)).toContain(NO_CALLER_AUTH_PROBLEM);
    expect(
      registry.getValidationErrors('transit-point-a2a', {
        target_endpoint: 'https://upstream.example.com',
      })
    ).toEqual([]);
  });
});

describe('the dashboard save round-trip', () => {
  it('keeps a stored source_auth and the transit token choice', () => {
    const point = pointOf({ require_transit_token: false, source_auth: apiKey });
    expect(point.source_auth).toEqual(apiKey);
    expect(point.require_transit_token).toBe(false);
    expect(point).not.toHaveProperty('allow_unauthenticated_callers');
  });

  it('keeps the open marking only while the Transit Point authenticates no caller', () => {
    expect(
      pointOf({ require_transit_token: false, allow_unauthenticated_callers: true })
        .allow_unauthenticated_callers
    ).toBe(true);
    expect(
      pointOf({ require_transit_token: true, allow_unauthenticated_callers: true })
    ).not.toHaveProperty('allow_unauthenticated_callers', true);
  });

  it('sends an explicit false when the operator turned the open marking off', () => {
    expect(
      pointOf({ require_transit_token: true, allow_unauthenticated_callers: false })
        .allow_unauthenticated_callers
    ).toBe(false);
  });

  it('sends a null source_auth the operator removed, which a PUT otherwise keeps', () => {
    const point = pointOf({ require_transit_token: true, source_auth: null });
    expect(point).toHaveProperty('source_auth', null);
    expect(pointOf({ require_transit_token: true })).not.toHaveProperty('source_auth');
  });

  it('hydrates what the gateway returns and writes it back unchanged', () => {
    const stored = {
      access_point: { route: '/api' },
      target: { endpoint: 'https://upstream.example.com' },
      transit_point_source_auth: true,
      transit: {
        points: [
          {
            id: 'keyed',
            alias: 'keyed',
            target_endpoint: 'https://keyed.example.com',
            protocol: 'a2a',
            require_transit_token: false,
            source_auth: jwt,
          },
          {
            id: 'open',
            alias: 'open',
            target_endpoint: 'https://open.example.com',
            protocol: 'a2a',
            require_transit_token: false,
            allow_unauthenticated_callers: true,
          },
          {
            id: 'tokened',
            alias: 'tokened',
            target_endpoint: 'https://tokened.example.com',
            protocol: 'a2a',
            require_transit_token: true,
          },
        ],
      },
    };
    const nodes = registry.nodesFromPayload(stored);
    const tps = nodes.filter(n => n.type === 'transit-point-a2a');
    expect(tps).toHaveLength(3);
    const written = (registry.buildPayload(makeCtx([...baseNodes, ...tps])) as any).transit.points;
    expect(written.map((p: any) => p.source_auth)).toEqual([jwt, undefined, undefined]);
    expect(written.map((p: any) => p.allow_unauthenticated_callers)).toEqual([
      undefined,
      true,
      undefined,
    ]);
    expect(written.map((p: any) => p.require_transit_token)).toEqual([false, false, true]);
    // The derived marker is the gateway's to set: the built payload never carries it.
    expect(registry.buildPayload(makeCtx([...baseNodes, ...tps]))).not.toHaveProperty(
      'transit_point_source_auth'
    );
    for (const tp of tps) expect(callerAuthProblems(tp.config)).toEqual([]);
  });

  it('writes the fields only through callerAuthToWire', () => {
    expect(callerAuthToWire({})).toEqual({});
    expect(callerAuthToWire({ source_auth: apiKey })).toEqual({ source_auth: apiKey });
    expect(callerAuthToWire({ source_auth: apiKey }, 'surface-1')).toEqual({ source_auth: apiKey });
  });

  it('validates API Key Provider keys against the surface being saved, not the one it was copied from', () => {
    const provider = {
      type: 'api_key_provider',
      extraction: { source: 'http_header', field: 'X-API-Key' },
      agent_id: 'original-surface',
    };
    const copied = {
      access_point: { route: '/api' },
      target: { endpoint: 'https://upstream.example.com' },
      transit: {
        points: [
          {
            alias: 'partner',
            target_endpoint: 'https://partner.example.com',
            protocol: 'a2a',
            require_transit_token: false,
            source_auth: provider,
          },
        ],
      },
    };
    const tps = registry.nodesFromPayload(copied).filter(n => n.type === 'transit-point-a2a');
    const written = (registry.buildPayload(makeCtx([...baseNodes, ...tps], 'new-surface')) as any)
      .transit.points[0];
    expect(written.source_auth).toEqual({ ...provider, agent_id: 'new-surface' });
  });
});

describe('exposure on an address other hosts reach', () => {
  it.each([
    ['https://gateway.example.com', true],
    ['https://10.1.2.3:8443', true],
    ['http://169.254.1.1', true],
    ['not a url', true],
    ['http://localhost:8080', false],
    ['http://tools.localhost', false],
    ['http://127.0.0.1:9000', false],
    ['http://127.1.2.3', false],
    ['http://0.0.0.0:8080', false],
    ['http://[::1]:8080', false],
    ['http://[::]:8080', false],
    ['http://[::ffff:127.0.0.1]:8080', false],
    ['http://[2001:db8::1]', true],
    ['', false],
  ])('%s is reachable from other hosts: %s', (url, expected) => {
    expect(reachableFromOtherHosts(url)).toBe(expected);
  });

  it('warns of an open Transit Point on such an address, in the gateway words', () => {
    expect(
      exposureWarning(
        {
          require_transit_token: false,
          allow_unauthenticated_callers: true,
          listen_address: 'https://gateway.example.com',
        },
        'crm'
      )
    ).toBe(
      "Transit Point 'crm' serves callers it does not authenticate and is reachable from other hosts: https://gateway.example.com"
    );
  });

  it('does not warn when it is on loopback, authenticates callers, or is not open', () => {
    const open = { require_transit_token: false, allow_unauthenticated_callers: true };
    expect(exposureWarning({ ...open, listen_address: 'http://localhost:8080' }, 'crm')).toBeNull();
    expect(
      exposureWarning(
        { ...open, source_auth: apiKey, listen_address: 'https://gateway.example.com' },
        'crm'
      )
    ).toBeNull();
    expect(
      exposureWarning(
        { require_transit_token: false, listen_address: 'https://gateway.example.com' },
        'crm'
      )
    ).toBeNull();
  });
});

describe('what a save answers with', () => {
  it('reads each Warning header, joined by a comma or alone', () => {
    const a =
      "Transit Point 'crm' serves callers it does not authenticate: 0.0.0.0:8080, https://g.example.com";
    const b = "Transit Point 'hr' accepts tokens from issuer 'https://idp'";
    expect(parseWarningHeader(`299 - "${a}", 299 - "${b}"`)).toEqual([a, b]);
    expect(parseWarningHeader(`299 - "${a}"`)).toEqual([a]);
    expect(parseWarningHeader(null)).toEqual([]);
    expect(parseWarningHeader('')).toEqual([]);
  });

  it('unescapes a quote and a backslash in the text', () => {
    expect(parseWarningHeader('299 - "say \\"hi\\" \\\\ ok"')).toEqual(['say "hi" \\ ok']);
  });

  it('keeps the warnings that name the Transit Point, not a longer alias', () => {
    const warnings = ["Transit Point 'crm' is open", "Transit Point 'crm-2' is open", 'Other'];
    expect(warningsForTransitPoint(warnings, 'crm')).toEqual(["Transit Point 'crm' is open"]);
    expect(warningsForTransitPoint(warnings, '')).toEqual([]);
  });

  it('matches a warning by alias and variant', () => {
    const base = "Transit Point 'crm' serves callers it does not authenticate";
    const variant = "Transit Point 'crm' in variant 'v1' serves callers it does not authenticate";
    const other = "Transit Point 'crm' in variant 'v10' serves callers it does not authenticate";
    const all = [base, variant, other];
    expect(warningsForTransitPoint(all, 'crm')).toEqual([base]);
    expect(warningsForTransitPoint(all, 'crm', 'v1')).toEqual([variant]);
    expect(warningsForTransitPoint(all, 'crm', 'v2')).toEqual([]);
  });

  it("lands a variant's JWT warning on that variant's Transit Point only", () => {
    const base =
      "Transit Point 'crm' accepts the Access Point's own tokens (JWT verification strategy 'idp', audience 'a')";
    const variant =
      "Transit Point 'crm' in variant 'beta' accepts the Access Point's own tokens (JWT verification strategy 'idp', audience 'a')";
    expect(warningsForTransitPoint([base, variant], 'crm')).toEqual([base]);
    expect(warningsForTransitPoint([base, variant], 'crm', 'beta')).toEqual([variant]);
  });

  it('refuses an mTLS method that trusts no certificate, and a blank token header', () => {
    const mtls = (trust: unknown) => ({
      id: 'x',
      require_transit_token: false,
      source_auth: { type: 'mtls', trust },
    });
    expect(callerAuthProblems(mtls({ type: 'pinned', certificate_ids: [] }))[0]).toMatch(
      /trusts no certificate/
    );
    expect(callerAuthProblems(mtls({ type: 'ca', ca_certificate_ids: [] }))[0]).toMatch(
      /trusts no certificate/
    );
    expect(callerAuthProblems(mtls({ type: 'ca', ca_certificate_ids: ['c'] }))).toEqual([]);
    const jwt = (extra: object) => ({
      id: 'x',
      require_transit_token: false,
      source_auth: {
        type: 'jwt_bearer',
        jwt_verification_strategy_id: 's',
        audiences: ['a'],
        token_header: 'Authorization',
        token_scheme: 'Bearer',
        forward_header: false,
        ...extra,
      },
    });
    expect(callerAuthProblems(jwt({}))).toEqual([]);
    expect(callerAuthProblems(jwt({ token_header: '  ' }))[0]).toMatch(/header/);
    expect(callerAuthProblems(jwt({ token_scheme: '' }))).toEqual([]);
  });

  it('keeps a source_auth without a readable type as set', () => {
    const config = { id: 'x', require_transit_token: false, source_auth: { foo: 1 } };
    expect(callerAuthProblems(config)).toEqual([]);
    expect(callerAuthToWire(config)).toEqual({ source_auth: { foo: 1 } });
  });

  it('joins warnings into one message, with a cap and a count', () => {
    expect(joinWarnings(['a', 'b'])).toBe('a\nb');
    expect(joinWarnings(['a', 'b', 'c', 'd', 'e'])).toBe('a\nb\nc\nand 2 more');
    expect(joinWarnings(['x'.repeat(400)], 3, 10)).toBe('xxxxxxx...');
  });

  it('puts a refusal in plain words on the Transit Point and variant it names', () => {
    const baseError =
      "transit.points[1]: Transit Point 'crm' authenticates no caller: require a transit token (400)";
    const variantError = "variant 'v' transit.points[0]: Transit Point 'crm' sets x";
    expect(transitPointSaveError(baseError, 'crm')).toBe(
      "Transit Point 'crm' authenticates no caller: require a transit token"
    );
    expect(transitPointSaveError(baseError, 'crm', 'v')).toBeNull();
    expect(transitPointSaveError(variantError, 'crm', 'v')).toBe("Transit Point 'crm' sets x");
    expect(transitPointSaveError(variantError, 'crm')).toBeNull();
    expect(transitPointSaveError(variantError, 'crm', 'w')).toBeNull();
    expect(transitPointSaveError("transit.points[0]: Transit Point 'hr' x", 'crm')).toBeNull();
    expect(transitPointSaveError(null, 'crm')).toBeNull();
  });

  it('changes the signature when the caller authentication or address changes', () => {
    const before = callerAuthSignature({ listen_address: 'a', require_transit_token: true });
    expect(callerAuthSignature({ listen_address: 'a', require_transit_token: true })).toBe(before);
    expect(callerAuthSignature({ listen_address: 'b', require_transit_token: true })).not.toBe(
      before
    );
    expect(callerAuthSignature({ listen_address: 'a', require_transit_token: false })).not.toBe(
      before
    );
    expect(
      callerAuthSignature({ listen_address: 'a', require_transit_token: true, source_auth: apiKey })
    ).not.toBe(before);
  });
});
