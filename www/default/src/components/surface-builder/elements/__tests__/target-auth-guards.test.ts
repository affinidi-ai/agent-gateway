import { registry } from '../index';
import { buildCanvasBlob } from '../registry';
import type { SurfaceContext } from '../types';
import { managedAgentDefinition } from '../managed-agent/definition';
import {
  headerFormatProblem,
  headerNameProblem,
  RESERVED_HEADERS,
  isHttpsTarget,
  mergeTargetAuth,
  TARGET_AUTH_HTTPS_PROBLEM,
  TP_CALLER_CHECK_PROBLEM,
} from '../_shared/providerTargetAuth';
import { managedAgentTargetAuthProblems } from '../managed-agent/targetAuth';
import { staticSecretAuthType, transitPointTargetAuthProblems } from '../transit-point/targetAuth';
import { targetAuthBreaches } from '../targetAuthRules';
import { validateSurfacePayload } from '../validateSurface';

function makeCtx(nodes: any[]): SurfaceContext {
  return {
    protocol: 'a2a',
    surfaceMeta: { name: 'guards', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: type => nodes.filter(n => n.type === type),
    firstNodeOfType: type => nodes.find(n => n.type === type),
  };
}

const staticSecret = (headerName: string, headerFormat: string) => ({
  method: {
    static_secret: { secret_id: 's', header_name: headerName, header_format: headerFormat },
  },
  fallback: 'reject',
});

const providerAuth = {
  method: {
    credential_provider: {
      provider_id: 'prov-1',
      header_name: 'Authorization',
      header_format: 'Bearer {value}',
      scopes: ['read', 'write'],
    },
  },
  auth_type: 'bearer',
  target_identifier: null,
  fallback: 'passthrough',
  future_field: { keep: true },
};

const maConfig = (over: Record<string, unknown> = {}) => ({
  endpoint: 'https://agent.example.com',
  target_auth_enabled: true,
  target_auth_source: 'secret',
  target_auth_secret_id: 's',
  target_auth_type: 'custom',
  target_auth_header_name: 'X-Api-Key',
  target_auth_header_format: '{value}',
  ...over,
});

describe('header and endpoint rules', () => {
  it.each([
    ['Authorization', null],
    ['X-Api-Key', null],
    ['X Api', 'Header name must be an HTTP header name'],
    ['', 'Header name must be an HTTP header name'],
    ['host', 'Header name must not be the reserved header Host'],
    ['TE', 'Header name must not be the reserved header TE'],
    ['Proxy-Connection', 'Header name must not be the reserved header Proxy-Connection'],
  ])('header name %p', (name, problem) => {
    expect(headerNameProblem(name)).toBe(problem);
  });

  it.each([
    ['{value}', null],
    ['Bearer {value}', null],
    ['Bearer', 'Header format must contain {value} exactly once'],
    ['{value}{value}', 'Header format must contain {value} exactly once'],
    ['Bearer {value}\r', 'Header format must not contain CR, LF or NUL'],
    ['{value}\nX: 1', 'Header format must not contain CR, LF or NUL'],
    ['{value}\0', 'Header format must not contain CR, LF or NUL'],
  ])('header format %p', (format, problem) => {
    expect(headerFormatProblem(format)).toBe(problem);
  });

  it('counts only an https URL with a host as https', () => {
    expect(isHttpsTarget('https://api.example.com/v1')).toBe(true);
    for (const endpoint of ['http://a.example', 'fabric://g/s', 'a2a-proxy://p', 'proxy://m', '']) {
      expect(isHttpsTarget(endpoint)).toBe(false);
    }
  });
});

describe('reserved header names', () => {
  it('lists the 23 names the gateway reserves', () => {
    expect(RESERVED_HEADERS).toHaveLength(23);
    expect(RESERVED_HEADERS).toEqual(
      expect.arrayContaining([
        'Proxy-Authorization',
        'X-Transit-Token',
        'Mcp-Session-Id',
        'Trailers',
      ])
    );
  });

  it.each(RESERVED_HEADERS)('refuses %s in any case and passes a prefixed twin', name => {
    expect(headerNameProblem(name)).toBe(`Header name must not be the reserved header ${name}`);
    expect(headerNameProblem(name.toLowerCase())).toBe(
      `Header name must not be the reserved header ${name}`
    );
    expect(headerNameProblem(`X-Partner-${name}`)).toBeNull();
  });
});

describe('Transit Point auth type of a stored static secret', () => {
  it('reads a Bearer format as bearer only under the Authorization header', () => {
    expect(staticSecretAuthType('Authorization', 'Bearer {value}')).toBe('bearer');
    expect(staticSecretAuthType('authorization', 'Bearer {value}')).toBe('custom_header');
    expect(staticSecretAuthType('X-Partner', 'Bearer {value}')).toBe('custom_header');
  });

  it('keeps the api key and custom header readings', () => {
    expect(staticSecretAuthType('X-API-Key', '{value}')).toBe('api_key');
    expect(staticSecretAuthType('X-Auth', 'Token {value}')).toBe('custom_header');
  });
});

describe('Managed Agent Target authentication validation', () => {
  it('passes a valid setting', () => {
    expect(managedAgentTargetAuthProblems(maConfig())).toEqual({ errors: {}, warnings: [] });
  });

  it('blocks a header name that is not a token or is reserved, and passes its twin', () => {
    expect(
      managedAgentTargetAuthProblems(maConfig({ target_auth_header_name: 'Host' })).errors
    ).toEqual({ target_auth_header_name: 'Header name must not be the reserved header Host' });
    expect(
      managedAgentTargetAuthProblems(maConfig({ target_auth_header_name: 'X Key' })).errors
    ).toEqual({ target_auth_header_name: 'Header name must be an HTTP header name' });
    expect(
      managedAgentTargetAuthProblems(maConfig({ target_auth_header_name: 'X-Host' })).errors
    ).toEqual({});
  });

  it('blocks a format without exactly one {value} or with CR, LF or NUL, and passes its twin', () => {
    expect(
      managedAgentTargetAuthProblems(maConfig({ target_auth_header_format: 'Bearer' })).errors
    ).toEqual({ target_auth_header_format: 'Header format must contain {value} exactly once' });
    expect(
      managedAgentTargetAuthProblems(maConfig({ target_auth_header_format: '{value}\r\nX: 1' }))
        .errors
    ).toEqual({ target_auth_header_format: 'Header format must not contain CR, LF or NUL' });
    expect(
      managedAgentTargetAuthProblems(maConfig({ target_auth_header_format: 'Token {value}' }))
        .errors
    ).toEqual({});
  });

  it('blocks a credential on a Target that is not https, and passes its twin', () => {
    for (const endpoint of ['http://agent.example.com', 'fabric://g/s', 'a2a-proxy://p']) {
      expect(managedAgentTargetAuthProblems(maConfig({ endpoint })).errors).toEqual({
        target_auth_https: TARGET_AUTH_HTTPS_PROBLEM,
      });
    }
    expect(
      managedAgentTargetAuthProblems(maConfig({ endpoint: 'https://agent.example.com' })).errors
    ).toEqual({});
  });

  it('blocks a credential provider method without a provider, and passes its twin', () => {
    const provider = maConfig({ target_auth_source: 'provider', target_auth_provider_id: '' });
    expect(Object.keys(managedAgentTargetAuthProblems(provider).errors)).toEqual([
      'target_auth_provider_id',
    ]);
    expect(
      managedAgentTargetAuthProblems({ ...provider, target_auth_provider_id: 'prov-1' }).errors
    ).toEqual({});
  });

  it('blocks Save through the element validation', () => {
    const errors = registry.getValidationErrors('target', maConfig({ endpoint: 'http://a.test' }));
    expect(errors).toContainEqual({
      field: 'target_auth_https',
      message: TARGET_AUTH_HTTPS_PROBLEM,
    });
  });

  it('only warns about a stored setting that was not edited', () => {
    const stored = { endpoint: 'http://agent.example.com', auth: staticSecret('Host', 'Bearer') };
    const config: any = managedAgentDefinition.configFromPayload!(
      { endpoint: stored.endpoint, auth: stored.auth },
      {}
    );
    const problems = managedAgentTargetAuthProblems(config);
    expect(problems.errors).toEqual({});
    expect(problems.warnings).toHaveLength(3);
    expect(registry.getValidationErrors('target', config)).toEqual([]);

    const edited = managedAgentTargetAuthProblems({
      ...config,
      target_auth_header_name: 'Bad Name',
    });
    expect(edited.errors.target_auth_header_name).toBe('Header name must be an HTTP header name');
    const moved = managedAgentTargetAuthProblems({
      ...config,
      endpoint: 'http://other.example.com',
    });
    expect(moved.errors.target_auth_https).toBe(TARGET_AUTH_HTTPS_PROBLEM);
  });
});

describe('Transit Point Target authentication validation', () => {
  const tp = (over: Record<string, unknown> = {}) => ({
    target_endpoint: 'https://partner.example.com',
    auth_type: 'custom_header',
    auth_secret: 's',
    auth_header_name: 'X-Auth',
    auth_header_format: '{value}',
    ...over,
  });

  it('passes a valid setting', () => {
    expect(transitPointTargetAuthProblems(tp())).toEqual({ errors: {}, warnings: [] });
  });

  it('blocks a bad header name, a bad format and a non-https Target, each with a passing twin', () => {
    expect(transitPointTargetAuthProblems(tp({ auth_header_name: 'Upgrade' })).errors).toEqual({
      auth_header_name: 'Header name must not be the reserved header Upgrade',
    });
    expect(transitPointTargetAuthProblems(tp({ auth_header_format: 'x' })).errors).toEqual({
      auth_header_format: 'Header format must contain {value} exactly once',
    });
    expect(transitPointTargetAuthProblems(tp({ target_endpoint: 'fabric://g/s' })).errors).toEqual({
      auth_https: TARGET_AUTH_HTTPS_PROBLEM,
    });
  });

  it('blocks a Target credential on a Transit Point that checks no caller, and passes its twin', () => {
    expect(
      transitPointTargetAuthProblems(
        tp({ require_transit_token: false, allow_unauthenticated_callers: true })
      ).errors
    ).toEqual({ auth_callers: TP_CALLER_CHECK_PROBLEM });
    expect(
      transitPointTargetAuthProblems(
        tp({ require_transit_token: false, source_auth: { type: 'api_key' } })
      ).errors
    ).toEqual({});
  });

  it('blocks Save through the element validation', () => {
    expect(
      registry.getValidationErrors('transit-point-a2a', tp({ auth_header_name: 'Host' }))
    ).toContainEqual({
      field: 'auth_header_name',
      message: 'Header name must not be the reserved header Host',
    });
  });

  it('only warns about a stored setting that was not edited', () => {
    const stored = {
      endpoint: 'http://partner.example.com',
      auth: staticSecret('Host', '{value}'),
    };
    const config = {
      target_endpoint: stored.endpoint,
      _stored_target_auth: stored,
      target_auth: stored.auth,
    };
    expect(transitPointTargetAuthProblems(config)).toEqual({
      errors: {},
      warnings: ['Header name must not be the reserved header Host', TARGET_AUTH_HTTPS_PROBLEM],
    });
  });
});

describe('Target authentication rules that need the whole surface', () => {
  const surface = (over: Record<string, unknown> = {}): any => ({
    name: 's',
    protocol: 'mcp',
    access_point: {
      caller_authentication: { methods: [{ type: 'api_key' }] },
    },
    target: { endpoint: 'https://agent.example.com', auth: staticSecret('X-Api-Key', '{value}') },
    ...over,
  });

  it('passes a valid surface', () => {
    expect(targetAuthBreaches(surface(), null)).toEqual([]);
  });

  it('counts a forwarded JWT only on the first caller method, as the gateway does', () => {
    const forwarding = { type: 'jwt_bearer', forward_header: true };
    const withMethods = (methods: unknown[]) =>
      surface({
        access_point: { caller_authentication: { methods } },
        target: {
          endpoint: 'https://agent.example.com',
          auth: staticSecret('Authorization', 'Bearer {value}'),
        },
      });
    expect(targetAuthBreaches(withMethods([forwarding]), null)).toHaveLength(1);
    expect(targetAuthBreaches(withMethods([{ type: 'api_key' }, forwarding]), null)).toEqual([]);
  });

  it('blocks a header the Access Point maps from metadata, and passes a different one', () => {
    const mapped = (name: string) =>
      surface({
        protocol: undefined,
        access_point: {
          protocol: 'a2a',
          caller_authentication: { methods: [{ type: 'api_key' }] },
          header_metadata_mapping: { headers: [{ header: 'x-tenant' }] },
        },
        target: { endpoint: 'https://agent.example.com', auth: staticSecret(name, '{value}') },
      });
    expect(targetAuthBreaches(mapped('X-Tenant'), null)).toEqual([
      'target.auth.header_name X-Tenant is already sent by header metadata mapping',
    ]);
    expect(targetAuthBreaches(mapped('X-Other'), null)).toEqual([]);
  });

  it('blocks a Target credential when the Access Point checks no caller, and passes its twin', () => {
    const open = surface({ access_point: {} });
    expect(targetAuthBreaches(open, null)).toEqual([
      'target.auth: Target authentication sends a credential, so it needs source authentication on the Access Point',
    ]);
    const resource = surface({ access_point: {}, mcp_http: { authorization: { resource: 'r' } } });
    expect(targetAuthBreaches(resource, null)).toEqual([]);
  });

  it('blocks a header another credential on the leg already sends, and passes its twin', () => {
    const clash = surface({
      outbound_credentials: [
        { inject_as: { type: 'custom_header', name: 'x-api-key', format: '{value}' } },
      ],
    });
    expect(targetAuthBreaches(clash, null)).toEqual([
      'target.auth.header_name X-Api-Key is already sent by a credential binding',
    ]);
    const bearer = surface({
      target: {
        endpoint: 'https://agent.example.com',
        auth: staticSecret('Authorization', 'Bearer {value}'),
      },
      outbound_credentials: [{ inject_as: { type: 'bearer_header' } }],
    });
    expect(targetAuthBreaches(bearer, null)).toEqual([
      'target.auth.header_name Authorization is already sent by a credential binding',
    ]);
    const other = surface({ outbound_credentials: [{ inject_as: { type: 'bearer_header' } }] });
    expect(targetAuthBreaches(other, null)).toEqual([]);
  });

  it('applies the rules to a Transit Point, where a withheld fabric credential avoids the duplicate', () => {
    const point = (endpoint: string, extra: Record<string, unknown> = {}) =>
      surface({
        outbound_credentials: [{ inject_as: { type: 'bearer_header' } }],
        transit: {
          points: [
            {
              id: 'tp',
              alias: 'partner',
              protocol: 'mcp',
              target_endpoint: endpoint,
              require_transit_token: true,
              target_auth: staticSecret('Authorization', 'Bearer {value}'),
              ...extra,
            },
          ],
        },
      });
    expect(targetAuthBreaches(point('https://p.example.com'), null)).toEqual([
      "transit.points['partner'].target_auth.header_name Authorization is already sent by a credential binding",
    ]);
    expect(targetAuthBreaches(point('fabric://g/s'), null)).toEqual([]);
    expect(
      targetAuthBreaches(
        point('https://p.example.com', { require_transit_token: false, source_auth: undefined }),
        null
      )
    ).toEqual([
      "transit.points['partner'].target_auth.header_name Authorization is already sent by a credential binding",
      "transit.points['partner'].target_auth: Target authentication sends a credential, so it needs a Transit Point that authenticates its callers",
    ]);
  });

  it('keeps a breach the stored surface already had on the same leg, setting and endpoint', () => {
    const open = surface({ access_point: {} });
    expect(targetAuthBreaches(open, open)).toEqual([]);
    const changed = surface({
      access_point: {},
      target: { endpoint: 'https://agent.example.com', auth: staticSecret('X-Other', '{value}') },
    });
    expect(targetAuthBreaches(changed, open)).toHaveLength(1);
    const moved = surface({
      access_point: {},
      target: { endpoint: 'https://moved.example.com', auth: open.target.auth },
    });
    expect(targetAuthBreaches(moved, open)).toHaveLength(1);
  });

  it('reports a breach as a blocking issue only when the stored surface is given', () => {
    const open = surface({ access_point: {} });
    expect(validateSurfacePayload(open).filter(i => i.severity === 'error')).toEqual([]);
    expect(
      validateSurfacePayload(open, { stored: null }).filter(i => i.severity === 'error')
    ).toHaveLength(1);
    expect(
      validateSurfacePayload(open, { stored: open }).filter(i => i.severity === 'error')
    ).toEqual([]);
  });
});

describe('lossless Target authentication save', () => {
  const apiSurface: any = {
    name: 'lossless',
    protocol: 'a2a',
    access_point: { route: '/lossless', listen_address: '0.0.0.0:8443', protocol: 'a2a' },
    target: { endpoint: 'https://agent.example.com', auth: providerAuth },
    transit: {
      points: [
        {
          id: 'tp-1',
          alias: 'partner',
          protocol: 'a2a',
          target_endpoint: 'https://partner.example.com',
          require_transit_token: true,
          target_auth: {
            ...staticSecret('X-Partner', 'Token {value}'),
            target_identifier: 'partner',
            future_field: 1,
          },
        },
      ],
    },
  };

  const roundTrip = (surface: any, edit?: (nodes: any[]) => void) => {
    const nodes = registry.nodesFromPayload(surface);
    edit?.(nodes);
    return registry.buildPayload(makeCtx(nodes)) as any;
  };

  it('saves a loaded surface without edits with equal Target authentication', () => {
    const saved = roundTrip(apiSurface);
    expect(saved.target.auth).toEqual(apiSurface.target.auth);
    expect(saved.transit.points[0].target_auth).toEqual(apiSurface.transit.points[0].target_auth);
  });

  it('merges an edited field onto the stored one and keeps the fields the editor does not show', () => {
    const saved = roundTrip(apiSurface, nodes => {
      nodes.find(n => n.type === 'target').config.target_auth_header_name = 'X-Other';
      const point = nodes.find(n => n.type === 'transit-point-a2a').config;
      point.auth_type = 'custom_header';
      point.auth_secret = 's';
      point.auth_header_name = 'X-Changed';
      point.auth_header_format = 'Token {value}';
      point.auth_fallback = 'reject';
    });
    expect(saved.target.auth).toEqual({
      ...apiSurface.target.auth,
      method: {
        credential_provider: {
          ...apiSurface.target.auth.method.credential_provider,
          header_name: 'X-Other',
        },
      },
    });
    expect(saved.transit.points[0].target_auth.target_identifier).toBe('partner');
    expect(saved.transit.points[0].target_auth.future_field).toBe(1);
    expect(saved.transit.points[0].target_auth.method.static_secret.header_name).toBe('X-Changed');
  });

  it('writes and clears the scopes of a credential provider method', () => {
    const set = roundTrip(apiSurface, nodes => {
      nodes.find(n => n.type === 'target').config.target_auth_scopes = ' a  b ';
    });
    expect(set.target.auth.method.credential_provider.scopes).toEqual(['a', 'b']);
    const cleared = roundTrip(apiSurface, nodes => {
      nodes.find(n => n.type === 'target').config.target_auth_scopes = '';
    });
    expect(cleared.target.auth.method.credential_provider).not.toHaveProperty('scopes');
  });

  it('replaces the stored method when the kind changes and drops the auth when none is set', () => {
    expect(mergeTargetAuth(providerAuth, staticSecret('X', '{value}')).method).toEqual(
      staticSecret('X', '{value}').method
    );
    const none = roundTrip(apiSurface, nodes => {
      nodes.find(n => n.type === 'target').config.target_auth_enabled = false;
      nodes.find(n => n.type === 'transit-point-a2a').config.auth_type = 'none';
    });
    expect(none.target.auth).toBeUndefined();
    expect(none.transit.points[0].target_auth).toBeUndefined();
  });

  it('does not bring back a Target credential that the stored surface no longer has', () => {
    const first = roundTrip(apiSurface, nodes => {
      nodes.find(n => n.type === 'target').config.target_auth_header_name = 'X-Edited';
      const point = nodes.find(n => n.type === 'transit-point-a2a').config;
      point.auth_type = 'custom_header';
      point.auth_secret = 's';
      point.auth_header_name = 'X-Changed';
      point.auth_header_format = 'Token {value}';
      point.auth_fallback = 'reject';
    });
    expect(first.target.auth).toBeDefined();

    const blob = buildCanvasBlob(registry.nodesFromPayload(first).map(n => ({ ...n })));
    expect(blob.nodes.length).toBeGreaterThan(0);
    const moved = {
      ...first,
      canvas: blob,
      target: { ...first.target, endpoint: 'https://new-party.example.com', auth: undefined },
      transit: {
        points: first.transit.points.map((point: any) => ({
          ...point,
          target_endpoint: 'https://new-partner.example.com',
          target_auth: undefined,
        })),
      },
    };
    const saved = registry.buildPayload(makeCtx(registry.nodesFromPayload(moved))) as any;
    expect(saved.target.auth).toBeUndefined();
    expect(saved.transit.points[0].target_auth).toBeUndefined();
  });

  it('keeps the stored Target authentication copy out of the canvas blob', () => {
    const nodes = registry.nodesFromPayload(apiSurface);
    const hasCopy = nodes.some(n => n.config && '_stored_target_auth' in n.config);
    expect(hasCopy).toBe(true);
    const blob = buildCanvasBlob(nodes.map(n => ({ ...n })));
    for (const node of blob.nodes) {
      expect(node.config ?? {}).not.toHaveProperty('_stored_target_auth');
    }
  });
});
