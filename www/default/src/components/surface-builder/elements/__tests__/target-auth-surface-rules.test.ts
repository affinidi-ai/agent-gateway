import { validateSurfacePayload } from '../validateSurface';
import { breachMessages, staticSecret } from '../testing/targetAuthFixtures';

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
    expect(breachMessages(surface(), null)).toEqual([]);
  });

  it('counts a forwarded JWT on every caller method, as the gateway does', () => {
    const forwarding = { type: 'jwt_bearer', forward_header: true };
    const withMethods = (methods: unknown[]) =>
      surface({
        access_point: { caller_authentication: { methods } },
        target: {
          endpoint: 'https://agent.example.com',
          auth: staticSecret('Authorization', 'Bearer {value}'),
        },
      });
    expect(breachMessages(withMethods([forwarding]), null)).toHaveLength(1);
    expect(breachMessages(withMethods([{ type: 'api_key' }, forwarding]), null)).toHaveLength(1);
    expect(breachMessages(withMethods([{ type: 'api_key' }]), null)).toEqual([]);
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
    expect(breachMessages(mapped('X-Tenant'), null)).toEqual([
      'target.auth.header_name X-Tenant is already sent by header metadata mapping',
    ]);
    expect(breachMessages(mapped('X-Other'), null)).toEqual([]);
  });

  it('reports a Target credential on a surface whose Access Point checks no caller, and passes its twin', () => {
    const open = surface({ access_point: {} });
    expect(breachMessages(open, null)).toEqual([
      'target.auth: Target authentication sends a credential, so it needs source authentication on the Access Point',
    ]);
    const resource = surface({ access_point: {}, mcp_http: { authorization: { resource: 'r' } } });
    expect(breachMessages(resource, null)).toEqual([]);
  });

  it('blocks a header another credential on the leg already sends, and passes its twin', () => {
    const clash = surface({
      outbound_credentials: [
        { inject_as: { type: 'custom_header', name: 'x-api-key', format: '{value}' } },
      ],
    });
    expect(breachMessages(clash, null)).toEqual([
      'target.auth.header_name X-Api-Key is already sent by a credential binding',
    ]);
    const bearer = surface({
      target: {
        endpoint: 'https://agent.example.com',
        auth: staticSecret('Authorization', 'Bearer {value}'),
      },
      outbound_credentials: [{ inject_as: { type: 'bearer_header' } }],
    });
    expect(breachMessages(bearer, null)).toEqual([
      'target.auth.header_name Authorization is already sent by a credential binding',
    ]);
    const other = surface({ outbound_credentials: [{ inject_as: { type: 'bearer_header' } }] });
    expect(breachMessages(other, null)).toEqual([]);
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
    expect(breachMessages(point('https://p.example.com'), null)).toEqual([
      "transit.points['partner'].target_auth.header_name Authorization is already sent by a credential binding",
    ]);
    expect(breachMessages(point('fabric://g/s'), null)).toEqual([]);
    expect(
      breachMessages(
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
    expect(breachMessages(open, open)).toEqual([]);
    const changed = surface({
      access_point: {},
      target: { endpoint: 'https://agent.example.com', auth: staticSecret('X-Other', '{value}') },
    });
    expect(breachMessages(changed, open)).toHaveLength(1);
    const moved = surface({
      access_point: {},
      target: { endpoint: 'https://moved.example.com', auth: open.target.auth },
    });
    expect(breachMessages(moved, open)).toHaveLength(1);
  });

  it('reports a header clash as a blocking issue only when the stored surface is given', () => {
    const open = surface({
      outbound_credentials: [
        { inject_as: { type: 'custom_header', name: 'x-api-key', format: '{value}' } },
      ],
    });
    expect(validateSurfacePayload(open).filter(i => i.severity === 'error')).toEqual([]);
    expect(
      validateSurfacePayload(open, { stored: null }).filter(i => i.severity === 'error')
    ).toHaveLength(1);
    expect(
      validateSurfacePayload(open, { stored: open }).filter(i => i.severity === 'error')
    ).toEqual([]);
  });
});

describe('Target authentication whole-surface problems in the Surface Builder', () => {
  const base = (over: Record<string, unknown> = {}): any => ({
    name: 's',
    protocol: 'mcp',
    access_point: { caller_authentication: { methods: [{ type: 'api_key' }] } },
    target: { endpoint: 'https://agent.example.com', auth: staticSecret('X-Api-Key', '{value}') },
    ...over,
  });
  const issuesFor = (surface: any) =>
    validateSurfacePayload(surface, { stored: null }).filter(i => i.path === 'target.auth');

  it('warns, without blocking Save, about a Target credential when the Access Point checks no caller', () => {
    const issues = issuesFor(base({ access_point: {} }));
    expect(issues).toEqual([expect.objectContaining({ severity: 'warning', nodeId: 'target' })]);
    expect(issuesFor(base())).toEqual([]);
  });

  it('blocks Save when a credential binding already sends the Target credential header', () => {
    const issues = issuesFor(
      base({
        outbound_credentials: [
          { inject_as: { type: 'custom_header', name: 'X-Api-Key', format: '{value}' } },
        ],
      })
    );
    expect(issues).toEqual([expect.objectContaining({ severity: 'error', nodeId: 'target' })]);
  });

  it('reports a Transit Point problem on that Transit Point, not on the Managed Agent', () => {
    const issues = issuesFor(
      base({
        target: { endpoint: 'https://agent.example.com' },
        outbound_credentials: [{ inject_as: { type: 'bearer_header' } }],
        transit: {
          points: [
            {
              id: 'tp',
              alias: 'partner',
              protocol: 'mcp',
              target_endpoint: 'https://p.example.com',
              require_transit_token: true,
              target_auth: staticSecret('Authorization', 'Bearer {value}'),
            },
          ],
        },
      })
    );
    expect(issues).toEqual([
      expect.objectContaining({ severity: 'error', nodeId: 'transit-point-1' }),
    ]);
  });
});

describe('header clash as the gateway compares names', () => {
  const clash = (targetHeader: string, bindingHeader: string) =>
    breachMessages(
      {
        name: 's',
        protocol: 'mcp',
        access_point: { caller_authentication: { methods: [{ type: 'api_key' }] } },
        outbound_credentials: [{ inject_as: { type: 'custom_header', name: bindingHeader } }],
        target: {
          endpoint: 'https://agent.example.com',
          auth: staticSecret(targetHeader, '{value}'),
        },
      },
      null
    );

  it('treats an underscore as a hyphen and ignores letter case', () => {
    expect(clash('X_Github_Token', 'x-github-token')).toEqual([
      'target.auth.header_name X_Github_Token is already sent by a credential binding',
    ]);
  });

  it('passes two different headers', () => {
    expect(clash('X-Api-Key', 'x-github-token')).toEqual([]);
  });

  it('keeps a stored clash whose keys come in another order', () => {
    const stored = {
      name: 's',
      protocol: 'mcp',
      access_point: { caller_authentication: { methods: [{ type: 'api_key' }] } },
      outbound_credentials: [{ inject_as: { type: 'custom_header', name: 'X-Token' } }],
      target: { endpoint: 'https://agent.example.com', auth: staticSecret('X-Token', '{value}') },
    };
    const reordered = {
      ...stored,
      target: {
        endpoint: 'https://agent.example.com',
        auth: {
          fallback: 'reject',
          method: {
            static_secret: { header_format: '{value}', header_name: 'X-Token', secret_id: 's' },
          },
        },
      },
    };
    expect(breachMessages(reordered, stored)).toEqual([]);
  });
});
