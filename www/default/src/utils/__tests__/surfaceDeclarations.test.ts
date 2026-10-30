import {
  describeDeclaration,
  fetchSurfaceDeclarations,
  parseSurfaceDeclarations,
  STRIP_REASON_TEXT,
  surfacePathAfterCreate,
  UNSERVABLE_REASON_TEXT,
} from '../surfaceDeclarations';

describe('parseSurfaceDeclarations', () => {
  it('reads warnings and declarations and drops malformed entries', () => {
    const parsed = parseSurfaceDeclarations({
      warnings: [
        { code: 'fail_open_policy', message: 'admits', path: 'access_point', variant: null },
        { code: 1, message: 'bad' },
        null,
      ],
      declarations: [
        { variant: null, outcome: 'strip', reason: 'not_declared', resource: null },
        { variant: 'v2', outcome: 'declare', resource: 'https://gw.example/a$v2' },
        { variant: null, outcome: 'maybe' },
      ],
    });
    expect(parsed.warnings).toEqual([
      { code: 'fail_open_policy', message: 'admits', path: 'access_point', variant: null },
    ]);
    expect(parsed.declarations).toEqual([
      { variant: null, outcome: 'strip', reason: 'not_declared', resource: null },
      { variant: 'v2', outcome: 'declare', reason: null, resource: 'https://gw.example/a$v2' },
    ]);
  });

  it('returns empty lists for a body without the fields', () => {
    expect(parseSurfaceDeclarations({ surface_id: 'x' })).toEqual({
      declarations: [],
      warnings: [],
    });
    expect(parseSurfaceDeclarations(null)).toEqual({ declarations: [], warnings: [] });
    expect(parseSurfaceDeclarations({ declarations: 'x', warnings: {} })).toEqual({
      declarations: [],
      warnings: [],
    });
  });
});

describe('describeDeclaration', () => {
  const base = { variant: null, resource: null };
  const CARD_KEEPS = 'The agent card keeps the managed agent’s own security.';

  it('labels each outcome and explains a strip reason', () => {
    expect(describeDeclaration({ ...base, outcome: 'declare', reason: null }).label).toBe(
      'Declares OAuth'
    );
    expect(describeDeclaration({ ...base, outcome: 'pass_through', reason: null }).label).toBe(
      'Upstream card unchanged'
    );
    const strip = describeDeclaration({ ...base, outcome: 'strip', reason: 'not_declared' });
    expect(strip.label).toBe('Not declared');
    expect(strip.detail).toBe(
      `Authorization server discovery is off for this route. ${CARD_KEEPS}`
    );
  });

  it('labels a strip Not declared on every protocol', () => {
    for (const protocol of ['mcp', 'a2a', 'ap2', undefined] as const) {
      expect(
        describeDeclaration({ ...base, outcome: 'strip', reason: 'not_declared' }, protocol).label
      ).toBe('Not declared');
    }
  });

  it('keeps only the strip reasons the gateway still produces', () => {
    expect(Object.keys(STRIP_REASON_TEXT).sort()).toEqual([
      'fabric_target',
      'not_declared',
      'transit_point',
    ]);
    expect(STRIP_REASON_TEXT.not_declared).toBe(
      'Authorization server discovery is off for this route.'
    );
  });

  it('explains a Fabric Target and a Transit Point', () => {
    expect(
      describeDeclaration({ ...base, outcome: 'strip', reason: 'fabric_target' }, 'mcp').detail
    ).toBe('The Target is a Fabric peer and this surface has no caller authentication.');
    expect(
      describeDeclaration({ ...base, outcome: 'strip', reason: 'transit_point' }, 'a2a').detail
    ).toBe(`Transit Point cards never declare authentication. ${CARD_KEEPS}`);
  });

  it('has a text for each of the nine unservable reasons and no other', () => {
    expect(Object.keys(UNSERVABLE_REASON_TEXT).sort()).toEqual([
      'incompatible_caller_authentication',
      'invalid_protected_resource',
      'issuer_not_advertisable',
      'network_unavailable',
      'resource_mismatch',
      'root_variant_resource',
      'strategy_store_unavailable',
      'strategy_unavailable',
      'unsupported_protocol',
    ]);
  });

  it.each([
    ['unsupported_protocol', 'Remove protected_resource.'],
    ['root_variant_resource', 'Give the surface a route.'],
    ['resource_mismatch', 'Set the resource to a URL the listener serves.'],
    [
      'invalid_protected_resource',
      'Check the resource URL and any stored authorization server or scopes.',
    ],
    [
      'incompatible_caller_authentication',
      'Fix the method or turn authorization server discovery off.',
    ],
    ['strategy_unavailable', 'Callers are refused until it is fixed.'],
    ['issuer_not_advertisable', 'Callers are refused until it is fixed.'],
    ['strategy_store_unavailable', 'Callers get 503 until it can; check the gateway log.'],
    ['network_unavailable', 'Callers are refused until it can; check the gateway log.'],
  ])('says what to do when the declaration cannot be served because of %s', (reason, action) => {
    const d = describeDeclaration({ ...base, outcome: 'unservable', reason }, 'mcp');
    expect(d.label).toBe('Cannot be served');
    expect(d.detail).toBe(UNSERVABLE_REASON_TEXT[reason]);
    expect(d.detail.endsWith(action)).toBe(true);
  });

  it('names the unsupported protocol and the non-https issuer in their own words', () => {
    expect(UNSERVABLE_REASON_TEXT.unsupported_protocol).toBe(
      'Authorization server discovery is set but this Access Point’s protocol cannot publish it. Remove protected_resource.'
    );
    expect(UNSERVABLE_REASON_TEXT.issuer_not_advertisable).toBe(
      'The JWT verification strategy’s issuer is not a URL protected resource metadata can name, so no authorization server can be published. Callers are refused until it is fixed.'
    );
  });

  it('keeps the general unservable text for an unknown or missing reason', () => {
    const general =
      'The discovery setting cannot be served on this route, so callers are refused until it is fixed.';
    expect(describeDeclaration({ ...base, outcome: 'unservable', reason: null }).detail).toBe(
      general
    );
    expect(describeDeclaration({ ...base, outcome: 'unservable', reason: 'new_code' }).detail).toBe(
      general
    );
    expect(describeDeclaration({ ...base, outcome: 'unservable', reason: 'not_mcp' }).detail).toBe(
      general
    );
  });

  it('falls back for a reason it does not know or a missing reason', () => {
    expect(describeDeclaration({ ...base, outcome: 'strip', reason: 'new_code' }).detail).toBe(
      CARD_KEEPS
    );
    expect(describeDeclaration({ ...base, outcome: 'strip', reason: null }).detail).toBe(
      CARD_KEEPS
    );
    expect(describeDeclaration({ ...base, outcome: 'strip', reason: 'not_pinned' }).detail).toBe(
      CARD_KEEPS
    );
  });

  it('speaks of the agent card for A2A and AP2', () => {
    for (const protocol of ['a2a', 'ap2'] as const) {
      expect(describeDeclaration({ ...base, outcome: 'declare', reason: null }, protocol)).toEqual({
        label: 'Declares OAuth',
        detail:
          'The agent card and the protected resource metadata name the authorization server of the selected strategy and the required scopes, and callers without a valid token are challenged.',
      });
      expect(
        describeDeclaration({ ...base, outcome: 'strip', reason: 'fabric_target' }, protocol).detail
      ).toMatch(/The agent card keeps the managed agent’s own security\.$/);
    }
  });

  it('speaks of protected resource metadata for MCP', () => {
    const declare = describeDeclaration({ ...base, outcome: 'declare', reason: null }, 'mcp');
    expect(declare.detail).toBe(
      'The protected resource metadata names the authorization server of the selected strategy and the required scopes, and callers without a valid token are challenged.'
    );
    expect(declare.detail).not.toMatch(/agent card/);
    expect(
      describeDeclaration({ ...base, outcome: 'pass_through', reason: null }, 'mcp').label
    ).toBe('No metadata published');
    const strip = describeDeclaration({ ...base, outcome: 'strip', reason: 'new_code' }, 'mcp');
    expect(strip.label).toBe('Not declared');
    expect(strip.detail).toBe('No protected resource metadata is published.');
    expect(
      describeDeclaration({ ...base, outcome: 'strip', reason: 'not_declared' }, 'mcp').detail
    ).toBe(STRIP_REASON_TEXT.not_declared);
  });
});

describe('fetchSurfaceDeclarations', () => {
  it('reads the declarations endpoint for the surface', async () => {
    const fetcher = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ declarations: [], warnings: [] }),
    });
    expect(await fetchSurfaceDeclarations(fetcher, 'a b')).toEqual({
      declarations: [],
      warnings: [],
    });
    expect(fetcher).toHaveBeenCalledWith('/api/v1/surfaces/a%20b/declarations');
  });

  it('returns null on a refusal or a network error', async () => {
    expect(
      await fetchSurfaceDeclarations(jest.fn().mockResolvedValue({ ok: false }), 'a')
    ).toBeNull();
    expect(
      await fetchSurfaceDeclarations(jest.fn().mockRejectedValue(new Error('x')), 'a')
    ).toBeNull();
  });

  it('returns null when a gateway without the endpoint answers with something unreadable', async () => {
    const fetcher = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => {
        throw new SyntaxError('Unexpected token <');
      },
    });
    expect(await fetchSurfaceDeclarations(fetcher, 'a')).toBeNull();
  });
});

describe('surfacePathAfterCreate', () => {
  const warning = { code: 'fail_open_policy', message: 'm', path: null, variant: null };

  it('opens Surface Detail when the create response carries warnings', () => {
    expect(surfacePathAfterCreate({ surface_id: 'a b', warnings: [warning] })).toBe(
      '/surfaces/a%20b'
    );
  });

  it('returns to the surface list without warnings', () => {
    expect(surfacePathAfterCreate({ surface_id: 's1', warnings: [] })).toBe('/surfaces');
    expect(surfacePathAfterCreate({ surface_id: 's1' })).toBe('/surfaces');
  });

  it('returns to the surface list when the response has no surface id', () => {
    expect(surfacePathAfterCreate({ warnings: [warning] })).toBe('/surfaces');
    expect(surfacePathAfterCreate({ surface_id: '', warnings: [warning] })).toBe('/surfaces');
  });
});
