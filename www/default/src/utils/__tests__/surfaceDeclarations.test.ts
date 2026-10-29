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
        { variant: null, outcome: 'strip', reason: 'not_pinned', resource: null },
        { variant: 'v2', outcome: 'declare', resource: 'https://gw.example/a$v2' },
        { variant: null, outcome: 'maybe' },
      ],
    });
    expect(parsed.warnings).toEqual([
      { code: 'fail_open_policy', message: 'admits', path: 'access_point', variant: null },
    ]);
    expect(parsed.declarations).toEqual([
      { variant: null, outcome: 'strip', reason: 'not_pinned', resource: null },
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

  it('labels each outcome and explains a strip reason', () => {
    expect(describeDeclaration({ ...base, outcome: 'declare', reason: null }).label).toBe(
      'Declares OAuth'
    );
    expect(describeDeclaration({ ...base, outcome: 'pass_through', reason: null }).label).toBe(
      'Upstream card unchanged'
    );
    const strip = describeDeclaration({ ...base, outcome: 'strip', reason: 'audience_missing' });
    expect(strip.label).toBe('Security removed from card');
    expect(strip.detail).toBe('The Access Point URL is not in Accepted Audiences.');
  });

  it('uses the Access Point URL and Accepted Audiences terms of the Caller Context editor', () => {
    expect(STRIP_REASON_TEXT.no_access_point_url).toBe(
      'The gateway reports no https URL for this Access Point.'
    );
    expect(STRIP_REASON_TEXT.static_jwks).toMatch(/no authorization server to declare/);
    for (const text of Object.values(STRIP_REASON_TEXT)) {
      expect(text).not.toMatch(/entry point URL/i);
      expect(text).not.toMatch(/accepted audiences/);
    }
  });

  it('explains a caller token that would be forwarded to the managed agent', () => {
    const strip = describeDeclaration({
      ...base,
      outcome: 'strip',
      reason: 'forwards_caller_token',
    });
    expect(strip.detail).toBe(STRIP_REASON_TEXT.forwards_caller_token);
    expect(strip.detail).toMatch(/Forward token header to managed agent is on/);
    expect(strip.detail).toMatch(/No authorization server is declared/);
  });

  it('explains a variant of an Access Point on the root route', () => {
    expect(
      describeDeclaration({ ...base, outcome: 'strip', reason: 'root_variant' }).detail
    ).toMatch(/root route/);
  });

  it.each([
    ['not_mcp', 'Remove protected_resource.'],
    ['root_variant_resource', 'Give the surface a route.'],
    ['resource_mismatch', 'Set it to the URL shown.'],
    ['invalid_protected_resource', 'Check the authorization servers, scopes and resource.'],
    ['incompatible_caller_authentication', 'Fix the method or remove protected_resource.'],
    ['strategy_store_unavailable', 'Callers get 503 until it can; check the gateway log.'],
  ])('says what to do when the declaration cannot be served because of %s', (reason, action) => {
    const d = describeDeclaration({ ...base, outcome: 'unservable', reason }, 'mcp');
    expect(d.label).toBe('Cannot be served');
    expect(d.detail).toBe(UNSERVABLE_REASON_TEXT[reason]);
    expect(d.detail.endsWith(action)).toBe(true);
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
    expect(
      describeDeclaration({ ...base, outcome: 'unservable', reason: 'audience_missing' }).detail
    ).toBe(general);
  });

  it('falls back for a reason it does not know or a missing reason', () => {
    expect(describeDeclaration({ ...base, outcome: 'strip', reason: 'new_code' }).detail).toBe(
      'The card declares no security scheme.'
    );
    expect(describeDeclaration({ ...base, outcome: 'strip', reason: null }).detail).toBe(
      'The card declares no security scheme.'
    );
  });

  it('speaks of the agent card for A2A and AP2', () => {
    for (const protocol of ['a2a', 'ap2'] as const) {
      expect(describeDeclaration({ ...base, outcome: 'declare', reason: null }, protocol)).toEqual({
        label: 'Declares OAuth',
        detail: 'The agent card advertises this gateway’s authorization server and scopes.',
      });
    }
  });

  it('speaks of protected resource metadata for MCP', () => {
    const declare = describeDeclaration({ ...base, outcome: 'declare', reason: null }, 'mcp');
    expect(declare.detail).toMatch(/protected resource metadata/);
    expect(declare.detail).not.toMatch(/agent card/);
    expect(
      describeDeclaration({ ...base, outcome: 'pass_through', reason: null }, 'mcp').label
    ).toBe('No metadata published');
    const strip = describeDeclaration({ ...base, outcome: 'strip', reason: 'new_code' }, 'mcp');
    expect(strip.label).toBe('Not declared');
    expect(strip.detail).toBe('No protected resource metadata is published.');
    expect(
      describeDeclaration({ ...base, outcome: 'strip', reason: 'not_pinned' }, 'mcp').detail
    ).toBe(STRIP_REASON_TEXT.not_pinned);
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
