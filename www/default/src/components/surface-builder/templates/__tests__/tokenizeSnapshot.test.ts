import { tokenizeSnapshot } from '../tokenizeSnapshot';

describe('tokenizeSnapshot', () => {
  it('replaces the four canonical fields with their tokens', () => {
    const { surface, applied } = tokenizeSnapshot({
      name: 'demo',
      access_point: {
        listen_address: '127.0.0.1:8443',
        route: '/agent',
        protocol: 'a2a',
      },
      target: { endpoint: 'http://backend:9000' },
    });
    expect(surface).toEqual({
      name: '$NAME',
      access_point: {
        listen_address: '$HOST',
        route: '$ROUTE',
        protocol: 'a2a',
      },
      target: { endpoint: '$TARGET_ENDPOINT' },
    });
    expect(applied).toEqual(['$HOST', '$NAME', '$ROUTE', '$TARGET_ENDPOINT']);
  });

  it('preserves every other field verbatim, including variants', () => {
    const input = {
      name: 'demo',
      description: 'keep me',
      tags: ['a', 'b'],
      access_point: {
        listen_address: '0.0.0.0:9000',
        route: '/agent',
        protocol: 'a2a',
        identity_resolution: { mode: 'mtls' },
      },
      target: { endpoint: 'http://upstream', auth: { type: 'bearer' } },
      transit: { points: [{ name: 'hop1' }] },
      canvas: { variants: [{ alias: 'v1', target: { endpoint: 'http://other' } }] },
    };
    const { surface } = tokenizeSnapshot(input);
    expect(surface.description).toBe('keep me');
    expect(surface.tags).toEqual(['a', 'b']);
    expect(surface.access_point.identity_resolution).toEqual({ mode: 'mtls' });
    expect(surface.target.auth).toEqual({ type: 'bearer' });
    expect(surface.transit).toEqual({ points: [{ name: 'hop1' }] });
    // Variants are NOT touched — variant overrides keep their concrete
    // values (caller can pre-edit if they want them tokenized).
    expect(surface.canvas.variants[0].target.endpoint).toBe('http://other');
  });

  it('does not mutate the input', () => {
    const input = {
      name: 'demo',
      access_point: { listen_address: 'h', route: '/r' },
      target: { endpoint: 'e' },
    };
    const before = JSON.parse(JSON.stringify(input));
    tokenizeSnapshot(input);
    expect(input).toEqual(before);
  });

  it('skips empty strings and missing fields without crashing', () => {
    const { surface, applied } = tokenizeSnapshot({
      name: '',
      access_point: { listen_address: '127.0.0.1:8443' /* no route */ },
      // no target
    });
    expect(surface.name).toBe('');
    expect(surface.access_point.listen_address).toBe('$HOST');
    expect(surface.access_point.route).toBeUndefined();
    expect(applied).toEqual(['$HOST']);
  });

  it('is idempotent — already-tokenized values stay as the token', () => {
    const input = {
      name: '$NAME',
      access_point: { listen_address: '$HOST', route: '/r' },
      target: { endpoint: 'http://e' },
    };
    const { surface, applied } = tokenizeSnapshot(input);
    expect(surface.name).toBe('$NAME');
    expect(surface.access_point.listen_address).toBe('$HOST');
    expect(surface.access_point.route).toBe('$ROUTE');
    expect(surface.target.endpoint).toBe('$TARGET_ENDPOINT');
    // Each token is reported exactly once.
    expect(applied).toEqual(['$HOST', '$NAME', '$ROUTE', '$TARGET_ENDPOINT']);
  });

  it('does not touch non-string values', () => {
    const { surface, applied } = tokenizeSnapshot({
      name: 42 as any,
      access_point: { listen_address: 'h', route: '/r' },
      target: { endpoint: null as any },
    });
    expect(surface.name).toBe(42);
    expect(surface.target.endpoint).toBeNull();
    expect(applied).toEqual(['$HOST', '$ROUTE']);
  });

  it('handles null / undefined input by returning an empty shell', () => {
    expect(tokenizeSnapshot(null as any).surface).toEqual({});
    expect(tokenizeSnapshot(undefined as any).surface).toEqual({});
    expect(tokenizeSnapshot(undefined as any).applied).toEqual([]);
  });

  it('strips gateway-runtime top-level fields (surface_id, last_activity, agent_did)', () => {
    const { surface } = tokenizeSnapshot({
      surface_id: 'abc-123',
      last_activity: '2026-05-24T00:00:00Z',
      agent_did: 'did:webvh:example:gw',
      name: 'demo',
      access_point: { listen_address: 'h', route: '/r' },
      target: { endpoint: 'e' },
    });
    expect(surface.surface_id).toBeUndefined();
    expect(surface.last_activity).toBeUndefined();
    expect(surface.agent_did).toBeUndefined();
    expect(surface.name).toBe('$NAME');
  });

  it('always scrubs transit-point listener / identity fields and reports the count', () => {
    const { surface, clearedTransitPoints } = tokenizeSnapshot({
      access_point: { listen_address: 'h', route: '/r' },
      transit: {
        points: [
          {
            listen_address: 'https://outbound',
            listen_path: '/payments/foo',
            id: 'tp-uuid-1',
            alias: 'tp-foo',
            target_endpoint: 'https://upstream-1',
            protocol: 'a2a',
          },
          {
            listen_address: 'https://outbound',
            listen_path: '/payments/bar',
            id: 'tp-uuid-2',
            alias: 'tp-bar',
            target_endpoint: 'https://upstream-2',
            protocol: 'a2a',
          },
          // TP with no volatile fields — should not count.
          { target_endpoint: 'https://upstream-3', protocol: 'mcp' },
        ],
      },
    });
    expect(clearedTransitPoints).toBe(2);
    const points = surface.transit.points;
    expect(points[0]).toEqual({
      target_endpoint: 'https://upstream-1',
      protocol: 'a2a',
    });
    expect(points[1]).toEqual({
      target_endpoint: 'https://upstream-2',
      protocol: 'a2a',
    });
    expect(points[2]).toEqual({
      target_endpoint: 'https://upstream-3',
      protocol: 'mcp',
    });
  });

  it('with { tokenizeNamedFields: false } still scrubs TPs but skips $HOST/$ROUTE/$NAME/$TARGET_ENDPOINT', () => {
    const { surface, applied, clearedTransitPoints } = tokenizeSnapshot(
      {
        name: 'demo',
        access_point: { listen_address: '127.0.0.1:8443', route: '/agent' },
        target: { endpoint: 'http://backend' },
        transit: {
          points: [{ listen_address: 'h', listen_path: '/p', alias: 'a', protocol: 'a2a' }],
        },
      },
      { tokenizeNamedFields: false }
    );
    expect(applied).toEqual([]);
    expect(clearedTransitPoints).toBe(1);
    expect(surface.name).toBe('demo');
    expect(surface.access_point.listen_address).toBe('127.0.0.1:8443');
    expect(surface.access_point.route).toBe('/agent');
    expect(surface.target.endpoint).toBe('http://backend');
    expect(surface.transit.points[0]).toEqual({ protocol: 'a2a' });
  });
});
