/**
 * `validateSurfacePayload` unit tests.
 */

import { validateSurfacePayload, hasBlockingIssues } from '../validateSurface';
// Side-effect import: registers every element definition so the
// validator's registry-aware checks (e.g. parent-type classification
// for the chain-leak watchdog) can resolve types.
import '../index';

describe('validateSurfacePayload', () => {
  const ok = (): Record<string, any> => ({
    name: 'My Surface',
    access_point: { caller_authentication: { methods: [{ type: 'did_auth' }] } },
    target: { endpoint: 'https://upstream/y' },
  });

  it('returns no issues for a minimally-valid surface', () => {
    const issues = validateSurfacePayload(ok());
    expect(issues).toEqual([]);
    expect(hasBlockingIssues(issues)).toBe(false);
  });

  describe('caller access', () => {
    const open = (extra: Record<string, unknown> = {}) => ({
      ...ok(),
      access_point: { route: '/a', ...extra },
    });

    it('lets a surface with no Caller Context save, leaving its warning to the gateway', () => {
      const issues = validateSurfacePayload(open());
      expect(hasBlockingIssues(issues)).toBe(false);
      expect(issues.find(i => i.path?.startsWith('access_point.'))).toBeUndefined();
    });

    it('lets a stored closed surface without caller authentication save', () => {
      for (const extra of [{}, { caller_authentication: { methods: [] } }]) {
        const issues = validateSurfacePayload(open({ public: false, ...extra }));
        expect(hasBlockingIssues(issues)).toBe(false);
        expect(issues.find(i => i.path?.startsWith('access_point.'))).toBeUndefined();
      }
    });

    it('does not warn about a stored MCP surface protected by a resource token', () => {
      const issues = validateSurfacePayload({
        ...open(),
        mcp_http: { authorization: { scopes: ['tools:call'] } },
      });
      expect(issues.find(i => i.path?.startsWith('access_point.'))).toBeUndefined();
    });

    it('raises no access issue when Public access is on, leaving its warning to the gateway', () => {
      const issues = validateSurfacePayload(open({ public: true }));
      expect(issues.find(i => i.path?.startsWith('access_point.'))).toBeUndefined();
    });
  });

  describe('a Transit Point that loses its stored Listen Path', () => {
    const point = (listen_path?: string) => ({
      id: '11111111-1111-4111-8111-111111111111',
      alias: 'partner-a',
      target_endpoint: 'https://partner.example/a',
      ...(listen_path === undefined ? {} : { listen_path }),
    });
    const surface = (listen_path?: string) => ({
      ...ok(),
      transit: { points: [point(listen_path)] },
    });

    it('warns that the derived route answers now, without blocking the save', () => {
      const issues = validateSurfacePayload(surface(), {
        stored: surface('/outbound/agents/partner-a'),
      });
      const dropped = issues.find(i => i.message.includes('no longer has a Listen Path'));
      expect(dropped).toMatchObject({ severity: 'warning' });
      expect(dropped?.message).toContain('/outbound/agents/partner-a');
      expect(hasBlockingIssues(issues)).toBe(false);
    });

    it('says nothing when the path is kept, changed, or was never set', () => {
      for (const [now, before] of [
        ['/outbound/agents/partner-a', '/outbound/agents/partner-a'],
        ['/outbound/agents/partner-b', '/outbound/agents/partner-a'],
        [undefined, undefined],
      ] as Array<[string | undefined, string | undefined]>) {
        const issues = validateSurfacePayload(surface(now), { stored: surface(before) });
        expect(issues.find(i => i.message.includes('no longer has a Listen Path'))).toBeUndefined();
      }
    });

    it('says nothing when the Transit Point itself is gone, which the canvas shows', () => {
      const issues = validateSurfacePayload(
        { ...ok(), transit: { points: [] } },
        { stored: surface('/outbound/agents/partner-a') }
      );
      expect(issues.find(i => i.message.includes('no longer has a Listen Path'))).toBeUndefined();
    });
  });

  describe('a Listen Path the gateway will not serve', () => {
    const routing = {
      available_listen_addresses: ['https://gateway.example.com'],
      available_outbound_listen_addresses: ['https://gateway.example.com'],
      shared_hostname_outbound_addresses: ['https://gateway.example.com'],
      channel_path_prefix: [{ id: 'agents', name: 'agents', prefix: '/agents' }],
    };
    const surface = (listen_path?: string) => ({
      ...ok(),
      transit: {
        points: [
          {
            id: '11111111-1111-4111-8111-111111111111',
            alias: 'partner-a',
            target_endpoint: 'https://partner.example/a',
            listen_address: 'https://gateway.example.com',
            ...(listen_path === undefined ? {} : { listen_path }),
          },
        ],
      },
    });
    const refused = '/agents/partner-a';

    it('blocks a save that introduces or changes it', () => {
      for (const stored of [surface(), surface('/outbound/agents/partner-a'), undefined]) {
        const issues = validateSurfacePayload(surface(refused), { stored, routing });
        expect(hasBlockingIssues(issues)).toBe(true);
        expect(issues.find(i => i.path?.endsWith('listen_path'))?.message).toContain(
          'outside /outbound'
        );
      }
    });

    it('leaves a surface already stored with it editable, as the gateway does', () => {
      const issues = validateSurfacePayload(surface(refused), {
        stored: surface(refused),
        routing,
      });
      expect(issues.find(i => i.path?.endsWith('listen_path'))).toBeUndefined();
      expect(hasBlockingIssues(issues)).toBe(false);
    });

    it('judges nothing while the routing config has not loaded', () => {
      const issues = validateSurfacePayload(surface(refused), { stored: surface(), routing: null });
      expect(issues.find(i => i.path?.endsWith('listen_path'))).toBeUndefined();
    });

    // What the page passes for a variant view: the stored surface resolved through that
    // variant's overrides, not the base surface and not nothing. Against either of those
    // an untouched legacy path reads as newly introduced and blocks an unrelated save.
    it('exempts a legacy path a variant view already holds', () => {
      const base = surface('/outbound/agents/partner-a');
      const variantView = surface(refused);
      expect(
        validateSurfacePayload(variantView, { stored: variantView, routing }).find(i =>
          i.path?.endsWith('listen_path')
        )
      ).toBeUndefined();
      // The two readings the page used to pass for that same view.
      for (const stored of [base, null]) {
        expect(
          validateSurfacePayload(variantView, { stored, routing }).find(i =>
            i.path?.endsWith('listen_path')
          )
        ).toMatchObject({ severity: 'error' });
      }
    });
  });

  it('flags missing surface name as an error', () => {
    const issues = validateSurfacePayload({ ...ok(), name: '' });
    expect(issues.find(i => i.path === 'name')).toMatchObject({ severity: 'error' });
    expect(hasBlockingIssues(issues)).toBe(true);
  });

  it('flags whitespace-only surface name as an error', () => {
    const issues = validateSurfacePayload({ ...ok(), name: '   ' });
    expect(issues.find(i => i.path === 'name')).toMatchObject({ severity: 'error' });
  });

  it('warns on empty target endpoint without blocking', () => {
    const issues = validateSurfacePayload({ ...ok(), target: { endpoint: '' } });
    const ep = issues.find(i => i.path === 'target.endpoint');
    expect(ep).toMatchObject({ severity: 'warning', nodeId: 'target' });
    expect(hasBlockingIssues(issues)).toBe(false);
  });

  it('warns per-transit-point when target_endpoint is empty', () => {
    const payload = {
      ...ok(),
      transit: {
        points: [
          { alias: 'tp-one', target_endpoint: 'https://up/1' },
          { alias: 'tp-two', target_endpoint: '' },
          { alias: 'tp-three', target_endpoint: '   ' },
        ],
      },
    };
    const issues = validateSurfacePayload(payload);
    const tpIssues = issues.filter(i => i.path?.startsWith('transit.points'));
    expect(tpIssues).toHaveLength(2);
    expect(tpIssues[0].path).toBe('transit.points.1.target_endpoint');
    expect(tpIssues[1].path).toBe('transit.points.2.target_endpoint');
    expect(tpIssues.every(i => i.severity === 'warning')).toBe(true);
  });

  it('errors when a transit point alias is missing, malformed, or duplicated', () => {
    const payload = {
      ...ok(),
      transit: {
        points: [
          { alias: '', target_endpoint: 'https://up/1' },
          { alias: 'BAD_ALIAS', target_endpoint: 'https://up/2' },
          { alias: 'good', target_endpoint: 'https://up/3' },
          { alias: 'good', target_endpoint: 'https://up/4' },
        ],
      },
    };
    const issues = validateSurfacePayload(payload);
    const aliasIssues = issues.filter(i => i.path?.endsWith('.alias'));
    expect(aliasIssues).toHaveLength(3);
    expect(aliasIssues.every(i => i.severity === 'error')).toBe(true);
    expect(aliasIssues[0].path).toBe('transit.points.0.alias');
    expect(aliasIssues[1].path).toBe('transit.points.1.alias');
    expect(aliasIssues[2].path).toBe('transit.points.3.alias');
    expect(hasBlockingIssues(issues)).toBe(true);
  });

  it('warns on canvas nodes whose parentId is missing', () => {
    const payload = {
      ...ok(),
      canvas: {
        nodes: [
          { id: 'access-point', parentId: null },
          { id: 'target', parentId: 'access-point' },
          { id: 'orphan', parentId: 'ghost-id' },
        ],
      },
    };
    const issues = validateSurfacePayload(payload);
    const orphan = issues.find(i => i.nodeId === 'orphan');
    expect(orphan).toMatchObject({
      severity: 'warning',
      message: expect.stringContaining('missing parent "ghost-id"'),
    });
  });

  it('warns when target anchor is parented to a non-chain node', () => {
    const payload = {
      ...ok(),
      canvas: {
        nodes: [
          { id: '__surface__' },
          { id: 'access-point', parentId: '__surface__' },
          { id: 'rogue', type: 'npc-endpoint' },
          { id: 'target', parentId: 'rogue' },
        ],
      },
    };
    const issues = validateSurfacePayload(payload);
    const leak = issues.find(i => i.nodeId === 'target');
    expect(leak).toMatchObject({ severity: 'warning' });
    expect(leak!.message).toContain('chain parent leaking');
  });

  it('does NOT warn when target is parented to a chain middleware (legitimate splice output)', () => {
    // Edge-drop middlewares (payment, networking, custom-metadata, …)
    // re-parent the target onto themselves to encode chain order in
    // `parentId` for `deriveEdges` to recover. This is by design and
    // must not trip the structural-leak watchdog.
    const payload = {
      ...ok(),
      canvas: {
        nodes: [
          { id: '__surface__' },
          { id: 'access-point', parentId: '__surface__' },
          { id: 'payment', type: 'payment', parentId: 'access-point' },
          { id: 'target', parentId: 'payment' },
        ],
      },
    };
    const issues = validateSurfacePayload(payload);
    expect(issues.find(i => i.nodeId === 'target')).toBeUndefined();
  });

  it('does NOT warn when target is parented to access-point or surface', () => {
    const payload = {
      ...ok(),
      canvas: {
        nodes: [
          { id: 'access-point', parentId: '__surface__' },
          { id: 'target', parentId: 'access-point' },
        ],
      },
    };
    const issues = validateSurfacePayload(payload);
    expect(issues.find(i => i.nodeId === 'target')).toBeUndefined();
  });

  it('returns a single error for null/undefined payload', () => {
    expect(validateSurfacePayload(null)).toMatchObject([{ severity: 'error' }]);
    expect(validateSurfacePayload(undefined)).toMatchObject([{ severity: 'error' }]);
  });

  describe('workload binding managed-identity requirement', () => {
    const wbTp = (extra: Record<string, unknown> = {}) => ({
      alias: 'tp-one',
      target_endpoint: 'https://up/1',
      workload_binding: { enabled: true, caller_source: 'transit_token' },
      ...extra,
    });

    it('errors when an enabled WB transit point has no managed-identity source', () => {
      const payload = { ...ok(), transit: { points: [wbTp()] } };
      const issues = validateSurfacePayload(payload);
      const wb = issues.find(i => i.path === 'transit.points.0.workload_binding');
      expect(wb).toMatchObject({ severity: 'error' });
      expect(hasBlockingIssues(issues)).toBe(true);
    });

    it('accepts an enabled WB transit point with its own managed_identity', () => {
      const payload = {
        ...ok(),
        transit: { points: [wbTp({ managed_identity: { type: 'from_payload' } })] },
      };
      const issues = validateSurfacePayload(payload);
      expect(issues.find(i => i.path === 'transit.points.0.workload_binding')).toBeUndefined();
    });

    it('accepts an enabled WB transit point when the surface has an identity slot', () => {
      const payload = {
        ...ok(),
        identity_slots: { protected: { type: 'from_payload' } },
        transit: { points: [wbTp()] },
      };
      const issues = validateSurfacePayload(payload);
      expect(issues.find(i => i.path === 'transit.points.0.workload_binding')).toBeUndefined();
    });

    it('accepts an enabled WB transit point when the managed agent DID source is enabled', () => {
      const payload = {
        name: 'My Surface',
        target: { endpoint: 'https://upstream/y', didwebvh_enabled: true },
        transit: { points: [wbTp()] },
      };
      const issues = validateSurfacePayload(payload);
      expect(issues.find(i => i.path === 'transit.points.0.workload_binding')).toBeUndefined();
    });

    it('ignores a disabled WB transit point regardless of identity source', () => {
      const payload = {
        ...ok(),
        transit: {
          points: [
            {
              alias: 'tp-one',
              target_endpoint: 'https://up/1',
              workload_binding: { enabled: false, caller_source: 'transit_token' },
            },
          ],
        },
      };
      const issues = validateSurfacePayload(payload);
      expect(issues.find(i => i.path === 'transit.points.0.workload_binding')).toBeUndefined();
    });
  });
});
