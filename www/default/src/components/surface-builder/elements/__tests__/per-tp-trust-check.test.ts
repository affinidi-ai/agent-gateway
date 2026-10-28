/**
 * Per-Transit-Point target-leg Trust Check: each MA→TP arrow owns its own
 * Trust Check node, saved to `transit.points[i].trust_check_list` by the TP
 * factory and hydrated back onto the same arrow. The Managed Agent's own
 * target leg (`target.trust_check_list`) is saved only for an A2A proxy or
 * gateway target.
 */

import { buildCanvasBlob, registry } from '../index';
import { deriveEdges } from '../edges/deriveEdges';
import {
  TRUST_CHECK_MANAGED_AGENT_SLOT_ID,
  TRUST_CHECK_TRANSIT_POINT_SLOT_ID,
} from '../edges/archetypes';
import { computeOverridesFromPayload, resolveVariant } from '../../variants/resolve';
import type { CanvasNode } from '../../SurfaceCanvas';

const ISSUER = 'did:web:issuer.example';

const wireEntry = (id: string, registryId: string) => ({
  id,
  trust_registry_id: registryId,
  query_type: 'recognition',
  query: { authority_id: ISSUER, entity_id: '{{ input.agent.did }}' },
});

function rebuild(nodes: CanvasNode[]): any {
  return registry.buildPayload({
    protocol: 'a2a',
    surfaceMeta: { name: 'per-tp-trust-check', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: (type: string) => nodes.filter(n => n.type === type),
    firstNodeOfType: (type: string) => nodes.find(n => n.type === type),
  } as any);
}

function surface(extra: Record<string, any> = {}): any {
  return {
    name: 'per-tp-trust-check',
    status: 'active',
    tags: [],
    access_point: { listen_address: 'https://0.0.0.0:8443', route: '/a2a', protocol: 'a2a' },
    target: { endpoint: 'https://agent.example.com/a2a' },
    transit: {
      points: [
        {
          id: 'tp-uuid-1',
          alias: 'tp1',
          protocol: 'a2a',
          target_endpoint: 'https://one.example.com/a2a',
          trust_check_list: [wireEntry('tc-1', 'tr-1')],
        },
        {
          id: 'tp-uuid-2',
          alias: 'tp2',
          protocol: 'a2a',
          target_endpoint: 'https://two.example.com/a2a',
          trust_check_list: [wireEntry('tc-2a', 'tr-2'), wireEntry('tc-2b', 'tr-2')],
        },
      ],
    },
    ...extra,
  };
}

const node = (n: Partial<CanvasNode> & Pick<CanvasNode, 'id' | 'type'>): CanvasNode =>
  ({ label: '', configured: true, config: {}, ...n }) as CanvasNode;

function canvasWithTrustCheckOn(
  tpId: string,
  targetEndpoint = 'https://agent.example.com/a2a'
): CanvasNode[] {
  return [
    node({ id: 'access-point', type: 'access-point', config: { route: '/a2a' } }),
    node({
      id: 'target',
      type: 'target',
      parentId: 'access-point',
      config: { endpoint: targetEndpoint },
    }),
    node({
      id: 'tp-a',
      type: 'transit-point-a2a',
      parentId: 'access-point',
      config: { id: 'tp-uuid-a', alias: 'tp-a', target_endpoint: 'https://a.example.com' },
    }),
    node({
      id: 'tp-b',
      type: 'transit-point-a2a',
      parentId: 'access-point',
      config: { id: 'tp-uuid-b', alias: 'tp-b', target_endpoint: 'https://b.example.com' },
    }),
    node({
      id: `trust-check-${tpId}`,
      type: 'trust-check',
      parentId: tpId,
      slotId: TRUST_CHECK_TRANSIT_POINT_SLOT_ID,
      config: {
        queries: [
          {
            id: 'q-1',
            trust_registry_id: 'tr-1',
            query_type: 'recognition',
            query: { authority_id: ISSUER },
          },
        ],
      },
    }),
  ];
}

describe('per-TP Trust Check — save payload', () => {
  it('writes a node on TP A only to that Transit Point and never to the Managed Agent', () => {
    const payload = rebuild(canvasWithTrustCheckOn('tp-a'));
    const [tpA, tpB] = payload.transit.points;
    expect(tpA.alias).toBe('tp-a');
    expect(tpA.trust_check_list).toEqual([
      {
        id: 'q-1',
        trust_registry_id: 'tr-1',
        query_type: 'recognition',
        query: { authority_id: ISSUER, entity_id: '{{ input.agent.did }}' },
      },
    ]);
    expect(tpB.alias).toBe('tp-b');
    expect(tpB).not.toHaveProperty('trust_check_list');
    expect(payload.target).not.toHaveProperty('trust_check_list');
    expect(payload.access_point?.trust_check_list).toBeUndefined();
  });

  it('target-leg entries leave a blank Authority blank (no caller-leg default)', () => {
    const nodes = canvasWithTrustCheckOn('tp-b');
    nodes[nodes.length - 1].config.queries[0].query = {};
    const payload = rebuild(nodes);
    expect(payload.transit.points[1].trust_check_list[0].query).toEqual({
      authority_id: '',
      entity_id: '{{ input.agent.did }}',
    });
  });

  it('writes the list of a Trust Check kept on an MCP Transit Point', () => {
    const nodes = canvasWithTrustCheckOn('tp-a');
    nodes[2] = { ...nodes[2], type: 'transit-point-mcp' } as CanvasNode;
    const payload = rebuild(nodes);
    expect(payload.transit.points[0].protocol).toBe('mcp');
    expect(payload.transit.points[0].trust_check_list.map((e: any) => e.id)).toEqual(['q-1']);
    expect(payload.target).not.toHaveProperty('trust_check_list');
  });

  it('keeps trust_check_migrated on a Transit Point that still has its list', () => {
    const nodes = canvasWithTrustCheckOn('tp-a');
    nodes[4] = { ...nodes[4], config: { ...nodes[4].config, trust_check_migrated: true } };
    const payload = rebuild(nodes);
    expect(payload.transit.points[0].trust_check_migrated).toBe(true);
    expect(payload.transit.points[1]).not.toHaveProperty('trust_check_migrated');
  });
});

describe('Managed Agent target-leg Trust Check', () => {
  const withManagedAgentNode = (endpoint: string): CanvasNode[] => [
    ...canvasWithTrustCheckOn('tp-a', endpoint).slice(0, 4),
    node({
      id: 'trust-check-target',
      type: 'trust-check',
      parentId: 'target',
      slotId: TRUST_CHECK_MANAGED_AGENT_SLOT_ID,
      config: {
        queries: [
          {
            id: 'ma-1',
            trust_registry_id: 'tr-1',
            query_type: 'recognition',
            query: { authority_id: ISSUER },
          },
        ],
      },
    }),
  ];

  it.each(['https://agent.example.com/a2a', 'http://agent.example.com/a2a'])(
    'never sends a non-empty target.trust_check_list for %s',
    endpoint => {
      const payload = rebuild(withManagedAgentNode(endpoint));
      expect(payload.target.endpoint).toBe(endpoint);
      expect(payload.target).not.toHaveProperty('trust_check_list');
      expect(payload.transit.points.every((p: any) => !('trust_check_list' in p))).toBe(true);
    }
  );

  it.each(['a2a-proxy://proxy-1', 'fabric://gw-1/surface-a'])(
    'saves target.trust_check_list for %s',
    endpoint => {
      const payload = rebuild(withManagedAgentNode(endpoint));
      expect(payload.target.trust_check_list.map((e: any) => e.id)).toEqual(['ma-1']);
      expect(payload.transit.points.every((p: any) => !('trust_check_list' in p))).toBe(true);
    }
  );

  it('hydrates the Managed Agent list onto the Managed Agent, not onto a Transit Point', () => {
    const nodes = registry.nodesFromPayload(
      surface({
        target: {
          endpoint: 'a2a-proxy://proxy-1',
          trust_check_list: [wireEntry('ma-1', 'tr-1')],
        },
        transit: { points: [] },
      })
    );
    const tc = nodes.filter(n => n.type === 'trust-check');
    expect(tc).toHaveLength(1);
    expect(tc[0]).toMatchObject({
      id: 'trust-check-target',
      parentId: 'target',
      slotId: TRUST_CHECK_MANAGED_AGENT_SLOT_ID,
    });
  });
});

describe('per-TP Trust Check — hydration', () => {
  it('creates one node per Transit Point on that Transit Point arrow', () => {
    const nodes = registry.nodesFromPayload(surface());
    const tps = nodes.filter(n => n.type === 'transit-point-a2a');
    expect(tps.map(n => n.id)).toEqual(['transit-point-a2a-1', 'transit-point-a2a-2']);
    const tc = nodes.filter(n => n.type === 'trust-check');
    expect(tc.map(n => [n.id, n.parentId, n.slotId])).toEqual([
      ['trust-check-transit-point-a2a-1', 'transit-point-a2a-1', TRUST_CHECK_TRANSIT_POINT_SLOT_ID],
      ['trust-check-transit-point-a2a-2', 'transit-point-a2a-2', TRUST_CHECK_TRANSIT_POINT_SLOT_ID],
    ]);
    expect(tc[0].config.queries.map((q: any) => q.id)).toEqual(['tc-1']);
    expect(tc[1].config.queries.map((q: any) => q.id)).toEqual(['tc-2a', 'tc-2b']);
    expect(tps[0].config).not.toHaveProperty('trust_check_list');

    const edges = deriveEdges(nodes as CanvasNode[]).filter(e => e.archetype === 'ma-tp');
    const slotOf = (tpId: string) =>
      edges.find(e => e.endpoints.target === tpId)!.slots.get(TRUST_CHECK_TRANSIT_POINT_SLOT_ID);
    expect(slotOf('transit-point-a2a-1')).toEqual(['trust-check-transit-point-a2a-1']);
    expect(slotOf('transit-point-a2a-2')).toEqual(['trust-check-transit-point-a2a-2']);
  });

  it('round-trips each Transit Point list unchanged', () => {
    const payload = surface();
    const rebuilt = rebuild(registry.nodesFromPayload(payload) as CanvasNode[]);
    expect(rebuilt.transit.points.map((p: any) => p.trust_check_list)).toEqual(
      payload.transit.points.map((p: any) => p.trust_check_list)
    );
    expect(rebuilt.target).not.toHaveProperty('trust_check_list');
  });

  it('keeps trust_check_migrated through hydrate and save', () => {
    const payload = surface();
    payload.transit.points[1].trust_check_migrated = true;
    const rebuilt = rebuild(registry.nodesFromPayload(payload) as CanvasNode[]);
    expect(rebuilt.transit.points[0]).not.toHaveProperty('trust_check_migrated');
    expect(rebuilt.transit.points[1].trust_check_migrated).toBe(true);
  });

  it('hydrates a stored list on an MCP Transit Point onto that Transit Point', () => {
    const payload = surface();
    payload.transit.points[0].protocol = 'mcp';
    const nodes = registry.nodesFromPayload(payload);
    expect(nodes.filter(n => n.type === 'trust-check').map(n => n.parentId)).toEqual([
      'transit-point-mcp-1',
      'transit-point-a2a-1',
    ]);
  });

  it('ignores a stale canvas node from the shared Managed Agent list', () => {
    const payload = surface({
      canvas: {
        version: 1,
        nodes: [
          {
            id: 'trust-check-target',
            type: 'trust-check',
            parentId: 'target',
            slotId: TRUST_CHECK_MANAGED_AGENT_SLOT_ID,
            position: { x: 10, y: 10 },
            config: {
              _edge: 'ma-tp',
              queries: [
                { id: 'old', trust_registry_id: 'tr-old', query_type: 'recognition', query: {} },
              ],
            },
          },
        ],
      },
    });
    const nodes = registry.nodesFromPayload(payload);
    const tc = nodes.filter(n => n.type === 'trust-check');
    expect(tc.map(n => n.id)).toEqual([
      'trust-check-transit-point-a2a-1',
      'trust-check-transit-point-a2a-2',
    ]);
    expect(tc.map(n => n.parentId)).toEqual(['transit-point-a2a-1', 'transit-point-a2a-2']);
    const rebuilt = rebuild(nodes as CanvasNode[]);
    expect(rebuilt.target).not.toHaveProperty('trust_check_list');
    expect(rebuilt.transit.points[0].trust_check_list.map((e: any) => e.id)).toEqual(['tc-1']);
  });

  it('keeps a per-TP node and its layout across a canvas save and reload', () => {
    const payload = surface();
    const first = registry.nodesFromPayload(payload);
    const placed = first.map(n =>
      n.id === 'trust-check-transit-point-a2a-2' ? { ...n, position: { x: 42, y: 24 } } : n
    );
    const reloaded = registry.nodesFromPayload({ ...payload, canvas: buildCanvasBlob(placed) });
    const tc = reloaded.filter(n => n.type === 'trust-check');
    expect(tc.map(n => n.id)).toEqual([
      'trust-check-transit-point-a2a-1',
      'trust-check-transit-point-a2a-2',
    ]);
    expect(tc[1]).toMatchObject({
      parentId: 'transit-point-a2a-2',
      position: { x: 42, y: 24 },
    });
    expect(tc[1].config.queries.map((q: any) => q.id)).toEqual(['tc-2a', 'tc-2b']);
  });
});

describe('per-TP Trust Check — variants', () => {
  it('carries each Transit Point list through a variant snapshot round-trip', () => {
    const variantPayload = surface();
    variantPayload.transit.points[0].trust_check_list = [wireEntry('variant-tc', 'tr-v')];
    const overrides = computeOverridesFromPayload(variantPayload);
    expect(
      (overrides.transit?.points as any[]).map(p => p.trust_check_list.map((e: any) => e.id))
    ).toEqual([['variant-tc'], ['tc-2a', 'tc-2b']]);

    const base = surface({ transit: { points: [] } });
    const resolved = resolveVariant(base, overrides);
    const rebuilt = rebuild(registry.nodesFromPayload(resolved) as CanvasNode[]);
    expect(
      rebuilt.transit.points.map((p: any) => p.trust_check_list.map((e: any) => e.id))
    ).toEqual([['variant-tc'], ['tc-2a', 'tc-2b']]);
    expect(rebuilt.target).not.toHaveProperty('trust_check_list');
  });
});
