import { hydrateSurfaceCanvas } from '../nodesFromSurface';
import {
  TRUST_CHECK_CALLER_SLOT_ID,
  TRUST_CHECK_MANAGED_AGENT_SLOT_ID,
} from '../elements/edges/archetypes';
import type { AgentSurface } from '../../../api';
import type { CanvasNode } from '../SurfaceCanvas';
import { registry } from '../elements';
import { buildSurfaceContext } from '../elements/surfaceContext';
import { MANAGED_AGENT_TRUST_CHECK_TARGET_MESSAGE } from '../elements/trust-check/definition';
import { dependencyErrorBlocker } from '../dependencyBlocker';

const ISSUER = 'did:web:issuer.example';
const entry = (id: string) => ({
  id,
  trust_registry_id: 'tr-1',
  query_type: 'recognition',
  query: { authority_id: ISSUER, entity_id: '{{ input.agent.did }}' },
});

const at = (id: string, type: string, x: number, y: number, extra: object = {}) => ({
  id,
  type,
  label: '',
  position: { x, y },
  ...extra,
});

const legacyBlob = (extra: unknown[] = []) => [
  at('__human__', 'human', -200, 0),
  at('__caller__', 'caller', -120, 0),
  at('access-point', 'access-point', 0, 100),
  at('target', 'target', 200, 100, { parentId: 'access-point' }),
  at('__managed-agent-npc__', 'npc-endpoint', 400, 100, { parentId: 'target' }),
  at('transit-point-a2a-1', 'transit-point-a2a', 300, 0, {
    parentId: 'access-point',
    config: { id: 'uuid-1' },
  }),
  at('trust-check-target', 'trust-check', 250, 60, {
    parentId: 'transit-point-a2a-1',
    slotId: TRUST_CHECK_MANAGED_AGENT_SLOT_ID,
    config: { _edge: 'ma-tp', queries: [entry('stale-blob-query')] },
  }),
  ...extra,
];

const migratedSurface = (canvasNodes: unknown[], extra: object = {}) =>
  ({
    name: 'legacy',
    status: 'active',
    tags: [],
    access_point: { route: '/a2a', protocol: 'a2a' },
    target: { endpoint: 'https://agent.example.com/a2a' },
    transit: {
      points: [
        {
          id: 'uuid-1',
          alias: 'tp1',
          protocol: 'a2a',
          target_endpoint: 'https://one.example.com/a2a',
          trust_check_list: [entry('migrated')],
          trust_check_migrated: true,
        },
      ],
    },
    canvas: { version: 1, nodes: canvasNodes },
    ...extra,
  }) as unknown as AgentSurface;

describe('hydrateSurfaceCanvas with a Trust Check the blob has no position for', () => {
  it('keeps the saved layout and places the Transit Point Trust Check on its arrow', () => {
    const hydrated = hydrateSurfaceCanvas(migratedSurface(legacyBlob()));
    expect(hydrated.didAutoLayout).toBe(false);
    const byId = new Map(hydrated.nodes.map(n => [n.id, n] as const));
    expect(byId.get('access-point')?.position).toEqual({ x: 0, y: 100 });
    expect(byId.get('target')?.position).toEqual({ x: 200, y: 100 });
    expect(byId.get('transit-point-a2a-1')?.position).toEqual({ x: 300, y: 0 });
    const tc = byId.get('trust-check-transit-point-a2a-1')!;
    expect(tc.parentId).toBe('transit-point-a2a-1');
    expect(tc.position).toEqual({ x: 250, y: 50 });
    expect(tc.config.queries.map((q: any) => q.id)).toEqual(['migrated']);
    expect(tc.config.trust_check_migrated).toBe(true);
    expect(byId.has('trust-check-target')).toBe(false);
  });

  it('places a caller Trust Check between the Access Point and the Managed Agent', () => {
    const hydrated = hydrateSurfaceCanvas(
      migratedSurface(legacyBlob(), {
        access_point: {
          route: '/a2a',
          protocol: 'a2a',
          trust_check_list: [entry('caller')],
        },
      })
    );
    expect(hydrated.didAutoLayout).toBe(false);
    const caller = hydrated.nodes.find(n => n.id === 'trust-check-caller')!;
    expect(caller.slotId).toBe(TRUST_CHECK_CALLER_SLOT_ID);
    expect(caller.position).toEqual({ x: 100, y: 100 });
  });

  it('keeps a Trust Check position the blob already has', () => {
    const hydrated = hydrateSurfaceCanvas(
      migratedSurface(
        legacyBlob([
          at('trust-check-transit-point-a2a-1', 'trust-check', 280, 30, {
            parentId: 'transit-point-a2a-1',
          }),
        ])
      )
    );
    expect(hydrated.didAutoLayout).toBe(false);
    expect(hydrated.nodes.find(n => n.id === 'trust-check-transit-point-a2a-1')?.position).toEqual({
      x: 280,
      y: 30,
    });
  });

  it('still lays out a surface whose blob has no positions', () => {
    const hydrated = hydrateSurfaceCanvas(migratedSurface([]));
    expect(hydrated.didAutoLayout).toBe(true);
    expect(hydrated.nodes.every(n => n.type === 'target-variant' || !!n.position)).toBe(true);
  });
});

describe("hydrateSurfaceCanvas with the Managed Agent's own Trust Check on a URL target", () => {
  const surfaceWith = (endpoint: string, tpLists: unknown[][], canvasNodes?: unknown[]) =>
    ({
      name: 'ma',
      status: 'active',
      tags: [],
      access_point: { route: '/a2a', protocol: 'a2a' },
      target: { endpoint, trust_check_list: [entry('ma-1')] },
      transit: {
        points: tpLists.map((list, i) => ({
          id: `uuid-${i}`,
          alias: `tp${i}`,
          protocol: 'a2a',
          target_endpoint: `https://tp${i}.example.com/a2a`,
          trust_check_list: list,
          trust_check_migrated: true,
        })),
      },
      ...(canvasNodes ? { canvas: { version: 1, nodes: canvasNodes } } : {}),
    }) as unknown as AgentSurface;
  const rebuild = (nodes: CanvasNode[]) =>
    registry.buildPayload({
      protocol: 'a2a',
      surfaceMeta: { name: 'ma', tags: [], status: 'active' },
      allNodes: nodes,
      nodesOfType: (type: string) => nodes.filter(n => n.type === type),
      firstNodeOfType: (type: string) => nodes.find(n => n.type === type),
    } as any);
  const blocker = (nodes: CanvasNode[]) => {
    const ctx = buildSurfaceContext('a2a', nodes);
    return dependencyErrorBlocker(
      nodes.flatMap(n =>
        registry
          .getDependencyWarnings(n.type, n.config, ctx, n)
          .filter(w => w.severity === 'error')
          .map(w => ({ nodeId: n.id, nodeType: n.type, message: w.message }))
      )
    );
  };
  const copy = () => [{ ...entry('tp-copy'), name: 'copied' }];
  const has = (nodes: CanvasNode[], id: string) => nodes.some(n => n.id === id);

  it('drops it when every Transit Point runs the same queries, so Save is not blocked', () => {
    const { nodes } = hydrateSurfaceCanvas(
      surfaceWith('https://agent.example.com/a2a', [copy(), copy()])
    );
    expect(has(nodes, 'trust-check-target')).toBe(false);
    expect(blocker(nodes)).toBeNull();
    const payload = rebuild(nodes);
    expect(payload.target).not.toHaveProperty('trust_check_list');
    expect(
      payload.transit.points.map((p: any) => p.trust_check_list.map((e: any) => e.id))
    ).toEqual([['tp-copy'], ['tp-copy']]);
  });

  it('reattaches a node chained after the dropped one to the Managed Agent', () => {
    const { nodes } = hydrateSurfaceCanvas(
      surfaceWith(
        'https://agent.example.com/a2a',
        [copy()],
        [
          {
            id: 'trust-check-target',
            type: 'trust-check',
            label: '',
            parentId: 'target',
            slotId: TRUST_CHECK_MANAGED_AGENT_SLOT_ID,
          },
          {
            id: 'ext',
            type: 'npc-endpoint',
            label: 'External',
            parentId: 'trust-check-target',
            config: {},
          },
        ]
      )
    );
    expect(has(nodes, 'trust-check-target')).toBe(false);
    expect(nodes.find(n => n.id === 'ext')?.parentId).toBe('target');
  });

  it('keeps it and blocks Save when one Transit Point runs different queries', () => {
    const other = [{ ...entry('other'), query: { authority_id: 'did:web:other.example' } }];
    const { nodes } = hydrateSurfaceCanvas(
      surfaceWith('https://agent.example.com/a2a', [copy(), other])
    );
    expect(has(nodes, 'trust-check-target')).toBe(true);
    expect(blocker(nodes)).toEqual({
      message: `Trust Check: ${MANAGED_AGENT_TRUST_CHECK_TARGET_MESSAGE}`,
      nodeId: 'trust-check-target',
    });
  });

  it('keeps it and blocks Save when the surface has no Transit Points', () => {
    const { nodes } = hydrateSurfaceCanvas(surfaceWith('https://agent.example.com/a2a', []));
    expect(has(nodes, 'trust-check-target')).toBe(true);
    expect(blocker(nodes)?.nodeId).toBe('trust-check-target');
  });

  it('keeps it on an A2A Proxy target even when the Transit Points run the same queries', () => {
    const { nodes } = hydrateSurfaceCanvas(surfaceWith('a2a-proxy://proxy-1', [copy()]));
    expect(has(nodes, 'trust-check-target')).toBe(true);
    expect(blocker(nodes)).toBeNull();
    expect(rebuild(nodes).target.trust_check_list.map((e: any) => e.id)).toEqual(['ma-1']);
  });
});
