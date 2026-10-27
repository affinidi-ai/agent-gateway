import { hydrateSurfaceCanvas } from '../nodesFromSurface';
import {
  TRUST_CHECK_CALLER_SLOT_ID,
  TRUST_CHECK_MANAGED_AGENT_SLOT_ID,
} from '../elements/edges/archetypes';
import type { AgentSurface } from '../../../api';

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
