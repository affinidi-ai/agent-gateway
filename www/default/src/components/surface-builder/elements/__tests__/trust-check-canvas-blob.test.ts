/**
 * Trust Check nodes against stored canvas blobs and shipped templates: the
 * payload decides which list a node belongs to, a blob only supplies layout,
 * and unconfigured placeholders survive.
 */

import fs from 'fs';
import path from 'path';
import { registry } from '../index';
import { deriveEdges } from '../edges/deriveEdges';
import {
  findArchetypeForPair,
  makeSurfaceSlotFilter,
  tryDrop,
  TRUST_CHECK_CALLER_SLOT_ID,
  TRUST_CHECK_MANAGED_AGENT_SLOT_ID,
  TRUST_CHECK_TRANSIT_POINT_SLOT_ID,
} from '../edges/archetypes';
import type { CanvasNode } from '../../SurfaceCanvas';

const ISSUER = 'did:web:issuer.example';
const entry = (id: string) => ({
  id,
  trust_registry_id: 'tr-1',
  query_type: 'recognition',
  query: { authority_id: ISSUER, entity_id: '{{ input.agent.did }}' },
});

function rebuild(nodes: CanvasNode[]): any {
  return registry.buildPayload({
    protocol: 'a2a',
    surfaceMeta: { name: 'blob', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: (type: string) => nodes.filter(n => n.type === type),
    firstNodeOfType: (type: string) => nodes.find(n => n.type === type),
  } as any);
}

const blobNode = (n: Record<string, unknown>) => ({ label: '', ...n });

function fabricSurface(canvasNodes: Array<Record<string, unknown>>): any {
  return {
    name: 'blob',
    status: 'active',
    tags: [],
    access_point: { route: '/a2a', protocol: 'a2a' },
    target: { endpoint: 'fabric://gw-1/surface-a', trust_check_list: [entry('ma-1')] },
    transit: {
      points: [
        {
          id: 'uuid-1',
          alias: 'tp1',
          protocol: 'a2a',
          target_endpoint: 'https://one.example.com/a2a',
          trust_check_list: [entry('tp1-1')],
          trust_check_migrated: true,
        },
        {
          id: 'uuid-2',
          alias: 'tp2',
          protocol: 'a2a',
          target_endpoint: 'https://two.example.com/a2a',
          trust_check_list: [entry('tp2-1')],
        },
      ],
    },
    canvas: { version: 1, nodes: canvasNodes },
  };
}

const trustChecks = (nodes: CanvasNode[]) =>
  nodes.filter(n => n.type === 'trust-check').map(n => [n.id, n.parentId, n.slotId]);

describe('Trust Check against a stale canvas blob', () => {
  it('keeps the Managed Agent node on the Managed Agent when the blob parents it on a Transit Point', () => {
    const payload = fabricSurface([
      blobNode({
        id: 'transit-point-a2a-1',
        type: 'transit-point-a2a',
        parentId: 'access-point',
        config: { id: 'uuid-1' },
      }),
      blobNode({
        id: 'trust-check-target',
        type: 'trust-check',
        parentId: 'transit-point-a2a-1',
        slotId: TRUST_CHECK_MANAGED_AGENT_SLOT_ID,
        position: { x: 5, y: 6 },
        config: { _edge: 'ma-tp', queries: [] },
      }),
    ]);
    const nodes = registry.nodesFromPayload(payload) as CanvasNode[];
    expect(trustChecks(nodes)).toEqual([
      ['trust-check-target', 'target', TRUST_CHECK_MANAGED_AGENT_SLOT_ID],
      ['trust-check-transit-point-a2a-1', 'transit-point-a2a-1', TRUST_CHECK_TRANSIT_POINT_SLOT_ID],
      ['trust-check-transit-point-a2a-2', 'transit-point-a2a-2', TRUST_CHECK_TRANSIT_POINT_SLOT_ID],
    ]);
    expect(nodes.find(n => n.id === 'trust-check-target')?.position).toEqual({ x: 5, y: 6 });

    const rebuilt = rebuild(nodes);
    expect(rebuilt.target.trust_check_list.map((e: any) => e.id)).toEqual(['ma-1']);
    expect(
      rebuilt.transit.points.map((p: any) => p.trust_check_list.map((e: any) => e.id))
    ).toEqual([['tp1-1'], ['tp2-1']]);
    expect(rebuilt.transit.points.map((p: any) => p.trust_check_migrated === true)).toEqual([
      true,
      false,
    ]);

    const viewNodes = [
      ...nodes,
      { id: 'npc', type: 'npc-endpoint', label: '', configured: true, parentId: 'target' },
    ] as CanvasNode[];
    const edges = deriveEdges(viewNodes);
    expect(
      edges.find(e => e.archetype === 'ma-external')!.slots.get(TRUST_CHECK_MANAGED_AGENT_SLOT_ID)
    ).toEqual(['trust-check-target']);
    for (const tpId of ['transit-point-a2a-1', 'transit-point-a2a-2']) {
      const edge = edges.find(e => e.archetype === 'ma-tp' && e.endpoints.target === tpId)!;
      expect(edge.slots.get(TRUST_CHECK_TRANSIT_POINT_SLOT_ID)).toEqual([`trust-check-${tpId}`]);
      expect(edge.slots.get(TRUST_CHECK_MANAGED_AGENT_SLOT_ID)).toBeUndefined();
    }
  });

  it('keeps a Transit Point node on its own Transit Point when the blob names another', () => {
    const payload = fabricSurface([
      blobNode({
        id: 'trust-check-transit-point-a2a-1',
        type: 'trust-check',
        parentId: 'transit-point-a2a-2',
        slotId: TRUST_CHECK_TRANSIT_POINT_SLOT_ID,
      }),
    ]);
    const nodes = registry.nodesFromPayload(payload) as CanvasNode[];
    expect(nodes.find(n => n.id === 'trust-check-transit-point-a2a-1')?.parentId).toBe(
      'transit-point-a2a-1'
    );
    expect(rebuild(nodes).transit.points[0].trust_check_list.map((e: any) => e.id)).toEqual([
      'tp1-1',
    ]);
  });

  it('never adopts a stored list onto a placeholder from another leg', () => {
    const payload = fabricSurface([
      blobNode({
        id: 'trust-check-caller',
        type: 'trust-check',
        parentId: 'access-point',
        slotId: TRUST_CHECK_CALLER_SLOT_ID,
        config: {},
      }),
    ]);
    const nodes = registry.nodesFromPayload(payload) as CanvasNode[];
    const caller = nodes.find(n => n.id === 'trust-check-caller')!;
    expect(caller.slotId).toBe(TRUST_CHECK_CALLER_SLOT_ID);
    expect(caller.config).toEqual({});
    expect(nodes.find(n => n.id === 'trust-check-target')?.slotId).toBe(
      TRUST_CHECK_MANAGED_AGENT_SLOT_ID
    );
    const rebuilt = rebuild(nodes);
    expect(rebuilt.target.trust_check_list.map((e: any) => e.id)).toEqual(['ma-1']);
    expect(rebuilt.access_point?.trust_check_list).toBeUndefined();
  });

  it('restores an unconfigured placeholder but drops stale queries with no stored list', () => {
    const payload = {
      ...fabricSurface([
        blobNode({
          id: 'trust-check-caller',
          type: 'trust-check',
          parentId: 'access-point',
          slotId: TRUST_CHECK_CALLER_SLOT_ID,
          config: {},
        }),
        blobNode({
          id: 'trust-check-stale',
          type: 'trust-check',
          parentId: 'target',
          slotId: TRUST_CHECK_MANAGED_AGENT_SLOT_ID,
          config: { queries: [entry('stale')] },
        }),
      ]),
      target: { endpoint: 'https://agent.example.com' },
      transit: { points: [] },
    };
    const nodes = registry.nodesFromPayload(payload) as CanvasNode[];
    expect(nodes.filter(n => n.type === 'trust-check').map(n => n.id)).toEqual([
      'trust-check-caller',
    ]);
  });
});

describe('Managed Agent target-leg Trust Check drop', () => {
  it.each(['npc-endpoint', 'local-gateway-hop'])(
    'snaps to the Managed Agent → %s arrow and lands on the Managed Agent slot',
    externalType => {
      const archetype = findArchetypeForPair('target', externalType as any);
      expect(archetype).toBe('ma-external');
      expect(registry.snapsToArchetype('trust-check', archetype)).toBe(true);
      const nodes = [
        { id: 'access-point', type: 'access-point', label: '', configured: true },
        {
          id: 'target',
          type: 'target',
          label: '',
          configured: true,
          parentId: 'access-point',
          config: { endpoint: 'a2a-proxy://proxy-1' },
        },
        { id: 'ext', type: externalType, label: '', configured: true, parentId: 'target' },
      ] as CanvasNode[];
      const edge = deriveEdges(nodes).find(e => e.archetype === 'ma-external')!;
      const result = tryDrop(
        edge,
        'trust-check',
        'request',
        undefined,
        makeSurfaceSlotFilter('a2a-proxy://proxy-1', false, nodes)
      );
      expect(result).toEqual({ ok: true, slotId: TRUST_CHECK_MANAGED_AGENT_SLOT_ID });
    }
  );

  it('still snaps to the caller and Transit Point arrows', () => {
    expect(registry.snapsToArchetype('trust-check', 'ap-ma')).toBe(true);
    expect(registry.snapsToArchetype('trust-check', 'ma-tp')).toBe(true);
    expect(registry.snapsToArchetype('trust-check', undefined)).toBe(false);
  });
});

describe('shipped surface templates', () => {
  const dir = path.resolve(
    __dirname,
    '../../../../../../../config/examples/agent_surface_templates'
  );
  const templates = fs
    .readdirSync(dir)
    .filter(f => f.endsWith('.json'))
    .map(f => ({ file: f, json: JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')) }));

  it('finds the templates', () => {
    expect(templates.map(t => t.file)).toContain('full_a2a_surface_with_tr_throttling.json');
  });

  it.each(templates.map(t => [t.file, t.json] as const))(
    '%s has no Managed Agent Trust Check list on a URL target',
    (_file, json) => {
      const target = json?.surface?.target;
      const endpoint = typeof target?.endpoint === 'string' ? target.endpoint : '';
      const list = target?.trust_check_list;
      const allowed = endpoint.startsWith('a2a-proxy://') || endpoint.startsWith('fabric://');
      expect(allowed || !Array.isArray(list) || list.length === 0).toBe(true);
    }
  );

  it('hydrates the A2A Trust Check template onto its Transit Point and caller placeholder', () => {
    const tpl = templates.find(t => t.file === 'full_a2a_surface_with_tr_throttling.json')!;
    const nodes = registry.nodesFromPayload(tpl.json.surface) as CanvasNode[];
    expect(trustChecks(nodes)).toEqual([
      ['trust-check-transit-point-a2a-1', 'transit-point-a2a-1', TRUST_CHECK_TRANSIT_POINT_SLOT_ID],
      ['trust-check-caller', 'access-point', TRUST_CHECK_CALLER_SLOT_ID],
    ]);
    const rebuilt = rebuild(nodes);
    expect(rebuilt.target).not.toHaveProperty('trust_check_list');
    expect(rebuilt.transit.points[0].trust_check_list.map((e: any) => e.id)).toEqual([
      'trust-check-target-recognition',
    ]);
  });
});
