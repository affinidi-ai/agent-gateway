/**
 * `tryDrop` dispatcher tests. Pin the slot-selection rules declared in
 * `archetypes.ts`:
 *   - prefer specific accepts over the `'*'` sentinel
 *   - on ties, prefer lower `order`
 *   - reject when a 'one' slot is occupied (do not silently fall back
 *     to the generic slot)
 */

import { deriveEdges } from '../edges/deriveEdges';
import {
  tryDrop,
  getArchetype,
  EDGE_ARCHETYPES,
  makeSurfaceSlotFilter,
  findEdgeForHit,
} from '../edges/archetypes';
import { synthesizeFabricCanvasNodes, SYNTH_HOP_PREFIX } from '../synthesizeFabric';
import type { CanvasNode } from '../../SurfaceCanvas';

const node = (n: Partial<CanvasNode> & Pick<CanvasNode, 'id' | 'type'>): CanvasNode =>
  ({ label: '', configured: true, ...n }) as CanvasNode;

describe('archetypes catalogue', () => {
  it('exposes the ap-ma, ma-external, and ma-tp archetypes', () => {
    expect(EDGE_ARCHETYPES.map(a => a.id).sort()).toEqual(['ap-ma', 'ma-external', 'ma-tp']);
  });

  it('getArchetype returns undefined for unknown ids', () => {
    expect(getArchetype('does-not-exist')).toBeUndefined();
  });

  it('orders AP→MA request nodes by inbound execution seam', () => {
    const apMa = getArchetype('ap-ma')!;
    const orderOf = (slotId: string) => apMa.slots.find(slot => slot.id === slotId)!.order;
    expect(orderOf('request:caller-auth')).toBeLessThan(orderOf('request:rate-limit'));
    expect(orderOf('request:rate-limit')).toBeLessThan(orderOf('request:metadata-extraction'));
    expect(orderOf('request:metadata-extraction')).toBeLessThan(orderOf('request:payment'));
    expect(orderOf('request:payment')).toBeLessThan(orderOf('request:extension-validation'));
    expect(orderOf('request:extension-validation')).toBeLessThan(
      orderOf('request:extension-rules')
    );
    expect(orderOf('request:extension-rules')).toBeLessThan(orderOf('request:identity-inbound'));
    expect(orderOf('request:identity-inbound')).toBeLessThan(orderOf('request:custom-metadata'));
    expect(orderOf('request:custom-metadata')).toBeLessThan(
      orderOf('request:trust-check-access_point_trust_check_list')
    );
    expect(orderOf('request:trust-check-access_point_trust_check_list')).toBeLessThan(
      orderOf('request:policy')
    );
    expect(orderOf('request:policy')).toBeLessThan(orderOf('request:policy-inbound'));
    expect(orderOf('request:policy-inbound')).toBeLessThan(orderOf('request:networking'));
  });

  it('orders MA→TP request Metadata Extraction before managed-agent Identity', () => {
    const maTp = getArchetype('ma-tp')!;
    const orderOf = (slotId: string) => maTp.slots.find(slot => slot.id === slotId)!.order;
    expect(orderOf('request:metadata-extraction')).toBeLessThan(
      orderOf('request:identity-managed_identity')
    );
    expect(orderOf('request:rate-limit')).toBeLessThan(orderOf('request:metadata-extraction'));
    expect(orderOf('request:policy')).toBeGreaterThan(
      orderOf('request:trust-check-target_trust_check_list')
    );
  });
});

describe('tryDrop', () => {
  const baseNodes: CanvasNode[] = [
    node({ id: 'ap', type: 'access-point' }),
    node({ id: 'ma', type: 'target', parentId: 'ap' }),
    node({ id: 'tp1', type: 'transit-point-a2a' }),
  ];

  it('routes a typed mw onto its dedicated slot of an empty ap-ma edge', () => {
    const [apMa] = deriveEdges(baseNodes);
    const r = tryDrop(apMa, 'rate-limit', 'request');
    expect(r).toEqual({ ok: true, slotId: 'request:rate-limit' });
  });

  it('routes policy onto its typed slot when dropping on ma-tp request', () => {
    const edges = deriveEdges(baseNodes);
    const tpEdge = edges.find(e => e.archetype === 'ma-tp')!;
    const r = tryDrop(tpEdge, 'policy', 'request');
    expect(r).toEqual({ ok: true, slotId: 'request:policy' });
  });

  it('routes policy onto its typed slot on ma-tp response too', () => {
    const edges = deriveEdges(baseNodes);
    const tpEdge = edges.find(e => e.archetype === 'ma-tp')!;
    const r = tryDrop(tpEdge, 'policy', 'response');
    expect(r).toEqual({ ok: true, slotId: 'response:policy' });
  });

  it('rejects a second policy on an occupied per-tp-policy slot (no silent fallback)', () => {
    const nodes: CanvasNode[] = [
      ...baseNodes,
      node({ id: 'pol-req', type: 'policy', parentId: 'tp1' }),
    ];
    const tpEdge = deriveEdges(nodes).find(e => e.archetype === 'ma-tp')!;
    const r = tryDrop(tpEdge, 'policy', 'request');
    expect(r.ok).toBe(false);
    expect(r.ok ? '' : r.reason).toMatch(/already in use/i);
  });

  it('routes Metadata Extraction onto the A2A ma-tp request header-mapping slot', () => {
    const tpEdge = deriveEdges(baseNodes).find(e => e.archetype === 'ma-tp')!;
    const r = tryDrop(
      tpEdge,
      'metadata-extraction',
      'request',
      undefined,
      makeSurfaceSlotFilter('https://upstream.example/api', true, baseNodes)
    );
    expect(r).toEqual({ ok: true, slotId: 'request:metadata-extraction' });
  });

  it('rejects Metadata Injection on ma-tp request edges', () => {
    const tpEdge = deriveEdges(baseNodes).find(e => e.archetype === 'ma-tp')!;
    const r = tryDrop(
      tpEdge,
      'custom-metadata',
      'request',
      undefined,
      makeSurfaceSlotFilter('https://upstream.example/api', true, baseNodes)
    );
    expect(r.ok).toBe(false);
    expect(r.ok ? '' : r.reason).toMatch(/transit-wide/i);
  });

  it('rejects Metadata Extraction on unsupported ma-tp request protocols', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({ id: 'tp1', type: 'transit-point-mcp' }),
    ];
    const tpEdge = deriveEdges(nodes).find(e => e.archetype === 'ma-tp')!;
    const r = tryDrop(
      tpEdge,
      'metadata-extraction',
      'request',
      undefined,
      makeSurfaceSlotFilter('https://upstream.example/api', true, nodes)
    );
    expect(r.ok).toBe(false);
    expect(r.ok ? '' : r.reason).toMatch(/transit-wide/i);
  });

  it('routes target-leg Trust Check onto the A2A ma-tp slot', () => {
    const tpEdge = deriveEdges(baseNodes).find(e => e.archetype === 'ma-tp')!;
    const r = tryDrop(
      tpEdge,
      'trust-check',
      'request',
      undefined,
      makeSurfaceSlotFilter('https://upstream.example/api', true, baseNodes)
    );
    expect(r).toEqual({ ok: true, slotId: 'request:trust-check-target_trust_check_list' });
  });

  it('rejects target-leg Trust Check on an MCP Transit Point (no MCP target-leg impl)', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({ id: 'tp1', type: 'transit-point-mcp' }),
    ];
    const tpEdge = deriveEdges(nodes).find(e => e.archetype === 'ma-tp')!;
    const r = tryDrop(
      tpEdge,
      'trust-check',
      'request',
      undefined,
      makeSurfaceSlotFilter('https://upstream.example/api', true, nodes)
    );
    expect(r.ok).toBe(false);
    expect(r.ok ? '' : r.reason).toMatch(/transit-wide/i);
  });

  it('rejects a direction the archetype does not support', () => {
    const apMa = deriveEdges(baseNodes)[0];
    const broken = { ...apMa, archetype: 'unknown-archetype' };
    const r = tryDrop(broken, 'rate-limit', 'request');
    expect(r.ok).toBe(false);
  });

  it('allows multiple generic mw to stack on request:mw (cardinality=many)', () => {
    const nodes: CanvasNode[] = [
      ...baseNodes,
      node({ id: 'mw1', type: 'rate-limit', parentId: 'ap' }),
      // simulate the chain: ma re-parented under mw1
      node({ id: 'ma', type: 'target', parentId: 'mw1' }),
    ];
    // dedupe ma to avoid double entry
    const deduped = nodes.filter((n, i, arr) => arr.findIndex(x => x.id === n.id) === i);
    const apMa = deriveEdges(deduped)[0];
    // Each typed slot is `cardinality: 'one'`; a second
    // custom-metadata is rejected by its own typed slot rather than
    // stacking on the catch-all.
    const r = tryDrop(apMa, 'custom-metadata', 'request');
    expect(r).toEqual({ ok: true, slotId: 'request:custom-metadata' });
  });

  it('routes identity onto its per-TP request slot on ma-tp', () => {
    const edges = deriveEdges(baseNodes);
    const tpEdge = edges.find(e => e.archetype === 'ma-tp')!;
    const r = tryDrop(tpEdge, 'identity', 'request');
    expect(r).toEqual({ ok: true, slotId: 'request:identity-managed_identity' });
  });
});

describe('makeSurfaceSlotFilter (topology-aware slot visibility)', () => {
  const apMaTarget = (endpoint: string): CanvasNode[] => [
    node({ id: 'ap', type: 'access-point' }),
    node({ id: 'target', type: 'target', parentId: 'ap', config: { endpoint } }),
    node({ id: 'npc', type: 'npc-endpoint', parentId: 'target' }),
  ];

  it('returns undefined when MA endpoint is fabric:// (G2G — external slot still meaningful)', () => {
    const filter = makeSurfaceSlotFilter('fabric://gw1/svc', false);
    expect(filter).toBeUndefined();
  });

  it('returns undefined when the surface already has a TP (outbound pipeline exists)', () => {
    const filter = makeSurfaceSlotFilter('https://upstream.example/api', true);
    expect(filter).toBeUndefined();
  });

  it('hides the external identity slot on plain-URL inbound surfaces with no TP', () => {
    const filter = makeSurfaceSlotFilter('https://upstream.example/api', false);
    expect(filter).toBeDefined();
    const nodes = apMaTarget('https://upstream.example/api');
    const maExt = deriveEdges(nodes).find(e => e.archetype === 'ma-external')!;
    const result = tryDrop(maExt, 'identity', 'response', undefined, filter);
    expect(result.ok).toBe(false);
    expect(result.ok ? '' : result.reason).toMatch(/no slot/i);
  });

  it('leaves AP-side identity slot reachable on plain-URL surfaces', () => {
    const filter = makeSurfaceSlotFilter('https://upstream.example/api', false);
    const nodes = apMaTarget('https://upstream.example/api');
    const apMa = deriveEdges(nodes).find(e => e.archetype === 'ap-ma')!;
    const result = tryDrop(apMa, 'identity', 'response', undefined, filter);
    expect(result).toEqual({ ok: true, slotId: 'response:identity-protected' });
  });

  it('allows MCP Tool Gating on an MCP Transit Point response leg', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({ id: 'tp1', type: 'transit-point-mcp' }),
    ];
    const filter = makeSurfaceSlotFilter('https://upstream.example/api', true, nodes);
    const tpEdge = deriveEdges(nodes).find(e => e.archetype === 'ma-tp')!;
    const result = tryDrop(tpEdge, 'mcp-tool-gating', 'response', undefined, filter);
    expect(result).toEqual({ ok: true, slotId: 'response:mcp-tool-gating' });
  });

  it('rejects MCP Tool Gating on an A2A Transit Point response leg (MCP TPs only)', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({ id: 'tp1', type: 'transit-point-a2a' }),
    ];
    const filter = makeSurfaceSlotFilter('https://upstream.example/api', true, nodes);
    const tpEdge = deriveEdges(nodes).find(e => e.archetype === 'ma-tp')!;
    const result = tryDrop(tpEdge, 'mcp-tool-gating', 'response', undefined, filter);
    expect(result.ok).toBe(false);
    // Not "transit-wide" guidance — MCP Tool Gating has no AP→MA slot.
    expect(result.ok ? '' : result.reason).toMatch(/can't be placed on this Transit Point/i);
  });
});

describe('fabric:// (G2G) external-target drop resolution', () => {
  // The MA→remote-gateway arrow is drawn through a view-only synthesised
  // `local-gateway-hop`; its id exists only in the synthesised view, not
  // in the persisted nodes. Edge resolution must run against the same
  // synthesised view or the drop reports "Could not resolve the edge".
  const fabricNodes = (): CanvasNode[] => [
    node({ id: 'ap', type: 'access-point' }),
    node({
      id: 'target',
      type: 'target',
      parentId: 'ap',
      config: { endpoint: 'fabric://gw2/svc', endpoint_type: 'gateway' },
    }),
  ];

  it('resolves the ma-external edge for the synthesised hop and accepts MCP Tool Gating', () => {
    const nodes = fabricNodes();
    const viewNodes = synthesizeFabricCanvasNodes(nodes);
    const hopId = `${SYNTH_HOP_PREFIX}target`;
    expect(viewNodes.some(n => n.id === hopId && n.type === 'local-gateway-hop')).toBe(true);

    const edges = deriveEdges(viewNodes);
    // The drop hit-test reports the response link endpoints (hop → MA).
    const edge = findEdgeForHit(edges, hopId, 'target');
    expect(edge).toBeDefined();
    expect(edge!.archetype).toBe('ma-external');

    const filter = makeSurfaceSlotFilter('fabric://gw2/svc', false, viewNodes);
    const result = tryDrop(edge!, 'mcp-tool-gating', 'response', undefined, filter);
    expect(result).toEqual({ ok: true, slotId: 'response:mcp-tool-gating' });
  });

  it('deriving edges from the raw (un-synthesised) nodes cannot resolve the hop', () => {
    const nodes = fabricNodes();
    const hopId = `${SYNTH_HOP_PREFIX}target`;
    const edges = deriveEdges(nodes);
    expect(findEdgeForHit(edges, hopId, 'target')).toBeUndefined();
  });
});
