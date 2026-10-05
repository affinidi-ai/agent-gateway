/**
 * Read-only adapter tests for `deriveEdges`. The adapter reconstructs
 * the new edge/slot model from today's encoding without changing
 * behaviour, so these tests pin the inversion of the conventions that
 * the renderer and drop handler currently encode directly:
 *
 *   - AP↔MA: request mw chain via parentId; response mw as direct
 *     children of MA with `direction: 'response'`.
 *   - MA↔TP: per-TP policy as child of TP (split by direction); generic
 *     request mw chain via parentId; response mw as TP children with
 *     `direction: 'response'`.
 */

import { deriveEdges } from '../edges/deriveEdges';
import type { CanvasNode } from '../../SurfaceCanvas';

const node = (n: Partial<CanvasNode> & Pick<CanvasNode, 'id' | 'type'>): CanvasNode =>
  ({ label: '', configured: true, ...n }) as CanvasNode;

describe('deriveEdges', () => {
  it('returns empty when neither AP nor MA exist', () => {
    expect(deriveEdges([])).toEqual([]);
  });

  it('emits AP↔MA edge with empty slots when no middleware exists', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
    ];
    const edges = deriveEdges(nodes);
    expect(edges).toHaveLength(1);
    expect(edges[0].id).toBe('ap-ma:ap:ma');
    expect(edges[0].archetype).toBe('ap-ma');
    expect(edges[0].slots.size).toBe(0);
  });

  it('collects request mw chain on AP↔MA', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'mw1', type: 'rate-limit', parentId: 'ap' }),
      node({ id: 'mw2', type: 'custom-metadata', parentId: 'mw1' }),
      node({ id: 'ma', type: 'target', parentId: 'mw2' }),
    ];
    const [edge] = deriveEdges(nodes);
    // Typed slots give each element type its own slot id.
    expect(edge.slots.get('request:rate-limit')).toEqual(['mw1']);
    expect(edge.slots.get('request:custom-metadata')).toEqual(['mw2']);
    expect(edge.slots.get('response:custom-metadata')).toBeUndefined();
  });

  it('binds a hydrated AP Header Metadata Mapping node to AP↔MA request extraction slot', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({
        id: 'metadata-extraction',
        type: 'metadata-extraction',
        slotId: 'request:metadata-extraction',
        config: { header_metadata_mapping: { headers: [] } },
      }),
    ];
    const [edge] = deriveEdges(nodes);
    expect(edge.slots.get('request:metadata-extraction')).toEqual(['metadata-extraction']);
  });

  it('collects response mw on AP↔MA as direct children of MA', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({ id: 'rmw', type: 'custom-metadata', parentId: 'ma', direction: 'response' }),
    ];
    const [edge] = deriveEdges(nodes);
    expect(edge.slots.get('response:custom-metadata')).toEqual(['rmw']);
  });

  it('emits one MA↔TP edge per TP', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({ id: 'tp1', type: 'transit-point-a2a' }),
      node({ id: 'tp2', type: 'transit-point-mcp' }),
    ];
    const edges = deriveEdges(nodes);
    expect(edges.map(e => e.id).sort()).toEqual(
      ['ap-ma:ap:ma', 'ma-tp:ma:tp1', 'ma-tp:ma:tp2'].sort()
    );
  });

  it('routes per-TP request and response policies into the per-tp slots', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({ id: 'tp1', type: 'transit-point-a2a' }),
      node({ id: 'pol-req', type: 'policy', parentId: 'tp1' }),
      node({
        id: 'pol-resp',
        type: 'policy',
        parentId: 'tp1',
        direction: 'response',
      }),
    ];
    const edges = deriveEdges(nodes);
    const tpEdge = edges.find(e => e.archetype === 'ma-tp')!;
    // Per-TP policies live on the typed `request:policy` /
    // `response:policy` slots of the ma-tp archetype.
    expect(tpEdge.slots.get('request:policy')).toEqual(['pol-req']);
    expect(tpEdge.slots.get('response:policy')).toEqual(['pol-resp']);
    expect(tpEdge.slots.get('response:custom-metadata')).toBeUndefined();
  });

  it('binds a per-TP Metadata Extraction node to the ma-tp request:metadata-extraction slot', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({ id: 'tp1', type: 'transit-point-a2a' }),
      node({
        id: 'metadata-extraction-tp1',
        type: 'metadata-extraction',
        parentId: 'tp1',
        slotId: 'request:metadata-extraction',
      }),
    ];
    const edges = deriveEdges(nodes);
    const tpEdge = edges.find(e => e.archetype === 'ma-tp')!;
    expect(tpEdge.slots.get('request:metadata-extraction')).toEqual(['metadata-extraction-tp1']);
  });

  it('binds a per-TP workload-binding node to the ma-tp request:workload-binding slot', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({ id: 'tp1', type: 'transit-point-a2a' }),
      node({
        id: 'wb-tp1',
        type: 'workload-binding',
        parentId: 'tp1',
        slotId: 'request:workload-binding',
      }),
    ];
    const edges = deriveEdges(nodes);
    const tpEdge = edges.find(e => e.archetype === 'ma-tp')!;
    // Per-endpoint (`ownedBy: 'target'`) request slot: the node parents
    // on the TP and must be bound to the ma-tp arrow, not left floating.
    expect(tpEdge.slots.get('request:workload-binding')).toEqual(['wb-tp1']);
  });

  it('binds a target-parented workload-binding node to the ma-external request:workload-binding slot', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({ id: 'ext', type: 'npc-endpoint', parentId: 'ma' }),
      node({
        id: 'workload-binding-target',
        type: 'workload-binding',
        parentId: 'ma',
        slotId: 'request:workload-binding',
      }),
    ];
    const edges = deriveEdges(nodes);
    const extEdge = edges.find(e => e.archetype === 'ma-external')!;
    expect(extEdge).toBeDefined();
    // MA→EXT (`ownedBy: 'source'`) request slot: the node parents on MA
    // and locks onto the external arrow instead of floating.
    expect(extEdge.slots.get('request:workload-binding')).toEqual(['workload-binding-target']);
  });

  it('binds an MA-parented mcp-tool-gating node to the ma-external response slot, not AP↔MA', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({ id: 'ext', type: 'npc-endpoint', parentId: 'ma' }),
      node({
        id: 'mcp-tool-gating-ma-response',
        type: 'mcp-tool-gating',
        parentId: 'ma',
        direction: 'response',
        slotId: 'response:mcp-tool-gating',
      }),
    ];
    const edges = deriveEdges(nodes);
    const extEdge = edges.find(e => e.archetype === 'ma-external')!;
    const apEdge = edges.find(e => e.archetype === 'ap-ma')!;
    // The gating circle locks onto the External→MA response arrow…
    expect(extEdge.slots.get('response:mcp-tool-gating')).toEqual(['mcp-tool-gating-ma-response']);
    // …and is NOT swept into the AP↔MA catch-all response chain.
    expect(apEdge.slots.get('response:mw')).toBeUndefined();
  });

  it('binds a TP-parented mcp-tool-gating node to the ma-tp response slot', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({ id: 'tp1', type: 'transit-point-mcp' }),
      node({
        id: 'mcp-tool-gating-tp1',
        type: 'mcp-tool-gating',
        parentId: 'tp1',
        direction: 'response',
        slotId: 'response:mcp-tool-gating',
      }),
    ];
    const edges = deriveEdges(nodes);
    const tpEdge = edges.find(e => e.archetype === 'ma-tp')!;
    expect(tpEdge.slots.get('response:mcp-tool-gating')).toEqual(['mcp-tool-gating-tp1']);
    // Not swept into the ma-tp response catch-all/policy either.
    expect(tpEdge.slots.get('response:mw')).toBeUndefined();
  });

  it('a stray non-policy node parented between MA and TP is ignored by ma-tp slots (no catch-all)', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({ id: 'meta', type: 'custom-metadata', parentId: 'ma' }),
      node({ id: 'tp1', type: 'transit-point-a2a', parentId: 'meta' }),
      node({ id: 'pol-req', type: 'policy', parentId: 'tp1' }),
    ];
    const edges = deriveEdges(nodes);
    const tpEdge = edges.find(e => e.archetype === 'ma-tp')!;
    // ma-tp no longer declares a catch-all because TransitPoint only
    // supports per-TP `policy`/`response_policy`. A stray non-policy
    // node parented into the chain is simply unattached on this edge
    // (the per-TP policy still hydrates onto its own slot).
    expect(tpEdge.slots.get('request:mw')).toBeUndefined();
    expect(tpEdge.slots.get('request:policy')).toEqual(['pol-req']);
  });

  it('does not double-count per-TP response policy as response:mw', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({ id: 'tp1', type: 'transit-point-a2a' }),
      node({
        id: 'pol-resp',
        type: 'policy',
        parentId: 'tp1',
        direction: 'response',
      }),
      node({
        id: 'rmeta',
        type: 'custom-metadata',
        parentId: 'tp1',
        direction: 'response',
      }),
    ];
    const edges = deriveEdges(nodes);
    const tpEdge = edges.find(e => e.archetype === 'ma-tp')!;
    expect(tpEdge.slots.get('response:policy')).toEqual(['pol-resp']);
    // ma-tp no longer has a catch-all; an unsupported response type
    // is simply unattached on this edge.
    expect(tpEdge.slots.get('response:mw')).toBeUndefined();
  });

  it('produces a stable edge id derived from archetype + endpoints', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({ id: 'tp1', type: 'transit-point-a2a' }),
    ];
    const edges = deriveEdges(nodes);
    expect(new Set(edges.map(e => e.id)).size).toBe(edges.length);
  });

  it('binds inbound identity (child of AP) to AP↔MA request:identity-inbound', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({
        id: 'identity-inbound',
        type: 'identity',
        parentId: 'ap',
        slotId: 'request:identity-inbound',
      }),
    ];
    const [edge] = deriveEdges(nodes);
    expect(edge.slots.get('request:identity-inbound')).toEqual(['identity-inbound']);
  });

  it('binds protected identity (child of MA) to AP↔MA response:identity-protected', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({
        id: 'identity-protected',
        type: 'identity',
        parentId: 'ma',
        direction: 'response',
        slotId: 'response:identity-protected',
      }),
    ];
    const [edge] = deriveEdges(nodes);
    expect(edge.slots.get('response:identity-protected')).toEqual(['identity-protected']);
  });

  it('binds per-TP identity (child of TP) to MA↔TP request:identity-managed_identity', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({ id: 'tp1', type: 'transit-point-a2a' }),
      node({
        id: 'identity-tp1-request',
        type: 'identity',
        parentId: 'tp1',
        direction: 'request',
        slotId: 'request:identity-managed_identity',
      }),
    ];
    const edges = deriveEdges(nodes);
    const tpEdge = edges.find(e => e.archetype === 'ma-tp')!;
    expect(tpEdge.slots.get('request:identity-managed_identity')).toEqual(['identity-tp1-request']);
  });

  it('rebinds legacy per-TP response identity nodes to the MA↔TP request slot', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({ id: 'tp1', type: 'transit-point-a2a' }),
      node({
        id: 'identity-tp1-response',
        type: 'identity',
        parentId: 'tp1',
        direction: 'response',
        slotId: 'response:identity-managed_identity',
      }),
    ];
    const edges = deriveEdges(nodes);
    const tpEdge = edges.find(e => e.archetype === 'ma-tp')!;
    expect(tpEdge.slots.get('request:identity-managed_identity')).toEqual([
      'identity-tp1-response',
    ]);
  });
});
