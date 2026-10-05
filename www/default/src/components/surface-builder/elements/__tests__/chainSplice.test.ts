/**
 * Regression: dropping a second middleware on an AP→MA edge must not
 * orphan the first one. The bug: chain-insertion only looked at the
 * NEW node's own slot when picking a parent, so the second mw always
 * re-parented the original target endpoint onto itself, leaving the
 * earlier mw as a dangling sibling of the source.
 *
 * The fix splices the new node into the existing request chain by slot
 * order across ALL request slots on the edge.
 */

import { deriveEdges } from '../edges/deriveEdges';
import { getArchetype } from '../edges/archetypes';
import type { CanvasNode } from '../../SurfaceCanvas';

const node = (n: Partial<CanvasNode> & Pick<CanvasNode, 'id' | 'type'>): CanvasNode =>
  ({ label: '', configured: true, ...n }) as CanvasNode;

/**
 * Mirror of the chain-splice logic in `useSurfaceBuilder.handleDrop`.
 * Returns the predecessor (new parent) + successor (whose parent must
 * be re-pointed at the new node) so a test can apply the parentId
 * mutation and assert the resulting topology.
 */
function spliceIntoChain(
  nodes: CanvasNode[],
  archetypeId: string,
  edgeSourceId: string,
  edgeTargetId: string,
  newSlotId: string
): { predecessor: string | undefined; successor: string | undefined } {
  const edge = deriveEdges(nodes).find(
    e =>
      e.archetype === archetypeId &&
      e.endpoints.source === edgeSourceId &&
      e.endpoints.target === edgeTargetId
  )!;
  const archetype = getArchetype(archetypeId)!;
  const newSlot = archetype.slots.find(s => s.id === newSlotId)!;
  const orderedOccupants: Array<{ id: string; order: number }> = [];
  for (const s of archetype.slots) {
    if (s.direction !== 'request') continue;
    if (s.ownedBy) continue;
    const occs = edge.slots.get(s.id) ?? [];
    for (const id of occs) orderedOccupants.push({ id, order: s.order });
  }
  orderedOccupants.sort((a, b) => a.order - b.order);
  let predecessor: string | undefined;
  let successor: string | undefined;
  for (const o of orderedOccupants) {
    if (o.order <= newSlot.order) predecessor = o.id;
    else if (successor === undefined) successor = o.id;
  }
  return { predecessor, successor };
}

describe('chain insertion across slots', () => {
  it('keeps the earlier middleware on the chain when a later one is added', () => {
    // Initial state: rate-limit (slot order 10) already on AP→MA edge.
    const start: CanvasNode[] = [
      node({ id: 'access-point', type: 'access-point' }),
      node({ id: 'rate-limit', type: 'rate-limit', parentId: 'access-point' }),
      node({ id: 'target', type: 'target', parentId: 'rate-limit' }),
    ];
    {
      const apMa = deriveEdges(start).find(e => e.archetype === 'ap-ma')!;
      expect(apMa.slots.get('request:rate-limit')).toEqual(['rate-limit']);
    }

    // Drop custom-metadata (slot order 80). Predecessor must be the
    // existing rate-limit; successor is undefined (no later mw on the
    // chain) which the caller resolves to the original target endpoint.
    const splice = spliceIntoChain(
      start,
      'ap-ma',
      'access-point',
      'target',
      'request:custom-metadata'
    );
    expect(splice.predecessor).toBe('rate-limit');
    expect(splice.successor).toBeUndefined();

    const successor = splice.successor ?? 'target';
    const after: CanvasNode[] = [
      ...start.map(n => (n.id === successor ? { ...n, parentId: 'custom-metadata' } : n)),
      node({ id: 'custom-metadata', type: 'custom-metadata', parentId: splice.predecessor }),
    ];

    const apMaAfter = deriveEdges(after).find(e => e.archetype === 'ap-ma')!;
    // Both mw must be visible in their typed slots — the bug left
    // request:rate-limit empty because rate-limit became a sibling of
    // custom-metadata under access-point and fell off the chain walk.
    expect(apMaAfter.slots.get('request:rate-limit')).toEqual(['rate-limit']);
    expect(apMaAfter.slots.get('request:custom-metadata')).toEqual(['custom-metadata']);
  });

  it('inserts a lower-ordered middleware between the source and an existing higher-ordered one', () => {
    // Initial state: custom-metadata (order 80) already on AP→MA edge.
    const start: CanvasNode[] = [
      node({ id: 'access-point', type: 'access-point' }),
      node({ id: 'custom-metadata', type: 'custom-metadata', parentId: 'access-point' }),
      node({ id: 'target', type: 'target', parentId: 'custom-metadata' }),
    ];

    // Drop rate-limit (order 10). Predecessor must be the source
    // (no lower-order occupant), successor must be custom-metadata.
    const splice = spliceIntoChain(start, 'ap-ma', 'access-point', 'target', 'request:rate-limit');
    expect(splice.predecessor).toBeUndefined();
    expect(splice.successor).toBe('custom-metadata');

    const after: CanvasNode[] = [
      ...start.map(n => (n.id === splice.successor ? { ...n, parentId: 'rate-limit' } : n)),
      node({ id: 'rate-limit', type: 'rate-limit', parentId: 'access-point' }),
    ];

    const apMaAfter = deriveEdges(after).find(e => e.archetype === 'ap-ma')!;
    expect(apMaAfter.slots.get('request:rate-limit')).toEqual(['rate-limit']);
    expect(apMaAfter.slots.get('request:custom-metadata')).toEqual(['custom-metadata']);
  });
});
