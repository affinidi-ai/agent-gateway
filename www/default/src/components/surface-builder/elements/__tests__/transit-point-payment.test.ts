import { registry } from '../index';
import * as Cap from '../capabilities';
import { deriveEdges } from '../edges/deriveEdges';
import { tryDrop } from '../edges/archetypes';
import type { CanvasNode } from '../../SurfaceCanvas';

const node = (n: Partial<CanvasNode> & Pick<CanvasNode, 'id' | 'type'>): CanvasNode =>
  ({ label: '', configured: true, ...n }) as CanvasNode;

describe('Transit Point payment', () => {
  it.each(['transit-point-a2a', 'transit-point-ap2', 'transit-point-mcp'])(
    '%s does not offer a payment target',
    type => {
      expect(registry.get(type as any)!.provides).not.toContain(Cap.PAYMENT_TARGET);
    }
  );

  it('rejects a Payment node dropped on a Transit Point edge', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
      node({ id: 'tp1', type: 'transit-point-a2a' }),
    ];
    const tpEdge = deriveEdges(nodes).find(e => e.archetype === 'ma-tp')!;
    expect(tryDrop(tpEdge, 'payment', 'request').ok).toBe(false);
  });

  it('still accepts a Payment node on the Access Point to Managed Agent edge', () => {
    const nodes: CanvasNode[] = [
      node({ id: 'ap', type: 'access-point' }),
      node({ id: 'ma', type: 'target', parentId: 'ap' }),
    ];
    const apMa = deriveEdges(nodes).find(e => e.archetype === 'ap-ma')!;
    expect(tryDrop(apMa, 'payment', 'request')).toEqual({ ok: true, slotId: 'request:payment' });
  });
});
