import { withoutCanvasLayout } from '../surfaceDirtySignature';

const signature = (canvas: unknown, extra: Record<string, unknown> = {}) =>
  JSON.stringify({
    variantsSig: JSON.stringify({
      d: null,
      v: [],
      s: { __base__: { target: { endpoint: 'a' }, canvas } },
    }),
    name: 'surface',
    ...extra,
  });

const canvas = (position: { x: number; y: number }, view?: unknown) => ({
  version: 1,
  surface: { width: 800, height: 600 },
  ...(view ? { view } : {}),
  nodes: [{ id: 'access-point', type: 'access-point', position, config: { route: '/a' } }],
});

describe('withoutCanvasLayout', () => {
  it('ignores node positions, the canvas size and the view', () => {
    const before = signature(canvas({ x: 10, y: 30 }));
    const after = signature({
      ...canvas({ x: 12, y: 32 }, { x: 0.1, y: 0.2, k: 1 }),
      surface: { width: 900, height: 700 },
    });
    expect(before).not.toBe(after);
    expect(withoutCanvasLayout(before)).toBe(withoutCanvasLayout(after));
  });

  it('still tells apart a change to a node config', () => {
    const before = signature(canvas({ x: 10, y: 30 }));
    const edited = signature({
      ...canvas({ x: 10, y: 30 }),
      nodes: [
        {
          id: 'access-point',
          type: 'access-point',
          position: { x: 10, y: 30 },
          config: { route: '/b' },
        },
      ],
    });
    expect(withoutCanvasLayout(before)).not.toBe(withoutCanvasLayout(edited));
  });

  it('still tells apart a change outside the canvas', () => {
    const base = canvas({ x: 10, y: 30 });
    expect(withoutCanvasLayout(signature(base))).not.toBe(
      withoutCanvasLayout(signature(base, { name: 'renamed' }))
    );
  });

  it('keeps every other key of the signature', () => {
    const result = JSON.parse(withoutCanvasLayout(signature(canvas({ x: 1, y: 2 }))));
    const variants = JSON.parse(result.variantsSig);
    expect(result.name).toBe('surface');
    expect(variants.s.__base__.target).toEqual({ endpoint: 'a' });
    expect(variants.s.__base__.canvas.nodes).toEqual([
      { id: 'access-point', type: 'access-point', config: { route: '/a' } },
    ]);
    expect(variants.s.__base__.canvas).not.toHaveProperty('view');
    expect(variants.s.__base__.canvas).not.toHaveProperty('surface');
  });

  it('returns a signature it cannot read unchanged', () => {
    expect(withoutCanvasLayout('not json')).toBe('not json');
    expect(withoutCanvasLayout('[]')).toBe('[]');
    expect(withoutCanvasLayout(JSON.stringify({ variantsSig: 'nope' }))).toBe(
      JSON.stringify({ variantsSig: 'nope' })
    );
    expect(withoutCanvasLayout(JSON.stringify({ variantsSig: '{}' }))).toBe(
      JSON.stringify({ variantsSig: '{}' })
    );
  });

  it('handles snapshots without a canvas', () => {
    const noCanvas = JSON.stringify({
      variantsSig: JSON.stringify({ s: { __base__: { target: {} }, other: null } }),
    });
    expect(JSON.parse(JSON.parse(withoutCanvasLayout(noCanvas)).variantsSig).s.__base__).toEqual({
      target: {},
    });
  });
});
