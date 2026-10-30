type Json = Record<string, unknown>;

const isRecord = (v: unknown): v is Json =>
  v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * The surface page's dirty signature without where things sit on the canvas: node positions, the
 * canvas size and the pan/zoom view. A surface that was never saved from the dashboard gets its
 * layout fitted after it loads, which changes those values without any edit to the surface.
 */
export function withoutCanvasLayout(signature: string): string {
  try {
    const outer: unknown = JSON.parse(signature);
    if (!isRecord(outer) || typeof outer.variantsSig !== 'string') return signature;
    const variants: unknown = JSON.parse(outer.variantsSig);
    if (!isRecord(variants) || !isRecord(variants.s)) return signature;
    for (const snapshot of Object.values(variants.s)) {
      const canvas = isRecord(snapshot) ? snapshot.canvas : undefined;
      if (!isRecord(canvas)) continue;
      delete canvas.view;
      delete canvas.surface;
      if (Array.isArray(canvas.nodes)) {
        for (const node of canvas.nodes) if (isRecord(node)) delete node.position;
      }
    }
    return JSON.stringify({ ...outer, variantsSig: JSON.stringify(variants) });
  } catch {
    return signature;
  }
}
