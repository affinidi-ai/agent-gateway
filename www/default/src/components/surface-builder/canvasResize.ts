export interface CanvasSize {
  w: number;
  h: number;
}

/**
 * Whether a container resize should rebuild the canvas. A hidden container (size 0) never does.
 * A visible one does when its size changed since the last draw, or when the last rebuild found the
 * container hidden and so left the nodes undrawn.
 */
export function resizeNeedsRebuild(
  last: CanvasSize,
  next: CanvasSize,
  rebuildPending: boolean
): boolean {
  if (next.w === 0 || next.h === 0) return false;
  return rebuildPending || Math.abs(last.w - next.w) >= 1 || Math.abs(last.h - next.h) >= 1;
}
