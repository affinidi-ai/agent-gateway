import { useCallback, useReducer, useRef } from 'react';

/**
 * Page-level full-surface undo / redo ring buffer.
 *
 * Each snapshot is the JSON-serialised projection of the entire surface
 * at a moment in time (full payload with all variants + the active
 * variant id + page metadata). The page captures snapshots at every
 * meaningful boundary; undo/redo step the buffer and the page applies
 * the popped snapshot wholesale — including switching the active
 * variant if the snapshot was taken on a different one.
 *
 * Why a ring of full snapshots instead of per-variant deltas:
 *   - Undo across variant switches: a change made on variant A then a
 *     switch to B then undo must restore A's state with A active. A
 *     per-variant history can't express that.
 *   - Simplicity: applying a snapshot is a pure replace of all
 *     surface-derived state; no merge logic, no per-element diffing.
 *   - Save survival: saving just commits a new snapshot. The past
 *     stack is preserved, so undo after save still walks the user's
 *     edit history.
 *
 * Snapshots are opaque strings to this hook — equality is by string
 * compare, so commits that produce an identical snapshot to the
 * current `committed` are silently dropped (no spurious history step).
 */

export const SURFACE_HISTORY_LIMIT = 50;

interface Store {
  past: string[];
  committed: string | null;
  future: string[];
}

export interface UseSurfaceHistoryReturn {
  /**
   * Push a new snapshot. Promotes the prior `committed` onto `past`
   * (subject to `limit`), sets `committed` to the supplied snapshot,
   * and clears `future`. No-op when the snapshot equals `committed`.
   */
  commit: (snapshot: string) => void;
  /**
   * Replace `committed` in-place without pushing onto `past`. Clears
   * `future`. Used after a successful save to re-baseline without
   * inserting a duplicate step into the history walk.
   */
  replaceCommitted: (snapshot: string) => void;
  /**
   * Wipe `past`, `future`, and set `committed` to the supplied
   * snapshot. Used on initial load so the history starts fresh from
   * the persisted state.
   */
  reset: (snapshot: string) => void;
  /**
   * Pop the most recent entry from `past`. Returns the snapshot the
   * caller should apply, or `null` if there's nothing to undo. Promotes
   * the prior `committed` onto `future` so a subsequent `redo` walks
   * back to it.
   */
  undo: () => string | null;
  /**
   * Pop the front entry from `future`. Returns the snapshot the caller
   * should apply, or `null` if there's nothing to redo. Promotes the
   * prior `committed` onto `past`.
   */
  redo: () => string | null;
  canUndo: boolean;
  canRedo: boolean;
}

export function useSurfaceHistory(limit: number = SURFACE_HISTORY_LIMIT): UseSurfaceHistoryReturn {
  const storeRef = useRef<Store>({ past: [], committed: null, future: [] });
  const [, bump] = useReducer((x: number) => x + 1, 0);

  const commit = useCallback(
    (snapshot: string) => {
      const s = storeRef.current;
      if (snapshot === s.committed) {
        return;
      }
      const past = s.committed !== null ? [...s.past, s.committed] : [...s.past];
      while (past.length > limit) past.shift();
      storeRef.current = { past, committed: snapshot, future: [] };
      bump();
    },
    [limit]
  );

  const replaceCommitted = useCallback((snapshot: string) => {
    const s = storeRef.current;
    if (snapshot === s.committed) return;
    storeRef.current = { past: s.past, committed: snapshot, future: [] };
    bump();
  }, []);

  const reset = useCallback((snapshot: string) => {
    storeRef.current = { past: [], committed: snapshot, future: [] };
    bump();
  }, []);

  const undo = useCallback((): string | null => {
    const s = storeRef.current;
    if (s.past.length === 0 || s.committed === null) {
      return null;
    }
    const newCommitted = s.past[s.past.length - 1];
    const newPast = s.past.slice(0, -1);
    const newFuture = [s.committed, ...s.future];
    storeRef.current = { past: newPast, committed: newCommitted, future: newFuture };
    bump();
    return newCommitted;
  }, []);

  const redo = useCallback((): string | null => {
    const s = storeRef.current;
    if (s.future.length === 0 || s.committed === null) {
      return null;
    }
    const newCommitted = s.future[0];
    const newFuture = s.future.slice(1);
    const newPast = [...s.past, s.committed];
    while (newPast.length > limit) newPast.shift();
    storeRef.current = { past: newPast, committed: newCommitted, future: newFuture };
    bump();
    return newCommitted;
  }, [limit]);

  const s = storeRef.current;
  return {
    commit,
    replaceCommitted,
    reset,
    undo,
    redo,
    canUndo: s.past.length > 0,
    canRedo: s.future.length > 0,
  };
}
