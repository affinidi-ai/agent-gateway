import { useCallback, useReducer, useRef, useState } from 'react';

/**
 * Undo / redo history with explicit commit semantics.
 *
 * Two distinct operations:
 *
 *   - `set(updater)`  — applies a live edit. The new state is rendered
 *                       immediately but is NOT recorded as a new history
 *                       snapshot. Use this for typing into a field, dragging
 *                       a node, etc.
 *
 *   - `commit()`      — records the current state as a new snapshot. Call
 *                       this at the end of a coherent edit (blur of an
 *                       input, mouseup of a drag, drop of a new element,
 *                       removal of a node, arrow-key nudge, etc.).
 *
 * `undo()` first auto-commits any uncommitted live edits (so they remain
 * recoverable via `redo`), then steps back to the previous snapshot.
 *
 * Snapshots form a circular FIFO of length `limit` — once full, the oldest
 * snapshot is evicted on the next commit.
 */
export const HISTORY_LIMIT = 10;

interface HistorySnapshots<T> {
  past: T[];
  committed: T;
  future: T[];
}

export interface UseHistoryReturn<T> {
  state: T;
  set: (updater: React.SetStateAction<T>) => void;
  commit: () => void;
  /**
   * Replace the most recent committed snapshot with the current state
   * in-place, without pushing a new entry onto the history stack. Use
   * this when an element's mount-time seeding effect writes default
   * values: the seed should not appear as a separately-undoable step,
   * because the user thinks of "drop + auto-seed" as one action.
   * Future is cleared (a redo would otherwise carry stale data).
   */
  replaceCommit: () => void;
  undo: () => void;
  redo: () => void;
  canUndo: boolean;
  canRedo: boolean;
  /**
   * Counter incremented exactly once per externally-driven mutation
   * (undo / redo, or an explicit `bumpExternalRevision()` call). Live
   * `set()` edits do NOT bump it. Components with uncontrolled local
   * state can use this as a remount key to resync from props after an
   * undo or after a load/save replaces the snapshot wholesale.
   */
  externalRevision: number;
  /**
   * Manually bump `externalRevision` without altering history. Use
   * after operations that swap the entire snapshot in place (load,
   * save round-trip) so panels with local state remount and resync.
   */
  bumpExternalRevision: () => void;
}

export function useHistory<T>(initial: T, limit: number = HISTORY_LIMIT): UseHistoryReturn<T> {
  const [state, setState] = useState<T>(initial);
  const [externalRevision, bumpRevision] = useReducer((x: number) => x + 1, 0);
  const snapshotsRef = useRef<HistorySnapshots<T>>({
    past: [],
    committed: initial,
    future: [],
  });
  const [, forceUpdate] = useReducer((x: number) => x + 1, 0);

  const set = useCallback((updater: React.SetStateAction<T>) => {
    setState(updater);
  }, []);

  const commit = useCallback(() => {
    setState(current => {
      const h = snapshotsRef.current;
      if (current === h.committed) return current;
      const past = [...h.past, h.committed];
      if (past.length > limit) past.shift();
      snapshotsRef.current = { past, committed: current, future: [] };
      forceUpdate();
      return current;
    });
  }, [limit]);

  const replaceCommit = useCallback(() => {
    setState(current => {
      const h = snapshotsRef.current;
      if (current === h.committed) return current;
      // Overwrite the top-of-stack snapshot in-place. `past` is unchanged,
      // so an undo from here jumps to the entry before the one being
      // replaced — exactly what we want when seeding defaults right
      // after a drop.
      snapshotsRef.current = { past: h.past, committed: current, future: [] };
      forceUpdate();
      return current;
    });
  }, []);

  const undo = useCallback(() => {
    setState(current => {
      const h = snapshotsRef.current;
      let past = h.past;
      let committed = h.committed;
      let future = h.future;

      // Auto-commit any in-progress edits so they're recoverable via redo.
      if (current !== committed) {
        past = [...past, committed];
        if (past.length > limit) past.shift();
        committed = current;
        future = [];
      }

      if (past.length === 0) {
        snapshotsRef.current = { past, committed, future };
        forceUpdate();
        return current;
      }
      const newCommitted = past[past.length - 1];
      const newPast = past.slice(0, -1);
      const newFuture = [committed, ...future];
      snapshotsRef.current = { past: newPast, committed: newCommitted, future: newFuture };
      forceUpdate();
      bumpRevision();
      return newCommitted;
    });
  }, [limit]);

  const redo = useCallback(() => {
    setState(current => {
      const h = snapshotsRef.current;
      if (h.future.length === 0) return current;
      const newCommitted = h.future[0];
      const newFuture = h.future.slice(1);
      // Drop any uncommitted in-progress edits when redoing.
      void current;
      const newPast = [...h.past, h.committed];
      if (newPast.length > limit) newPast.shift();
      snapshotsRef.current = { past: newPast, committed: newCommitted, future: newFuture };
      forceUpdate();
      bumpRevision();
      return newCommitted;
    });
  }, [limit]);

  return {
    state,
    set,
    commit,
    replaceCommit,
    undo,
    redo,
    // An uncommitted live edit alone does not enable undo — without
    // a prior snapshot to step back to, an undo from that state just
    // auto-commits the edit and reverts it, which surprises the user
    // (e.g. initial-hydrate effects make state !== committed before
    // any real interaction).
    canUndo: snapshotsRef.current.past.length > 0,
    canRedo: snapshotsRef.current.future.length > 0,
    externalRevision,
    bumpExternalRevision: bumpRevision,
  };
}
