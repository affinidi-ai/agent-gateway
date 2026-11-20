import { useCallback, useEffect, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { showUndoToast } from '../../../utils/toaster';
import { setNavGuard } from '../../../utils/navGuard';

export interface DiscardSnapshot {
  /**
   * sessionStorage key scoped to the entity being edited
   * (e.g. `surface-draft:${surfaceId}`).
   */
  storageKey: string;
  /** Serialize current dirty state to a string just before navigation. */
  save: () => string;
  /**
   * Restore state from the string produced by `save`. Called by the
   * consumer at the appropriate point in its load sequence (after the
   * API response arrives) via the returned `popPendingRestore()`.
   */
  restore: (saved: string) => void;
  /**
   * Restore only when the editor is reopened by the toast's Undo; any other visit drops the
   * snapshot, so the editor starts fresh.
   */
  restoreOnlyOnUndo?: boolean;
}

/** Navigation state the toast's Undo sets, so the editor can tell it was reopened by Undo. */
const UNDO_STATE = { discardUndo: true } as const;

/** Dismisses the discard toast still showing for a snapshot, by its storage key. */
const pendingToasts = new Map<string, () => void>();

export interface UseDiscardWithUndoOptions {
  dirty: boolean;
  navigateTo: string;
  message?: string;
  duration?: number;
  snapshot?: DiscardSnapshot;
}

export interface UseDiscardWithUndoResult {
  /** Call from Back / Cancel buttons. */
  discard: () => void;
  /**
   * Call at the end of your async load (after API data is applied).
   * If an undo-restore snapshot is waiting in sessionStorage it will
   * be applied and `true` is returned; otherwise a no-op returning `false`.
   */
  popPendingRestore: () => boolean;
}

/**
 * Discard-with-undo for dirty forms.
 *
 * Navigation proceeds immediately; a timed toast with Undo appears.
 * When `snapshot` is configured the dirty state survives the remount
 * — call `popPendingRestore()` at the end of your load to apply it.
 *
 * `beforeunload` still uses the browser's native dialog.
 */
export function useDiscardWithUndo({
  dirty,
  navigateTo,
  message = 'Changes discarded.',
  duration = 5000,
  snapshot,
}: UseDiscardWithUndoOptions): UseDiscardWithUndoResult {
  const navigate = useNavigate();
  const location = useLocation();
  const dirtyRef = useRef(dirty);
  dirtyRef.current = dirty;
  // Editor's own path, refreshed every render so a discard always undoes
  // back to *this* route rather than a relative history hop, which drifts
  // once the user navigates further before clicking Undo.
  const editorPathRef = useRef(location.pathname + location.search);
  editorPathRef.current = location.pathname + location.search;
  // Keep snapshot in a ref so callbacks don't need it as a dep —
  // avoids re-creating saveSnapshot / popPendingRestore on every render
  // when the caller passes an inline object.
  const snapshotRef = useRef(snapshot);
  snapshotRef.current = snapshot;
  const openedByUndoRef = useRef(
    (location.state as { discardUndo?: boolean } | null)?.discardUndo === true
  );

  // Tab / window close — only the native browser dialog is available here.
  useEffect(() => {
    if (!dirty) return;
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, [dirty]);

  const saveSnapshot = useCallback(() => {
    const snap = snapshotRef.current;
    if (!snap || !dirtyRef.current) return;
    try {
      sessionStorage.setItem(snap.storageKey, snap.save());
    } catch (_ignored) {
      // quota exceeded or unavailable — silently skip
    }
  }, []); // stable — uses refs

  // A toast replaced by a newer one for the same key expires, but the draft is the newer one's.
  const showDiscardToast = useCallback(
    (onUndo: () => void) => {
      const key = snapshotRef.current?.storageKey;
      if (key) pendingToasts.delete(key);
      const dismiss = showUndoToast({
        message,
        duration,
        onUndo: () => {
          if (key) pendingToasts.delete(key);
          onUndo();
        },
        onExpire: () => {
          if (!key || pendingToasts.get(key) !== dismiss) return;
          pendingToasts.delete(key);
          try {
            sessionStorage.removeItem(key);
          } catch (_ignored) {
            /* ignore */
          }
        },
      });
      if (key) pendingToasts.set(key, dismiss);
    },
    [message, duration]
  );

  // Sidebar / header link guard.
  useEffect(() => {
    setNavGuard(() => {
      if (dirtyRef.current) {
        saveSnapshot();
        setTimeout(
          () => showDiscardToast(() => navigate(editorPathRef.current, { state: UNDO_STATE })),
          0
        );
      }
      return true;
    });
    return () => setNavGuard(null);
  }, [navigate, saveSnapshot, showDiscardToast]);

  // Explicit Back / Cancel button.
  const discard = useCallback(() => {
    if (!dirtyRef.current) {
      navigate(navigateTo);
      return;
    }
    saveSnapshot();
    const editorPath = editorPathRef.current;
    navigate(navigateTo);
    showDiscardToast(() => navigate(editorPath, { state: UNDO_STATE }));
  }, [navigate, navigateTo, saveSnapshot, showDiscardToast]);

  // Called by the consumer after its async load completes.
  const popPendingRestore = useCallback((): boolean => {
    const snap = snapshotRef.current;
    if (!snap) return false;
    const saved = sessionStorage.getItem(snap.storageKey);
    if (!saved) return false;
    sessionStorage.removeItem(snap.storageKey);
    if (snap.restoreOnlyOnUndo && !openedByUndoRef.current) {
      // The draft is gone, so its toast's Undo would reopen nothing.
      pendingToasts.get(snap.storageKey)?.();
      pendingToasts.delete(snap.storageKey);
      return false;
    }
    snap.restore(saved);
    return true;
  }, []); // stable — uses refs

  return { discard, popPendingRestore };
}
