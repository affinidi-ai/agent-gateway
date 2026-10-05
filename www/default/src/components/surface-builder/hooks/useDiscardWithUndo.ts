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
}

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

  const clearSnapshot = useCallback(() => {
    const snap = snapshotRef.current;
    if (snap) {
      try {
        sessionStorage.removeItem(snap.storageKey);
      } catch (_ignored) {
        /* ignore */
      }
    }
  }, []); // stable — uses refs

  // Sidebar / header link guard.
  useEffect(() => {
    setNavGuard(() => {
      if (dirtyRef.current) {
        saveSnapshot();
        setTimeout(
          () =>
            showUndoToast({
              message,
              duration,
              onUndo: () => navigate(editorPathRef.current),
              onExpire: clearSnapshot,
            }),
          0
        );
      }
      return true;
    });
    return () => setNavGuard(null);
  }, [message, duration, navigate, saveSnapshot, clearSnapshot]);

  // Explicit Back / Cancel button.
  const discard = useCallback(() => {
    if (!dirtyRef.current) {
      navigate(navigateTo);
      return;
    }
    saveSnapshot();
    const editorPath = editorPathRef.current;
    navigate(navigateTo);
    showUndoToast({
      message,
      duration,
      onUndo: () => navigate(editorPath),
      onExpire: clearSnapshot,
    });
  }, [navigate, navigateTo, message, duration, saveSnapshot, clearSnapshot]);

  // Called by the consumer after its async load completes.
  const popPendingRestore = useCallback((): boolean => {
    const snap = snapshotRef.current;
    if (!snap) return false;
    const saved = sessionStorage.getItem(snap.storageKey);
    if (!saved) return false;
    sessionStorage.removeItem(snap.storageKey);
    snap.restore(saved);
    return true;
  }, []); // stable — uses refs

  return { discard, popPendingRestore };
}
