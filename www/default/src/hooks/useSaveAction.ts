import { useCallback, useState } from 'react';
import { To } from 'react-router-dom';
import { showToast } from '../utils/toaster';
import { useSafeNavigate } from './useSafeNavigate';

interface RunOptions {
  /** Toast shown on success. */
  successMessage: string;
  /** Where to go on success. Omit to stay on the page. */
  redirectTo?: To;
  /** Page-specific work to run after a successful action (before redirect). */
  onSuccess?: () => void;
  /**
   * Handle a failure — e.g. `setError` to render an inline banner. When omitted,
   * the failure is surfaced as an error toast instead.
   */
  onError?: (message: string) => void;
  /** Fallback message when the thrown error carries none. */
  errorMessage?: string;
}

/**
 * Thin orchestrator for the repo's standard save/delete UX: manages the busy
 * flag, shows a success toast, runs optional page-specific work, and returns to
 * a list — with the navigation guarded against firing after the page has been
 * left (via `useSafeNavigate`).
 *
 * It deliberately does NOT own validation, payload building, or create-vs-update
 * branching — those stay in the caller, which passes the ready-to-run async
 * action. Tabbed editors that should stay put simply omit `redirectTo`.
 */
export function useSaveAction() {
  const { navigate } = useSafeNavigate();
  const [saving, setSaving] = useState(false);

  const run = useCallback(
    async (action: () => Promise<unknown>, opts: RunOptions): Promise<boolean> => {
      setSaving(true);
      try {
        await action();
        showToast('success', opts.successMessage);
        opts.onSuccess?.();
        if (opts.redirectTo !== undefined) navigate(opts.redirectTo);
        return true;
      } catch (e: any) {
        const message = e?.message || opts.errorMessage || 'Something went wrong';
        if (opts.onError) {
          opts.onError(message);
        } else {
          showToast('error', message);
        }
        return false;
      } finally {
        setSaving(false);
      }
    },
    [navigate]
  );

  return { run, saving, navigate };
}
