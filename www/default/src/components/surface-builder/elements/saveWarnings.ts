import { showToast } from '../../../utils/toaster';
import { joinWarnings } from '../../../utils/warningHeader';
import { validateSurfacePayload } from './validateSurface';

export interface SurfaceSaveToastOptions {
  /** Messages of the save response's `Warning` headers. */
  headerWarnings?: readonly string[];
}

/**
 * Shows a save in one toast, since a later toast replaces an earlier one:
 * `saved` alone, or with the save's warnings, the gateway's first (its
 * `Warning` headers), then the dashboard's non-blocking issues, each once.
 */
export function showSurfaceSaveToast(
  saved: string,
  payload: unknown,
  { headerWarnings = [] }: SurfaceSaveToastOptions = {}
): void {
  const fromDashboard = validateSurfacePayload(payload)
    .filter(i => i.severity === 'warning')
    .map(i => i.message);
  const all = Array.from(new Set([...headerWarnings, ...fromDashboard]));
  if (all.length === 0) {
    showToast('success', saved);
    return;
  }
  showToast('warning', `${saved}, with warnings:\n${joinWarnings(all)}`, {
    autoRemove: true,
    duration: 10000,
  });
}
