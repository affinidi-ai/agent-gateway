import { showToast } from '../../../utils/toaster';
import { joinWarnings } from '../../../utils/warningHeader';
import { validateSurfacePayload, type ValidateSurfaceOptions } from './validateSurface';

export interface SurfaceSaveToastOptions extends ValidateSurfaceOptions {
  /** Messages of the save response's `Warning` headers. */
  headerWarnings?: readonly string[];
  /** The save response's `warnings`. */
  warnings?: unknown;
}

/**
 * Shows a save in one toast, since a later toast replaces an earlier one:
 * `saved` alone, or with the save's warnings, the gateway's first (its
 * `Warning` headers, then the response's `warnings`), then the dashboard's
 * non-blocking issues, each once.
 */
export function showSurfaceSaveToast(
  saved: string,
  payload: unknown,
  { headerWarnings = [], warnings, ...options }: SurfaceSaveToastOptions = {}
): void {
  const fromApi = Array.isArray(warnings)
    ? warnings.filter((w): w is string => typeof w === 'string' && w.trim().length > 0)
    : [];
  const fromDashboard = validateSurfacePayload(payload, options)
    .filter(i => i.severity === 'warning')
    .map(i => i.message);
  const all = Array.from(new Set([...headerWarnings, ...fromApi, ...fromDashboard]));
  if (all.length === 0) {
    showToast('success', saved);
    return;
  }
  showToast('warning', `${saved}, with warnings:\n${joinWarnings(all)}`, {
    autoRemove: true,
    duration: 10000,
  });
}
