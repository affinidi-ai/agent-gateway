import { showToast } from '../../../utils/toaster';
import { joinWarnings } from '../../../utils/warningHeader';
import { validateSurfacePayload, type ValidateSurfaceOptions } from './validateSurface';

export interface SurfaceSaveToastOptions extends ValidateSurfaceOptions {
  /** Messages of the save response's `Warning` headers. */
  headerWarnings?: readonly string[];
}

/**
 * Shows a save in one toast, since a later toast replaces an earlier one:
 * `saved` alone, or with the save's warnings, the gateway's first, then the
 * dashboard's non-blocking issues, each once.
 */
export function showSurfaceSaveToast(
  saved: string,
  payload: unknown,
  { headerWarnings = [], ...options }: SurfaceSaveToastOptions = {}
): void {
  const fromDashboard = validateSurfacePayload(payload, options)
    .filter(i => i.severity === 'warning')
    .map(i => i.message);
  const warnings = Array.from(new Set([...headerWarnings, ...fromDashboard]));
  if (warnings.length === 0) {
    showToast('success', saved);
    return;
  }
  showToast('warning', `${saved}, with warnings:\n${joinWarnings(warnings)}`, {
    autoRemove: true,
    duration: 10000,
  });
}
