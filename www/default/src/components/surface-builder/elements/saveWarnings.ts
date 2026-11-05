import { showToast } from '../../../utils/toaster';
import { joinWarnings } from '../../../utils/warningHeader';
import { validateSurfacePayload } from './validateSurface';

/** The gateway's `Warning` for a save with Public access on. */
export const PUBLIC_ACCESS_WARNING =
  'This Access Point is public. Anyone who can reach it can call your agent without credentials.';

/**
 * Drops the gateway's public Access Point warning: the operator turned Public
 * access on themselves, so a save does not warn them about it.
 */
export function withoutPublicAccessWarning(warnings: readonly string[]): string[] {
  return warnings.filter(w => w !== PUBLIC_ACCESS_WARNING);
}

/**
 * Shows a save in one toast, since a later toast replaces an earlier one:
 * `saved` alone, or with the dashboard's non-blocking issues, each once. The
 * gateway's `Warning` headers are left to the panels they name.
 */
export function showSurfaceSaveToast(saved: string, payload: unknown): void {
  const fromDashboard = validateSurfacePayload(payload)
    .filter(i => i.severity === 'warning')
    .map(i => i.message);
  const all = Array.from(new Set(fromDashboard));
  if (all.length === 0) {
    showToast('success', saved);
    return;
  }
  showToast('warning', `${saved}, with warnings:\n${joinWarnings(all)}`, {
    autoRemove: true,
    duration: 10000,
  });
}
