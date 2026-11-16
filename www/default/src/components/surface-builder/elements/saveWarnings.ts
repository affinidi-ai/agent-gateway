import { showToast } from '../../../utils/toaster';
import { joinWarnings } from '../../../utils/warningHeader';
import { validateSurfacePayload } from './validateSurface';

/**
 * The gateway's Access Point `Warning` headers (`access_point_warnings`): public,
 * open and not ready. A save shows none of them.
 */
const ACCESS_POINT_WARNINGS: ReadonlySet<string> = new Set([
  'This Access Point is public. Anyone who can reach it can call your agent without credentials.',
  'This Access Point is neither closed nor public, and it admits callers without credentials. Add source authentication, or set access_point.public to false to close it or to true to keep it open.',
  'This Access Point is not ready for external access. Add source authentication (a caller_authentication method), or set access_point.public to true to allow callers without credentials.',
]);

/** A variant's not-ready warning is prefixed `variant '<alias>': `. */
const VARIANT_PREFIX = /^variant '[^']*': /;

/** The save's `Warning` headers a save shows: all but the Access Point's. */
export function shownSaveWarnings(headerWarnings: readonly string[]): string[] {
  return headerWarnings.filter(w => !ACCESS_POINT_WARNINGS.has(w.replace(VARIANT_PREFIX, '')));
}

export interface SurfaceSaveToastOptions {
  /** Messages of the save response's `Warning` headers. */
  headerWarnings?: readonly string[];
}

/**
 * Shows a save in one toast, since a later toast replaces an earlier one:
 * `saved` alone, or with the save's warnings, the gateway's first (its
 * `Warning` headers but the Access Point's), then the dashboard's non-blocking
 * issues, each once.
 */
export function showSurfaceSaveToast(
  saved: string,
  payload: unknown,
  { headerWarnings = [] }: SurfaceSaveToastOptions = {}
): void {
  const fromDashboard = validateSurfacePayload(payload)
    .filter(i => i.severity === 'warning')
    .map(i => i.message);
  const all = Array.from(new Set([...shownSaveWarnings(headerWarnings), ...fromDashboard]));
  if (all.length === 0) {
    showToast('success', saved);
    return;
  }
  showToast('warning', `${saved}, with warnings:\n${joinWarnings(all)}`, {
    autoRemove: true,
    duration: 10000,
  });
}
