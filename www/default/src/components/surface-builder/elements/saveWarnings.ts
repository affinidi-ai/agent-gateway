import { showToast } from '../../../utils/toaster';
import { validateSurfacePayload, type ValidateSurfaceOptions } from './validateSurface';

/** Shows a saved surface's non-blocking issues as warning toasts, at most three. */
export function showSurfaceSaveWarnings(payload: unknown, options?: ValidateSurfaceOptions): void {
  const warnings = validateSurfacePayload(payload, options).filter(i => i.severity === 'warning');
  for (const w of warnings.slice(0, 3)) {
    showToast('warning', `Warning: ${w.message}`, { autoRemove: true, duration: 8000 });
  }
}
