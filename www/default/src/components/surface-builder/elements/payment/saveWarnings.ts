import { showToast } from '../../../../utils/toaster';

/** Messages for the non-blocking `warnings` a surface save returns, objects of `{code, message}`. */
export function saveWarningMessages(warnings: unknown): string[] {
  if (!Array.isArray(warnings)) return [];
  return warnings.flatMap((w: unknown) => {
    const { code, message } = (w ?? {}) as { code?: unknown; message?: unknown };
    const text = typeof message === 'string' ? message.trim() : '';
    if (text) return [text];
    return typeof code === 'string' && code ? [code] : [];
  });
}

export function showSaveWarnings(warnings: unknown): void {
  for (const message of saveWarningMessages(warnings)) {
    showToast('error', message, { autoRemove: true, duration: 8000 });
  }
}
