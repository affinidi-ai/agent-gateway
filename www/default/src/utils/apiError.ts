/**
 * Turn a backend error response into a user-friendly toast string.
 *
 * The gateway returns JSON error bodies in a few shapes — `{ message }`,
 * `{ error }`, `{ error, details }` (surface API: the human message is in
 * `details`, `error` holds a short label like "Forbidden"), `{ error: { message } }`,
 * `{ detail }` — so dumping the raw body into a toast shows unreadable JSON.
 * These helpers pull the human message out and append the HTTP status in
 * parentheses, e.g. `"Appliance limit reached… (403)"`.
 */

/** Best-effort human message from a response body (JSON or plain text). */
export function extractErrorMessage(body: string | null | undefined): string | null {
  const trimmed = (body ?? '').trim();
  if (!trimmed) return null;
  try {
    return messageFromJson(JSON.parse(trimmed)) ?? trimmed;
  } catch {
    // Not JSON — the body is already plain text.
    return trimmed;
  }
}

function messageFromJson(value: unknown): string | null {
  if (value == null) return null;
  if (typeof value === 'string') return value.trim() || null;
  if (typeof value !== 'object') return String(value);
  const obj = value as Record<string, unknown>;
  // Ordered by usefulness: the specific message (`message`/`details`/`detail`)
  // wins over the short `error` label the surface API pairs with `details`.
  for (const candidate of [obj.message, obj.details, obj.detail, obj.error, obj.msg, obj.reason]) {
    if (typeof candidate === 'string' && candidate.trim()) return candidate.trim();
    if (
      candidate &&
      typeof candidate === 'object' &&
      typeof (candidate as { message?: unknown }).message === 'string' &&
      (candidate as { message: string }).message.trim()
    ) {
      return (candidate as { message: string }).message.trim();
    }
  }
  return null;
}

/**
 * Compose the string shown to the user: the extracted body message (falling
 * back to the status text, then a generic label) with the HTTP status in
 * parentheses.
 */
export function formatApiError(
  status: number | undefined,
  body: string | null | undefined,
  statusText?: string
): string {
  const message = extractErrorMessage(body) || (statusText || '').trim() || 'Request failed';
  return status ? `${message} (${status})` : message;
}

/**
 * Extract a human-readable message from a value thrown by a failed request.
 *
 * `apiClient` rejects with a plain `Error` whose `message` is already the
 * formatted backend message (see `formatApiError` / the api client), so
 * `err.message` is the primary source. Axios-shaped errors (`err.response.data`)
 * are handled defensively so callers don't silently fall back to a generic
 * label. Always prefer this over reading `err.response?.data?.message` directly,
 * which is `undefined` for the plain `Error`s this client throws.
 */
export function getErrorMessage(err: unknown, fallback = 'Request failed'): string {
  if (err instanceof Error && err.message.trim()) return err.message.trim();
  const anyErr = err as { message?: unknown; response?: { data?: unknown } } | null | undefined;
  if (typeof anyErr?.message === 'string' && anyErr.message.trim()) return anyErr.message.trim();
  const data = anyErr?.response?.data;
  if (data != null) {
    const fromData = extractErrorMessage(typeof data === 'string' ? data : JSON.stringify(data));
    if (fromData) return fromData;
  }
  return fallback;
}
