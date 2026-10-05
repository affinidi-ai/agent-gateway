/**
 * tokenizeSnapshot — prepare a live `AgentSurface` payload for being
 * saved as a `kind: 'full'` template. Replaces a small fixed set of
 * scalar fields with the placeholder tokens recognised by
 * {@link applyFullSurfaceTemplate}:
 *
 *   - top-level `name`                  → `$NAME`
 *   - `access_point.listen_address`     → `$HOST`
 *   - `access_point.route`              → `$ROUTE`
 *   - `target.endpoint`                 → `$TARGET_ENDPOINT`
 *
 * Transit points have no scalar token vocabulary, so their volatile
 * listener / identity fields are blanked via
 * {@link scrubVolatileTemplateFields} (always, regardless of the
 * `tokenizeNamedFields` flag) and a count is returned so the UI can
 * report it. Gateway-runtime top-level keys are stripped too.
 *
 * Pure function; idempotent (re-tokenizing a token leaves it alone).
 */

import { TOKEN_TO_CONTEXT_KEY, type PlaceholderContext } from './placeholders';
import { scrubVolatileTemplateFields } from './scrubVolatile';

export type TokenizableSurface = Record<string, any>;

export interface TokenizeResult {
  surface: TokenizableSurface;
  /** Tokens introduced, sorted. */
  applied: string[];
  /** Transit points whose listener / identity fields were cleared. */
  clearedTransitPoints: number;
}

const STRIPPED_TOP_LEVEL: ReadonlyArray<string> = ['surface_id', 'last_activity', 'agent_did'];

const REPLACEMENTS: ReadonlyArray<{
  path: string[];
  token: keyof typeof TOKEN_TO_CONTEXT_KEY;
}> = [
  { path: ['name'], token: '$NAME' },
  { path: ['access_point', 'listen_address'], token: '$HOST' },
  { path: ['access_point', 'route'], token: '$ROUTE' },
  { path: ['target', 'endpoint'], token: '$TARGET_ENDPOINT' },
];

// Compile-time guard: every token we replace must be a known context key.
const _CONTEXT_KEY_CHECK: PlaceholderContext = {};
void _CONTEXT_KEY_CHECK;

function getAt(obj: any, path: string[]): unknown {
  let cur: any = obj;
  for (const seg of path) {
    if (cur == null || typeof cur !== 'object') return undefined;
    cur = cur[seg];
  }
  return cur;
}

function setAt(obj: Record<string, any>, path: string[], value: unknown): void {
  let cur: any = obj;
  for (let i = 0; i < path.length - 1; i++) {
    const seg = path[i];
    if (cur[seg] == null || typeof cur[seg] !== 'object') {
      cur[seg] = {};
    }
    cur = cur[seg];
  }
  cur[path[path.length - 1]] = value;
}

export interface TokenizeOptions {
  /** When false, skip AP-level token substitutions; TP scrub + top-level
   *  strip still run. Defaults to `true`. */
  tokenizeNamedFields?: boolean;
}

export function tokenizeSnapshot(
  input: TokenizableSurface,
  options: TokenizeOptions = {}
): TokenizeResult {
  const { tokenizeNamedFields = true } = options;
  // Count TPs with any volatile listener / identity field set BEFORE
  // we scrub — so the UI can report "3 transit-point listener paths
  // cleared" rather than just silently dropping them.
  const clearedTransitPoints = countTransitPointsWithListenerFields(input);
  // Structured clone + scrub volatile per-surface fields (transit
  // points, canvas listener mirrors) so the saved template can be
  // re-applied to many surfaces without collision.
  const out: TokenizableSurface = scrubVolatileTemplateFields(
    JSON.parse(JSON.stringify(input ?? {}))
  );
  for (const key of STRIPPED_TOP_LEVEL) {
    delete out[key];
  }
  const applied = new Set<string>();
  if (!tokenizeNamedFields) {
    return { surface: out, applied: [], clearedTransitPoints };
  }
  for (const { path, token } of REPLACEMENTS) {
    const existing = getAt(out, path);
    if (typeof existing !== 'string') continue;
    if (existing === '') continue;
    if (existing === token) {
      // Already tokenized — count it as applied so the UI doesn't
      // mislead the user into thinking nothing happened, but don't
      // re-write.
      applied.add(token);
      continue;
    }
    setAt(out, path, token);
    applied.add(token);
  }
  return {
    surface: out,
    applied: Array.from(applied).sort(),
    clearedTransitPoints,
  };
}

function countTransitPointsWithListenerFields(input: unknown): number {
  if (!input || typeof input !== 'object') return 0;
  const transit = (input as Record<string, unknown>).transit;
  if (!transit || typeof transit !== 'object') return 0;
  const points = (transit as Record<string, unknown>).points;
  if (!Array.isArray(points)) return 0;
  let n = 0;
  for (const tp of points) {
    if (!tp || typeof tp !== 'object') continue;
    const t = tp as Record<string, unknown>;
    if (
      (typeof t.listen_address === 'string' && t.listen_address) ||
      (typeof t.listen_path === 'string' && t.listen_path) ||
      (typeof t.id === 'string' && t.id) ||
      (typeof t.alias === 'string' && t.alias)
    ) {
      n++;
    }
  }
  return n;
}
