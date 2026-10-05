/**
 * Placeholder engine for full-kind surface templates.
 *
 * Full templates ship a verbatim `channel` snapshot (same shape as
 * what `createChannel` accepts). To keep them reusable, string fields
 * inside that snapshot may contain placeholder tokens like `$HOST` or
 * `$TARGET_ENDPOINT`. When the user applies the template we substitute
 * tokens with concrete values supplied by the apply flow (CLI/UX).
 *
 * Design notes:
 * - Pure TypeScript, no server involvement. The Rust side treats
 *   `channel` as opaque `serde_json::Value` (Option A from the design
 *   discussion).
 * - Substring substitution (not whole-string match) so values like
 *   `"$HOST/admin"` work.
 * - Tokens are case-sensitive and start with `$` followed by uppercase
 *   ASCII / underscore characters.
 * - Unknown tokens (no value in context) are left untouched and
 *   reported in `missing` so the UI can prompt the user.
 */

export const PLACEHOLDER_TOKENS = [
  '$HOST',
  '$ROUTE',
  '$NAME',
  '$SLUG',
  '$TARGET_ENDPOINT',
] as const;

export type PlaceholderToken = (typeof PLACEHOLDER_TOKENS)[number];

export interface PlaceholderContext {
  host?: string;
  route?: string;
  name?: string;
  slug?: string;
  targetEndpoint?: string;
}

export interface PlaceholderResult<T = unknown> {
  /** Resolved value with substitutions applied. */
  value: T;
  /** Tokens that appeared in the input but had no value in the context. */
  missing: PlaceholderToken[];
}

const TOKEN_TO_CONTEXT_KEY: Record<PlaceholderToken, keyof PlaceholderContext> = {
  $HOST: 'host',
  $ROUTE: 'route',
  $NAME: 'name',
  $SLUG: 'slug',
  $TARGET_ENDPOINT: 'targetEndpoint',
};

/**
 * Canonical token → context-key mapping. Exported so callers like
 * the create-form's `tokenizeSnapshot` and the apply modal's input
 * binder do not have to maintain parallel tables (which silently
 * drift when a new token is added).
 */
export { TOKEN_TO_CONTEXT_KEY };

// Matches any of the known tokens. Anchored to a `$` followed by
// uppercase / underscore so `$HOSTNAME` does not partially match `$HOST`.
const TOKEN_RE = /\$[A-Z_]+/g;

function isKnownToken(raw: string): raw is PlaceholderToken {
  return (PLACEHOLDER_TOKENS as readonly string[]).includes(raw);
}

function substituteString(
  input: string,
  ctx: PlaceholderContext,
  missing: Set<PlaceholderToken>
): string {
  return input.replace(TOKEN_RE, match => {
    if (!isKnownToken(match)) return match;
    const key = TOKEN_TO_CONTEXT_KEY[match];
    const value = ctx[key];
    if (value === undefined || value === null || value === '') {
      missing.add(match);
      return match;
    }
    return value;
  });
}

function walk(node: unknown, ctx: PlaceholderContext, missing: Set<PlaceholderToken>): unknown {
  if (typeof node === 'string') {
    return substituteString(node, ctx, missing);
  }
  if (Array.isArray(node)) {
    return node.map(entry => walk(entry, ctx, missing));
  }
  if (node && typeof node === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      out[k] = walk(v, ctx, missing);
    }
    return out;
  }
  return node;
}

/**
 * Deep-walk `payload` and replace placeholder tokens in every string
 * (including object keys' values and array entries). Returns the new
 * value and a sorted list of tokens that had no binding in `ctx`.
 *
 * The input is never mutated.
 */
export function applyPlaceholders<T = unknown>(
  payload: T,
  ctx: PlaceholderContext
): PlaceholderResult<T> {
  const missing = new Set<PlaceholderToken>();
  const value = walk(payload, ctx, missing) as T;
  return {
    value,
    missing: Array.from(missing).sort() as PlaceholderToken[],
  };
}

/**
 * Scan `payload` for every known placeholder token without substituting
 * anything. Useful for the apply UX to know which inputs to prompt for.
 */
export function findPlaceholders(payload: unknown): PlaceholderToken[] {
  const found = new Set<PlaceholderToken>();
  const visit = (node: unknown): void => {
    if (typeof node === 'string') {
      const matches = node.match(TOKEN_RE);
      if (matches) {
        for (const m of matches) {
          if (isKnownToken(m)) found.add(m);
        }
      }
      return;
    }
    if (Array.isArray(node)) {
      node.forEach(visit);
      return;
    }
    if (node && typeof node === 'object') {
      Object.values(node as Record<string, unknown>).forEach(visit);
    }
  };
  visit(payload);
  return Array.from(found).sort() as PlaceholderToken[];
}

/**
 * Second-pass cleanup: strip any remaining known placeholder tokens
 * from string fields so downstream validators see empty strings (and
 * report "X is required") instead of literal `$NAME` / `$TARGET_ENDPOINT`
 * values leaking onto the canvas.
 *
 * Use after `applyPlaceholders` when the apply flow auto-fills only a
 * subset of tokens and wants the rest to fall through to the form
 * validator rather than prompting the user up front.
 */
export function clearUnresolvedTokens<T = unknown>(payload: T): T {
  const walk = (node: unknown): unknown => {
    if (typeof node === 'string') {
      // Replace every known-token occurrence with empty string. Unknown
      // `$XXX` sequences are left alone so they don't silently mask
      // typos in user-authored snapshots.
      return node.replace(TOKEN_RE, m => (isKnownToken(m) ? '' : m));
    }
    if (Array.isArray(node)) return node.map(walk);
    if (node && typeof node === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        out[k] = walk(v);
      }
      return out;
    }
    return node;
  };
  return walk(payload) as T;
}
