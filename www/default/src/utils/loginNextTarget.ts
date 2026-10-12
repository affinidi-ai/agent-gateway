import { ROUTES } from '../routes';

export const CLI_AUTHORIZE_PATH = '/api/auth/cli/authorize';

const ALLOWED_CHARACTERS = /^[A-Za-z0-9\-_./?&=%~:+]+$/;
const ENCODED_SLASH_OR_BACKSLASH = /%2f|%5c/i;
const MAX_TARGET_LENGTH = 1024;

/**
 * Returns the post-login return target rebuilt from its validated parts, or null. Only the
 * dashboard root, the new access token form with or without its preset query, and the CLI
 * authorize path with a query are allowed, and the path may not hold an encoded slash or
 * backslash. The query may, since the CLI `state` is opaque. The gateway applies the same rule to
 * the SAML return target.
 */
export function safeNextTarget(next: string | null, origin: string): string | null {
  if (
    !next ||
    next.length > MAX_TARGET_LENGTH ||
    !ALLOWED_CHARACTERS.test(next) ||
    ENCODED_SLASH_OR_BACKSLASH.test(next.split('?', 1)[0]) ||
    !next.startsWith('/') ||
    next.startsWith('//')
  ) {
    return null;
  }
  let resolved: URL;
  try {
    resolved = new URL(next, origin);
  } catch {
    return null;
  }
  if (resolved.origin !== origin) {
    return null;
  }
  if (resolved.pathname === ROUTES.DASHBOARD && resolved.search === '') {
    return ROUTES.DASHBOARD;
  }
  if (resolved.pathname === ROUTES.ACCESS_TOKEN_NEW) {
    return `${resolved.pathname}${resolved.search}`;
  }
  if (resolved.pathname === CLI_AUTHORIZE_PATH && resolved.search.length > 1) {
    return `${resolved.pathname}${resolved.search}`;
  }
  return null;
}

/**
 * The query of `search` re-encoded so every value is percent-encoded, including the `*` and `,`
 * that links commonly carry raw and `safeNextTarget` rejects.
 */
function canonicalQuery(search: string): string {
  const query = new URLSearchParams(search).toString().replace(/\*/g, '%2A');
  return query ? `?${query}` : '';
}

/**
 * The return target for the login page at `location`: its `?next=` when present; when the
 * signed-out user opened the CLI consent page, the CLI authorize path with the consent query, so
 * the CLI login continues after sign-in; or, when they opened a new access token link, that form
 * with its preset query. Either way the target passes `safeNextTarget`.
 */
export function loginNextTarget(
  location: Pick<Location, 'pathname' | 'search' | 'origin'>
): string | null {
  const next = new URLSearchParams(location.search).get('next');
  if (next !== null) {
    return safeNextTarget(next, location.origin);
  }
  if (location.pathname === ROUTES.CLI_CONSENT) {
    return safeNextTarget(`${CLI_AUTHORIZE_PATH}${location.search}`, location.origin);
  }
  if (location.pathname === ROUTES.ACCESS_TOKEN_NEW) {
    return safeNextTarget(
      `${ROUTES.ACCESS_TOKEN_NEW}${canonicalQuery(location.search)}`,
      location.origin
    );
  }
  return null;
}
