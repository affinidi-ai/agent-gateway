import { ROUTES } from '../routes';

export const CLI_AUTHORIZE_PATH = '/api/auth/cli/authorize';

const ALLOWED_CHARACTERS = /^[A-Za-z0-9\-_./?&=%~:+]+$/;
const ENCODED_SLASH_OR_BACKSLASH = /%2f|%5c/i;
const MAX_TARGET_LENGTH = 1024;

/**
 * Returns the post-login return target rebuilt from its validated parts, or null. Only the
 * dashboard root and the CLI authorize path with a query are allowed, and the path may not hold an
 * encoded slash or backslash. The query may, since the CLI `state` is opaque. The gateway applies
 * the same rule to the SAML return target.
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
  if (resolved.pathname === CLI_AUTHORIZE_PATH && resolved.search.length > 1) {
    return `${resolved.pathname}${resolved.search}`;
  }
  return null;
}
