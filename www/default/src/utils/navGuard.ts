/**
 * Cross-component navigation guard for in-app (SPA) link clicks.
 *
 * React Router 6 in BrowserRouter mode does not expose `useBlocker`,
 * and we only need to gate a handful of explicit nav surfaces
 * (sidebar, header, brand button). Pages that own unsaved state
 * register a predicate via `setNavGuard`; nav surfaces ask
 * `runNavGuard()` from their click handlers and `preventDefault` /
 * skip `navigate(...)` when it returns false.
 */

export type NavGuard = () => boolean;

let activeGuard: NavGuard | null = null;

export function setNavGuard(guard: NavGuard | null): void {
  activeGuard = guard;
}

/** Returns true when navigation may proceed, false to cancel. */
export function runNavGuard(): boolean {
  if (!activeGuard) return true;
  try {
    return activeGuard();
  } catch {
    return true;
  }
}
