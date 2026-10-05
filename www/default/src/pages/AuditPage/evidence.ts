import { eventTypeName } from './auditHelpers';
import type { AuditEntry } from './types';

/**
 * Every entry that belongs to the same request as `entry`, i.e. shares its
 * `trace_id`. Falls back to just `[entry]` when the entry has no trace id (so a
 * standalone event still renders its own evidence). Order is preserved.
 */
export function traceSiblings(entries: AuditEntry[], entry: AuditEntry): AuditEntry[] {
  if (!entry.trace_id) return [entry];
  const siblings = entries.filter(e => e.trace_id === entry.trace_id);
  return siblings.length > 0 ? siblings : [entry];
}

/** The VP-injected sibling carrying a signed presentation for the request, if any. */
export function signedVpEntry(siblings: AuditEntry[]): AuditEntry | null {
  return (
    siblings.find(e => e.vp_jwt) ??
    siblings.find(e => eventTypeName(e) === 'vp_injected' && e.vp_fingerprint) ??
    null
  );
}
