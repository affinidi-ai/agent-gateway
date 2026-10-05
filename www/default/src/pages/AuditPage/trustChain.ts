import { decodeJwtPayload } from '../../components/shared/VpViewer';
import { trustCheck } from './auditHelpers';
import { trustErrorClause } from './eventNarrative';
import { signedVpEntry } from './evidence';
import type { AuditEntry } from './types';

export type TrustRungKind = 'root' | 'authority' | 'provider';

export interface TrustRung {
  kind: TrustRungKind;
  /** Role label, e.g. "Root of trust", "caller trust check", "Credential provider". */
  role: string;
  /** Resolved human-readable name (or a relationship phrase). */
  title: string;
  /** Verdict for recognition rungs. */
  ok?: boolean;
  /** Supporting line — a truncated DID, fingerprint, or failure reason. */
  detail?: string;
}

/** Name resolver: DID → human-readable name, with a caller-supplied fallback. */
export type NameResolver = (did: string | null | undefined) => string;

/**
 * Builds the root-of-trust ladder for a request from its correlated events:
 * the trust-check recognition edges (authority → entity), the credential
 * provider, and the signing gateway as the base anchor. DIDs are humanised via
 * the injected `resolveName` (see `useDidNames`). Pure and order-stable.
 */
export function buildTrustChain(siblings: AuditEntry[], resolveName: NameResolver): TrustRung[] {
  const rungs: TrustRung[] = [];
  const seen = new Set<string>();

  // Recognition edges — one rung per distinct trust-check leg. Skip
  // events that don't carry both endpoints (the target-leg
  // "unavailable" paths — `AGENT_CARD_UNAVAILABLE`,
  // `TRUST_REGISTRY_METADATA_UNAVAILABLE` — omit `authority_id` /
  // `entity_id`, and a rung with an empty side would be meaningless).
  for (const entry of siblings) {
    const tc = trustCheck(entry);
    if (!tc) continue;
    if (!tc.authority_id || !tc.entity_id) continue;
    const key = `${tc.leg}:${tc.authority_id}:${tc.entity_id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    rungs.push({
      kind: 'authority',
      role: `${tc.leg} trust check`,
      title: `${resolveName(tc.authority_id)} → ${resolveName(tc.entity_id)}`,
      ok: tc.ok,
      detail: tc.ok
        ? undefined
        : (trustErrorClause(tc.error_code, tc.leg) ?? 'verification failed'),
    });
  }

  // Credential provider (already human-readable on the event).
  const provider = siblings.find(e => e.provider_name || e.provider_id);
  if (provider && (provider.provider_name || provider.provider_id)) {
    rungs.push({
      kind: 'provider',
      role: 'Credential provider',
      title: String(provider.provider_name ?? provider.provider_id),
    });
  }

  // Root of trust — the gateway that signed the VP.
  const signed = signedVpEntry(siblings);
  if (signed?.vp_jwt) {
    const issuer = issuerOf(signed.vp_jwt);
    if (issuer) {
      rungs.push({
        kind: 'root',
        role: 'Root of trust — signed by',
        title: resolveName(issuer),
        detail: signed.vp_fingerprint ?? undefined,
      });
    }
  }

  return rungs;
}

/** The `iss` (issuer DID) of a decoded VP JWT, if present. */
function issuerOf(vpJwt: string): string | null {
  const payload = decodeJwtPayload(vpJwt);
  const iss = payload?.iss;
  return typeof iss === 'string' && iss ? iss : null;
}

/** True when the request left no chain-of-trust signals worth rendering. */
export function isEmptyTrustChain(rungs: TrustRung[]): boolean {
  return rungs.length === 0;
}
