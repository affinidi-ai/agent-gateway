import type { AuthoritySource } from '../../../../types';

/**
 * DIDs of the Authorities register once it has loaded; `null` or `undefined` while it loads or
 * after it could not be loaded, so nothing is reported missing then.
 */
export type AuthorityDids = ReadonlySet<string> | null | undefined;

/** One trust anchor that names an Authority the register no longer has. */
export interface MissingAuthority {
  /** Position of the query or entry in its list. */
  index: number;
  did: string;
}

const SOURCES: readonly AuthoritySource[] = ['authority', 'issuer'];

export function isTemplateValue(value: string): boolean {
  return value.includes('{{');
}

/**
 * The `authority_source` kept beside an anchor value: a known source beside a literal DID, and
 * nothing beside an empty value or a template, which the gateway refuses.
 */
export function authoritySourceFor(value: unknown, source: unknown): AuthoritySource | undefined {
  if (typeof value !== 'string') return undefined;
  const did = value.trim();
  if (!did || isTemplateValue(did)) return undefined;
  return SOURCES.includes(source as AuthoritySource) ? (source as AuthoritySource) : undefined;
}

/**
 * The DID of an anchor picked from the Authorities register when the loaded register no longer
 * has it, else null.
 */
export function missingAuthorityDid(
  value: unknown,
  source: unknown,
  authorityDids: AuthorityDids
): string | null {
  if (!authorityDids || authoritySourceFor(value, source) !== 'authority') return null;
  const did = (value as string).trim();
  return authorityDids.has(did) ? null : did;
}

export function authorityDidSet(authorities: ReadonlyArray<{ did: string }>): ReadonlySet<string> {
  return new Set(authorities.map(a => a.did));
}

/** Short reason shown under a Trust Check or Trust Recorder node on the canvas. */
export const MISSING_AUTHORITY_CANVAS_REASON = 'Authority deleted';
