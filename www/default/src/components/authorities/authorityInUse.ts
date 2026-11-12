import { ApiError } from '../../api';

export type AuthorityUsePlacement = 'access_point' | 'target' | 'transit_point';

/** One Trust Check or Trust Recorder entry that names the Authority. */
export interface AuthorityUse {
  element: 'trust_check' | 'trust_recorder';
  id?: string;
  name?: string;
  placement?: AuthorityUsePlacement;
  transitPoint?: string;
  variant?: string;
  trustRegistryId?: string;
}

/** A surface or STS client the caller may view, with what in it uses the Authority. */
export interface AuthorityReference {
  kind: 'surface' | 'sts_client';
  id: string;
  name?: string;
  uses: AuthorityUse[];
}

/** The `409` body of `DELETE /authorities/{id}` while something uses the Authority. */
export interface AuthorityInUse {
  references: AuthorityReference[];
  /** Users of the Authority the caller may not view. */
  hiddenReferences: number;
}

const PLACEMENTS: readonly AuthorityUsePlacement[] = ['access_point', 'target', 'transit_point'];

const text = (value: unknown): string | undefined =>
  typeof value === 'string' && value.trim() ? value : undefined;

function readUse(raw: any): AuthorityUse | null {
  if (raw?.element !== 'trust_check' && raw?.element !== 'trust_recorder') return null;
  return {
    element: raw.element,
    id: text(raw.id),
    name: text(raw.name),
    placement: PLACEMENTS.includes(raw.placement) ? raw.placement : undefined,
    transitPoint: text(raw.transit_point),
    variant: text(raw.variant),
    trustRegistryId: text(raw.trust_registry_id),
  };
}

function readReference(raw: any): AuthorityReference | null {
  if (raw?.kind !== 'surface' && raw?.kind !== 'sts_client') return null;
  const id = text(raw.id);
  if (!id) return null;
  const uses = Array.isArray(raw.uses)
    ? raw.uses.map(readUse).filter((u: AuthorityUse | null): u is AuthorityUse => u !== null)
    : [];
  return { kind: raw.kind, id, name: text(raw.name), uses };
}

/**
 * The surfaces and STS clients a refused Authority delete names, or null when the error is not
 * that `409`.
 */
export function authorityInUse(error: unknown): AuthorityInUse | null {
  if (!(error instanceof ApiError) || error.status !== 409 || !error.body) return null;
  let body: any;
  try {
    body = JSON.parse(error.body);
  } catch {
    return null;
  }
  if (!body || !Array.isArray(body.references)) return null;
  const hidden = Number(body.hidden_references);
  return {
    references: body.references
      .map(readReference)
      .filter((r: AuthorityReference | null): r is AuthorityReference => r !== null),
    hiddenReferences: Number.isInteger(hidden) && hidden > 0 ? hidden : 0,
  };
}

const PLACEMENT_TEXT: Record<AuthorityUsePlacement, string> = {
  access_point: 'on the Access Point',
  target: "on the Managed Agent's target",
  transit_point: 'on a Transit Point',
};

/** One line naming a use, for example "Trust Check “Agent recognised” on the Access Point". */
export function describeAuthorityUse(
  use: AuthorityUse,
  registryName: (id: string) => string
): string {
  const parts: string[] = [];
  if (use.element === 'trust_recorder') {
    parts.push(
      use.trustRegistryId
        ? `Trust Recorder entry for ${registryName(use.trustRegistryId)}`
        : 'Trust Recorder entry'
    );
  } else {
    parts.push(use.name ? `Trust Check “${use.name}”` : 'Trust Check');
    if (use.placement === 'transit_point' && use.transitPoint) {
      parts.push(`on Transit Point ${use.transitPoint}`);
    } else if (use.placement) {
      parts.push(PLACEMENT_TEXT[use.placement]);
    }
  }
  if (use.variant) parts.push(`in variant ${use.variant}`);
  return parts.join(' ');
}
