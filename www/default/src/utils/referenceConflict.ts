export type ReferenceKind = 'surface' | 'credential_provider' | 'a2a_proxy' | 'sts_client';

export interface ConflictReference {
  kind: string;
  id: string;
  name: string;
}

/** A 409 that names what still uses the thing being deleted or retyped. */
export interface ReferenceConflict {
  message: string;
  references: ConflictReference[];
  hiddenReferences: number;
}

const KIND_LABELS: Record<ReferenceKind, string> = {
  surface: 'Surface',
  credential_provider: 'Credential provider',
  a2a_proxy: 'A2A proxy',
  sts_client: 'STS client',
};

export function referenceKindLabel(kind: string): string {
  return KIND_LABELS[kind as ReferenceKind] ?? kind;
}

/**
 * The reference list of a 409 response body, or null when the body has none (an integration
 * endpoint's 409 carries only a message).
 */
export function parseReferenceConflict(
  status: number,
  body: string | null | undefined
): ReferenceConflict | null {
  if (status !== 409) return null;
  let data: unknown;
  try {
    data = JSON.parse(body ?? '');
  } catch {
    return null;
  }
  if (!data || typeof data !== 'object') return null;
  const { message, references, hidden_references } = data as Record<string, unknown>;
  if (!Array.isArray(references)) return null;
  const named = references.flatMap((entry): ConflictReference[] => {
    if (!entry || typeof entry !== 'object') return [];
    const { kind, id, name } = entry as Record<string, unknown>;
    return typeof kind === 'string' && typeof id === 'string'
      ? [{ kind, id, name: typeof name === 'string' && name ? name : id }]
      : [];
  });
  const hidden = typeof hidden_references === 'number' ? hidden_references : 0;
  if (named.length === 0 && hidden === 0) return null;
  return {
    message: typeof message === 'string' ? message : 'The item is in use',
    references: named,
    hiddenReferences: hidden,
  };
}
