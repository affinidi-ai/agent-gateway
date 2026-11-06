import type { ApiKeyReference, ApiKeyReferenceStatus } from '../../../../api';
import type { DependencyNode } from '../types';
import { isInboundIdentity } from './placement';

/** Status of each API key the stored surface names, by key id. */
export type ApiKeyStatuses = ReadonlyMap<string, ApiKeyReferenceStatus>;

/** Statuses that leave an Identity unconfigured. */
export type UnusableApiKeyStatus = Extract<
  ApiKeyReferenceStatus,
  'revoked' | 'missing' | 'unavailable'
>;

const WARNINGS: Record<UnusableApiKeyStatus, string> = {
  revoked: 'The API key this Identity uses was revoked. Select an active API key of this surface.',
  missing: 'The API key this Identity uses was deleted. Select an active API key of this surface.',
  unavailable: 'The API key this Identity uses belongs to another surface.',
};

const LABELS: Record<UnusableApiKeyStatus, string> = {
  revoked: 'revoked',
  missing: 'deleted',
  unavailable: 'belongs to another surface',
};

const CANVAS_REASONS: Record<UnusableApiKeyStatus, string> = {
  revoked: 'API key revoked',
  missing: 'API key deleted',
  unavailable: 'API key of another surface',
};

export function apiKeyStatusMap(references?: readonly ApiKeyReference[] | null): ApiKeyStatuses {
  return new Map((references ?? []).map(r => [r.key_id, r.status]));
}

/** The status of a stored key id when it leaves the Identity unconfigured, else null. */
export function unusableApiKeyStatus(
  keyId: string | undefined,
  statuses: ApiKeyStatuses | null | undefined
): UnusableApiKeyStatus | null {
  if (!keyId || !statuses) return null;
  const status = statuses.get(keyId);
  return status === 'revoked' || status === 'missing' || status === 'unavailable' ? status : null;
}

type IdentityNodeLike = Pick<DependencyNode, 'id' | 'slotId'> & {
  type: string;
  config?: { type?: unknown; api_key_id?: unknown } | null;
};

/**
 * The unusable status of the key a protected, external or Transit Point From
 * API Key Identity names, else null.
 */
function identityApiKeyProblem(
  node: IdentityNodeLike,
  statuses: ApiKeyStatuses | null | undefined
): UnusableApiKeyStatus | null {
  if (node.type !== 'identity' || isInboundIdentity(node)) return null;
  if (node.config?.type !== 'from_api_key') return null;
  const keyId = node.config.api_key_id;
  return unusableApiKeyStatus(typeof keyId === 'string' ? keyId : undefined, statuses);
}

/** Full warning for an Identity whose stored key was revoked, deleted or belongs to another surface. */
export function apiKeyReferenceWarning(
  node: IdentityNodeLike,
  statuses: ApiKeyStatuses | null | undefined
): string | null {
  const status = identityApiKeyProblem(node, statuses);
  return status ? WARNINGS[status] : null;
}

/** The first Identity whose stored key was revoked, deleted or belongs to another surface, with its warning. */
export function firstUnusableApiKeyIdentity<T extends IdentityNodeLike>(
  nodes: readonly T[],
  statuses: ApiKeyStatuses | null | undefined
): { node: T; warning: string } | null {
  for (const node of nodes) {
    const warning = apiKeyReferenceWarning(node, statuses);
    if (warning) return { node, warning };
  }
  return null;
}

export function apiKeyReferenceWarningText(status: UnusableApiKeyStatus): string {
  return WARNINGS[status];
}

/** Short reason shown under the Identity's label on the canvas. */
export function apiKeyReferenceCanvasReason(
  node: IdentityNodeLike,
  statuses: ApiKeyStatuses | null | undefined
): string | null {
  const status = identityApiKeyProblem(node, statuses);
  return status ? CANVAS_REASONS[status] : null;
}

/** Picker label of a stored key, by name or id, that is not among the surface's active keys. */
export function unlistedApiKeyLabel(keyName: string, status: UnusableApiKeyStatus | null): string {
  return `${keyName} (${status ? LABELS[status] : 'not an active key of this surface'})`;
}
