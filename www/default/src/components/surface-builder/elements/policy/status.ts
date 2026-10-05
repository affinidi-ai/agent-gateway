// Status helpers for the surface-builder Policy node. Kept separate from the
// heavy D3 canvas so the predicate can be unit-tested in isolation.

// Dotted stroke used for a policy node that is not configured (no policy
// selected, or the attached policy definition no longer exists among surface
// policies). Distinct from the solid incomplete ring and the "6 4"
// marching-ants feature-error ring.
export const POLICY_UNCONFIGURED_DASH = '2 3';
export const POLICY_DEFINITION_MISSING_REASON = 'Policy no longer configured';
export const POLICY_DEFINITIONS_LOADING_REASON = 'Policy definitions are still loading';
export const POLICY_DEFINITIONS_LOAD_FAILED_REASON = 'Policy definitions could not be loaded';

export type SurfacePolicyDefinitionLoadState =
  | { status: 'loading'; ids: null; error?: null }
  | { status: 'loaded'; ids: Set<string>; error?: null }
  | { status: 'error'; ids: null; error: string };

/** Minimal shape of a canvas node the policy-status predicates read. */
type PolicyNodeLike = { type: string; config?: { policy_definition_id?: string } | null };

/**
 * Reason to block Save while the surface-policy id set is not yet usable.
 *
 * Only the transient `loading` state blocks — it is short-lived and blocking
 * avoids a race where Save runs the missing-policy check against a `null` set.
 * A load `error` does NOT block: the backend validates policy references on
 * save (definition-backed), so a flaky secondary GET must not trap the user on
 * an otherwise-valid surface. The error is surfaced non-blockingly instead via
 * `policyDefinitionsWarning`.
 */
export function policyDefinitionsBlockingReason(
  state: SurfacePolicyDefinitionLoadState
): string | null {
  if (state.status === 'loading') return POLICY_DEFINITIONS_LOADING_REASON;
  return null;
}

/**
 * Non-blocking notice shown when the surface-policy id set could not be loaded
 * and the surface actually references a policy definition. Tells the user the
 * "policy no longer configured" check was skipped; the backend still validates
 * on save. Returns `null` when there is nothing to warn about.
 */
export function policyDefinitionsWarning(
  state: SurfacePolicyDefinitionLoadState,
  hasReference: boolean
): string | null {
  if (!hasReference || state.status !== 'error') return null;
  const detail = state.error.trim();
  return detail
    ? `${POLICY_DEFINITIONS_LOAD_FAILED_REASON}: ${detail}`
    : POLICY_DEFINITIONS_LOAD_FAILED_REASON;
}

export function hasPolicyDefinitionReference(nodes: PolicyNodeLike[]): boolean {
  return nodes.some(n => n.type === 'policy' && Boolean(n.config?.policy_definition_id));
}

/**
 * Combined Save-gating reason for the surface-policy definition set: returns a
 * blocking reason only when the surface actually references a policy definition
 * AND the id set is still loading. Wraps `hasPolicyDefinitionReference` +
 * `policyDefinitionsBlockingReason` so `AddSurfacePage` / `SurfaceDetailPage`
 * don't repeat the guard at each Save-gate site. Returns `null` when Save need
 * not be blocked on this account (no reference, loaded, or load error — the
 * error path is surfaced non-blockingly via `policyDefinitionsWarning`).
 */
export function surfacePolicyBlockingReason(
  nodes: PolicyNodeLike[],
  state: SurfacePolicyDefinitionLoadState
): string | null {
  return hasPolicyDefinitionReference(nodes) ? policyDefinitionsBlockingReason(state) : null;
}

/**
 * True when a policy node points at a policy definition that no longer exists
 * among the surface (`agent_surface`) policies — e.g. the definition was
 * deleted, or its type was changed to Gateway so it dropped out of the
 * surface-policy list.
 *
 * An empty `policy_definition_id` is NOT reported here (that is already covered
 * by the node's `incompleteReason`). While the surface-policy id set is still
 * loading (`null`), nothing is reported missing, so an attached policy is never
 * falsely flagged before the list arrives.
 */
export function policyDefinitionMissing(
  node: PolicyNodeLike,
  surfacePolicyIds: Set<string> | null
): boolean {
  if (node.type !== 'policy') return false;
  const id = node.config?.policy_definition_id;
  if (!id) return false;
  return surfacePolicyIds !== null && !surfacePolicyIds.has(id);
}

export function policyDefinitionMissingReason(
  node: PolicyNodeLike,
  surfacePolicyIds: Set<string> | null
): string | null {
  return policyDefinitionMissing(node, surfacePolicyIds) ? POLICY_DEFINITION_MISSING_REASON : null;
}
