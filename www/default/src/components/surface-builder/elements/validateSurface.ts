/**
 * Structural validation of a built surface payload.
 *
 * Runs *after* `registry.buildPayload` and *before* the API call.
 * Per-node "incomplete reason" already covers field-level requirements
 * (handled by `computeBlockingReason` in the page); this layer catches
 * shape problems that only surface once individual element slices are
 * stitched together — typically empty endpoints, empty required
 * top-level metadata, and dangling references on the canvas blob.
 *
 * Issues are returned (never thrown) so callers can render them in the
 * UI. `error` severity should block save; `warning` should inform.
 */

import { registry } from './registry';

export type ValidationSeverity = 'error' | 'warning';

export interface ValidationIssue {
  severity: ValidationSeverity;
  message: string;
  /**
   * Optional canvas node id the issue is attached to. The save toast
   * uses this to offer a "Show me" jump action.
   */
  nodeId?: string;
  /**
   * Optional dot-notation payload path the issue is attached to. Used
   * by the JSON editor to highlight the offending slice.
   */
  path?: string;
}

/**
 * Validate the built payload. Cheap, side-effect-free, no async.
 */
export function validateSurfacePayload(payload: any): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  if (!payload || typeof payload !== 'object') {
    issues.push({ severity: 'error', message: 'Surface payload is missing or malformed.' });
    return issues;
  }

  // Surface-level metadata.
  if (typeof payload.name !== 'string' || payload.name.trim().length === 0) {
    issues.push({
      severity: 'error',
      message: 'Surface name is required.',
      path: 'name',
    });
  }

  // Target endpoint — required for any surface that proxies to an
  // upstream. Surfaces wired exclusively to NPCs (managed agents) may
  // legitimately leave this empty; we surface it as a warning so the
  // user notices but don't hard-block.
  const targetEndpoint = payload?.target?.endpoint;
  if (typeof targetEndpoint !== 'string' || targetEndpoint.trim().length === 0) {
    issues.push({
      severity: 'warning',
      message: 'Target endpoint is empty — requests cannot be proxied upstream.',
      nodeId: 'target',
      path: 'target.endpoint',
    });
  }

  // Transit points: each must declare a non-empty `target_endpoint`,
  // otherwise the runtime cannot route to its destination. Each must
  // also carry a URL-safe alias unique within the surface — the
  // backend rejects empty/malformed/duplicate aliases on save, so we
  // surface them as blocking errors here to give the user immediate
  // feedback rather than letting the API roundtrip fail.
  const tps: any[] = Array.isArray(payload?.transit?.points) ? payload.transit.points : [];
  const aliasPattern = /^[a-z][a-z0-9-]{0,62}$/;
  const seenAliases = new Map<string, number>();
  tps.forEach((tp, idx) => {
    const ep = tp?.target_endpoint;
    if (typeof ep !== 'string' || ep.trim().length === 0) {
      issues.push({
        severity: 'warning',
        message: `Transit point #${idx + 1} has no target endpoint — outbound traffic will not route.`,
        path: `transit.points.${idx}.target_endpoint`,
      });
    }
    const alias = typeof tp?.alias === 'string' ? tp.alias : '';
    if (alias.length === 0) {
      issues.push({
        severity: 'error',
        message: `Transit point #${idx + 1} is missing a required alias.`,
        path: `transit.points.${idx}.alias`,
      });
    } else if (!aliasPattern.test(alias)) {
      issues.push({
        severity: 'error',
        message: `Transit point #${idx + 1} alias "${alias}" must start with a lowercase letter and contain only lowercase letters, digits, and dashes.`,
        path: `transit.points.${idx}.alias`,
      });
    } else {
      const prior = seenAliases.get(alias);
      if (prior !== undefined) {
        issues.push({
          severity: 'error',
          message: `Transit point #${idx + 1} reuses alias "${alias}" already used by transit point #${prior + 1}.`,
          path: `transit.points.${idx}.alias`,
        });
      } else {
        seenAliases.set(alias, idx);
      }
    }
  });

  // Workload Binding: a Transit Point with an enabled binding must have a
  // managed-identity source capable of signing the VP. Mirrors the backend
  // `AgentSurface::has_managed_identity_source` (the same rule that returns
  // `WorkloadBindingSurfaceError::MissingManagedIdentity` and 400s the save):
  // the TP carries its own `managed_identity`, OR the surface has any
  // identity slot configured, OR a managed agent DID source is present.
  const hasIdentitySlot =
    !!payload?.identity_slots &&
    typeof payload.identity_slots === 'object' &&
    Object.keys(payload.identity_slots).length > 0;
  const hasAgentDidSource = !!payload?.target?.didwebvh_enabled;
  tps.forEach((tp, idx) => {
    const wb = tp?.workload_binding;
    if (!wb || typeof wb !== 'object' || wb.enabled !== true) return;
    const hasTpManagedIdentity =
      !!tp?.managed_identity &&
      typeof tp.managed_identity === 'object' &&
      Object.keys(tp.managed_identity).length > 0;
    if (!hasTpManagedIdentity && !hasIdentitySlot && !hasAgentDidSource) {
      issues.push({
        severity: 'error',
        message: `Transit point #${idx + 1} enables Workload Binding but has no managed-identity source to sign the VP — add a managed identity on this Transit Point, an Identity element, or enable a managed agent DID.`,
        path: `transit.points.${idx}.workload_binding`,
      });
    }
  });

  // Primary-target (MA→EXT) Workload Binding: same managed-identity
  // requirement, but the target leg has no per-TP `managed_identity`
  // fallback. Mirrors the backend `AgentSurface::has_target_managed_identity_source`
  // (returns `WorkloadBindingSurfaceError::TargetMissingManagedIdentity` and
  // 400s the save).
  {
    const targetWb = payload?.target?.workload_binding;
    if (
      targetWb &&
      typeof targetWb === 'object' &&
      targetWb.enabled === true &&
      !hasIdentitySlot &&
      !hasAgentDidSource
    ) {
      issues.push({
        severity: 'error',
        message:
          'The primary target enables Workload Binding but the surface has no managed-identity source to sign the VP — add an Identity element or enable a managed agent DID.',
        path: 'target.workload_binding',
      });
    }
  }

  // Canvas blob — dangling parent refs and obvious chain leaks.
  const canvasNodes: any[] = Array.isArray(payload?.canvas?.nodes) ? payload.canvas.nodes : [];
  if (canvasNodes.length > 0) {
    const ids = new Set(canvasNodes.map(n => n?.id).filter(id => typeof id === 'string'));
    for (const n of canvasNodes) {
      if (typeof n?.parentId === 'string' && n.parentId && !ids.has(n.parentId)) {
        issues.push({
          severity: 'warning',
          message: `Canvas node "${n.id}" references missing parent "${n.parentId}".`,
          nodeId: typeof n.id === 'string' ? n.id : undefined,
        });
      }
    }
    // The `target` anchor should not be parented to a node that
    // doesn't legitimately sit on the request chain. Edge-drop
    // middleware (payment, networking, custom-metadata, etc.) re-parent
    // the target onto themselves by design — that's how the chain
    // order is encoded in `parentId` for `deriveEdges` to recover.
    // We only warn when the parent is something genuinely unexpected
    // (e.g. an NPC, an off-chain node) so the watchdog still catches
    // real structural drift without crying wolf on the routine
    // chain-splice output.
    const target = canvasNodes.find(n => n?.id === 'target');
    if (
      target &&
      typeof target.parentId === 'string' &&
      target.parentId &&
      target.parentId !== 'access-point' &&
      target.parentId !== '__surface__'
    ) {
      const parent = canvasNodes.find(n => n?.id === target.parentId);
      const parentDef = typeof parent?.type === 'string' ? registry.get(parent.type) : undefined;
      const parentIsChainMiddleware = parentDef?.dropMode === 'edge';
      if (!parentIsChainMiddleware) {
        issues.push({
          severity: 'warning',
          message: `Target anchor is parented to "${target.parentId}" — chain parent leaking onto an anchor.`,
          nodeId: 'target',
        });
      }
    }
  }

  return issues;
}

/** Convenience: any error-severity issues present? */
export function hasBlockingIssues(issues: ValidationIssue[]): boolean {
  return issues.some(i => i.severity === 'error');
}
