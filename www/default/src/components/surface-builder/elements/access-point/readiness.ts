import type { AccessPointStatus, AgentSurface } from '../../../../api';
import { resolveVariant } from '../../variants/resolve';

/** The slice of a surface payload that decides whether its Access Point admits callers. */
export interface CallerAccessPayload {
  access_point?: {
    public?: boolean;
    caller_authentication?: { methods?: unknown } | null;
  } | null;
  mcp_http?: { authorization?: unknown } | null;
}

/** What to show under the Access Point URL. */
export type AccessPointNotice = 'not_ready' | 'save_to_activate';

export const ACCESS_POINT_NOT_READY_TEXT = 'Not ready for external access';
export const ACCESS_POINT_SAVE_TO_ACTIVATE_TEXT =
  'Not ready for external access. Save to activate.';
export const CONFIGURE_AUTHENTICATION_LABEL = 'Configure Authentication';

/** A caller authentication method, or on MCP a resource token (`mcp_http.authorization`). */
export function hasCallerAuthentication(payload: CallerAccessPayload | null | undefined): boolean {
  const methods = payload?.access_point?.caller_authentication?.methods;
  return (Array.isArray(methods) && methods.length > 0) || payload?.mcp_http?.authorization != null;
}

/**
 * The gateway's readiness rule. A closed Access Point (`public: false`) with
 * no caller authentication is not ready: callers get 503 until one is added
 * or Public access is turned on. A public one, and a surface stored without
 * `public`, are always ready. `isNew` treats a missing `public` as `false`,
 * as the gateway stamps it on create.
 */
export function accessPointStatus(
  payload: CallerAccessPayload | null | undefined,
  { isNew = false }: { isNew?: boolean } = {}
): AccessPointStatus {
  const isPublic = payload?.access_point?.public;
  const closed = isPublic === false || (isNew && isPublic === undefined);
  return closed && !hasCallerAuthentication(payload) ? 'not_ready' : 'ready';
}

/**
 * The stored status of the view on the canvas: the gateway's
 * `access_point_status` for the base surface, or the stored variant resolved
 * over it. `variantId` is a variant's id, or anything else for the base.
 */
export function savedAccessPointStatus(
  surface: AgentSurface,
  variantId: string | null | undefined
): AccessPointStatus {
  const variant = variantId ? surface.variants?.find(v => v.id === variantId) : undefined;
  if (variant) return accessPointStatus(resolveVariant(surface, variant.overrides));
  return surface.access_point_status ?? accessPointStatus(surface);
}

/**
 * Chooses the notice. `saved` is `null` for a surface not created yet, which
 * shows the draft's state; otherwise the saved state shows, with "Save to
 * activate" when the unsaved draft would be ready.
 */
export function chooseAccessPointNotice(
  saved: AccessPointStatus | null,
  draft: AccessPointStatus
): AccessPointNotice | null {
  if (saved === null) return draft === 'not_ready' ? 'not_ready' : null;
  if (saved === 'ready') return null;
  return draft === 'ready' ? 'save_to_activate' : 'not_ready';
}
