import type { AgentSurface, CallerAuthentication } from '../../../../api';

function withoutOnFailure(auth: CallerAuthentication): CallerAuthentication {
  const rest = { ...auth };
  delete rest.on_failure;
  return rest;
}

/**
 * Settles the caller access fields of a surface write. When `public` is sent,
 * the gateway derives `caller_authentication.on_failure` from it, so the
 * loaded value is left out of the surface and its variants. A legacy surface
 * (stored without `public`) sends none unless the operator set it: the Public
 * access switch clears it again when turned off (`AccessPointPanel`).
 */
export function withCallerAccessSettled<T extends Partial<AgentSurface>>(payload: T): T {
  if (!payload?.access_point) return payload;
  const ap = { ...payload.access_point };
  if (typeof ap.public !== 'boolean') return payload;
  if (ap.caller_authentication)
    ap.caller_authentication = withoutOnFailure(ap.caller_authentication);
  const variants = payload.variants?.map(v => {
    const vAp = v.overrides?.access_point;
    const vAuth = vAp?.caller_authentication;
    if (!vAuth || typeof vAuth !== 'object' || !('on_failure' in vAuth)) return v;
    return {
      ...v,
      overrides: {
        ...v.overrides,
        access_point: { ...vAp, caller_authentication: withoutOnFailure(vAuth) },
      },
    };
  });
  return { ...payload, access_point: ap, ...(variants ? { variants } : {}) };
}
