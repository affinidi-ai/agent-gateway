import {
  CALLER_AUTH_METHOD_SHORT_LABEL,
  credentialLocation,
  type CallerAuthMethodConfig,
  type MethodIdentity,
} from '../caller-auth/methods';

/** Identity types that read the credential the caller presented. */
export const CREDENTIAL_IDENTITY_TYPES: ReadonlySet<unknown> = new Set([
  'from_jwt_claim',
  'from_api_key',
]);

/** Caller Context method types whose credential a From API Key identity can read. */
export const API_KEY_METHOD_TYPES: ReadonlySet<unknown> = new Set(['api_key', 'api_key_provider']);

/** Whether an identity of this type can be derived from the credential of `method`. */
export function readsMethod(identityType: unknown, method: CallerAuthMethodConfig): boolean {
  if (identityType === 'from_jwt_claim') return method.method_type === 'jwt_bearer';
  if (identityType === 'from_api_key') return API_KEY_METHOD_TYPES.has(method.method_type);
  return false;
}

/** The identity type a method can set for its own callers, if any. */
export function ownIdentityType(
  method: CallerAuthMethodConfig
): MethodIdentity['type'] | undefined {
  if (method.method_type === 'jwt_bearer') return 'from_jwt_claim';
  if (API_KEY_METHOD_TYPES.has(method.method_type)) return 'from_api_key';
  return undefined;
}

/**
 * A new identity of `type` for a method's own callers. A JWT claim is
 * namespaced by the token's issuer, so two JWT Bearer methods trusting
 * different identity providers never give their users the same DID.
 */
export function newMethodIdentity(type: MethodIdentity['type']): MethodIdentity {
  return type === 'from_jwt_claim' ? { type, claim: 'oid', namespace_claims: ['iss'] } : { type };
}

/**
 * Whether callers of `method` get an inbound identity: the method's own, or
 * the surface's (`surfaceType`) when that reads no credential or reads this one.
 */
export function methodGetsIdentity(surfaceType: unknown, method: CallerAuthMethodConfig): boolean {
  if (method.identity && ownIdentityType(method) === method.identity.type) return true;
  return !CREDENTIAL_IDENTITY_TYPES.has(surfaceType) || readsMethod(surfaceType, method);
}

/** `Method N: <kind>, reads <location>`, as the per-method list names a method. */
export function methodLabel(method: CallerAuthMethodConfig, position: number): string {
  const kind = method.method_type ? CALLER_AUTH_METHOD_SHORT_LABEL[method.method_type] : 'Method';
  return `Method ${position + 1}: ${kind}, reads ${credentialLocation(method)}`;
}

export const USES_SURFACE_IDENTITY = 'Uses this Identity';
export const REFUSED_WITHOUT_OWN_IDENTITY =
  'Callers of this method are refused: this Identity cannot read its credential. Give the method its own identity.';
