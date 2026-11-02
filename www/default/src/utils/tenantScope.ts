export interface TenantOwned {
  tenant_id?: string | null;
}

export const OUT_OF_TENANT_LABEL = 'appliance-wide, stops working when enforced';
export const OTHER_TENANT_LABEL = 'another tenant, refused by the gateway';

/** The tenant that owns the thing being edited: `null` is appliance-wide, `undefined` is not yet known. */
export type OwnerTenant = string | null | undefined;

/**
 * An authorization code provider sends the user's own token, so the gateway lets a tenant
 * surface keep using an appliance-wide one; every other type sends the gateway's credential.
 * A provider with an issuer (external consent) is held to the tenant rule like those: the
 * gateway refuses an appliance-wide one outside its own tenant.
 */
export function sendsGatewayCredential(provider: {
  provider_type?: string;
  issuer?: string | null;
}): boolean {
  return provider.provider_type !== 'oauth2_authorization_code' || Boolean(provider.issuer);
}

/** Appliance-wide items a tenant owner may still use, beside its own. */
export type ApplianceWideAllowed<T> = (item: T) => boolean;

export function inOwnerTenant<T extends TenantOwned>(
  item: T,
  owner: OwnerTenant,
  applianceWideAllowed?: ApplianceWideAllowed<T>
): boolean {
  const tenant = item.tenant_id ?? null;
  return (
    owner === undefined ||
    tenant === owner ||
    (tenant === null && applianceWideAllowed !== undefined && applianceWideAllowed(item))
  );
}

/** Items the picker offers, and the other visible items kept only to label a stored choice. */
export function splitByTenant<T extends TenantOwned>(
  items: readonly T[],
  owner: OwnerTenant,
  applianceWideAllowed?: ApplianceWideAllowed<T>
): { offered: T[]; outside: T[] } {
  return {
    offered: items.filter(item => inOwnerTenant(item, owner, applianceWideAllowed)),
    outside: items.filter(item => !inOwnerTenant(item, owner, applianceWideAllowed)),
  };
}

export function outOfTenantLabel(item: TenantOwned): string {
  return item.tenant_id ? OTHER_TENANT_LABEL : OUT_OF_TENANT_LABEL;
}
