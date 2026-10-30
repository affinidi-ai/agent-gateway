export interface TenantOwned {
  tenant_id?: string | null;
}

export const OUT_OF_TENANT_LABEL = 'appliance-wide, stops working when enforced';

/** The tenant that owns the thing being edited: `null` is appliance-wide, `undefined` is not yet known. */
export type OwnerTenant = string | null | undefined;

export function inOwnerTenant(item: TenantOwned, owner: OwnerTenant): boolean {
  return owner === undefined || (item.tenant_id ?? null) === owner;
}

/** Items the picker offers, and the other visible items kept only to label a stored choice. */
export function splitByTenant<T extends TenantOwned>(
  items: readonly T[],
  owner: OwnerTenant
): { offered: T[]; outside: T[] } {
  return {
    offered: items.filter(item => inOwnerTenant(item, owner)),
    outside: items.filter(item => !inOwnerTenant(item, owner)),
  };
}

export function outOfTenantLabel(item: TenantOwned): string {
  return item.tenant_id ? 'another tenant, stops working when enforced' : OUT_OF_TENANT_LABEL;
}
