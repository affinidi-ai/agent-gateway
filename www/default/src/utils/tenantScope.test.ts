import { inOwnerTenant, outOfTenantLabel, splitByTenant } from './tenantScope';

const items = [
  { id: 'wide' },
  { id: 'acme', tenant_id: 'acme' },
  { id: 'null', tenant_id: null },
  { id: 'other', tenant_id: 'other' },
];

describe('tenantScope', () => {
  it('offers a tenant only its own items', () => {
    const { offered, outside } = splitByTenant(items, 'acme');
    expect(offered.map(i => i.id)).toEqual(['acme']);
    expect(outside.map(i => i.id)).toEqual(['wide', 'null', 'other']);
  });

  it('offers an appliance-wide owner only appliance-wide items', () => {
    const { offered, outside } = splitByTenant(items, null);
    expect(offered.map(i => i.id)).toEqual(['wide', 'null']);
    expect(outside.map(i => i.id)).toEqual(['acme', 'other']);
  });

  it('offers everything while the owner is unknown', () => {
    expect(splitByTenant(items, undefined)).toEqual({ offered: items, outside: [] });
    expect(inOwnerTenant({ tenant_id: 'x' }, undefined)).toBe(true);
  });

  it('labels out-of-tenant items', () => {
    expect(outOfTenantLabel({})).toBe('appliance-wide, stops working when enforced');
    expect(outOfTenantLabel({ tenant_id: 'other' })).toBe(
      'another tenant, stops working when enforced'
    );
  });
});
