import {
  inOwnerTenant,
  outOfTenantLabel,
  sendsGatewayCredential,
  splitByTenant,
} from './tenantScope';

const items = [
  { id: 'wide' },
  { id: 'acme', tenant_id: 'acme' },
  { id: 'null', tenant_id: null },
  { id: 'other', tenant_id: 'other' },
];

const providers = [
  { id: 'wide-code', provider_type: 'oauth2_authorization_code' },
  { id: 'wide-cc', provider_type: 'oauth2_client_credentials' },
  { id: 'other-code', provider_type: 'oauth2_authorization_code', tenant_id: 'other' },
  { id: 'acme-cc', provider_type: 'oauth2_client_credentials', tenant_id: 'acme' },
  {
    id: 'wide-issuer',
    provider_type: 'oauth2_authorization_code',
    issuer: 'https://issuer.example',
  },
  {
    id: 'acme-issuer',
    provider_type: 'oauth2_authorization_code',
    issuer: 'https://issuer.example',
    tenant_id: 'acme',
  },
];

const userTokenProvider = (p: { provider_type?: string }) => !sendsGatewayCredential(p);

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

  it('offers a tenant the appliance-wide items the gateway still accepts', () => {
    const { offered, outside } = splitByTenant(providers, 'acme', userTokenProvider);
    expect(offered.map(p => p.id)).toEqual(['wide-code', 'acme-cc', 'acme-issuer']);
    expect(outside.map(p => p.id)).toEqual(['wide-cc', 'other-code', 'wide-issuer']);
  });

  it('never offers another tenant an item through the appliance-wide allowance', () => {
    expect(inOwnerTenant(providers[2], 'acme', userTokenProvider)).toBe(false);
    expect(inOwnerTenant(providers[1], 'acme', userTokenProvider)).toBe(false);
  });

  it('tells user-token providers from those that send the gateway credential', () => {
    expect(sendsGatewayCredential({ provider_type: 'oauth2_authorization_code' })).toBe(false);
    expect(sendsGatewayCredential({ provider_type: 'oauth2_client_credentials' })).toBe(true);
    expect(sendsGatewayCredential({ provider_type: 'oauth2_jwt_bearer' })).toBe(true);
    expect(sendsGatewayCredential({ provider_type: 'api_key' })).toBe(true);
    expect(
      sendsGatewayCredential({
        provider_type: 'oauth2_authorization_code',
        issuer: 'https://issuer.example',
      })
    ).toBe(true);
  });

  it('labels out-of-tenant items by what the gateway does with them', () => {
    expect(outOfTenantLabel({})).toBe('appliance-wide, stops working when enforced');
    expect(outOfTenantLabel({ tenant_id: null })).toBe(
      'appliance-wide, stops working when enforced'
    );
    expect(outOfTenantLabel({ tenant_id: 'other' })).toBe('another tenant, refused by the gateway');
  });

  it('labels an appliance-wide provider with an issuer as refused', () => {
    expect(outOfTenantLabel({ tenant_id: null, issuer: 'https://issuer.example' })).toBe(
      'appliance-wide, refused by the gateway'
    );
    expect(outOfTenantLabel({ issuer: 'https://issuer.example' })).toBe(
      'appliance-wide, refused by the gateway'
    );
    expect(outOfTenantLabel({ tenant_id: null, issuer: null })).toBe(
      'appliance-wide, stops working when enforced'
    );
    expect(outOfTenantLabel({ tenant_id: 'other', issuer: 'https://issuer.example' })).toBe(
      'another tenant, refused by the gateway'
    );
  });
});
