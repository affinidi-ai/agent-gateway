import { deepLinks } from '../deepLinks';

describe('deepLinks', () => {
  it('returns canonical create routes for on-product resources', () => {
    expect(deepLinks.agentSurface).toBe('/surfaces/new');
    expect(deepLinks.secret).toBe('/secrets/new');
    expect(deepLinks.apiKey).toBe('/secrets?tab=api-keys');
    expect(deepLinks.trustRegistry).toBe('/trust-registries/wizard');
    expect(deepLinks.issuer).toBe('/issuers/new');
    expect(deepLinks.authority).toBe('/authorities/new');
    expect(deepLinks.mediator).toBe('/mediators/wizard');
  });

  it('encodes the certificate kind filter when supplied', () => {
    expect(deepLinks.certificate()).toBe('/secrets?tab=certificates');
    expect(deepLinks.certificate('client_leaf')).toBe('/secrets?tab=certificates&kind=client_leaf');
    expect(deepLinks.certificate('server_leaf')).toBe('/secrets?tab=certificates&kind=server_leaf');
    expect(deepLinks.certificate('ca')).toBe('/secrets?tab=certificates&kind=ca');
  });

  it('encodes the policy-definition type filter when supplied', () => {
    expect(deepLinks.policyDefinition()).toBe('/policy-definitions/new');
    expect(deepLinks.policyDefinition('gateway')).toBe('/policy-definitions/new?type=gateway');
    expect(deepLinks.policyDefinition('surface')).toBe('/policy-definitions/new?type=surface');
  });
});
