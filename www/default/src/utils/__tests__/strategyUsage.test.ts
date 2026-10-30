import { providersUsingStrategy, surfacesUsingStrategy } from '../strategyUsage';

const method = (id: string) => ({
  caller_authentication: { methods: [{ jwt_verification_strategy_id: id }] },
});

describe('surfacesUsingStrategy', () => {
  it('finds surfaces that reference the strategy on the base or on a variant', () => {
    const surfaces = [
      { surface_id: 'a', name: 'Alpha', access_point: method('s1') },
      { surface_id: 'b', name: 'Beta', access_point: method('s2') },
      {
        surface_id: 'c',
        name: '',
        access_point: {},
        variants: [{ overrides: { access_point: method('s1') } }],
      },
    ];
    expect(surfacesUsingStrategy(surfaces, 's1')).toEqual([
      { id: 'a', name: 'Alpha' },
      { id: 'c', name: 'c' },
    ]);
  });

  it('returns nothing for unusable input', () => {
    expect(surfacesUsingStrategy(null, 's1')).toEqual([]);
    expect(surfacesUsingStrategy([{ name: 'x' }, null], 's1')).toEqual([]);
  });
});

describe('providersUsingStrategy', () => {
  it('finds the providers that use the strategy for consent identity', () => {
    const providers = [
      { id: 'p1', name: 'Calendar', consent_identity_strategy_id: 's1' },
      { id: 'p2', name: 'Mail', consent_identity_strategy_id: 's2' },
      { id: 'p3', name: 'Drive' },
      { id: 'p4', name: '', consent_identity_strategy_id: 's1' },
      { name: 'No id', consent_identity_strategy_id: 's1' },
      null,
    ];
    expect(providersUsingStrategy(providers, 's1')).toEqual([
      { id: 'p1', name: 'Calendar' },
      { id: 'p4', name: 'p4' },
    ]);
  });

  it('returns nothing for unusable input', () => {
    expect(providersUsingStrategy(null, 's1')).toEqual([]);
    expect(providersUsingStrategy({ id: 'p1', consent_identity_strategy_id: 's1' }, 's1')).toEqual(
      []
    );
  });
});

describe('surfacesUsingStrategy with consent providers', () => {
  const surfaces = [
    {
      surface_id: 'tp',
      name: 'Transit',
      transit: { points: [{ transit_credentials: { credential_provider_id: 'p1' } }] },
    },
    {
      surface_id: 'ob',
      name: 'Outbound',
      outbound_credentials: [{ credential_provider_id: 'p1' }],
    },
    {
      surface_id: 'var',
      name: 'Variant',
      variants: [{ overrides: { outbound_credentials: [{ credential_provider_id: 'p1' }] } }],
    },
    {
      surface_id: 'other',
      name: 'Other',
      transit: { points: [{ transit_credentials: { credential_provider_id: 'p9' } }, {}] },
      outbound_credentials: [{ credential_provider_id: 'p9' }],
    },
  ];

  it('counts a surface whose Transit Point or outbound credentials use a consent provider', () => {
    expect(surfacesUsingStrategy(surfaces, 's1', ['p1'])).toEqual([
      { id: 'tp', name: 'Transit' },
      { id: 'ob', name: 'Outbound' },
      { id: 'var', name: 'Variant' },
    ]);
  });

  it('ignores provider bindings without consent providers or with unrelated ones', () => {
    expect(surfacesUsingStrategy(surfaces, 's1')).toEqual([]);
    expect(surfacesUsingStrategy(surfaces, 's1', ['p2'])).toEqual([]);
  });
});
