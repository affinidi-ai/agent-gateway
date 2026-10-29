import { surfacesUsingStrategy } from '../strategyUsage';

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
