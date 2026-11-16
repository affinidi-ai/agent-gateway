import { ApiError } from '../../../api';
import { authorityInUse, describeAuthorityUse } from '../authorityInUse';

const conflict = (body: unknown, status = 409) =>
  new ApiError('in use (409)', status, undefined, JSON.stringify(body));

const BODY = {
  message: 'The Authority is used by Trust Checks or Trust Recorder entries.',
  references: [
    {
      kind: 'surface',
      id: 'surface-1',
      name: 'Orders',
      uses: [
        { element: 'trust_check', id: 'tc-1', name: 'Agent recognised', placement: 'access_point' },
        {
          element: 'trust_check',
          id: 'tc-2',
          placement: 'transit_point',
          transit_point: 'partner',
          variant: 'staging',
        },
        { element: 'trust_recorder', trust_registry_id: 'tr-1' },
        { element: 'something_new' },
      ],
    },
    { kind: 'sts_client', id: 'sts-1', name: 'Exchange', uses: [{ element: 'trust_check' }] },
    { kind: 'unknown', id: 'x' },
  ],
  hidden_references: 2,
};

describe('authorityInUse', () => {
  it('reads the references and hidden count of a 409', () => {
    const inUse = authorityInUse(conflict(BODY));
    expect(inUse?.hiddenReferences).toBe(2);
    expect(inUse?.references.map(r => [r.kind, r.id, r.name])).toEqual([
      ['surface', 'surface-1', 'Orders'],
      ['sts_client', 'sts-1', 'Exchange'],
    ]);
    expect(inUse?.references[0].uses).toEqual([
      {
        element: 'trust_check',
        id: 'tc-1',
        name: 'Agent recognised',
        placement: 'access_point',
        transitPoint: undefined,
        variant: undefined,
        trustRegistryId: undefined,
      },
      {
        element: 'trust_check',
        id: 'tc-2',
        name: undefined,
        placement: 'transit_point',
        transitPoint: 'partner',
        variant: 'staging',
        trustRegistryId: undefined,
      },
      {
        element: 'trust_recorder',
        id: undefined,
        name: undefined,
        placement: undefined,
        transitPoint: undefined,
        variant: undefined,
        trustRegistryId: 'tr-1',
      },
    ]);
  });

  it('is null for another status, a plain Error, or a body without references', () => {
    expect(authorityInUse(conflict(BODY, 400))).toBeNull();
    expect(authorityInUse(new Error('boom'))).toBeNull();
    expect(authorityInUse(conflict({ message: 'conflict' }))).toBeNull();
    expect(authorityInUse(new ApiError('x', 409, undefined, 'not json'))).toBeNull();
    expect(authorityInUse(new ApiError('x', 409))).toBeNull();
  });

  it('counts no hidden references when the field is missing or not a positive whole number', () => {
    expect(authorityInUse(conflict({ references: [] }))?.hiddenReferences).toBe(0);
    expect(
      authorityInUse(conflict({ references: [], hidden_references: -1 }))?.hiddenReferences
    ).toBe(0);
  });
});

describe('describeAuthorityUse', () => {
  const name = (id: string) => (id === 'tr-1' ? 'Partner registry' : id);

  it('names a Trust Check, its leg, Transit Point and variant', () => {
    expect(
      describeAuthorityUse(
        { element: 'trust_check', name: 'Agent recognised', placement: 'access_point' },
        name
      )
    ).toBe('Trust Check “Agent recognised” on the Access Point');
    expect(
      describeAuthorityUse(
        {
          element: 'trust_check',
          placement: 'transit_point',
          transitPoint: 'partner',
          variant: 'staging',
        },
        name
      )
    ).toBe('Trust Check on Transit Point partner in variant staging');
    expect(describeAuthorityUse({ element: 'trust_check', placement: 'target' }, name)).toBe(
      "Trust Check on the Managed Agent's target"
    );
    expect(describeAuthorityUse({ element: 'trust_check' }, name)).toBe('Trust Check');
  });

  it('names a Trust Recorder entry by its trust registry', () => {
    expect(describeAuthorityUse({ element: 'trust_recorder', trustRegistryId: 'tr-1' }, name)).toBe(
      'Trust Recorder entry for Partner registry'
    );
    expect(
      describeAuthorityUse(
        { element: 'trust_recorder', trustRegistryId: 'tr-9', variant: 'beta' },
        name
      )
    ).toBe('Trust Recorder entry for tr-9 in variant beta');
  });
});
