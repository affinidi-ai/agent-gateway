import { parseReferenceConflict, referenceKindLabel } from './referenceConflict';

describe('parseReferenceConflict', () => {
  const body = (extra: object) => JSON.stringify({ message: 'In use', ...extra });

  it('reads the named references and the hidden count of a 409', () => {
    expect(
      parseReferenceConflict(
        409,
        body({ references: [{ kind: 'a2a_proxy', id: 'x', name: 'Proxy' }], hidden_references: 2 })
      )
    ).toEqual({
      message: 'In use',
      references: [{ kind: 'a2a_proxy', id: 'x', name: 'Proxy' }],
      hiddenReferences: 2,
    });
  });

  it('keeps a conflict that has only hidden references', () => {
    expect(
      parseReferenceConflict(409, body({ references: [], hidden_references: 4 }))
    ).toMatchObject({
      references: [],
      hiddenReferences: 4,
    });
  });

  it('returns null without references, for another status, or for a body that is not JSON', () => {
    expect(parseReferenceConflict(409, body({}))).toBeNull();
    expect(parseReferenceConflict(409, body({ references: [], hidden_references: 0 }))).toBeNull();
    expect(
      parseReferenceConflict(400, body({ references: [{ kind: 'surface', id: 's', name: 'S' }] }))
    ).toBeNull();
    expect(parseReferenceConflict(409, 'plain text')).toBeNull();
  });

  it('labels each kind and falls back to the raw kind', () => {
    expect(referenceKindLabel('sts_client')).toBe('STS client');
    expect(referenceKindLabel('other')).toBe('other');
  });
});
