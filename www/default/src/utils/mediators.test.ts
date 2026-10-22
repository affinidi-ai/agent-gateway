import {
  dropdownMediators,
  isProvidedMediator,
  isUnstoredDirectoryMediator,
  mediatorPageRows,
} from './mediators';

describe('isProvidedMediator', () => {
  it('is true only for a record the directory provides', () => {
    expect(isProvidedMediator({ provided: true })).toBe(true);
    expect(isProvidedMediator({ provided: false })).toBe(false);
    expect(isProvidedMediator({})).toBe(false);
  });
});

describe('isUnstoredDirectoryMediator', () => {
  it('is true for a directory entry that has no stored record yet', () => {
    expect(isUnstoredDirectoryMediator({ id: 'directory:0123456789abcdef' })).toBe(true);
    expect(isUnstoredDirectoryMediator({ id: '3f6c1f1e-1111-2222-3333-444444444444' })).toBe(false);
  });
});

describe('dropdownMediators and mediatorPageRows', () => {
  const entry = { id: 'directory:0123456789abcdef', did: 'did:web:shared', provided: true };
  const storedProvided = { id: 'aaaa-1', did: 'did:web:shared', provided: true };
  const staleProvided = { id: 'bbbb-2', did: 'did:web:gone', provided: true };
  const operator = { id: 'cccc-3', did: 'did:web:shared' };
  const all = [entry, storedProvided, staleProvided, operator];

  it('offers a directory mediator once in the dropdown, as its entry', () => {
    expect(dropdownMediators(all).map(m => m.id)).toEqual([
      entry.id,
      staleProvided.id,
      operator.id,
    ]);
  });

  it('shows the stored record instead of the entry on the Mediators page', () => {
    expect(mediatorPageRows(all).map(m => m.id)).toEqual([
      storedProvided.id,
      staleProvided.id,
      operator.id,
    ]);
    expect(mediatorPageRows([entry, staleProvided]).map(m => m.id)).toEqual([
      entry.id,
      staleProvided.id,
    ]);
  });
});
