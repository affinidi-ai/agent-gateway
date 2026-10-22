import { isProvidedMediator, isUnstoredDirectoryMediator } from './mediators';

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
