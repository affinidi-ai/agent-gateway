import { initialMediatorSelection, MediatorOption } from './mediatorOptions';

const stored = (id: string): MediatorOption => ({ id, did: `did:web:${id}`, name: id });
const directory = (id: string): MediatorOption => ({
  id,
  did: `did:web:${id}`,
  name: id,
  provided: true,
});

describe('initialMediatorSelection', () => {
  it('keeps an explicit initial choice', () => {
    expect(initialMediatorSelection([directory('directory:a'), stored('b')], 'b')).toBe('b');
  });

  it('pre-selects the first directory entry in list order', () => {
    expect(
      initialMediatorSelection(
        [stored('c'), directory('directory:a'), directory('directory:z')],
        null
      )
    ).toBe('directory:a');
  });

  it('never pre-selects a stored record created from a directory entry', () => {
    expect(
      initialMediatorSelection(
        [{ ...stored('kept'), provided: true }, stored('own'), stored('other')],
        null
      )
    ).toBe('');
  });

  it('never falls back to a single stored provided record', () => {
    expect(initialMediatorSelection([{ ...stored('kept'), provided: true }], null)).toBe('');
  });

  it('falls back to the only stored mediator', () => {
    expect(initialMediatorSelection([stored('only')], null)).toBe('only');
  });

  it('leaves the field empty with several stored mediators and none provided', () => {
    expect(initialMediatorSelection([stored('a'), stored('b')], null)).toBe('');
  });

  it('leaves the field empty when nothing is listed', () => {
    expect(initialMediatorSelection([], null)).toBe('');
  });
});
