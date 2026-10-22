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

  it('pre-selects the first provided mediator in list order', () => {
    expect(
      initialMediatorSelection(
        [stored('c'), directory('directory:a'), { ...stored('b'), provided: true }],
        null
      )
    ).toBe('directory:a');
  });

  it('pre-selects a stored mediator that was created from a directory entry', () => {
    expect(
      initialMediatorSelection([{ ...stored('kept'), provided: true }, stored('own')], null)
    ).toBe('kept');
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
