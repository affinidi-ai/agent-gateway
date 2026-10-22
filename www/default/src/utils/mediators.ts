export function isProvidedMediator(mediator: { provided?: boolean }): boolean {
  return mediator.provided === true;
}

export function isUnstoredDirectoryMediator(mediator: { id: string }): boolean {
  return mediator.id.startsWith('directory:');
}

interface ListedMediator {
  id: string;
  did: string;
  provided?: boolean;
}

/**
 * The Create Connection Point dropdown offers a directory mediator once, as its
 * `directory:` entry: a stored provided record for a DID the directory lists is
 * left out.
 */
export function dropdownMediators<T extends ListedMediator>(mediators: T[]): T[] {
  const offered = new Set(mediators.filter(isUnstoredDirectoryMediator).map(m => m.did));
  return mediators.filter(
    mediator =>
      isUnstoredDirectoryMediator(mediator) ||
      !(mediator.provided === true && offered.has(mediator.did))
  );
}

/**
 * The Mediators page shows the stored record when one exists for a directory DID
 * (connection points refer to it by its id), and the `directory:` entry only
 * while there is none.
 */
export function mediatorPageRows<T extends ListedMediator>(mediators: T[]): T[] {
  const stored = new Set(mediators.filter(m => !isUnstoredDirectoryMediator(m)).map(m => m.did));
  return mediators.filter(
    mediator => !isUnstoredDirectoryMediator(mediator) || !stored.has(mediator.did)
  );
}
