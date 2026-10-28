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
 * The Mediators page shows the stored provided record when one exists for a
 * directory DID (connection points refer to it by its id), and the `directory:`
 * entry only while there is none. An operator-added mediator with the same DID is
 * a row of its own and never hides the entry.
 */
export function mediatorPageRows<T extends ListedMediator>(mediators: T[]): T[] {
  const storedProvided = new Set(
    mediators.filter(m => !isUnstoredDirectoryMediator(m) && m.provided === true).map(m => m.did)
  );
  return mediators.filter(
    mediator => !isUnstoredDirectoryMediator(mediator) || !storedProvided.has(mediator.did)
  );
}

/**
 * Delete is offered for a stored provided record only when the server marks it
 * `deletable`: the directory answered without its DID, or none is configured.
 * The API still refuses while something uses the record.
 */
export function canDeleteProvidedMediator(mediator: {
  id: string;
  provided?: boolean;
  deletable?: boolean;
}): boolean {
  return (
    mediator.provided === true &&
    mediator.deletable === true &&
    !isUnstoredDirectoryMediator(mediator)
  );
}
