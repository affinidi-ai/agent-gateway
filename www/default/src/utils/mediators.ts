export function isProvidedMediator(mediator: { provided?: boolean }): boolean {
  return mediator.provided === true;
}

export function isUnstoredDirectoryMediator(mediator: { id: string }): boolean {
  return mediator.id.startsWith('directory:');
}
