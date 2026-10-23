import { isUnstoredDirectoryMediator } from '../../utils/mediators';

export interface MediatorOption {
  id: string;
  name?: string;
  description?: string;
  did: string;
  provided?: boolean;
}

/**
 * The mediator pre-selected when the step opens: an explicit initial choice,
 * else the first `directory:` entry of the mediator directory (a stored record
 * created from an entry is never pre-selected), else the only mediator when
 * there is exactly one, else none.
 */
export function initialMediatorSelection(
  mediators: MediatorOption[],
  initialMediatorId: string | null
): string {
  if (initialMediatorId) return initialMediatorId;
  const offered = mediators.find(isUnstoredDirectoryMediator);
  if (offered) return offered.id;
  if (mediators.length === 1) return mediators[0].id;
  return '';
}
