export interface MediatorOption {
  id: string;
  name?: string;
  description?: string;
  did: string;
  provided?: boolean;
}

/**
 * The mediator pre-selected when the step opens: an explicit initial choice,
 * else the first mediator offered by the mediator directory (whether still a
 * directory entry or already stored), else the only mediator when there is
 * exactly one, else none.
 */
export function initialMediatorSelection(
  mediators: MediatorOption[],
  initialMediatorId: string | null
): string {
  if (initialMediatorId) return initialMediatorId;
  const offered = mediators.find(mediator => mediator.provided === true);
  if (offered) return offered.id;
  if (mediators.length === 1) return mediators[0].id;
  return '';
}
