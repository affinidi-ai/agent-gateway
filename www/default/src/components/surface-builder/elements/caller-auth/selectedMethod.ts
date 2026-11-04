import { useCallback, useSyncExternalStore } from 'react';

/**
 * Which method of a caller-auth element its fullscreen editor shows, by node
 * id. "Configure" on a method row in the sidebar picks it before opening the
 * editor, and an editor that is already open follows the pick. Never saved.
 */
const selected = new Map<string, number>();
const listeners = new Set<() => void>();

export function selectMethod(nodeId: string, position: number) {
  selected.set(nodeId, position);
  listeners.forEach(listener => listener());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function useSelectedMethod(nodeId: string): [number, (position: number) => void] {
  const position = useSyncExternalStore(subscribe, () => selected.get(nodeId) ?? 0);
  const select = useCallback((next: number) => selectMethod(nodeId, next), [nodeId]);
  return [position, select];
}
