import { useEffect, useRef } from 'react';

/**
 * Bind Cmd/Ctrl+S to a save handler.
 *
 * The handler typically closes over render-scope state (form fields, derived
 * payload, etc.) so we keep it in a ref that's refreshed every render. This
 * means callers can pass an inline arrow function safely — the registered
 * keyboard listener always invokes the latest version.
 *
 * `commit` is invoked before the handler so that any in-flight live edit
 * (e.g. a freshly typed input value) is recorded as a history snapshot
 * and reflected in the saved payload.
 */
export function useSaveShortcut(handler: () => void, commit?: () => void): void {
  const handlerRef = useRef(handler);
  handlerRef.current = handler;
  const commitRef = useRef(commit);
  commitRef.current = commit;

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      const isMeta = e.metaKey || e.ctrlKey;
      if (!isMeta || e.key !== 's') return;
      e.preventDefault();
      commitRef.current?.();
      handlerRef.current();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);
}
