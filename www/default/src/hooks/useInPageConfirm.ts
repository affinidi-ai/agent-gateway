import React, { useCallback, useEffect, useRef } from 'react';

/**
 * Focus handling for a confirmation shown in the page (role `alertdialog`). Whenever `openFor`
 * names a new subject, the dialog takes focus and scrolls into view. `rememberTrigger` records
 * the control that opened it and `returnFocus` moves focus back there when the operator cancels.
 * `cancelOnEscape` builds the dialog's key handler.
 */
export function useInPageConfirm(openFor: string | null) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (openFor === null) return;
    dialogRef.current?.focus();
    dialogRef.current?.scrollIntoView?.({ block: 'nearest' });
  }, [openFor]);

  const rememberTrigger = useCallback(() => {
    const active = document.activeElement;
    triggerRef.current = active instanceof HTMLElement && active !== document.body ? active : null;
  }, []);

  const returnFocus = useCallback(() => {
    const trigger = triggerRef.current;
    triggerRef.current = null;
    if (trigger?.isConnected) trigger.focus();
  }, []);

  const cancelOnEscape =
    (cancel: () => void, busy: boolean) => (event: React.KeyboardEvent<HTMLElement>) => {
      if (event.key === 'Escape' && !busy) {
        event.preventDefault();
        cancel();
      }
    };

  return { dialogRef, rememberTrigger, returnFocus, cancelOnEscape };
}
