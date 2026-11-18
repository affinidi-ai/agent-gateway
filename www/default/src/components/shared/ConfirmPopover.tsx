import React, { useEffect, useId, useRef, useState } from 'react';
import { createPortal } from 'react-dom';

interface ConfirmPopoverProps {
  anchor: HTMLElement;
  testId: string;
  icon?: 'fa-info-circle' | 'fa-triangle-exclamation';
  title: string;
  confirmLabel: string;
  confirmVariant?: 'primary' | 'danger';
  confirmDisabled?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  children: React.ReactNode;
}

/**
 * A speech-bubble confirmation balloon that floats to the left of an anchor
 * element via a body portal, so it never clips off the right edge of the
 * viewport. Confirms a destructive action inline instead of a browser confirm.
 * Dismisses on Escape or an outside click. Cancel takes focus when it opens and
 * focus returns to the anchor when it closes; no key reaches a window listener
 * while it is open.
 */
const ConfirmPopover: React.FC<ConfirmPopoverProps> = ({
  anchor,
  testId,
  icon = 'fa-info-circle',
  title,
  confirmLabel,
  confirmVariant = 'primary',
  confirmDisabled,
  busy,
  onConfirm,
  onCancel,
  children,
}) => {
  const popRef = useRef<HTMLDivElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const titleId = useId();
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null);

  useEffect(() => {
    let raf = 0;
    const tick = () => {
      const r = anchor.getBoundingClientRect();
      setPos(prev => {
        const next = { x: r.left, y: r.top + r.height / 2 };
        if (prev && Math.abs(prev.x - next.x) < 0.5 && Math.abs(prev.y - next.y) < 0.5) {
          return prev;
        }
        return next;
      });
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [anchor]);

  const shown = pos !== null;

  useEffect(() => {
    if (shown) cancelRef.current?.focus();
  }, [shown]);

  useEffect(
    () => () => {
      const active = document.activeElement;
      if (anchor.isConnected && (!active || active === document.body)) anchor.focus();
    },
    [anchor]
  );

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      e.stopPropagation();
      if (e.key !== 'Escape') return;
      e.preventDefault();
      if (!busy) onCancel();
    };
    const onDown = (e: MouseEvent) => {
      if (busy) return;
      const t = e.target as Node;
      if (popRef.current?.contains(t) || anchor.contains(t)) return;
      onCancel();
    };
    document.addEventListener('keydown', onKey);
    document.addEventListener('mousedown', onDown);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('mousedown', onDown);
    };
  }, [anchor, busy, onCancel]);

  if (!pos) return null;

  return createPortal(
    <div
      ref={popRef}
      className="confirm-popover"
      style={{ left: pos.x - 12, top: pos.y }}
      role="dialog"
      aria-labelledby={titleId}
      data-testid={testId}
    >
      <button
        type="button"
        className="confirm-popover__close"
        aria-label="Dismiss"
        onClick={onCancel}
        disabled={busy}
      >
        <i className="fas fa-times" />
      </button>
      <div className="confirm-popover__title" id={titleId}>
        <i
          className={`fas ${icon} me-2${confirmVariant === 'danger' ? ' text-danger' : ''}`}
          aria-hidden="true"
        />
        {title}
      </div>
      <div className="confirm-popover__body">{children}</div>
      <div className="confirm-popover__footer">
        <button
          type="button"
          ref={cancelRef}
          className="btn btn-sm btn-outline-secondary"
          onClick={onCancel}
          disabled={busy}
          data-testid={`${testId}-cancel`}
        >
          Cancel
        </button>
        <button
          type="button"
          className={`btn btn-sm btn-${confirmVariant}`}
          onClick={onConfirm}
          disabled={busy || confirmDisabled}
          data-testid={`${testId}-confirm`}
        >
          {busy ? '…' : confirmLabel}
        </button>
      </div>
      <span className="confirm-popover__tail" />
    </div>,
    document.body
  );
};

export default ConfirmPopover;
