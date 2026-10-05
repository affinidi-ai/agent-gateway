import React, { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';

interface PolicyConfirmPopoverProps {
  anchor: HTMLElement;
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
 * viewport. Used by the policy list to confirm a delete inline (showing the
 * blast radius) instead of a browser confirm. Dismisses on Escape or an outside
 * click.
 */
const PolicyConfirmPopover: React.FC<PolicyConfirmPopoverProps> = ({
  anchor,
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

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !busy) onCancel();
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
      className="policy-popover"
      style={{ left: pos.x - 12, top: pos.y }}
      role="dialog"
      data-testid="policy-confirm-popover"
    >
      <button
        type="button"
        className="policy-popover__close"
        aria-label="Dismiss"
        onClick={onCancel}
        disabled={busy}
      >
        <i className="fas fa-times" />
      </button>
      <div className="policy-popover__title">
        <i className="fas fa-info-circle me-2" />
        {title}
      </div>
      <div className="policy-popover__body">{children}</div>
      <div className="policy-popover__footer">
        <button
          type="button"
          className="btn btn-sm btn-outline-secondary"
          onClick={onCancel}
          disabled={busy}
        >
          Cancel
        </button>
        <button
          type="button"
          className={`btn btn-sm btn-${confirmVariant}`}
          onClick={onConfirm}
          disabled={busy || confirmDisabled}
          data-testid="policy-confirm-popover-confirm"
        >
          {busy ? '…' : confirmLabel}
        </button>
      </div>
      <span className="policy-popover__tail" />
    </div>,
    document.body
  );
};

export default PolicyConfirmPopover;
