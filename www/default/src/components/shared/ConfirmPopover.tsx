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

const GAP = 12;
const MARGIN = 8;
const DEFAULT_WIDTH = 300;
const TAIL_INSET = 16;

interface Placement {
  left: number;
  top: number;
  side: 'left' | 'right';
  tailTop: number;
}

const clamp = (value: number, min: number, max: number) =>
  Math.min(Math.max(value, min), Math.max(min, max));

/**
 * Places the balloon to the left of the anchor, or to its right when the left
 * has no room, kept inside the viewport on both axes with the tail pointing at
 * the anchor's middle.
 */
export function placeConfirmPopover(
  anchor: Pick<DOMRect, 'left' | 'right' | 'top' | 'height'>,
  size: { width: number; height: number },
  viewport: { width: number; height: number }
): Placement {
  const roomLeft = anchor.left - GAP - MARGIN;
  const roomRight = viewport.width - anchor.right - GAP - MARGIN;
  const side = roomLeft >= size.width || roomLeft >= roomRight ? 'left' : 'right';
  const left = clamp(
    side === 'left' ? anchor.left - GAP - size.width : anchor.right + GAP,
    MARGIN,
    viewport.width - size.width - MARGIN
  );
  const middle = anchor.top + anchor.height / 2;
  const top = clamp(middle - size.height / 2, MARGIN, viewport.height - size.height - MARGIN);
  const tailTop = clamp(middle - top, TAIL_INSET, size.height - TAIL_INSET);
  return { left, top, side, tailTop };
}

/**
 * A speech-bubble confirmation balloon that floats beside an anchor element
 * via a body portal, on the left when there is room and otherwise on the
 * right, always inside the viewport. Confirms a destructive action inline instead of a browser confirm.
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
  const [pos, setPos] = useState<Placement | null>(null);

  useEffect(() => {
    let raf = 0;
    const tick = () => {
      const next = placeConfirmPopover(
        anchor.getBoundingClientRect(),
        {
          width: popRef.current?.offsetWidth || DEFAULT_WIDTH,
          height: popRef.current?.offsetHeight ?? 0,
        },
        { width: window.innerWidth, height: window.innerHeight }
      );
      setPos(prev =>
        prev &&
        prev.side === next.side &&
        Math.abs(prev.left - next.left) < 0.5 &&
        Math.abs(prev.top - next.top) < 0.5 &&
        Math.abs(prev.tailTop - next.tailTop) < 0.5
          ? prev
          : next
      );
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
      className={`confirm-popover confirm-popover--${pos.side}`}
      style={{ left: pos.left, top: pos.top }}
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
      <span className="confirm-popover__tail" style={{ top: pos.tailTop }} />
    </div>,
    document.body
  );
};

export default ConfirmPopover;
