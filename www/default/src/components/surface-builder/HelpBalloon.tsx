import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';

interface HelpBalloonProps {
  anchorRect: DOMRect;
  title?: string;
  bodyHtml: string;
  onClose: () => void;
  /** Optional link to the official documentation site for this element. */
  docLink?: string;
  /** Label for the doc link. Defaults to "Learn more". */
  docLinkLabel?: string;
}

const BALLOON_WIDTH = 320;
const GAP = 14;
const VIEWPORT_MARGIN = 8;
// Keeps the tail arrow from sliding past the balloon's rounded corners
// when the balloon gets nudged up/down to stay on-screen.
const TAIL_EDGE_INSET = 20;

interface HelpBalloonPos {
  left: number;
  top: number;
  /** Vertical offset of the tail within the balloon; null until measured. */
  tailTop: number | null;
  flipped: boolean;
}

/**
 * Balloon that floats to the right of a palette item, with a small tail
 * pointing left at the anchor. Position is recomputed against window size
 * so the balloon stays on-screen even when the anchor sits near the right
 * edge (in which case it flips to the left of the anchor) or near the top/
 * bottom edge (in which case it's nudged down/up, and the tail moves within
 * the balloon to keep pointing at the anchor).
 */
const HelpBalloon: React.FC<HelpBalloonProps> = ({
  anchorRect,
  title,
  bodyHtml,
  onClose,
  docLink,
  docLinkLabel = 'Learn more',
}) => {
  const ref = useRef<HTMLDivElement>(null);
  const computePos = (height: number): HelpBalloonPos => {
    const wantLeft = anchorRect.right + GAP;
    const flipped = wantLeft + BALLOON_WIDTH > window.innerWidth - VIEWPORT_MARGIN;
    const left = flipped ? anchorRect.left - GAP - BALLOON_WIDTH : wantLeft;
    const anchorCenter = anchorRect.top + anchorRect.height / 2;
    // The balloon renders above the app's own fixed topbar (z-index
    // 1100 vs. the topbar's 1030), so simply keeping it inside the raw
    // viewport isn't enough — a balloon nudged up to y=8 would still sit
    // visually on top of the toolbar. Read the toolbar's real bottom edge
    // (~80px) instead of hardcoding it, so this keeps working if that
    // height ever changes.
    const topbarBottom = document.querySelector('.topbar')?.getBoundingClientRect().bottom ?? 0;
    const minTop = Math.max(VIEWPORT_MARGIN, topbarBottom + VIEWPORT_MARGIN);
    if (height === 0) {
      // Real height isn't known until the balloon has rendered once —
      // center-on-anchor is just a first guess; the layout effect below
      // corrects it (and the tail offset) the instant we can measure it.
      return { left, top: anchorCenter, tailTop: null, flipped };
    }
    const idealTop = anchorCenter - height / 2;
    const maxTop = Math.max(minTop, window.innerHeight - height - VIEWPORT_MARGIN);
    const top = Math.min(Math.max(idealTop, minTop), maxTop);
    const tailTop = Math.min(
      Math.max(anchorCenter - top, TAIL_EDGE_INSET),
      Math.max(height - TAIL_EDGE_INSET, TAIL_EDGE_INSET)
    );
    return { left, top, tailTop, flipped };
  };

  const [pos, setPos] = useState<HelpBalloonPos>(() => computePos(0));

  // Measure the balloon's real (content-dependent) height as soon as it's
  // in the DOM, then re-clamp its position so it never overflows above or
  // below the viewport — mirroring the horizontal `flipped` handling above.
  useLayoutEffect(() => {
    setPos(computePos(ref.current?.offsetHeight ?? 0));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [anchorRect, bodyHtml]);

  // Click anywhere outside the balloon dismisses it. Uses capture phase
  // so d3-drag (which calls stopPropagation on mousedown for canvas
  // nodes) can't swallow the event before we see it. Clicks on a
  // palette item are excluded — the palette owns the open/close
  // toggle for those (clicking the same item closes; clicking another
  // opens). Drag start anywhere on the page also dismisses, so the
  // balloon doesn't linger while the user is dragging an element onto
  // the canvas.
  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (!ref.current) return;
      if (ref.current.contains(e.target as Node)) return;
      const target = e.target as Element | null;
      // Palette items and any other help-toggle button own their own
      // open/close click handling (clicking the same anchor again should
      // close, not close-then-immediately-reopen via this listener).
      if (target && target.closest && target.closest('.palette-item')) return;
      if (target && target.closest && target.closest('[data-help-toggle]')) return;
      onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    const onDrag = () => onClose();
    document.addEventListener('mousedown', onDoc, true);
    document.addEventListener('keydown', onKey);
    document.addEventListener('dragstart', onDrag, true);
    return () => {
      document.removeEventListener('mousedown', onDoc, true);
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('dragstart', onDrag, true);
    };
  }, [onClose]);

  // Re-pin if the window resizes while open.
  useEffect(() => {
    const onResize = () => setPos(computePos(ref.current?.offsetHeight ?? 0));
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [anchorRect]);

  return createPortal(
    <div
      ref={ref}
      className={`surface-help-balloon ${pos.flipped ? 'surface-help-balloon--left' : ''}`}
      style={{
        position: 'fixed',
        left: pos.left,
        top: pos.top,
        width: BALLOON_WIDTH,
        zIndex: 1100,
      }}
      role="tooltip"
    >
      <button
        type="button"
        className="surface-help-balloon__close"
        aria-label="Dismiss"
        onClick={onClose}
      >
        <i className="fas fa-times" />
      </button>
      {title && (
        <div className="surface-help-balloon__title">
          <i className="fas fa-info-circle me-2" />
          {title}
        </div>
      )}
      <div
        className="surface-help-balloon__body"
        // Hardcoded help content from the element registry — safe.
        dangerouslySetInnerHTML={{ __html: bodyHtml }}
      />
      {docLink && (
        <a
          className="surface-help-balloon__doclink"
          href={docLink}
          target="_blank"
          rel="noopener noreferrer"
        >
          {docLinkLabel} <i className="fas fa-arrow-right ms-1" aria-hidden="true" />
        </a>
      )}
      <span
        className="surface-help-balloon__tail"
        style={pos.tailTop != null ? { top: pos.tailTop } : undefined}
      />
    </div>,
    document.body
  );
};

export default HelpBalloon;
