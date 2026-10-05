import React, { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';

interface LimitBalloonProps {
  anchorRect: DOMRect;
  message: string;
  onClose: () => void;
}

const BALLOON_WIDTH = 300;
const GAP = 12;

/**
 * "Limit reached" balloon anchored below the create button that was clicked.
 * Modelled on the surface-builder HelpBalloon: portal-rendered and dismissed on
 * outside click, Escape, or scroll.
 */
const LimitBalloon: React.FC<LimitBalloonProps> = ({ anchorRect, message, onClose }) => {
  const ref = useRef<HTMLDivElement>(null);
  const [pos] = useState(() => {
    const left = Math.min(anchorRect.left, window.innerWidth - BALLOON_WIDTH - 8);
    return { left: Math.max(8, left), top: anchorRect.bottom + GAP };
  });

  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('mousedown', onDoc, true);
    document.addEventListener('keydown', onKey);
    window.addEventListener('scroll', onClose, true);
    return () => {
      document.removeEventListener('mousedown', onDoc, true);
      document.removeEventListener('keydown', onKey);
      window.removeEventListener('scroll', onClose, true);
    };
  }, [onClose]);

  return createPortal(
    <div
      ref={ref}
      className="limit-balloon"
      style={{
        position: 'fixed',
        left: pos.left,
        top: pos.top,
        width: BALLOON_WIDTH,
        zIndex: 1100,
      }}
      role="alert"
    >
      <button type="button" className="limit-balloon__close" aria-label="Dismiss" onClick={onClose}>
        <i className="fas fa-times" />
      </button>
      <div className="limit-balloon__title">
        <i className="fas fa-triangle-exclamation me-2" />
        Limit reached
      </div>
      <div className="limit-balloon__body">{message}</div>
      <span className="limit-balloon__tail" />
    </div>,
    document.body
  );
};

export default LimitBalloon;
