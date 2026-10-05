import React, { useCallback, useState } from 'react';
import LimitBalloon from '../components/shared/LimitBalloon';
import { useLimits } from './useLimits';

/**
 * Keeps create buttons clickable but pops a "limit reached" balloon (instead of
 * running the action) when the entity's dimension is at capacity. Render
 * `balloonNode` once in the component and call `guard(dimension, action, event)`
 * from the button's onClick.
 */
export function useLimitGuard() {
  const { checkLimit, refresh } = useLimits();
  const [balloon, setBalloon] = useState<{ rect: DOMRect; message: string } | null>(null);

  const guard = useCallback(
    (dimension: string, action: () => void, e: React.MouseEvent<HTMLElement>) => {
      const check = checkLimit(dimension);
      if (check) {
        e.preventDefault();
        e.stopPropagation();
        setBalloon({ rect: e.currentTarget.getBoundingClientRect(), message: check.message });
        return;
      }
      action();
    },
    [checkLimit]
  );

  const balloonNode = balloon ? (
    <LimitBalloon
      anchorRect={balloon.rect}
      message={balloon.message}
      onClose={() => setBalloon(null)}
    />
  ) : null;

  return { guard, balloonNode, refreshLimits: refresh };
}
