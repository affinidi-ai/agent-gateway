import { useCallback, useEffect, useRef } from 'react';
import { NavigateOptions, To, useNavigate } from 'react-router-dom';

/**
 * Drop-in replacement for `useNavigate` that is safe to call across an async
 * gap — e.g. after an `await save()`.
 *
 * If the component has unmounted in the meantime (typically because the user
 * navigated elsewhere while a save was still in flight), the navigation is
 * skipped instead of yanking the user back to the save handler's target route.
 *
 * `navigate(to, options?)` / `navigate(delta)` — navigates only while mounted.
 */
export function useSafeNavigate() {
  const routerNavigate = useNavigate();
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const navigate = useCallback(
    (to: To | number, options?: NavigateOptions) => {
      if (!mountedRef.current) return;
      if (typeof to === 'number') {
        routerNavigate(to);
      } else {
        routerNavigate(to, options);
      }
    },
    [routerNavigate]
  );

  return { navigate };
}
