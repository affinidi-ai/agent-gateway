import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';

interface PageTitleContextValue {
  title: string | null;
  setTitle: (title: string | null) => void;
}

const PageTitleContext = createContext<PageTitleContextValue | undefined>(undefined);

export const PageTitleProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [title, setTitle] = useState<string | null>(null);
  const value = useMemo<PageTitleContextValue>(
    () => ({
      title,
      setTitle: (next: string | null) => setTitle(next),
    }),
    [title]
  );
  return <PageTitleContext.Provider value={value}>{children}</PageTitleContext.Provider>;
};

export const usePageTitleContext = (): PageTitleContextValue => {
  const ctx = useContext(PageTitleContext);
  if (!ctx) throw new Error('usePageTitleContext must be used within PageTitleProvider');
  return ctx;
};

/**
 * Set the top-bar page title from any page. Pass `null` (or omit by
 * not calling) to fall back to the route-based default in `Header`.
 * The title clears on unmount so navigating away restores the
 * default for the next route.
 */
export function usePageTitle(title: string | null | undefined): void {
  const { setTitle } = usePageTitleContext();
  const normalized = title && title.trim().length > 0 ? title : null;
  const setStable = useCallback(setTitle, [setTitle]);
  useEffect(() => {
    setStable(normalized);
    return () => setStable(null);
  }, [normalized, setStable]);
}
