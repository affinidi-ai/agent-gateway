import { useCallback, useEffect, useState } from 'react';
import { loadApplicableTerms, termsRequirementKey, TermsRequirement } from '../termsApi';

export const registrationTermsKey = termsRequirementKey;

export const useRegistrationTerms = (active: boolean, onLoadError: (message: string) => void) => {
  const [requirements, setRequirements] = useState<TermsRequirement[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [ready, setReady] = useState(false);

  const reload = useCallback(async () => {
    setReady(false);
    const terms = await loadApplicableTerms();
    setRequirements(terms);
    setSelected(new Set());
    setReady(true);
  }, []);

  useEffect(() => {
    if (!active) return;
    void reload().catch(() =>
      onLoadError('The Terms required for registration could not be loaded.')
    );
  }, [active, onLoadError, reload]);

  const toggle = (term: TermsRequirement, checked: boolean) => {
    setSelected(previous => {
      const next = new Set(previous);
      const key = registrationTermsKey(term);
      checked ? next.add(key) : next.delete(key);
      return next;
    });
  };

  return {
    requirements,
    selected,
    ready,
    reload,
    toggle,
    allAccepted: ready && requirements.every(term => selected.has(registrationTermsKey(term))),
  };
};
