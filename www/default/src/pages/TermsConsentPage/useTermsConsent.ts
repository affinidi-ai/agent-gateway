import { useCallback, useEffect, useState } from 'react';
import {
  acceptTerms,
  loadTermsStatus,
  termsRequirementKey,
  TermsApiError,
  TermsRequirement,
} from '../../termsApi';

export const termsSelectionKey = termsRequirementKey;

export const useTermsConsent = (onAccepted: () => void) => {
  const [required, setRequired] = useState<TermsRequirement[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const status = await loadTermsStatus();
      if (!status.consent_required) {
        onAccepted();
        return;
      }
      setRequired(status.required_terms);
      setSelected(new Set());
    } catch {
      setError('Terms acceptance cannot be verified. Try again when the appliance is available.');
    } finally {
      setLoading(false);
    }
  }, [onAccepted]);

  useEffect(() => {
    void load();
  }, [load]);

  const toggle = (term: TermsRequirement, checked: boolean) => {
    setSelected(previous => {
      const next = new Set(previous);
      const key = termsSelectionKey(term);
      checked ? next.add(key) : next.delete(key);
      return next;
    });
  };

  const submit = async () => {
    setSubmitting(true);
    setError(null);
    try {
      await acceptTerms(required);
      onAccepted();
    } catch (caught) {
      if (caught instanceof TermsApiError && caught.code === 'TERMS_VERSION_STALE') {
        if (caught.requiredTerms.length === 0) {
          onAccepted();
          return;
        }
        setRequired(caught.requiredTerms);
        setSelected(new Set());
        setError('The Terms changed while you were reviewing them. Review the current versions.');
      } else {
        setError('Acceptance could not be recorded. Please try again.');
      }
    } finally {
      setSubmitting(false);
    }
  };

  return {
    required,
    selected,
    loading,
    submitting,
    error,
    allSelected:
      required.length > 0 && required.every(term => selected.has(termsSelectionKey(term))),
    toggle,
    submit,
  };
};
