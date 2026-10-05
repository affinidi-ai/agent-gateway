import { Dispatch, SetStateAction, useCallback, useEffect, useMemo, useState } from 'react';
import {
  CustomerTermsDraft,
  deactivateCustomerTerms,
  loadTermsDefinitions,
  publishCustomerTerms,
  saveCustomerTermsDraft,
  TermsDefinitions,
  TermsApiError,
} from '../../termsApi';

const emptyDraft: CustomerTermsDraft = {
  title: '',
  version: '',
  url: '',
  requires_reconsent: true,
};

export const useTermsManager = () => {
  const [definitions, setDefinitions] = useState<TermsDefinitions | null>(null);
  const [draft, setDraftState] = useState<CustomerTermsDraft>(emptyDraft);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const loaded = await loadTermsDefinitions();
      setDefinitions(loaded);
      setDraftState(loaded.customer.draft ?? emptyDraft);
    } catch {
      setError('Terms configuration could not be loaded.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const run = useCallback(
    async (action: () => Promise<unknown>, message: string) => {
      setSaving(true);
      setError(null);
      setNotice(null);
      try {
        await action();
        setNotice(message);
        await load();
      } catch (caught) {
        setError(
          caught instanceof TermsApiError && caught.code === 'TERMS_INVALID'
            ? caught.message
            : 'The Terms configuration could not be updated.'
        );
      } finally {
        setSaving(false);
      }
    },
    [load]
  );

  const current = useMemo(
    () =>
      definitions?.customer.versions.find(
        version => version.version_id === definitions.customer.current_version_id
      ),
    [definitions]
  );

  const setDraft = useCallback<Dispatch<SetStateAction<CustomerTermsDraft>>>(value => {
    setDraftState(value);
  }, []);

  const versionAlreadyPublished = useMemo(() => {
    const candidate = draft.version.trim();
    return Boolean(
      candidate &&
      definitions?.customer.versions.some(version => version.version.trim() === candidate)
    );
  }, [definitions, draft.version]);

  return {
    definitions,
    current,
    draft,
    setDraft,
    versionAlreadyPublished,
    saving,
    error,
    notice,
    publish: () =>
      run(async () => {
        await saveCustomerTermsDraft(draft);
        await publishCustomerTerms();
      }, 'Customer T&C published.'),
    deactivate: () => run(deactivateCustomerTerms, 'Customer T&C deactivated.'),
  };
};
