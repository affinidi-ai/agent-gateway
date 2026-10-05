import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../../api';
import type { AccessTokenCreated, AccessTokenMeta } from '../../types';
import { getErrorMessage } from '../../utils/apiError';
import { showToast } from '../../utils/toaster';
import { validateScopeConfig } from '../SecretsPage/accessTokenHelpers';
import { accessTokenExpiryBounds, validateAccessTokenExpiry } from './accessTokenExpiry';
import {
  ACCESS_TOKEN_LIST_ROUTE,
  AccessTokenFormState,
  accessTokenFormFor,
  accessTokenPayload,
  newAccessTokenForm,
} from './editorHelpers';

export function useAccessTokenEditor(id: string | undefined, availableScopes: string[]) {
  const navigate = useNavigate();
  const isEditMode = Boolean(id);
  const initialNow = useRef(new Date());
  const requestGeneration = useRef(0);
  const [form, setForm] = useState(() => newAccessTokenForm(initialNow.current));
  const [expiryReference, setExpiryReference] = useState(initialNow.current);
  const [token, setToken] = useState<AccessTokenMeta | null>(null);
  const [created, setCreated] = useState<AccessTokenCreated | null>(null);
  const [loading, setLoading] = useState(isEditMode);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [validationAttempted, setValidationAttempted] = useState(false);

  useEffect(() => {
    const generation = ++requestGeneration.current;
    setCreated(null);
    setError(null);
    setValidationAttempted(false);

    if (!id) {
      const now = new Date();
      setExpiryReference(now);
      setForm(newAccessTokenForm(now));
      setToken(null);
      setLoading(false);
    } else {
      setLoading(true);
      apiClient
        .getAccessToken(id)
        .then(loaded => {
          if (generation !== requestGeneration.current) return;
          setToken(loaded);
          setForm(accessTokenFormFor(loaded));
        })
        .catch(loadError => {
          if (generation !== requestGeneration.current) return;
          setError(getErrorMessage(loadError, 'Failed to load access token'));
        })
        .finally(() => {
          if (generation === requestGeneration.current) setLoading(false);
        });
    }

    return () => {
      if (generation === requestGeneration.current) requestGeneration.current += 1;
    };
  }, [id]);

  const updateField = <Key extends keyof AccessTokenFormState>(
    key: Key,
    value: AccessTokenFormState[Key]
  ) => setForm(current => ({ ...current, [key]: value }));

  const scopeErrors = useMemo(
    () => validateScopeConfig(form.resourcePattern, form.requiredHeaders),
    [form.requiredHeaders, form.resourcePattern]
  );
  const expiry = validateAccessTokenExpiry(form.neverExpires, form.expiresAt);
  const expiryBounds = accessTokenExpiryBounds(expiryReference);
  const unavailableScopes = useMemo(() => {
    const available = new Set(availableScopes);
    return form.scopes.filter(scope => !available.has(scope));
  }, [availableScopes, form.scopes]);
  const revoked = Boolean(token?.revoked_at);
  const nameError = form.name.trim() ? undefined : 'Name is required.';
  const canSave =
    !nameError &&
    scopeErrors.length === 0 &&
    unavailableScopes.length === 0 &&
    !expiry.error &&
    !revoked;

  const leave = () => {
    if (saving) return;
    requestGeneration.current += 1;
    setCreated(null);
    navigate(ACCESS_TOKEN_LIST_ROUTE);
  };

  const save = async () => {
    setValidationAttempted(true);
    if (!canSave) return;
    const generation = ++requestGeneration.current;
    setSaving(true);
    setError(null);
    try {
      const payload = accessTokenPayload(form);
      if (id) {
        const updated = await apiClient.updateAccessToken(id, payload);
        if (generation !== requestGeneration.current) return;
        setToken(updated);
        showToast('success', 'Access token updated');
      } else {
        const nextCreated = await apiClient.createAccessToken({
          ...payload,
          expires_at: expiry.expiresAt,
        });
        if (generation !== requestGeneration.current) return;
        setCreated(nextCreated);
      }
    } catch (saveError) {
      if (generation !== requestGeneration.current) return;
      setError(getErrorMessage(saveError, 'Failed to save access token'));
    } finally {
      if (generation === requestGeneration.current) setSaving(false);
    }
  };

  const revoke = async () => {
    if (!id) return;
    try {
      await apiClient.revokeAccessToken(id);
      showToast('success', 'Access token revoked');
      leave();
    } catch (revokeError) {
      setError(getErrorMessage(revokeError, 'Failed to revoke access token'));
    }
  };

  return {
    isEditMode,
    form,
    updateField,
    token,
    created,
    loading,
    saving,
    error,
    expiryBounds,
    expiryError: expiry.error,
    nameError,
    validationAttempted,
    unavailableScopes,
    revoked,
    canSave,
    leave,
    save,
    revoke,
  };
}

export type AccessTokenEditor = ReturnType<typeof useAccessTokenEditor>;
