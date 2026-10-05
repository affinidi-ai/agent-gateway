import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useParams } from 'react-router-dom';
import { apiClient } from '../api';
import { showToast } from '../utils/toaster';
import { formatDateTime } from '../utils/stringUtils';
import type { Authority } from '../types';
import { DeleteButton } from '../components/shared/DeleteButton';
import { useSafeNavigate } from '../hooks/useSafeNavigate';
import { clearAuthoritiesCache } from '../utils/authoritiesCache';
import FieldHelp from '../components/shared/FieldHelp';

interface EditAuthorityPageProps {
  embeddedId?: string;
  onDone?: () => void;
}

interface ContextParseResult {
  value: Record<string, unknown> | null;
  error: string | null;
}

/**
 * Parse the JSON `context` textarea. Empty/whitespace → null (field cleared).
 * Non-object results (array, primitive, invalid JSON) surface an error and
 * block save.
 */
function parseContext(raw: string): ContextParseResult {
  const trimmed = raw.trim();
  if (!trimmed) return { value: null, error: null };
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch (err: any) {
    return { value: null, error: err?.message || 'Invalid JSON' };
  }
  if (parsed === null) return { value: null, error: null };
  if (typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { value: null, error: 'Context must be a JSON object' };
  }
  return { value: parsed as Record<string, unknown>, error: null };
}

const EditAuthorityPage: React.FC<EditAuthorityPageProps> = ({ embeddedId, onDone }) => {
  const { navigate } = useSafeNavigate();
  const { id: routeId } = useParams<{ id: string }>();
  const id = embeddedId !== undefined ? (embeddedId === 'new' ? undefined : embeddedId) : routeId;
  const isEditMode = id !== undefined;

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [did, setDid] = useState('');
  const [contextText, setContextText] = useState('');
  const [loading, setLoading] = useState(isEditMode);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [createdAt, setCreatedAt] = useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);

  const fetchAuthority = useCallback(async () => {
    if (!id) return;
    try {
      setLoading(true);
      const response = await apiClient.get<Authority>(`/authorities/${id}`);
      const authority = response.data;
      setName(authority.name);
      setDescription(authority.description || '');
      setDid(authority.did);
      setContextText(
        authority.context && typeof authority.context === 'object'
          ? JSON.stringify(authority.context, null, 2)
          : ''
      );
      setCreatedAt(authority.created_at || null);
      setUpdatedAt(authority.updated_at || null);
    } catch (err: any) {
      setError(err.message || 'Failed to load authority');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    if (isEditMode) {
      fetchAuthority();
    }
  }, [fetchAuthority, isEditMode]);

  const contextParse = useMemo(() => parseContext(contextText), [contextText]);
  const contextInvalid = contextText.trim().length > 0 && contextParse.error !== null;

  const handleSubmit = useCallback(async () => {
    if (!name.trim()) {
      setError('Authority name is required');
      return;
    }
    const trimmedDid = did.trim();
    if (!trimmedDid) {
      setError('Authority DID is required');
      return;
    }
    if (!trimmedDid.startsWith('did:')) {
      setError("Authority DID must start with 'did:'");
      return;
    }
    if (contextParse.error) {
      setError(`Authority context: ${contextParse.error}`);
      return;
    }
    try {
      setSaving(true);
      setError(null);
      const payload = {
        name: name.trim(),
        did: trimmedDid,
        description: description.trim() || undefined,
        context: contextParse.value ?? undefined,
      };
      if (isEditMode && id) {
        await apiClient.updateAuthority(id, payload);
      } else {
        await apiClient.createAuthority(payload);
      }
      clearAuthoritiesCache();
      onDone ? onDone() : navigate(-1);
    } catch (err: any) {
      setError(err.message || 'Failed to save authority');
    } finally {
      setSaving(false);
    }
  }, [name, did, description, contextParse, id, isEditMode, navigate, onDone]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault();
        handleSubmit();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [handleSubmit]);

  const handleDelete = async () => {
    if (!id) return;
    try {
      await apiClient.delete(`/authorities/${id}`);
      clearAuthoritiesCache();
      onDone ? onDone() : navigate(-1);
    } catch (err: any) {
      showToast('error', err.message || 'Failed to delete authority');
    }
  };

  if (loading) {
    return (
      <div
        style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          minHeight: '60vh',
        }}
      >
        <div className="spinner-border" role="status" style={{ color: 'rgba(0, 0, 0, 0.5)' }}>
          <span className="visually-hidden"></span>
        </div>
      </div>
    );
  }

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button
          className="btn btn-sm btn-secondary"
          onClick={() => (onDone ? onDone() : navigate(-1))}
        >
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div></div>
        <div className="d-flex gap-2">
          {isEditMode && <DeleteButton onDelete={handleDelete} />}
          <button
            className="btn btn-sm btn-primary"
            onClick={handleSubmit}
            disabled={saving || contextInvalid}
          >
            {saving ? (
              <>
                <span className="spinner-border spinner-border-sm me-1" role="status"></span>
                Saving...
              </>
            ) : (
              <>
                <i className="fas fa-save me-1"></i> Save
              </>
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="alert alert-danger alert-dismissible fade show" role="alert">
          {error}
          <button
            type="button"
            className="btn-close"
            onClick={() => setError(null)}
            aria-label="Close"
          />
        </div>
      )}

      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-landmark"></i> {isEditMode ? 'Edit Authority' : 'New Authority'}
          </h6>
        </div>
        <div className="card-body">
          <p className="text-muted mb-3">
            An authority is an outside organization you trust to vouch for issuers. Trust Check (a
            separate feature) can reference an authority when deciding whether to accept a
            credential.
          </p>
          <div className="mb-3">
            <label className="form-label" htmlFor="authority-name">
              Authority Name
            </label>
            <input
              id="authority-name"
              type="text"
              className="form-control"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="Enter authority name"
              autoFocus
              required
            />
          </div>
          <div className="mb-3">
            <div className="field-label-with-help">
              <label className="form-label mb-0" htmlFor="authority-did">
                Authority DID
              </label>
              <FieldHelp ariaLabel="About Authority DID" testId="field-help-authority-did">
                The outside organization's DID (Decentralized Identifier), the ID that anchors trust
                to this authority.
              </FieldHelp>
            </div>
            <input
              id="authority-did"
              type="text"
              className="form-control"
              value={did}
              onChange={e => setDid(e.target.value)}
              placeholder="did:web:your-authority.example.com"
              disabled={isEditMode}
              required
            />
            <small className="form-text text-muted">
              {isEditMode
                ? 'The DID is set at creation and cannot be changed.'
                : 'External DID for this trust anchor. Must start with did: and be unique.'}
            </small>
          </div>
          <div className="mb-3">
            <label className="form-label" htmlFor="authority-description">
              Authority Description
            </label>
            <textarea
              id="authority-description"
              className="form-control"
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder="Optional description"
              rows={3}
            />
          </div>
          <div className="mb-3">
            <div className="field-label-with-help">
              <label className="form-label mb-0" htmlFor="authority-context">
                Authority Context
                {contextInvalid && (
                  <span className="ms-2 text-danger small">
                    <i className="fas fa-exclamation-circle"></i> {contextParse.error}
                  </span>
                )}
                {!contextInvalid && contextText.trim() && (
                  <span className="ms-2 text-success small">
                    <i className="fas fa-check-circle"></i> Valid JSON object
                  </span>
                )}
              </label>
              <FieldHelp ariaLabel="About Authority Context" testId="field-help-authority-context">
                A JSON object of extra properties that policy rules (written in Rego, an
                authorization-policy language) or Trust Check can read when deciding whether to
                trust this authority.
              </FieldHelp>
            </div>
            <textarea
              id="authority-context"
              className={`form-control font-monospace small ${contextInvalid ? 'is-invalid' : ''}`}
              rows={8}
              style={{ fontSize: '0.875rem' }}
              value={contextText}
              onChange={e => setContextText(e.target.value)}
              placeholder='{\n  "role": "issuer"\n}'
            />
            {contextInvalid && <div className="invalid-feedback d-block">{contextParse.error}</div>}
            <small className="form-text text-muted">
              Optional. Must be a JSON object, for example: {'{"role": "issuer"}'}.
            </small>
          </div>
        </div>
      </div>

      {isEditMode && (createdAt || updatedAt) && (
        <div className="card shadow mb-4">
          <div className="card-header py-3">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-clock me-2"></i>Metadata
            </h6>
          </div>
          <div className="card-body">
            <div className="row">
              {createdAt && (
                <div className="col-md-6">
                  <label className="form-label text-muted small">Created</label>
                  <div>{formatDateTime(createdAt)}</div>
                </div>
              )}
              {updatedAt && (
                <div className="col-md-6">
                  <label className="form-label text-muted small">Last updated</label>
                  <div>{formatDateTime(updatedAt)}</div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default EditAuthorityPage;
