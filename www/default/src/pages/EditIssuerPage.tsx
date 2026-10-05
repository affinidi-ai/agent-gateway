import React, { useCallback, useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { apiClient } from '../api';
import { showToast } from '../utils/toaster';
import { formatDateTime } from '../utils/stringUtils';
import { TrustRegistry } from '../types';
import { DeleteButton } from '../components/shared/DeleteButton';
import { useSafeNavigate } from '../hooks/useSafeNavigate';
import FieldHelp from '../components/shared/FieldHelp';

interface Issuer {
  id: string;
  name: string;
  description?: string;
  did: string;
  trust_registry_did?: string;
  authority_did?: string;
  tr_registered?: boolean | null;
  created_at: string;
  updated_at: string;
}

interface EditIssuerPageProps {
  embeddedId?: string;
  onDone?: () => void;
}

const EditIssuerPage: React.FC<EditIssuerPageProps> = ({ embeddedId, onDone }) => {
  const { navigate } = useSafeNavigate();
  const { id: routeId } = useParams<{ id: string }>();
  const id = embeddedId !== undefined ? (embeddedId === 'new' ? undefined : embeddedId) : routeId;
  const isEditMode = id !== undefined;

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [did, setDid] = useState('');
  const [trustRegistryDid, setTrustRegistryDid] = useState('');
  const [authorityDid, setAuthorityDid] = useState('');
  const [trustRegistries, setTrustRegistries] = useState<TrustRegistry[]>([]);
  const [loading, setLoading] = useState(isEditMode);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [trRegistered, setTrRegistered] = useState<boolean | null | undefined>(undefined);
  const [retryingTr, setRetryingTr] = useState(false);
  const [createdAt, setCreatedAt] = useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);

  const fetchIssuer = useCallback(async () => {
    try {
      setLoading(true);
      const response = await apiClient.get(`/issuers/${id}`);
      const issuer: Issuer = response.data;
      setName(issuer.name);
      setDescription(issuer.description || '');
      setDid(issuer.did);
      if (issuer.trust_registry_did) setTrustRegistryDid(issuer.trust_registry_did);
      if (issuer.authority_did) setAuthorityDid(issuer.authority_did);
      setTrRegistered(issuer.tr_registered);
      setCreatedAt(issuer.created_at || null);
      setUpdatedAt(issuer.updated_at || null);
    } catch (err: any) {
      setError(err.message || 'Failed to load issuer');
    } finally {
      setLoading(false);
    }
  }, [id]);

  const handleRetryTr = useCallback(async () => {
    if (!id) return;
    setRetryingTr(true);
    try {
      const res = await apiClient.retryIssuerTrRegistration(id);
      if (res?.data?.success) {
        showToast('success', 'Issuer registered in trust registry');
        setTrRegistered(true);
      } else {
        showToast('error', res?.data?.message || 'TR registration failed');
      }
    } catch (err: any) {
      showToast('error', err?.message || 'TR registration retry failed');
    } finally {
      setRetryingTr(false);
    }
  }, [id]);

  useEffect(() => {
    if (isEditMode) {
      fetchIssuer();
    }
  }, [fetchIssuer, isEditMode]);

  useEffect(() => {
    if (!isEditMode) {
      apiClient
        .listTrustRegistries()
        .then(registries => {
          setTrustRegistries(registries.filter(r => r.status === 'active'));
        })
        .catch(() => {});

      apiClient
        .getGatewayDidDocument()
        .then((doc: any) => {
          if (doc?.id) setAuthorityDid(doc.id);
        })
        .catch(() => {});
    }
  }, [isEditMode]);

  const handleSubmit = useCallback(async () => {
    if (!name.trim()) {
      setError('Issuer name is required');
      return;
    }
    if (!description.trim()) {
      setError('Issuer description is required');
      return;
    }
    if (!isEditMode && trustRegistryDid && !authorityDid.trim()) {
      setError('Authority DID is required when a Trust Registry is selected');
      return;
    }
    try {
      setSaving(true);
      setError(null);
      if (isEditMode) {
        await apiClient.put(`/issuers/${id}`, {
          name: name.trim(),
          description: description.trim(),
        });
      } else {
        const payload: any = { name: name.trim(), description: description.trim() };
        if (trustRegistryDid && authorityDid.trim()) {
          payload.trust_registry_did = trustRegistryDid;
          payload.authority_did = authorityDid.trim();
        }
        await apiClient.post('/issuers', payload);
      }
      onDone ? onDone() : navigate(-1);
    } finally {
      setSaving(false);
    }
  }, [name, description, id, isEditMode, trustRegistryDid, authorityDid, navigate, onDone]);

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
    try {
      await apiClient.delete(`/issuers/${id}`);
      onDone ? onDone() : navigate(-1);
    } catch (err: any) {
      showToast('error', err.message || 'Failed to delete issuer');
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
          <button className="btn btn-sm btn-primary" onClick={handleSubmit} disabled={saving}>
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
            <i className="fas fa-sitemap"></i> {isEditMode ? 'Edit Issuer' : 'New Issuer'}
          </h6>
        </div>
        <div className="card-body">
          <p className="text-muted mb-3">
            An issuer is the department or team whose surfaces issue credentials. Trust Registry
            registration lets outside parties verify that credential back to your organization.
          </p>
          <div className="mb-3">
            <label className="form-label" htmlFor="issuer-name">
              Issuer Name
            </label>
            <input
              id="issuer-name"
              type="text"
              className="form-control"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="Enter issuer name"
              autoFocus
            />
          </div>
          <div className="mb-3">
            <label className="form-label" htmlFor="issuer-description">
              Issuer Description
            </label>
            <textarea
              id="issuer-description"
              className="form-control"
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder="Enter issuer description"
              rows={3}
            />
            <small className="form-text text-muted">
              Explains what this issuer is for, shown alongside its name wherever issuers are
              listed. A description is required for every issuer.
            </small>
          </div>
          {isEditMode && did && (
            <div className="mb-3">
              <div className="field-label-with-help">
                <label className="form-label mb-0" htmlFor="issuer-did">
                  DID
                </label>
                <FieldHelp ariaLabel="About DID" testId="field-help-issuer-did">
                  A DID (Decentralized Identifier) is the unique ID this issuer uses to sign and be
                  identified by. The DID is auto-generated and cannot be changed.
                </FieldHelp>
              </div>
              <input id="issuer-did" type="text" className="form-control" value={did} disabled />
            </div>
          )}

          {!isEditMode && trustRegistries.length > 0 && (
            <>
              <div className="mb-3">
                <div className="field-label-with-help">
                  <label className="form-label mb-0" htmlFor="issuer-trust-registry">
                    Trust Registry
                  </label>
                  <FieldHelp ariaLabel="About Trust Registry" testId="field-help-trust-registry">
                    Optionally register this issuer with an outside trust registry, a directory
                    other organizations can check to confirm this issuer is legitimate. Registration
                    happens automatically over DIDComm, a secure messaging protocol used between
                    gateways.
                  </FieldHelp>
                </div>
                <select
                  className="form-control dropdown-styling"
                  id="issuer-trust-registry"
                  value={trustRegistryDid}
                  onChange={e => setTrustRegistryDid(e.target.value)}
                >
                  <option value="">None</option>
                  {trustRegistries.map(tr => (
                    <option key={tr.id} value={tr.main_did ?? tr.registry_did ?? ''}>
                      {tr.name}
                    </option>
                  ))}
                </select>
                <small className="form-text text-muted">
                  Register this issuer in the selected trust registry via DIDComm.
                </small>
              </div>
              {trustRegistryDid && (
                <div className="mb-3">
                  <div className="field-label-with-help">
                    <label className="form-label mb-0" htmlFor="issuer-authority-did">
                      Authority DID
                    </label>
                    <FieldHelp ariaLabel="About Authority DID" testId="field-help-authority-did">
                      A DID (Decentralized Identifier) is a unique ID for an organization or
                      identity. This is the DID of the authority (a trusted outside organization)
                      that vouches for this issuer.
                    </FieldHelp>
                  </div>
                  <input
                    id="issuer-authority-did"
                    type="text"
                    className="form-control"
                    value={authorityDid}
                    onChange={e => setAuthorityDid(e.target.value)}
                    placeholder="did:web:your-company-did"
                  />
                </div>
              )}
            </>
          )}
          {isEditMode && trustRegistryDid && (
            <>
              <div className="mb-3">
                <label className="form-label" htmlFor="issuer-trust-registry-ro">
                  Trust Registry DID
                </label>
                <input
                  id="issuer-trust-registry-ro"
                  type="text"
                  className="form-control"
                  value={trustRegistryDid}
                  disabled
                />
              </div>
              <div className="mb-3">
                <label className="form-label" htmlFor="issuer-authority-did-ro">
                  Authority DID
                </label>
                <input
                  id="issuer-authority-did-ro"
                  type="text"
                  className="form-control"
                  value={authorityDid}
                  disabled
                />
                <small className="form-text text-muted">
                  Trust registry registration is set at creation and cannot be changed.
                </small>
              </div>
              <div className="mb-3">
                <div className="field-label-with-help">
                  <label className="form-label mb-0">TR Registration Status</label>
                  <FieldHelp
                    ariaLabel="About TR Registration Status"
                    testId="field-help-tr-registration-status"
                  >
                    If registration fails, the issuer still works normally inside the gateway. It
                    just won't be discoverable by outside parties checking the trust registry until
                    registration succeeds.
                  </FieldHelp>
                </div>
                <div>
                  {trRegistered === true ? (
                    <span className="badge text-bg-success">Registered</span>
                  ) : (
                    <>
                      <span className="badge text-bg-danger">Failed</span>
                      <button
                        className="btn btn-xs btn-warning ms-1"
                        style={{
                          marginLeft: '0.5rem',
                          fontSize: '0.8rem',
                          padding: '0.15rem 0.5rem',
                        }}
                        disabled={retryingTr}
                        onClick={handleRetryTr}
                      >
                        {retryingTr ? 'Retrying...' : 'Retry TR Registration'}
                      </button>
                    </>
                  )}
                </div>
                <small className="form-text text-muted">
                  Retry re-attempts the same registration.
                </small>
              </div>
            </>
          )}
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
                <div className="col-md-6 mb-3">
                  <label className="form-label">Created</label>
                  <input
                    type="text"
                    className="form-control"
                    value={formatDateTime(createdAt, true)}
                    disabled
                  />
                </div>
              )}
              {updatedAt && (
                <div className="col-md-6 mb-3">
                  <label className="form-label">Last Updated</label>
                  <input
                    type="text"
                    className="form-control"
                    value={formatDateTime(updatedAt, true)}
                    disabled
                  />
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default EditIssuerPage;
