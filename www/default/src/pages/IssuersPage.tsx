import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../api';
import { Badge } from '../components/shared/Badge';
import { showToast } from '../utils/toaster';
import { AppButton } from '../components/shared/AppButton';
import { EmptyState } from '../components/shared/EmptyState';
import { DeleteButton } from '../components/shared/DeleteButton';
import { CopyButton } from '../components/shared/CopyButton';
import { topAndTail } from '../utils/stringUtils';
import { DOCS_URL } from '../config/docs';

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

interface IssuersPageProps {
  onEdit?: (id: string) => void;
  onAdd?: () => void;
  externalSearchTerm?: string;
  onFilteredCountChange?: (n: number) => void;
  hideAddButton?: boolean;
}

const IssuersPage: React.FC<IssuersPageProps> = ({
  onEdit,
  onAdd,
  externalSearchTerm,
  onFilteredCountChange,
  hideAddButton,
}) => {
  const navigate = useNavigate();
  const [issuers, setIssuers] = useState<Issuer[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [retryingTr, setRetryingTr] = useState<Set<string>>(new Set());

  const fetchIssuers = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get('/issuers');
      setIssuers(response.data);
    } catch (err: any) {
      setError(err.message || 'Failed to load issuers');
    } finally {
      setLoading(false);
    }
  };

  const handleRetryTr = useCallback(async (issuerId: string) => {
    setRetryingTr(prev => new Set(prev).add(issuerId));
    try {
      const res = await apiClient.retryIssuerTrRegistration(issuerId);
      if (res?.data?.success) {
        showToast('success', 'Issuer registered in trust registry');
        fetchIssuers();
      } else {
        showToast('error', res?.data?.message || 'TR registration failed');
      }
    } catch (err: any) {
      showToast('error', err?.message || 'TR registration retry failed');
    } finally {
      setRetryingTr(prev => {
        const next = new Set(prev);
        next.delete(issuerId);
        return next;
      });
    }
  }, []);

  useEffect(() => {
    fetchIssuers();
  }, []);

  const filteredIssuers = useMemo(() => {
    const q = (externalSearchTerm ?? '').trim().toLowerCase();
    if (!q) return issuers;
    return issuers.filter(
      i =>
        i.name.toLowerCase().includes(q) ||
        (i.description ?? '').toLowerCase().includes(q) ||
        i.did.toLowerCase().includes(q) ||
        (i.trust_registry_did ?? '').toLowerCase().includes(q) ||
        (i.authority_did ?? '').toLowerCase().includes(q)
    );
  }, [issuers, externalSearchTerm]);

  useEffect(() => {
    onFilteredCountChange?.(filteredIssuers.length);
  }, [filteredIssuers.length, onFilteredCountChange]);

  const handleDelete = async (id: string) => {
    try {
      await apiClient.delete(`/issuers/${id}`);
      setSuccess('Issuer deleted successfully');
      setTimeout(() => setSuccess(null), 3000);
      fetchIssuers();
    } catch (err: any) {
      setError(err.message || 'Failed to delete issuer');
    }
  };

  return (
    <div className="container-fluid">
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
      {success && (
        <div className="alert alert-success alert-dismissible fade show" role="alert">
          {success}
          <button
            type="button"
            className="btn-close"
            onClick={() => setSuccess(null)}
            aria-label="Close"
          />
        </div>
      )}

      {loading ? (
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
      ) : (
        <div className="card shadow mb-4">
          <div className="card-header py-3 d-flex justify-content-between align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-sitemap"></i> Issuers
              <Badge
                value={filteredIssuers.length}
                suffix={(externalSearchTerm ?? '').trim() ? ` of ${issuers.length}` : undefined}
                className="ms-2"
                ariaLabel={`${filteredIssuers.length}${(externalSearchTerm ?? '').trim() ? ` of ${issuers.length}` : ''} issuers`}
              />
            </h6>
            {!hideAddButton && (
              <AppButton
                variant="primary"
                size="md"
                className="shadow-sm"
                onClick={() => (onAdd ? onAdd() : navigate('/issuers/new'))}
                iconStart={<i className="fas fa-plus fa-sm me-2" aria-hidden="true" />}
              >
                Add Issuer
              </AppButton>
            )}
          </div>
          <div className="card-body">
            {issuers.length === 0 ? (
              <EmptyState
                icon="fa-sitemap"
                title="Add your first issuer"
                body="Issuers (Departments) own the surfaces that issue agent credentials. Add one to group and attribute your surfaces."
                docsHref={DOCS_URL.identity}
              />
            ) : filteredIssuers.length === 0 ? (
              <div className="text-center text-muted py-5">
                <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
                <p className="mb-0">No issuers match your search.</p>
              </div>
            ) : (
              <div className="table-responsive">
                <table className="table table-hover table-sm">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th style={{ width: '35%' }}>DID</th>
                      <th>Trust Registry Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredIssuers.map(issuer => (
                      <tr key={issuer.id}>
                        <td>
                          <div>{issuer.name}</div>
                          {issuer.description && (
                            <small className="text-muted">{issuer.description}</small>
                          )}
                        </td>
                        <td>
                          <div className="d-inline-flex align-items-center flex-nowrap">
                            <code
                              title={issuer.did}
                              style={{
                                whiteSpace: 'nowrap',
                                fontSize: '0.85em',
                              }}
                            >
                              {topAndTail(issuer.did, 20, 16)}
                            </code>
                            <CopyButton text={issuer.did} title="Copy DID" />
                          </div>
                        </td>
                        <td>
                          {!issuer.trust_registry_did ? (
                            <span className="text-muted">-</span>
                          ) : issuer.tr_registered === true ? (
                            <span
                              className="badge text-bg-success"
                              title="Registered with the Trust Registry"
                            >
                              Registered
                            </span>
                          ) : (
                            <>
                              <span
                                className="badge text-bg-danger"
                                title="Trust Registry registration failed"
                              >
                                Registration failed
                              </span>
                              <AppButton
                                variant="warning"
                                size="sm"
                                className="ms-1"
                                style={{
                                  marginLeft: '0.25rem',
                                  fontSize: '0.7rem',
                                  padding: '0.1rem 0.35rem',
                                }}
                                disabled={retryingTr.has(issuer.id)}
                                onClick={e => {
                                  e.stopPropagation();
                                  handleRetryTr(issuer.id);
                                }}
                                title="Retry Trust Registry registration"
                              >
                                {retryingTr.has(issuer.id) ? '...' : 'Retry TR'}
                              </AppButton>
                            </>
                          )}
                        </td>
                        <td>
                          <div className="d-flex gap-2">
                            <AppButton
                              variant="outline-primary"
                              size="sm"
                              aria-label={`Edit issuer ${issuer.name}`}
                              onClick={() =>
                                onEdit ? onEdit(issuer.id) : navigate(`/issuers/${issuer.id}`)
                              }
                            >
                              <i className="fas fa-edit" aria-hidden="true"></i>
                            </AppButton>
                            <DeleteButton onDelete={() => handleDelete(issuer.id)} />
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default IssuersPage;
