import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../api';
import type { Authority } from '../types';
import { Badge } from '../components/shared/Badge';
import { AppButton } from '../components/shared/AppButton';
import { EmptyState } from '../components/shared/EmptyState';
import { DeleteButton } from '../components/shared/DeleteButton';
import { CopyButton } from '../components/shared/CopyButton';
import { topAndTail } from '../utils/stringUtils';
import { clearAuthoritiesCache } from '../utils/authoritiesCache';
import { DOCS_URL } from '../config/docs';

interface AuthoritiesPageProps {
  onEdit?: (id: string) => void;
  onAdd?: () => void;
  externalSearchTerm?: string;
  onFilteredCountChange?: (n: number) => void;
  hideAddButton?: boolean;
}

const AuthoritiesPage: React.FC<AuthoritiesPageProps> = ({
  onEdit,
  onAdd,
  externalSearchTerm,
  onFilteredCountChange,
  hideAddButton,
}) => {
  const navigate = useNavigate();
  const [authorities, setAuthorities] = useState<Authority[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const fetchAuthorities = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get<Authority[]>('/authorities');
      setAuthorities(response.data);
    } catch (err: any) {
      setError(err.message || 'Failed to load authorities');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAuthorities();
  }, []);

  const filteredAuthorities = useMemo(() => {
    const q = (externalSearchTerm ?? '').trim().toLowerCase();
    if (!q) return authorities;
    return authorities.filter(
      a =>
        a.name.toLowerCase().includes(q) ||
        (a.description ?? '').toLowerCase().includes(q) ||
        a.did.toLowerCase().includes(q)
    );
  }, [authorities, externalSearchTerm]);

  useEffect(() => {
    onFilteredCountChange?.(filteredAuthorities.length);
  }, [filteredAuthorities.length, onFilteredCountChange]);

  const handleDelete = async (id: string) => {
    try {
      await apiClient.delete(`/authorities/${id}`);
      clearAuthoritiesCache();
      setSuccess('Authority deleted successfully');
      setTimeout(() => setSuccess(null), 3000);
      fetchAuthorities();
    } catch (err: any) {
      setError(err.message || 'Failed to delete authority');
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
              <i className="fas fa-landmark"></i> Authorities
              <Badge
                value={filteredAuthorities.length}
                suffix={(externalSearchTerm ?? '').trim() ? ` of ${authorities.length}` : undefined}
                className="ms-2"
                ariaLabel={`${filteredAuthorities.length}${
                  (externalSearchTerm ?? '').trim() ? ` of ${authorities.length}` : ''
                } authorities`}
              />
            </h6>
            {!hideAddButton && (
              <AppButton
                variant="primary"
                size="md"
                className="shadow-sm"
                onClick={() => (onAdd ? onAdd() : navigate('/authorities/new'))}
                iconStart={<i className="fas fa-plus fa-sm me-2" aria-hidden="true" />}
              >
                Add Authority
              </AppButton>
            )}
          </div>
          <div className="card-body">
            {authorities.length === 0 ? (
              <EmptyState
                icon="fa-landmark"
                title="Add your first authority"
                body="Authorities are the outside organizations you trust to vouch for issuers. Trust Check (a separate feature) can reference an authority when deciding whether to accept a credential."
                docsHref={DOCS_URL.identity}
              />
            ) : filteredAuthorities.length === 0 ? (
              <div className="text-center text-muted py-5">
                <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
                <p className="mb-0">No authorities match your search.</p>
              </div>
            ) : (
              <div className="table-responsive">
                <table className="table table-hover table-sm">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th style={{ width: '45%' }}>DID</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredAuthorities.map(authority => (
                      <tr key={authority.id}>
                        <td>
                          <div>{authority.name}</div>
                          {authority.description && (
                            <small className="text-muted">{authority.description}</small>
                          )}
                        </td>
                        <td>
                          <div className="d-inline-flex align-items-center flex-nowrap">
                            <code
                              title={authority.did}
                              style={{
                                whiteSpace: 'nowrap',
                                fontSize: '0.85em',
                              }}
                            >
                              {topAndTail(authority.did, 20, 16)}
                            </code>
                            <CopyButton text={authority.did} title="Copy DID" />
                          </div>
                        </td>
                        <td>
                          <div className="d-flex gap-2">
                            <AppButton
                              variant="outline-primary"
                              size="sm"
                              aria-label={`Edit authority ${authority.name}`}
                              onClick={() =>
                                onEdit
                                  ? onEdit(authority.id)
                                  : navigate(`/authorities/${authority.id}`)
                              }
                            >
                              <i className="fas fa-edit" aria-hidden="true"></i>
                            </AppButton>
                            <DeleteButton onDelete={() => handleDelete(authority.id)} />
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

export default AuthoritiesPage;
