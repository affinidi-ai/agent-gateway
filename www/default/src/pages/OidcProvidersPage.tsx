import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { usePermissions } from '../context/PermissionsContext';
import { apiClient } from '../api';

export interface OidcProvider {
  id: string;
  name: string;
  issuer_url: string;
  expected_issuer?: string;
  jwks_uri?: string;
  validation_strategy: 'jwt' | 'introspection';
  created_at: string;
  updated_at: string;
}

const OidcProvidersPage: React.FC = () => {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const [providers, setProviders] = useState<OidcProvider[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const canEdit = hasPermission('oidc_providers.edit');
  const canDelete = hasPermission('oidc_providers.delete');

  useEffect(() => {
    loadProviders();
  }, []);

  const loadProviders = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiClient.fetch('/api/v1/oidc-providers');
      if (!response.ok) {
        throw new Error(`Failed to load providers: ${response.statusText}`);
      }
      const data: OidcProvider[] = await response.json();
      setProviders(data);
    } catch (e: any) {
      setError(e.message ?? 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (provider: OidcProvider) => {
    if (
      !window.confirm(
        `Delete OIDC provider "${provider.name}"?\n\nWarning: any channel still referencing this provider will return 403.`
      )
    ) {
      return;
    }
    setDeletingId(provider.id);
    try {
      const response = await apiClient.fetch(
        `/api/v1/oidc-providers/${encodeURIComponent(provider.id)}`,
        { method: 'DELETE' }
      );
      if (!response.ok) {
        throw new Error(`Delete failed: ${response.statusText}`);
      }
      setProviders(prev => prev.filter(p => p.id !== provider.id));
    } catch (e: any) {
      alert(`Failed to delete provider: ${e.message}`);
    } finally {
      setDeletingId(null);
    }
  };

  const filtered = providers.filter(
    p =>
      p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.issuer_url.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="container-fluid">
      {/* Page Heading */}
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <h1 className="h3 mb-0 text-gray-800">
          <i className="fas fa-id-badge me-2"></i>OIDC Providers
        </h1>
        {canEdit && (
          <button
            className="btn btn-primary btn-sm shadow-sm"
            onClick={() => navigate('/oidc-providers/new')}
          >
            <i className="fas fa-plus fa-sm me-1"></i> Add Provider
          </button>
        )}
      </div>

      {/* Search */}
      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <div className="input-group">
            <input
              type="text"
              className="form-control bg-light border-0 small"
              placeholder="Search by name or issuer URL…"
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
            />
            <div className="input-group-append">
              <button className="btn btn-primary" type="button">
                <i className="fas fa-search fa-sm"></i>
              </button>
            </div>
          </div>
        </div>

        <div className="card-body">
          {loading && (
            <div className="text-center py-4">
              <div className="spinner-border text-primary" role="status" />
            </div>
          )}

          {error && (
            <div className="alert alert-danger">
              <i className="fas fa-exclamation-triangle me-2"></i>
              {error}
              <button className="btn btn-sm btn-outline-danger ms-3" onClick={loadProviders}>
                Retry
              </button>
            </div>
          )}

          {!loading && !error && filtered.length === 0 && (
            <div className="text-center text-muted py-5">
              <i className="fas fa-id-badge fa-3x mb-3 d-block"></i>
              {providers.length === 0
                ? 'No OIDC providers configured yet.'
                : 'No providers match your search.'}
              {canEdit && providers.length === 0 && (
                <div className="mt-3">
                  <button
                    className="btn btn-primary"
                    onClick={() => navigate('/oidc-providers/new')}
                  >
                    <i className="fas fa-plus me-1"></i> Add your first provider
                  </button>
                </div>
              )}
            </div>
          )}

          {!loading && !error && filtered.length > 0 && (
            <div className="table-responsive">
              <table className="table table-bordered table-hover" width="100%" cellSpacing="0">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Issuer URL</th>
                    <th>Strategy</th>
                    <th>Custom JWKS</th>
                    <th>Updated</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(provider => (
                    <tr key={provider.id}>
                      <td>
                        <strong>{provider.name}</strong>
                        <div>
                          <small className="text-muted font-monospace">{provider.id}</small>
                        </div>
                      </td>
                      <td>
                        <code>{provider.issuer_url}</code>
                        {provider.expected_issuer && (
                          <div>
                            <small className="text-muted">
                              iss override: <code>{provider.expected_issuer}</code>
                            </small>
                          </div>
                        )}
                      </td>
                      <td>
                        <span
                          className={`badge badge-${provider.validation_strategy === 'jwt' ? 'success' : 'warning'}`}
                        >
                          {provider.validation_strategy.toUpperCase()}
                        </span>
                      </td>
                      <td>
                        {provider.jwks_uri ? (
                          <code className="small">{provider.jwks_uri}</code>
                        ) : (
                          <span className="text-muted">auto-discover</span>
                        )}
                      </td>
                      <td>
                        <small>{new Date(provider.updated_at).toLocaleString()}</small>
                      </td>
                      <td>
                        {canEdit && (
                          <button
                            className="btn btn-sm btn-outline-primary me-1"
                            onClick={() => navigate(`/oidc-providers/${provider.id}`)}
                            title="Edit"
                          >
                            <i className="fas fa-edit"></i>
                          </button>
                        )}
                        {canDelete && (
                          <button
                            className="btn btn-sm btn-outline-danger"
                            onClick={() => handleDelete(provider)}
                            disabled={deletingId === provider.id}
                            title="Delete"
                          >
                            {deletingId === provider.id ? (
                              <span className="spinner-border spinner-border-sm" />
                            ) : (
                              <i className="fas fa-trash"></i>
                            )}
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default OidcProvidersPage;
