import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { usePermissions } from '../../context/PermissionsContext';
import { apiClient } from '../../api';
import { AppButton } from '../../components/shared/AppButton';
import { Badge } from '../../components/shared/Badge';
import SearchInput from '../../components/shared/SearchInput';
import { DeleteButton } from '../../components/shared/DeleteButton';
import { EmptyState } from '../../components/shared/EmptyState';
import { DOCS_URL } from '../../config/docs';
import { formatDateTime } from '../../utils/stringUtils';

interface CredentialProviderListItem {
  id: string;
  name: string;
  provider_id: string;
  provider_type: 'oauth2_authorization_code' | 'oauth2_client_credentials' | 'api_key';
  token_endpoint?: string;
  default_scopes: string[];
  token_refresh_enabled: boolean;
  description?: string;
  created_at: string;
  updated_at: string;
}

const PROVIDER_TYPE_LABELS: Record<string, string> = {
  oauth2_authorization_code: 'Authorization Code',
  oauth2_client_credentials: 'Client Credentials',
  api_key: 'API Key',
};

const PROVIDER_TYPE_COLORS: Record<string, string> = {
  oauth2_authorization_code: 'text-bg-info',
  oauth2_client_credentials: 'text-bg-primary',
  api_key: 'text-bg-warning',
};

interface CredentialProvidersTabProps {
  externalSearchTerm?: string;
  onFilteredCountChange?: (n: number) => void;
}

const CredentialProvidersTab: React.FC<CredentialProvidersTabProps> = ({
  externalSearchTerm,
  onFilteredCountChange,
}) => {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const [providers, setProviders] = useState<CredentialProviderListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [internalSearchTerm, setInternalSearchTerm] = useState('');
  const externalProvided = externalSearchTerm !== undefined;
  const searchTerm = externalProvided ? externalSearchTerm! : internalSearchTerm;
  const setSearchTerm = setInternalSearchTerm;

  const canEdit = hasPermission('settings.edit');

  useEffect(() => {
    loadProviders();
  }, []);

  const loadProviders = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiClient.fetch('/api/v1/credential-providers');
      if (!response.ok) {
        throw new Error(`Failed to load: ${response.statusText}`);
      }
      const data: CredentialProviderListItem[] = await response.json();
      setProviders(data);
    } catch (e: any) {
      setError(e.message ?? 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (provider: CredentialProviderListItem) => {
    try {
      const response = await apiClient.fetch(
        `/api/v1/credential-providers/${encodeURIComponent(provider.id)}`,
        { method: 'DELETE' }
      );
      if (!response.ok) {
        throw new Error(`Delete failed: ${response.statusText}`);
      }
      setProviders(prev => prev.filter(p => p.id !== provider.id));
    } catch (e: any) {
      alert(`Failed to delete provider: ${e.message}`);
    }
  };

  const filtered = useMemo(
    () =>
      providers.filter(p => {
        if (!searchTerm.trim()) return true;
        const s = searchTerm.toLowerCase();
        return (
          p.name.toLowerCase().includes(s) ||
          p.provider_id.toLowerCase().includes(s) ||
          (p.token_endpoint ?? '').toLowerCase().includes(s) ||
          (p.description ?? '').toLowerCase().includes(s)
        );
      }),
    [providers, searchTerm]
  );

  useEffect(() => {
    onFilteredCountChange?.(filtered.length);
  }, [filtered.length, onFilteredCountChange]);

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-id-card"></i> Credential Providers
          <Badge
            value={filtered.length}
            suffix={searchTerm ? ` of ${providers.length}` : undefined}
            className="ms-2"
            ariaLabel={`${filtered.length}${searchTerm ? ` of ${providers.length}` : ''} credential providers`}
          />
        </h6>
        <div className="d-flex align-items-center gap-2">
          {!externalProvided && (
            <SearchInput
              value={searchTerm}
              onChange={setSearchTerm}
              placeholder="Filter providers..."
            />
          )}
          {canEdit && (
            <AppButton
              variant="primary"
              size="md"
              className="shadow-sm"
              onClick={() => navigate('/credential-providers/new')}
              iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
            >
              Add Provider
            </AppButton>
          )}
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
            <AppButton variant="outline-danger" size="sm" className="ms-3" onClick={loadProviders}>
              Retry
            </AppButton>
          </div>
        )}

        {!loading && !error && providers.length === 0 && (
          <EmptyState
            icon="fa-id-card"
            title="No credential providers yet"
            body="Credential providers store the connection details this gateway uses to fetch credentials from an external system, like an OAuth client ID and secret or an API key. Add one to let a Transit Point pull a real credential on an agent's behalf instead of hardcoding one."
            docsHref={DOCS_URL.credentials}
          />
        )}

        {!loading && !error && providers.length > 0 && filtered.length === 0 && (
          <div className="text-center text-muted py-5">
            <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
            <p className="mb-0">No credential providers match your search.</p>
          </div>
        )}

        {!loading && !error && filtered.length > 0 && (
          <div className="table-responsive">
            <table className="table table-hover">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Provider ID</th>
                  <th>Type</th>
                  <th>Scopes</th>
                  <th>Token Refresh</th>
                  <th>Updated</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(provider => (
                  <tr
                    key={provider.id}
                    style={{ cursor: 'pointer' }}
                    onClick={() => navigate(`/credential-providers/${provider.id}`)}
                  >
                    <td>
                      <strong>{provider.name}</strong>
                      {provider.description && (
                        <div>
                          <small className="text-muted">{provider.description}</small>
                        </div>
                      )}
                    </td>
                    <td>
                      <code className="text-muted">{provider.provider_id}</code>
                    </td>
                    <td>
                      <span
                        className={`badge ${PROVIDER_TYPE_COLORS[provider.provider_type] ?? 'text-bg-secondary'}`}
                      >
                        {PROVIDER_TYPE_LABELS[provider.provider_type] ?? provider.provider_type}
                      </span>
                    </td>
                    <td>
                      {provider.default_scopes.length > 0 ? (
                        provider.default_scopes.map(scope => (
                          <span key={scope} className="badge text-bg-secondary me-1">
                            {scope}
                          </span>
                        ))
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                    <td>
                      {provider.token_refresh_enabled ? (
                        <span className="badge text-bg-success">On</span>
                      ) : (
                        <span className="badge text-bg-secondary">Off</span>
                      )}
                    </td>
                    <td>
                      <small>{formatDateTime(provider.updated_at)}</small>
                    </td>
                    <td onClick={e => e.stopPropagation()}>
                      {canEdit && (
                        <DeleteButton
                          onDelete={() => handleDelete(provider)}
                          className="btn-sm"
                          title={`Delete "${provider.name}"`}
                        />
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
  );
};

export default CredentialProvidersTab;
