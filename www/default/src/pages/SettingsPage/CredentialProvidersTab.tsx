import React, { useState, useEffect, useMemo } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { usePermissions } from '../../context/PermissionsContext';
import { apiClient } from '../../api';
import { AppButton } from '../../components/shared/AppButton';
import { Badge } from '../../components/shared/Badge';
import SearchInput from '../../components/shared/SearchInput';
import { DeleteButton } from '../../components/shared/DeleteButton';
import { EmptyState } from '../../components/shared/EmptyState';
import { DOCS_URL } from '../../config/docs';
import { formatDateTime } from '../../utils/stringUtils';
import { formatApiError } from '../../utils/apiError';
import { providerTypeBadgeClass, providerTypeLabel } from '../../utils/credentialProviders';

interface CredentialProviderListItem {
  id: string;
  name: string;
  provider_id: string;
  provider_type: string;
  token_endpoint?: string;
  default_scopes: string[];
  token_refresh_enabled: boolean;
  description?: string;
  created_at: string;
  updated_at: string;
}

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
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [internalSearchTerm, setInternalSearchTerm] = useState('');
  const externalProvided = externalSearchTerm !== undefined;
  const searchTerm = externalProvided ? externalSearchTerm! : internalSearchTerm;
  const setSearchTerm = setInternalSearchTerm;

  const canView = hasPermission('credential_providers.view');
  const canEdit = hasPermission('credential_providers.edit');
  const canDelete = hasPermission('credential_providers.delete');

  useEffect(() => {
    if (canView) {
      loadProviders();
    } else {
      setLoading(false);
    }
  }, [canView]);

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
    setDeleteError(null);
    try {
      const response = await apiClient.fetch(
        `/api/v1/credential-providers/${encodeURIComponent(provider.id)}`,
        { method: 'DELETE' }
      );
      if (!response.ok) {
        throw new Error(
          formatApiError(response.status, await response.text(), response.statusText)
        );
      }
      setProviders(prev => prev.filter(p => p.id !== provider.id));
    } catch (e: any) {
      setDeleteError(`Failed to delete provider "${provider.name}": ${e.message}`);
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
              data-testid="credential-providers-add-button"
              onClick={() => navigate('/credential-providers/new')}
              iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
            >
              Add Provider
            </AppButton>
          )}
        </div>
      </div>
      <div className="card-body">
        {!canView && (
          <div
            className="alert alert-secondary mb-0"
            role="status"
            data-testid="credential-providers-no-access"
          >
            Your role cannot view credential providers.
          </div>
        )}

        {canView && loading && (
          <div className="text-center py-4">
            <div className="spinner-border text-primary" role="status" />
          </div>
        )}

        {deleteError && (
          <div
            className="alert alert-danger"
            role="alert"
            data-testid="credential-provider-delete-error"
          >
            <i className="fas fa-exclamation-triangle me-2"></i>
            {deleteError}
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

        {canView && !loading && !error && providers.length === 0 && (
          <EmptyState
            icon="fa-id-card"
            title="No credential providers yet"
            body="Credential providers store the connection details this gateway uses to fetch credentials from an external system, like an OAuth client ID and secret or an API key. Add one to let a Transit Point pull a real credential on an agent's behalf instead of hardcoding one."
            docsHref={DOCS_URL.credentials}
          />
        )}

        {canView && !loading && !error && providers.length > 0 && filtered.length === 0 && (
          <div className="text-center text-muted py-5">
            <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
            <p className="mb-0">No credential providers match your search.</p>
          </div>
        )}

        {canView && !loading && !error && filtered.length > 0 && (
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
                    data-testid={`credential-provider-row-${provider.id}`}
                    key={provider.id}
                    style={{ cursor: 'pointer' }}
                    onClick={() =>
                      navigate(`/credential-providers/${encodeURIComponent(provider.id)}`)
                    }
                  >
                    <td>
                      <Link
                        to={`/credential-providers/${encodeURIComponent(provider.id)}`}
                        onClick={e => e.stopPropagation()}
                      >
                        <strong>{provider.name}</strong>
                      </Link>
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
                      <span className={`badge ${providerTypeBadgeClass(provider.provider_type)}`}>
                        {providerTypeLabel(provider.provider_type)}
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
                      {canDelete && (
                        <DeleteButton
                          data-testid={`credential-provider-delete-button-${provider.id}`}
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
