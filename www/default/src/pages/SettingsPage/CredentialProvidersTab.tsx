import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { usePermissions } from '../../context/PermissionsContext';
import { apiClient } from '../../api';
import { AppButton } from '../../components/shared/AppButton';
import { Badge } from '../../components/shared/Badge';
import SearchInput from '../../components/shared/SearchInput';
import { DeleteButton } from '../../components/shared/DeleteButton';
import { TwoStepButton } from '../../components/shared/TwoStepButton';
import { showToast } from '../../utils/toaster';
import { EmptyState } from '../../components/shared/EmptyState';
import { DOCS_URL } from '../../config/docs';
import { formatDateTime } from '../../utils/stringUtils';
import { formatApiError } from '../../utils/apiError';
import {
  CLIENT_AUTHENTICATION_LABELS,
  ClientAuthentication,
  CredentialProviderType,
  PROVIDER_TYPE_LABELS,
  entraRejectsResource,
  entraResourceMessage,
  takesConsent,
} from '../EditCredentialProviderPage/credentialProviderForm';

/**
 * Why a delete failed, from the API's answer: its `error`, the surface a `409`
 * names as binding the provider, and the status. `statusText` is empty over
 * HTTP/2, so it is only the last resort.
 */
export function providerDeleteError(status: number, body: string, statusText: string): string {
  let surfaceId: unknown;
  try {
    surfaceId = JSON.parse(body)?.surface_id;
  } catch {
    surfaceId = undefined;
  }
  const message = formatApiError(undefined, body, statusText);
  const named =
    typeof surfaceId === 'string' && surfaceId ? `${message} (surface ${surfaceId})` : message;
  return `${named} (${status})`;
}

interface CredentialProviderListItem {
  id: string;
  name: string;
  provider_id: string;
  provider_type: CredentialProviderType;
  client_authentication?: ClientAuthentication;
  token_endpoint?: string;
  resource?: string | null;
  issuer?: string | null;
  send_resource?: boolean;
  default_scopes: string[];
  token_refresh_enabled: boolean;
  description?: string;
  /** Set once the provider takes no new consent. */
  deactivated_at?: string | null;
  created_at: string;
  updated_at: string;
}

const PROVIDER_TYPE_COLORS: Record<CredentialProviderType, string> = {
  oauth2_authorization_code: 'text-bg-info',
  oauth2_client_credentials: 'text-bg-primary',
  oauth2_jwt_bearer: 'text-bg-primary',
  oauth2_client_credentials_jwt_auth: 'text-bg-primary',
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
        const body = await response.text();
        throw new Error(providerDeleteError(response.status, body, response.statusText));
      }
      setProviders(prev => prev.filter(p => p.id !== provider.id));
    } catch (e: any) {
      alert(`Failed to delete provider: ${e.message}`);
    }
  };

  /** Deactivates a provider, which stops new consent and nothing else, or activates it again. */
  const setActive = async (provider: CredentialProviderListItem, active: boolean) => {
    try {
      const response = await apiClient.fetch(
        `/api/v1/credential-providers/${encodeURIComponent(provider.id)}/${active ? 'activate' : 'deactivate'}`,
        { method: 'POST' }
      );
      if (!response.ok) {
        throw new Error(
          formatApiError(response.status, await response.text(), response.statusText)
        );
      }
      const saved = await response.json();
      setProviders(prev =>
        prev.map(p =>
          p.id === provider.id ? { ...p, deactivated_at: saved.deactivated_at ?? null } : p
        )
      );
      showToast(
        'success',
        active
          ? `"${provider.name}" takes consent again`
          : `"${provider.name}" takes no new consent. Access already given keeps working.`
      );
    } catch (e: any) {
      showToast('error', `Failed to ${active ? 'activate' : 'deactivate'} provider: ${e.message}`);
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
                    data-testid={`credential-provider-row-${provider.id}`}
                    key={provider.id}
                    style={{ cursor: 'pointer' }}
                    onClick={() => navigate(`/credential-providers/${provider.id}`)}
                  >
                    <td>
                      <strong>{provider.name}</strong>
                      {provider.resource &&
                        entraRejectsResource(
                          provider.token_endpoint ?? '',
                          provider.resource,
                          provider
                        ) && (
                          <i
                            className="fas fa-exclamation-triangle text-warning ms-2"
                            role="img"
                            aria-label={entraResourceMessage(provider.resource, provider)}
                            title={entraResourceMessage(provider.resource, provider)}
                            data-testid="credential-provider-entra-resource-badge"
                          />
                        )}
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
                      {provider.provider_type === 'oauth2_jwt_bearer' &&
                        provider.client_authentication &&
                        CLIENT_AUTHENTICATION_LABELS[provider.client_authentication] && (
                          <span
                            className="badge text-bg-secondary ms-1"
                            data-testid="credential-provider-client-authentication-badge"
                          >
                            {CLIENT_AUTHENTICATION_LABELS[provider.client_authentication]}
                          </span>
                        )}
                      {provider.deactivated_at && (
                        <span
                          className="badge text-bg-secondary ms-1"
                          title="Takes no new consent. Access already given keeps working."
                          data-testid={`credential-provider-deactivated-badge-${provider.id}`}
                        >
                          Deactivated
                        </span>
                      )}
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
                      {canEdit && !takesConsent(provider.provider_type) && (
                        <DeleteButton
                          data-testid={`credential-provider-delete-button-${provider.id}`}
                          onDelete={() => handleDelete(provider)}
                          className="btn-sm"
                          title={`Delete "${provider.name}"`}
                        />
                      )}
                      {canEdit &&
                        takesConsent(provider.provider_type) &&
                        !provider.deactivated_at && (
                          <TwoStepButton
                            icon="fa-ban"
                            label="Deactivate"
                            confirmLabel="Click again to deactivate"
                            title={`Deactivate "${provider.name}": no new consent, access already given keeps working`}
                            confirmTitle={`Click again to deactivate "${provider.name}"`}
                            className="btn btn-outline-warning btn-sm text-nowrap"
                            data-testid={`credential-provider-deactivate-button-${provider.id}`}
                            onConfirm={() => setActive(provider, false)}
                          />
                        )}
                      {canEdit &&
                        takesConsent(provider.provider_type) &&
                        provider.deactivated_at && (
                          <AppButton
                            variant="outline-primary"
                            size="sm"
                            className="text-nowrap"
                            data-testid={`credential-provider-activate-button-${provider.id}`}
                            title={`Let "${provider.name}" take consent again`}
                            onClick={() => setActive(provider, true)}
                          >
                            Activate
                          </AppButton>
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
