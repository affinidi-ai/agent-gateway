import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../../api';
import { usePermissions } from '../../context/PermissionsContext';
import { Badge } from '../../components/shared/Badge';
import { formatDateTime } from '../../utils/stringUtils';
import { AppButton } from '../../components/shared/AppButton';
import { EmptyState } from '../../components/shared/EmptyState';

export interface StsClient {
  id: string;
  client_id: string;
  name: string;
  client_secret_ref?: string | null;
  allowed_audiences: string[];
  allowed_scopes: string[];
  allowed_subject_token_types: string[];
  allow_impersonation: boolean;
  max_ttl_secs?: number | null;
  issue_id_jag: boolean;
  created_at: string;
  updated_at: string;
}

interface StsClientsTabProps {
  externalSearchTerm?: string;
  onFilteredCountChange?: (n: number) => void;
}

const StsClientsTab: React.FC<StsClientsTabProps> = ({
  externalSearchTerm,
  onFilteredCountChange,
}) => {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const [clients, setClients] = useState<StsClient[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [internalSearchTerm, setInternalSearchTerm] = useState('');
  const externalProvided = externalSearchTerm !== undefined;
  const searchTerm = externalProvided ? externalSearchTerm! : internalSearchTerm;
  const setSearchTerm = setInternalSearchTerm;
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const canEdit = hasPermission('sts_clients.edit');
  const canDelete = hasPermission('sts_clients.delete');

  useEffect(() => {
    loadClients();
  }, []);

  const loadClients = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiClient.fetch('/api/v1/sts/clients');
      if (!response.ok) {
        throw new Error(`Failed to load STS clients: ${response.statusText}`);
      }
      const data: StsClient[] = await response.json();
      setClients(data);
    } catch (e: any) {
      setError(e.message ?? 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (client: StsClient) => {
    if (
      !window.confirm(
        `Delete STS client "${client.name}" (${client.client_id})?\n\nAny agent still using this client_id to exchange tokens will be rejected with invalid_client.`
      )
    ) {
      return;
    }
    setDeletingId(client.id);
    try {
      const response = await apiClient.fetch(
        `/api/v1/sts/clients/${encodeURIComponent(client.id)}`,
        { method: 'DELETE' }
      );
      if (!response.ok) {
        throw new Error(`Delete failed: ${response.statusText}`);
      }
      setClients(prev => prev.filter(c => c.id !== client.id));
    } catch (e: any) {
      alert(`Failed to delete managed connection: ${e.message}`);
    } finally {
      setDeletingId(null);
    }
  };

  const filtered = clients.filter(
    c =>
      c.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      c.client_id.toLowerCase().includes(searchTerm.toLowerCase())
  );

  useEffect(() => {
    onFilteredCountChange?.(filtered.length);
  }, [filtered.length, onFilteredCountChange]);

  return (
    <>
      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-right-left"></i> STS Clients
            <Badge
              value={filtered.length}
              suffix={searchTerm ? ` of ${clients.length}` : undefined}
              className="ms-2"
              ariaLabel={`${filtered.length}${searchTerm ? ` of ${clients.length}` : ''} STS clients`}
            />
          </h6>
          {canEdit && (
            <AppButton
              variant="primary"
              size="sm"
              className="shadow-sm"
              onClick={() => navigate('/sts-clients/new')}
              iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
            >
              Add STS Client
            </AppButton>
          )}
        </div>

        <div className="card-body">
          {!externalProvided && (
            <div className="input-group mb-3">
              <input
                type="text"
                className="form-control bg-light border-0 small"
                placeholder="Search by name or client_id…"
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
              />
              <div className="input-group-append">
                <AppButton
                  variant="primary"
                  type="button"
                  aria-label="Search STS clients"
                  iconStart={<i className="fas fa-search fa-sm" aria-hidden="true" />}
                />
              </div>
            </div>
          )}

          {loading && (
            <div className="text-center py-4">
              <div className="spinner-border text-primary" role="status" />
            </div>
          )}

          {error && (
            <div className="alert alert-danger">
              <i className="fas fa-exclamation-triangle me-2"></i>
              {error}
              <AppButton variant="outline-danger" size="sm" className="ms-3" onClick={loadClients}>
                Retry
              </AppButton>
            </div>
          )}

          {!loading && !error && clients.length === 0 && (
            <EmptyState
              icon="fa-right-left"
              title="No STS clients configured yet"
              body="An STS client is an agent authorized to exchange tokens at /oauth2/token. Add one for each agent (or agent family) that needs to trade a token it already holds for a different token scoped to a downstream service."
              ctaLabel={canEdit ? 'Add your first STS client' : undefined}
              ctaIcon={canEdit ? 'fa-plus' : undefined}
              onCtaClick={canEdit ? () => navigate('/sts-clients/new') : undefined}
            />
          )}

          {!loading && !error && clients.length > 0 && filtered.length === 0 && (
            <div className="text-center text-muted py-5">
              <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
              <p className="mb-0">No clients match your search.</p>
            </div>
          )}

          {!loading && !error && filtered.length > 0 && (
            <div className="table-responsive">
              <table className="table table-hover table-sm" width="100%" cellSpacing="0">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Access</th>
                    <th>Options</th>
                    <th>Updated</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(client => (
                    <tr
                      key={client.id}
                      onClick={() => canEdit && navigate(`/sts-clients/${client.id}`)}
                      style={{ cursor: canEdit ? 'pointer' : 'default' }}
                    >
                      <td>
                        <strong>{client.name}</strong>
                        <div>
                          <small className="text-muted font-monospace">{client.client_id}</small>
                        </div>
                      </td>
                      <td>
                        <div>
                          <small>
                            <span className="badge badge-secondary me-1">Audiences</span>
                            {client.allowed_audiences.length === 0
                              ? 'any'
                              : client.allowed_audiences.length}
                          </small>
                        </div>
                        <div>
                          <small>
                            <span className="badge badge-secondary me-1">Scopes</span>
                            {client.allowed_scopes.length === 0
                              ? 'any'
                              : client.allowed_scopes.length}
                          </small>
                        </div>
                      </td>
                      <td>
                        {client.issue_id_jag && (
                          <span className="badge text-bg-primary me-1">ID-JAG</span>
                        )}
                        {client.allow_impersonation ? (
                          <span className="badge text-bg-warning me-1">Impersonation</span>
                        ) : (
                          <span className="badge text-bg-secondary me-1">Delegation</span>
                        )}
                        {client.client_secret_ref ? (
                          <span className="badge text-bg-success">Secret</span>
                        ) : (
                          <span
                            className="badge text-bg-danger"
                            title="No client secret, this client cannot authenticate and must be fixed"
                          >
                            No secret
                          </span>
                        )}
                      </td>
                      <td>
                        <small>{formatDateTime(client.updated_at)}</small>
                      </td>
                      <td onClick={e => e.stopPropagation()}>
                        {canEdit && (
                          <AppButton
                            variant="outline-primary"
                            size="sm"
                            className="me-1"
                            onClick={() => navigate(`/sts-clients/${client.id}`)}
                            aria-label={`Edit ${client.name}`}
                            iconStart={<i className="fas fa-edit" aria-hidden="true" />}
                          />
                        )}
                        {canDelete && (
                          <AppButton
                            variant="outline-danger"
                            size="sm"
                            onClick={() => handleDelete(client)}
                            disabled={deletingId === client.id}
                            aria-label={`Delete ${client.name}`}
                            iconStart={
                              deletingId === client.id ? (
                                <span className="spinner-border spinner-border-sm" />
                              ) : (
                                <i className="fas fa-trash" aria-hidden="true" />
                              )
                            }
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
    </>
  );
};

export default StsClientsTab;
