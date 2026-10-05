import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { usePermissions } from '../context/PermissionsContext';
import { useLimitGuard } from '../hooks/useLimitGuard';
import { apiClient } from '../api';
import { AppButton } from '../components/shared/AppButton';
import { Badge } from '../components/shared/Badge';
import { DeleteButton } from '../components/shared/DeleteButton';
import { EmptyState } from '../components/shared/EmptyState';
import FieldHelp from '../components/shared/FieldHelp';
import SearchInput from '../components/shared/SearchInput';
import { DOCS_URL } from '../config/docs';

type ConnectionStatus =
  | 'connecting'
  | 'awaiting_approval'
  | 'connected'
  | 'disconnected'
  | 'failed';

interface TrustRegistry {
  id: string;
  name: string;
  description: string;
  oob_url: string;
  our_did?: string;
  registry_did?: string;
  main_did?: string;
  connection_status: ConnectionStatus;
  status: 'active' | 'disabled';
  created_at: string;
  updated_at: string;
}

const connectionStatusBadge = (status: ConnectionStatus) => {
  switch (status) {
    case 'connected':
      return <span className="badge text-bg-success">CONNECTED</span>;
    case 'connecting':
      return <span className="badge text-bg-warning">CONNECTING</span>;
    case 'awaiting_approval':
      return <span className="badge text-bg-info">AWAITING APPROVAL</span>;
    case 'disconnected':
      return <span className="badge text-bg-secondary">DISCONNECTED</span>;
    case 'failed':
      return <span className="badge text-bg-danger">FAILED</span>;
    default:
      return <span className="badge text-bg-secondary">{(status as string)?.toUpperCase()}</span>;
  }
};

interface TrustRegistriesPageProps {
  externalSearchTerm?: string;
  onCountChange?: (filtered: number, total: number) => void;
}

const TrustRegistriesPage: React.FC<TrustRegistriesPageProps> = ({
  externalSearchTerm,
  onCountChange,
}) => {
  const navigate = useNavigate();
  const { guard, balloonNode } = useLimitGuard();
  const { hasPermission } = usePermissions();
  const [trustRegistries, setTrustRegistries] = useState<TrustRegistry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [listingRecordsId, setListingRecordsId] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const effectiveSearchTerm = externalSearchTerm ?? searchTerm;

  useEffect(() => {
    fetchTrustRegistries();
  }, []);

  useEffect(() => {
    const handler = (event: Event) => {
      const detail = (event as CustomEvent)?.detail;
      if (detail?.type === 'refresh_dashboard') {
        fetchTrustRegistries();
      }
    };
    window.addEventListener('ws-message', handler);
    return () => window.removeEventListener('ws-message', handler);
  }, []);

  const fetchTrustRegistries = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get('/trust-registries');
      setTrustRegistries(response.data);
    } catch (error: any) {
      setError(error.message || 'Failed to load trust registries');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await apiClient.delete(`/trust-registries/${id}`);
      setSuccess('Trust registry deleted successfully');
      setTimeout(() => setSuccess(null), 3000);
      fetchTrustRegistries();
    } catch (error: any) {
      setError(error.message || 'Failed to delete trust registry');
    }
  };

  const handleListRecords = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    try {
      setListingRecordsId(id);
      setError(null);
      const registry = trustRegistries.find(item => item.id === id);
      const response = await apiClient.listTrustRegistryRecords(id);
      setSuccess(
        `Ping to "${registry?.name ?? 'Trust Registry'}" successful (${response.round_trip_ms}ms)`
      );
      setTimeout(() => setSuccess(null), 2000);
    } catch (err: any) {
      setError(err.message || 'Failed to list records');
    } finally {
      setListingRecordsId(null);
    }
  };

  const filteredTrustRegistries = useMemo(() => {
    const trimmedSearch = effectiveSearchTerm.trim().toLowerCase();

    return trustRegistries.filter(registry => {
      if (trimmedSearch) {
        const matchesSearch =
          registry.name?.toLowerCase().includes(trimmedSearch) ||
          registry.description?.toLowerCase().includes(trimmedSearch) ||
          registry.registry_did?.toLowerCase().includes(trimmedSearch) ||
          registry.main_did?.toLowerCase().includes(trimmedSearch) ||
          registry.our_did?.toLowerCase().includes(trimmedSearch) ||
          registry.oob_url?.toLowerCase().includes(trimmedSearch);

        if (!matchesSearch) return false;
      }

      return true;
    });
  }, [effectiveSearchTerm, trustRegistries]);

  useEffect(() => {
    if (onCountChange) onCountChange(filteredTrustRegistries.length, trustRegistries.length);
  }, [filteredTrustRegistries.length, trustRegistries.length, onCountChange]);

  const isEmbedded = externalSearchTerm !== undefined;
  const actionButtons = hasPermission('trust_registries.edit') ? (
    <>
      <AppButton
        variant="primary"
        size="md"
        className="shadow-sm"
        onClick={e =>
          guard('connections.trustregistries', () => navigate('/trust-registries/wizard'), e)
        }
        iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
      >
        Add Trust Registry
      </AppButton>
      {balloonNode}
    </>
  ) : null;

  return (
    <div className={isEmbedded ? '' : 'container-fluid'}>
      {!isEmbedded && (
        <div className="d-sm-flex align-items-center justify-content-between mb-4">
          <div>
            <SearchInput
              value={searchTerm}
              onChange={setSearchTerm}
              placeholder="Filter Trust Registries..."
            />
          </div>
        </div>
      )}

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
      ) : trustRegistries.length === 0 ? (
        <div className="card shadow mb-4">
          <div className="card-header py-3">
            <div className="d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-shield-alt"></i> All Trust Registries
                <Badge value={0} tone="primary" className="ms-2" ariaLabel="0 trust registries" />
              </h6>
              {actionButtons}
            </div>
          </div>
          <div className="card-body">
            <EmptyState
              icon="fa-shield-alt"
              title="Add your first trust registry"
              body="Trust Registries let the gateway verify that agents and their providers are recognised and authorised. Add one to enable Trust Check queries, real-time lookups the gateway runs to confirm a caller or target agent is recognised before allowing a request."
              docsHref={DOCS_URL.connections}
            />
          </div>
        </div>
      ) : (
        <div className="card shadow mb-4">
          <div className="card-header py-3">
            <div className="d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-shield-alt"></i> All Trust Registries
                <span className="badge text-bg-primary ms-2" style={{ verticalAlign: 'middle' }}>
                  {filteredTrustRegistries.length}
                  {effectiveSearchTerm && ` of ${trustRegistries.length}`}
                </span>
              </h6>
              {actionButtons}
            </div>
          </div>
          <div className="card-body">
            {filteredTrustRegistries.length === 0 ? (
              <div className="text-center text-muted py-5">
                <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
                <p className="mb-0">No trust registries match your search.</p>
              </div>
            ) : (
              <div className="table-responsive">
                <table className="table table-hover table-sm">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Description</th>
                      <th>
                        Connection{' '}
                        <FieldHelp
                          testId="field-help-trust-registry-connection"
                          ariaLabel="About Connection status"
                        >
                          CONNECTING and AWAITING APPROVAL are normal during setup. DISCONNECTED or
                          FAILED means Trust Check queries to this registry won't run until it
                          reconnects.
                        </FieldHelp>
                      </th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredTrustRegistries.map(registry => (
                      <tr
                        key={registry.id}
                        style={{ cursor: 'pointer' }}
                        onClick={() => navigate(`/trust-registries/${registry.id}`)}
                      >
                        <td>{registry.name}</td>
                        <td>
                          <small>{registry.description}</small>
                        </td>
                        <td>{connectionStatusBadge(registry.connection_status)}</td>
                        <td>
                          <span
                            className={`badge ${registry.status === 'active' ? 'text-bg-success' : 'text-bg-secondary'}`}
                          >
                            {registry.status.toUpperCase()}
                          </span>
                        </td>
                        <td>
                          {registry.connection_status === 'connected' && (
                            <AppButton
                              variant="outline-primary"
                              size="sm"
                              title="Ping this registry to confirm it's reachable and measure round-trip latency"
                              className="me-2"
                              onClick={e => handleListRecords(e, registry.id)}
                              disabled={listingRecordsId === registry.id}
                              aria-label={`Ping ${registry.name} to check connectivity`}
                            >
                              {listingRecordsId === registry.id ? (
                                <span
                                  className="spinner-border spinner-border-sm"
                                  role="status"
                                ></span>
                              ) : (
                                <i className="fas fa-heartbeat" aria-hidden="true"></i>
                              )}
                            </AppButton>
                          )}
                          {hasPermission('trust_registries.edit') && (
                            <AppButton
                              variant="outline-primary"
                              size="sm"
                              title="Edit Trust Registry"
                              className="me-2"
                              aria-label={`Edit trust registry ${registry.name}`}
                              onClick={() => navigate(`/trust-registries/${registry.id}`)}
                            >
                              <i className="fas fa-edit" aria-hidden="true"></i>
                            </AppButton>
                          )}
                          {hasPermission('trust_registries.delete') && (
                            <DeleteButton
                              onDelete={() => handleDelete(registry.id)}
                              className="btn-sm"
                              title="Delete Trust Registry"
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
      )}
    </div>
  );
};

export default TrustRegistriesPage;
