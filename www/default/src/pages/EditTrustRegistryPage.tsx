import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { apiClient } from '../api';
import { DeleteButton } from '../components/shared/DeleteButton';
import FieldHelp from '../components/shared/FieldHelp';
import { showToast } from '../utils/toaster';
import { useSafeNavigate } from '../hooks/useSafeNavigate';

type ConnectionStatus =
  | 'connecting'
  | 'awaiting_approval'
  | 'connected'
  | 'disconnected'
  | 'failed';

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

interface TrustRegistryData {
  id: string;
  name: string;
  description: string;
  oob_url: string;
  our_did?: string;
  registry_did?: string;
  main_did?: string;
  connection_status: ConnectionStatus;
  status: string;
  created_at: string;
  updated_at: string;
}

const EditTrustRegistryPage: React.FC = () => {
  const { navigate } = useSafeNavigate();
  const { id } = useParams<{ id: string }>();

  const [loading, setLoading] = useState(true);
  const [reconnecting, setReconnecting] = useState(false);
  const [listingRecords, setListingRecords] = useState(false);
  const [registry, setRegistry] = useState<TrustRegistryData | null>(null);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string>('');
  const [success, setSuccess] = useState<string>('');
  const [copiedField, setCopiedField] = useState<string>('');

  useEffect(() => {
    if (id) {
      fetchTrustRegistry();
    }
  }, [id]);

  useEffect(() => {
    const handler = (event: Event) => {
      const detail = (event as CustomEvent)?.detail;
      if (detail?.type === 'refresh_dashboard' && id) {
        fetchTrustRegistry();
      }
    };
    window.addEventListener('ws-message', handler);
    return () => window.removeEventListener('ws-message', handler);
  }, [id]);

  const fetchTrustRegistry = async () => {
    try {
      setLoading(true);
      const response = await apiClient.get(`/trust-registries/${id}`);
      setRegistry(response.data);
      setName(response.data.name);
      setDescription(response.data.description || '');
    } catch (err: any) {
      setError(err.message || 'Failed to load trust registry');
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!name.trim()) {
      setError('Name is required');
      return;
    }

    try {
      setSaving(true);
      await apiClient.put(`/trust-registries/${id}`, {
        name: name.trim(),
        description: description.trim(),
      });
      showToast('success', 'Trust registry updated!');
      navigate('/connections?tab=trust-registries');
    } catch (err: any) {
      setError(err.message || 'Failed to save trust registry');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    try {
      setSaving(true);
      await apiClient.delete(`/trust-registries/${id}`);
      navigate('/connections?tab=trust-registries');
    } catch (err: any) {
      setError(err.message || 'Failed to delete trust registry');
    } finally {
      setSaving(false);
    }
  };

  const handleReconnect = async () => {
    try {
      setReconnecting(true);
      setError('');
      await apiClient.post(`/trust-registries/${id}/reconnect`, {});
      setSuccess('Reconnection initiated');
      setTimeout(() => setSuccess(''), 3000);
      await fetchTrustRegistry();
    } catch (err: any) {
      setError(err.message || 'Failed to reconnect');
    } finally {
      setReconnecting(false);
    }
  };

  const handleListRecords = async () => {
    try {
      setListingRecords(true);
      setError('');
      const response = await apiClient.listTrustRegistryRecords(id!);
      setSuccess(
        `Ping to "${registry?.name ?? 'Trust Registry'}" successful (${response.round_trip_ms}ms)`
      );
      setTimeout(() => setSuccess(''), 2000);
    } catch (err: any) {
      setError(err.message || 'Failed to list records');
    } finally {
      setListingRecords(false);
    }
  };

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(''), 2000);
  };

  const CopyButton: React.FC<{ text: string; field: string }> = ({ text, field }) => (
    <button
      className="btn btn-sm btn-outline-secondary ms-2"
      style={{ whiteSpace: 'nowrap' }}
      onClick={() => copyToClipboard(text, field)}
      title="Copy"
    >
      {copiedField === field ? (
        <>
          <i className="fas fa-check"></i> Copied
        </>
      ) : (
        <i className="fas fa-copy"></i>
      )}
    </button>
  );

  if (loading) {
    return (
      <div className="container mt-4">
        <div className="text-center py-4">
          <div className="spinner-border" role="status">
            <span className="visually-hidden"></span>
          </div>
        </div>
      </div>
    );
  }

  if (!registry) {
    return (
      <div className="container-fluid">
        <div className="alert alert-danger">Trust registry not found</div>
      </div>
    );
  }

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button
          className="btn btn-sm btn-secondary"
          onClick={() => navigate('/connections?tab=trust-registries')}
        >
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-edit"></i> Edit Trust Registry: {registry.name}
            <span className="ms-2">{connectionStatusBadge(registry.connection_status)}</span>
          </h6>
        </div>
        <div className="card-body">
          {error && (
            <div className="alert alert-danger" role="alert">
              {error}
            </div>
          )}
          {success && (
            <div className="alert alert-success" role="alert">
              {success}
            </div>
          )}

          {/* Connection Details (read-only) */}
          <div className="card bg-light mb-4">
            <div className="card-header py-2">
              <strong>
                <i className="fas fa-plug me-1"></i> Connection Details
              </strong>
            </div>
            <div className="card-body">
              <div className="mb-3">
                <label className="form-label text-muted mb-1">
                  OOB URL{' '}
                  <FieldHelp testId="field-help-tr-oob-url" ariaLabel="About OOB URL">
                    The out-of-band invitation URL provided by the registry administrator, used to
                    establish this DIDComm (a secure agent-to-agent messaging protocol) connection.
                    Not needed for day-to-day use, kept for reference and troubleshooting.
                  </FieldHelp>
                </label>
                <div className="d-flex align-items-center">
                  <code style={{ fontSize: '0.8rem', wordBreak: 'break-all' }}>
                    {registry.oob_url}
                  </code>
                  <CopyButton text={registry.oob_url} field="oob_url" />
                </div>
              </div>

              {registry.our_did && (
                <div className="mb-3">
                  <label className="form-label text-muted mb-1">
                    Our DID{' '}
                    <FieldHelp testId="field-help-tr-our-did" ariaLabel="About Our DID">
                      This gateway's own per-registry DID, created during the OOB handshake. It's
                      the DID the trust registry uses to identify this gateway.
                    </FieldHelp>
                  </label>
                  <div className="d-flex align-items-center">
                    <code style={{ fontSize: '0.8rem', wordBreak: 'break-all' }}>
                      {registry.our_did}
                    </code>
                    <CopyButton text={registry.our_did} field="our_did" />
                  </div>
                </div>
              )}

              {registry.registry_did && (
                <div className="mb-3">
                  <label className="form-label text-muted mb-1">
                    Registry DID{' '}
                    <FieldHelp testId="field-help-tr-registry-did" ariaLabel="About Registry DID">
                      The trust registry's own DIDComm (a secure agent-to-agent messaging protocol)
                      identity, discovered during the OOB handshake. Distinct from Main DID, which
                      is the identity agents reference when naming this registry.
                    </FieldHelp>
                  </label>
                  <div className="d-flex align-items-center">
                    <code style={{ fontSize: '0.8rem', wordBreak: 'break-all' }}>
                      {registry.registry_did}
                    </code>
                    <CopyButton text={registry.registry_did} field="registry_did" />
                  </div>
                </div>
              )}

              {registry.main_did && (
                <div className="mb-3">
                  <label className="form-label text-muted mb-1">
                    Main DID{' '}
                    <FieldHelp testId="field-help-tr-main-did" ariaLabel="About Main DID">
                      The trust registry's canonical DID, populated from the OOB invitation. This is
                      the DID agents reference when they name this registry in their own request
                      metadata.
                    </FieldHelp>
                  </label>
                  <div className="d-flex align-items-center">
                    <code style={{ fontSize: '0.8rem', wordBreak: 'break-all' }}>
                      {registry.main_did}
                    </code>
                    <CopyButton text={registry.main_did} field="main_did" />
                  </div>
                </div>
              )}

              <div className="mb-0">
                <label className="form-label text-muted mb-1">
                  Connection Status{' '}
                  <FieldHelp
                    testId="field-help-tr-connection-status"
                    ariaLabel="About Connection Status"
                  >
                    CONNECTING and AWAITING APPROVAL are normal during setup. CONNECTED means this
                    gateway can send TRQP (Trust Registry Query Protocol) queries, also called Trust
                    Checks, to this registry. DISCONNECTED or FAILED means those queries won't run
                    until you reconnect.
                  </FieldHelp>
                </label>
                <div>
                  {connectionStatusBadge(registry.connection_status)}
                  {(registry.connection_status === 'failed' ||
                    registry.connection_status === 'disconnected') && (
                    <button
                      className="btn btn-sm btn-warning ms-2"
                      onClick={handleReconnect}
                      disabled={reconnecting}
                      title="Attempts to restore the existing connection. If that fails, re-establishes it using the stored OOB URL."
                    >
                      {reconnecting ? (
                        <>
                          <span
                            className="spinner-border spinner-border-sm me-1"
                            role="status"
                          ></span>
                          Reconnecting...
                        </>
                      ) : (
                        <>
                          <i className="fas fa-redo me-1"></i> Reconnect
                        </>
                      )}
                    </button>
                  )}
                  {registry.connection_status === 'connected' && (
                    <button
                      title="Sends a test query to confirm the connection is live and reports the round-trip time"
                      className="btn btn-sm btn-outline-primary ms-2"
                      onClick={handleListRecords}
                      disabled={listingRecords}
                    >
                      {listingRecords ? (
                        <span className="spinner-border spinner-border-sm" role="status"></span>
                      ) : (
                        <i className="fas fa-heartbeat"></i>
                      )}
                    </button>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Editable fields */}
          <form onSubmit={handleSave}>
            <div className="mb-3">
              <label htmlFor="name" className="form-label">
                Name *
              </label>
              <input
                type="text"
                className="form-control"
                id="name"
                value={name}
                onChange={e => setName(e.target.value)}
                required
              />
            </div>
            <div className="mb-4">
              <label htmlFor="description" className="form-label">
                Description
              </label>
              <textarea
                className="form-control"
                id="description"
                rows={3}
                value={description}
                onChange={e => setDescription(e.target.value)}
              />
            </div>
            <div className="d-flex gap-2">
              <button type="submit" className="btn btn-primary" disabled={saving}>
                {saving ? (
                  <>
                    <span
                      className="spinner-border spinner-border-sm me-2"
                      role="status"
                      aria-hidden="true"
                    ></span>
                    Saving...
                  </>
                ) : (
                  <>
                    <i className="fas fa-save me-2"></i> Save
                  </>
                )}
              </button>
              <DeleteButton onDelete={handleDelete} disabled={saving} variant="danger">
                Delete
              </DeleteButton>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => navigate('/connections?tab=trust-registries')}
                disabled={saving}
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default EditTrustRegistryPage;
