import React, { useState, useEffect, useMemo } from 'react';
import { useParams } from 'react-router-dom';
import { apiClient, ApiKeyRecord, ApiKeyCreated } from '../api';
import { useApp } from '../context/AppContext';
import { showToast } from '../utils/toaster';
import { formatDateTime } from '../utils/stringUtils';
import { DeleteButton } from '../components/shared/DeleteButton';
import { useSafeNavigate } from '../hooks/useSafeNavigate';

const ApiKeyDetailPage: React.FC = () => {
  const { navigate } = useSafeNavigate();
  const { agentId, keyId } = useParams<{ agentId: string; keyId: string }>();
  const { getCurrentStats } = useApp();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [apiKey, setApiKey] = useState<ApiKeyRecord | null>(null);

  // Rotate result modal
  const [rotatedKey, setRotatedKey] = useState<ApiKeyCreated | null>(null);
  const [secretCopied, setSecretCopied] = useState(false);

  const stats = getCurrentStats();
  const channels = stats?.channels || [];

  const channelName = useMemo(() => {
    if (!apiKey) return '';
    const ch = channels.find(c => c.config_id === apiKey.agent_id);
    return ch?.name || apiKey.agent_id;
  }, [apiKey, channels]);

  useEffect(() => {
    if (agentId && keyId) {
      fetchApiKey();
    }
  }, [agentId, keyId]);

  const fetchApiKey = async () => {
    if (!agentId || !keyId) return;
    try {
      setLoading(true);
      const data = await apiClient.getApiKey(agentId, keyId);
      setApiKey(data);
      setError('');
    } catch (err: any) {
      console.error('Failed to fetch API key:', err);
      setError('Failed to load API key');
      showToast('error', 'Failed to load API key');
    } finally {
      setLoading(false);
    }
  };

  const handleRevoke = async () => {
    if (!agentId || !keyId) return;
    try {
      await apiClient.revokeApiKey(agentId, keyId, 'dashboard');
      showToast('success', 'API key revoked');
      fetchApiKey();
    } catch (err: any) {
      console.error('Failed to revoke API key:', err);
      showToast('error', 'Failed to revoke API key');
    }
  };

  const handleRotate = async () => {
    if (!agentId || !keyId) return;
    try {
      const created = await apiClient.rotateApiKey(agentId, keyId, 'dashboard');
      setRotatedKey(created);
      setSecretCopied(false);
      showToast('success', 'API key rotated');
    } catch (err: any) {
      console.error('Failed to rotate API key:', err);
      showToast('error', 'Failed to rotate API key');
    }
  };

  const handleDelete = async () => {
    if (!agentId || !keyId) return;
    try {
      await apiClient.deleteApiKey(agentId, keyId);
      showToast('success', 'API key deleted');
      navigate('/secrets');
    } catch (err: any) {
      console.error('Failed to delete API key:', err);
      showToast('error', 'Failed to delete API key');
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
          <span className="visually-hidden">Loading...</span>
        </div>
      </div>
    );
  }

  if (!apiKey) {
    return (
      <div className="container-fluid">
        <div className="alert alert-danger">API key not found.</div>
        <button className="btn btn-secondary" onClick={() => navigate('/secrets')}>
          Back to Secrets
        </button>
      </div>
    );
  }

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button className="btn btn-sm btn-secondary" onClick={() => navigate('/secrets')}>
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <h1 className="h3 mb-0 text-gray-800">API Key Details</h1>
      </div>

      {error && (
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      )}

      <div className="row">
        <div className="col-lg-8">
          <div className="card shadow mb-4">
            <div className="card-header py-3 d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">Key Information</h6>
              {apiKey.needs_rotation ? (
                <span className="badge text-bg-warning">Rotation required</span>
              ) : (
                <span
                  className={`badge ${apiKey.status === 'active' ? 'text-bg-success' : 'text-bg-danger'}`}
                >
                  {apiKey.status === 'active' ? 'Active' : 'Revoked'}
                </span>
              )}
            </div>
            <div className="card-body">
              {apiKey.needs_rotation && (
                <div className="alert alert-warning" role="alert">
                  <i className="fas fa-exclamation-triangle me-2"></i>
                  <strong>Rotation required.</strong> This key predates hashed secret storage and
                  can no longer authenticate. Rotate it to issue a new secret.
                </div>
              )}
              <div className="mb-3">
                <label className="fw-bold text-muted">Key ID</label>
                <div>
                  <code>{apiKey.key_id}</code>
                </div>
              </div>

              <div className="mb-3">
                <label className="fw-bold text-muted">Client ID</label>
                <div>{apiKey.client_id}</div>
              </div>

              <div className="mb-3">
                <label className="fw-bold text-muted">Channel</label>
                <div>{channelName}</div>
              </div>

              {Object.keys(apiKey.labels || {}).length > 0 && (
                <div className="mb-3">
                  <label className="fw-bold text-muted">Labels</label>
                  <div>
                    {Object.entries(apiKey.labels).map(([k, v]) => (
                      <span key={k} className="badge text-bg-secondary me-1">
                        {k}: {v}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {apiKey.rotated_from && (
                <div className="mb-3">
                  <label className="fw-bold text-muted">Rotated From</label>
                  <div>
                    <code>{apiKey.rotated_from}</code>
                  </div>
                </div>
              )}

              {/* Actions */}
              <hr />
              {apiKey.status === 'active' && (
                <div className="row mb-3">
                  <div className="col-md-6 mb-2">
                    <button className="btn btn-warning w-100" onClick={handleRevoke}>
                      <i className="fas fa-ban me-1"></i> Revoke
                    </button>
                    <small className="text-muted d-block mt-1">
                      Permanently disables this key. There&apos;s no replacement, any client using
                      it will start getting authentication errors immediately. This can&apos;t be
                      undone.
                    </small>
                  </div>
                  <div className="col-md-6 mb-2">
                    <button className="btn btn-primary w-100" onClick={handleRotate}>
                      <i className="fas fa-sync-alt me-1"></i> Rotate
                    </button>
                    <small className="text-muted d-block mt-1">
                      Issues a brand-new secret for this same key. The old secret stops working
                      immediately, so update any client still using it before rotating.
                    </small>
                  </div>
                </div>
              )}
              <div className="d-flex justify-content-end">
                <DeleteButton onDelete={handleDelete} title="Delete this API key" variant="danger">
                  Delete
                </DeleteButton>
              </div>
            </div>
          </div>
        </div>

        {/* Sidebar */}
        <div className="col-lg-4">
          <div className="card shadow mb-4">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-clock me-2"></i>Metadata
              </h6>
            </div>
            <div className="card-body">
              <div className="mb-2">
                <strong className="text-muted">Created</strong>
                <div style={{ fontSize: '0.9em' }}>{formatDateTime(apiKey.created_at, true)}</div>
              </div>
              {apiKey.revoked_at && (
                <div className="mb-2">
                  <strong className="text-muted">Revoked</strong>
                  <div style={{ fontSize: '0.9em' }}>{formatDateTime(apiKey.revoked_at, true)}</div>
                </div>
              )}
              {apiKey.last_used_at && (
                <div className="mb-2">
                  <strong className="text-muted">Last Used</strong>
                  <div style={{ fontSize: '0.9em' }}>
                    {formatDateTime(apiKey.last_used_at, true)}
                  </div>
                </div>
              )}
              {apiKey.issuer && (
                <div className="mb-2">
                  <strong className="text-muted">Issuer</strong>
                  <div style={{ fontSize: '0.9em' }}>
                    {apiKey.issuer.actor} ({apiKey.issuer.method})
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="card shadow mb-4 border-warning">
            <div className="card-body">
              <h6 className="font-weight-bold text-warning">
                <i className="fas fa-shield-alt me-2"></i>Security Notice
              </h6>
              <p className="mb-0" style={{ fontSize: '0.85em' }}>
                Keep your API keys secure and rotate them regularly. Revoked keys cannot be
                reactivated.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Rotated Key Secret Modal */}
      {rotatedKey && (
        <div className="modal d-block" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
          <div className="modal-dialog">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">Key Rotated</h5>
                <button
                  type="button"
                  className="btn-close"
                  onClick={() => {
                    setRotatedKey(null);
                    navigate(`/api-keys/${rotatedKey.agent_id}/${rotatedKey.key_id}`);
                  }}
                ></button>
              </div>
              <div className="modal-body">
                <div className="alert alert-warning">
                  <i className="fas fa-exclamation-triangle me-2"></i>
                  <strong>Copy the secret now.</strong> This is the only time it will be shown,
                  store it somewhere secure. It cannot be retrieved later.
                </div>
                <div className="mb-3">
                  <label className="form-label fw-bold">New Key ID</label>
                  <div>
                    <code>{rotatedKey.key_id}</code>
                  </div>
                </div>
                <div className="mb-3">
                  <label className="form-label fw-bold">New Secret</label>
                  <div className="input-group">
                    <input
                      type="text"
                      className="form-control font-monospace"
                      value={rotatedKey.secret}
                      readOnly
                    />
                    <button
                      className="btn btn-outline-secondary"
                      onClick={() => {
                        navigator.clipboard.writeText(rotatedKey.secret);
                        setSecretCopied(true);
                      }}
                    >
                      {secretCopied ? (
                        <i className="fas fa-check"></i>
                      ) : (
                        <i className="fas fa-copy"></i>
                      )}
                    </button>
                  </div>
                </div>
                <div className="mb-3">
                  <label className="form-label fw-bold">Rotated From</label>
                  <div>
                    <code>{rotatedKey.rotated_from}</code>
                  </div>
                </div>
              </div>
              <div className="modal-footer">
                <button
                  className="btn btn-primary"
                  onClick={() => {
                    setRotatedKey(null);
                    navigate(`/api-keys/${rotatedKey.agent_id}/${rotatedKey.key_id}`);
                  }}
                >
                  View New Key
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ApiKeyDetailPage;
