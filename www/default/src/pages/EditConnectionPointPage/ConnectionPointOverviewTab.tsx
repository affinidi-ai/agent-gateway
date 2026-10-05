import React from 'react';

import { apiClient } from '../../api';
import FieldHelp from '../../components/shared/FieldHelp';
import {
  ConnectionHealthBadge,
  ConnectionRuntimeStatus,
  errorCodeLabel,
  reconnectAtLabel,
} from '../../utils/connectionHealth';
import { formatDateTime, timeAgo } from '../../utils/stringUtils';

interface ConnectionPoint {
  id: string;
  gateway_id: string;
  name: string;
  description: string;
  oob_url: string;
  use_count: number;
  created_at: string;
  last_used_at?: string;
  expires_at?: string;
  secret?: string;
  enabled?: boolean;
  did_method?: string;
  runtime_status?: ConnectionRuntimeStatus;
}

interface ConnectionPointFormData {
  name: string;
  description: string;
  enabled: boolean;
}

interface ConnectionPointOverviewTabProps {
  connectionPoint: ConnectionPoint | null;
  formData: ConnectionPointFormData;
  onInputChange: (field: keyof ConnectionPointFormData, value: string | boolean) => void;
  onCopyUrl: () => void;
  onCopySecret: () => void;
}

const ConnectionPointOverviewTab: React.FC<ConnectionPointOverviewTabProps> = ({
  connectionPoint,
  formData,
  onInputChange,
  onCopyUrl,
  onCopySecret,
}) => {
  // Force re-render every 30 seconds to update relative time displays ("5 minutes ago")
  const [, setTick] = React.useState(0);
  const [showSecret, setShowSecret] = React.useState(false);
  const [reconnecting, setReconnecting] = React.useState(false);
  const [reconnectMessage, setReconnectMessage] = React.useState<string | null>(null);
  React.useEffect(() => {
    const interval = setInterval(() => {
      setTick(prev => prev + 1);
    }, 30000); // Update every 30 seconds

    return () => clearInterval(interval);
  }, []);

  if (!connectionPoint) {
    return <div>Loading...</div>;
  }

  const handleReconnect = async () => {
    try {
      setReconnecting(true);
      setReconnectMessage(null);
      await apiClient.post(`/connection-points/${connectionPoint.id}/reconnect`, {});
      setReconnectMessage('Reconnect requested');
    } catch (e: any) {
      setReconnectMessage(e.message || 'Failed to reconnect');
    } finally {
      setReconnecting(false);
    }
  };

  const isExpired = connectionPoint.expires_at
    ? new Date(connectionPoint.expires_at) < new Date()
    : false;

  return (
    <>
      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light">
          <div className="d-flex justify-content-between align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-info-circle"></i> Connection Information
            </h6>
          </div>
        </div>
        <div className="card-body">
          {/* Connection Point Link */}
          <div className="mb-3">
            <label htmlFor="cp-edit-link">
              Connection Point Link{' '}
              <FieldHelp testId="field-help-cp-link" ariaLabel="About Connection Point Link">
                The out-of-band (OOB) invitation URL. Share it with the remote gateway's
                administrator, anyone with this link can attempt to connect.
              </FieldHelp>
            </label>
            <div className="input-group">
              <input
                type="text"
                className="form-control"
                id="cp-edit-link"
                value={connectionPoint.oob_url}
                readOnly
                style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}
              />
              <button
                className="btn btn-outline-secondary"
                type="button"
                onClick={onCopyUrl}
                title="Copy to clipboard"
              >
                <i className="fas fa-copy"></i>
              </button>
            </div>
          </div>

          {/* Secret */}
          {connectionPoint.secret && (
            <div className="mb-3">
              <label htmlFor="cp-edit-secret">
                Connection Secret{' '}
                <FieldHelp testId="field-help-cp-secret" ariaLabel="About Connection Secret">
                  A shared secret the remote gateway must present alongside the link. Treat it like
                  a password, anyone with both can connect.
                </FieldHelp>
              </label>
              <div className="input-group">
                <input
                  type={showSecret ? 'text' : 'password'}
                  className="form-control"
                  id="cp-edit-secret"
                  value={connectionPoint.secret}
                  readOnly
                  style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}
                />
                <button
                  className="btn btn-outline-secondary"
                  type="button"
                  onClick={() => setShowSecret(s => !s)}
                  title={showSecret ? 'Hide secret' : 'Show secret'}
                >
                  <i className={`fas ${showSecret ? 'fa-eye-slash' : 'fa-eye'}`}></i>
                </button>
                <button
                  className="btn btn-outline-secondary"
                  type="button"
                  onClick={onCopySecret}
                  title="Copy to clipboard"
                >
                  <i className="fas fa-copy"></i>
                </button>
              </div>
            </div>
          )}

          {/* Name */}
          <div className="mb-3">
            <label htmlFor="cp-edit-name">Connection Point Name</label>
            <input
              type="text"
              className="form-control"
              id="cp-edit-name"
              value={formData.name}
              onChange={e => onInputChange('name', e.target.value)}
            />
          </div>

          {/* Description */}
          <div className="mb-3">
            <label htmlFor="cp-edit-description">Description</label>
            <input
              type="text"
              className="form-control"
              id="cp-edit-description"
              value={formData.description}
              onChange={e => onInputChange('description', e.target.value)}
              placeholder="Enter connection point description"
            />
          </div>

          {/* DID Method */}
          {connectionPoint.did_method && (
            <div className="mb-3">
              <label htmlFor="cp-edit-did-method">
                DID Method{' '}
                <FieldHelp testId="field-help-cp-did-method" ariaLabel="About DID Method">
                  The DID method this connection point uses for its own identity, which the remote
                  gateway connecting to it will resolve, set when it was created. did:peer needs no
                  hosting; did:webvh and did:web publish a resolvable document at a URL you control.
                </FieldHelp>
              </label>
              <input
                type="text"
                className="form-control"
                id="cp-edit-did-method"
                value={
                  connectionPoint.did_method === 'peer'
                    ? 'Peer (did:peer)'
                    : connectionPoint.did_method === 'webvh'
                      ? 'WebVH (did:webvh)'
                      : 'Web (did:web)'
                }
                readOnly
                disabled
              />
            </div>
          )}

          <div className="mb-3">
            <i className="fas fa-clock text-muted me-2"></i>
            <strong> Last Used: </strong>
            {connectionPoint.last_used_at ? (
              <span>
                {timeAgo(connectionPoint.last_used_at)}
                <span className="text-muted">
                  {' '}
                  - {formatDateTime(connectionPoint.last_used_at, true)}
                </span>
              </span>
            ) : (
              <span className="text-muted">Never used</span>
            )}
          </div>
          <div className="mb-4">
            <div className="form-check">
              <input
                type="checkbox"
                className="form-check-input"
                id="cp-edit-enabled"
                checked={formData.enabled}
                onChange={e => onInputChange('enabled', e.target.checked)}
              />
              <label className="form-check-label" htmlFor="cp-edit-enabled">
                <strong>Connection Point Enabled</strong> - When unchecked, this connection point
                will be disabled
                {!formData.enabled && (
                  <span className="badge text-bg-warning ms-2">
                    <i className="fas fa-power-off"></i> DISABLED
                  </span>
                )}
              </label>
            </div>
          </div>
          <div className="mb-3">
            <span className={`badge badge-${isExpired ? 'danger' : 'success'} me-2`}>
              {isExpired ? 'EXPIRED' : 'VALID'}
            </span>
            <span className="badge text-bg-info me-2">
              <i className="fas fa-chart-line"></i> {connectionPoint.use_count} Uses
            </span>
          </div>
        </div>
      </div>

      {/* Connection Health */}
      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-heartbeat"></i> Connection Health{' '}
            <FieldHelp testId="field-help-cp-connection-health" ariaLabel="About Connection Health">
              Shows whether the remote gateway is currently reachable through this connection point.
              A failure here doesn't affect other connection points or gateways.
            </FieldHelp>
          </h6>
        </div>
        <div className="card-body">
          {connectionPoint.runtime_status ? (
            <>
              <div className="mb-2">
                <ConnectionHealthBadge
                  runtime={connectionPoint.runtime_status}
                  showReconnectLine={false}
                />
              </div>
              {connectionPoint.runtime_status.status !== 'connected' && (
                <>
                  {(connectionPoint.runtime_status.error_message ||
                    errorCodeLabel(connectionPoint.runtime_status.error_code)) && (
                    <div className="mb-1">
                      <strong>Reason:</strong>{' '}
                      {connectionPoint.runtime_status.error_message ||
                        errorCodeLabel(connectionPoint.runtime_status.error_code)}
                    </div>
                  )}
                  {reconnectAtLabel(connectionPoint.runtime_status) && (
                    <div className="mb-1 text-muted">
                      {reconnectAtLabel(connectionPoint.runtime_status)}
                    </div>
                  )}
                  {typeof connectionPoint.runtime_status.consecutive_failures === 'number' &&
                    connectionPoint.runtime_status.consecutive_failures > 0 && (
                      <div className="mb-1 text-muted">
                        Failed attempts: {connectionPoint.runtime_status.consecutive_failures}
                      </div>
                    )}
                  {connectionPoint.runtime_status.original_error && (
                    <details className="mb-2">
                      <summary className="text-muted" style={{ cursor: 'pointer' }}>
                        Error details
                      </summary>
                      <code style={{ fontSize: '0.75rem', whiteSpace: 'pre-wrap' }}>
                        {connectionPoint.runtime_status.original_error}
                      </code>
                    </details>
                  )}
                </>
              )}
              <div className="mb-3">
                {connectionPoint.runtime_status.last_active_at ? (
                  <span className="text-muted">
                    Last active:{' '}
                    {formatDateTime(connectionPoint.runtime_status.last_active_at, true)}
                  </span>
                ) : (
                  <span className="text-muted">Never connected</span>
                )}
              </div>
            </>
          ) : (
            <div className="text-muted mb-3">No runtime status recorded yet.</div>
          )}
          <button
            className="btn btn-outline-primary btn-sm"
            type="button"
            disabled={reconnecting}
            onClick={handleReconnect}
            title="Immediately retries the connection instead of waiting for the next scheduled attempt"
          >
            {reconnecting ? (
              <>
                <span className="spinner-border spinner-border-sm" role="status"></span>{' '}
                Reconnecting…
              </>
            ) : (
              <>
                <i className="fas fa-sync-alt"></i> Retry Now
              </>
            )}
          </button>
          {reconnectMessage && <span className="ms-2 text-success">{reconnectMessage}</span>}
        </div>
      </div>
    </>
  );
};

export default ConnectionPointOverviewTab;
