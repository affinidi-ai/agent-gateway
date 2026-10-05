import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../../api';
import FieldHelp from '../../components/shared/FieldHelp';
import { formatDateTime } from '../../utils/stringUtils';

interface Mediator {
  id: string;
  name: string;
  description: string;
  did: string;
  status: string;
  created_at: string;
  updated_at: string;
  did_document?: any;
}

interface ConnectionPoint {
  id: string;
  mediator_id: string;
  gateway_id: string;
  created_at: string;
  updated_at: string;
  expires_at?: string;
}

interface ConnectionPointMetadataTabProps {
  connectionPoint: ConnectionPoint | null;
}

const ConnectionPointMetadataTab: React.FC<ConnectionPointMetadataTabProps> = ({
  connectionPoint,
}) => {
  const navigate = useNavigate();
  const [mediator, setMediator] = useState<Mediator | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (connectionPoint?.mediator_id) {
      fetchMediator();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [connectionPoint?.mediator_id]);

  const fetchMediator = async () => {
    if (!connectionPoint?.mediator_id) return;

    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get(`/mediators/${connectionPoint.mediator_id}`);
      setMediator(response.data);
    } catch (error: any) {
      setError(error.message || 'Failed to load mediator');
    } finally {
      setLoading(false);
    }
  };

  if (!connectionPoint) {
    return <div>Loading...</div>;
  }

  const isExpired = connectionPoint.expires_at
    ? new Date(connectionPoint.expires_at) < new Date()
    : false;
  const serviceCount = mediator?.did_document?.service?.length || 0;

  return (
    <>
      {/* Connection Point Metadata */}
      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-database"></i> Connection Point Metadata{' '}
            <FieldHelp testId="field-help-cp-metadata" ariaLabel="About Connection Point Metadata">
              Reference values used in the API, not something you need to edit.
            </FieldHelp>
          </h6>
        </div>
        <div className="card-body">
          <div className="row">
            <div className="col-md-6 mb-3">
              <label htmlFor="cp-metadata-id">Connection Point ID</label>
              <input
                type="text"
                className="form-control"
                id="cp-metadata-id"
                value={connectionPoint.id}
                readOnly
                disabled
              />
            </div>
            <div className="col-md-6 mb-3">
              <label htmlFor="cp-metadata-gateway">Gateway ID</label>
              <input
                type="text"
                className="form-control"
                id="cp-metadata-gateway"
                value={connectionPoint.gateway_id}
                readOnly
                disabled
              />
            </div>
          </div>

          <div className="row">
            <div className="col-md-6 mb-3">
              <label htmlFor="cp-metadata-mediator">Mediator ID</label>
              <input
                type="text"
                className="form-control"
                id="cp-metadata-mediator"
                value={connectionPoint.mediator_id}
                readOnly
                disabled
              />
            </div>
            <div className="col-md-6 mb-3">
              <label htmlFor="cp-metadata-created">Created</label>
              <input
                type="text"
                className="form-control"
                id="cp-metadata-created"
                value={formatDateTime(connectionPoint.created_at, true)}
                readOnly
                disabled
              />
            </div>
          </div>

          <div className="row">
            <div className="col-md-6 mb-3">
              <label htmlFor="cp-metadata-updated">Last Updated</label>
              <input
                type="text"
                className="form-control"
                id="cp-metadata-updated"
                value={
                  connectionPoint.updated_at
                    ? formatDateTime(connectionPoint.updated_at, true)
                    : '-'
                }
                readOnly
                disabled
              />
            </div>
          </div>

          {connectionPoint.expires_at && (
            <div className="row">
              <div className="col-md-6 mb-3">
                <label htmlFor="cp-metadata-expires">Expires</label>
                <input
                  type="text"
                  className="form-control"
                  id="cp-metadata-expires"
                  value={formatDateTime(connectionPoint.expires_at, true)}
                  readOnly
                  disabled
                  style={{
                    color: isExpired ? 'var(--danger)' : undefined,
                    fontWeight: isExpired ? 'bold' : undefined,
                  }}
                />
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Mediator Information */}
      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light">
          <div className="d-flex justify-content-between align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-server"></i> Mediator Information{' '}
              <FieldHelp
                testId="field-help-cp-mediator-info"
                ariaLabel="About Mediator Information"
              >
                This is the mediator this connection point uses to receive messages. Changing
                mediators requires creating a new connection point.
              </FieldHelp>
            </h6>
            {!loading && !error && mediator && (
              <div style={{ fontSize: '1.2rem' }}>
                <span
                  className={`badge badge-${mediator.status === 'active' ? 'success' : 'secondary'} me-2`}
                >
                  <i className="fas fa-circle"></i> {mediator.status.toUpperCase()}
                </span>
                <span className="badge text-bg-info">
                  <i className="fas fa-cog"></i> {serviceCount} Service
                  {serviceCount !== 1 ? 's' : ''}
                </span>
              </div>
            )}
          </div>
        </div>
        <div className="card-body">
          {loading ? (
            <div className="text-center py-3">
              <div className="spinner-border spinner-border-sm" role="status">
                <span className="visually-hidden"></span>
              </div>
              <p className="mt-2 mb-0 text-muted">Loading mediator details...</p>
            </div>
          ) : error ? (
            <div className="alert alert-danger mb-0">
              <i className="fas fa-exclamation-triangle me-2"></i>
              {error}
            </div>
          ) : !mediator ? (
            <div className="alert alert-warning mb-0">
              <i className="fas fa-exclamation-triangle me-2"></i>
              Mediator not found (ID: {connectionPoint.mediator_id})
            </div>
          ) : (
            <>
              <div className="row">
                <div className="col-md-12 mb-3">
                  <label htmlFor="mediator-name">Mediator Name</label>
                  <input
                    type="text"
                    className="form-control"
                    id="mediator-name"
                    value={mediator.name}
                    readOnly
                    disabled
                  />
                </div>
              </div>

              <div className="row">
                <div className="col-md-12 mb-3">
                  <label htmlFor="mediator-description">Description</label>
                  <input
                    type="text"
                    className="form-control"
                    id="mediator-description"
                    value={mediator.description}
                    readOnly
                    disabled
                  />
                </div>
              </div>

              <div className="row">
                <div className="col-md-12 mb-3">
                  <label htmlFor="mediator-did">DID</label>
                  <input
                    type="text"
                    className="form-control"
                    id="mediator-did"
                    value={mediator.did}
                    readOnly
                    disabled
                    style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}
                  />
                </div>
              </div>

              <div className="mt-3">
                <button
                  className="btn btn-sm btn-outline-primary"
                  onClick={() => navigate(`/mediators/view/${mediator.id}`)}
                >
                  <i className="fas fa-external-link-alt"></i> View Full Mediator Details
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </>
  );
};

export default ConnectionPointMetadataTab;
