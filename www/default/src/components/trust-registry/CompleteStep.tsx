import React from 'react';

interface CompleteStepProps {
  trustRegistry: any;
  onFinish: () => void;
  onViewTrustRegistry: () => void;
}

const connectionStatusBadge = (status: string) => {
  switch (status) {
    case 'connected':
      return <span className="badge text-bg-success">CONNECTED</span>;
    case 'connecting':
      return <span className="badge text-bg-warning">CONNECTING</span>;
    case 'disconnected':
      return <span className="badge text-bg-secondary">DISCONNECTED</span>;
    case 'failed':
      return <span className="badge text-bg-danger">FAILED</span>;
    default:
      return <span className="badge text-bg-secondary">{status?.toUpperCase()}</span>;
  }
};

const CompleteStep: React.FC<CompleteStepProps> = ({
  trustRegistry,
  onFinish,
  onViewTrustRegistry,
}) => {
  return (
    <div className="card shadow">
      <div className="card-body">
        <div className="text-center py-5">
          <div className="mb-4">
            <i className="fas fa-check-circle hero-status-icon success"></i>
          </div>

          <h3 className="mb-3">Trust Registry Added Successfully!</h3>

          <p className="text-muted mb-4">The trust registry connection has been established.</p>

          <div className="card bg-light mb-4 mx-auto" style={{ maxWidth: '600px' }}>
            <div className="card-body text-start">
              <h5 className="font-weight-bold mb-3 text-center">{trustRegistry.name}</h5>

              {trustRegistry.our_did && (
                <div className="mb-3">
                  <strong>Our DID:</strong>
                  <div className="mt-1">
                    <code style={{ fontSize: '0.85rem', wordBreak: 'break-all' }}>
                      {trustRegistry.our_did}
                    </code>
                  </div>
                </div>
              )}

              {trustRegistry.registry_did && (
                <div className="mb-3">
                  <strong>Registry DID:</strong>
                  <div className="mt-1">
                    <code style={{ fontSize: '0.85rem', wordBreak: 'break-all' }}>
                      {trustRegistry.registry_did}
                    </code>
                  </div>
                </div>
              )}

              {trustRegistry.main_did && (
                <div className="mb-3">
                  <strong>Main DID:</strong>
                  <div className="mt-1">
                    <code style={{ fontSize: '0.85rem', wordBreak: 'break-all' }}>
                      {trustRegistry.main_did}
                    </code>
                  </div>
                </div>
              )}

              {trustRegistry.description && (
                <div className="mb-3">
                  <strong>Description:</strong>
                  <div className="mt-1">{trustRegistry.description}</div>
                </div>
              )}

              <div className="mb-3">
                <strong>Connection Status:</strong>
                <div className="mt-1">{connectionStatusBadge(trustRegistry.connection_status)}</div>
              </div>

              <div className="mb-0">
                <strong>Created:</strong>
                <div className="mt-1">{new Date(trustRegistry.created_at).toLocaleString()}</div>
              </div>
            </div>
          </div>

          <div className="d-flex justify-content-center" style={{ gap: '1rem' }}>
            <button type="button" className="btn btn-secondary" onClick={onFinish}>
              <i className="fas fa-list me-2"></i> View All Trust Registries
            </button>
            <button type="button" className="btn btn-primary" onClick={onViewTrustRegistry}>
              <i className="fas fa-edit me-2"></i> Edit Trust Registry
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CompleteStep;
