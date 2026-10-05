import React, { useState } from 'react';
import { formatDateTime } from '../../utils/stringUtils';
import { AppButton } from '../shared/AppButton';

interface CompleteStepProps {
  connectionPoint: any;
  onFinish: () => void;
}

const CompleteStep: React.FC<CompleteStepProps> = ({ connectionPoint, onFinish }) => {
  const [copied, setCopied] = useState(false);
  const [secretCopied, setSecretCopied] = useState(false);
  const [showSecret, setShowSecret] = useState(false);

  const handleCopyUrl = () => {
    if (connectionPoint?.oob_url) {
      navigator.clipboard.writeText(connectionPoint.oob_url);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleCopySecret = () => {
    if (connectionPoint?.secret) {
      navigator.clipboard.writeText(connectionPoint.secret);
      setSecretCopied(true);
      setTimeout(() => setSecretCopied(false), 2000);
    }
  };

  if (!connectionPoint) {
    return (
      <div className="card shadow">
        <div className="card-body text-center py-5">
          <div className="mb-3">
            <i className="fas fa-exclamation-triangle hero-status-icon warning"></i>
          </div>
          <h5>No Connection Point Data</h5>
          <p className="text-muted">Unable to display connection point details.</p>
          <AppButton
            variant="secondary"
            size="md"
            onClick={onFinish}
            iconStart={<i className="fas fa-list"></i>}
          >
            View All Connection Points
          </AppButton>
        </div>
      </div>
    );
  }

  return (
    <div className="card shadow" style={{ maxWidth: '800px', margin: '0 auto' }}>
      <div className="text-center">
        <h3 className="mb-3" style={{ marginTop: '15px' }}>
          Connection Point Created Successfully!
        </h3>
        <p className="text-muted mb-4">The Connection Point has been added to your gateway.</p>
      </div>
      <div className="card-body">
        <div className="mb-4">
          <h6 className="font-weight-bold mb-3">
            <i className="fas fa-link me-2"></i>
            Gateway Connection Point Link
          </h6>
          <div className="input-group">
            <input
              type="text"
              className="form-control font-monospace"
              value={connectionPoint.oob_url}
              readOnly
              title="Gateway Connection Point URL"
              style={{ fontSize: '0.85rem' }}
            />
            <button className="btn btn-outline-primary" onClick={handleCopyUrl}>
              <i className={`fas ${copied ? 'fa-check' : 'fa-copy'} me-1`}></i>
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <small className="text-muted mt-2 d-block">
            Share this URL with users to allow them to connect to your gateway
          </small>
        </div>

        <div className="mb-4">
          <h6 className="font-weight-bold mb-3">
            <i className="fas fa-lock me-2"></i>
            Connection Secret
          </h6>
          <div className="input-group">
            <input
              type={showSecret ? 'text' : 'password'}
              className="form-control font-monospace"
              value={connectionPoint.secret}
              readOnly
              title="Connection Secret"
              style={{ fontSize: '0.85rem' }}
            />
            <button
              className="btn btn-outline-secondary"
              onClick={() => setShowSecret(s => !s)}
              title={showSecret ? 'Hide secret' : 'Show secret'}
            >
              <i className={`fas ${showSecret ? 'fa-eye-slash' : 'fa-eye'}`}></i>
            </button>
            <button className="btn btn-outline-primary" onClick={handleCopySecret}>
              <i className={`fas ${secretCopied ? 'fa-check' : 'fa-copy'} me-1`}></i>
              {secretCopied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <small className="text-muted mt-2 d-block">
            Share this secret with users who need to accept the connection - they will need both the
            URL and the secret
          </small>
        </div>

        <div className="mb-4 p-3 bg-light rounded">
          <h6 className="font-weight-bold mb-2">
            <i className="fas fa-info-circle me-2"></i>
            Connection Point Details
          </h6>
          <div className="row">
            <div className="col-sm-4 text-muted small">Name:</div>
            <div className="col-sm-8 small">{connectionPoint.name}</div>

            <div className="col-sm-4 text-muted small">Description:</div>
            <div className="col-sm-8 small">{formatDateTime(connectionPoint.created_at, true)}</div>

            <div className="col-sm-4 text-muted small">Id:</div>
            <div className="col-sm-8 small">
              <code style={{ wordBreak: 'break-all' }}>{connectionPoint.id}</code>
            </div>
          </div>
          <div className="row mt-2">
            <div className="col-sm-4 text-muted small">Created:</div>
            <div className="col-sm-8 small">{formatDateTime(connectionPoint.created_at, true)}</div>
          </div>
        </div>

        <div className="text-center mt-4">
          <AppButton
            variant="secondary"
            size="md"
            onClick={onFinish}
            iconStart={<i className="fas fa-arrow-left"></i>}
          >
            View All Connections
          </AppButton>
        </div>
      </div>
    </div>
  );
};

export default CompleteStep;
