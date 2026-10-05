import React, { useState } from 'react';
import { validateUrl } from '../../utils/urlValidation';
import { AppButton } from '../shared/AppButton';

interface EnterOOBLinkStepProps {
  onNext: (link: string, secret: string) => void;
  onBack?: () => void;
  onCancel: () => void;
  initialLink?: string;
  initialSecret?: string;
}

const EnterOOBLinkStep: React.FC<EnterOOBLinkStepProps> = ({
  onNext,
  onBack,
  onCancel,
  initialLink = '',
  initialSecret = '',
}) => {
  const [link, setLink] = useState(initialLink);
  const [secret, setSecret] = useState(initialSecret);
  const [showSecret, setShowSecret] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!link.trim()) {
      setError('Please enter a connection point link');
      return;
    }

    // Validate that it's a URL
    const decodedLink = (() => {
      try {
        return decodeURIComponent(link);
      } catch {
        return link;
      }
    })();
    const linkCheck = validateUrl(decodedLink);
    if (!linkCheck.valid) {
      setError(linkCheck.error);
      return;
    }

    // Check if it looks like an OOB invitation URL (contains _oobid parameter)
    if (!link.includes('_oobid=') && !link.includes('oob')) {
      setError("This doesn't appear to be a valid Connection Point Link?");
      return;
    }

    if (!secret.trim()) {
      setError('Connection secret is required');
      return;
    }

    onNext(decodeURIComponent(link), secret);
  };

  return (
    <div className="card shadow">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-link me-2"></i> Enter Connection Point Link
        </h6>
      </div>
      <div className="card-body">
        <p className="text-muted">
          Enter the Connection Point Link provided by the administrator of the Agent Gateway you
          wish to connect to. This link allows you to establish a secure DIDComm connection to your
          Agent Gateway.
        </p>

        <form onSubmit={handleSubmit}>
          {error && (
            <div className="alert alert-danger" role="alert">
              <i className="fas fa-exclamation-circle me-2"></i>
              {error}
            </div>
          )}

          <div className="mb-4">
            <label htmlFor="oobLink" className="form-label fw-bold">
              Connection Point Link <span className="text-danger">*</span>
            </label>
            <input
              type="text"
              className="form-control form-control-lg"
              id="oobLink"
              value={link}
              onChange={e => setLink(e.target.value)}
              placeholder="https://example.mediator.com/oob?_oobid=..."
              required
              autoFocus
            />
            <small className="form-text text-muted">
              Example: https://apse1.mediator.affinidi.io/oob?_oobid=abc123...
            </small>
          </div>

          <div className="mb-4">
            <label htmlFor="oobSecret" className="form-label fw-bold">
              Connection Secret <span className="text-danger">*</span>
            </label>
            <div className="input-group">
              <input
                type={showSecret ? 'text' : 'password'}
                className="form-control form-control-lg font-monospace"
                id="oobSecret"
                value={secret}
                onChange={e => setSecret(e.target.value)}
                placeholder="Enter the connection secret..."
                required
              />
              <button
                type="button"
                className="btn btn-outline-secondary"
                onClick={() => setShowSecret(s => !s)}
                title={showSecret ? 'Hide secret' : 'Show secret'}
              >
                <i className={`fas ${showSecret ? 'fa-eye-slash' : 'fa-eye'}`}></i>
              </button>
            </div>
            <small className="form-text text-muted">
              <i className="fas fa-lock me-1"></i>
              Enter the secret provided by the Connection Point administrator. This secret is
              required to accept the invitation.
            </small>
          </div>

          <div className="alert alert-info" role="alert">
            <i className="fas fa-info-circle me-3"></i>
            <strong style={{ whiteSpace: 'nowrap', marginRight: '20px' }}>
              What is a Connection Point Link?
            </strong>
            <p className="mb-0 mt-2">
              A Connection Point Link is a URL created by an Agent Gateway administrator that allows
              another Agent Gateway to connect to their Agent Gateway via a Connection Point. The
              gateway administrator creates this link and shares it with you securely. Once you
              enter the link, the system will use it to establish a secure DIDComm connection to the
              Agent Gateway and allow you to configure a channel to route agent traffic through it.
            </p>
          </div>

          <div className="d-flex justify-content-between mt-4">
            <AppButton
              type="button"
              variant="secondary"
              size="md"
              onClick={onCancel}
              iconStart={<i className="fas fa-times"></i>}
            >
              Cancel
            </AppButton>
            <div className="d-flex gap-2">
              {onBack && (
                <AppButton
                  type="button"
                  variant="secondary"
                  size="md"
                  onClick={onBack}
                  iconStart={<i className="fas fa-arrow-left"></i>}
                >
                  Back
                </AppButton>
              )}
              <AppButton
                type="submit"
                variant="primary"
                size="md"
                iconEnd={<i className="fas fa-arrow-right"></i>}
              >
                Next
              </AppButton>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};

export default EnterOOBLinkStep;
