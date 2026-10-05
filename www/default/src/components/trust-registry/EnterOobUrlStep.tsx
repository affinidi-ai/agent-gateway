import React, { useState } from 'react';
import { validateUrl } from '../../utils/urlValidation';

interface EnterOobUrlStepProps {
  onNext: (name: string, description: string, oobUrl: string, didMethod: string) => void;
  onCancel: () => void;
}

const EnterOobUrlStep: React.FC<EnterOobUrlStepProps> = ({ onNext, onCancel }) => {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [oobUrl, setOobUrl] = useState('');
  const [didMethod, setDidMethod] = useState('web');
  const [error, setError] = useState('');

  const validateOobUrl = (url: string): boolean => {
    const result = validateUrl(url);
    if (!result.valid) {
      setError(result.error);
      return false;
    }
    return true;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    const trimmedName = name.trim();
    const trimmedUrl = oobUrl.trim();

    if (!trimmedName) {
      setError('Name is required');
      return;
    }

    if (!trimmedUrl) {
      setError('OOB URL is required');
      return;
    }

    if (!validateOobUrl(trimmedUrl)) {
      return;
    }

    onNext(trimmedName, description.trim(), trimmedUrl, didMethod);
  };

  return (
    <div className="card shadow">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-link me-2"></i> Enter Trust Registry Connection Details
        </h6>
      </div>
      <div className="card-body">
        <p className="text-muted mb-4">
          Enter the OOB (Out-of-Band) invitation URL provided by the trust registry. This URL is
          used to establish a secure DIDComm connection with the registry.
        </p>

        {error && (
          <div className="alert alert-danger" role="alert">
            <i className="fas fa-exclamation-circle me-2"></i>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
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
              placeholder="e.g. Affinidi Trust Registry"
              autoFocus
              required
            />
          </div>

          <div className="mb-3">
            <label htmlFor="description" className="form-label">
              Description
            </label>
            <textarea
              className="form-control"
              id="description"
              rows={2}
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder="Optional description of this trust registry"
            />
          </div>

          <div className="mb-3">
            <label htmlFor="didMethod" className="form-label">
              DID Method
            </label>
            <select
              className="form-select dropdown-styling"
              id="didMethod"
              value={didMethod}
              onChange={e => setDidMethod(e.target.value)}
            >
              <option value="web">Web (did:web)</option>
              <option value="webvh">WebVH (did:webvh)</option>
              <option value="peer">Peer (did:peer)</option>
            </select>
            <small className="form-text text-muted">
              The DID method used to generate the per-registry identity for this connection.
            </small>
          </div>

          <div className="mb-4">
            <label htmlFor="oobUrl" className="form-label">
              OOB Invitation URL *
            </label>
            <input
              type="url"
              className="form-control"
              id="oobUrl"
              value={oobUrl}
              onChange={e => setOobUrl(e.target.value)}
              placeholder="https://trust-registry.example.com/oob?_oobid=..."
              required
            />
            <small className="form-text text-muted">
              The trust registry administrator provides this URL. It contains the invitation to
              establish a secure connection.
            </small>
          </div>

          <div className="d-flex justify-content-between">
            <button type="button" className="btn btn-secondary" onClick={onCancel}>
              <i className="fas fa-times me-1"></i> Cancel
            </button>
            <button type="submit" className="btn btn-primary">
              Connect <i className="fas fa-arrow-right ms-1"></i>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default EnterOobUrlStep;
