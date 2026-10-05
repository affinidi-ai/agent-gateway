import React, { useState } from 'react';
import { topAndTail } from '../../utils/stringUtils';
import { AppButton } from '../shared/AppButton';
import { CopyButton } from '../shared/CopyButton';

interface ConfirmStepProps {
  did: string;
  didDocument: any;
  onConfirm: (name: string, description: string) => void;
  onBack: () => void;
  onCancel: () => void;
}

const ConfirmStep: React.FC<ConfirmStepProps> = ({
  did,
  didDocument,
  onConfirm,
  onBack,
  onCancel,
}) => {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!name.trim()) {
      setError('Please enter a name for the mediator');
      return;
    }

    onConfirm(name.trim(), description.trim());
  };

  return (
    <div className="card shadow">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-cog me-2"></i> Configure Mediator
        </h6>
      </div>
      <div className="card-body">
        <p className="text-muted mb-4">
          The DID has been successfully resolved and validated. Please provide a name and
          description for this mediator.
        </p>

        <div className="alert alert-info mb-4">
          <h6 className="font-weight-bold mb-2">
            <i className="fas fa-info-circle me-2"></i>
            Mediator Details
          </h6>
          <div className="mb-2">
            <strong>DID:</strong>
            <div className="mt-1">
              <code style={{ fontSize: '0.85rem' }}>{topAndTail(didDocument.id, 16, 16)}</code>
              <CopyButton text={didDocument.id} />
            </div>
          </div>

          {didDocument.service && didDocument.service.length > 0 && (
            <div>
              <strong>Service Endpoints:</strong>
              <ul className="mt-1 mb-0">
                {didDocument.service.map((service: any, idx: number) => {
                  // Extract URI from serviceEndpoint
                  let uri = '';
                  if (typeof service.serviceEndpoint === 'string') {
                    uri = service.serviceEndpoint;
                  } else if (service.serviceEndpoint?.uri) {
                    uri = service.serviceEndpoint.uri;
                  } else if (
                    Array.isArray(service.serviceEndpoint) &&
                    service.serviceEndpoint.length > 0
                  ) {
                    uri =
                      typeof service.serviceEndpoint[0] === 'string'
                        ? service.serviceEndpoint[0]
                        : service.serviceEndpoint[0]?.uri || '';
                  }

                  return uri ? (
                    <li key={idx}>
                      <code style={{ fontSize: '0.8rem' }}>{uri}</code>
                    </li>
                  ) : null;
                })}
              </ul>
            </div>
          )}
        </div>

        <form onSubmit={handleSubmit}>
          <div className="mb-3">
            <label htmlFor="name" className="form-label">
              <strong>Mediator Name *</strong>
            </label>
            <input
              type="text"
              className={`form-control ${error && !name.trim() ? 'is-invalid' : ''}`}
              id="name"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="Enter a friendly name for this mediator"
              required
            />
            {error && !name.trim() && <div className="invalid-feedback">{error}</div>}
          </div>

          <div className="mb-4">
            <label htmlFor="description" className="form-label">
              <strong>Description</strong>
            </label>
            <input
              className="form-control"
              id="description"
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder="Enter an optional description for this mediator"
            />
          </div>

          <div className="d-flex justify-content-between">
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
              <AppButton
                type="button"
                variant="secondary"
                size="md"
                onClick={onBack}
                iconStart={<i className="fas fa-arrow-left"></i>}
              >
                Back
              </AppButton>
              <AppButton
                type="submit"
                variant="primary"
                size="md"
                iconStart={<i className="fas fa-check"></i>}
              >
                Create Mediator
              </AppButton>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};

export default ConfirmStep;
