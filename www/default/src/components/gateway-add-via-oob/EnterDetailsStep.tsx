import React, { useEffect, useState } from 'react';
import { apiClient } from '../../api';
import { AppButton } from '../shared/AppButton';
import { useApp } from '../../context/AppContext';

interface Mediator {
  id: string;
  name: string;
  our_did?: string;
  status: 'active' | 'disabled';
}

interface EnterDetailsStepProps {
  onNext: (
    name: string,
    description: string,
    didMethod: string,
    acceptorMediatorId: string
  ) => void;
  onCancel: () => void;
  initialName?: string;
  initialDescription?: string;
  initialDidMethod?: string;
  initialAcceptorMediatorId?: string;
}

const EnterDetailsStep: React.FC<EnterDetailsStepProps> = ({
  onNext,
  onCancel,
  initialName = '',
  initialDescription = '',
  initialDidMethod = 'web',
  initialAcceptorMediatorId = '',
}) => {
  const [name, setName] = useState(initialName);
  const [description, setDescription] = useState(initialDescription);
  const [didMethod, setDidMethod] = useState(initialDidMethod);
  const [acceptorMediatorId, setAcceptorMediatorId] = useState(initialAcceptorMediatorId);
  const [mediators, setMediators] = useState<Mediator[]>([]);
  const [error, setError] = useState('');
  const { state } = useApp();
  const mediatorFederationEnabled = state.settings?.feature_flags?.mediator_federation === true;

  useEffect(() => {
    if (!mediatorFederationEnabled) return;
    apiClient
      .get('/mediators')
      .then(response => setMediators(response.data))
      .catch(() => setMediators([]));
  }, [mediatorFederationEnabled]);

  // Only a mediator already registered on this gateway (our_did present) can
  // be selected — the backend rejects an unregistered mediator with a 400.
  const registeredMediators = mediators.filter(m => m.our_did && m.status === 'active');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    if (!name.trim()) {
      setError('Gateway name is required');
      return;
    }

    onNext(name.trim(), description.trim(), didMethod, acceptorMediatorId);
  };

  return (
    <div className="card shadow">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-info-circle me-2"></i> Enter Gateway Details
        </h6>
      </div>
      <div className="card-body">
        <p className="text-muted">
          Provide a name and description for the gateway you're connecting to. This will help you
          identify it in your connections list.
        </p>

        {error && (
          <div className="alert alert-danger alert-dismissible fade show" role="alert">
            {error}
            <button
              type="button"
              className="btn-close"
              onClick={() => setError('')}
              aria-label="Close"
            />
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="mb-3">
            <label htmlFor="gatewayName">
              Gateway Name <span className="text-danger">*</span>
            </label>
            <input
              type="text"
              className="form-control"
              id="gatewayName"
              placeholder="e.g., Partner Gateway, Production Server, etc."
              value={name}
              onChange={e => setName(e.target.value)}
              required
            />
            <small className="form-text text-muted">
              Choose a descriptive name to easily identify this Agent Gateway Connection Point
            </small>
          </div>

          <div className="mb-3">
            <label htmlFor="gatewayDescription">Description (Optional)</label>
            <input
              className="form-control"
              id="gatewayDescription"
              placeholder="e.g., Connection to partner organization's Agent Gateway"
              value={description}
              onChange={e => setDescription(e.target.value)}
            />
            <small className="form-text text-muted">
              Add any additional details about this Agent Gateway Connection Point
            </small>
          </div>

          <div className="mb-3">
            <label htmlFor="didMethod">DID Method</label>
            <select
              className="form-select"
              id="didMethod"
              value={didMethod}
              onChange={e => setDidMethod(e.target.value)}
            >
              <option value="web">Web (did:web)</option>
              <option value="webvh">WebVH (did:webvh)</option>
              <option value="peer">Peer (did:peer)</option>
            </select>
            <small className="form-text text-muted">
              The DID method used to generate the identity for this connection.
            </small>
          </div>

          {mediatorFederationEnabled && (
            <div className="mb-3">
              <label htmlFor="acceptorMediatorId">Mediator for this connection (Optional)</label>
              <select
                className="form-select"
                id="acceptorMediatorId"
                value={acceptorMediatorId}
                onChange={e => setAcceptorMediatorId(e.target.value)}
              >
                <option value="">Use the inviter's mediator (default)</option>
                {registeredMediators.map(m => (
                  <option key={m.id} value={m.id}>
                    {m.name}
                  </option>
                ))}
              </select>
              <small className="form-text text-muted">
                By default the permanent connection is homed on the inviter's mediator. Select one
                of your own registered mediators to keep this gateway's traffic on its own mediator
                instead (cross-mediator federation).
              </small>
            </div>
          )}

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
            <AppButton
              type="submit"
              variant="primary"
              size="md"
              iconEnd={<i className="fas fa-arrow-right"></i>}
            >
              Next
            </AppButton>
          </div>
        </form>
      </div>
    </div>
  );
};

export default EnterDetailsStep;
