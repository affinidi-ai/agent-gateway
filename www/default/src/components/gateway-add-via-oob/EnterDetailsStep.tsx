import React, { useEffect, useState } from 'react';
import { apiClient } from '../../api';
import { AppButton } from '../shared/AppButton';
import { useApp } from '../../context/AppContext';

interface Mediator {
  id: string;
  name: string;
  registered?: boolean;
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
  const [mediatorsLoadFailed, setMediatorsLoadFailed] = useState(false);
  const [error, setError] = useState('');
  const { state } = useApp();
  const mediatorFederationEnabled = state.settings?.feature_flags?.mediator_federation === true;

  useEffect(() => {
    if (!mediatorFederationEnabled) return;
    apiClient
      .get('/mediators')
      .then(response => {
        setMediators(Array.isArray(response.data) ? response.data : []);
        setMediatorsLoadFailed(false);
      })
      .catch(() => {
        setMediators([]);
        setMediatorsLoadFailed(true);
      });
  }, [mediatorFederationEnabled]);

  const registeredMediators = mediators.filter(m => m.registered && m.status === 'active');

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
                data-testid="wizard-oob-acceptor-mediator"
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
              {mediatorsLoadFailed ? (
                <small
                  className="form-text text-danger d-block"
                  data-testid="wizard-oob-acceptor-mediator-load-error"
                >
                  Your mediators could not be loaded, so only the inviter's mediator is offered.
                </small>
              ) : (
                registeredMediators.length === 0 && (
                  <small
                    className="form-text text-muted d-block"
                    data-testid="wizard-oob-acceptor-mediator-empty"
                  >
                    You have no active, registered mediator to select.
                  </small>
                )
              )}
              <small className="form-text text-muted d-block">
                By default the permanent connection is homed on the inviter's mediator. Selecting
                one of your own active, registered mediators homes it there instead. Experimental:
                requests between gateways on different mediators are not relayed yet.
              </small>
            </div>
          )}

          <div className="d-flex justify-content-between">
            <AppButton
              type="button"
              variant="secondary"
              size="md"
              data-testid="wizard-cancel"
              onClick={onCancel}
              iconStart={<i className="fas fa-times"></i>}
            >
              Cancel
            </AppButton>
            <AppButton
              data-testid="wizard-next"
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
