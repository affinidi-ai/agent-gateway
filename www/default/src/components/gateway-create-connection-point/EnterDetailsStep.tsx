import React, { useState, useEffect } from 'react';
import { apiClient } from '../../api';
import { AppButton } from '../shared/AppButton';

interface EnterDetailsStepProps {
  onCreate: (
    gatewayId: string,
    name: string,
    description: string,
    secret: string,
    expirySeconds?: number,
    didMethod?: string
  ) => void;
  onBack: () => void;
  onCancel: () => void;
  initialGatewayId?: string | null;
  initialName?: string;
  initialDescription?: string;
  initialSecret?: string;
  initialExpirySeconds?: number;
  initialDidMethod?: string;
}

interface Gateway {
  id: string;
  name: string;
  gateway_type: string;
}

const EnterDetailsStep: React.FC<EnterDetailsStepProps> = ({
  onCreate,
  onBack,
  onCancel,
  initialGatewayId = null,
  initialName = '',
  initialDescription = '',
  initialSecret = '',
  initialExpirySeconds,
  initialDidMethod = 'web',
}) => {
  const [gateways, setGateways] = useState<Gateway[]>([]);
  const [selectedGatewayId, setSelectedGatewayId] = useState(initialGatewayId || '');
  const [name, setName] = useState(initialName);
  const [description, setDescription] = useState(initialDescription);
  const [secret, setSecret] = useState(initialSecret);
  const [didMethod, setDidMethod] = useState(initialDidMethod);
  const [expiryDateTime, setExpiryDateTime] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Generate a random UUID for the secret
  const generateSecret = () => {
    return crypto.randomUUID();
  };

  useEffect(() => {
    fetchGateways();

    // Set default expiry to 24 hours from now if not provided
    if (initialExpirySeconds) {
      const expiryDate = new Date(Date.now() + initialExpirySeconds * 1000);
      const formattedDate = expiryDate.toISOString().slice(0, 16);
      setExpiryDateTime(formattedDate);
    } else {
      const tomorrow = new Date();
      tomorrow.setHours(tomorrow.getHours() + 24);
      const formattedDate = tomorrow.toISOString().slice(0, 16);
      setExpiryDateTime(formattedDate);
    }

    // Generate initial secret only if not provided
    if (!initialSecret) {
      setSecret(generateSecret());
    }
  }, []);

  const fetchGateways = async () => {
    try {
      setLoading(true);
      const response = await apiClient.get('/gateways');
      // Filter to only show self gateways
      const selfGateways = response.data.filter((g: Gateway) => g.gateway_type === 'self');
      setGateways(selfGateways);

      // Auto-select if only one self gateway
      if (selfGateways.length === 1) {
        setSelectedGatewayId(selfGateways[0].id);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load gateways');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    if (!selectedGatewayId) {
      setError('Please select a gateway');
      return;
    }

    if (!name.trim()) {
      setError('Connection point name is required');
      return;
    }

    if (!expiryDateTime) {
      setError('Expiry date and time is required');
      return;
    }

    if (!secret.trim()) {
      setError('Secret is required');
      return;
    }

    // Calculate seconds from now to the expiry time
    const now = new Date();
    const expiry = new Date(expiryDateTime);
    const secondsFromNow = Math.floor((expiry.getTime() - now.getTime()) / 1000);

    if (secondsFromNow <= 0) {
      setError('Expiry time must be in the future');
      return;
    }

    onCreate(
      selectedGatewayId,
      name.trim(),
      description.trim(),
      secret.trim(),
      secondsFromNow,
      didMethod
    );
  };

  if (loading) {
    return (
      <div className="card shadow">
        <div className="card-body text-center py-5">
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden"></span>
          </div>
        </div>
      </div>
    );
  }

  if (gateways.length === 0) {
    return (
      <div className="card shadow">
        <div className="card-body text-center py-5">
          <div className="mb-3">
            <i className="fas fa-exclamation-triangle hero-status-icon warning"></i>
          </div>
          <h5>No Self Gateway Found</h5>
          <p className="text-muted">You need a self gateway to create connection points.</p>
          <AppButton
            variant="secondary"
            size="md"
            onClick={onCancel}
            iconStart={<i className="fas fa-arrow-left"></i>}
          >
            Back to Connection Points
          </AppButton>
        </div>
      </div>
    );
  }

  return (
    <div className="card shadow">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-info-circle me-2"></i>
          Connection Point Details
        </h6>
      </div>
      <div className="card-body">
        {error && (
          <div className="alert alert-danger" role="alert">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label htmlFor="gateway" className="form-label">
              Gateway <span className="text-danger">*</span>
            </label>
            <select
              id="gateway"
              className="form-control dropdown-styling"
              value={selectedGatewayId}
              onChange={e => setSelectedGatewayId(e.target.value)}
              required
            >
              <option value="">Select a gateway...</option>
              {gateways.map(gateway => (
                <option key={gateway.id} value={gateway.id}>
                  {gateway.name}
                </option>
              ))}
            </select>
            <small className="form-text text-muted">Only self gateways can be published</small>
          </div>

          <div className="mb-3">
            <label htmlFor="name" className="form-label">
              Connection Point Name <span className="text-danger">*</span>
            </label>
            <input
              type="text"
              id="name"
              className="form-control"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="e.g., Public Gateway Invitation"
              required
            />
            <small className="form-text text-muted">
              A friendly name for this connection point
            </small>
          </div>

          <div className="mb-3">
            <label htmlFor="description" className="form-label">
              Description
            </label>
            <input
              id="description"
              className="form-control"
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder="Describe the purpose of this connection point..."
            />
            <small className="form-text text-muted">
              Optional description of what this connection point is for
            </small>
          </div>

          <div className="mb-3">
            <label htmlFor="didMethod" className="form-label">
              DID Method
            </label>
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
              The DID method used to generate the identity for this connection point.
            </small>
          </div>

          <div className="mb-3">
            <label htmlFor="secret" className="form-label">
              Connection Secret <span className="text-danger">*</span>
            </label>
            <div className="input-group">
              <input
                type="text"
                id="secret"
                className="form-control font-monospace"
                value={secret}
                onChange={e => setSecret(e.target.value)}
                placeholder="Enter or generate a secret..."
                required
              />
              <button
                type="button"
                className="btn btn-outline-secondary"
                onClick={() => setSecret(generateSecret())}
                title="Generate new secret"
              >
                <i className="fas fa-sync-alt"></i>
              </button>
            </div>
            <small className="form-text text-muted">
              <i className="fas fa-lock me-1"></i>
              This secret is required for accepting the OOB invitation. Keep it secure and share it
              only with trusted parties.
            </small>
          </div>

          <div className="mb-3">
            <label htmlFor="expiryDateTime" className="form-label">
              Expiry Date & Time <span className="text-danger">*</span>
            </label>
            <input
              type="datetime-local"
              id="expiryDateTime"
              className="form-control"
              value={expiryDateTime}
              onChange={e => setExpiryDateTime(e.target.value)}
              required
            />
            <small className="form-text text-muted">
              The Connection Point invitation will expire at this date and time
            </small>
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

export default EnterDetailsStep;
