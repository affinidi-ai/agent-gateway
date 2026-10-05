import React, { useState } from 'react';
import { apiClient } from '../../api';
import { getErrorMessage } from '../../utils/apiError';
import { topAndTail } from '../../utils/stringUtils';
import { AppButton } from '../shared/AppButton';
import { CopyButton } from '../shared/CopyButton';

interface ApproveStepProps {
  gatewayId: string;
  name: string;
  description: string;
  gatewayDid: string;
  onApproved: (gateway: any) => void;
  onBack: () => void;
  onCancel: () => void;
}

const ApproveStep: React.FC<ApproveStepProps> = ({
  gatewayId,
  name,
  description,
  gatewayDid,
  onApproved,
  onBack,
  onCancel,
}) => {
  const [isApproving, setIsApproving] = useState(false);
  const [error, setError] = useState('');

  const handleApprove = async () => {
    setIsApproving(true);
    setError('');

    try {
      const response = await apiClient.post(`/gateways/${gatewayId}/approve`, {
        name,
        description,
      });
      onApproved(response.data);
    } catch (err: any) {
      console.error('Approval failed:', err);
      setError(getErrorMessage(err, 'Failed to approve gateway connection'));
      setIsApproving(false);
    }
  };

  return (
    <div className="card shadow">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-check-circle me-2"></i> Confirm Approval
        </h6>
      </div>
      <div className="card-body">
        <p className="text-muted">Confirm the details below before approving this connection.</p>

        <div className="alert alert-warning">
          <i className="fas fa-exclamation-triangle me-2"></i>
          <strong>Approving grants access.</strong> Once approved, the remote Agent Gateway will be
          able to communicate with your Agent Gateway. Only approve connections from Agent Gateways
          you recognize and trust.
        </div>

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

        <div className="card bg-light mb-3">
          <div className="card-body">
            <h6 className="text-primary mb-3">Gateway Information</h6>
            <dl className="row mb-0" style={{ fontSize: '0.875rem' }}>
              <dt className="col-sm-3">Name:</dt>
              <dd className="col-sm-9">{name}</dd>

              <dt className="col-sm-3">Description:</dt>
              <dd className="col-sm-9">
                {description || <span className="text-muted">No description provided</span>}
              </dd>

              <dt className="col-sm-3">Gateway DID:</dt>
              <dd className="col-sm-9">
                <code style={{ fontSize: '0.75rem' }}>{topAndTail(gatewayDid, 16, 16)}</code>
                <CopyButton text={gatewayDid} />
              </dd>
            </dl>
          </div>
        </div>

        {isApproving && (
          <div className="alert alert-info">
            <div className="spinner-border spinner-border-sm me-2" role="status">
              <span className="sr-only">Approving...</span>
            </div>
            Establishing connection and sending approval to remote Agent Gateway...
          </div>
        )}

        <div className="d-flex justify-content-between">
          <AppButton
            type="button"
            variant="secondary"
            size="md"
            onClick={onCancel}
            disabled={isApproving}
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
              disabled={isApproving}
              iconStart={<i className="fas fa-arrow-left"></i>}
            >
              Back
            </AppButton>
            <AppButton
              type="button"
              variant="primary"
              size="md"
              onClick={handleApprove}
              loading={isApproving}
              loadingLabel="Approving..."
              iconStart={<i className="fas fa-check"></i>}
            >
              Approve Connection
            </AppButton>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ApproveStep;
