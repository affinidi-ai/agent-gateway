import React from 'react';
import { topAndTail } from '../../utils/stringUtils';
import { AppButton } from '../shared/AppButton';
import { CopyButton } from '../shared/CopyButton';

interface CompleteStepProps {
  mediator: any;
  onFinish: () => void;
  onViewMediator: () => void;
}

const CompleteStep: React.FC<CompleteStepProps> = ({ mediator, onFinish, onViewMediator }) => {
  return (
    <div className="card shadow">
      <div className="card-body">
        <div className="text-center py-5">
          <div className="mb-4">
            <i className="fas fa-check-circle hero-status-icon success"></i>
          </div>

          <h3 className="mb-3">Mediator Added Successfully!</h3>

          <p className="text-muted mb-4">
            The mediator has been successfully added to your system.
          </p>

          <div className="card bg-light mb-4 mx-auto" style={{ maxWidth: '600px' }}>
            <div className="card-body text-start">
              <h5 className="font-weight-bold mb-3 text-center">{mediator.name}</h5>

              <div className="mb-3">
                <strong>Mediator DID:</strong>
                <div className="mt-1">
                  <code style={{ fontSize: '0.85rem' }}>{topAndTail(mediator.did, 16, 16)}</code>
                  <CopyButton text={mediator.did} />
                </div>
              </div>

              {mediator.our_did && (
                <div className="mb-3">
                  <strong>Our DID:</strong>
                  <div className="mt-1">
                    <code style={{ fontSize: '0.85rem' }}>
                      {topAndTail(mediator.our_did, 16, 16)}
                    </code>
                    <CopyButton text={mediator.our_did} />
                  </div>
                  <small className="text-muted d-block mt-1">
                    <i className="fas fa-info-circle me-1"></i>
                    This is a persistent did:peer used for administrative communications with this
                    mediator
                  </small>
                </div>
              )}

              {mediator.description && (
                <div className="mb-3">
                  <strong>Description:</strong>
                  <div className="mt-1">{mediator.description}</div>
                </div>
              )}

              <div className="mb-3">
                <strong>Status:</strong>
                <div className="mt-1">
                  <span className="badge text-bg-success">ACTIVE</span>
                </div>
              </div>

              <div className="mb-0">
                <strong>Created:</strong>
                <div className="mt-1">{new Date(mediator.created_at).toLocaleString()}</div>
              </div>
            </div>
          </div>

          <div className="d-flex justify-content-center" style={{ gap: '1rem' }}>
            <AppButton
              type="button"
              variant="secondary"
              size="md"
              onClick={onFinish}
              iconStart={<i className="fas fa-list"></i>}
            >
              Back to Mediators
            </AppButton>
            <AppButton
              type="button"
              variant="primary"
              size="md"
              onClick={onViewMediator}
              iconStart={<i className="fas fa-eye"></i>}
            >
              View Mediator
            </AppButton>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CompleteStep;
