import React from 'react';
import { topAndTail } from '../../utils/stringUtils';
import { AppButton } from '../shared/AppButton';
import { CopyButton } from '../shared/CopyButton';

interface CompleteStepProps {
  gateway: any;
  onFinish: () => void;
  onViewGateway: () => void;
}

const CompleteStep: React.FC<CompleteStepProps> = ({ gateway, onFinish, onViewGateway }) => {
  return (
    <div className="card shadow">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-check-circle me-2"></i> Gateway Connection Approved!
        </h6>
      </div>
      <div className="card-body">
        <div className="text-center py-4">
          <div className="mb-3">
            <i className="fas fa-check-circle hero-status-icon success"></i>
          </div>
          <h4 className="mt-3">Connection Successfully Established</h4>
          <p className="text-muted">The gateway connection has been approved and is now active.</p>
        </div>

        {gateway && (
          <div className="card bg-light mx-auto" style={{ maxWidth: '600px' }}>
            <div className="card-body">
              <h6 className="text-primary mb-3">Gateway Information</h6>
              <dl className="row mb-0" style={{ fontSize: '0.875rem' }}>
                <dt className="col-sm-3">Name:</dt>
                <dd className="col-sm-9">{gateway.name}</dd>

                <dt className="col-sm-3">Description:</dt>
                <dd className="col-sm-9">
                  {gateway.description || (
                    <span className="text-muted">No description provided</span>
                  )}
                </dd>

                <dt className="col-sm-3">Status:</dt>
                <dd className="col-sm-9">
                  <span className="badge text-bg-success">ACTIVE</span>
                </dd>

                {gateway.did && (
                  <>
                    <dt className="col-sm-3">Gateway DID:</dt>
                    <dd className="col-sm-9">
                      <code style={{ fontSize: '0.75rem' }}>{topAndTail(gateway.did, 16, 16)}</code>
                      <CopyButton text={gateway.did} />
                    </dd>
                  </>
                )}
              </dl>
            </div>
          </div>
        )}

        <div className="alert alert-info mt-3 mx-auto" style={{ maxWidth: '600px' }}>
          <i className="fas fa-info-circle me-2"></i>
          The remote Agent Gateway can now communicate with your Agent Gateway. You can manage this
          connection from the Connections page.
        </div>

        <div className="d-flex justify-content-between mt-4 mx-auto" style={{ maxWidth: '600px' }}>
          <AppButton
            type="button"
            variant="secondary"
            size="md"
            onClick={onFinish}
            iconStart={<i className="fas fa-arrow-left"></i>}
          >
            Back to Connections
          </AppButton>
          <AppButton
            type="button"
            variant="primary"
            size="md"
            onClick={onViewGateway}
            iconStart={<i className="fas fa-eye"></i>}
          >
            View Connection
          </AppButton>
        </div>
      </div>
    </div>
  );
};

export default CompleteStep;
