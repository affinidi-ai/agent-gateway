import React from 'react';
import { AppButton } from '../shared/AppButton';

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
          <i className="fas fa-check-circle me-2"></i> Process Complete
        </h6>
      </div>
      <div className="card-body">
        <div className="text-center py-4">
          <div className="mb-3">
            <i className="fas fa-check-circle hero-status-icon success"></i>
          </div>
          <h4 className="mb-3">Gateway connection is now pending</h4>
          <p className="text-muted" style={{ maxWidth: '600px', margin: '0 auto' }}>
            You have successfully completed the steps to link to the other connection via the
            Connection Point Link. The connection is now pending processing by the other Agent
            Gateway, and it has been added to your Connections page. Once the other Agent Gateway
            processes the request, the Gateway connection will be active and ready for use.
          </p>
        </div>

        <div className="d-flex justify-content-between mt-4 mx-auto" style={{ maxWidth: '600px' }}>
          <AppButton
            type="button"
            variant="secondary"
            size="md"
            onClick={onViewGateway}
            iconStart={<i className="fas fa-eye"></i>}
          >
            View Connection
          </AppButton>
          <AppButton
            type="button"
            variant="primary"
            size="md"
            onClick={onFinish}
            iconStart={<i className="fas fa-check"></i>}
          >
            Back to Connections
          </AppButton>
        </div>
      </div>
    </div>
  );
};

export default CompleteStep;
