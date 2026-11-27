import React from 'react';
import { AppButton } from './AppButton';

interface ResumeUnavailableCardProps {
  message: string;
  onBack: () => void;
}

/**
 * Shown instead of a wizard step when `?resume=` cannot continue a paused pairing: the
 * record is gone or already continued, or its invitation has expired.
 */
const ResumeUnavailableCard: React.FC<ResumeUnavailableCardProps> = ({ message, onBack }) => (
  <div className="card shadow" data-testid="wizard-resume-unavailable">
    <div className="card-header py-3">
      <h6 className="m-0 font-weight-bold text-primary">
        <i className="fas fa-exclamation-circle me-2" aria-hidden="true"></i>
        This Pairing Can&apos;t Continue
      </h6>
    </div>
    <div className="card-body">
      <p className="mb-0" data-testid="wizard-resume-unavailable-message">
        {message}
      </p>
      <div className="d-flex justify-content-end mt-4">
        <AppButton
          type="button"
          variant="primary"
          size="md"
          onClick={onBack}
          iconStart={<i className="fas fa-arrow-left" aria-hidden="true"></i>}
          data-testid="wizard-resume-back-button"
        >
          Back to Connections
        </AppButton>
      </div>
    </div>
  </div>
);

export default ResumeUnavailableCard;
