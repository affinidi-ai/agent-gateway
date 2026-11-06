import React from 'react';

export interface WizardProgressStep {
  key: string;
  label: string;
}

interface WizardProgressProps {
  steps: ReadonlyArray<WizardProgressStep>;
  currentIndex: number;
}

/** The numbered step bar at the top of a wizard page. */
const WizardProgress: React.FC<WizardProgressProps> = ({ steps, currentIndex }) => (
  <div className="card shadow mb-4">
    <div className="card-body">
      <div className="wizard-progress" data-testid="wizard-progress">
        <div className="wizard-steps">
          {steps.map((step, index) => (
            <div
              key={step.key}
              className={`wizard-step ${
                index === currentIndex ? 'active' : index < currentIndex ? 'completed' : ''
              }`}
              data-testid={`wizard-progress-step-${step.key}`}
              aria-current={index === currentIndex ? 'step' : undefined}
            >
              <div className="wizard-step-circle">
                {index < currentIndex ? (
                  <i className="fas fa-check" aria-hidden="true"></i>
                ) : (
                  <span>{index + 1}</span>
                )}
              </div>
              <div className="wizard-step-label">{step.label}</div>
              {index < steps.length - 1 && <div className="wizard-step-line"></div>}
            </div>
          ))}
        </div>
      </div>
    </div>
  </div>
);

export default WizardProgress;
