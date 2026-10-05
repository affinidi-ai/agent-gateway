import React from 'react';
import { timeAgo } from '../../utils/stringUtils';
import type { JourneyStep } from './journey';

interface AuditJourneyProps {
  steps: JourneyStep[];
}

/** Vertical pipeline timeline of a request's correlated events, in request order. */
const AuditJourney: React.FC<AuditJourneyProps> = ({ steps }) => {
  if (steps.length === 0) {
    return <p className="small text-muted mb-0">No pipeline events recorded for this request.</p>;
  }
  return (
    <ol className="audit-journey" data-testid="audit-journey">
      {steps.map(step => (
        <li key={step.key} className={`audit-journey-step audit-journey-step--${step.tone}`}>
          <span className="audit-journey-rail" aria-hidden="true">
            <span className="audit-journey-dot" />
          </span>
          <span className="audit-journey-body">
            <span className="audit-journey-title">{step.title}</span>
            {step.detail && <span className="audit-journey-detail">{step.detail}</span>}
            <span className="audit-journey-time">{timeAgo(step.timestamp)}</span>
          </span>
        </li>
      ))}
    </ol>
  );
};

export default AuditJourney;
