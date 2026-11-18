import React from 'react';
import type { PolicyDecision } from './types';

interface DecisionBadgeProps {
  decision: PolicyDecision;
  /** Shown before the decision, e.g. "Default". */
  prefix?: string;
}

/** A template's default decision as the Audit Log's decision pill: DENY or ALLOW. */
export const DecisionBadge: React.FC<DecisionBadgeProps> = ({ decision, prefix }) => (
  <span
    className={`audit-decision audit-decision--${decision}`}
    title={
      decision === 'allow'
        ? 'Allows requests that no rule denies'
        : 'Denies requests that no rule allows'
    }
  >
    {prefix ? `${prefix} ` : ''}
    {decision.toUpperCase()}
  </span>
);
