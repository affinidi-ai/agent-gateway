import React from 'react';
import type { PolicyDecision } from './types';

/**
 * A policy's or template's default decision: a quiet grey outline with a shield for DENY, and
 * amber with a warning icon for ALLOW, since allowing by default is the less safe choice.
 */
export const DecisionBadge: React.FC<{ decision: PolicyDecision }> = ({ decision }) => (
  <span
    className={`policy-default-decision policy-default-decision--${decision}`}
    title={
      decision === 'allow'
        ? 'Allows requests that no allow rule decides'
        : 'Denies requests that no rule allows'
    }
  >
    <i
      className={`fas ${decision === 'allow' ? 'fa-exclamation-triangle' : 'fa-shield-alt'}`}
      aria-hidden="true"
    />
    Default {decision.toUpperCase()}
  </span>
);

/** Marks a template Add rules lists, whose rules can be added to a policy, as a neutral outline. */
export const AddsRulesBadge: React.FC = () => (
  <span
    className="badge policy-rules__kind policy-template-role"
    title="Its rules can be added to a policy"
    data-testid="policy-template-role-badge"
  >
    <i className="fas fa-list-check" aria-hidden="true" />
    Adds rules
  </span>
);
