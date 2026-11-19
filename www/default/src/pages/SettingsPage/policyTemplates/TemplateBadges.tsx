import React from 'react';
import { templateRole } from './regoTemplate';
import type { PolicyDecision, PolicyTemplate } from './types';

/**
 * A policy's or template's default decision: a quiet grey outline with a shield for DENY, and
 * amber with a warning icon for ALLOW, since allowing by default is the less safe choice.
 */
export const DecisionBadge: React.FC<{ decision: PolicyDecision }> = ({ decision }) => (
  <span
    className={`policy-default-decision policy-default-decision--${decision}`}
    title={
      decision === 'allow'
        ? 'Allows requests that no rule denies'
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

/** Whether a template is the whole policy or rules Add to policy can add, as a neutral outline. */
export const TemplateRoleBadge: React.FC<{ template: PolicyTemplate }> = ({ template }) => (
  <RoleBadge role={templateRole(template)} />
);

export const RoleBadge: React.FC<{ role: 'policy' | 'rules' }> = ({ role }) => {
  const policy = role === 'policy';
  return (
    <span
      className="badge policy-rules__kind policy-template-role"
      title={
        policy
          ? 'Meant to be the whole policy; used from Start from on a new policy'
          : 'Its rules can be added to a policy'
      }
      data-testid="policy-template-role-badge"
    >
      <i className={`fas ${policy ? 'fa-file-shield' : 'fa-list-check'}`} aria-hidden="true" />
      {policy ? 'Whole policy' : 'Adds rules'}
    </span>
  );
};
