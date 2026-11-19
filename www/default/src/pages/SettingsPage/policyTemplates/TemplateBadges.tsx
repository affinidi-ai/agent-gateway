import React from 'react';
import { Badge } from '../../../components/shared/Badge';
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

/** Recommended on a suggested built-in, and This tab only on an organisation template. */
export const TemplateOriginBadges: React.FC<{ template: PolicyTemplate }> = ({ template }) => (
  <>
    {template.builtin && template.recommended && (
      <Badge tone="primary" value="Recommended" data-testid="policy-template-recommended-badge" />
    )}
    {!template.builtin && (
      <Badge
        tone="info"
        value="This tab only"
        title="Kept in this browser tab until it closes"
        data-testid="policy-template-tab-only-badge"
      />
    )}
  </>
);
