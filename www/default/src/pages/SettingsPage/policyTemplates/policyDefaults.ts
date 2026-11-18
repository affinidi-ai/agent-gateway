import type { PolicyType } from './types';

/** The view the Policy section opens in: the Rego for a blank new policy, else the rules. */
export const DEFAULT_POLICY_VIEW = { create: 'rego', edit: 'rules' } as const;

/** The Start from choice for the default policy. */
export const BLANK_TEMPLATE_ID = 'blank';

export const EXPECTED_PACKAGE: Record<PolicyType, string> = {
  gateway: 'gateway.policy',
  agent_surface: 'surface.policy',
};

export const DEFAULT_POLICY: Record<PolicyType, string> = {
  gateway: `package gateway.policy

# Allow all traffic by default
default allow = true`,
  agent_surface: `package surface.policy

# Allow all traffic by default
default allow = true`,
};
