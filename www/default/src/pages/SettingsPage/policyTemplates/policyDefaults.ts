import type { PolicyType } from './types';

/** The view the Policy section opens in. */
export const DEFAULT_POLICY_VIEW = { create: 'rules', edit: 'rules' } as const;

/** The Start from choice for the allow-all policy. */
export const BLANK_TEMPLATE_ID = 'blank';

/** The Start from choice a new policy begins with, whose Rego is `DEFAULT_POLICY`. */
export const DEFAULT_TEMPLATE_KEY = 'deny-by-default';

export const EXPECTED_PACKAGE: Record<PolicyType, string> = {
  gateway: 'gateway.policy',
  agent_surface: 'surface.policy',
};

/** A new policy: deny every request until a rule allows it. */
export const DEFAULT_POLICY: Record<PolicyType, string> = {
  gateway: 'package gateway.policy\n\ndefault allow := false\n',
  agent_surface: 'package surface.policy\n\ndefault allow := false\n',
};

/** The Allow all (blank) starting point. */
export const ALLOW_ALL_POLICY: Record<PolicyType, string> = {
  gateway: `package gateway.policy

# Allow all traffic by default
default allow = true`,
  agent_surface: `package surface.policy

# Allow all traffic by default
default allow = true`,
};
