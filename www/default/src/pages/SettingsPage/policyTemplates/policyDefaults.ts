import type { PolicyType } from './types';

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
