import type { FeatureFlags } from '../types';

/**
 * Whether the gateway accepts A2A 0.3 callers. The `a2a_legacy_compatibility`
 * flag is on unless it is explicitly `false`; an unset flag counts as on, the
 * same rule the gateway applies (`legacy_compatibility_from_flags`).
 */
export const isA2aLegacyCompatibilityOn = (flags?: FeatureFlags | null): boolean =>
  flags?.a2a_legacy_compatibility !== false;
