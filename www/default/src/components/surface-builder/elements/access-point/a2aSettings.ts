/**
 * Per-surface A2A settings of an A2A Access Point (`access_point.a2a`), mirrored
 * from `A2aAccessPointSettings` in `src/config/agent_surface.rs`.
 *
 * The access-point node keeps them flat as `a2a_accepted_versions` and
 * `a2a_validation`; the payload carries them as one `a2a` object.
 */

import { isA2aProxyEndpoint } from '../_shared/a2aProxyEndpoint';

export const A2A_VERSIONS = ['0.3', '1.0'] as const;
export type A2aVersion = (typeof A2A_VERSIONS)[number];

/** How much of a request the gateway validates before forwarding it. */
export type A2aValidation = 'off' | 'envelope' | 'full';

/** The dropdown options, in order of increasing strictness. */
export const A2A_VALIDATION_OPTIONS: ReadonlyArray<{ value: A2aValidation; label: string }> = [
  { value: 'off', label: 'Off' },
  { value: 'envelope', label: 'JSON-RPC envelope' },
  { value: 'full', label: 'Envelope + A2A fields' },
];

export interface A2aAccessPointSettings {
  accepted_versions: string[];
  validation: A2aValidation;
}

/** Defaults for an A2A surface: both versions, envelope validation. */
export const DEFAULT_A2A_SETTINGS: A2aAccessPointSettings = {
  accepted_versions: [...A2A_VERSIONS],
  validation: 'envelope',
};

/**
 * The fixed settings of an A2A proxy Target: A2A 1.0 only, with the envelope
 * checked but not the request shape, so the proxy keeps serving its callers'
 * lenient requests.
 */
export const A2A_PROXY_SETTINGS: A2aAccessPointSettings = {
  accepted_versions: ['1.0'],
  validation: 'envelope',
};

export const isA2aValidation = (value: unknown): value is A2aValidation =>
  A2A_VALIDATION_OPTIONS.some(option => option.value === value);

/** The node's selected versions in A2A_VERSIONS order, or the defaults when unset. */
export const selectedA2aVersions = (config: Record<string, unknown> | undefined): string[] => {
  const raw = config?.a2a_accepted_versions;
  if (!Array.isArray(raw)) return [...DEFAULT_A2A_SETTINGS.accepted_versions];
  return A2A_VERSIONS.filter(version => raw.includes(version));
};

/** The node's validation level, or the default when unset. */
export const selectedA2aValidation = (
  config: Record<string, unknown> | undefined
): A2aValidation => {
  const raw = config?.a2a_validation;
  return isA2aValidation(raw) ? raw : DEFAULT_A2A_SETTINGS.validation;
};

/**
 * The settings the payload carries for an access-point node and its Target
 * endpoint, or `undefined` for an A2A proxy Target. The proxy's fixed values are
 * enforced by the gateway and only shown in the panel; leaving the block out
 * keeps the surface's own settings, which still configure any variant that
 * points the Target at a URL, instead of overwriting them with the proxy's.
 */
export const a2aSettingsForPayload = (
  config: Record<string, unknown> | undefined,
  targetEndpoint: unknown
): A2aAccessPointSettings | undefined =>
  isA2aProxyEndpoint(targetEndpoint)
    ? undefined
    : {
        accepted_versions: selectedA2aVersions(config),
        validation: selectedA2aValidation(config),
      };
