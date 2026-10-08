/**
 * Per-surface A2A settings of an A2A Access Point (`access_point.a2a`), mirrored
 * from `A2aAccessPointSettings` in `src/config/agent_surface.rs`.
 *
 * The access-point node keeps them flat as `a2a_accepted_versions` and
 * `a2a_validate_messages`; the payload carries them as one `a2a` object.
 */

export const A2A_VERSIONS = ['0.3', '1.0'] as const;
export type A2aVersion = (typeof A2A_VERSIONS)[number];

export interface A2aAccessPointSettings {
  accepted_versions: string[];
  validate_messages: boolean;
}

/** Defaults for an A2A surface: both versions, no message validation. */
export const DEFAULT_A2A_SETTINGS: A2aAccessPointSettings = {
  accepted_versions: [...A2A_VERSIONS],
  validate_messages: false,
};

/**
 * The fixed settings of an A2A proxy Target: A2A 1.0 only, without message
 * validation, so the proxy keeps serving its callers' lenient requests.
 */
export const A2A_PROXY_SETTINGS: A2aAccessPointSettings = {
  accepted_versions: ['1.0'],
  validate_messages: false,
};

export const isA2aProxyEndpoint = (endpoint: unknown): boolean =>
  typeof endpoint === 'string' && endpoint.startsWith('a2a-proxy://');

/** The node's selected versions in A2A_VERSIONS order, or the defaults when unset. */
export const selectedA2aVersions = (config: Record<string, unknown> | undefined): string[] => {
  const raw = config?.a2a_accepted_versions;
  if (!Array.isArray(raw)) return [...DEFAULT_A2A_SETTINGS.accepted_versions];
  return A2A_VERSIONS.filter(version => raw.includes(version));
};

/** The settings the payload carries for an access-point node and its Target endpoint. */
export const a2aSettingsForPayload = (
  config: Record<string, unknown> | undefined,
  targetEndpoint: unknown
): A2aAccessPointSettings =>
  isA2aProxyEndpoint(targetEndpoint)
    ? { ...A2A_PROXY_SETTINGS, accepted_versions: [...A2A_PROXY_SETTINGS.accepted_versions] }
    : {
        accepted_versions: selectedA2aVersions(config),
        validate_messages: config?.a2a_validate_messages === true,
      };
