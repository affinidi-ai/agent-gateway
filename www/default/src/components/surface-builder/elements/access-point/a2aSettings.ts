/**
 * Per-surface A2A settings of an A2A Access Point (`access_point.a2a`), mirrored
 * from `A2aAccessPointSettings` in `src/config/agent_surface.rs`.
 *
 * The access-point node keeps them flat as `a2a_accepted_versions` and
 * `a2a_validation`; the payload carries them as one `a2a` object. A surface
 * stored with an A2A proxy base Target also gets `a2a_locked_versions`, the
 * versions the gateway keeps fixed for it.
 */

import { isA2aProxyEndpoint } from '../_shared/a2aProxyEndpoint';
import type { BaseSurfaceView } from '../types';

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
 * The settings of a new surface with an A2A proxy Target, or one whose Target
 * moves to an A2A proxy: A2A 1.0 only, with the envelope checked. The gateway
 * keeps an A2A proxy surface's versions fixed.
 */
export const A2A_PROXY_SETTINGS: A2aAccessPointSettings = {
  accepted_versions: ['1.0'],
  validation: 'envelope',
};

export const isA2aValidation = (value: unknown): value is A2aValidation =>
  A2A_VALIDATION_OPTIONS.some(option => option.value === value);

/** Why an A2A proxy surface that accepts 0.3 does, shown wherever its versions are. */
export const A2A_PROXY_0_3_REASON =
  'This surface was created as an A2A 0.3 proxy, so it keeps accepting 0.3 for its existing callers. New surfaces with an A2A proxy accept A2A 1.0 only.';

/** The node's selected versions in A2A_VERSIONS order, or the defaults when unset. */
export const selectedA2aVersions = (config: Record<string, unknown> | undefined): string[] => {
  const raw = config?.a2a_accepted_versions;
  if (!Array.isArray(raw)) return [...DEFAULT_A2A_SETTINGS.accepted_versions];
  return A2A_VERSIONS.filter(version => raw.includes(version));
};

/**
 * The fixed versions of an A2A proxy Target: those of a surface stored with an
 * A2A proxy Target, and A2A 1.0 only for a new surface or one whose Target moves
 * to an A2A proxy.
 */
export const a2aProxyVersions = (config: Record<string, unknown> | undefined): string[] => {
  const raw = config?.a2a_locked_versions;
  if (!Array.isArray(raw)) return [...A2A_PROXY_SETTINGS.accepted_versions];
  return A2A_VERSIONS.filter(version => raw.includes(version));
};

/**
 * The versions the gateway serves for a stored version list, as
 * `accepted_set` in `src/a2a/version.rs` does: the supported versions it
 * names, or both when it names neither.
 */
export const servedA2aVersions = (stored: unknown): string[] => {
  const named = Array.isArray(stored)
    ? A2A_VERSIONS.filter(version => stored.includes(version))
    : [];
  return named.length > 0 ? named : [...A2A_VERSIONS];
};

/**
 * The fixed versions a stored surface payload shows for an A2A proxy Target:
 * those its stored block is served with, or both when it has no block.
 * `undefined` when the Target is not an A2A proxy, or the block names no
 * versions (a dashboard payload, whose canvas blob carries them).
 */
export const storedA2aProxyVersions = (payload: any): string[] | undefined => {
  if (!isA2aProxyEndpoint(payload?.target?.endpoint)) return undefined;
  const a2a = payload?.access_point?.a2a;
  if (a2a && !Array.isArray(a2a.accepted_versions)) return undefined;
  return servedA2aVersions(a2a?.accepted_versions);
};

/** The node's validation level, or the default when unset. */
export const selectedA2aValidation = (
  config: Record<string, unknown> | undefined
): A2aValidation => {
  const raw = config?.a2a_validation;
  return isA2aValidation(raw) ? raw : DEFAULT_A2A_SETTINGS.validation;
};

/** The base Target's endpoint: the base surface's when given, else the Target in view. */
export const baseTargetEndpoint = (
  base: BaseSurfaceView | undefined,
  targetInView: unknown
): unknown => (base ? base.targetEndpoint : targetInView);

/** How the gateway serves the A2A settings to the Target in view. */
export interface A2aTargetView {
  /** The base Target is an A2A proxy, so the gateway fixes the surface's versions. */
  versionsFixed: boolean;
  /** The Target in view is an A2A proxy, so it checks only the JSON-RPC envelope. */
  envelopeOnly: boolean;
  /** The versions every Target of the surface accepts. */
  versions: string[];
}

/**
 * The A2A settings of the Target in view. The versions belong to the surface
 * and follow the base Target, as the gateway decides them; the validation
 * level applies only to a Target that is a URL.
 */
export const a2aTargetView = (
  config: Record<string, unknown> | undefined,
  targetInView: unknown,
  base?: BaseSurfaceView
): A2aTargetView => {
  const versionsFixed = isA2aProxyEndpoint(baseTargetEndpoint(base, targetInView));
  return {
    versionsFixed,
    envelopeOnly: isA2aProxyEndpoint(targetInView),
    versions: versionsFixed
      ? a2aProxyVersions(base?.accessPointConfig ?? config)
      : selectedA2aVersions(config),
  };
};

/**
 * The `access_point.a2a` block for an access-point node and the base Target
 * endpoint. With an A2A proxy base Target the block leaves the versions out,
 * so the gateway keeps its fixed ones, and carries only the validation level,
 * which still applies to any variant that points the Target at a URL.
 */
export const a2aSettingsForPayload = (
  config: Record<string, unknown> | undefined,
  baseEndpoint: unknown
): Partial<A2aAccessPointSettings> =>
  isA2aProxyEndpoint(baseEndpoint)
    ? { validation: selectedA2aValidation(config) }
    : {
        accepted_versions: selectedA2aVersions(config),
        validation: selectedA2aValidation(config),
      };

interface A2aWirePayload {
  access_point?: { a2a?: Partial<A2aAccessPointSettings> } & Record<string, unknown>;
  target?: { endpoint?: unknown };
  variants?: Array<{
    overrides?: { complete?: boolean; target?: { endpoint?: unknown } };
  }>;
}

const variantTargetEndpoint = (
  payload: A2aWirePayload,
  overrides: NonNullable<A2aWirePayload['variants']>[number]['overrides']
): unknown => {
  if (overrides?.target?.endpoint != null) return overrides.target.endpoint;
  return payload.target?.endpoint;
};

/**
 * The assembled wire payload, with its validation level set to the JSON-RPC
 * envelope when it applies to no Target: the base Target is an A2A proxy and
 * so is every variant's. The gateway refuses another level there.
 */
export function withA2aValidationSettled<T extends A2aWirePayload>(payload: T): T {
  const a2a = payload.access_point?.a2a;
  if (!a2a || a2a.validation === 'envelope') return payload;
  if (!isA2aProxyEndpoint(payload.target?.endpoint)) return payload;
  const urlVariant = (payload.variants ?? []).some(
    variant => !isA2aProxyEndpoint(variantTargetEndpoint(payload, variant.overrides))
  );
  if (urlVariant) return payload;
  return {
    ...payload,
    access_point: { ...payload.access_point, a2a: { ...a2a, validation: 'envelope' } },
  };
}
