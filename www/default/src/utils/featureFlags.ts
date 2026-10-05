/**
 * Frontend-only feature flags for temporarily hiding UI surfaces.
 *
 * Driven by Create React App env vars (must be prefixed `REACT_APP_`).
 * Defaults are `false`. Set the env var to `"true"` (case-insensitive) to
 * re-enable the corresponding flow. These are compile-time constants
 * intentionally — they are not driven from backend settings (see
 * `Settings.feature_flags` for server-driven flags).
 */

const isTrue = (value: string | undefined): boolean => value?.toLowerCase() === 'true';

/** Controls the MPP Paywall section in the surface Policies tab. */
export const ENABLE_MPP_PAYWALL = isTrue(process.env.REACT_APP_ENABLE_MPP_PAYWALL);
