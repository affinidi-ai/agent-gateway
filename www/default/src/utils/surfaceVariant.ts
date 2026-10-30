/**
 * The values the gateway writes in `surface_variant` itself, rather than an alias someone
 * configured. No alias can contain `_`, so they never clash with a real variant.
 */
const BASE = '_base_';
const UNKNOWN = '_unknown_';

/** The configured alias a `surface_variant` names, if it is one. */
export function surfaceVariantAlias(variant?: string | null): string | undefined {
  if (!variant || variant.startsWith('_')) return undefined;
  return variant;
}

/** A `surface_variant` in words: the alias, "Base surface" or "Unknown variant". */
export function surfaceVariantLabel(variant?: string | null): string | undefined {
  if (variant === BASE) return 'Base surface';
  if (variant === UNKNOWN) return 'Unknown variant';
  return variant || undefined;
}

/**
 * Where a request ran, as a phrase: "on variant beta", "on the base surface", or "on an unknown
 * variant" naming the alias the caller asked for.
 */
export function surfaceVariantPhrase(
  variant?: string | null,
  requested?: string | null
): string | undefined {
  if (variant === BASE) return 'on the base surface';
  if (variant === UNKNOWN) {
    return requested
      ? `on an unknown variant (“${requested}” was asked for)`
      : 'on an unknown variant';
  }
  return variant ? `on variant ${variant}` : undefined;
}

/** Whether `variant` is the base surface. */
export function isBaseSurfaceVariant(variant?: string | null): boolean {
  return variant === BASE;
}
