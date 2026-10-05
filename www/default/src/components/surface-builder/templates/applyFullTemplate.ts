/**
 * Apply a `kind: 'full'` surface template: substitute placeholder
 * tokens in the template's verbatim `surface` snapshot and hand back
 * a ready-to-load AgentSurface payload.
 *
 * This is intentionally a thin shim around {@link applyPlaceholders}:
 * the snapshot is opaque (the Rust side stores it as `serde_json::Value`)
 * and the dashboard treats it as the same payload `onApplyJsonPayload`
 * accepts — so the apply flow is just "substitute tokens, hand off to
 * the existing JSON-payload hook the Config tab uses".
 */

import {
  applyPlaceholders,
  clearUnresolvedTokens,
  findPlaceholders,
  type PlaceholderContext,
  type PlaceholderToken,
} from './placeholders';
import {
  buildDefaultAccessPointConfig,
  type RoutingConfig,
} from '../elements/access-point/defaults';
import { scrubVolatileTemplateFields } from './scrubVolatile';
import type { SurfaceTemplate } from './types';

export interface FullTemplatePreview {
  /** Token list found in the raw template (pre-substitution). */
  tokens: PlaceholderToken[];
}

export interface FullTemplateApplyResult {
  /** Substituted surface payload ready to hand to `onApplyJsonPayload`. */
  surface: any;
  /** Tokens that appeared in the snapshot but had no value in `ctx`. */
  missing: PlaceholderToken[];
}

/**
 * Build a placeholder context from the gateway's routing config so
 * full templates can be applied without prompting the user: `$HOST`
 * and `$ROUTE` get the same defaults the AddSurface wizard uses
 * (first available listen address + first channel prefix + random
 * suffix). `$NAME` / `$TARGET_ENDPOINT` / `$SLUG` are left unset on
 * purpose — the form validator will surface them as missing required
 * fields, which is gentler than a modal.
 */
export function buildAutoPlaceholderContext(routing: RoutingConfig): PlaceholderContext {
  const ap = buildDefaultAccessPointConfig(routing);
  return {
    host: ap.listen_address || undefined,
    route: ap.route || undefined,
  };
}

/**
 * Inspect a full template without substituting anything. Useful for
 * the confirm modal to prompt the user for placeholder values up
 * front. Throws if called on a non-full template or one with no
 * `surface` blob — those are bugs in the caller, not user errors.
 */
export function previewFullTemplate(template: SurfaceTemplate): FullTemplatePreview {
  if (template.kind !== 'full') {
    throw new Error(`previewFullTemplate called with kind='${template.kind ?? 'partial'}'`);
  }
  if (!template.surface) {
    throw new Error(`full template '${template.id}' has no surface snapshot`);
  }
  return { tokens: findPlaceholders(template.surface) };
}

/**
 * Substitute placeholders in the template's surface snapshot using
 * `ctx`. Unresolved tokens remain as literals in the output and are
 * listed in `missing` so the caller can keep the user in the modal
 * until everything's bound. Never mutates the input.
 */
export function applyFullSurfaceTemplate(
  template: SurfaceTemplate,
  ctx: PlaceholderContext
): FullTemplateApplyResult {
  if (template.kind !== 'full') {
    throw new Error(`applyFullSurfaceTemplate called with kind='${template.kind ?? 'partial'}'`);
  }
  if (!template.surface) {
    throw new Error(`full template '${template.id}' has no surface snapshot`);
  }
  const { value, missing } = applyPlaceholders(template.surface, ctx);
  return { surface: value, missing };
}

/**
 * Auto-apply a full template: substitute every token we can derive
 * from `routing`, then blank out the rest so downstream validators
 * report them as missing required fields. This is the no-modal path
 * used by the Templates sidebar.
 */
export function autoApplyFullSurfaceTemplate(
  template: SurfaceTemplate,
  routing: RoutingConfig | null
): FullTemplateApplyResult {
  const ctx = routing ? buildAutoPlaceholderContext(routing) : {};
  const { surface, missing } = applyFullSurfaceTemplate(template, ctx);
  const cleared = clearUnresolvedTokens(surface) as Record<string, unknown>;
  // A full template must never set the surface's display name — the
  // user owns that field and is prompted for it just like a new
  // surface. Strip it from the payload so the apply helpers leave
  // any existing `meta.name` untouched.
  if (cleared && typeof cleared === 'object' && 'name' in cleared) {
    delete cleared.name;
  }
  // Defence-in-depth: blank per-surface volatile listener / TP
  // identity fields. Transit-point routes are not part of the token
  // vocabulary, so without this scrub two surfaces created from the
  // same starter would land on identical TP `(listen_address,
  // listen_path)` tuples and the second would fail to register.
  const scrubbed = scrubVolatileTemplateFields(cleared) as Record<string, unknown>;
  return { surface: scrubbed, missing };
}
