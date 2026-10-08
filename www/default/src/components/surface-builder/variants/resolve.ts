/**
 * JS-side mirror of the backend `AgentSurface::resolve_variant` and the
 * inverse `computeOverridesFromPayload`. Lets the surface builder treat
 * each variant as a full-canvas snapshot at edit time without depending
 * on the backend for round-trip resolution.
 *
 * Mirrors `src/config/agent_surface_variants.rs`:
 *   - `AccessPointOverrides` / `TargetOverrides` — same field names as
 *     `AccessPoint` / `Target` but Option-wrapped at one level deep.
 *     Resolution is field-wise merge with `Some(v)` winning over base.
 *   - `TransitOverrides` — `disabled` removes transit entirely,
 *     `points` replaces the whole catalog, `shared` is a sub-struct of
 *     option-wrapped shared-config fields merged like above.
 *
 * Vec / map / object fields nested INSIDE the overrides are replaced
 * wholesale (never element-wise merged) per the spec.
 *
 * The base surface's `listen_address`, `route`, `protocol`, and
 * `outbound_listen_address` are surface-level identifiers and never
 * overridable per variant — they are dropped from any payload-derived
 * overrides.
 */

const ACCESS_POINT_FIELDS = [
  'caller_authentication',
  'caller_context',
  'identity_resolution',
  'inbound_policy',
  'rate_limit',
  'extension_validation',
  'trust_check_list',
  'trust_recorder',
  'publish_to_did_document',
  'terminate_trace_id',
  'supported_extensions',
  'primary_extension',
  'agent_card_path',
  'response_custom_metadata',
  'didwebvh_identity',
] as const;

const TARGET_FIELDS = [
  'endpoint',
  'auth',
  'policy',
  'response_policy',
  'payment_policy',
  'mcp_tool_policies',
  'mcp_tool_policies_enabled',
  'networking',
  'identity_injection',
  'trust_check_list',
  'extension_rules',
  'custom_metadata',
  'response_custom_metadata',
  'mcp_proxy_id',
  'a2a_proxy_id',
  'mcp_identity_config',
  'fabric_target_name',
  'mpp_auto_pay',
  'mpp_auto_pay_max_amount',
] as const;

const SHARED_TRANSIT_FIELDS = [
  'transit_token_mode',
  'transit_policy',
  'rate_limit',
  'sign_requests',
  'workload_binding',
  'extension_rules',
  'custom_metadata',
  'response_extension_rules',
  'opa_policy_definition_id',
  'source_auth',
] as const;

/**
 * Surface-level access point fields. The URL identifiers identify the
 * listener and route, and `a2a` (accepted A2A versions and message
 * validation) is surface-level on the backend, so all of them MUST be
 * identical across the base surface and every variant — a variant can never
 * carry a different URL or A2A settings. They are never emitted as
 * per-variant overrides: `computeOverridesFromPayload` omits them and
 * `resolveVariant` always sources them from base.
 */
export const ACCESS_POINT_IDENTIFIER_FIELDS = [
  'listen_address',
  'route',
  'protocol',
  'name',
  'a2a',
] as const;

/**
 * Access point identifier fields as they appear on the access-point node
 * *inside the canvas blob* (`canvas.nodes[access-point].config`). Superset
 * of {@link ACCESS_POINT_IDENTIFIER_FIELDS}: the canvas node additionally
 * carries the UI-only route-composition fields (`route_prefix` /
 * `route_suffix`) that never reach the wire `access_point` slice. These are
 * surface-level too — the per-variant canvas blob must not freeze a stale
 * copy — so they are synced alongside the wire identifiers.
 */
export const ACCESS_POINT_CANVAS_IDENTIFIER_FIELDS = [
  ...ACCESS_POINT_IDENTIFIER_FIELDS,
  'route_prefix',
  'route_suffix',
  'a2a_accepted_versions',
  'a2a_validate_messages',
] as const;

export interface SurfaceOverrides {
  /**
   * Wholesale-replace flag (frozen-snapshot mode).
   *
   * - `true` — the override carries a full snapshot of the variant's
   *   overridable fields. Resolving replaces every overridable field on
   *   base with the value from `overrides`; fields absent from
   *   `overrides` are cleared. Surface-level identifier fields
   *   (`access_point.listen_address`, `.route`, `.protocol`,
   *   `transit.outbound_listen_address`) are preserved from base — they
   *   cannot vary per variant. This is the model new variants use:
   *   copy-on-create + frozen thereafter, so later base edits do NOT
   *   leak into existing variants.
   * - `false` / absent — legacy sparse delta. `Some(v)` wins over base,
   *   absent fields inherit from base. Kept for back-compat with
   *   variants written before the snapshot model.
   */
  complete?: boolean;
  access_point?: Record<string, unknown>;
  target?: Record<string, unknown>;
  transit?: {
    disabled?: boolean;
    points?: unknown[];
    shared?: Record<string, unknown>;
  };
  /**
   * Wholesale replacement of the surface's `identity_slots` bundle
   * (inbound / protected / external). Mirrors
   * `SurfaceOverrides.identity_slots: Option<ChannelIdentitySlots>` in
   * `agent_surface_variants.rs` — `Some(_)` replaces the whole bundle,
   * `None` inherits base.
   */
  identity_slots?: Record<string, unknown>;
  /**
   * Wholesale replacement of the surface's `outbound_credentials` list.
   * Mirrors `SurfaceOverrides.outbound_credentials:
   * Option<Vec<OutboundCredentialBinding>>`. `Some(_)` replaces the
   * whole list, `None` inherits base.
   */
  outbound_credentials?: unknown[];
  /**
   * Per-variant snapshot of the canvas blob (positions, viewport,
   * canvas-only NPC/human/caller nodes). Wholesale-replaces the base
   * `payload.canvas` at resolve time so each variant keeps its own
   * layout — including positions for variant-only TPs and the
   * `__managed-agent-npc__` "External Target" node attached to them.
   * Treated as opaque JSON; the runtime never reads it.
   */
  canvas?: unknown;
}

export interface VariantEntryWire {
  id: string;
  alias: string;
  name: string;
  description?: string;
  enabled?: boolean;
  overrides?: SurfaceOverrides;
}

function pickFields<T extends string>(
  src: Record<string, unknown> | null | undefined,
  fields: readonly T[]
): Record<string, unknown> | undefined {
  if (!src || typeof src !== 'object') return undefined;
  const out: Record<string, unknown> = {};
  for (const f of fields) {
    const v = (src as Record<string, unknown>)[f];
    if (v !== undefined && v !== null) out[f] = v;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

/**
 * Build a SurfaceOverrides delta from a fully-resolved payload. This is
 * the simple "full replacement" projection: every populated field of
 * `payload.access_point` / `payload.target` / `payload.transit.shared`
 * lands in the corresponding overrides slot, plus the wholesale
 * `transit.points` array. Sparse-delta computation (skip fields equal
 * to the default-variant base) is a deferred optimisation; the backend
 * resolver is happy with full replacement because `Some(v)` simply wins
 * over base.
 */
export function computeOverridesFromPayload(payload: any): SurfaceOverrides {
  const out: SurfaceOverrides = { complete: true };
  const ap = pickFields(payload?.access_point, ACCESS_POINT_FIELDS);
  if (ap) out.access_point = ap;
  const tg = pickFields(payload?.target, TARGET_FIELDS);
  if (tg) out.target = tg;
  const transit = payload?.transit;
  if (transit && typeof transit === 'object') {
    const transitOverride: NonNullable<SurfaceOverrides['transit']> = {};
    // Always emit `points` (even when empty) so a variant whose user
    // deleted every TP still overrides base's TP catalog. Without
    // this an empty array drops out of the override and the backend
    // resolver inherits base's TPs, causing deleted TPs to
    // "resurrect" on save / reload.
    transitOverride.points = Array.isArray(transit.points) ? transit.points : [];
    const shared = pickFields(transit.shared, SHARED_TRANSIT_FIELDS);
    if (shared) transitOverride.shared = shared;
    out.transit = transitOverride;
  } else {
    // The variant payload has no transit object at all (e.g. a
    // variant that explicitly removed every TP and the shared
    // transit config). Emit an empty `points` override so base's
    // TPs don't leak back in via the resolver's inherit-from-base
    // semantics.
    out.transit = { points: [] };
  }
  // Capture the per-variant canvas blob verbatim so positions for
  // variant-only nodes (e.g. a TP introduced on this variant) and any
  // canvas-only NPC nodes (e.g. the auto-spawned External Target
  // attached to that TP) survive a save/reload round-trip. Without
  // this every variant inherits base's blob and variant-only layout
  // resets to the d3 default placement on next page load.
  if (payload?.canvas != null) {
    out.canvas = payload.canvas;
  }
  // Wholesale per-variant identity_slots. The backend resolver
  // replaces the whole bundle when `Some(_)` is supplied, so emit it
  // verbatim whenever the variant payload has any slot configured.
  const slots = payload?.identity_slots;
  if (slots && typeof slots === 'object' && Object.keys(slots).length > 0) {
    out.identity_slots = slots;
  }
  if (Array.isArray(payload?.outbound_credentials)) {
    out.outbound_credentials = payload.outbound_credentials;
  }
  return out;
}

/**
 * Apply a SurfaceOverrides delta to a base payload, returning a new
 * payload object. Mirrors `SurfaceVariant::apply` in the backend.
 *
 * The base is deep-cloned so callers can mutate the result without
 * touching their input. Surface payloads are plain JSON (no Dates,
 * Maps, Sets, etc.), so a JSON round-trip clone is sufficient and
 * works in older Jest jsdom envs where `structuredClone` is absent.
 */
export function resolveVariant(base: any, overrides: SurfaceOverrides | undefined | null): any {
  const out = base == null ? {} : JSON.parse(JSON.stringify(base));
  if (!overrides) return out;
  if (overrides.complete) {
    // Frozen-snapshot mode: overrides carries a full per-variant
    // payload of every overridable field. Replace wholesale; do not
    // inherit from base. Surface-level identifier fields
    // (`listen_address`, `route`, `protocol`, `name` on access_point;
    // `outbound_listen_address` on transit) are preserved from base
    // because variants are not allowed to change them — the override
    // payload never carries them.
    const baseAp = (out.access_point ?? {}) as Record<string, unknown>;
    const apIdentifiers: Record<string, unknown> = {};
    for (const f of ACCESS_POINT_IDENTIFIER_FIELDS) {
      apIdentifiers[f] = baseAp[f];
    }
    out.access_point = { ...apIdentifiers, ...(overrides.access_point ?? {}) };
    out.target = { ...(overrides.target ?? {}) };
    if (overrides.transit) {
      if (overrides.transit.disabled === true) {
        out.transit = undefined;
      } else {
        const baseTransit = (out.transit ?? {}) as Record<string, unknown>;
        out.transit = {
          outbound_listen_address: baseTransit.outbound_listen_address,
          points: overrides.transit.points ?? [],
          shared: overrides.transit.shared ?? {},
        };
      }
    } else {
      out.transit = undefined;
    }
    out.identity_slots = overrides.identity_slots ?? {};
    out.outbound_credentials = overrides.outbound_credentials ?? [];
    if (overrides.canvas !== undefined) {
      out.canvas = overrides.canvas;
    }
    delete out.variants;
    delete out.default_variant_id;
    return out;
  }
  if (overrides.access_point) {
    out.access_point = { ...(out.access_point ?? {}), ...overrides.access_point };
  }
  if (overrides.target) {
    out.target = { ...(out.target ?? {}), ...overrides.target };
  }
  if (overrides.transit) {
    if (overrides.transit.disabled === true) {
      out.transit = undefined;
    } else {
      const baseTransit =
        out.transit && typeof out.transit === 'object' ? out.transit : { points: [], shared: {} };
      const merged = { ...baseTransit };
      if (overrides.transit.points) {
        merged.points = overrides.transit.points;
      }
      if (overrides.transit.shared) {
        merged.shared = { ...(merged.shared ?? {}), ...overrides.transit.shared };
      }
      out.transit = merged;
    }
  }
  // Wholesale-replace the canvas blob when the variant carries one.
  // The blob is opaque JSON owned by the dashboard; merging would risk
  // mixing layout state from different variants, so we always swap.
  if (overrides.canvas !== undefined) {
    out.canvas = overrides.canvas;
  }
  if (overrides.identity_slots !== undefined) {
    out.identity_slots = overrides.identity_slots;
  }
  if (overrides.outbound_credentials !== undefined) {
    out.outbound_credentials = overrides.outbound_credentials;
  }
  // Per the spec, `variants` and `default_variant_id` belong to the
  // surface, not to a resolved variant view. Strip them so each
  // resolved snapshot is self-contained and round-trips through
  // `nodesFromPayload` cleanly.
  delete out.variants;
  delete out.default_variant_id;
  return out;
}

/**
 * Project the assembled base payload into every variant that has no
 * overrides of its own, returning a new `variants` array.
 *
 * The create canvas cannot switch per-variant, so the variant element
 * emits `overrides: {}` for each variant. An empty override means
 * "inherit from base" to the backend resolver, so the variant silently
 * tracks every later base edit instead of snapshotting the config it
 * was created from. Freezing base into each empty variant gives it an
 * independent, complete override up front (the create-page analogue of
 * the detail page's snapshot-based `buildVariantsWireSlice`).
 *
 * Variants that already carry a non-empty override are left untouched.
 */
export function freezeEmptyVariantOverrides(payload: any): any[] {
  const variants = Array.isArray(payload?.variants) ? payload.variants : [];
  if (variants.length === 0) return [];
  const frozen = computeOverridesFromPayload(payload);
  return variants.map((v: any) => {
    const existing = v?.overrides;
    const hasOverrides =
      existing && typeof existing === 'object' && Object.keys(existing).length > 0;
    return hasOverrides ? v : { ...v, overrides: frozen };
  });
}
