/**
 * AgentSurface payload field inventory.
 *
 * Mirrored by hand from `src/config/agent_surface.rs` — the source of
 * truth lives in Rust. This module exists so the build-time payload
 * audit can assert that every element's `payloadPath` and every edge
 * slot's `payloadPathTemplate` resolves to a real persisted field.
 *
 * If a backend field is added/renamed/removed, update this file too.
 * The audit test in `__tests__/payloadAudit.test.ts` is the regression
 * gate.
 *
 * Path conventions:
 * - Dotted JSON paths rooted at the AgentSurface payload.
 * - `transit.points[*].X` matches any TP entry's field X.
 * - The frontend translation layer in `src/api.ts` rewrites
 *   `target.agent_identity` → `target.identity_injection` on submit;
 *   the UI-side path is what we list here so the builder code reads
 *   cleanly and the translation is an implementation detail.
 */

/**
 * Every persisted path the UI is allowed to write to (or the
 * translation chokepoint in `src/api.ts` rewrites to a real one).
 */
export const AGENT_SURFACE_PATHS: ReadonlySet<string> = new Set([
  // ── Top level ────────────────────────────────────────────────────
  'surface_id',
  'name',
  'description',
  'status',
  'agent_did',
  'issuer_id',
  'mcp_legacy_metadata_output',
  'mcp_http',
  'tags',
  'access_point',
  'target',
  'transit',
  'canvas',
  'outbound_credentials',

  // ── Identity slots (channel-level managed identity split) ────────
  'identity_slots.inbound',
  'identity_slots.protected',
  'identity_slots.external',

  // ── AccessPoint ──────────────────────────────────────────────────
  'access_point.listen_address',
  'access_point.route',
  'access_point.protocol',
  'access_point.caller_authentication',
  'access_point.caller_context',
  'access_point.identity_resolution',
  'access_point.inbound_policy',
  'access_point.rate_limit',
  'access_point.extension_validation',
  'access_point.trust_check_list',
  'access_point.trust_recorder',
  'access_point.publish_to_did_document',
  'access_point.terminate_trace_id',
  'access_point.supported_extensions',
  'access_point.agent_card_path',
  'access_point.response_custom_metadata',
  'access_point.didwebvh_identity',
  'access_point.header_metadata_mapping',

  // ── Target ───────────────────────────────────────────────────────
  'target.endpoint',
  'target.auth',
  'target.policy',
  'target.response_policy',
  'target.payment_policy',
  'target.mcp_tool_policies',
  'target.mcp_tool_policies_enabled',
  'target.mcp_tool_gating',
  'target.networking',
  'target.identity_injection',
  'target.trust_check_list',
  'target.workload_binding',
  'target.extension_rules',
  'target.custom_metadata',
  'target.response_custom_metadata',
  'target.mcp_proxy_id',
  'target.a2a_proxy_id',
  'target.mcp_identity_config',
  'target.fabric_target_name',
  'target.mpp_auto_pay',
  'target.mpp_auto_pay_max_amount',

  // ── Transit (SharedTransitConfig is flattened into transit.*) ────
  'transit.points',
  'transit.outbound_listen_address',
  'transit.transit_token_mode',
  'transit.transit_policy',
  'transit.rate_limit',
  'transit.sign_requests',
  'transit.workload_binding',
  'transit.extension_rules',
  'transit.custom_metadata',
  'transit.response_extension_rules',
  'transit.opa_policy_definition_id',
  'transit.source_auth',

  // ── TransitPoint (each entry in transit.points[]) ────────────────
  'transit.points[*].id',
  'transit.points[*].name',
  'transit.points[*].alias',
  'transit.points[*].target_endpoint',
  'transit.points[*].protocol',
  'transit.points[*].mcp_http',
  'transit.points[*].header_metadata_mapping',
  'transit.points[*].target_auth',
  'transit.points[*].policy',
  'transit.points[*].response_policy',
  'transit.points[*].mcp_tool_gating',
  'transit.points[*].payment_policy',
  'transit.points[*].networking',
  'transit.points[*].rate_limit',
  'transit.points[*].identity_injection',
  'transit.points[*].managed_identity',
  'transit.points[*].workload_binding',
  'transit.points[*].transit_credentials',
  'transit.points[*].gateway_url',
  'transit.points[*].listen_address',
  'transit.points[*].listen_path',
]);

/**
 * UI-side aliases the api.ts translation layer rewrites on submit.
 * Listed here so the audit treats them as valid even though they
 * never appear on the wire.
 */
export const UI_ONLY_ALIASES: ReadonlySet<string> = new Set([
  // `target.agent_identity` → `target.identity_injection` (see
  // `toBackendSurface` in src/api.ts).
  'target.agent_identity',
]);

/**
 * Normalise a slot's `payloadPathTemplate` (which may contain
 * `{owner}` substitutions) into a schema-comparable path with
 * `[*]` for any variable slot id.
 */
export function normalisePath(template: string): string {
  return template.replace(/\[\{owner\}\]/g, '[*]').replace(/\.\{owner\}/g, '.*');
}

/**
 * True when `path` (already normalised by `normalisePath` if it had
 * `{owner}`) is either a real AgentSurface field or a known UI alias.
 */
export function isKnownAgentSurfacePath(path: string): boolean {
  if (!path) return false;
  if (AGENT_SURFACE_PATHS.has(path)) return true;
  if (UI_ONLY_ALIASES.has(path)) return true;
  return false;
}
