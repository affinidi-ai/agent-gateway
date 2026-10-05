import type { PredefinedTrustCheckQuery } from '../../../../types';
import { findSlotById } from '../edges/archetypes';
import * as Cap from '../capabilities';
import type { NodeDefinition, PayloadSlice } from '../types';
import TrustCheckPanel from './TrustCheckPanel';
import TrustCheckFullscreenPanel from './TrustCheckFullscreenPanel';
import { DOCS_URL } from '../../../../config/docs';

export type { PredefinedQueryOrigin, PredefinedTrustCheckQuery } from '../../../../types';

export type TrustCheckRecordType = 'authorization' | 'recognition';

/**
 * The `{{ input.agent.provider_did }}` template — the caller's **provider**
 * DID (e.g. the department / issuing org) resolved at runtime from the
 * caller's `https://fabric.affinidi.io/extensions/trust-registry`
 * extension.
 *
 * This is **no longer** the caller-leg Authority default: both legs now
 * require the operator to pick an explicit Issuer / Authority literal DID
 * from the gateway's own registers (see `classifyTargetAuthoritySelection`),
 * because deriving the authority from a payload / agent-card trust-registry
 * extension trips the runtime `TRUST_REGISTRY_METADATA_UNAVAILABLE` gate
 * whenever that extension is absent. The constant survives only as the
 * template for the Entity ID picker's `provider` subject (a JSON-API /
 * power-user option), mapped via `templateForSubject` / `subjectForTemplate`.
 */
export const AUTHORITY_ID_TEMPLATE = '{{ input.agent.provider_did }}';

/**
 * Other OPA `PolicyInput` template tokens used across the Trust Check UI.
 * Kept as named constants so the panel copy, the Advanced Entity ID help,
 * and the fullscreen editor banners all reference one canonical string —
 * avoiding subtle whitespace typos (`{{input.agent.did}}` vs
 * `{{ input.agent.did }}`) that would silently fail at runtime as
 * `TEMPLATE_RESOLUTION_FAILED`.
 */
export const AGENT_DID_TEMPLATE = '{{ input.agent.did }}';
export const AGENT_AUTHORITY_DID_TEMPLATE = '{{ input.agent.authority_did }}';
export const EXTENSION_IDENTITY_DID_TEMPLATE = '{{ input.extension_identity.did }}';
export const AGENT_IDENTITY_ISSUER_DID_TEMPLATE = '{{ input.agent.identity_issuer_did }}';
/**
 * The `{{ input.gateway.source_id }}` template resolves at runtime to
 * the DID of the **sending gateway** on the fabric-inbound receive path
 * (populated by `process_forward_request` on GW2). On direct inbound
 * (non-fabric) the value is `null` and the template resolves empty — the
 * Trust Check probe then denies fail-safe. Only meaningful on the caller
 * leg (`ap-ma`) of surfaces that are reachable via `fabric://`.
 */
export const INPUT_GATEWAY_SOURCE_ID_TEMPLATE = '{{ input.gateway.source_id }}';

/**
 * Auto-injected `entity_id` template. Both legs default to the single
 * semantic token `{{ input.agent.did }}` — the *effective* caller DID.
 *
 * The backend normalises `input.agent.did` at every OPA seam (including
 * the Trust Check stage) via `PolicyInput::normalize_caller_did`: when
 * the inbound payload carries the `https://fabric.affinidi.io/extensions/trust-registry`
 * extension, `input.agent.did` is the asserted agent DID; when the
 * payload omits that extension, the gateway-derived managed identity
 * (`input.extension_identity.did`) is promoted into `input.agent.did`
 * so this template resolves identically across both scenarios. Operators
 * therefore never need to author a fallback chain for the common case.
 *
 * Power users can still override the default with any template: the
 * resolver supports a generic `||` fallback operator (e.g.
 * `{{ input.agent.did || input.extension_identity.did }}`) which tries
 * each branch in order and uses the first scalar that resolves — useful
 * for templating other fields where the fallback is not auto-applied.
 */
export function defaultEntityIdTemplate(_edge: 'ap-ma' | 'ma-tp'): string {
  return AGENT_DID_TEMPLATE;
}

/**
 * Auto-injected `authority_id` template. The **caller leg** defaults to
 * the verified agent-identity-credential issuer
 * (`{{ input.agent.identity_issuer_did }}`) — a crypto-verified trust
 * anchor that never trips the runtime trust-registry metadata gate. The
 * **target leg** has no such verified value (a target must not assert
 * who vouches for it), so it stays blank and the operator must pick an
 * explicit Issuer / Authority literal DID.
 */
export function defaultAuthorityIdTemplate(edge: 'ap-ma' | 'ma-tp'): string {
  return edge === 'ma-tp' ? '' : AGENT_IDENTITY_ISSUER_DID_TEMPLATE;
}

/**
 * Classifier for the Authority picker's stored value (both legs).
 *
 * Neither leg derives its authority from an agent card / trust-registry
 * metadata anymore — on the target leg that would let the called party
 * assert who vouches for it; on the caller leg the `{{ input.agent.provider_did }}`
 * template depends on the caller's trust-registry extension, which is
 * absent when the payload carries only an identity credential. Instead
 * the operator picks an explicit trust anchor from the gateway's own
 * registers: an **Issuer** (a configured Department, `/v1/departments`)
 * or an **Authority** (a record from the Authorities register,
 * `/v1/authorities`). The chosen literal DID is written verbatim into
 * `query.authority_id`, so the runtime never has to resolve a
 * `{{ input.agent.provider_did }}` template — which is exactly the
 * metadata-gate failure this replaces.
 *
 * `unset` (empty) means the operator hasn't picked yet — an incomplete
 * query. `legacy-template` surfaces a value authored before this change
 * (or via the JSON API) that still references a `{{ … }}` template, so
 * the operator can see it and replace it. `custom-did` is a literal DID
 * that isn't in either register (JSON-API-authored). Issuers take
 * precedence over Authorities on a DID collision.
 */
export type TargetAuthoritySelection =
  | { kind: 'unset' }
  | { kind: 'issuer'; name: string; did: string }
  | { kind: 'authority'; name: string; did: string }
  | { kind: 'legacy-template'; template: string }
  | { kind: 'custom-did'; did: string };

export function classifyTargetAuthoritySelection(
  storedValue: string,
  issuers: ReadonlyArray<{ did: string; name: string }>,
  authorities: ReadonlyArray<{ did: string; name: string }>
): TargetAuthoritySelection {
  if (!storedValue) return { kind: 'unset' };
  const issuer = issuers.find(i => i.did === storedValue);
  if (issuer) return { kind: 'issuer', name: issuer.name, did: storedValue };
  const authority = authorities.find(a => a.did === storedValue);
  if (authority) return { kind: 'authority', name: authority.name, did: storedValue };
  if (storedValue.startsWith('{{')) return { kind: 'legacy-template', template: storedValue };
  return { kind: 'custom-did', did: storedValue };
}

/**
 * `true` when an Authority value is not a usable trust anchor. Leg-aware:
 *
 * - **Target leg** (`isApMa = false`, the default): empty (operator hasn't
 *   picked) or any `{{ … }}` template is unusable — the target must be
 *   checked against an explicit Issuer / Authority literal DID.
 * - **Caller leg** (`isApMa = true`): empty is fine — it wire-defaults to
 *   the verified-issuer template (`defaultAuthorityIdTemplate('ap-ma')`);
 *   the verified-issuer token itself is valid; a literal DID is a valid
 *   explicit override. Only a *different* `{{ … }}` template (e.g. a
 *   legacy `{{ input.agent.provider_did }}`) is unusable and must be
 *   replaced, because it would trip the runtime trust-registry metadata
 *   gate.
 *
 * Used by `incompleteReason`, the picker's invalid state, and the
 * fullscreen save-gate.
 */
export function authorityNeedsSelection(storedValue: string | undefined, isApMa = false): boolean {
  const value = typeof storedValue === 'string' ? storedValue.trim() : '';
  if (isApMa) {
    // Caller-leg accepts blank (→ verified-issuer default), the
    // verified-issuer template itself, and the sending-gateway template
    // (a valid fabric-inbound root-of-trust anchor). Any other `{{ … }}`
    // template is a leftover to replace (e.g. legacy
    // `{{ input.agent.provider_did }}`), which the runtime would deny.
    if (
      value.length === 0 ||
      value === AGENT_IDENTITY_ISSUER_DID_TEMPLATE ||
      value === INPUT_GATEWAY_SOURCE_ID_TEMPLATE
    )
      return false;
    return value.startsWith('{{');
  }
  return value.length === 0 || value.startsWith('{{');
}

// -------------------------------------------------------------------------
// Named subject vocabulary — the plain-English labels used by the Entity
// ID subject-picker dropdown on both legs. Kept as an enum-of-strings
// rather than a Map so the
// exhaustiveness checker catches new subjects at compile time.
// -------------------------------------------------------------------------

export type NamedSubject =
  | 'agent-did'
  | 'extension-identity'
  | 'provider'
  | 'authority-did'
  | 'identity-issuer'
  | 'sending-gateway';

export function templateForSubject(subject: NamedSubject): string {
  switch (subject) {
    case 'agent-did':
      return AGENT_DID_TEMPLATE;
    case 'extension-identity':
      return EXTENSION_IDENTITY_DID_TEMPLATE;
    case 'provider':
      return AUTHORITY_ID_TEMPLATE; // {{ input.agent.provider_did }}
    case 'authority-did':
      return AGENT_AUTHORITY_DID_TEMPLATE;
    case 'identity-issuer':
      return AGENT_IDENTITY_ISSUER_DID_TEMPLATE;
    case 'sending-gateway':
      return INPUT_GATEWAY_SOURCE_ID_TEMPLATE;
  }
}

export function subjectForTemplate(template: string): NamedSubject | null {
  switch (template) {
    case AGENT_DID_TEMPLATE:
      return 'agent-did';
    case EXTENSION_IDENTITY_DID_TEMPLATE:
      return 'extension-identity';
    case AUTHORITY_ID_TEMPLATE:
      return 'provider';
    case AGENT_AUTHORITY_DID_TEMPLATE:
      return 'authority-did';
    case AGENT_IDENTITY_ISSUER_DID_TEMPLATE:
      return 'identity-issuer';
    case INPUT_GATEWAY_SOURCE_ID_TEMPLATE:
      return 'sending-gateway';
    default:
      return null;
  }
}

/**
 * Plain-English label for a named subject, leg-aware. Backend templates
 * are identical on both legs — the resolved *subject* is the caller on
 * the AP→MA edge and the target on the MA→TP edge, so the label swaps
 * per-leg.
 */
export function subjectLabel(subject: NamedSubject, isApMa: boolean): string {
  const who = isApMa ? "the caller's" : "the target's";
  switch (subject) {
    case 'agent-did':
      return `${who} agent DID`;
    case 'extension-identity':
      return "the gateway's managed-identity DID";
    case 'provider':
      return `${who} Provider DID`;
    case 'authority-did':
      return `${who} higher Authority DID`;
    case 'identity-issuer':
      return `${who} verified identity credential issuer DID`;
    case 'sending-gateway':
      return 'the sending gateway DID (fabric-inbound only)';
  }
}

/**
 * Plain-English one-line explanation of a named subject, used as the
 * FormSelect subheader on the Entity ID and target-leg Authority
 * dropdowns. Complements `subjectLabel` (the short subject name) by
 * naming where the runtime reads the value from — caller-leg templates
 * resolve against the inbound request payload, target-leg templates
 * resolve against the target's agent card fetched at request time.
 */
export function subjectDescription(subject: NamedSubject, isApMa: boolean): string {
  switch (subject) {
    case 'agent-did':
      return isApMa
        ? "The agent DID from the caller's agent-identity extension in the request payload."
        : "The agent DID published in the target's agent card.";
    case 'extension-identity':
      // Leg-invariant: the extension identity is always the caller-side
      // gateway-derived DID, regardless of which leg the query runs on.
      return "The gateway's managed-identity DID for the caller (derived from Identity node).";
    case 'provider':
      return isApMa
        ? "The Provider DID from the caller's trust-registry extension in the request payload."
        : "The Provider DID from the target's agent card (its trust-registry extension).";
    case 'authority-did':
      return isApMa
        ? "The higher Authority DID from the caller's trust-registry extension in the request payload."
        : "The higher Authority DID from the target's agent card (its trust-registry extension).";
    case 'identity-issuer':
      return "The cryptographically-verified issuer DID of the caller's agent-identity credential (from the VP presented on inbound).";
    case 'sending-gateway':
      return 'The DID of the sending gateway on the fabric-inbound path. Populated only when the request arrived via `fabric://`; on direct inbound the value is null and the query denies fail-safe.';
  }
}

/**
 * Dropdown state for the Entity ID subject-picker (and target-leg
 * Authority picker). The four named subjects are the operator-authored
 * options; a stored value that isn't one of them (JSON-API-authored
 * literal DID or an unrecognised template) falls into `custom` and is
 * surfaced inline as a locked, read-only dropdown option — mirroring
 * the caller-leg Authority relabel pattern. The operator can see the
 * custom value and pick a named subject to overwrite it, but cannot
 * author a new custom value from the UI.
 */
export type SubjectPickerState =
  | { kind: 'subject'; subject: NamedSubject }
  | { kind: 'custom'; value: string };

/**
 * Read a stored wire value into a `SubjectPickerState`. Blank storage
 * resolves to the default subject (`agent-did`) so legacy configs with
 * an absent `entity_id` field surface as the top option. Values that
 * match one of the four named-subject templates resolve to that
 * subject; everything else (literal DIDs, unrecognised templates from
 * the JSON API) falls into `custom`.
 */
export function readSubjectPickerState(storedValue: string): SubjectPickerState {
  if (!storedValue) return { kind: 'subject', subject: 'agent-did' };
  const subject = subjectForTemplate(storedValue);
  if (subject) return { kind: 'subject', subject };
  return { kind: 'custom', value: storedValue };
}

// -------------------------------------------------------------------------
// Predefined query catalogue — mirrors backend `PredefinedTrustCheckQuery`.
// Fetched at panel mount from `GET /v1/trust-check/predefined-queries` and
// surfaced as a "Query Template" dropdown per query. Selection is a value
// loader: the catalogue tuple is written verbatim into the widget state so
// the stored query matches byte-for-byte, and `matchCatalogueByTuple`
// derives the dropdown label on reload.
// -------------------------------------------------------------------------

/**
 * Wire-adapter defaults the backend applies to a recognition query when
 * `action`/`resource` are blank on the element. Mirrors
 * `RECOGNITION_DEFAULT_ACTION` / `RECOGNITION_DEFAULT_RESOURCE` in
 * `src/trust_registry_verification/trqp_adapter.rs`. Used by
 * `matchCatalogueByTuple` to treat a legacy stored recognition query
 * with blank action/resource as semantically equivalent to the same
 * query with explicit `is`/`ownedAgent` — so pre-preset surfaces match
 * Q1 without needing a re-save migration through the new UI.
 */
export const RECOGNITION_DEFAULT_ACTION = 'is';
export const RECOGNITION_DEFAULT_RESOURCE = 'ownedAgent';

/**
 * Strict tuple comparison with **backend-parity blank normalisation for
 * recognition queries**: on the recognition side (both catalogue and
 * stored), a missing/blank `action` normalises to `is` and a
 * missing/blank `resource` normalises to `ownedAgent` before comparison —
 * so a legacy config stored before this MR (recognition + defaults +
 * blank action/resource) still matches Q1. Authorization queries stay
 * strict-literal (they require action + resource on the wire; a divergent
 * value must not be masked). Blank `authority_id`/`entity_id` on either
 * side never normalise — they carry semantic meaning that would silently
 * collide with the top-subject templates. Returns `null` when the
 * current query is "Custom".
 */
export function matchCatalogueByTuple(
  query: TrustCheckQueryConfig,
  catalogue: ReadonlyArray<PredefinedTrustCheckQuery>
): PredefinedTrustCheckQuery | null {
  const qt: TrustCheckRecordType =
    query.query_type === 'recognition' ? 'recognition' : 'authorization';
  const sq = query.query || {};
  const authority = typeof sq.authority_id === 'string' ? sq.authority_id : '';
  const entity = typeof sq.entity_id === 'string' ? sq.entity_id : '';
  const rawAction = typeof sq.action === 'string' ? sq.action : '';
  const rawResource = typeof sq.resource === 'string' ? sq.resource : '';
  for (const entry of catalogue) {
    if (entry.query_type !== qt) continue;
    if (entry.query.authority_id !== authority) continue;
    if (entry.query.entity_id !== entity) continue;
    const action = qt === 'recognition' ? rawAction || RECOGNITION_DEFAULT_ACTION : rawAction;
    const resource =
      qt === 'recognition' ? rawResource || RECOGNITION_DEFAULT_RESOURCE : rawResource;
    const entryAction =
      qt === 'recognition'
        ? entry.query.action || RECOGNITION_DEFAULT_ACTION
        : entry.query.action || '';
    const entryResource =
      qt === 'recognition'
        ? entry.query.resource || RECOGNITION_DEFAULT_RESOURCE
        : entry.query.resource || '';
    if (entryAction !== action) continue;
    if (entryResource !== resource) continue;
    return entry;
  }
  return null;
}

/**
 * Load a preset's canonical tuple into a `TrustCheckQueryConfig` draft.
 * Overwrites `query_type` and every `query.*` field with the catalogue
 * entry's values verbatim — preserving the wire tuple exactly so
 * `matchCatalogueByTuple` continues to identify the preset on save/reload.
 * Preserves the per-query `id`, `trust_registry_id`, and `name` on the
 * draft (those are per-element, not per-preset).
 */
export function applyPresetToQuery(
  draft: TrustCheckQueryConfig,
  preset: PredefinedTrustCheckQuery
): TrustCheckQueryConfig {
  const query: TrustCheckQueryConfig['query'] = {
    authority_id: preset.query.authority_id,
    entity_id: preset.query.entity_id,
  };
  if (typeof preset.query.action === 'string' && preset.query.action) {
    query.action = preset.query.action;
  }
  if (typeof preset.query.resource === 'string' && preset.query.resource) {
    query.resource = preset.query.resource;
  }
  return {
    ...draft,
    query_type: preset.query_type,
    query,
  };
}

function nodeEdge(node: { slotId?: string; config?: any }): 'ap-ma' | 'ma-tp' {
  const slotId = node.slotId || '';
  const resolved = slotId ? findSlotById(slotId) : undefined;
  if (resolved?.archetype.id === 'ap-ma') return 'ap-ma';
  if (resolved?.archetype.id === 'ma-tp') return 'ma-tp';
  return node.config?._edge === 'ma-tp' ? 'ma-tp' : 'ap-ma';
}

/**
 * Mint a fresh UUID for a new Trust Check element. The id is required on
 * the wire (`pub id: String`) but invisible in the UI — its only purpose is
 * OPA addressability on `input.trust_check_results.{caller|target}[]` and
 * audit-log correlation. Generated client-side at element creation; once
 * persisted, `configFromPayload` / `hydrateLeg` round-trip it unchanged so
 * the id is stable across save/load cycles.
 */
export function generateTrustCheckElementId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `tc-${Math.random().toString(36).slice(2, 10)}-${Date.now().toString(36)}`;
}

/**
 * One Trust Check sub-query as the panel/list edits it. A node holds
 * `queries: TrustCheckQueryConfig[]`; `buildPayload` fans each entry
 * out into the leg's wire `trust_check_list` array.
 */
export interface TrustCheckQueryConfig {
  id?: string;
  trust_registry_id?: string;
  query_type?: TrustCheckRecordType;
  // Operator-visible label. Round-tripped verbatim; the panel has no editor
  // for it today, but a surface authored via the JSON API must not lose the
  // field the first time it is saved from the dashboard (backend uses it in
  // probe results + audit events, per AGENTS.md).
  name?: string;
  query?: {
    authority_id?: string;
    action?: string;
    resource?: string;
    [k: string]: unknown;
  };
}

/**
 * Normalise a node's config into the canonical `queries[]` shape.
 * Saved surfaces from before multi-query support carried the four
 * fields (`trust_registry_id`, `query_type`, `query`, `id`) flat on
 * the node config; they are read as a single-element list so legacy
 * configs round-trip without a migration step.
 */
export function readQueries(config: any): TrustCheckQueryConfig[] {
  if (Array.isArray(config?.queries)) {
    return config.queries.filter(
      (q: any): q is TrustCheckQueryConfig => !!q && typeof q === 'object'
    );
  }
  if (
    config &&
    (config.trust_registry_id !== undefined ||
      config.query_type !== undefined ||
      config.query !== undefined)
  ) {
    return [
      {
        id: typeof config.id === 'string' ? config.id : undefined,
        trust_registry_id:
          typeof config.trust_registry_id === 'string' ? config.trust_registry_id : '',
        query_type: config.query_type === 'recognition' ? 'recognition' : 'authorization',
        name: typeof config.name === 'string' ? config.name : undefined,
        query: config.query || {},
      },
    ];
  }
  return [];
}

/** Mint a fresh empty query for the panel's "+ Add Another Query" action. */
export function makeDefaultQuery(): TrustCheckQueryConfig {
  return {
    id: generateTrustCheckElementId(),
    trust_registry_id: '',
    query_type: 'authorization',
    query: {},
  };
}

function buildEntry(
  node: { id: string; slotId?: string; config?: any },
  q: TrustCheckQueryConfig
): Record<string, unknown> {
  const queryType: TrustCheckRecordType =
    q.query_type === 'recognition' ? 'recognition' : 'authorization';
  const stored = q.query || {};
  const edge = nodeEdge(node);
  // The caller leg wire-defaults a blank Authority to the verified
  // agent-identity-credential issuer template — a crypto-verified anchor
  // that never trips the runtime trust-registry metadata gate. The target
  // leg has no verified value to default to, so blank stays blank and
  // surfaces as incomplete (see `incompleteReason` /
  // `authorityNeedsSelection`). An explicitly picked Issuer / Authority
  // literal DID (or a JSON-API template) is emitted verbatim on both legs.
  const explicitAuthority =
    typeof stored.authority_id === 'string' ? stored.authority_id.trim() : '';
  const explicitEntity = typeof stored.entity_id === 'string' ? stored.entity_id.trim() : '';
  const query: Record<string, string> = {
    authority_id: explicitAuthority || defaultAuthorityIdTemplate(edge),
    entity_id: explicitEntity || defaultEntityIdTemplate(edge),
  };
  if (typeof stored.action === 'string' && stored.action) query.action = stored.action;
  if (typeof stored.resource === 'string' && stored.resource) query.resource = stored.resource;
  const entry: Record<string, unknown> = {
    id: typeof q.id === 'string' && q.id ? q.id : generateTrustCheckElementId(),
    trust_registry_id: typeof q.trust_registry_id === 'string' ? q.trust_registry_id : '',
    query_type: queryType,
    query,
  };
  if (typeof q.name === 'string' && q.name.length > 0) entry.name = q.name;
  return entry;
}

export const trustCheckDefinition: NodeDefinition = {
  type: 'trust-check',
  label: 'Trust Check',
  description: 'Run a TRQP authorization or recognition query against a trust registry',
  namePlaceholder: 'Give your Trust Check a descriptive name',
  suppressIncompleteBanner: c => readQueries(c).length === 0,
  icon: '\uf0a3', // fa-certificate (shared family with Trust Registry)
  paletteIcon: 'fa-certificate',
  color: '#8e44ad',
  shape: 'circle',
  defaultRadius: 22,
  resizable: true,
  resizeRange: { min: 16, max: 60 },
  draggable: true,
  containedInSurface: false,
  edgeConstrained: false,
  xWeight: 0.35,
  stage: 'middleware',
  cardinality: 'multi',
  paletteCategory: 'policy',
  paletteOrder: 5,
  dropMode: 'edge',
  directionality: 'request',
  edgeSnap: {
    radius: 100000,
    archetypes: ['ap-ma', 'ma-tp'],
  },
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: {
    dropOnEdge: [Cap.TRUST_REGISTRY_TARGET],
  },
  help: {
    title: 'Trust Check',
    docLink: DOCS_URL.trustElements,
    bodyHtml: `
      <p>Run one TRQP query per element. Multiple Trust Checks can chain on
      the same edge: each result is surfaced to your policies on every
      gateway and surface evaluation, which decide what to do with allow /
      deny / unreachable.</p>
      <p><strong>Placement determines which leg the query runs on:</strong></p>
      <ul>
        <li><strong>On the Access Point \u2192 Managed Agent edge</strong>:
          the caller leg. Available for all protocols.</li>
        <li><strong>On the Managed Agent \u2192 Transit Point edge</strong>:
          the target leg. A2A / AP2 Transit Points only (the MCP target-leg
          check is not available yet, so the slot is not offered on MCP
          Transit Points).</li>
      </ul>
      <p>Query templates can reference the policy input via
      <code>{{ input.\u2026 }}</code>; they resolve against the same data
      your policies see at that point.</p>
    `,
  },
  incompleteReason: c => {
    const queries = readQueries(c);
    if (queries.length === 0) return 'Needs at least one query';
    const isTargetLeg = c?._edge === 'ma-tp';
    for (let i = 0; i < queries.length; i++) {
      const q = queries[i];
      const prefix = queries.length > 1 ? `Query ${i + 1}: ` : '';
      if (!q.trust_registry_id) return `${prefix}Trust registry must be selected`;
      if (authorityNeedsSelection(q.query?.authority_id as string, !isTargetLeg)) {
        return isTargetLeg
          ? `${prefix}Select an Issuer or Authority for the target-leg Authority`
          : `${prefix}Replace the caller-leg Authority template with the agent identity credential issuer default or an explicit Issuer / Authority`;
      }
      const qt: TrustCheckRecordType =
        q.query_type === 'recognition' ? 'recognition' : 'authorization';
      if (qt === 'authorization') {
        const action = typeof q.query?.action === 'string' ? q.query.action.trim() : '';
        const resource = typeof q.query?.resource === 'string' ? q.query.resource.trim() : '';
        if (!action) return `${prefix}Action is required for authorization queries`;
        if (!resource) return `${prefix}Resource is required for authorization queries`;
      }
    }
    return null;
  },
  ConfigPanel: TrustCheckPanel,
  FullscreenPanel: TrustCheckFullscreenPanel,
  summary: c => {
    const queries = readQueries(c);
    if (queries.length === 0) return 'no queries';
    if (queries.length === 1) {
      return queries[0].query_type === 'recognition' ? 'recognition' : 'authorization';
    }
    return `${queries.length} queries`;
  },
  buildPayload: ctx => {
    const nodes = ctx.nodesOfType('trust-check');
    if (nodes.length === 0) return undefined;
    const caller: Array<Record<string, unknown>> = [];
    const target: Array<Record<string, unknown>> = [];
    for (const node of nodes) {
      const queries = readQueries(node.config);
      if (queries.length === 0) continue;
      const bucket = nodeEdge(node) === 'ma-tp' ? target : caller;
      for (const q of queries) bucket.push(buildEntry(node, q));
    }
    const slices: PayloadSlice[] = [];
    if (caller.length > 0) {
      slices.push({ path: 'access_point.trust_check_list', value: caller });
    }
    if (target.length > 0) {
      slices.push({ path: 'target.trust_check_list', value: target });
    }
    return slices.length > 0 ? slices : undefined;
  },
};
