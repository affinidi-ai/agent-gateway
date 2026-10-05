import * as Cap from '../capabilities';
import type { NodeDefinition, PayloadSlice } from '../types';
import { findSlotById } from '../edges/archetypes';
import { registry } from '../registry';
import IdentityPanel from './IdentityPanel';
import IdentityPayloadFullscreenPanel from './IdentityPayloadFullscreenPanel';
import { DOCS_URL } from '../../../../config/docs';

export const identityDefinition: NodeDefinition = {
  type: 'identity',
  label: 'Identity',
  description:
    'Edge-bound: extracts an agent identity from one of the surface identity slots (inbound caller, protected agent response, external agent response, or outbound managed-agent Transit Point request).',
  icon: '\uf2c1', // fa-id-badge
  paletteIcon: 'fa-id-badge',
  color: '#7b68ee',
  shape: 'circle',
  defaultRadius: 14,
  resizable: true,
  resizeRange: { min: 16, max: 60 },
  draggable: true,
  containedInSurface: false,
  edgeConstrained: false,
  stage: 'middleware',
  // Multi-instance: one per slot (inbound / protected / external / per-TP managed identity).
  // The drop dispatcher selects the slot based on which edge the node
  // is released over and the drop direction.
  paletteCategory: 'enhancement',
  paletteOrder: 1,
  // Agent Identity drops on any edge that exposes an identity slot.
  // Today: AP→MA (inbound/protected), MA→External (external), and
  // MA→Transit Point (per-TP managed identity). The slot's
  // `payloadPathTemplate` decides which identity config key the node
  // serialises to.
  dropMode: 'edge',
  directionality: 'both',
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: { dropOnEdge: [Cap.IDENTITY_TARGET] },
  help: {
    title: 'Identity',
    docLink: DOCS_URL.identityElement,
    bodyHtml: `
      <p>Extracts an <strong>agent identity</strong> at the surface seam where
      identity evidence is available. Drop it on the relevant edge: Access Point
      → Managed Agent for caller/protected identity, Managed Agent → External for
      upstream external identity, or Managed Agent → Transit Point for the
      outbound managed-agent identity used by that Transit Point.</p>
      <p>For Copilot Studio calling a Transit Point, drop Identity on the
      Managed Agent → Transit Point edge and configure it to read Header Metadata
      Mapping. Without this element the TP request has no managed-agent identity
      to stamp into VP / Workload Binding flows.</p>
      <p><strong>Extraction types:</strong></p>
      <ul>
        <li><strong>From payload</strong>: read identity claims from a
        named field in the request or response body, depending on which
        edge you drop this on. Configure the meta-field name
        (e.g. <code>agentIdentity</code>), the list of fields to pull,
        and an optional JSON schema to validate the extracted block.</li>
        <li><strong>From API key</strong>: derive identity from the
        configured API key id.</li>
        <li><strong>From mTLS</strong>: take the identity from the other
        side's TLS client certificate (the caller's certificate on an
        inbound edge, the upstream's on an outbound edge).</li>
        <li><strong>Static</strong>: always present a fixed DID for the
        upstream (useful for stub agents and tests).</li>
      </ul>
      <p>Strict <em>Extension Rules</em> with a default action of
      <strong>reject</strong> require an extraction type to be set. The
      builder flags this as a missing-feature warning.</p>
    `,
  },
  // Returns a reason only when a credential type has been picked but the
  // required credential field is still missing (api_key_id, certificate_id,
  // or static_did). No type selected → no credential requirements violated
  // → returns null (not treated as incomplete on drop).
  incompleteReason: config => identityIncompleteReason(config),
  defaultConfig: () => ({
    meta_field: 'agentIdentity',
    json_schema: {
      properties: {
        agentIdentity: {
          properties: {},
          required: [],
          type: 'object',
        },
      },
      required: [],
      type: 'object',
    },
    fields: [],
  }),
  summary: c => (c?.type ? `Type: ${c.type}` : null),
  featureDependencies: [
    {
      description: 'Strict extension rules need an identity extraction type',
      condition: (_c, ctx) => {
        const ext = ctx.allNodes.filter(n => n.type === 'extension-rules');
        return ext.some(
          n =>
            (n.config?.scope === 'inbound' || n.config?.scope === 'both') &&
            n.config?.default_action === 'reject'
        );
      },
      check: c => !!c.type && c.type !== 'none',
      severity: 'warning',
      message: 'Extension rules with default_action=reject need an identity extraction type',
    },
    {
      description:
        'from_jwt_claim derives the DID from a validated JWT, so the surface must authenticate the caller with JWT Bearer',
      condition: c => c.type === 'from_jwt_claim',
      check: (_c, ctx) =>
        ctx.allNodes.some(n => n.type === 'caller-auth' && n.config?.method_type === 'jwt_bearer'),
      severity: 'error',
      message:
        'From JWT Claims requires a Caller Context using JWT Bearer. Switch it back, or change this extraction type.',
    },
  ],
  ConfigPanel: IdentityPanel,
  FullscreenPanel: IdentityPayloadFullscreenPanel,
  // Per-instance payload path is resolved at serialization time from the
  // node's `slotId` (one of `identity_slots.inbound | .protected | .external`).
  // `payloadPath` is retained for legacy single-instance callers that still
  // ask the registry for "the" identity path; it points at slot 2 (the
  // original singleton behaviour).
  payloadPath: 'identity_slots.protected',
  // The backend serializes `ManagedIdentityConfig::PayloadExtraction`
  // as `"type": "payload_extraction"` (snake_case enum tag), while the
  // dashboard's extraction-type dropdown only knows `"from_payload"`
  // (the UI/wire-input alias). Without this normalisation the saved
  // slice round-trips as a `type` the dropdown can't render, so the
  // panel reports "Pick an identity extraction type" even though the
  // identity is fully configured.
  configFromPayload: (slice: any) => {
    if (!slice || typeof slice !== 'object') return slice;
    if (slice.type === 'payload_extraction') {
      const mapped: Record<string, any> = { ...slice, type: 'from_payload' };
      if (slice.strip_raw_meta) mapped.strip_raw_meta = true;
      return mapped;
    }
    if (slice.type === 'static') {
      // The backend `ManagedIdentityConfig::Static` serialises the DID
      // under `did`; the panel edits it as `static_did`.
      const { did, ...rest } = slice;
      return { ...rest, static_did: rest.static_did ?? did };
    }
    return slice;
  },
  buildPayload: ctx => {
    const nodes = ctx.nodesOfType('identity');
    if (nodes.length === 0) return undefined;
    const slices: PayloadSlice[] = [];
    for (const node of nodes) {
      const ic = node.config;
      if (!ic) continue;
      // Per-TP identities are folded into `transit.points[]` by the TP
      // factory (it owns the entire transit.points slice). Skip them
      // here to avoid double-writing under the wrong path.
      if (node.parentId) {
        const parentNode = ctx.allNodes.find(n => n.id === node.parentId);
        if (parentNode && registry.isTransitPointType(parentNode.type)) {
          continue;
        }
      }
      // Resolve the per-instance payload path. Prefer the canonical
      // node id (`identity-{inbound|protected|external}`) because it
      // is unambiguous — historical slot ids used the bare
      // `response:identity` form for both the AP→MA protected slot
      // and the MA→External external slot, so any node persisted
      // before that collision was fixed would otherwise mis-route to
      // protected. Fall back to slotId lookup, then to the legacy
      // single-instance path.
      let path: string | undefined;
      if (node.id === 'identity-inbound') path = 'identity_slots.inbound';
      else if (node.id === 'identity-protected') path = 'identity_slots.protected';
      else if (node.id === 'identity-external') path = 'identity_slots.external';
      if (!path && node.slotId) {
        const found = findSlotById(node.slotId);
        path = found?.slot.payloadPathTemplate;
      }
      if (!path) path = 'identity_slots.protected';

      const value = identityConfigToWire(ic);
      if (!value) continue;
      slices.push({ path, value });
    }
    return slices.length > 0 ? slices : undefined;
  },
};

/**
 * Project an identity panel config onto the backend
 * `ManagedIdentityConfig`/`PayloadExtraction` wire shape. Shared with
 * the TP factory so per-TP `managed_identity` slices emit an
 * identical structure.
 *
 * Returns `undefined` when the config is empty (no type, no fields).
 */
export function identityConfigToWire(ic: Record<string, any> | undefined): any | undefined {
  if (!ic || typeof ic !== 'object') return undefined;
  const value: Record<string, any> = {};
  if (ic.type) value.type = ic.type;
  if (ic.type === 'from_api_key' && ic.api_key_id) value.api_key_id = ic.api_key_id;
  if (ic.type === 'from_mtls' && ic.certificate_id) value.certificate_id = ic.certificate_id;
  // Backend `ManagedIdentityConfig::Static` expects the DID under `did`
  // (the panel edits it as `static_did`).
  if (ic.type === 'static' && ic.static_did) value.did = ic.static_did;
  if (ic.type === 'from_jwt_claim') {
    value.claim = ic.claim && String(ic.claim).trim() ? ic.claim : 'oid';
    if (Array.isArray(ic.namespace_claims) && ic.namespace_claims.length > 0)
      value.namespace_claims = ic.namespace_claims;
  }
  if (ic.meta_field) value.meta_field = ic.meta_field;
  if (ic.extension_uri) value.extension_uri = ic.extension_uri;
  if (Array.isArray(ic.fields) && ic.fields.length > 0) value.fields = ic.fields;
  if (ic.json_schema && typeof ic.json_schema === 'object') value.json_schema = ic.json_schema;
  if (ic.strip_raw_meta) value.strip_raw_meta = true;
  if (Object.keys(value).length === 0) return undefined;
  return value;
}

/**
 * Returns null when the identity is fully configured, else the user-facing
 * reason. The empty string sentinel from the sidebar dropdown does NOT
 * count as a selected type.
 */
function identityIncompleteReason(config: Record<string, any>): string | null {
  if (!config.type) return 'Select an identity extraction type';
  if (config.type === 'from_api_key' && !config.api_key_id) return 'Select an API key';
  if (config.type === 'from_mtls' && !config.certificate_id) return 'Select a certificate';
  if (config.type === 'static' && !config.static_did) return 'Enter a static DID';
  return null;
}
