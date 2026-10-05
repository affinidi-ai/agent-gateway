import * as Cap from '../capabilities';
import type { NodeDefinition, PayloadSlice } from '../types';
import TrustRecorderPanel from './TrustRecorderPanel';
import TrustRecorderFullscreenPanel from './TrustRecorderFullscreenPanel';
import { DOCS_URL } from '../../../../config/docs';

/**
 * One row of the Trust Recorder editor: which registry to write to, which
 * issuer signs the records, an optional ownedAgent triple, and any
 * operator-defined custom records.
 *
 * Wire shape mirrors `TrustRecorderEntry` in `src/config/types.rs`.
 */
export interface TrustRecorderEntry {
  trust_registry_id: string;
  issuer_did: string;
  authority_did: string;
  include_owned_agent: boolean;
  custom_resources: CustomResource[];
}

/** Which DID the runtime writes as `entity_id` on a custom record. */
export type EntityTarget = 'issuer' | 'agent';

/** TrAdmin record type. Free-form on the wire; UI exposes these two. */
export type RecordType = 'recognition' | 'authorization';

/**
 * A single custom record on a Trust Recorder entry. Mirrors
 * `CustomResource` in `src/config/types.rs`.
 */
export interface CustomResource {
  action: string;
  resource: string;
  entity_target: EntityTarget;
  record_type: string;
}

/**
 * Mirrors backend `TRUST_RECORDER_ENTRIES_MAX`. Keeps the panel from
 * silently over-configuring a surface the runtime will later reject.
 */
export const TRUST_RECORDER_ENTRIES_MAX = 10;

/**
 * Template token that expands at write time to the surface's Issuer DID
 * (`Issuer.did` looked up via `surface.issuer_id`). Kept in sync with
 * `SURFACE_ISSUER_DID_TEMPLATE` in
 * `src/trust_registry_verification/trust_recorder.rs`.
 *
 * Storing this literal in `TrustRecorderEntry.authority_did` tells the
 * recorder to use the surface's currently-configured Issuer's DID as
 * `authority_id` on every emitted record — so records satisfy the
 * downstream Trust Check `authority = verified issuer` query on any
 * gateway whose caller VP was minted by the same Issuer.
 */
export const SURFACE_ISSUER_DID_TEMPLATE = '{{ surface.issuer_did }}';

/** Mint a fresh empty entry for the panel's "+ Add Trust Registry" action. */
export function makeDefaultEntry(): TrustRecorderEntry {
  return {
    trust_registry_id: '',
    issuer_did: '',
    authority_did: '',
    include_owned_agent: true,
    custom_resources: [],
  };
}

/** Mint a fresh empty custom-resource row. */
export function makeDefaultCustomResource(): CustomResource {
  return { action: '', resource: '', entity_target: 'agent', record_type: 'recognition' };
}

/**
 * Normalise a node's config into the canonical `entries[]` shape. Panels
 * write `config.entries`; hydration lands `entries` directly from the
 * wire slice (`access_point.trust_recorder.entries`).
 */
export function readEntries(config: any): TrustRecorderEntry[] {
  const raw = config?.entries;
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((e: any): e is Record<string, unknown> => !!e && typeof e === 'object')
    .map((e: any) => ({
      trust_registry_id: typeof e.trust_registry_id === 'string' ? e.trust_registry_id : '',
      issuer_did: typeof e.issuer_did === 'string' ? e.issuer_did : '',
      authority_did: typeof e.authority_did === 'string' ? e.authority_did : '',
      include_owned_agent: e.include_owned_agent !== false,
      custom_resources: Array.isArray(e.custom_resources)
        ? e.custom_resources
            .filter((r: any): r is Record<string, unknown> => !!r && typeof r === 'object')
            .map((r: any) => ({
              action: typeof r.action === 'string' ? r.action : '',
              resource: typeof r.resource === 'string' ? r.resource : '',
              entity_target: r.entity_target === 'issuer' ? 'issuer' : 'agent',
              record_type:
                typeof r.record_type === 'string' && r.record_type.trim().length > 0
                  ? r.record_type
                  : 'recognition',
            }))
        : [],
    }));
}

export const trustRecorderDefinition: NodeDefinition = {
  type: 'trust-recorder',
  label: 'Trust Recorder',
  description: 'Write agent-registration records into one or more Trust Registries',
  namePlaceholder: 'Give your Trust Recorder a descriptive name',
  suppressIncompleteBanner: c => readEntries(c).length === 0,
  icon: '\uf044', // fa-pen-to-square
  paletteIcon: 'fa-pen-to-square',
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
  paletteOrder: 6,
  dropMode: 'edge',
  directionality: 'response',
  edgeSnap: {
    radius: 100000,
    archetypes: ['ap-ma'],
  },
  payloadPath: 'access_point.trust_recorder',
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: {
    dropOnEdge: [Cap.TRUST_REGISTRY_TARGET],
  },
  help: {
    title: 'Trust Recorder',
    docLink: DOCS_URL.trustElements,
    bodyHtml: `
      <p>Write agent-registration records into one or more
      <strong>Trust Registries</strong> on the response leg
      (Managed Agent &rarr; Access Point). Runs after the managed agent
      responds so the agent's DID from the reply can be recorded.</p>
      <p>Each configured registry may emit the built-in <code>ownedAgent</code>
      triple plus any custom records. Every record is asserted by the entry's
      <strong>authority DID</strong> (the trust anchor):</p>
      <ul>
        <li><code>authority = authority DID</code>,
            <code>entity = agent DID</code> (auto-filled),
            <code>action = is</code>,
            <code>resource = ownedAgent</code></li>
        <li>Custom records: <code>authority = authority DID</code>,
            <code>entity = issuer DID</code> or <code>agent DID</code>
            (per row's target), <code>action</code> and
            <code>resource</code> free-form.</li>
      </ul>
    `,
  },
  incompleteReason: c => {
    const entries = readEntries(c);
    if (entries.length === 0) return 'At least one Trust Registry entry is required';
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i];
      const prefix = entries.length > 1 ? `Entry ${i + 1}: ` : '';
      if (!e.trust_registry_id) return `${prefix}Trust registry must be selected`;
      if (!e.issuer_did) return `${prefix}Issuer DID must be set`;
      if (!e.authority_did) return `${prefix}Authority DID must be set`;
      const hasCustom = e.custom_resources.some(
        r =>
          r.action.trim().length > 0 &&
          r.resource.trim().length > 0 &&
          r.record_type.trim().length > 0
      );
      if (!e.include_owned_agent && !hasCustom) {
        return `${prefix}Enable ownedAgent or add at least one custom resource`;
      }
    }
    return null;
  },
  ConfigPanel: TrustRecorderPanel,
  FullscreenPanel: TrustRecorderFullscreenPanel,
  summary: c => {
    const entries = readEntries(c);
    if (entries.length === 0) return 'no registries';
    if (entries.length === 1) return '1 registry';
    return `${entries.length} registries`;
  },
  buildPayload: ctx => {
    const nodes = ctx.nodesOfType('trust-recorder');
    if (nodes.length === 0) return undefined;
    const entries: TrustRecorderEntry[] = [];
    for (const node of nodes) {
      for (const e of readEntries(node.config)) entries.push(e);
    }
    if (entries.length === 0) return undefined;
    const slices: PayloadSlice[] = [
      {
        path: 'access_point.trust_recorder',
        value: { entries },
      },
    ];
    return slices;
  },
  configFromPayload: slice => {
    const entries = Array.isArray(slice?.entries) ? slice.entries : [];
    return { entries: readEntries({ entries }) };
  },
};
