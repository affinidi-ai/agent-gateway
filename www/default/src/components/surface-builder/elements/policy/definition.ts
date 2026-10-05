import * as Cap from '../capabilities';
import { findSlotById } from '../edges/archetypes';
import { registry } from '../registry';
import type { NodeDefinition, PayloadSlice } from '../types';
import PolicyPanel from './PolicyPanel';
import { DOCS_URL } from '../../../../config/docs';

export const policyDefinition: NodeDefinition = {
  type: 'policy',
  label: 'Policy',
  description: 'OPA policy evaluation gate',
  icon: '\uf132', // fa-shield
  paletteIcon: 'fa-shield-alt',
  color: '#e74a3b',
  shape: 'circle',
  defaultRadius: 14,
  resizable: true,
  resizeRange: { min: 16, max: 60 },
  draggable: true,
  containedInSurface: false,
  edgeConstrained: false,
  xWeight: 0.35,
  stage: 'middleware',
  cardinality: 'multi',
  paletteCategory: 'policy',
  paletteOrder: 1,
  dropMode: 'edge',
  // The slot the policy fills is derived from {parent, direction}:
  //   parent = access-point        → access_point.inbound_policy
  //   parent = target, request     → target.policy
  //   parent = target, response    → target.response_policy
  // The legacy in-config `policy_type` field is gone; the user picks the
  // slot by dropping on the matching arrow (AP\u2192MA request for inbound,
  // MA\u2192TP request for target.policy, MA\u2192AP response for response_policy).
  directionality: 'either',
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: {
    dropOnEdge: [Cap.POLICY_TARGET],
  },
  help: {
    title: 'Policy',
    docLink: DOCS_URL.opaPoliciesReference,
    bodyHtml: `
      <p>OPA (Rego) policy gate. The Gateway evaluates the selected
      policy against the request (and/or response) and short-circuits
      with a deny when the policy returns <code>false</code>.</p>
      <p>Pick a policy from the dashboard's Policy Definitions list.</p>
      <p><strong>Where it docks</strong> determines what it gates:</p>
      <ul>
        <li><strong>Caller → Access Point</strong> (request): inbound
        gate. Runs before the request reaches the Managed Agent.</li>
        <li><strong>Managed Agent → Target</strong> (request): target
        gate. Runs just before the upstream call.</li>
        <li><strong>Target → Managed Agent</strong> (response): response
        gate. Runs on the way back.</li>
        <li><strong>On a Transit Point</strong>: a policy attached to
        that outbound route.</li>
      </ul>
      <p>You can stack multiple policy nodes, one per slot. Gateway-level
      policies (configured outside the Surface) always run before any
      policy here; a gateway-level deny cannot be overridden.</p>
    `,
  },
  incompleteReason: config =>
    !config.policy_definition_id ? 'Policy definition must be selected' : null,
  ConfigPanel: PolicyPanel,
  payloadPath: 'target.policy',
  responsePayloadPath: 'target.response_policy',
  summary: c => (c?.policy_definition_id ? String(c.policy_definition_id).substring(0, 16) : null),
  buildPayload: ctx => {
    const slices: PayloadSlice[] = [];
    for (const p of ctx.nodesOfType('policy')) {
      const id = p.config?.policy_definition_id;
      if (!id) continue;
      // Per-TP policies are folded into `transit.points[]` by the TP
      // factory (it owns the entire transit.points slice). Skip them
      // here to avoid double-writing.
      if (p.parentId) {
        const parentNode = ctx.allNodes.find(n => n.id === p.parentId);
        if (parentNode && registry.isTransitPointType(parentNode.type)) {
          continue;
        }
      }
      const direction = p.direction ?? 'request';
      // Slot identity is the source of truth for which payload key to
      // write. The slot was either set at drop time (`handleDrop`) or
      // restored from `nodesFromPayload` / canvas blob. We fall back
      // to id pattern + direction only when the node lacks a slotId
      // (legacy persisted nodes from before the slotId rollout).
      let path: string | undefined;
      if (p.slotId) {
        const found = findSlotById(p.slotId);
        path = found?.slot.payloadPathTemplate;
      }
      if (!path) {
        const isInbound = p.id === 'policy-inbound' || p.id.startsWith('policy-inbound-');
        if (isInbound && direction === 'request') {
          path = 'access_point.inbound_policy';
        } else if (direction === 'response') {
          path = 'target.response_policy';
        } else {
          path = 'target.policy';
        }
      }
      slices.push({
        path,
        value: {
          policy_definition_id: id,
          ...(p.config?.require_agent_context ? { require_agent_context: true } : {}),
        },
      });
    }
    return slices.length > 0 ? slices : undefined;
  },
};
