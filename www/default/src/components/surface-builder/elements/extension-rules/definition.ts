import * as Cap from '../capabilities';
import type { NodeDefinition, PayloadSlice } from '../types';
import ExtensionRulesPanel from './ExtensionRulesPanel';
import { DOCS_URL } from '../../../../config/docs';

function buildSlice(node: any | undefined): any | undefined {
  const c = node?.config;
  if (!c) return undefined;
  const hasRules = Array.isArray(c.rules) && c.rules.length > 0;
  if (!hasRules && !c.default_action) return undefined;
  return {
    ...(c.default_action ? { default_action: c.default_action } : {}),
    ...(hasRules ? { filter_rules: c.rules } : {}),
  };
}

export const extensionRulesDefinition: NodeDefinition = {
  type: 'extension-rules',
  label: 'Extension Rules',
  description: 'Allow / strip / reject protocol extensions per URI',
  icon: '\uf085', // fa-gears
  paletteIcon: 'fa-cogs',
  color: '#6610f2',
  shape: 'circle',
  defaultRadius: 14,
  resizable: true,
  resizeRange: { min: 16, max: 60 },
  draggable: true,
  containedInSurface: false,
  edgeConstrained: false,
  xWeight: 0.45,
  stage: 'middleware',
  cardinality: 'multi',
  paletteCategory: 'enhancement',
  paletteOrder: 7,
  dropMode: 'edge',
  help: {
    title: 'Extension Rules',
    docLink: DOCS_URL.protocolExtensionElements,
    bodyHtml: `
      <p>Per-URI <strong>allow / strip / reject</strong> filter on protocol
      extensions, plus a default action for anything not listed.</p>
      <p><strong>Direction:</strong> request only. Extension Rules filters
      inbound (request) extensions; dropping it on the response arrow has
      no effect on outbound traffic.</p>
      <p><strong>Actions:</strong></p>
      <ul>
        <li><strong>allow</strong>: pass the extension through unchanged</li>
        <li><strong>strip</strong>: silently remove it from the payload</li>
        <li><strong>reject</strong>: fail the request with an error</li>
      </ul>
    `,
  },
  // Direction set by drop position. Drop on request arrow → filters inbound
  // extensions. The Target schema doesn't model response-side extension
  // rules, so the response slot was removed; this element is
  // effectively request-only at the payload level.
  directionality: 'either',
  protocols: ['a2a', 'ap2'],
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: {
    dropOnEdge: [Cap.EXTENSION_TARGET],
  },
  incompleteReason: c =>
    !Array.isArray(c.rules) || c.rules.length === 0 ? 'At least one rule is required' : null,
  ConfigPanel: ExtensionRulesPanel,
  payloadPath: 'target.extension_rules',
  configFromPayload: (slice: any) => ({
    default_action: slice?.default_action,
    rules: slice?.filter_rules ?? [],
  }),
  buildPayload: ctx => {
    const all = ctx.nodesOfType('extension-rules');
    if (all.length === 0) return undefined;
    const slices: PayloadSlice[] = [];
    const reqNode = all.find(n => (n.direction ?? 'request') === 'request');
    const reqValue = buildSlice(reqNode);
    if (reqValue) slices.push({ path: 'target.extension_rules', value: reqValue });
    return slices.length > 0 ? slices : undefined;
  },
};
