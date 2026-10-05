import * as Cap from '../capabilities';
import type { NodeDefinition } from '../types';
import ExtensionValidationPanel from './ExtensionValidationPanel';
import { DOCS_URL } from '../../../../config/docs';

export const extensionValidationDefinition: NodeDefinition = {
  type: 'extension-validation',
  label: 'Extension Validation',
  description: 'Require and validate protocol extensions on requests',
  icon: '\uf560', // fa-check-double
  paletteIcon: 'fa-check-double',
  color: '#0dcaf0',
  shape: 'circle',
  defaultRadius: 14,
  resizable: true,
  resizeRange: { min: 16, max: 60 },
  draggable: true,
  containedInSurface: false,
  edgeConstrained: false,
  xWeight: 0.5,
  stage: 'middleware',
  cardinality: 'singleton',
  paletteCategory: 'enhancement',
  paletteOrder: 5,
  dropMode: 'edge',
  help: {
    title: 'Extension Validation',
    docLink: DOCS_URL.protocolExtensionElements,
    bodyHtml: `
      <p>Validates that <strong>inbound</strong> requests carry required
      protocol-extension URIs and (optionally) match a JSON schema.</p>
      <p>Acts as a hard gate <em>before</em> any policy or payment check:
      requests missing the listed extensions are rejected with a 400.</p>
      <p><strong>Direction:</strong> request only. There is no response
      counterpart.</p>
    `,
  },
  // Validates required extensions on inbound requests only. Outbound
  // extension filtering is handled by the response-direction Extension Rules
  // element instead.
  directionality: 'request',
  protocols: ['a2a', 'ap2'],
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: {
    dropOnEdge: [Cap.EXTENSION_TARGET],
  },
  incompleteReason: c => (!c.required_extensions ? 'Required extensions must be specified' : null),
  ConfigPanel: ExtensionValidationPanel,
  payloadPath: 'access_point.extension_validation',
  configFromPayload: slice => {
    // Hydrate the persisted `{ required_extensions: string[], schema?: object }`
    // shape back into the panel form: CSV string + JSON text. Without this
    // the panel input receives an array (which React coerces with commas
    // but typing then replaces with a plain string) and the schema
    // textarea receives `[object Object]`. The element renders correctly
    // either way today (incompleteReason is truthy for non-empty arrays
    // too), but normalising here keeps the panel form consistent with
    // what the user originally typed and matches the custom-metadata /
    // transit-credentials pattern.
    if (!slice || typeof slice !== 'object') return {};
    const required = Array.isArray(slice.required_extensions)
      ? slice.required_extensions.join(', ')
      : typeof slice.required_extensions === 'string'
        ? slice.required_extensions
        : '';
    const schema =
      slice.schema && typeof slice.schema === 'object'
        ? JSON.stringify(slice.schema, null, 2)
        : typeof slice.schema === 'string'
          ? slice.schema
          : '';
    return {
      ...(required ? { required_extensions: required } : {}),
      ...(schema ? { schema } : {}),
    };
  },
  buildPayload: ctx => {
    const node = ctx.firstNodeOfType('extension-validation');
    const c = node?.config;
    if (!c?.required_extensions) return undefined;
    const required = String(c.required_extensions)
      .split(',')
      .map((s: string) => s.trim())
      .filter(Boolean);
    if (required.length === 0) return undefined;
    let schemaValue: any;
    if (c.schema) {
      if (typeof c.schema === 'string') {
        try {
          schemaValue = JSON.parse(c.schema || '{}');
        } catch {
          // Invalid JSON in the textarea — drop the schema rather than
          // throwing during save. The validator surfaces the parse error.
        }
      } else if (typeof c.schema === 'object') {
        schemaValue = c.schema;
      }
    }
    return [
      {
        path: 'access_point.extension_validation',
        value: {
          required_extensions: required,
          ...(schemaValue !== undefined ? { schema: schemaValue } : {}),
        },
      },
    ];
  },
};
