import * as Cap from '../capabilities';
import type { NodeDefinition, PayloadSlice } from '../types';
import type { CanvasNode } from '../../SurfaceCanvas';
import { isTransitPointType } from '../edges/archetypes';
import {
  HEADER_METADATA_EXTENSION_URI,
  type HeaderMetadataMappingConfig,
  validateHeaderMetadataMapping,
} from '../_shared/headerMetadataMapping';
import MetadataExtractionPanel from './MetadataExtractionPanel';
import { DOCS_URL } from '../../../../config/docs';

export function headerMetadataMappingToWire(
  input: HeaderMetadataMappingConfig | undefined
): HeaderMetadataMappingConfig | undefined {
  if (!input || typeof input !== 'object') return undefined;
  const headers = Array.isArray(input.headers)
    ? input.headers
        .map(row => ({
          header: typeof row?.header === 'string' ? row.header.trim() : '',
          field: typeof row?.field === 'string' ? row.field.trim() : '',
        }))
        .filter(row => row.header || row.field)
    : [];
  if (headers.length === 0) {
    return undefined;
  }
  return {
    extension_uri:
      typeof input.extension_uri === 'string'
        ? input.extension_uri.trim()
        : HEADER_METADATA_EXTENSION_URI,
    headers,
    strip_mapped_headers: input.strip_mapped_headers !== false,
  };
}

function parentIsTransitPoint(node: CanvasNode, allNodes: CanvasNode[]): boolean {
  const parent = node.parentId ? allNodes.find(n => n.id === node.parentId) : undefined;
  return !!parent && isTransitPointType(parent.type);
}

export const metadataExtractionDefinition: NodeDefinition = {
  type: 'metadata-extraction',
  label: 'Metadata Extraction',
  description: 'Map request headers into protocol metadata before downstream controls run',
  icon: '\uf0ae', // fa-tasks
  paletteIcon: 'fa-table-list',
  color: '#6f42c1',
  shape: 'circle',
  defaultRadius: 14,
  resizable: true,
  resizeRange: { min: 16, max: 60 },
  draggable: true,
  containedInSurface: false,
  edgeConstrained: false,
  xWeight: 0.55,
  stage: 'middleware',
  cardinality: 'multi',
  paletteCategory: 'enhancement',
  paletteOrder: 5,
  dropMode: 'edge',
  protocols: ['a2a', 'ap2'],
  help: {
    title: 'Metadata Extraction',
    docLink: DOCS_URL.metadataElements,
    bodyHtml: `
      <p>Extract values from selected HTTP request headers and normalize
      them into protocol metadata before identity, policy, Trust Check,
      Workload Binding, and forwarding controls run.</p>
      <p>Use this when an upstream caller or managed agent can present
      metadata-like evidence only as request headers but downstream
      controls need to read it from the protocol metadata namespace.</p>
      <p>Metadata Extraction uses Header Metadata Mapping and persists to
      the Access Point or Transit Point header mapping fields. It does
      not inject arbitrary key/value metadata.</p>
    `,
  },
  directionality: 'request',
  provides: [Cap.PIPELINE_EDGE, Cap.CONFIGURABLE],
  requires: {
    dropOnEdge: [Cap.METADATA_TARGET],
  },
  incompleteReason: c => {
    const mapping = headerMetadataMappingToWire(c.header_metadata_mapping);
    if (!mapping) return 'Configure at least one header mapping';
    const headerErrors = validateHeaderMetadataMapping(c.header_metadata_mapping);
    if (headerErrors.length > 0) return headerErrors[0].message;
    return null;
  },
  ConfigPanel: MetadataExtractionPanel,
  FullscreenPanel: MetadataExtractionPanel,
  payloadPath: 'access_point.header_metadata_mapping',
  configFromPayload: slice => ({ header_metadata_mapping: slice }),
  buildPayload: ctx => {
    const all = ctx.nodesOfType('metadata-extraction');
    if (all.length === 0) return undefined;
    const requestNodes = all.filter(n => (n.direction ?? 'request') === 'request');
    const apNodes = requestNodes.filter(n => !parentIsTransitPoint(n, ctx.allNodes));
    const apHeaderMapping = headerMetadataMappingToWire(
      apNodes.find(n => n.config?.header_metadata_mapping)?.config?.header_metadata_mapping
    );
    const slices: PayloadSlice[] = [];
    if (apHeaderMapping) {
      slices.push({ path: 'access_point.header_metadata_mapping', value: apHeaderMapping });
    }
    return slices.length > 0 ? slices : undefined;
  },
};
