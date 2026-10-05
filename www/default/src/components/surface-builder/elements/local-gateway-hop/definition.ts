import McpProxyPanel from './McpProxyPanel';
import type { NodeDefinition } from '../types';

/**
 * Synthetic canvas-only node representing the local gateway in a
 * `fabric://` routing chain (the hop this gateway performs before
 * forwarding the request to a remote gateway).
 *
 * Hidden from the palette; auto-synthesised by
 * `synthesizeFabricCanvasNodes` whenever a Transit Point or the
 * surface Target has `target_endpoint`/`endpoint = "fabric://<gw>/<channel>"`.
 * Never persisted — it exists solely for visual representation.
 */
export const localGatewayHopDefinition: NodeDefinition = {
  type: 'local-gateway-hop',
  label: 'GW',
  description: 'Local gateway fabric:// hop to a remote gateway',
  icon: '\uf542', // fa-exchange-alt
  paletteIcon: 'fa-exchange-alt',
  color: '#36b9cc',
  shape: 'rect',
  defaultRadius: 20,
  resizable: false,
  resizeRange: { min: 16, max: 32 },
  draggable: false,
  containedInSurface: false,
  // The GW hop visualises the boundary at which traffic leaves this
  // gateway — it must always sit ON the surface perimeter, alongside
  // the AP and TPs. Marking it `edgeConstrained` opts it into the
  // canvas's perimeter-snap pipeline so drags keep it on the border.
  edgeConstrained: true,
  xWeight: 0.96,
  stage: 'decorative',
  cardinality: 'multi',
  paletteCategory: 'transitPoints',
  paletteOrder: 101,
  hiddenFromPalette: true,
  canvasOnly: true,
  dropMode: 'canvas',
  deletable: false,
  ConfigPanel: McpProxyPanel,
  provides: [],
  requires: {},
  incompleteReason: () => null,
};
