import * as Cap from '../capabilities';
import type { NodeDefinition } from '../types';
import RemoteGatewayPanel from './RemoteGatewayPanel';

/**
 * Synthetic canvas-only node depicting the destination of a fabric://
 * routing target — the remote gateway and the remote surface that
 * receives the request after it leaves this gateway over the G2G
 * connection.
 *
 * Hidden from the palette; auto-synthesised by
 * `synthesizeFabricCanvasNodes` whenever a TP or the surface Target
 * has `target_endpoint`/`endpoint = "fabric://<gw>/<surface>"`. The
 * config carries the resolved `gateway_id` and `gateway_surface` so
 * the panel can render names and a click-through link to the
 * dashboard pages for each.
 */
export const remoteGatewayDefinition: NodeDefinition = {
  type: 'remote-gateway',
  label: 'Remote GW',
  description: 'Destination gateway and surface reached over fabric://',
  icon: '\uf6ff', // fa-network-wired
  paletteIcon: 'fa-network-wired',
  color: '#1cc88a',
  shape: 'rect',
  defaultRadius: 24,
  resizable: false,
  resizeRange: { min: 18, max: 36 },
  draggable: false,
  containedInSurface: false,
  edgeConstrained: false,
  xWeight: 0.98,
  stage: 'decorative',
  cardinality: 'multi',
  paletteCategory: 'transitPoints',
  paletteOrder: 100,
  hiddenFromPalette: true,
  canvasOnly: true,
  deletable: false,
  provides: [Cap.CONFIGURABLE, Cap.IDENTITY_TARGET],
  requires: {},
  incompleteReason: () => null,
  ConfigPanel: RemoteGatewayPanel,
};
