import type { NodeDefinition } from '../types';
import RemoteChannelPanel from './RemoteChannelPanel';

/**
 * Synthetic canvas-only node depicting the channel endpoint on the
 * remote gateway that a `fabric://` route lands on. Renders as an
 * external actor hanging south of the synthesised `remote-gateway`.
 *
 * Hidden from the palette; auto-synthesised by
 * `synthesizeFabricCanvasNodes` whenever a TP or the surface Target
 * has `target_endpoint`/`endpoint = "fabric://<gw>/<channel>"`. The
 * user-editable name persists on the parent target/TP's config under
 * `fabric_remote_channel_name`.
 */
export const remoteChannelDefinition: NodeDefinition = {
  type: 'remote-channel',
  label: 'Remote Channel',
  description: 'Channel endpoint on the remote gateway',
  icon: '\uf0e8', // fa-sitemap
  paletteIcon: 'fa-sitemap',
  color: '#1cc88a',
  shape: 'circle',
  defaultRadius: 18,
  resizable: false,
  resizeRange: { min: 14, max: 24 },
  draggable: false,
  containedInSurface: false,
  edgeConstrained: false,
  xWeight: 0.98,
  stage: 'decorative',
  cardinality: 'multi',
  paletteCategory: 'transitPoints',
  paletteOrder: 102,
  hiddenFromPalette: true,
  canvasOnly: true,
  deletable: false,
  provides: [],
  requires: {},
  incompleteReason: () => null,
  ConfigPanel: RemoteChannelPanel,
};
