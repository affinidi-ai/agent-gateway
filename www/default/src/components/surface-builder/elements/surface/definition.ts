import type { NodeDefinition } from '../types';
import SurfacePanel from './SurfacePanel';

/**
 * The Surface itself (root node). Auto-created by the builder; never in the palette.
 * Provides only the capability for child nodes to attach as middleware around it.
 * Selecting the surface on the canvas opens its property panel
 * (`SurfacePanel`), which edits the page-level meta via `SurfaceMetaContext`.
 */
export const surfaceDefinition: NodeDefinition = {
  type: 'surface',
  label: 'Surface',
  description: 'The Agent Surface root node',
  icon: '\uf544', // fa-robot
  paletteIcon: 'fa-cube',
  color: '#4e73df',
  shape: 'rect',
  defaultRadius: 52,
  resizable: true,
  resizeRange: { min: 200, max: 800 },
  draggable: true,
  containedInSurface: false,
  edgeConstrained: false,
  xWeight: 0.5,
  stage: 'middleware', // not really; surface is a container
  cardinality: 'singleton',
  paletteCategory: 'transitPoints',
  paletteOrder: 0,
  dropMode: 'canvas',
  hiddenFromPalette: true,
  deletable: false, // the surface itself cannot be removed
  provides: [],
  requires: {},
  incompleteReason: () => null,
  ConfigPanel: SurfacePanel,
};
