import * as Cap from '../capabilities';
import type { NodeDefinition } from '../types';

export const humanDefinition: NodeDefinition = {
  type: 'human',
  label: 'Human',
  description: 'A human user interacting with the surface',
  icon: '\uf007', // fa-user
  paletteIcon: 'fa-user',
  color: '#8b5cf6',
  shape: 'circle',
  defaultRadius: 16,
  resizable: true,
  resizeRange: { min: 16, max: 60 },
  draggable: true,
  containedInSurface: false,
  edgeConstrained: false,
  xWeight: 0.02,
  stage: 'decorative',
  cardinality: 'multi',
  paletteCategory: 'actor',
  hiddenFromPalette: true,
  paletteOrder: 1,
  dropMode: 'canvas',
  canvasOnly: true,
  deletable: false, // auto-injected actor; the surface always has one
  provides: [Cap.CONFIGURABLE],
  requires: {},
  incompleteReason: () => null,
};
