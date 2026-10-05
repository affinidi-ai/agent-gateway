import * as Cap from '../capabilities';
import type { NodeDefinition } from '../types';

export const callerDefinition: NodeDefinition = {
  type: 'caller',
  label: 'External Agent',
  description: 'An external agent invoking the surface',
  icon: '\uf544', // fa-robot
  paletteIcon: 'fa-robot',
  color: '#6366f1',
  shape: 'circle',
  defaultRadius: 20,
  resizable: true,
  resizeRange: { min: 16, max: 60 },
  draggable: true,
  containedInSurface: false,
  edgeConstrained: false,
  xWeight: 0.05,
  stage: 'decorative',
  cardinality: 'multi',
  paletteCategory: 'actor',
  hiddenFromPalette: true,
  paletteOrder: 2,
  dropMode: 'canvas',
  canvasOnly: true,
  deletable: false, // auto-injected actor; the surface always has one
  provides: [Cap.CONFIGURABLE],
  requires: {},
  incompleteReason: () => null,
};
