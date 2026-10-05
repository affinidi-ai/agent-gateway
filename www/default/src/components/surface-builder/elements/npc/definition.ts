import * as Cap from '../capabilities';
import type { NodeDefinition } from '../types';
import type { SurfaceNodeType } from '../../nodeTypes';
import NpcPanel from './NpcPanel';

interface NpcSpec {
  type: SurfaceNodeType;
  label: string;
  description: string;
  icon: string;
  paletteIcon: string;
  color: string;
  xWeight: number;
  paletteOrder: number;
}

const npcSpecs: NpcSpec[] = [
  {
    type: 'npc-actor',
    label: 'Actor',
    description: 'External actor or system using the surface',
    icon: '\uf007', // fa-user
    paletteIcon: 'fa-user',
    color: '#8b5cf6',
    xWeight: 0.1,
    paletteOrder: 1,
  },
  {
    type: 'npc-agent',
    label: 'Agent',
    description: 'External agent connected to this surface',
    icon: '\uf544', // fa-robot
    paletteIcon: 'fa-robot',
    color: '#6366f1',
    xWeight: 0.1,
    paletteOrder: 2,
  },
  {
    type: 'npc-endpoint',
    label: 'Endpoint',
    description: 'Generic external endpoint',
    icon: '\uf0ac', // fa-globe
    paletteIcon: 'fa-globe',
    color: '#64748b',
    xWeight: 0.9,
    paletteOrder: 3,
  },
  {
    type: 'npc-server',
    label: 'Server',
    description: 'Backend server or API',
    icon: '\uf233', // fa-server
    paletteIcon: 'fa-server',
    color: '#475569',
    xWeight: 0.9,
    paletteOrder: 4,
  },
  {
    type: 'npc-database',
    label: 'Database',
    description: 'Data store or database',
    icon: '\uf1c0', // fa-database
    paletteIcon: 'fa-database',
    color: '#0891b2',
    xWeight: 0.9,
    paletteOrder: 5,
  },
  {
    type: 'npc-service',
    label: 'Service',
    description: 'Generic service or microservice',
    icon: '\uf013', // fa-gear
    paletteIcon: 'fa-cog',
    color: '#7c3aed',
    xWeight: 0.9,
    paletteOrder: 6,
  },
];

function buildNpcDefinition(spec: NpcSpec): NodeDefinition {
  return {
    type: spec.type,
    label: spec.label,
    description: spec.description,
    icon: spec.icon,
    paletteIcon: spec.paletteIcon,
    color: spec.color,
    shape: 'circle',
    defaultRadius: 18,
    resizable: true,
    resizeRange: { min: 16, max: 60 },
    draggable: true,
    containedInSurface: false,
    edgeConstrained: false,
    xWeight: spec.xWeight,
    stage: 'decorative',
    cardinality: 'multi',
    paletteCategory: 'npc',
    paletteOrder: spec.paletteOrder,
    dropMode: 'canvas',
    canvasOnly: true,
    provides:
      spec.type === 'npc-endpoint' ? [Cap.CONFIGURABLE, Cap.IDENTITY_TARGET] : [Cap.CONFIGURABLE],
    requires: {},
    incompleteReason: () => null,
    ConfigPanel: NpcPanel,
  };
}

export const npcDefinitions: NodeDefinition[] = npcSpecs.map(buildNpcDefinition);
