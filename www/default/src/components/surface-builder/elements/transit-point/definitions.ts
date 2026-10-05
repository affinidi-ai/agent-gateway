import { makeTransitPointDefinition } from './factory';

export const transitPointA2aDefinition = makeTransitPointDefinition({
  type: 'transit-point-a2a',
  protocol: 'a2a',
  label: 'A2A',
  color: '#f6c23e',
  paletteOrder: 3,
  isPayloadCoordinator: true,
});

export const transitPointMcpDefinition = makeTransitPointDefinition({
  type: 'transit-point-mcp',
  protocol: 'mcp',
  label: 'MCP',
  color: '#36b9cc',
  paletteOrder: 4,
});

export const transitPointAp2Definition = makeTransitPointDefinition({
  type: 'transit-point-ap2',
  protocol: 'ap2',
  label: 'AP2',
  color: '#e74a3b',
  paletteOrder: 5,
  // AP2 is experimental and no longer offered as a new creation option.
  // hiddenFromPalette only removes the create-flow entry, so any AP2
  // Transit Point created directly via the API would still render and
  // edit normally.
  hiddenFromPalette: true,
});
