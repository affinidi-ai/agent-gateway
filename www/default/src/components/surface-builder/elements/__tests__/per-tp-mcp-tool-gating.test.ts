/**
 * Per-TP MCP Tool Gating build + hydration round-trip.
 *
 * Covers the `transit.points[i].mcp_tool_gating` slice produced by the TP
 * factory from a `mcp-tool-gating` node parented to that TP, and the inverse
 * hydration in `registry.nodesFromPayload`. The surface-wide external-target
 * gate (`target.mcp_tool_gating`) stays independent.
 */

import { registry } from '../index';
import type { SurfaceContext } from '../types';

function makeCtx(nodes: any[]): SurfaceContext {
  return {
    protocol: 'mcp',
    surfaceMeta: { name: 'per-tp-gating', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: type => nodes.filter(n => n.type === type),
    firstNodeOfType: type => nodes.find(n => n.type === type),
  };
}

function readPath(obj: any, path: string): any {
  return path.split('.').reduce((acc, k) => (acc == null ? acc : acc[k]), obj);
}

const baseNodes = [
  { id: 'ap', type: 'access-point', label: 'AP', configured: true, config: { route: '/api' } },
  {
    id: 'target',
    type: 'target',
    label: 'T',
    configured: true,
    config: { endpoint: 'https://upstream.example.com' },
  },
];

function makeTp() {
  return {
    id: 'tp-1',
    type: 'transit-point-mcp',
    label: '',
    configured: true,
    config: { target_endpoint: 'https://partner.example.com/mcp', alias: 'tp1' },
  };
}

function makeGatingNode(gates: any[], parentId = 'tp-1') {
  return {
    id: `mcp-tool-gating-${parentId}`,
    type: 'mcp-tool-gating',
    label: '',
    configured: true,
    parentId,
    direction: 'response' as const,
    slotId: 'response:mcp-tool-gating',
    config: { gates },
  };
}

const denyAdminGate = {
  id: 'gate-1',
  name: 'Block admin',
  action: { effect: 'deny', patterns: ['^admin_', '  '] },
};

describe('per-TP MCP tool gating', () => {
  it('TP factory writes mcp_tool_gating slice from a TP-parented node', () => {
    const node = makeGatingNode([denyAdminGate]);
    const payload = registry.buildPayload(makeCtx([...baseNodes, makeTp(), node]));
    const point = readPath(payload, 'transit.points')?.[0];
    // Whitespace pattern stripped by normalisation.
    expect(point?.mcp_tool_gating).toEqual({
      gates: [
        {
          id: 'gate-1',
          name: 'Block admin',
          action: { effect: 'deny', patterns: ['^admin_'] },
        },
      ],
    });
  });

  it('does not write the surface-wide target.mcp_tool_gating for a TP-parented node', () => {
    const node = makeGatingNode([denyAdminGate]);
    const payload = registry.buildPayload(makeCtx([...baseNodes, makeTp(), node]));
    expect(readPath(payload, 'target.mcp_tool_gating')).toBeUndefined();
  });

  it('TP factory omits mcp_tool_gating when no TP-parented node exists', () => {
    const payload = registry.buildPayload(makeCtx([...baseNodes, makeTp()]));
    const point = readPath(payload, 'transit.points')?.[0];
    expect(point?.mcp_tool_gating).toBeUndefined();
  });

  it('nodesFromPayload hydrates mcp_tool_gating back into a node parented to its TP', () => {
    const payload = {
      access_point: { route: '/api' },
      target: { endpoint: 'https://upstream.example.com' },
      transit: {
        points: [
          {
            id: 'tp-uuid',
            alias: 'tp1',
            target_endpoint: 'https://partner.example.com/mcp',
            protocol: 'mcp',
            mcp_tool_gating: {
              gates: [
                {
                  id: 'gate-1',
                  name: 'Block admin',
                  action: { effect: 'deny', patterns: ['^admin_'] },
                },
              ],
            },
          },
        ],
      },
    };
    const nodes = registry.nodesFromPayload(payload);
    const tpNode = nodes.find(n => n.type === 'transit-point-mcp');
    expect(tpNode).toBeDefined();
    const gatingNode = nodes.find(n => n.type === 'mcp-tool-gating' && n.parentId === tpNode!.id);
    expect(gatingNode).toBeDefined();
    expect(gatingNode!.slotId).toBe('response:mcp-tool-gating');
    expect(gatingNode!.direction).toBe('response');
    expect((gatingNode!.config as any).gates).toHaveLength(1);
  });

  it('round-trips build → hydrate → build to a stable slice', () => {
    const node = makeGatingNode([denyAdminGate]);
    const payload1 = registry.buildPayload(makeCtx([...baseNodes, makeTp(), node]));
    const p1: any = { transit: readPath(payload1, 'transit') };
    p1.access_point = { route: '/api' };
    p1.target = { endpoint: 'https://upstream.example.com' };
    const nodes = registry.nodesFromPayload(p1);
    const payload2 = registry.buildPayload(makeCtx(nodes));
    expect(readPath(payload2, 'transit.points')?.[0]?.mcp_tool_gating).toEqual(
      readPath(payload1, 'transit.points')?.[0]?.mcp_tool_gating
    );
  });
});
