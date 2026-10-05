/**
 * Per-TP Workload Binding build + hydration round-trip.
 *
 * Covers the `transit.points[i].workload_binding` slice produced by the
 * TP factory from a `workload-binding` node parented to that TP, and the
 * inverse hydration in `registry.nodesFromPayload`.
 */

import { registry } from '../index';
import type { SurfaceContext } from '../types';
import type { WorkloadBindingFormConfig } from '../workload-binding/config';

function makeCtx(nodes: any[]): SurfaceContext {
  return {
    protocol: 'a2a',
    surfaceMeta: { name: 'per-tp-wb', tags: [], status: 'active' },
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
    type: 'transit-point-a2a',
    label: '',
    configured: true,
    config: { target_endpoint: 'https://upstream.example.com', alias: 'tp1' },
  };
}

function makeWbNode(config: WorkloadBindingFormConfig) {
  return {
    id: 'workload-binding-tp-1',
    type: 'workload-binding',
    label: '',
    configured: true,
    parentId: 'tp-1',
    slotId: 'request:workload-binding',
    config,
  };
}

describe('per-TP workload binding', () => {
  it('TP factory writes workload_binding slice from a TP-parented node', () => {
    const wbNode = makeWbNode({
      enabled: true,
      caller_source: 'transit_token',
      caller_context_fields: ['sub', 'email'],
      chain_caller_credentials: false,
    });
    const payload = registry.buildPayload(makeCtx([...baseNodes, makeTp(), wbNode]));
    const point = readPath(payload, 'transit.points')?.[0];
    expect(point?.workload_binding).toEqual({
      enabled: true,
      caller_source: 'transit_token',
      caller_context_fields: ['sub', 'email'],
    });
  });

  it('TP factory serializes chain flag and omits empty caller fields', () => {
    const wbNode = makeWbNode({
      enabled: true,
      caller_source: 'authorization_bearer_jwt',
      caller_context_fields: [],
      chain_caller_credentials: true,
    });
    const payload = registry.buildPayload(makeCtx([...baseNodes, makeTp(), wbNode]));
    const point = readPath(payload, 'transit.points')?.[0];
    expect(point?.workload_binding).toEqual({
      enabled: true,
      caller_source: 'authorization_bearer_jwt',
      chain_caller_credentials: true,
    });
  });

  it('TP factory omits workload_binding when the node is disabled', () => {
    const wbNode = makeWbNode({
      enabled: false,
      caller_source: 'transit_token',
      caller_context_fields: ['sub'],
      chain_caller_credentials: false,
    });
    const payload = registry.buildPayload(makeCtx([...baseNodes, makeTp(), wbNode]));
    const point = readPath(payload, 'transit.points')?.[0];
    expect(point?.workload_binding).toBeUndefined();
  });

  it('TP factory omits workload_binding when no TP-parented node exists', () => {
    const payload = registry.buildPayload(makeCtx([...baseNodes, makeTp()]));
    const point = readPath(payload, 'transit.points')?.[0];
    expect(point?.workload_binding).toBeUndefined();
  });

  it('nodesFromPayload hydrates workload_binding back into a node parented to its TP', () => {
    const payload = {
      access_point: { route: '/api' },
      target: { endpoint: 'https://upstream.example.com' },
      transit: {
        points: [
          {
            id: 'tp-uuid',
            alias: 'tp1',
            target_endpoint: 'https://upstream.example.com',
            protocol: 'a2a',
            workload_binding: {
              enabled: true,
              caller_source: 'authorization_bearer_jwt',
              caller_context_fields: ['sub'],
              chain_caller_credentials: true,
            },
          },
        ],
      },
    };
    const nodes = registry.nodesFromPayload(payload);
    const tpNode = nodes.find(n => n.type === 'transit-point-a2a');
    expect(tpNode).toBeDefined();
    const wbNode = nodes.find(n => n.type === 'workload-binding' && n.parentId === tpNode!.id);
    expect(wbNode).toBeDefined();
    expect(wbNode!.config).toEqual({
      enabled: true,
      caller_source: 'authorization_bearer_jwt',
      caller_context_fields: ['sub'],
      chain_caller_credentials: true,
    });
    expect(wbNode!.slotId).toBe('request:workload-binding');
  });

  it('round-trips build → hydrate → build to a stable slice', () => {
    const wbNode = makeWbNode({
      enabled: true,
      caller_source: 'transit_token',
      caller_context_fields: ['sub', 'org'],
      chain_caller_credentials: true,
    });
    const payload1 = registry.buildPayload(makeCtx([...baseNodes, makeTp(), wbNode]));
    const p1: any = { transit: readPath(payload1, 'transit') };
    p1.access_point = { route: '/api' };
    p1.target = { endpoint: 'https://upstream.example.com' };
    const nodes = registry.nodesFromPayload(p1);
    const payload2 = registry.buildPayload(makeCtx(nodes));
    expect(readPath(payload2, 'transit.points')?.[0]?.workload_binding).toEqual(
      readPath(payload1, 'transit.points')?.[0]?.workload_binding
    );
  });
});
