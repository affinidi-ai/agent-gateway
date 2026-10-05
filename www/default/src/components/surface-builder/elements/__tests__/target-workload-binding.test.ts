/**
 * Primary-target (MA→EXT) Workload Binding build + hydration round-trip.
 *
 * Covers the `target.workload_binding` slice the workload-binding element
 * owns on the `ma-external` edge (a node parented to the Managed Agent),
 * and the inverse hydration in `registry.nodesFromPayload`. The per-TP
 * path (`transit.points[i].workload_binding`) is covered separately in
 * `per-tp-workload-binding.test.ts`; here we assert the two paths do not
 * cross-contaminate.
 */

import { registry } from '../index';
import type { SurfaceContext } from '../types';
import type { WorkloadBindingFormConfig } from '../workload-binding/config';

function makeCtx(nodes: any[]): SurfaceContext {
  return {
    protocol: 'a2a',
    surfaceMeta: { name: 'target-wb', tags: [], status: 'active' },
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

function makeTargetWbNode(config: WorkloadBindingFormConfig) {
  return {
    id: 'workload-binding-target',
    type: 'workload-binding',
    label: '',
    configured: true,
    parentId: 'target',
    slotId: 'request:workload-binding',
    config,
  };
}

describe('primary-target (MA→EXT) workload binding', () => {
  it('writes target.workload_binding from a target-parented node', () => {
    const node = makeTargetWbNode({
      enabled: true,
      caller_source: 'authorization_bearer_jwt',
      caller_context_fields: ['sub', 'email'],
      chain_caller_credentials: false,
    });
    const payload = registry.buildPayload(makeCtx([...baseNodes, node]));
    expect(readPath(payload, 'target.workload_binding')).toEqual({
      enabled: true,
      caller_source: 'authorization_bearer_jwt',
      caller_context_fields: ['sub', 'email'],
    });
  });

  it('omits target.workload_binding when the node is disabled', () => {
    const node = makeTargetWbNode({
      enabled: false,
      caller_source: 'authorization_bearer_jwt',
      caller_context_fields: ['sub'],
      chain_caller_credentials: false,
    });
    const payload = registry.buildPayload(makeCtx([...baseNodes, node]));
    expect(readPath(payload, 'target.workload_binding')).toBeUndefined();
  });

  it('does NOT write target.workload_binding for a TP-parented node', () => {
    const tp = {
      id: 'tp-1',
      type: 'transit-point-a2a',
      label: '',
      configured: true,
      config: { target_endpoint: 'https://upstream.example.com', alias: 'tp1' },
    };
    const tpWbNode = {
      id: 'workload-binding-tp-1',
      type: 'workload-binding',
      label: '',
      configured: true,
      parentId: 'tp-1',
      slotId: 'request:workload-binding',
      config: {
        enabled: true,
        caller_source: 'transit_token',
        caller_context_fields: ['sub'],
        chain_caller_credentials: false,
      } as WorkloadBindingFormConfig,
    };
    const payload = registry.buildPayload(makeCtx([...baseNodes, tp, tpWbNode]));
    expect(readPath(payload, 'target.workload_binding')).toBeUndefined();
    expect(readPath(payload, 'transit.points')?.[0]?.workload_binding).toEqual({
      enabled: true,
      caller_source: 'transit_token',
      caller_context_fields: ['sub'],
    });
  });

  it('hydrates target.workload_binding into a node parented on the target', () => {
    const payload = {
      access_point: { route: '/api' },
      target: {
        endpoint: 'https://upstream.example.com',
        workload_binding: {
          enabled: true,
          caller_source: 'authorization_bearer_jwt',
          caller_context_fields: ['sub'],
          chain_caller_credentials: true,
        },
      },
    };
    const nodes = registry.nodesFromPayload(payload);
    const wbNode = nodes.find(n => n.type === 'workload-binding' && n.parentId === 'target');
    expect(wbNode).toBeDefined();
    expect(wbNode!.slotId).toBe('request:workload-binding');
    expect(wbNode!.config).toEqual({
      enabled: true,
      caller_source: 'authorization_bearer_jwt',
      caller_context_fields: ['sub'],
      chain_caller_credentials: true,
    });
  });

  it('round-trips build → hydrate for the target leg', () => {
    const node = makeTargetWbNode({
      enabled: true,
      caller_source: 'authorization_bearer_jwt',
      caller_context_fields: ['sub', 'org'],
      chain_caller_credentials: true,
    });
    const payload = registry.buildPayload(makeCtx([...baseNodes, node]));
    const nodes = registry.nodesFromPayload(payload);
    const wbNode = nodes.find(n => n.type === 'workload-binding' && n.parentId === 'target');
    expect(wbNode?.config).toEqual({
      enabled: true,
      caller_source: 'authorization_bearer_jwt',
      caller_context_fields: ['sub', 'org'],
      chain_caller_credentials: true,
    });
  });
});
