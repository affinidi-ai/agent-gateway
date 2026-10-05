/**
 * Per-TP managed identity build + hydration round-trip.
 *
 * Covers the new `transit.points[i].managed_identity` slice produced
 * by the TP factory from an `identity` node parented to that TP, and
 * the inverse hydration in `registry.nodesFromPayload`.
 */

import { registry } from '../index';
import type { SurfaceContext } from '../types';

function makeCtx(nodes: any[]): SurfaceContext {
  return {
    protocol: 'a2a',
    surfaceMeta: { name: 'per-tp-id', tags: [], status: 'active' },
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

describe('per-TP managed identity', () => {
  it('TP factory writes managed_identity slice from a TP-parented identity node', () => {
    const tp = {
      id: 'tp-1',
      type: 'transit-point-a2a',
      label: '',
      configured: true,
      config: { target_endpoint: 'https://upstream.example.com', alias: 'tp1' },
    };
    const idNode = {
      id: 'identity-tp-1-request',
      type: 'identity',
      label: '',
      configured: true,
      direction: 'request' as const,
      parentId: 'tp-1',
      slotId: 'request:identity-managed_identity',
      config: {
        type: 'from_payload',
        meta_field: 'agentIdentity',
        fields: ['name'],
        json_schema: { type: 'object', required: [], properties: {} },
      },
    };
    const payload = registry.buildPayload(makeCtx([...baseNodes, tp, idNode]));
    const point = readPath(payload, 'transit.points')?.[0];
    expect(point?.managed_identity).toEqual({
      type: 'from_payload',
      meta_field: 'agentIdentity',
      fields: ['name'],
      json_schema: { type: 'object', required: [], properties: {} },
    });
  });

  it('TP factory omits managed_identity when no TP-parented identity exists', () => {
    const tp = {
      id: 'tp-1',
      type: 'transit-point-a2a',
      label: '',
      configured: true,
      config: { target_endpoint: 'https://upstream.example.com', alias: 'tp1' },
    };
    const payload = registry.buildPayload(makeCtx([...baseNodes, tp]));
    const point = readPath(payload, 'transit.points')?.[0];
    expect(point?.managed_identity).toBeUndefined();
  });

  it('identity element skips TP-parented nodes (no double-write to identity_slots.*)', () => {
    const tp = {
      id: 'tp-1',
      type: 'transit-point-a2a',
      label: '',
      configured: true,
      config: { target_endpoint: 'https://upstream.example.com', alias: 'tp1' },
    };
    const idNode = {
      id: 'identity-tp-1-request',
      type: 'identity',
      label: '',
      configured: true,
      direction: 'request' as const,
      parentId: 'tp-1',
      slotId: 'request:identity-managed_identity',
      config: { type: 'from_payload', meta_field: 'agentIdentity' },
    };
    const payload = registry.buildPayload(makeCtx([...baseNodes, tp, idNode]));
    expect(readPath(payload, 'identity_slots')).toBeUndefined();
  });

  it('nodesFromPayload hydrates managed_identity back into an identity node parented to its TP', () => {
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
            managed_identity: {
              type: 'from_payload',
              meta_field: 'agentIdentity',
              fields: ['name'],
            },
          },
        ],
      },
    };
    const nodes = registry.nodesFromPayload(payload);
    const tpNode = nodes.find(n => n.type === 'transit-point-a2a');
    expect(tpNode).toBeDefined();
    const idNode = nodes.find(n => n.type === 'identity' && n.parentId === tpNode!.id);
    expect(idNode).toBeDefined();
    expect(idNode!.direction).toBe('request');
    expect(idNode!.slotId).toBe('request:identity-managed_identity');
    expect(idNode!.config.meta_field).toBe('agentIdentity');
    expect(idNode!.config.fields).toEqual(['name']);
  });
});
