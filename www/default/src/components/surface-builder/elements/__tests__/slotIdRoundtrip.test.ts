/**
 * Slot identity round-trip — Tier 1A invariants.
 *
 * Asserts that `slotId` is the single source of truth for routing on
 * the AP→MA edge: a node hydrated from a runtime payload carries the
 * slot id of the path it came from, and the matching `buildPayload`
 * writes back to the same path.
 *
 * This is the structural guard that retires the bug class where
 * `policy` (and other elements with multiple possible payload paths)
 * could ghost-duplicate on save/reload because routing was inferred
 * from `parentId`/`direction` rather than persisted slot identity.
 */

import { registry } from '../index';
import { findSlotById } from '../edges/archetypes';

const seedSurface = (extra: Record<string, any> = {}) => ({
  name: 'roundtrip',
  status: 'active' as const,
  tags: [],
  access_point: { listener_url: 'https://gw/x' },
  target: { endpoint: 'https://upstream/y' },
  ...extra,
});

describe('slotId round-trip — ap-ma policy', () => {
  it('hydrates request:policy-inbound from access_point.inbound_policy with that slotId', () => {
    const payload = seedSurface({
      access_point: {
        listener_url: 'https://gw/x',
        inbound_policy: { policy_definition_id: 'pol-inbound' },
      },
    });
    const nodes = registry.nodesFromPayload(payload);
    const node = nodes.find(n => n.id === 'policy-inbound');
    expect(node).toBeDefined();
    expect(node!.slotId).toBe('request:policy-inbound');
  });

  it('hydrates request:policy from target.policy with that slotId', () => {
    const payload = seedSurface({
      target: {
        endpoint: 'https://upstream/y',
        policy: { policy_definition_id: 'pol-target' },
      },
    });
    const nodes = registry.nodesFromPayload(payload);
    const node = nodes.find(n => n.type === 'policy' && n.slotId === 'request:policy');
    expect(node).toBeDefined();
  });

  it('every typed ap-ma slot resolves back to its declared payload path via findSlotById', () => {
    // Every emitted node with a slotId must round-trip its slotId →
    // payloadPathTemplate. This is the contract `buildPayload` callers
    // rely on.
    const payload = seedSurface({
      access_point: {
        listener_url: 'https://gw/x',
        inbound_policy: { policy_definition_id: 'p1' },
        rate_limit: { requests: 10, window_secs: 1 },
      },
      target: {
        endpoint: 'https://upstream/y',
        policy: { policy_definition_id: 'p2' },
        response_policy: { policy_definition_id: 'p3' },
        custom_metadata: { foo: 'bar' },
      },
    });
    const nodes = registry.nodesFromPayload(payload);
    const slotted = nodes.filter(n => n.slotId);
    expect(slotted.length).toBeGreaterThan(0);
    for (const n of slotted) {
      const found = findSlotById(n.slotId!);
      expect(found).toBeDefined();
      expect(found!.slot.payloadPathTemplate).toBeTruthy();
    }
  });
});

describe('slotId round-trip — policy buildPayload routes by slotId', () => {
  // Reuses the registry's policy element — the actual production
  // routing path. We pass a node whose `parentId` would mislead the
  // legacy heuristic; only the slotId should determine the path.
  const ctx = (nodes: any[]) =>
    ({
      protocol: 'a2a' as const,
      surfaceMeta: { name: 't', tags: [], status: 'active' as const },
      allNodes: nodes,
      nodesOfType: (type: string) => nodes.filter(n => n.type === type),
      firstNodeOfType: (type: string) => nodes.find(n => n.type === type),
    }) as any;

  it('writes target.policy when slotId=request:policy regardless of parentId', () => {
    // A request-chain policy whose chain parent is the source endpoint
    // (the chain-splice fix's normal case). Legacy code would have
    // misrouted this to access_point.inbound_policy.
    const slices = registry.get('policy')!.buildPayload!(
      ctx([
        {
          id: 'policy',
          type: 'policy',
          parentId: 'access-point',
          slotId: 'request:policy',
          direction: 'request',
          config: { policy_definition_id: 'pol-target' },
        },
      ])
    );
    expect(slices).toHaveLength(1);
    expect(slices![0].path).toBe('target.policy');
  });

  it('writes access_point.inbound_policy when slotId=request:policy-inbound', () => {
    const slices = registry.get('policy')!.buildPayload!(
      ctx([
        {
          id: 'policy-inbound',
          type: 'policy',
          parentId: 'access-point',
          slotId: 'request:policy-inbound',
          direction: 'request',
          config: { policy_definition_id: 'pol-in' },
        },
      ])
    );
    expect(slices).toHaveLength(1);
    expect(slices![0].path).toBe('access_point.inbound_policy');
  });

  it('legacy fallback: id=policy-inbound without slotId still routes to inbound_policy', () => {
    const slices = registry.get('policy')!.buildPayload!(
      ctx([
        {
          id: 'policy-inbound',
          type: 'policy',
          parentId: 'access-point',
          direction: 'request',
          config: { policy_definition_id: 'pol-legacy' },
        },
      ])
    );
    expect(slices).toHaveLength(1);
    expect(slices![0].path).toBe('access_point.inbound_policy');
  });
});
