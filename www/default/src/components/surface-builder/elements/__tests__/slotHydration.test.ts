/**
 * Slot-driven `nodesFromPayload` parity tests.
 *
 * Asserts that the slot-driven hydration of the AP↔MA edge produces a
 * canvas node for every typed slot whose payload path has a non-empty
 * slice, and that the emitted ids match what `useSurfaceBuilder.handleDrop`
 * mints (so save/reload round-trips through the same id).
 */

import { buildCanvasBlob, registry } from '../index';
import { deriveEdges } from '../edges/deriveEdges';
import { getArchetype, ANY_EDGE_MW } from '../edges/archetypes';
import { hydrateSurfaceCanvas, nodesFromSurface } from '../../nodesFromSurface';

const seedSurface = (extra: Record<string, any> = {}) => ({
  name: 'parity',
  status: 'active' as const,
  tags: [],
  access_point: { listener_url: 'https://gw/x' },
  target: { endpoint: 'https://upstream/y' },
  ...extra,
});

describe('nodesFromPayload — ap-ma slot-driven hydration', () => {
  const apMa = getArchetype('ap-ma')!;
  const apMaTypedSlots = apMa.slots.filter(s => s.payloadPathTemplate && s.accepts !== ANY_EDGE_MW);

  it('hydrates every typed ap-ma slot from a payload that fills its path', () => {
    // Build a payload with every typed slot path populated by a
    // throw-away truthy slice; assert every one comes back as a node.
    // Vec-typed slots on the wire (paths ending in `_list`, e.g.
    // `trust_check_list`) need a single-element array; everything else
    // gets the legacy `{ _filled: true }` object marker. Slot
    // `cardinality` is a palette/UX concern (does the slot accept
    // multiple drops?) and does not reflect the underlying wire shape.
    const payload: any = seedSurface();
    for (const slot of apMaTypedSlots) {
      const segs = slot.payloadPathTemplate.split('.');
      let cur = payload;
      for (let i = 0; i < segs.length - 1; i++) {
        cur[segs[i]] = cur[segs[i]] ?? {};
        cur = cur[segs[i]];
      }
      const leaf = segs[segs.length - 1];
      const isVecPath = leaf.endsWith('_list') || slot.cardinality === 'many';
      // Trust-recorder's wire shape is `{ entries: [...] }` — a
      // populated slice needs at least one entry for the custom
      // hydration block to emit a node.
      if (slot.payloadPathTemplate === 'access_point.trust_recorder') {
        cur[leaf] = { entries: [{ _filled: true }] };
      } else {
        cur[leaf] = isVecPath ? [{ _filled: true }] : { _filled: true };
      }
    }
    const nodes = registry.nodesFromPayload(payload);
    for (const slot of apMaTypedSlots) {
      const expectedType = slot.accepts[0];
      const matches = nodes.filter(n => n.type === expectedType);
      expect(matches.length).toBeGreaterThan(0);
    }
  });

  it('per-endpoint slot ids match the drop-handler canonical id format', () => {
    const payload: any = seedSurface({
      access_point: {
        listener_url: 'https://gw/x',
        inbound_policy: { policy_definition_id: 'inbound-pol' },
      },
    });
    const nodes = registry.nodesFromPayload(payload);
    // Inbound-policy slot is `ownedBy: 'source'` on AP; legacy id
    // suffix is `policy-inbound`.
    expect(nodes.find(n => n.id === 'policy-inbound')).toBeDefined();
  });

  it('response-direction slots emit `<type>-response` ids with direction:"response"', () => {
    const payload = seedSurface({
      target: {
        endpoint: 'https://upstream/y',
        response_custom_metadata: { foo: 'bar' },
      },
    });
    const nodes = registry.nodesFromPayload(payload);
    const cm = nodes.find(n => n.id === 'custom-metadata-response');
    expect(cm).toBeDefined();
    expect(cm!.direction).toBe('response');
  });

  it('skips slots whose payload slice is missing or empty', () => {
    const payload = seedSurface();
    const nodes = registry.nodesFromPayload(payload);
    // No edge mw was filled → no edge mw nodes should appear (only the
    // anchor singletons access-point + target).
    const types = new Set<string>(nodes.map(n => n.type));
    for (const slot of apMaTypedSlots) {
      const t = slot.accepts[0] as string;
      expect(types.has(t)).toBe(false);
    }
  });

  it('edge-binds Caller Context when hydrating a runtime-only surface', () => {
    const payload = seedSurface({
      access_point: {
        listener_url: 'https://gw/x',
        caller_authentication: { methods: [{ method_type: 'jwt_bearer' }] },
      },
    });

    const nodes = nodesFromSurface(payload as any);
    const callerAuth = nodes.find(node => node.id === 'caller-auth');
    const target = nodes.find(node => node.id === 'target');
    const apMa = deriveEdges(nodes).find(edge => edge.archetype === 'ap-ma');

    expect(callerAuth).toMatchObject({
      parentId: 'access-point',
      slotId: 'request:caller-auth',
    });
    expect(target?.parentId).toBe('caller-auth');
    expect(apMa?.slots.get('request:caller-auth')).toEqual(['caller-auth']);
  });

  it('preserves the slot-ordered request chain across canvas save and reload', () => {
    const runtimePayload = seedSurface({
      access_point: {
        listener_url: 'https://gw/x',
        caller_authentication: { methods: [{ method_type: 'jwt_bearer' }] },
        rate_limit: { requests: 10, window_secs: 1 },
      },
      target: {
        endpoint: 'https://upstream/y',
        custom_metadata: { environment: 'test' },
      },
    });
    const hydrated = nodesFromSurface(runtimePayload as any);
    const reloaded = nodesFromSurface({
      ...runtimePayload,
      canvas: buildCanvasBlob(hydrated),
    } as any);

    for (const nodes of [hydrated, reloaded]) {
      expect(nodes.find(node => node.id === 'caller-auth')?.parentId).toBe('access-point');
      expect(nodes.find(node => node.id === 'rate-limit')?.parentId).toBe('caller-auth');
      expect(nodes.find(node => node.id === 'custom-metadata')?.parentId).toBe('rate-limit');
      expect(nodes.find(node => node.id === 'target')?.parentId).toBe('custom-metadata');
      expect(
        deriveEdges(nodes)
          .find(edge => edge.archetype === 'ap-ma')
          ?.slots.get('request:caller-auth')
      ).toEqual(['caller-auth']);
    }
  });

  it('normalizes and lays out an API-created responder trust check and policy', () => {
    const runtimePayload: any = seedSurface({
      access_point: {
        listener_url: 'https://gw/x',
        trust_check_list: [
          {
            id: 'full-g2g-requester-recognition',
            query_type: 'recognition',
          },
        ],
      },
      target: {
        endpoint: 'https://upstream/y',
        policy: {
          policy_definition_id: 'full-g2g-gw2-inbound',
          require_agent_context: false,
        },
      },
      canvas: {
        version: 1,
        nodes: [
          {
            id: 'trust-check-caller',
            type: 'trust-check',
            parentId: 'access-point',
            slotId: 'request:trust-check-access_point_trust_check_list',
          },
          {
            id: 'policy',
            type: 'policy',
            parentId: 'trust-check-caller',
            slotId: 'request:policy',
          },
          {
            id: 'target',
            type: 'target',
            parentId: 'access-point',
          },
        ],
      },
    });

    const hydrated = nodesFromSurface(runtimePayload as any);
    const reloaded = nodesFromSurface({
      ...runtimePayload,
      canvas: buildCanvasBlob(hydrated),
    } as any);

    for (const nodes of [hydrated, reloaded]) {
      expect(nodes.find(node => node.id === 'trust-check-caller')).toMatchObject({
        parentId: 'access-point',
        slotId: 'request:trust-check-access_point_trust_check_list',
      });
      expect(nodes.find(node => node.id === 'policy')).toMatchObject({
        parentId: 'trust-check-caller',
        slotId: 'request:policy',
      });
      expect(nodes.find(node => node.id === 'target')?.parentId).toBe('policy');
      expect(
        nodes
          .filter(node => ['trust-check-caller', 'policy'].includes(node.id))
          .every(node => node.position)
      ).toBe(true);
      const edge = deriveEdges(nodes).find(candidate => candidate.archetype === 'ap-ma');
      expect(edge?.slots.get('request:trust-check-access_point_trust_check_list')).toEqual([
        'trust-check-caller',
      ]);
      expect(edge?.slots.get('request:policy')).toEqual(['policy']);

      const roundTripped = registry.buildPayload({
        protocol: 'a2a',
        surfaceMeta: { name: 'parity', status: 'active', tags: [] },
        allNodes: nodes,
        nodesOfType: (type: string) => nodes.filter(node => node.type === type),
        firstNodeOfType: (type: string) => nodes.find(node => node.type === type),
      } as any);
      expect(roundTripped.access_point.trust_check_list).toMatchObject(
        runtimePayload.access_point.trust_check_list
      );
      expect(roundTripped.target.policy.policy_definition_id).toBe(
        runtimePayload.target.policy.policy_definition_id
      );
      expect(roundTripped.target.policy.require_agent_context ?? false).toBe(false);
    }
  });

  it('lays out a partially positioned requester graph without overlap or drift', () => {
    const runtimePayload: any = seedSurface({
      access_point: {
        listener_url: 'https://gw/x',
        trust_recorder: {
          entries: [{ trust_registry_id: 'requester-registry' }],
        },
      },
      target: {
        endpoint: 'https://protected-agent.example.com/a2a',
        trust_check_list: [
          {
            id: 'responder-recognition',
            query_type: 'recognition',
          },
        ],
      },
      identity_slots: {
        protected: { type: 'static', did: 'did:example:protected-agent' },
      },
      transit: {
        points: [
          {
            alias: 'gw2',
            protocol: 'a2a',
            target_endpoint: 'https://gw2.example.com/a2a',
            policy: { policy_definition_id: 'gw1-outbound-policy' },
            managed_identity: { type: 'static', did: 'did:example:requester-agent' },
            workload_binding: {
              enabled: true,
              caller_source: 'transit_token',
              caller_context_fields: ['sub'],
            },
          },
        ],
      },
      canvas: {
        version: 1,
        surface: { width: 336, height: 294 },
        nodes: [
          { id: 'access-point', type: 'access-point' },
          { id: 'target-variant', type: 'target-variant' },
          {
            id: 'transit-point-a2a-1',
            type: 'transit-point-a2a',
            parentId: 'access-point',
          },
          { id: '__human__', type: 'human' },
          { id: '__caller__', type: 'caller' },
          {
            id: 'trust-recorder-target-response',
            type: 'trust-recorder',
            parentId: 'target',
            slotId: 'response:trust-recorder',
          },
          {
            id: 'trust-check-target',
            type: 'trust-check',
            parentId: 'target',
            slotId: 'request:trust-check-target_trust_check_list',
          },
          {
            id: 'policy-transit-point-a2a-1',
            type: 'policy',
            parentId: 'transit-point-a2a-1',
            slotId: 'request:policy',
          },
          { id: 'target', type: 'target', position: { x: 9.06, y: 1.97 } },
          {
            id: 'identity-protected',
            type: 'identity',
            parentId: 'target',
            slotId: 'response:identity-protected',
            position: { x: -134, y: 151 },
          },
          {
            id: 'identity-transit-point-a2a-1-request',
            type: 'identity',
            parentId: 'transit-point-a2a-1',
            slotId: 'request:identity-managed_identity',
            position: { x: 145, y: 94 },
          },
          {
            id: 'workload-binding-transit-point-a2a-1',
            type: 'workload-binding',
            parentId: 'transit-point-a2a-1',
            slotId: 'request:workload-binding',
            position: { x: 147, y: -18 },
          },
        ],
      },
    });

    const hydration = hydrateSurfaceCanvas(runtimePayload);
    const hydrated = hydration.nodes;
    const reloadedHydration = hydrateSurfaceCanvas({
      ...runtimePayload,
      canvas: buildCanvasBlob(hydrated, {
        surfaceSize: hydration.surfaceSize ?? undefined,
      }),
    });
    const reloaded = reloadedHydration.nodes;

    const visible = (nodes: typeof hydrated) =>
      nodes.filter(node => node.type !== 'target-variant');
    const positions = (nodes: typeof hydrated) =>
      new Map(visible(nodes).map(node => [node.id, node.position] as const));

    for (const nodes of [hydrated, reloaded]) {
      expect(visible(nodes).every(node => node.position)).toBe(true);
      expect(
        new Set(
          visible(nodes).map(
            node => `${node.position?.x ?? 'missing'}:${node.position?.y ?? 'missing'}`
          )
        ).size
      ).toBe(visible(nodes).length);
      expect(nodes.find(node => node.id === 'policy-transit-point-a2a-1')).toMatchObject({
        parentId: 'transit-point-a2a-1',
        slotId: 'request:policy',
      });
      expect(nodes.find(node => node.id === 'trust-check-target')).toMatchObject({
        parentId: 'target',
        slotId: 'request:trust-check-target_trust_check_list',
      });
      expect(nodes.find(node => node.id === 'trust-recorder-target-response')).toMatchObject({
        parentId: 'target',
        slotId: 'response:trust-recorder',
      });
      for (let leftIndex = 0; leftIndex < visible(nodes).length; leftIndex += 1) {
        for (let rightIndex = leftIndex + 1; rightIndex < visible(nodes).length; rightIndex += 1) {
          const left = visible(nodes)[leftIndex].position!;
          const right = visible(nodes)[rightIndex].position!;
          expect(Math.hypot(left.x - right.x, left.y - right.y)).toBeGreaterThan(35);
        }
      }
    }
    expect(hydration.didAutoLayout).toBe(true);
    expect(hydration.surfaceSize?.width).toBeGreaterThan(336);
    expect(hydration.surfaceSize?.height).toBeGreaterThan(294);
    expect(hydration.view).toBeNull();
    expect(reloadedHydration.didAutoLayout).toBe(false);
    expect(reloadedHydration.surfaceSize).toEqual(hydration.surfaceSize);
    expect(positions(reloaded)).toEqual(positions(hydrated));

    const roundTripped = registry.buildPayload({
      protocol: 'a2a',
      surfaceMeta: { name: 'parity', status: 'active', tags: [] },
      allNodes: reloaded,
      nodesOfType: (type: string) => reloaded.filter(node => node.type === type),
      firstNodeOfType: (type: string) => reloaded.find(node => node.type === type),
    } as any);
    expect(roundTripped.access_point.trust_recorder.entries).toHaveLength(1);
    expect(roundTripped.target.trust_check_list).toMatchObject(
      runtimePayload.target.trust_check_list
    );
    expect(roundTripped.identity_slots.protected).toBeDefined();
    expect(roundTripped.transit.points[0].policy.policy_definition_id).toBe('gw1-outbound-policy');
    expect(roundTripped.transit.points[0].managed_identity).toBeDefined();
    expect(roundTripped.transit.points[0].workload_binding).toBeDefined();
  });
});
