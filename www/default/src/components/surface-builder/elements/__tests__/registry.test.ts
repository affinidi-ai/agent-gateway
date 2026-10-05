import { registry } from '../index';
import * as Cap from '../capabilities';
import type { SurfaceContext } from '../types';
import {
  POLICY_DEFINITIONS_LOADING_REASON,
  hasPolicyDefinitionReference,
  policyDefinitionsBlockingReason,
  type SurfacePolicyDefinitionLoadState,
} from '../policy/status';

describe('ElementRegistry', () => {
  describe('registration', () => {
    it('registers all 33 element types', () => {
      const types = registry
        .all()
        .map(d => d.type)
        .sort();
      expect(types).toEqual(
        [
          'access-point',
          'caller',
          'caller-auth',
          'credential-delegation',
          'custom-metadata',
          'extension-rules',
          'extension-validation',
          'human',
          'identity',
          'local-gateway-hop',
          'mcp-tool-gating',
          'metadata-extraction',
          'networking',
          'npc-actor',
          'npc-agent',
          'npc-database',
          'npc-endpoint',
          'npc-server',
          'npc-service',
          'payment',
          'policy',
          'rate-limit',
          'remote-channel',
          'remote-gateway',
          'surface',
          'target',
          'target-variant',
          'transit-point-a2a',
          'transit-point-ap2',
          'transit-point-mcp',
          'trust-check',
          'trust-recorder',
          'workload-binding',
        ].sort()
      );
    });

    it('every definition has matching label, color and icon', () => {
      for (const def of registry.all()) {
        expect(def.label).toBeTruthy();
        expect(def.color).toMatch(/^#[0-9a-f]{3,8}$/i);
        expect(def.icon).toBeTruthy();
        expect(def.defaultRadius).toBeGreaterThan(0);
      }
    });
  });

  describe('isConfigured / getIncompleteReason', () => {
    it('treats missing access-point route as incomplete', () => {
      expect(registry.isConfigured('access-point', {})).toBe(false);
      expect(registry.getIncompleteReason('access-point', {})).toBe('Route path is required');
      expect(registry.isConfigured('access-point', { route: '/api' })).toBe(true);
      expect(registry.getIncompleteReason('access-point', { route: '/api' })).toBeNull();
    });

    it('treats missing target endpoint as incomplete', () => {
      expect(registry.isConfigured('target', {})).toBe(false);
      expect(registry.getIncompleteReason('target', {})).toBe('Agent endpoint URL is required');
      expect(registry.isConfigured('target', { endpoint: 'http://x' })).toBe(true);
    });

    it('treats missing gateway fields as incomplete for gateway endpoint type', () => {
      expect(registry.isConfigured('target', { endpoint_type: 'gateway' })).toBe(false);
      expect(registry.getIncompleteReason('target', { endpoint_type: 'gateway' })).toBe(
        'Gateway connection is required'
      );
      expect(
        registry.isConfigured('target', {
          endpoint_type: 'gateway',
          gateway_id: 'gw1',
          gateway_channel: 'ch1',
        })
      ).toBe(true);
    });

    it('treats missing mcp_proxy_id as incomplete for mcp-proxy endpoint type', () => {
      expect(registry.isConfigured('target', { endpoint_type: 'mcp-proxy' })).toBe(false);
      expect(registry.getIncompleteReason('target', { endpoint_type: 'mcp-proxy' })).toBe(
        'MCP Proxy selection is required'
      );
      expect(
        registry.isConfigured('target', { endpoint_type: 'mcp-proxy', mcp_proxy_id: 'px1' })
      ).toBe(true);
    });

    it('payment requires enabled flag and x402 payment options', () => {
      expect(registry.isConfigured('payment', {})).toBe(false);
      expect(registry.isConfigured('payment', { enabled: false })).toBe(false);
      expect(
        registry.isConfigured('payment', {
          enabled: true,
          payment_kind: 'x402',
          payment_requirements: [],
        })
      ).toBe(false);
      expect(
        registry.isConfigured('payment', {
          enabled: true,
          payment_kind: 'x402',
          payment_requirements: [{ amount: '1', recipient_id: 'recipient-1' }],
        })
      ).toBe(true);
    });

    it('NPC and actor types are always configured', () => {
      expect(registry.isConfigured('human', {})).toBe(true);
      expect(registry.isConfigured('caller', {})).toBe(true);
      expect(registry.isConfigured('npc-agent', {})).toBe(true);
    });

    it('blocks save while policy definitions are loading but not on load error (fail-open)', () => {
      const loading: SurfacePolicyDefinitionLoadState = { status: 'loading', ids: null };
      const failed: SurfacePolicyDefinitionLoadState = {
        status: 'error',
        ids: null,
        error: 'HTTP 500',
      };
      const loaded: SurfacePolicyDefinitionLoadState = {
        status: 'loaded',
        ids: new Set(['policy-1']),
      };

      expect(policyDefinitionsBlockingReason(loading)).toBe(POLICY_DEFINITIONS_LOADING_REASON);
      expect(policyDefinitionsBlockingReason(failed)).toBeNull();
      expect(policyDefinitionsBlockingReason(loaded)).toBeNull();
    });

    it('only requires policy definitions for configured policy references', () => {
      expect(hasPolicyDefinitionReference([])).toBe(false);
      expect(hasPolicyDefinitionReference([{ type: 'policy', config: {} }])).toBe(false);
      expect(
        hasPolicyDefinitionReference([
          { type: 'policy', config: { policy_definition_id: 'policy-1' } },
        ])
      ).toBe(true);
    });
  });

  describe('palette filtering by protocol', () => {
    it('does not include core auto-created elements (surface, access-point, target)', () => {
      const a2a = registry.paletteItems('a2a').map(d => d.type);
      expect(a2a).not.toContain('surface');
      expect(a2a).not.toContain('access-point');
      expect(a2a).not.toContain('target');
    });

    it('offers Metadata Extraction only on A2A / AP2 surfaces', () => {
      expect(registry.paletteItems('a2a').map(d => d.type)).toContain('metadata-extraction');
      expect(registry.paletteItems('ap2').map(d => d.type)).toContain('metadata-extraction');
      expect(registry.paletteItems('mcp').map(d => d.type)).not.toContain('metadata-extraction');
      expect(registry.paletteItems('didcomm').map(d => d.type)).not.toContain(
        'metadata-extraction'
      );
    });
  });

  describe('drop compatibility', () => {
    it('allows policy to be dropped on access-point ↔ target edge', () => {
      expect(registry.canDropOnEdge('policy', 'access-point', 'target')).toBe(true);
    });

    it('allows target to be dropped on the surface interior', () => {
      expect(registry.canDropOnNode('target', 'surface')).toBe(false); // surface itself doesn't provide SURFACE_INTERIOR
      expect(registry.canDropOnNode('target', 'target')).toBe(true);
    });
  });

  describe('feature dependencies', () => {
    const baseCtx: SurfaceContext = {
      protocol: 'mcp',
      accessPoint: {},
      target: {},
      transitPoints: [],
      allNodes: [],
    };

    it('errors when MCP payment lacks a trigger mode', () => {
      const warnings = registry.getDependencyWarnings('payment', { enabled: true }, baseCtx);
      expect(
        warnings.some(w => w.severity === 'error' && w.message.includes('MCP payment triggers'))
      ).toBe(true);
    });

    it('clears MCP payment trigger error when mcp_payment_triggers has patterns', () => {
      const warnings = registry.getDependencyWarnings(
        'payment',
        {
          enabled: true,
          mcp_payment_triggers: { mode: 'match', patterns: ['^get_weather$'] },
        },
        baseCtx
      );
      expect(warnings.some(w => w.message.includes('MCP payment triggers'))).toBe(false);
    });

    it('clears A2A payment triggers warning when a2a_method_filters is non-empty', () => {
      const a2aCtx: SurfaceContext = { ...baseCtx, protocol: 'a2a' };
      const warnings = registry.getDependencyWarnings(
        'payment',
        {
          enabled: true,
          a2a_method_filters: [{ method: 'message/send', message_patterns: [] }],
        },
        a2aCtx
      );
      expect(warnings.some(w => w.message.includes('method filters'))).toBe(false);
    });

    it('errors when mirror_percentage out of range', () => {
      const warnings = registry.getDependencyWarnings(
        'networking',
        { mirror_enabled: true, mirror_percentage: 200, mirror_endpoint: 'x' },
        baseCtx
      );
      expect(
        warnings.some(w => w.severity === 'error' && w.message.includes('between 0 and 100'))
      ).toBe(true);
    });
  });

  describe('capability constants', () => {
    it('exports expected pipeline capabilities', () => {
      expect(Cap.PIPELINE_SOURCE).toBe('pipeline-source');
      expect(Cap.PIPELINE_SINK).toBe('pipeline-sink');
      expect(Cap.PIPELINE_EDGE).toBe('pipeline-edge');
    });
  });

  describe('buildSurfaceContext', () => {
    it('extracts accessPoint, target, transitPoints from a node array', () => {
      const { buildSurfaceContext } = require('../surfaceContext');
      const nodes = [
        { id: 'a', type: 'access-point', config: { x: 1 } },
        { id: 't', type: 'target', config: { endpoint: 'http://x' } },
        { id: 'tp1', type: 'transit-point-a2a', config: { name: 'first' } },
        { id: 'tp2', type: 'transit-point-mcp', config: { name: 'second' } },
        { id: 'p', type: 'payment', config: {} },
      ];
      const ctx = buildSurfaceContext('mcp', nodes);
      expect(ctx.protocol).toBe('mcp');
      expect(ctx.accessPoint).toEqual({ x: 1 });
      expect(ctx.target).toEqual({ endpoint: 'http://x' });
      expect(ctx.transitPoints).toEqual([{ name: 'first' }, { name: 'second' }]);
      expect(ctx.allNodes).toBe(nodes);
    });

    it('falls back to a2a protocol and empty objects on missing input', () => {
      const { buildSurfaceContext } = require('../surfaceContext');
      const ctx = buildSurfaceContext(undefined, undefined);
      expect(ctx.protocol).toBe('a2a');
      expect(ctx.accessPoint).toEqual({});
      expect(ctx.target).toEqual({});
      expect(ctx.transitPoints).toEqual([]);
      expect(ctx.allNodes).toEqual([]);
    });
  });

  describe('buildPayload', () => {
    function makeCtx(nodes: any[], overrides: any = {}) {
      return {
        protocol: 'a2a',
        surfaceMeta: {
          name: 'test-surface',
          tags: ['x'],
          status: 'active',
          ...overrides.surfaceMeta,
        },
        allNodes: nodes,
        nodesOfType: (type: string) => nodes.filter(n => n.type === type),
        firstNodeOfType: (type: string) => nodes.find(n => n.type === type),
        ...overrides,
      };
    }

    it('always emits surface metadata', () => {
      const out = registry.buildPayload(makeCtx([]));
      expect(out.name).toBe('test-surface');
      expect(out.status).toBe('active');
      expect(out.tags).toEqual(['x']);
    });

    it('always emits access_point and target sections (defaults)', () => {
      const out = registry.buildPayload(makeCtx([]));
      expect(out.access_point).toBeDefined();
      expect(out.access_point.protocol).toBe('a2a');
      expect(out.target).toBeDefined();
      expect(out.target.endpoint).toBe('');
    });

    it('routes policy slots from {id, direction}: id=policy-inbound → inbound_policy, request id=policy → target.policy, response → target.response_policy', () => {
      const out = registry.buildPayload(
        makeCtx([
          {
            id: 'policy-inbound',
            type: 'policy',
            parentId: 'access-point',
            direction: 'request',
            config: { policy_definition_id: 'pol-1' },
          },
          {
            id: 'p2',
            type: 'policy',
            parentId: 'target',
            direction: 'request',
            config: { policy_definition_id: 'pol-2' },
          },
          {
            id: 'p3',
            type: 'policy',
            parentId: 'target',
            direction: 'response',
            config: { policy_definition_id: 'pol-3' },
          },
        ])
      );
      expect(out.access_point.inbound_policy).toEqual({ policy_definition_id: 'pol-1' });
      expect(out.target.policy).toEqual({ policy_definition_id: 'pol-2' });
      expect(out.target.response_policy).toEqual({ policy_definition_id: 'pol-3' });
    });

    it('emits payment_policy with x402 fields when enabled', () => {
      const out = registry.buildPayload(
        makeCtx([
          {
            id: 'pay',
            type: 'payment',
            config: {
              enabled: true,
              verification_mode: 'mock',
              settlement_mode: 'none',
              supported_networks: ['base'],
              facilitator_url: 'https://x',
              mcp_payment_triggers: { mode: 'match', patterns: ['^get_weather$'] },
            },
          },
        ])
      );
      expect(out.target.payment_policy).toEqual({
        type: 'x402',
        enabled: true,
        verification_mode: 'mock',
        settlement_mode: 'none',
        supported_networks: ['base'],
        facilitator_url: 'https://x',
        mcp_payment_triggers: { mode: 'match', patterns: ['^get_weather$'] },
      });
    });

    it('omits payment_policy when payment node is not enabled', () => {
      const out = registry.buildPayload(
        makeCtx([{ id: 'pay', type: 'payment', config: { enabled: false } }])
      );
      expect(out.target.payment_policy).toBeUndefined();
    });

    it('emits payment_policy with mpp fields when enabled', () => {
      const out = registry.buildPayload(
        makeCtx([
          {
            id: 'pay',
            type: 'payment',
            config: {
              enabled: true,
              payment_kind: 'mpp',
              mpp_realm: 'example.com',
              mpp_secret_key: '$MPP_SECRET_KEY',
              mpp_challenge_ttl: '600',
              mpp_payment_methods: [
                {
                  method: 'tempo',
                  intent: 'charge',
                  currency: 'USDC',
                  recipient: '0xabc',
                  amount: '0.01',
                },
              ],
              mpp_mcp_payment_triggers: { mode: 'match', patterns: ['^paid_.*$'] },
              mpp_a2a_method_filters: [{ method: 'message/send', message_patterns: ['^premium'] }],
              mpp_stripe_secret_key: '$STRIPE_SECRET_KEY',
              mpp_crypto_verification_mode: 'onchain',
              mpp_min_confirmations: '2',
              mpp_verification_timeout_ms: '15000',
              mpp_rpc_endpoints: { 'eip155:8453': 'https://mainnet.base.org' },
            },
          },
        ])
      );
      expect(out.target.payment_policy).toEqual({
        type: 'mpp',
        enabled: true,
        realm: 'example.com',
        secret_key: '$MPP_SECRET_KEY',
        challenge_ttl_seconds: 600,
        payment_methods: [
          {
            method: 'tempo',
            intent: 'charge',
            currency: 'USDC',
            recipient: '0xabc',
            amount: '0.01',
          },
        ],
        mcp_payment_triggers: { mode: 'match', patterns: ['^paid_.*$'] },
        a2a_method_filters: [{ method: 'message/send', message_patterns: ['^premium'] }],
        stripe_secret_key: '$STRIPE_SECRET_KEY',
        crypto_verification_mode: 'onchain',
        min_confirmations: 2,
        verification_timeout_ms: 15000,
        rpc_endpoints: { 'eip155:8453': 'https://mainnet.base.org' },
      });
    });

    it('omits payment_policy for mpp when realm or secret key is missing', () => {
      const out = registry.buildPayload(
        makeCtx([
          {
            id: 'pay',
            type: 'payment',
            config: { enabled: true, payment_kind: 'mpp', mpp_realm: 'example.com' },
          },
        ])
      );
      expect(out.target.payment_policy).toBeUndefined();
    });

    it('emits identity_slots.protected once an extraction type is selected', () => {
      const out = registry.buildPayload(
        makeCtx([
          {
            id: 'identity-protected',
            type: 'identity',
            config: { type: 'from_payload' },
          },
        ])
      );
      expect(out.identity_slots.protected).toEqual({
        type: 'from_payload',
      });
    });

    it('routes inbound rate-limit to access_point and transit-parented rate-limit to per-TP rate_limit', () => {
      const out = registry.buildPayload(
        makeCtx([
          {
            id: 'rl1',
            type: 'rate-limit',
            parentId: 'access-point',
            config: { requests: '100', window_secs: '60' },
          },
          {
            id: 'rl2',
            type: 'rate-limit',
            parentId: 'transit-point-a2a-1',
            config: { requests: '50', window_secs: '30' },
          },
          {
            id: 'transit-point-a2a-1',
            type: 'transit-point-a2a',
            config: { name: 'h1', target_endpoint: 'http://a' },
          },
        ])
      );
      expect(out.access_point.rate_limit).toEqual({ requests: 100, window_secs: 60 });
      expect(out.transit.rate_limit).toBeUndefined();
      expect(out.transit.points).toHaveLength(1);
      expect(out.transit.points[0].name).toBe('h1');
      expect(out.transit.points[0].rate_limit).toEqual({ requests: 50, window_secs: 30 });
    });

    it('aggregates custom-metadata entries from multiple nodes', () => {
      const out = registry.buildPayload(
        makeCtx([
          { id: 'm1', type: 'custom-metadata', config: { entries: [{ key: 'a', value: '1' }] } },
          {
            id: 'm2',
            type: 'custom-metadata',
            config: { entries: [{ key: 'b', value: '2' }], scope: 'request' },
          },
        ])
      );
      expect(out.target.custom_metadata).toEqual({
        enabled: true,
        payload: { a: '1', b: '2' },
      });
    });

    it('routes extension-validation to access_point only', () => {
      const out = registry.buildPayload(
        makeCtx([
          {
            id: 'e',
            type: 'extension-validation',
            config: { required_extensions: 'foo, bar' },
          },
        ])
      );
      expect(out.access_point.extension_validation).toEqual({
        required_extensions: ['foo', 'bar'],
      });
      expect(out.target.extension_rules).toBeUndefined();
    });

    it('emits trust_recorder on access_point', () => {
      const entry = {
        trust_registry_id: 'tr-1',
        issuer_did: 'did:web:example',
        authority_did: 'did:web:authority',
        include_owned_agent: true,
        custom_resources: [
          {
            action: 'is',
            resource: 'paymentAgent',
            entity_target: 'agent' as const,
            record_type: 'recognition',
          },
        ],
      };
      const out = registry.buildPayload(
        makeCtx([
          {
            id: 'tr',
            type: 'trust-recorder',
            config: { entries: [entry] },
            slotId: 'response:trust-recorder',
          },
        ])
      );
      expect(out.access_point.trust_recorder).toEqual({ entries: [entry] });
    });

    it('emits one transit point per node, with protocol derived from the variant type', () => {
      const out = registry.buildPayload(
        makeCtx([
          {
            id: 'tp1',
            type: 'transit-point-a2a',
            config: { name: 'first', target_endpoint: 'http://a' },
          },
          {
            id: 'tp2',
            type: 'transit-point-mcp',
            config: { name: 'second', target_endpoint: 'http://b' },
          },
        ])
      );
      expect(out.transit.points).toHaveLength(2);
      expect(out.transit.points[0]).toMatchObject({
        name: 'first',
        target_endpoint: 'http://a',
        protocol: 'a2a',
      });
      expect(out.transit.points[1]).toMatchObject({
        name: 'second',
        target_endpoint: 'http://b',
        protocol: 'mcp',
      });
    });

    it('omits sections for absent elements', () => {
      const out = registry.buildPayload(makeCtx([]));
      expect(out.target.payment_policy).toBeUndefined();
      expect(out.target.identity_injection).toBeUndefined();
      expect(out.target.networking).toBeUndefined();
      expect(out.transit).toBeUndefined();
    });
  });

  describe('deletable', () => {
    it('marks core singletons (surface, access-point, target) as not deletable', () => {
      expect(registry.get('surface')!.deletable).toBe(false);
      expect(registry.get('access-point')!.deletable).toBe(false);
      expect(registry.get('target')!.deletable).toBe(false);
    });

    it('leaves all other elements deletable by default', () => {
      const undeletable = registry
        .all()
        .filter(d => d.deletable === false)
        .map(d => d.type)
        .sort();
      // human + caller are auto-injected actors that are also locked
      // (the d3 simulation has hard link dependencies on them).
      // local-gateway-hop + remote-gateway are synthesised view-only
      // nodes with no presence in builder state, so they are also locked.
      expect(undeletable).toEqual(
        [
          'access-point',
          'caller',
          'human',
          'local-gateway-hop',
          'remote-channel',
          'remote-gateway',
          'surface',
          'target',
          'target-variant',
        ].sort()
      );
    });
  });

  describe('Identity', () => {
    it('renames identity to "Identity" with a circle shape and edge-bound drop', () => {
      const def = registry.get('identity')!;
      expect(def.label).toBe('Identity');
      expect(def.shape).toBe('circle');
      expect(def.dropMode).toBe('edge');
      expect(def.surfaceWide).toBeFalsy();
      expect(def.requires.dropOnEdge).toContain('identity-target');
    });

    it('exposes a FullscreenPanel for the heavy payload-fields editor', () => {
      const def = registry.get('identity')!;
      expect(def.FullscreenPanel).toBeDefined();
      // The compact form lives in the sidebar by default.
      expect(def.configSurface).toBeUndefined();
    });

    it('exposes a FullscreenPanel for trust-recorder and trust-check with sidebar summary intact', () => {
      const tr = registry.get('trust-recorder')!;
      expect(tr.FullscreenPanel).toBeDefined();
      expect(tr.configSurface).toBeUndefined();
      const tc = registry.get('trust-check')!;
      expect(tc.FullscreenPanel).toBeDefined();
      expect(tc.configSurface).toBeUndefined();
    });

    it('normalises the backend `payload_extraction` tag back to the dropdown-friendly `from_payload` on hydrate', () => {
      // Regression: the backend serializes
      // `ManagedIdentityConfig::PayloadExtraction` as
      // `"type": "payload_extraction"` (snake_case enum tag) while the
      // panel dropdown only knows the wire-input alias `from_payload`.
      // Without `configFromPayload` normalisation the reloaded panel
      // shows "Pick an identity extraction type" for a fully
      // configured identity.
      const def = registry.get('identity')!;
      expect(def.configFromPayload).toBeDefined();
      const recovered = def.configFromPayload!(
        { type: 'payload_extraction', meta_field: 'agentIdentity' },
        {}
      );
      expect(recovered).toEqual({ type: 'from_payload', meta_field: 'agentIdentity' });
      // The backend serializes `ManagedIdentityConfig::Static` with the DID
      // under `did`; the panel edits it as `static_did`, so hydrate maps it.
      const stat = def.configFromPayload!({ type: 'static', did: 'did:x' }, {});
      expect(stat).toEqual({ type: 'static', static_did: 'did:x' });
    });
  });

  describe('configSurface', () => {
    it('defaults to sidebar for normal-sized panels', () => {
      // policy/payment/rate-limit fit in the 320–600px sidebar
      expect(registry.get('policy')!.configSurface).toBeUndefined();
      expect(registry.get('rate-limit')!.configSurface).toBeUndefined();
    });
  });

  describe('buildPayload contract (PayloadSlice[] API)', () => {
    function makeCtx(nodes: any[]) {
      return {
        protocol: 'a2a',
        surfaceMeta: { name: 'test', tags: [], status: 'active' },
        allNodes: nodes,
        nodesOfType: (type: string) => nodes.filter(n => n.type === type),
        firstNodeOfType: (type: string) => nodes.find(n => n.type === type),
      };
    }

    it('every element with a buildPayload returns slices in the expected shape', () => {
      // For an element that has runtime nodes, calling its buildPayload
      // returns either undefined or an array where every entry has a
      // non-empty string path and a defined value. Sanity check on the
      // contract.
      const probe = (def: any, nodes: any[]) => {
        if (!def.buildPayload) return;
        const slices = def.buildPayload(makeCtx(nodes));
        if (slices === undefined) return;
        expect(Array.isArray(slices)).toBe(true);
        for (const s of slices) {
          expect(typeof s.path).toBe('string');
          expect(s.path.length).toBeGreaterThan(0);
          expect(s.value).toBeDefined();
        }
      };
      probe(registry.get('access-point'), [
        { id: 'a', type: 'access-point', config: { route: '/x' } },
      ]);
      probe(registry.get('target'), [
        { id: 't', type: 'target', config: { endpoint: 'http://x' } },
      ]);
      probe(registry.get('payment'), [
        { id: 'p', type: 'payment', config: { payment_type: 'mpp' } },
      ]);
      probe(registry.get('identity'), [
        { id: 'i', type: 'identity', config: { type: 'from_payload' } },
      ]);
    });

    it('migrated elements that emit at well-known paths declare them via payloadPath', () => {
      const expected: Record<string, string> = {
        identity: 'identity_slots.protected',
        'rate-limit': 'access_point.rate_limit',
        'trust-recorder': 'access_point.trust_recorder',
        networking: 'target.networking',
        payment: 'target.payment_policy',
        'extension-rules': 'target.extension_rules',
        'custom-metadata': 'target.custom_metadata',
      };
      for (const [type, path] of Object.entries(expected)) {
        const def = registry.get(type as any)!;
        expect(def.payloadPath).toBe(path);
        expect(def.buildPayload).toBeDefined();
      }
    });

    it('deep-merges slice into nested path without clobbering siblings', () => {
      // identity (identity_slots.protected) coexists with target.endpoint
      // and target.policy that come from other elements.
      const out = registry.buildPayload(
        makeCtx([
          { id: 't', type: 'target', config: { endpoint: 'http://a' } },
          { id: 'p', type: 'policy', config: { policy_definition_id: 'pol-x' } },
          {
            id: 'identity-protected',
            type: 'identity',
            config: { type: 'from_payload' },
          },
          { id: 'rl', type: 'rate-limit', config: { requests: '10', window_secs: '1' } },
        ])
      );
      expect(out.target.endpoint).toBe('http://a');
      expect(out.target.policy).toEqual({ policy_definition_id: 'pol-x' });
      expect(out.identity_slots.protected).toEqual({ type: 'from_payload' });
      expect(out.access_point.rate_limit).toEqual({ requests: 10, window_secs: 1 });
    });

    it('skips writing when buildPayload returns undefined', () => {
      const out = registry.buildPayload(makeCtx([]));
      expect(out.identity_slots?.protected).toBeUndefined();
      expect(out.target.payment_policy).toBeUndefined();
      expect(out.access_point.rate_limit).toBeUndefined();
    });

    it('multi-slice elements emit multiple slices in one call (policy)', () => {
      const slices = registry.get('policy')!.buildPayload!({
        protocol: 'a2a',
        surfaceMeta: { name: 't', tags: [], status: 'active' },
        allNodes: [],
        nodesOfType: (type: string) =>
          type === 'policy'
            ? ([
                {
                  id: 'a',
                  type: 'policy',
                  parentId: 'target',
                  direction: 'request',
                  config: { policy_definition_id: 'pa' },
                },
                {
                  id: 'b',
                  type: 'policy',
                  parentId: 'target',
                  direction: 'response',
                  config: { policy_definition_id: 'pb' },
                },
                {
                  id: 'policy-inbound',
                  type: 'policy',
                  parentId: 'access-point',
                  direction: 'request',
                  config: { policy_definition_id: 'pc' },
                },
              ] as any)
            : [],
        firstNodeOfType: () => undefined,
      } as any);
      const paths = (slices ?? []).map(s => s.path).sort();
      expect(paths).toEqual([
        'access_point.inbound_policy',
        'target.policy',
        'target.response_policy',
      ]);
    });
  });
});
