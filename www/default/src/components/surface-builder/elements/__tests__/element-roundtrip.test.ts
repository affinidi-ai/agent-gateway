import { registry } from '../index';
import type { PayloadContext } from '../types';

/**
 * Per-element integration test template.
 *
 * For each migrated element we exercise the full lifecycle the wizard
 * relies on:
 *
 *   1. Drop a node onto the canvas with a representative config.
 *   2. Mark `configured` based on `registry.isConfigured`.
 *   3. Run `registry.buildPayload` and check the slice was written at the
 *      expected path with the meaningful fields intact.
 *   4. Run `registry.nodesFromPayload` to recover nodes from the payload
 *      and assert we get back a node of the same type with at least the
 *      meaningful fields matching.
 *
 * The list below is the contract: adding a new element-with-payloadPath
 * should add a row here so the round-trip is guaranteed.
 */

interface Case {
  type: string;
  /**
   * Disambiguator when more than one case targets the same `type`
   * (e.g. policy on target.policy vs access_point.inbound_policy).
   * Used in `it()` titles only.
   */
  variant?: string;
  /**
   * Optional `slotId` to set on the dropped node. Required for
   * elements that route by slot (currently policy with multiple
   * payload paths). Without it the legacy id/parentId fallback runs.
   */
  slotId?: string;
  /**
   * Optional `id` override for the dropped node. Defaults to `c.type`.
   * Set this when the slot's canonical id differs from the type
   * (e.g. policy-inbound).
   */
  nodeId?: string;
  /**
   * Optional `parentId` override on the dropped node. Some elements'
   * routing (rate-limit, policy) inspects this for legacy fallback.
   */
  parentId?: string;
  /**
   * Optional `direction` override on the dropped node. Default is
   * unset (which `buildPayload` treats as 'request').
   */
  direction?: 'request' | 'response';
  /** Config the wizard would store on the canvas node. */
  config: any;
  /** Where the slice is expected to land in the surface payload. */
  payloadPath: string;
  /**
   * Subset of the slice we assert on (deep-equal). Keep this small —
   * each element panel has its own unit tests for shape details.
   */
  expectedSlice: any;
  /**
   * Optional: when the recovered panel config differs from the
   * persisted slice (because the element has a `configFromPayload`
   * adapter), assert against this shape on the round-trip pass instead.
   * Defaults to `expectedSlice`.
   */
  expectedRecoveredConfig?: any;
  /**
   * If the node won't survive the reverse pass (e.g. element is
   * surface-wide and the round-trip strips it), set this. Default true.
   */
  roundtripsToNode?: boolean;
  /**
   * Surface defaults that need to be present for `nodesFromPayload` to
   * see the slice — by default we add a populated access-point + target
   * because every payload has them.
   */
  extraNodes?: any[];
}

const cases: Case[] = [
  {
    type: 'rate-limit',
    config: { requests: '100', window_secs: '60' },
    payloadPath: 'access_point.rate_limit',
    expectedSlice: { requests: 100, window_secs: 60 },
  },
  {
    type: 'trust-recorder',
    config: {
      entries: [
        {
          trust_registry_id: 'tr-1',
          issuer_did: 'did:web:example',
          authority_did: 'did:web:authority',
          include_owned_agent: true,
          custom_resources: [
            {
              action: 'is',
              resource: 'paymentAgent',
              entity_target: 'agent',
              record_type: 'recognition',
            },
          ],
        },
      ],
    },
    slotId: 'response:trust-recorder',
    payloadPath: 'access_point.trust_recorder',
    expectedSlice: {
      entries: [
        {
          trust_registry_id: 'tr-1',
          issuer_did: 'did:web:example',
          authority_did: 'did:web:authority',
          include_owned_agent: true,
          custom_resources: [
            {
              action: 'is',
              resource: 'paymentAgent',
              entity_target: 'agent',
              record_type: 'recognition',
            },
          ],
        },
      ],
    },
  },
  {
    type: 'payment',
    config: {
      enabled: true,
      verification_mode: 'mock',
      settlement_mode: 'none',
      supported_networks: ['base'],
    },
    payloadPath: 'target.payment_policy',
    expectedSlice: {
      type: 'x402',
      enabled: true,
      verification_mode: 'mock',
      settlement_mode: 'none',
      supported_networks: ['base'],
    },
    // configFromPayload strips the `type` discriminator — the panel
    // sees the X402Config-shaped fields directly with `enabled: true`.
    expectedRecoveredConfig: {
      enabled: true,
      payment_kind: 'x402',
      verification_mode: 'mock',
      settlement_mode: 'none',
      supported_networks: ['base'],
    },
  },
  {
    type: 'payment',
    variant: 'mpp',
    config: {
      enabled: true,
      payment_kind: 'mpp',
      mpp_realm: 'example.com',
      mpp_secret_key: '$MPP_SECRET',
      mpp_challenge_ttl: '600',
      mpp_payment_methods: JSON.stringify([
        {
          method: 'tempo',
          intent: 'charge',
          currency: 'USDC',
          recipient: '0xabc',
          amount: '0.01',
        },
      ]),
      mpp_mcp_payment_triggers: { mode: 'match', patterns: ['^search$', '^summarize$'] },
      mpp_a2a_method_filters: [{ method: 'message/send', message_patterns: ['^premium'] }],
      mpp_stripe_secret_key: '$STRIPE_SECRET_KEY',
      mpp_crypto_verification_mode: 'onchain',
      mpp_min_confirmations: '1',
      mpp_rpc_endpoints: JSON.stringify({ 'eip155:8453': 'https://mainnet.base.org' }),
    },
    payloadPath: 'target.payment_policy',
    expectedSlice: {
      type: 'mpp',
      enabled: true,
      realm: 'example.com',
      secret_key: '$MPP_SECRET',
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
      mcp_payment_triggers: { mode: 'match', patterns: ['^search$', '^summarize$'] },
      a2a_method_filters: [{ method: 'message/send', message_patterns: ['^premium'] }],
      stripe_secret_key: '$STRIPE_SECRET_KEY',
      crypto_verification_mode: 'onchain',
      min_confirmations: 1,
      rpc_endpoints: { 'eip155:8453': 'https://mainnet.base.org' },
    },
    expectedRecoveredConfig: {
      enabled: true,
      payment_kind: 'mpp',
      mpp_realm: 'example.com',
      mpp_secret_key: '$MPP_SECRET',
      mpp_challenge_ttl: 600,
      mpp_payment_methods: JSON.stringify(
        [
          {
            method: 'tempo',
            intent: 'charge',
            currency: 'USDC',
            recipient: '0xabc',
            amount: '0.01',
          },
        ],
        null,
        2
      ),
      mpp_mcp_payment_triggers: { mode: 'match', patterns: ['^search$', '^summarize$'] },
      mpp_a2a_method_filters: [{ method: 'message/send', message_patterns: ['^premium'] }],
      mpp_stripe_secret_key: '$STRIPE_SECRET_KEY',
      mpp_crypto_verification_mode: 'onchain',
      mpp_min_confirmations: 1,
      mpp_rpc_endpoints: JSON.stringify({ 'eip155:8453': 'https://mainnet.base.org' }, null, 2),
    },
  },
  {
    type: 'identity',
    config: { type: 'from_payload', meta_field: 'agentIdentity' },
    payloadPath: 'identity_slots.protected',
    expectedSlice: { type: 'from_payload', meta_field: 'agentIdentity' },
    nodeId: 'identity-protected',
    slotId: 'response:identity-protected',
    parentId: 'target',
  },
  // Regression: the external identity slot must serialize to
  // `identity_slots.external`, NOT collide with the protected slot.
  // Before unique slot ids + node.id-based path resolution, both slots
  // resolved to `identity_slots.protected` and overwrote each other.
  {
    type: 'identity',
    config: { type: 'from_payload', meta_field: 'externalIdentity' },
    payloadPath: 'identity_slots.external',
    expectedSlice: { type: 'from_payload', meta_field: 'externalIdentity' },
    nodeId: 'identity-external',
    slotId: 'response:identity-external',
    parentId: 'target',
  },
  {
    type: 'custom-metadata',
    config: {
      enabled: true,
      entries: [{ key: 'a', value: '1' }],
    },
    // Default direction is 'request' → lands on the request slice.
    payloadPath: 'target.custom_metadata',
    expectedSlice: { enabled: true, payload: { a: '1' } },
    // After round-trip the panel sees its own form shape (entries[]),
    // not the persisted API shape — `configFromPayload` rebuilds
    // entries from `payload`. Without this, the panel reloads as
    // empty and reports "must have at least one entry".
    expectedRecoveredConfig: {
      entries: [{ key: 'a', value: '1', target: 'header' }],
    },
  },
  {
    type: 'metadata-extraction',
    config: {
      header_metadata_mapping: {
        extension_uri: 'https://fabric.affinidi.io/extensions/header-metadata/v1',
        headers: [{ header: 'x-ms-entra-agent-id', field: 'entra_agent_id' }],
        strip_mapped_headers: true,
      },
    },
    slotId: 'request:metadata-extraction',
    payloadPath: 'access_point.header_metadata_mapping',
    expectedSlice: {
      extension_uri: 'https://fabric.affinidi.io/extensions/header-metadata/v1',
      headers: [{ header: 'x-ms-entra-agent-id', field: 'entra_agent_id' }],
      strip_mapped_headers: true,
    },
    expectedRecoveredConfig: {
      header_metadata_mapping: {
        extension_uri: 'https://fabric.affinidi.io/extensions/header-metadata/v1',
        headers: [{ header: 'x-ms-entra-agent-id', field: 'entra_agent_id' }],
        strip_mapped_headers: true,
      },
    },
  },
  {
    type: 'extension-rules',
    config: { default_action: 'allow', rules: [{ name: 'r', action: 'allow' }] },
    // Default direction is 'request' → request slice.
    payloadPath: 'target.extension_rules',
    expectedSlice: {
      default_action: 'allow',
      filter_rules: [{ name: 'r', action: 'allow' }],
    },
    expectedRecoveredConfig: {
      default_action: 'allow',
      rules: [{ name: 'r', action: 'allow' }],
    },
  },
  {
    type: 'networking',
    parentId: 'tg',
    config: { timeout_secs: '30' },
    payloadPath: 'target.networking',
    expectedSlice: { timeout: { request_secs: 30 } },
  },
  {
    type: 'extension-validation',
    config: {
      required_extensions: 'ext-a, ext-b',
    },
    payloadPath: 'access_point.extension_validation',
    expectedSlice: {
      required_extensions: ['ext-a', 'ext-b'],
    },
    // configFromPayload converts the array back to a CSV string for
    // the panel's text input.
    expectedRecoveredConfig: {
      required_extensions: 'ext-a, ext-b',
    },
  },
  {
    type: 'policy',
    variant: 'request → target.policy',
    nodeId: 'policy',
    slotId: 'request:policy',
    parentId: 'access-point',
    config: { policy_definition_id: 'pol-target' },
    payloadPath: 'target.policy',
    expectedSlice: { policy_definition_id: 'pol-target' },
  },
  {
    type: 'policy',
    variant: 'request → access_point.inbound_policy',
    nodeId: 'policy-inbound',
    slotId: 'request:policy-inbound',
    parentId: 'access-point',
    config: { policy_definition_id: 'pol-inbound' },
    payloadPath: 'access_point.inbound_policy',
    expectedSlice: { policy_definition_id: 'pol-inbound' },
  },
  {
    type: 'policy',
    variant: 'response → target.response_policy',
    nodeId: 'policy-response',
    direction: 'response',
    parentId: 'target',
    config: { policy_definition_id: 'pol-resp' },
    payloadPath: 'target.response_policy',
    expectedSlice: { policy_definition_id: 'pol-resp' },
  },
  {
    type: 'mcp-tool-gating',
    direction: 'response',
    config: {
      gates: [
        {
          id: 'gate-1',
          name: 'Block admin',
          description: 'no admin tools',
          condition_policy_definition_id: 'pol-1',
          // The whitespace pattern is stripped by buildPayload normalisation.
          action: { effect: 'deny', patterns: ['^admin_', '  '] },
        },
      ],
    },
    payloadPath: 'target.mcp_tool_gating',
    expectedSlice: {
      gates: [
        {
          id: 'gate-1',
          name: 'Block admin',
          description: 'no admin tools',
          condition_policy_definition_id: 'pol-1',
          action: { effect: 'deny', patterns: ['^admin_'] },
        },
      ],
    },
  },
];

function makeCtx(nodes: any[]): PayloadContext {
  return {
    protocol: 'a2a',
    surfaceMeta: { name: 'roundtrip', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: type => nodes.filter(n => n.type === type),
    firstNodeOfType: type => nodes.find(n => n.type === type),
  };
}

function readPath(obj: any, path: string): any {
  return path.split('.').reduce((acc, k) => (acc == null ? acc : acc[k]), obj);
}

function deepIncludes(actual: any, expected: any): void {
  if (Array.isArray(expected)) {
    expect(Array.isArray(actual)).toBe(true);
    expect(actual.length).toBeGreaterThanOrEqual(expected.length);
    expected.forEach((e, i) => deepIncludes(actual[i], e));
    return;
  }
  if (expected && typeof expected === 'object') {
    expect(actual).toBeDefined();
    for (const [k, v] of Object.entries(expected)) {
      deepIncludes(actual[k], v);
    }
    return;
  }
  expect(actual).toEqual(expected);
}

describe('Element round-trip (drop → configure → buildPayload → nodesFromPayload)', () => {
  for (const c of cases) {
    const title = c.variant ? `${c.type} (${c.variant})` : c.type;
    // eslint-disable-next-line jest/valid-title
    describe(title, () => {
      const dropNode = () => ({
        id: c.nodeId ?? c.type,
        type: c.type,
        label: '',
        configured: registry.isConfigured(c.type as any, c.config),
        config: c.config,
        ...(c.slotId ? { slotId: c.slotId } : {}),
        ...(c.parentId ? { parentId: c.parentId } : {}),
        ...(c.direction ? { direction: c.direction } : {}),
      });

      it('builds the expected slice at the declared payloadPath', () => {
        const def = registry.get(c.type as any)!;
        expect(def).toBeDefined();
        expect(def.buildPayload).toBeDefined();
        expect(def.payloadPath).toBeTruthy();

        const nodes = [
          {
            id: 'ap',
            type: 'access-point',
            label: 'AP',
            configured: true,
            config: { route: '/api' },
          },
          {
            id: 'tg',
            type: 'target',
            label: 'T',
            configured: true,
            config: { endpoint: 'http://example.com' },
          },
          ...(c.extraNodes ?? []),
          dropNode(),
        ];

        const payload = registry.buildPayload(makeCtx(nodes));
        const slice = readPath(payload, c.payloadPath);
        deepIncludes(slice, c.expectedSlice);
      });

      if (c.roundtripsToNode !== false) {
        it('round-trips: nodesFromPayload(buildPayload(...)) yields a node of the same type', () => {
          const nodes = [
            {
              id: 'ap',
              type: 'access-point',
              label: 'AP',
              configured: true,
              config: { route: '/api' },
            },
            {
              id: 'tg',
              type: 'target',
              label: 'T',
              configured: true,
              config: { endpoint: 'http://example.com' },
            },
            ...(c.extraNodes ?? []),
            dropNode(),
          ];
          const payload = registry.buildPayload(makeCtx(nodes));
          const recovered = registry.nodesFromPayload(payload);
          // When a slotId was specified on the drop, recover the exact
          // node by slotId so multi-variant elements (policy) don't
          // collide on a plain `type` lookup.
          const recoveredOfType = c.slotId
            ? recovered.find(n => n.slotId === c.slotId)
            : recovered.find(n => n.type === c.type);
          expect(recoveredOfType).toBeDefined();
          deepIncludes(recoveredOfType!.config, c.expectedRecoveredConfig ?? c.expectedSlice);
        });
      }
    });
  }

  // ── managed-agent: mcp-proxy default_policy_id ────────────────────────────
  // The default tool policy is persisted as a `*` wildcard entry in the
  // backend `target.mcp_tool_policies` array and recovered back to
  // `default_policy_id` by `configFromPayload`.

  describe('managed-agent (mcp-proxy) — default_policy_id round-trip', () => {
    function makeMcpProxyNode(config: any) {
      return {
        id: 'target',
        type: 'target',
        label: '',
        configured: true,
        config: {
          endpoint: `proxy://${config.mcp_proxy_id}`,
          ...config,
        },
      };
    }

    it('serializes default_policy_id as a * wildcard entry in target.mcp_tool_policies', () => {
      const nodes = [
        makeMcpProxyNode({
          mcp_proxy_id: 'proxy-abc',
          mcp_tool_policies: { default_policy_id: 'pol-default', tools: [] },
        }),
      ];
      const payload = registry.buildPayload(makeCtx(nodes));
      const policies: any[] = readPath(payload, 'target.mcp_tool_policies') ?? [];
      expect(Array.isArray(policies)).toBe(true);
      const wildcard = policies.find((e: any) => e.tool_name === '*');
      expect(wildcard).toBeDefined();
      expect(wildcard?.policy_definition_id).toBe('pol-default');
    });

    it('serializes per-tool entries alongside the * wildcard entry', () => {
      const nodes = [
        makeMcpProxyNode({
          mcp_proxy_id: 'proxy-abc',
          mcp_tool_policies: {
            default_policy_id: 'pol-default',
            tools: [{ tool_name: 'get_news', policy_definition_id: 'pol-get', description: '' }],
          },
        }),
      ];
      const payload = registry.buildPayload(makeCtx(nodes));
      const policies: any[] = readPath(payload, 'target.mcp_tool_policies') ?? [];
      const wildcard = policies.find((e: any) => e.tool_name === '*');
      const perTool = policies.find((e: any) => e.tool_name === 'get_news');
      expect(wildcard).toBeDefined();
      expect(wildcard?.policy_definition_id).toBe('pol-default');
      expect(perTool).toBeDefined();
      expect(perTool?.policy_definition_id).toBe('pol-get');
    });

    it('does not emit a * entry when default_policy_id is empty', () => {
      const nodes = [
        makeMcpProxyNode({
          mcp_proxy_id: 'proxy-abc',
          mcp_tool_policies: {
            default_policy_id: '',
            tools: [{ tool_name: 'get_news', policy_definition_id: 'pol-get', description: '' }],
          },
        }),
      ];
      const payload = registry.buildPayload(makeCtx(nodes));
      const policies: any[] = readPath(payload, 'target.mcp_tool_policies') ?? [];
      const wildcard = policies.find((e: any) => e.tool_name === '*');
      expect(wildcard).toBeUndefined();
    });

    it('recovers default_policy_id from a * wildcard entry in the backend payload', () => {
      const backendPayload = {
        target: {
          endpoint: 'proxy://proxy-abc',
          mcp_tool_policies: [
            { tool_name: '*', policy_definition_id: 'pol-default', description: 'Default policy' },
            { tool_name: 'get_news', policy_definition_id: 'pol-get', description: '' },
          ],
          mcp_tool_policies_enabled: true,
        },
      };
      const nodes = registry.nodesFromPayload(backendPayload);
      const targetNode = nodes.find((n: any) => n.type === 'target');
      expect(targetNode).toBeDefined();
      expect(targetNode!.config.mcp_tool_policies?.default_policy_id).toBe('pol-default');
      const tools: any[] = targetNode!.config.mcp_tool_policies?.tools ?? [];
      expect(tools.find((t: any) => t.tool_name === '*')).toBeUndefined();
      expect(tools.find((t: any) => t.tool_name === 'get_news')).toBeDefined();
    });
  });

  it('surface contract: every element with a payloadPath has at least one round-trip case', () => {
    // The audit list excludes elements that aren't simple "drop and
    // round-trip" middleware: anchors (access-point, target,
    // managed-agent), per-instance entries (target-variant), and
    // surface-wide elements that participate in different lifecycles
    // (caller-auth). These have their own dedicated tests.
    const exempt = new Set([
      'access-point',
      'target',
      'managed-agent',
      'target-variant',
      'caller-auth',
    ]);
    const expected = registry
      .all()
      .filter(d => d.payloadPath && !exempt.has(d.type))
      .map(d => d.type);
    const covered = new Set(cases.map(c => c.type));
    for (const t of expected) {
      expect(covered.has(t)).toBe(true);
    }
  });
});
