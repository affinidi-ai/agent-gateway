import { planTemplate, applyPlan, applyTemplate } from '../placement';
import type { SurfaceTemplate } from '../types';
import type { CanvasNode } from '../../SurfaceCanvas';

const multiPolicyTemplate: SurfaceTemplate = {
  id: 'test-tpl-policy',
  name: 'Test policy',
  items: [
    {
      scope: 'channel_policy',
      kind: 'policy',
      config: { name: 'tpl-policy', rego: 'package x' },
    },
  ],
};

const mixedTemplate: SurfaceTemplate = {
  id: 'test-tpl-mixed',
  name: 'Mixed',
  items: [
    { scope: 'target', kind: 'policy', config: { name: 'tpl-policy', rego: 'package x' } },
    { scope: 'edge', kind: 'policy', config: {} },
    { scope: 'target', kind: 'not-a-real-kind', config: {} },
  ],
};

const singletonTemplate: SurfaceTemplate = {
  id: 'test-tpl-singleton',
  name: 'Test singleton',
  items: [
    {
      scope: 'channel_policy',
      kind: 'caller-auth',
      config: { server_url: 'https://tpl', auth: 'tpl-token' },
    },
  ],
};

// Alias used by the full-kind backwards-compat test below.
const targetIdentityTemplate = singletonTemplate;

function existingSingletonNode(config: Record<string, unknown> = {}): CanvasNode {
  return {
    id: 'existing-singleton-1',
    type: 'caller-auth',
    label: 'Caller Auth',
    configured: true,
    config,
  };
}

describe('placement: planTemplate', () => {
  it('marks singleton items as clean when the canvas is empty', () => {
    const plan = planTemplate(singletonTemplate, []);
    expect(plan.clean).toHaveLength(1);
    expect(plan.conflicts).toHaveLength(0);
    expect(plan.unsupported).toHaveLength(0);
  });

  it('flags a conflict when a singleton kind is already present', () => {
    const plan = planTemplate(singletonTemplate, [existingSingletonNode()]);
    expect(plan.clean).toHaveLength(0);
    expect(plan.conflicts).toHaveLength(1);
    expect(plan.conflicts[0].existingNode.id).toBe('existing-singleton-1');
    expect(plan.conflicts[0].suggested).toBe('merge');
  });

  it('treats multi-cardinality items as clean even with collisions', () => {
    const plan = planTemplate(multiPolicyTemplate, [
      {
        id: 'existing-policy',
        type: 'policy',
        label: 'Policy',
        configured: true,
        config: { name: 'existing' },
      },
    ]);
    expect(plan.clean).toHaveLength(1);
    expect(plan.conflicts).toHaveLength(0);
  });

  it('routes unknown kinds and scopes into unsupported', () => {
    const plan = planTemplate(mixedTemplate, []);
    expect(plan.clean).toHaveLength(1);
    expect(plan.unsupported).toHaveLength(2);
    expect(plan.unsupported.map(u => u.item.kind).sort()).toEqual(['not-a-real-kind', 'policy']);
  });
});

describe('placement: applyPlan decisions', () => {
  it('skip leaves the existing node untouched and records the skip', () => {
    const existing = existingSingletonNode({ server_url: 'https://existing' });
    const plan = planTemplate(singletonTemplate, [existing]);
    const result = applyPlan(plan, [existing], { 0: 'skip' });
    expect(result.nextNodes).toHaveLength(1);
    expect(result.nextNodes[0].config).toEqual({ server_url: 'https://existing' });
    expect(result.placed).toHaveLength(0);
    expect(result.skipped).toHaveLength(1);
  });

  it('overwrite replaces the existing config with the template values', () => {
    const existing = existingSingletonNode({ server_url: 'https://existing', auth: 'old' });
    const plan = planTemplate(singletonTemplate, [existing]);
    const result = applyPlan(plan, [existing], { 0: 'overwrite' });
    expect(result.nextNodes).toHaveLength(1);
    expect(result.nextNodes[0].id).toBe('existing-singleton-1');
    expect(result.nextNodes[0].config?.server_url).toBe('https://tpl');
    expect(result.nextNodes[0].config?.auth).toBe('tpl-token');
    expect(result.nextNodes[0].configured).toBe(false);
    expect(result.placed).toHaveLength(1);
  });

  it('merge only fills empty fields and preserves existing values', () => {
    const existing = existingSingletonNode({ server_url: 'https://existing', auth: '' });
    const plan = planTemplate(singletonTemplate, [existing]);
    const result = applyPlan(plan, [existing], { 0: 'merge' });
    expect(result.nextNodes).toHaveLength(1);
    // existing server_url wins (non-empty)
    expect(result.nextNodes[0].config?.server_url).toBe('https://existing');
    // empty-string auth filled from template
    expect(result.nextNodes[0].config?.auth).toBe('tpl-token');
    expect(result.placed).toHaveLength(1);
  });

  it('place creates a second instance even though kind is singleton', () => {
    const existing = existingSingletonNode();
    const plan = planTemplate(singletonTemplate, [existing]);
    const result = applyPlan(plan, [existing], { 0: 'place' });
    expect(result.nextNodes).toHaveLength(2);
    expect(result.nextNodes.filter(n => n.type === 'caller-auth')).toHaveLength(2);
  });

  it('defaults to the suggested decision when none is supplied', () => {
    const existing = existingSingletonNode({ server_url: 'https://existing' });
    const plan = planTemplate(singletonTemplate, [existing]);
    // suggested === 'merge' — should keep existing server_url
    const result = applyPlan(plan, [existing], {});
    expect(result.nextNodes[0].config?.server_url).toBe('https://existing');
  });
});

describe('placement: applyTemplate one-shot', () => {
  it('appends a clean item without any decisions', () => {
    const result = applyTemplate(singletonTemplate, []);
    expect(result.nextNodes).toHaveLength(1);
    expect(result.nextNodes[0].type).toBe('caller-auth');
    expect(result.nextNodes[0].config?.server_url).toBe('https://tpl');
    expect(result.placed).toHaveLength(1);
  });

  it('reports unsupported items via skipped', () => {
    const result = applyTemplate(mixedTemplate, []);
    // 1 clean (policy/target), 2 unsupported (edge scope + unknown kind)
    expect(result.placed).toHaveLength(1);
    expect(result.skipped).toHaveLength(2);
  });
});

describe('placement: edge-bound items', () => {
  const identityEdgeTemplate: SurfaceTemplate = {
    id: 'test-tpl-identity-binding',
    name: 'Identity binding',
    items: [
      {
        scope: 'edge',
        kind: 'identity',
        address: 'access-point->target/response',
        config: { type: 'from_payload' },
      },
    ],
  };

  const trustRegistryVerificationTemplate: SurfaceTemplate = {
    id: 'test-tpl-trust-registry-verification',
    name: 'Trust Registry Verification',
    items: [
      {
        scope: 'edge',
        kind: 'trust-check',
        address: 'ap-ma/request',
        config: {
          queries: [
            {
              trust_registry_id: '',
              query_type: 'recognition',
              query: {},
            },
          ],
        },
      },
    ],
  };

  function ap(): CanvasNode {
    return {
      id: 'access-point',
      type: 'access-point',
      label: 'AP',
      configured: true,
      config: {},
    };
  }

  function target(): CanvasNode {
    return {
      id: 'target',
      type: 'target',
      label: 'Target',
      configured: true,
      config: {},
      parentId: 'access-point',
    };
  }

  it('puts edge items in clean when both endpoints exist on the canvas', () => {
    const plan = planTemplate(identityEdgeTemplate, [ap(), target()]);
    expect(plan.clean).toHaveLength(1);
    expect(plan.unsupported).toHaveLength(0);
  });

  it('moves edge items to unsupported when endpoints are missing', () => {
    const plan = planTemplate(identityEdgeTemplate, [ap()]);
    expect(plan.clean).toHaveLength(0);
    expect(plan.unsupported).toHaveLength(1);
    expect(plan.unsupported[0].reason).toMatch(/edge .* is not on the canvas/);
  });

  it('emits an EdgeDropIntent (not a free node) when applied', () => {
    const result = applyTemplate(identityEdgeTemplate, [ap(), target()]);
    // Edge items must NOT be appended as free nodes — they go through
    // builder.handleEdgeTemplateDrop so the parentId/slot topology is
    // computed correctly.
    expect(result.nextNodes).toHaveLength(2); // unchanged
    expect(result.edgeDrops).toHaveLength(1);
    expect(result.edgeDrops[0]).toMatchObject({
      kind: 'identity',
      edgeSourceId: 'access-point',
      edgeTargetId: 'target',
      edgeDirection: 'response',
      config: { type: 'from_payload' },
    });
    expect(result.placed).toHaveLength(1);
  });

  it('places Trust Registry Verification through the Trust Check caller-leg flow', () => {
    const result = applyTemplate(trustRegistryVerificationTemplate, [ap(), target()]);

    expect(result.nextNodes).toHaveLength(2);
    expect(result.edgeDrops).toHaveLength(1);
    expect(result.edgeDrops[0]).toMatchObject({
      kind: 'trust-check',
      edgeSourceId: 'access-point',
      edgeTargetId: 'target',
      edgeDirection: 'request',
      config: {
        queries: [
          {
            trust_registry_id: '',
            query_type: 'recognition',
            query: {},
          },
        ],
      },
    });
    expect(result.skipped).toHaveLength(0);
  });

  it('rejects malformed addresses', () => {
    const tpl: SurfaceTemplate = {
      id: 'bad-addr',
      name: 'Bad address',
      items: [{ scope: 'edge', kind: 'identity', config: {} }],
    };
    const plan = planTemplate(tpl, [ap(), target()]);
    expect(plan.unsupported).toHaveLength(1);
    expect(plan.unsupported[0].reason).toMatch(/malformed address/);
  });
});

describe('placement: edge archetype shorthand', () => {
  const credentialDelegationTpl: SurfaceTemplate = {
    id: 'test-tpl-cred-delegation',
    name: 'Credential delegation',
    items: [
      {
        scope: 'edge',
        kind: 'credential-delegation',
        address: 'ma-external/request',
        config: { delegated_credentials: [] },
      },
    ],
  };

  const mcpToolGatingTpl: SurfaceTemplate = {
    id: 'test-tpl-mcp-tool-gating',
    name: 'MCP Tool Gating',
    tags: ['mcp'],
    items: [
      {
        scope: 'edge',
        kind: 'mcp-tool-gating',
        address: 'ma-external/response',
        config: { default_effect: 'allow', gates: [] },
      },
    ],
  };

  const workloadBindingTpl: SurfaceTemplate = {
    id: 'workload-binding',
    name: 'Workload Binding',
    items: [
      {
        scope: 'edge',
        kind: 'workload-binding',
        address: 'ma-external/request',
        config: { enabled: true, caller_source: 'transit_token' },
      },
    ],
  };

  function targetNode(): CanvasNode {
    return { id: 'target', type: 'target', label: 'MA', configured: true, config: {} };
  }
  function accessPointNode(): CanvasNode {
    return { id: 'access-point', type: 'access-point', label: 'AP', configured: true, config: {} };
  }
  function npcEndpoint(): CanvasNode {
    return {
      id: 'ext',
      type: 'npc-endpoint',
      label: 'EXT',
      configured: true,
      config: {},
      parentId: 'target',
    };
  }
  function remoteGw(): CanvasNode {
    return {
      id: 'rgw',
      type: 'remote-gateway',
      label: 'GW2',
      configured: true,
      config: {},
      parentId: 'target',
    };
  }

  it('resolves ma-external/request onto target->npc-endpoint', () => {
    const result = applyTemplate(credentialDelegationTpl, [targetNode(), npcEndpoint()]);
    expect(result.edgeDrops).toHaveLength(1);
    expect(result.edgeDrops[0]).toMatchObject({
      kind: 'credential-delegation',
      edgeSourceId: 'target',
      edgeTargetId: 'ext',
      edgeDirection: 'request',
    });
    expect(result.skipped).toHaveLength(0);
  });

  it('resolves ma-external/request onto target->remote-gateway when that is the external flavour', () => {
    const result = applyTemplate(credentialDelegationTpl, [targetNode(), remoteGw()]);
    expect(result.edgeDrops).toHaveLength(1);
    expect(result.edgeDrops[0]).toMatchObject({
      edgeSourceId: 'target',
      edgeTargetId: 'rgw',
      edgeDirection: 'request',
    });
  });

  it('drops Workload Binding onto the primary Target request edge', () => {
    const result = applyTemplate(workloadBindingTpl, [targetNode(), npcEndpoint()]);

    expect(result.nextNodes).toHaveLength(2);
    expect(result.edgeDrops).toHaveLength(1);
    expect(result.edgeDrops[0]).toMatchObject({
      kind: 'workload-binding',
      edgeSourceId: 'target',
      edgeTargetId: 'ext',
      edgeDirection: 'request',
      config: { enabled: true, caller_source: 'transit_token' },
    });
    expect(result.placed).toHaveLength(1);
    expect(result.skipped).toHaveLength(0);
  });

  it('does not place Workload Binding without a primary Target edge', () => {
    const plan = planTemplate(workloadBindingTpl, [targetNode()]);

    expect(plan.clean).toHaveLength(0);
    expect(plan.unsupported).toHaveLength(1);
    expect(plan.unsupported[0].reason).toMatch(/edge archetype 'ma-external' is not on the canvas/);
  });

  const trustRecorderTpl: SurfaceTemplate = {
    id: 'trust-registry-recording',
    name: 'Trust Registry Recording',
    items: [
      {
        scope: 'edge',
        kind: 'trust-recorder',
        address: 'ap-ma/response',
        config: {},
      },
    ],
  };

  it('drops Trust Recorder onto the AP response edge', () => {
    const result = applyTemplate(trustRecorderTpl, [accessPointNode(), targetNode()]);

    expect(result.nextNodes).toHaveLength(2);
    expect(result.edgeDrops).toHaveLength(1);
    expect(result.edgeDrops[0]).toMatchObject({
      kind: 'trust-recorder',
      edgeSourceId: 'access-point',
      edgeTargetId: 'target',
      edgeDirection: 'response',
      config: {},
    });
    expect(result.placed).toHaveLength(1);
    expect(result.skipped).toHaveLength(0);
  });

  it('does not place Trust Recorder without the AP-to-managed-agent edge', () => {
    const plan = planTemplate(trustRecorderTpl, [targetNode()]);

    expect(plan.clean).toHaveLength(0);
    expect(plan.unsupported).toHaveLength(1);
    expect(plan.unsupported[0].reason).toMatch(/edge archetype 'ap-ma' is not on the canvas/);
  });

  const a2aMetadataInjectionTpl: SurfaceTemplate = {
    id: 'a2a-metadata-injection',
    name: 'A2A Metadata Injection',
    tags: ['a2a', 'metadata', 'injection'],
    items: [
      {
        scope: 'edge',
        kind: 'custom-metadata',
        address: 'ap-ma/request',
        config: { entries: [] },
      },
    ],
  };

  it('drops A2A Metadata Injection onto the inbound request edge', () => {
    const result = applyTemplate(a2aMetadataInjectionTpl, [accessPointNode(), targetNode()]);

    expect(result.nextNodes).toHaveLength(2);
    expect(result.edgeDrops).toHaveLength(1);
    expect(result.edgeDrops[0]).toMatchObject({
      kind: 'custom-metadata',
      edgeSourceId: 'access-point',
      edgeTargetId: 'target',
      edgeDirection: 'request',
      config: { entries: [] },
    });
    expect(result.placed).toHaveLength(1);
    expect(result.skipped).toHaveLength(0);
  });

  it('drops MCP Tool Gating on the external-target response flow', () => {
    const result = applyTemplate(mcpToolGatingTpl, [targetNode(), npcEndpoint()]);

    expect(result.edgeDrops).toHaveLength(1);
    expect(result.edgeDrops[0]).toMatchObject({
      kind: 'mcp-tool-gating',
      edgeSourceId: 'target',
      edgeTargetId: 'ext',
      edgeDirection: 'response',
      config: { default_effect: 'allow', gates: [] },
    });
    expect(result.skipped).toHaveLength(0);
  });

  it('reports unknown archetype id as unsupported', () => {
    const tpl: SurfaceTemplate = {
      id: 'bad-arch',
      name: 'Bad archetype',
      items: [
        { scope: 'edge', kind: 'identity', address: 'no-such-archetype/request', config: {} },
      ],
    };
    const plan = planTemplate(tpl, [targetNode(), npcEndpoint()]);
    expect(plan.unsupported).toHaveLength(1);
    expect(plan.unsupported[0].reason).toMatch(/unknown edge archetype/);
  });

  it('reports archetype with no matching pair on canvas as unsupported', () => {
    const plan = planTemplate(credentialDelegationTpl, [targetNode()]);
    expect(plan.unsupported).toHaveLength(1);
    expect(plan.unsupported[0].reason).toMatch(/archetype 'ma-external' is not on the canvas/);
  });
});

describe('placement: full-kind templates', () => {
  it('rejects full templates from planTemplate with a synthetic unsupported entry', () => {
    const fullTpl: SurfaceTemplate = {
      id: 'tpl-full-mtls',
      name: 'mTLS A2A',
      kind: 'full',
      surface: {
        access_point: { listen_address: '$HOST', route: '$ROUTE' },
        target: { endpoint: '$TARGET_ENDPOINT' },
      },
    };
    const plan = planTemplate(fullTpl, []);
    expect(plan.clean).toHaveLength(0);
    expect(plan.conflicts).toHaveLength(0);
    expect(plan.unsupported).toHaveLength(1);
    expect(plan.unsupported[0].reason).toMatch(/applyFullTemplate/);
  });

  it('treats absent kind as partial (backwards compatible)', () => {
    const plan = planTemplate(targetIdentityTemplate, []);
    expect(plan.clean).toHaveLength(1);
    expect(plan.unsupported).toHaveLength(0);
  });
});
