import { paymentDefinition } from '../payment/definition';
import { classifyPaymentPolicy, migrateLegacyPaymentConfig } from '../payment/policy';
import { registry } from '../index';
import type { CanvasNode, PayloadContext, SurfaceContext } from '../types';

function makeCtx(nodes: CanvasNode[], protocol = 'mcp'): PayloadContext {
  return {
    protocol,
    surfaceMeta: { name: 't', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: type => nodes.filter(n => n.type === type),
    firstNodeOfType: type => nodes.find(n => n.type === type),
  };
}

function paymentNode(config: Record<string, unknown>): CanvasNode {
  return { id: 'pay', type: 'payment', label: '', configured: true, config };
}

const build = (config: Record<string, unknown>) =>
  paymentDefinition.buildPayload!(makeCtx([paymentNode(config)])) as
    | Array<{ path: string; value: Record<string, unknown> }>
    | undefined;

const snapshot = {
  version: '1',
  payable: { id: 'pay-ch', name: 'Premium' },
  amount: { amount: '0.01', unit: 'USDC' },
  payment_points: [
    {
      id: 'x402:base',
      label: 'USDC on Base',
      protocol: 'x402',
      credential: 'eip3009_signature',
      detail: { kind: 'onChain', scheme: 'exact', network: 'base', pay_to: '0xabc' },
    },
  ],
};

const ctx = (protocol: 'mcp' | 'a2a'): SurfaceContext => ({
  protocol,
  accessPoint: {},
  target: {},
  transitPoints: [],
  allNodes: [],
});

describe('paymentDefinition — agent-pay', () => {
  it('buildPayload emits only the agent_pay shape', () => {
    expect(
      build({
        enabled: true,
        provider: 'agent_pay',
        delegated_rail: 'mpp',
        payment_gateway_id: ' gw-1 ',
        payment_surface_id: 'pay-ch$eu',
        verification_mode: 'mock',
        manifest_snapshot: snapshot,
      })
    ).toEqual([
      {
        path: 'target.payment_policy',
        value: { type: 'agent_pay', payment_gateway_id: 'gw-1', payment_surface_id: 'pay-ch$eu' },
      },
    ]);
  });

  it('buildPayload passes triggers and options through', () => {
    const [slice] = build({
      payment_gateway_id: 'gw-1',
      payment_surface_id: 'pay-ch',
      mcp_payment_triggers: { mode: 'match', patterns: ['^premium_', ' ', ''] },
      a2a_method_filters: [{ method: 'message/send', message_patterns: ['', '^buy'] }],
      require_all: true,
      timeout_ms: 5000,
      share_payer_email: true,
    })!;
    expect(slice.value).toEqual({
      type: 'agent_pay',
      payment_gateway_id: 'gw-1',
      payment_surface_id: 'pay-ch',
      mcp_payment_triggers: { mode: 'match', patterns: ['^premium_'] },
      a2a_method_filters: [{ method: 'message/send', message_patterns: ['^buy'] }],
      require_all: true,
      timeout_ms: 5000,
      share_payer_email: true,
    });
  });

  it('buildPayload omits options left at their defaults', () => {
    const [slice] = build({
      payment_gateway_id: 'gw-1',
      payment_surface_id: 'pay-ch',
      require_all: false,
      share_payer_email: false,
      timeout_ms: undefined,
    })!;
    expect(slice.value).not.toHaveProperty('require_all');
    expect(slice.value).not.toHaveProperty('share_payer_email');
    expect(slice.value).not.toHaveProperty('timeout_ms');
  });

  it('buildPayload returns undefined when gateway or surface is missing', () => {
    expect(build({ payment_gateway_id: 'gw-1' })).toBeUndefined();
    expect(build({ payment_surface_id: 'pay-ch' })).toBeUndefined();
    expect(build({ payment_gateway_id: 'gw-1', payment_surface_id: '  ' })).toBeUndefined();
  });

  it('configFromPayload keeps manifest_snapshot, and buildPayload never emits it', () => {
    const cfg = paymentDefinition.configFromPayload!({
      type: 'agent_pay',
      payment_gateway_id: 'gw-1',
      payment_surface_id: 'pay-ch',
      timeout_ms: 8000,
      manifest_snapshot: snapshot,
    });
    expect(cfg).toEqual({
      payment_gateway_id: 'gw-1',
      payment_surface_id: 'pay-ch',
      timeout_ms: 8000,
      manifest_snapshot: snapshot,
    });
    expect(build(cfg)![0].value).not.toHaveProperty('manifest_snapshot');
  });

  it('configFromPayload normalises a legacy agent_pay x402 policy', () => {
    const cfg = paymentDefinition.configFromPayload!({
      type: 'x402',
      enabled: true,
      provider: 'agent_pay',
      delegated_rail: 'mpp',
      payment_gateway_id: 'gw-1',
      payment_surface_id: 'pay-ch',
      mcp_payment_triggers: { mode: 'all' },
    });
    expect(cfg).toEqual({
      payment_gateway_id: 'gw-1',
      payment_surface_id: 'pay-ch',
      mcp_payment_triggers: { mode: 'all' },
    });
    expect(build(cfg)![0].value).toEqual({
      type: 'agent_pay',
      payment_gateway_id: 'gw-1',
      payment_surface_id: 'pay-ch',
      mcp_payment_triggers: { mode: 'all' },
    });
  });

  it.each([
    ['x402', { type: 'x402', enabled: true, verification_mode: 'mock', payment_requirements: [] }],
    ['mpp', { type: 'mpp', enabled: true, realm: 'example.com', secret_key: '$MPP' }],
  ])('flags a local %s policy as unsupported and does not erase it', (kind, legacy) => {
    const cfg = paymentDefinition.configFromPayload!(legacy);
    expect(cfg).toEqual({ unsupported_legacy: kind, original: legacy });
    expect(build(cfg)).toEqual([{ path: 'target.payment_policy', value: legacy }]);
    expect(paymentDefinition.incompleteReason!(cfg)).toMatch(/no longer supported/i);
    const errors = registry
      .getDependencyWarnings('payment', cfg, ctx('mcp'))
      .filter(w => w.severity === 'error');
    expect(errors.map(w => w.message)).toEqual([expect.stringMatching(/returns 503/)]);
  });

  it('migrating a legacy policy keeps only its triggers', () => {
    const migrated = migrateLegacyPaymentConfig({
      unsupported_legacy: 'mpp',
      original: {
        type: 'mpp',
        realm: 'example.com',
        secret_key: '$MPP',
        mcp_payment_triggers: { mode: 'exclude', patterns: ['^free_'] },
        a2a_method_filters: [{ method: 'tasks/get' }],
      },
    });
    expect(migrated).toEqual({
      mcp_payment_triggers: { mode: 'exclude', patterns: ['^free_'] },
      a2a_method_filters: [{ method: 'tasks/get', message_patterns: [] }],
    });
  });

  it('incompleteReason requires a gateway and a surface', () => {
    expect(paymentDefinition.incompleteReason!({})).toMatch(/gateway/i);
    expect(paymentDefinition.incompleteReason!({ payment_gateway_id: 'gw-1' })).toMatch(/surface/i);
    expect(
      paymentDefinition.incompleteReason!({
        payment_gateway_id: 'gw-1',
        payment_surface_id: 'pay-ch',
      })
    ).toBeNull();
  });

  it('summary shows the snapshot price', () => {
    expect(
      paymentDefinition.summary!({
        payment_gateway_id: 'gw-1',
        payment_surface_id: 'pay-ch',
        manifest_snapshot: snapshot,
      })
    ).toBe('agent-pay · 0.01 USDC');
    expect(
      paymentDefinition.summary!({ payment_gateway_id: 'gw-1', payment_surface_id: 'pay-ch' })
    ).toBe('agent-pay');
    expect(paymentDefinition.summary!({})).toBeNull();
    expect(paymentDefinition.summary!({ unsupported_legacy: 'mpp' })).toBe(
      'unsupported (local mpp)'
    );
  });

  describe('trigger pattern checks', () => {
    const base = { payment_gateway_id: 'gw-1', payment_surface_id: 'pay-ch' };
    const checks = (cfg: Record<string, unknown>, protocol: 'mcp' | 'a2a' = 'mcp') =>
      registry.getDependencyWarnings('payment', cfg, ctx(protocol));

    it('only warns about a pattern the browser doubts, so it never blocks Save', () => {
      const cfg = {
        ...base,
        mcp_payment_triggers: { mode: 'match', patterns: ['(?=lookahead)'] },
      };

      expect(checks(cfg)).toEqual([
        expect.objectContaining({
          severity: 'warning',
          message: expect.stringMatching(/may not be accepted by the gateway/),
        }),
      ]);
      expect(checks(cfg).filter(w => w.severity === 'error')).toEqual([]);
    });

    it('does not even warn about syntax only the gateway accepts', () => {
      expect(
        checks({
          ...base,
          mcp_payment_triggers: { mode: 'match', patterns: ['(?i)^premium_', '(?P<tool>get_.*)'] },
        })
      ).toEqual([]);
    });

    it('never checks A2A message text as a regular expression', () => {
      expect(
        checks(
          {
            ...base,
            a2a_method_filters: [{ method: 'message/send', message_patterns: ['(bad', '(?=x)'] }],
          },
          'a2a'
        )
      ).toEqual([]);
    });

    it('still sends the pattern the browser doubted, leaving the verdict to the gateway', () => {
      const [slice] = build({
        ...base,
        mcp_payment_triggers: { mode: 'match', patterns: ['(?=lookahead)'] },
      })!;
      expect(slice.value.mcp_payment_triggers).toEqual({
        mode: 'match',
        patterns: ['(?=lookahead)'],
      });
    });
  });

  describe('timeout bounds', () => {
    const base = {
      payment_gateway_id: 'gw-1',
      payment_surface_id: 'pay-ch',
      mcp_payment_triggers: { mode: 'all' },
    };
    const errors = (timeout_ms: unknown) =>
      registry
        .getDependencyWarnings('payment', { ...base, timeout_ms }, ctx('mcp'))
        .filter(w => w.severity === 'error')
        .map(w => w.message);

    it.each([999, 500, 0, -1000, 120001, 200000, 1.5, 1500.5, 'abc'])(
      'blocks Save for %s',
      timeout => {
        expect(errors(timeout)).toEqual([
          'Timeout must be a whole number of milliseconds from 1000 to 120000.',
        ]);
      }
    );

    it.each([1000, 1001, 15000, 120000, '5000', undefined, null, ''])('accepts %s', timeout => {
      expect(errors(timeout)).toEqual([]);
    });

    it('sends the boundary values and drops a value the gateway would refuse', () => {
      const sent = (timeout_ms: unknown) => build({ ...base, timeout_ms })![0].value.timeout_ms;
      expect(sent(1000)).toBe(1000);
      expect(sent(120000)).toBe(120000);
      expect(sent('8000')).toBe(8000);
      expect(sent(999)).toBeUndefined();
      expect(sent(120001)).toBeUndefined();
      expect(sent('')).toBeUndefined();
      expect(sent(null)).toBeUndefined();
    });
  });

  it('charging every request satisfies the trigger checks', () => {
    const cfg = { payment_gateway_id: 'gw-1', payment_surface_id: 'pay-ch', require_all: true };
    expect(registry.getDependencyWarnings('payment', cfg, ctx('mcp'))).toEqual([]);
    expect(registry.getDependencyWarnings('payment', cfg, ctx('a2a'))).toEqual([]);
  });

  it.each([
    ['x402 without a provider', { type: 'x402', enabled: true }, 'unsupported'],
    ['x402 with enabled absent', { type: 'x402', provider: 'local' }, 'unsupported'],
    ['mpp', { type: 'mpp' }, 'unsupported'],
    ['disabled x402', { type: 'x402', enabled: false }, 'preserved'],
    ['disabled mpp', { type: 'mpp', enabled: false }, 'preserved'],
    [
      'disabled agent_pay x402',
      { type: 'x402', provider: 'agent_pay', enabled: false },
      'preserved',
    ],
    ['enabled agent_pay x402', { type: 'x402', provider: 'agent_pay' }, 'agent_pay'],
    ['agent_pay', { type: 'agent_pay' }, 'agent_pay'],
  ])('classifies %s', (_name, slice, expected) => {
    expect(classifyPaymentPolicy(slice)).toBe(expected);
  });

  it.each([
    ['x402', { type: 'x402', enabled: false, verification_mode: 'mock', payment_requirements: [] }],
    ['mpp', { type: 'mpp', enabled: false, realm: 'example.com' }],
    [
      'agent_pay x402',
      { type: 'x402', provider: 'agent_pay', enabled: false, payment_gateway_id: 'gw-1' },
    ],
  ])('keeps a disabled %s policy unchanged without blocking save', (_kind, disabled) => {
    const cfg = paymentDefinition.configFromPayload!(disabled);
    expect(cfg).toEqual({ preserved_policy: disabled });
    expect(build(cfg)).toEqual([{ path: 'target.payment_policy', value: disabled }]);
    expect(paymentDefinition.incompleteReason!(cfg)).toBeNull();
    expect(paymentDefinition.summary!(cfg)).toBe('disabled');
    expect(registry.getDependencyWarnings('payment', cfg, ctx('mcp'))).toEqual([]);
    expect(registry.getDependencyWarnings('payment', cfg, ctx('a2a'))).toEqual([]);
  });

  it('replaces a disabled policy once an agent-pay surface is chosen', () => {
    const disabled = { type: 'x402', enabled: false };
    const cfg = {
      ...paymentDefinition.configFromPayload!(disabled),
      payment_gateway_id: 'gw-1',
    };
    expect(paymentDefinition.incompleteReason!(cfg)).toMatch(/surface/i);
    const [slice] = build({ ...cfg, payment_surface_id: 'pay-ch', require_all: true })!;
    expect(slice.value).toEqual({
      type: 'agent_pay',
      payment_gateway_id: 'gw-1',
      payment_surface_id: 'pay-ch',
      require_all: true,
    });
  });
});
