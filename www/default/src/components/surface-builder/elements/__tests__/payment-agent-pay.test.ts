import { paymentDefinition } from '../payment/definition';
import type { CanvasNode, PayloadContext } from '../types';

function makeCtx(nodes: CanvasNode[], protocol = 'mcp'): PayloadContext {
  return {
    protocol,
    surfaceMeta: { name: 't', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: (type: string) => nodes.filter(n => n.type === type),
    firstNodeOfType: (type: string) => nodes.find(n => n.type === type),
  } as any;
}

function paymentNode(config: Record<string, unknown>): CanvasNode {
  return { id: 'pay', type: 'payment', label: '', configured: true, config } as any;
}

describe('paymentDefinition — Agent-Pay delegation (Model B)', () => {
  it('buildPayload emits a minimal delegation policy', () => {
    const slices = paymentDefinition.buildPayload!(
      makeCtx([
        paymentNode({
          enabled: true,
          provider: 'agent_pay',
          payment_gateway_id: 'gw-1',
          payment_surface_id: 'pay-ch',
        }),
      ])
    ) as Array<{ path: string; value: Record<string, unknown> }>;
    expect(slices).toHaveLength(1);
    expect(slices[0]).toEqual({
      path: 'target.payment_policy',
      value: {
        type: 'x402',
        enabled: true,
        provider: 'agent_pay',
        payment_gateway_id: 'gw-1',
        payment_surface_id: 'pay-ch',
      },
    });
  });

  it('buildPayload emits delegated_rail: mpp when the operator selects MPP', () => {
    const slices = paymentDefinition.buildPayload!(
      makeCtx([
        paymentNode({
          enabled: true,
          provider: 'agent_pay',
          payment_gateway_id: 'gw-1',
          payment_surface_id: 'pay-ch',
          payment_kind: 'mpp',
        }),
      ])
    ) as Array<{ path: string; value: Record<string, unknown> }>;
    expect(slices[0].value).toEqual({
      type: 'x402',
      enabled: true,
      provider: 'agent_pay',
      payment_gateway_id: 'gw-1',
      payment_surface_id: 'pay-ch',
      delegated_rail: 'mpp',
    });
  });

  it('buildPayload omits delegated_rail for the x402 default', () => {
    const slices = paymentDefinition.buildPayload!(
      makeCtx([
        paymentNode({
          enabled: true,
          provider: 'agent_pay',
          payment_gateway_id: 'gw-1',
          payment_surface_id: 'pay-ch',
          payment_kind: 'x402',
        }),
      ])
    ) as Array<{ path: string; value: Record<string, unknown> }>;
    expect(slices[0].value).not.toHaveProperty('delegated_rail');
  });

  it('buildPayload does not leak local x402 config in agent_pay mode', () => {
    const slices = paymentDefinition.buildPayload!(
      makeCtx([
        paymentNode({
          enabled: true,
          provider: 'agent_pay',
          payment_gateway_id: 'gw-1',
          payment_surface_id: 'pay-ch',
          verification_mode: 'mock',
          settlement_mode: 'none',
          payment_requirements: [{ recipient_id: 'x', amount: '1' }],
        }),
      ])
    ) as Array<{ path: string; value: Record<string, unknown> }>;
    expect(slices[0].value).not.toHaveProperty('verification_mode');
    expect(slices[0].value).not.toHaveProperty('settlement_mode');
    expect(slices[0].value).not.toHaveProperty('payment_requirements');
  });

  it('buildPayload returns undefined when gateway or surface is missing', () => {
    expect(
      paymentDefinition.buildPayload!(
        makeCtx([paymentNode({ enabled: true, provider: 'agent_pay', payment_gateway_id: 'gw-1' })])
      )
    ).toBeUndefined();
    expect(
      paymentDefinition.buildPayload!(
        makeCtx([
          paymentNode({ enabled: true, provider: 'agent_pay', payment_surface_id: 'pay-ch' }),
        ])
      )
    ).toBeUndefined();
  });

  it('configFromPayload round-trips an agent_pay policy', () => {
    const cfg = paymentDefinition.configFromPayload!({
      type: 'x402',
      enabled: true,
      provider: 'agent_pay',
      payment_gateway_id: 'gw-1',
      payment_surface_id: 'pay-ch',
    });
    expect(cfg.provider).toBe('agent_pay');
    expect(cfg.payment_gateway_id).toBe('gw-1');
    expect(cfg.payment_surface_id).toBe('pay-ch');
    expect(cfg.payment_kind).toBe('x402');
  });

  it('configFromPayload recovers the mpp rail selection from delegated_rail', () => {
    const cfg = paymentDefinition.configFromPayload!({
      type: 'x402',
      enabled: true,
      provider: 'agent_pay',
      payment_gateway_id: 'gw-1',
      payment_surface_id: 'pay-ch',
      delegated_rail: 'mpp',
    });
    expect(cfg.payment_kind).toBe('mpp');
  });

  it('incompleteReason flags missing gateway/surface in agent_pay mode', () => {
    expect(paymentDefinition.incompleteReason!({ enabled: true, provider: 'agent_pay' })).toMatch(
      /gateway/i
    );
    expect(
      paymentDefinition.incompleteReason!({
        enabled: true,
        provider: 'agent_pay',
        payment_gateway_id: 'gw-1',
      })
    ).toMatch(/surface/i);
    expect(
      paymentDefinition.incompleteReason!({
        enabled: true,
        provider: 'agent_pay',
        payment_gateway_id: 'gw-1',
        payment_surface_id: 'pay-ch',
      })
    ).toBeNull();
  });

  it('marks an enabled local x402 payment incomplete without payment options', () => {
    expect(
      paymentDefinition.incompleteReason!({
        enabled: true,
        payment_kind: 'x402',
        payment_requirements: [],
      })
    ).toMatch(/payment options/i);
    expect(
      paymentDefinition.incompleteReason!({
        enabled: true,
        payment_kind: 'x402',
        payment_requirements: [{ amount: '1', recipient_id: 'recipient-1' }],
      })
    ).toBeNull();
  });

  it('summary reports agent-pay with the delegated rail', () => {
    expect(paymentDefinition.summary!({ enabled: true, provider: 'agent_pay' })).toBe(
      'agent-pay (x402)'
    );
    expect(
      paymentDefinition.summary!({ enabled: true, provider: 'agent_pay', payment_kind: 'mpp' })
    ).toBe('agent-pay (mpp)');
    expect(paymentDefinition.summary!({ enabled: true, payment_kind: 'x402' })).toBe('x402');
  });
});
