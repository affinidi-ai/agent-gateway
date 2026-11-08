import { surfacesUsingPaymentGateway } from '../usedBy';
import type { AgentSurface } from '../../../api';

const surface = (over: Partial<AgentSurface>): AgentSurface =>
  ({
    surface_id: 's',
    name: 's',
    description: '',
    status: 'active',
    tags: [],
    access_point: { listen_address: '0.0.0.0:8443', route: '/s', protocol: 'mcp' },
    target: { endpoint: 'https://upstream' },
    ...over,
  }) as AgentSurface;

const agentPay = (gatewayId: string) => ({
  type: 'agent_pay' as const,
  payment_gateway_id: gatewayId,
  payment_surface_id: 'pay-ch',
});

describe('surfacesUsingPaymentGateway', () => {
  it('finds surfaces whose base policy or a variant override names the gateway', () => {
    const uses = surfacesUsingPaymentGateway(
      [
        surface({
          surface_id: 'base',
          name: 'Base',
          target: { endpoint: 'x', payment_policy: agentPay('gw-pay') },
        }),
        surface({
          surface_id: 'variant-only',
          name: 'Variant only',
          variants: [
            {
              id: 'v1',
              alias: 'eu',
              name: 'EU',
              overrides: { target: { payment_policy: agentPay('gw-pay') } },
            },
            {
              id: 'v2',
              alias: 'us',
              name: 'US',
              overrides: { target: { payment_policy: agentPay('gw-other') } },
            },
            { id: 'v3', alias: 'free', name: 'Free', overrides: {} },
          ],
        }),
      ],
      'gw-pay'
    );

    expect(uses).toEqual([
      { surfaceId: 'base', name: 'Base', base: true, variants: [] },
      { surfaceId: 'variant-only', name: 'Variant only', base: false, variants: ['eu'] },
    ]);
  });

  it('ignores other gateways, legacy policies and surfaces without a payment policy', () => {
    expect(
      surfacesUsingPaymentGateway(
        [
          surface({
            surface_id: 'other',
            target: { endpoint: 'x', payment_policy: agentPay('gw-other') },
          }),
          surface({
            surface_id: 'legacy',
            target: {
              endpoint: 'x',
              payment_policy: { type: 'x402', payment_gateway_id: 'gw-pay' },
            },
          }),
          surface({ surface_id: 'plain' }),
          surface({ surface_id: 'no-overrides', variants: [{ id: 'v', alias: 'a', name: 'A' }] }),
        ],
        'gw-pay'
      )
    ).toEqual([]);
  });
});
