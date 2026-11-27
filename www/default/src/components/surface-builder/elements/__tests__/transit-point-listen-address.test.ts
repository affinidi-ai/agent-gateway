import { getCachedOutboundListenAddresses } from '../access-point/defaults';
import { registry } from '../index';
import type { SurfaceContext } from '../types';

jest.mock('../access-point/defaults', () => {
  const actual = jest.requireActual('../access-point/defaults');
  return {
    __esModule: true,
    ...actual,
    getCachedOutboundListenAddresses: jest.fn(),
  };
});

const mockOutbound = getCachedOutboundListenAddresses as jest.MockedFunction<
  typeof getCachedOutboundListenAddresses
>;

function makeCtx(): SurfaceContext {
  return {
    protocol: 'a2a',
    accessPoint: null,
    target: null,
    transitPoints: [],
    allNodes: [],
  };
}

function listenAddressErrors(config: Record<string, unknown>): string[] {
  return registry
    .getDependencyWarnings('transit-point-a2a', config, makeCtx())
    .filter(w => w.severity === 'error')
    .map(w => w.message);
}

describe('transit-point listen_address validation', () => {
  afterEach(() => mockOutbound.mockReset());

  it('skips the check while the routing config has not loaded', () => {
    mockOutbound.mockReturnValue(null);
    expect(
      listenAddressErrors({
        target_endpoint: 'https://upstream.example.com',
        listen_address: 'https://not-a-listener.example.com',
      })
    ).toEqual([]);
  });

  it('passes when listen_address is a configured outbound listener', () => {
    mockOutbound.mockReturnValue(['https://out.example.com']);
    expect(
      listenAddressErrors({
        target_endpoint: 'https://upstream.example.com',
        listen_address: 'https://out.example.com',
      })
    ).toEqual([]);
  });

  it('faults when listen_address is set but not a configured outbound listener', () => {
    mockOutbound.mockReturnValue(['https://out.example.com']);
    expect(
      listenAddressErrors({
        target_endpoint: 'https://upstream.example.com',
        listen_address: 'https://inbound-only.example.com',
      })
    ).toEqual([
      'Listen address is not a configured outbound listener. Pick one from the dropdown.',
    ]);
  });

  it('reports a missing outbound listener when none are configured', () => {
    mockOutbound.mockReturnValue([]);
    expect(
      listenAddressErrors({
        target_endpoint: 'https://upstream.example.com',
        listen_address: 'https://out.example.com',
      })
    ).toEqual([
      'No outbound listener is configured. Add an outbound listener before using a transit point.',
    ]);
  });

  it('does not flag an empty listen_address (handled by incompleteReason)', () => {
    mockOutbound.mockReturnValue(['https://out.example.com']);
    expect(
      listenAddressErrors({
        target_endpoint: 'https://upstream.example.com',
        listen_address: '',
      })
    ).toEqual([]);
  });
});

describe('transit-point Listen Path typed without a prefix', () => {
  const incompleteReason = (config: Record<string, unknown>) =>
    registry.get('transit-point-a2a')?.incompleteReason?.(config);
  const typedWithoutPrefix = {
    listen_address: 'https://out.example.com',
    route_prefix: '',
    route_suffix: 'partner-a',
  };

  // The panel keeps the stored path while no prefix is picked, so the typed one would
  // be dropped on save, whatever the point routes to.
  it('blocks the save on a URL route and on a gateway route alike', () => {
    for (const target of [
      { target_endpoint: 'https://upstream.example.com' },
      { endpoint_type: 'gateway', gateway_id: 'gw-1', target_endpoint: 'fabric://gw-1/surface-1' },
    ]) {
      expect(incompleteReason({ ...typedWithoutPrefix, ...target })).toBe(
        'Pick a surface prefix for the Listen Path'
      );
    }
  });
});

describe('a stored Transit Point with no listener of its own', () => {
  const pointConfigs = (transit: Record<string, unknown>) =>
    registry
      .nodesFromPayload({
        name: 's',
        access_point: { route: '/a2a', protocol: 'a2a' },
        target: { endpoint: 'https://agent.example.com/a2a' },
        transit: {
          points: [
            {
              id: 'tp-1',
              alias: 'partner',
              protocol: 'a2a',
              target_endpoint: 'https://upstream.example.com',
            },
            {
              id: 'tp-2',
              alias: 'own',
              protocol: 'a2a',
              target_endpoint: 'https://upstream.example.com',
              listen_address: 'https://own.example.com',
            },
          ],
          ...transit,
        },
      })
      .filter(n => n.type === 'transit-point-a2a')
      .map(n => n.config ?? {});

  // The panel seeds a node with no address as a new one, so the inherited listener has
  // to be on the node, or opening it would move the point and give it a random path.
  it('shows the surface outbound listener it answers on', () => {
    const [inherited, own] = pointConfigs({
      outbound_listen_address: 'https://second.example.com',
    });

    expect(inherited.listen_address).toBe('https://second.example.com');
    expect(inherited.listen_path).toBeUndefined();
    expect(own.listen_address).toBe('https://own.example.com');
  });

  it('is left without one when the surface names none', () => {
    const [inherited] = pointConfigs({});

    expect(inherited.listen_address).toBeUndefined();
  });
});
