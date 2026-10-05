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
