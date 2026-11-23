import {
  computeSharedOutboundAddresses,
  listenPathProblem,
  meaningfulListenerAddresses,
  offeredChannelPrefixes,
  shouldHideListenerPicker,
  type RoutingConfig,
} from '../defaults';

function makeConfig(
  allUrls: string[],
  outboundUrls: string[],
  channelPrefixes: Array<{ id: string; name: string; prefix: string }> = []
): RoutingConfig {
  return {
    available_listen_addresses: allUrls,
    available_outbound_listen_addresses: outboundUrls,
    channel_path_prefix: channelPrefixes,
  };
}

describe('computeSharedOutboundAddresses', () => {
  it('returns empty set when outbound is empty', () => {
    const config = makeConfig(['https://example.com', 'http://localhost:8080'], []);
    expect(computeSharedOutboundAddresses(config).size).toBe(0);
  });

  it('returns empty set when domains are fully separate', () => {
    // available_listen_addresses is now inbound-only
    const config = makeConfig(
      ['https://inbound.example.com', 'http://localhost:8080'],
      ['https://outbound.example.com', 'http://localhost:9000']
    );
    expect(computeSharedOutboundAddresses(config).size).toBe(0);
  });

  it('detects shared URL that appears in both inbound and outbound listener lists', () => {
    // available_listen_addresses = inbound-only; shared.example.com appears in both
    const config = makeConfig(
      ['https://inbound.example.com', 'https://shared.example.com', 'http://localhost:8080'],
      ['https://outbound.example.com', 'https://shared.example.com', 'http://localhost:9000']
    );
    const shared = computeSharedOutboundAddresses(config);
    expect(shared.has('https://shared.example.com')).toBe(true);
    expect(shared.has('https://outbound.example.com')).toBe(false);
    expect(shared.has('http://localhost:9000')).toBe(false);
  });

  it('does not flag exclusive-outbound URLs as shared', () => {
    const config = makeConfig(
      ['https://inbound.example.com', 'http://localhost:8080'],
      ['https://outbound.example.com', 'http://localhost:9000']
    );
    const shared = computeSharedOutboundAddresses(config);
    expect(shared.has('https://outbound.example.com')).toBe(false);
    expect(shared.has('http://localhost:9000')).toBe(false);
  });

  it('detects a shared URL when it appears in two inbound listeners', () => {
    // Two inbound listeners both advertise shared.example.com (HTTP + HTTPS)
    const config = makeConfig(
      [
        'https://shared.example.com',
        'http://localhost:8080',
        'https://shared.example.com',
        'https://localhost:9049',
      ],
      ['https://outbound-only.example.com', 'https://shared.example.com', 'http://localhost:9606']
    );
    const shared = computeSharedOutboundAddresses(config);
    expect(shared.has('https://shared.example.com')).toBe(true);
    expect(shared.has('https://outbound-only.example.com')).toBe(false);
    expect(shared.has('http://localhost:9606')).toBe(false);
  });

  it('returns empty set when available_outbound_listen_addresses is undefined', () => {
    const config: RoutingConfig = {
      available_listen_addresses: ['https://example.com'],
      channel_path_prefix: [],
    };
    expect(computeSharedOutboundAddresses(config).size).toBe(0);
  });

  it('returns empty set when available_listen_addresses is empty', () => {
    const config = makeConfig([], ['https://outbound.example.com']);
    expect(computeSharedOutboundAddresses(config).size).toBe(0);
  });

  // The gateway classifies by listener, which no comparison of the two address
  // lists can reproduce. Both of these were called "not shared", so the picker
  // offered the plain prefixes and the save then failed with
  // listen_path_not_served.
  it('takes the gateway classification over equal URLs, across ports', () => {
    const config = makeConfig(
      ['https://gateway.example.com'],
      ['https://gateway.example.com:9443']
    );
    expect(computeSharedOutboundAddresses(config).size).toBe(0);

    config.shared_hostname_outbound_addresses = ['https://gateway.example.com:9443'];
    const shared = computeSharedOutboundAddresses(config);
    expect(shared.has('https://gateway.example.com:9443')).toBe(true);
  });

  it('shares an alias URL of a listener the gateway classified as shared', () => {
    const config = makeConfig(
      ['https://gateway.example.com'],
      ['https://gateway.example.com:9443', 'https://alias.example.net']
    );
    config.shared_hostname_outbound_addresses = [
      'https://gateway.example.com:9443',
      'https://alias.example.net',
    ];
    const shared = computeSharedOutboundAddresses(config);
    expect(shared.has('https://alias.example.net')).toBe(true);
  });

  it('keeps an outbound address the gateway left out of the classification', () => {
    const config = makeConfig(
      ['https://gateway.example.com'],
      ['https://gateway.example.com', 'https://own.example.net']
    );
    config.shared_hostname_outbound_addresses = ['https://gateway.example.com'];
    const shared = computeSharedOutboundAddresses(config);
    expect(shared.has('https://gateway.example.com')).toBe(true);
    expect(shared.has('https://own.example.net')).toBe(false);
  });
});

describe('offeredChannelPrefixes', () => {
  const channels = [{ id: 'agents', name: 'agents', prefix: '/agents' }];

  it('offers the plain prefixes for an inbound address', () => {
    const config = makeConfig(['https://gateway.example.com'], [], channels);
    expect(
      offeredChannelPrefixes(config, 'inbound', 'https://gateway.example.com').map(p => p.prefix)
    ).toEqual(['/agents']);
  });

  it('offers the /outbound prefixes on an address the gateway called shared', () => {
    const config = makeConfig(
      ['https://gateway.example.com'],
      ['https://gateway.example.com:9443'],
      channels
    );
    config.shared_hostname_outbound_addresses = ['https://gateway.example.com:9443'];
    expect(
      offeredChannelPrefixes(config, 'outbound', 'https://gateway.example.com:9443').map(
        p => p.prefix
      )
    ).toEqual(['/outbound/agents']);
  });

  it('offers the plain prefixes on an outbound address of its own', () => {
    const config = makeConfig(
      ['https://gateway.example.com'],
      ['https://own.example.net'],
      channels
    );
    config.shared_hostname_outbound_addresses = [];
    expect(
      offeredChannelPrefixes(config, 'outbound', 'https://own.example.net').map(p => p.prefix)
    ).toEqual(['/agents']);
  });

  // A root surface prefix has no usable plain form: it is the whole listener, which the
  // gateway does not accept a Listen Path directly under, so the picker would otherwise
  // offer nothing a save would take on such a deployment.
  it('offers the /outbound form of a root prefix even on a dedicated listener', () => {
    const root = [{ id: 'root', name: 'root', prefix: '/' }];
    const config = makeConfig(['https://gateway.example.com'], ['https://own.example.net'], root);
    config.shared_hostname_outbound_addresses = [];
    const offered = offeredChannelPrefixes(config, 'outbound', 'https://own.example.net');
    expect(offered.map(p => p.prefix)).toEqual(['/outbound']);
    expect(
      listenPathProblem(
        { listen_address: 'https://own.example.net', listen_path: '/outbound/partner-a' },
        config
      )
    ).toBeNull();
  });

  it('prefers the outbound prefixes the gateway advertises', () => {
    const config = makeConfig(
      ['https://gateway.example.com'],
      ['https://gateway.example.com'],
      channels
    );
    config.shared_hostname_outbound_addresses = ['https://gateway.example.com'];
    config.outbound_channel_path_prefix = [
      { id: 'agents', name: 'agents', prefix: '/outbound/agents' },
    ];
    expect(
      offeredChannelPrefixes(config, 'outbound', 'https://gateway.example.com').map(p => p.prefix)
    ).toEqual(['/outbound/agents']);
  });
});

describe('listenPathProblem', () => {
  const channels = [{ id: 'agents', name: 'agents', prefix: '/agents' }];
  const shared = (): RoutingConfig => {
    const config = makeConfig(
      ['https://gateway.example.com'],
      ['https://gateway.example.com:9443'],
      channels
    );
    config.shared_hostname_outbound_addresses = ['https://gateway.example.com:9443'];
    return config;
  };
  const point = (listen_path?: string) => ({
    listen_address: 'https://gateway.example.com:9443',
    ...(listen_path === undefined ? {} : { listen_path }),
  });

  it('passes a Transit Point with no Listen Path, which takes its derived route', () => {
    expect(listenPathProblem(point(), shared())).toBeNull();
    expect(listenPathProblem(point(''), shared())).toBeNull();
  });

  it('passes a path under an offered prefix', () => {
    expect(listenPathProblem(point('/outbound/agents/partner-a'), shared())).toBeNull();
  });

  it('blocks a path under no configured surface prefix', () => {
    const problem = listenPathProblem(point('/nowhere/partner-a'), shared());
    expect(problem).toContain('claims no segment of its own');
    expect(problem).toContain('/outbound/agents/');
  });

  it('blocks a bare prefix, which claims no segment of its own', () => {
    expect(listenPathProblem(point('/outbound/agents'), shared())).toContain(
      'claims no segment of its own'
    );
    expect(listenPathProblem(point('/agents'), shared())).toContain('claims no segment of its own');
  });

  // The two forms the admin API accepts, narrowed only by the listener's hostname:
  // what the picker offers is a subset, so checking against it blocked a good path.
  it('blocks a path outside /outbound only on a shared-hostname address', () => {
    expect(listenPathProblem(point('/agents/partner-a'), shared())).toContain('outside /outbound');

    const ownHostname = makeConfig(
      ['https://gateway.example.com'],
      ['https://own.example.net'],
      channels
    );
    ownHostname.shared_hostname_outbound_addresses = [];
    const onOwn = { listen_address: 'https://own.example.net', listen_path: '/agents/partner-a' };
    expect(listenPathProblem(onOwn, ownHostname)).toBeNull();
    expect(
      listenPathProblem({ ...onOwn, listen_path: '/outbound/agents/partner-a' }, ownHostname)
    ).toBeNull();
  });

  it('says nothing while the routing config has not loaded', () => {
    expect(listenPathProblem(point('/agents/partner-a'), null)).toBeNull();
  });
});

describe('meaningfulListenerAddresses', () => {
  it('strips localhost entries', () => {
    const result = meaningfulListenerAddresses(['https://gw.example.com', 'http://localhost:8080']);
    expect(result).toEqual(['https://gw.example.com']);
  });

  it('strips 127.0.0.1 entries', () => {
    const result = meaningfulListenerAddresses(['https://gw.example.com', 'http://127.0.0.1:8080']);
    expect(result).toEqual(['https://gw.example.com']);
  });

  it('falls back to full list when all addresses are local', () => {
    const addrs = ['http://localhost:8080', 'http://localhost:9000'];
    expect(meaningfulListenerAddresses(addrs)).toEqual(addrs);
  });

  it('returns single non-local address (triggers hideListenerPicker)', () => {
    const result = meaningfulListenerAddresses(['https://gw.example.com', 'http://localhost:8080']);
    expect(result).toHaveLength(1);
    expect(result[0]).toBe('https://gw.example.com');
  });

  it('returns all non-local addresses when multiple exist', () => {
    const result = meaningfulListenerAddresses([
      'https://gw1.example.com',
      'https://gw2.example.com',
      'http://localhost:8080',
    ]);
    expect(result).toEqual(['https://gw1.example.com', 'https://gw2.example.com']);
  });

  it('handles https:// localhost correctly', () => {
    const result = meaningfulListenerAddresses([
      'https://gw.example.com',
      'https://localhost:8443',
    ]);
    expect(result).toEqual(['https://gw.example.com']);
  });

  it('deduplicates before deciding: [ep, local1, local2, ep] → [ep]', () => {
    const result = meaningfulListenerAddresses([
      'https://gw.example.com',
      'http://localhost:8080',
      'http://localhost:9000',
      'https://gw.example.com',
    ]);
    expect(result).toEqual(['https://gw.example.com']);
  });

  it('returns empty array unchanged when input is empty', () => {
    expect(meaningfulListenerAddresses([])).toEqual([]);
  });
});

describe('shouldHideListenerPicker', () => {
  const single = ['https://gw.example.com'];
  const multiple = ['https://gw1.example.com', 'https://gw2.example.com'];

  it('hides when one meaningful address and nothing saved', () => {
    expect(shouldHideListenerPicker(single, '')).toBe(true);
  });

  it('hides when one meaningful address and saved address matches', () => {
    expect(shouldHideListenerPicker(single, 'https://gw.example.com')).toBe(true);
  });

  it('shows when saved address is NOT in the meaningful set (stale after listener added)', () => {
    expect(shouldHideListenerPicker(single, 'http://localhost:8080')).toBe(false);
  });

  it('shows when multiple meaningful addresses exist (regardless of saved)', () => {
    expect(shouldHideListenerPicker(multiple, '')).toBe(false);
    expect(shouldHideListenerPicker(multiple, 'https://gw1.example.com')).toBe(false);
  });

  it('hides when meaningful list is empty and nothing saved', () => {
    expect(shouldHideListenerPicker([], '')).toBe(true);
  });

  it('shows when meaningful list is empty but address is saved (stale)', () => {
    expect(shouldHideListenerPicker([], 'https://old.example.com')).toBe(false);
  });
});
