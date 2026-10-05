import {
  computeSharedOutboundAddresses,
  meaningfulListenerAddresses,
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
