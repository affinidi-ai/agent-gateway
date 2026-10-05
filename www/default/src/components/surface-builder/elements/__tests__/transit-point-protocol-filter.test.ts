import { transitPointProtocol } from '../transit-point/TransitPointPanel';

describe('transitPointProtocol', () => {
  it('extracts a2a from transit-point-a2a', () => {
    expect(transitPointProtocol('transit-point-a2a')).toBe('a2a');
  });

  it('extracts mcp from transit-point-mcp', () => {
    expect(transitPointProtocol('transit-point-mcp')).toBe('mcp');
  });

  it('extracts ap2 from transit-point-ap2', () => {
    expect(transitPointProtocol('transit-point-ap2')).toBe('ap2');
  });

  it('returns null for non-transit-point node types', () => {
    expect(transitPointProtocol('access-point')).toBeNull();
    expect(transitPointProtocol('target')).toBeNull();
  });

  it('returns null for undefined', () => {
    expect(transitPointProtocol(undefined)).toBeNull();
  });
});

describe('channel protocol filtering logic', () => {
  const channels = [
    { config_id: 'ch-1', name: 'A2A surface', protocol: 'a2a' },
    { config_id: 'ch-2', name: 'MCP surface', protocol: 'mcp' },
    { config_id: 'ch-3', name: 'Another A2A', protocol: 'a2a' },
    { config_id: 'ch-4', name: 'AP2 surface', protocol: 'ap2' },
  ];

  function filterChannels(allChannels: typeof channels, tpProtocol: string | null) {
    if (!tpProtocol || tpProtocol === 'http') return allChannels;
    return allChannels.filter(ch => ch.protocol === tpProtocol);
  }

  it('filters to only matching protocol', () => {
    const result = filterChannels(channels, 'a2a');
    expect(result).toHaveLength(2);
    expect(result.map(c => c.config_id)).toEqual(['ch-1', 'ch-3']);
  });

  it('returns empty when no channels match', () => {
    const result = filterChannels(channels, 'didcomm');
    expect(result).toHaveLength(0);
  });

  it('returns all channels for http protocol', () => {
    const result = filterChannels(channels, 'http');
    expect(result).toHaveLength(4);
  });

  it('returns all channels when protocol is null', () => {
    const result = filterChannels(channels, null);
    expect(result).toHaveLength(4);
  });
});
