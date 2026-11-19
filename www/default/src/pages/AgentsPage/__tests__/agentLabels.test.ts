import type { AgentRecord } from '../../../api';
import {
  agentMatchesFilter,
  connectionTarget,
  displayName,
  formatWindow,
  lastActivityLabel,
  protocolLabel,
  runtimeIcon,
  runtimeLabel,
  shortenDid,
  trustRegistryLabel,
} from '../agentLabels';

const agent = (overrides: Partial<AgentRecord> = {}): AgentRecord => ({
  id: 'a1',
  name: 'TimeAsker',
  protocol: 'a2a',
  runtime: 'url',
  endpoint: 'http://localhost:9002',
  tags: [],
  surfaces: [
    { surface_id: 's1', name: 'RICK' },
    { surface_id: 's2', name: 'Morty' },
  ],
  identities: [],
  trust_registry: { recorded: false },
  last_activity_at: null,
  ...overrides,
});

describe('agentLabels', () => {
  it.each([
    ['url', 'Direct'],
    ['a2a-proxy', 'Proxied'],
    ['gateway', 'Fabric'],
  ])('maps runtime %s to its route label', (runtime, label) => {
    expect(runtimeLabel(runtime)).toBe(label);
  });

  it('never shows raw enum values', () => {
    expect(runtimeLabel('ftp')).toBe('Unknown runtime');
    expect(protocolLabel('a2a')).toBe('A2A');
    expect(protocolLabel('mcp')).toBe('MCP');
    expect(protocolLabel('carrier-pigeon')).toBe('Other protocol');
  });

  it('labels the trust registry Recorded or Not recorded', () => {
    expect(trustRegistryLabel({ recorded: true })).toBe('Recorded');
    expect(trustRegistryLabel({ recorded: false })).toBe('Not recorded');
  });

  it('names an agent without a name Unnamed agent', () => {
    expect(displayName({ name: 'TimeAsker' })).toBe('TimeAsker');
    expect(displayName({ name: null })).toBe('Unnamed agent');
  });

  it('labels the retained window', () => {
    expect(formatWindow(360)).toBe('6h');
    expect(formatWindow(2880)).toBe('2d');
    expect(formatWindow(90)).toBe('90m');
    expect(lastActivityLabel(null, 360)).toBe('None in last 6h');
    expect(lastActivityLabel(null)).toBe('None retained');
  });

  it('shortens a DID in the middle', () => {
    const did = 'did:webvh:QmYAuadF1234567890:agent-gateway1.example.com:surface:abcdef12';
    const short = shortenDid(did);
    expect(short.startsWith('did:webvh:QmYAuadF12')).toBe(true);
    expect(short.endsWith('abcdef12')).toBe(true);
    expect(short).toContain('…');
    expect(shortenDid('did:web:a.com')).toBe('did:web:a.com');
  });

  it('parses the connection target and hides URL secrets', () => {
    expect(connectionTarget('http://localhost:9002')).toEqual({
      kind: 'url',
      display: 'http://localhost:9002',
    });
    expect(connectionTarget('https://user:pw@agent.example.com/a2a?api_key=s3cret#x')).toEqual({
      kind: 'url',
      display: 'https://agent.example.com/a2a',
    });
    expect(connectionTarget('a2a-proxy://proxy-1')).toEqual({
      kind: 'a2a-proxy',
      proxyId: 'proxy-1',
    });
    expect(connectionTarget('fabric://g1/c1')).toEqual({
      kind: 'gateway',
      gatewayId: 'g1',
      channelId: 'c1',
    });
    expect(connectionTarget('fabric://g1')).toEqual({
      kind: 'gateway',
      gatewayId: 'g1',
      channelId: null,
    });
    expect(connectionTarget('a2a-proxy://')).toEqual({ kind: 'unknown' });
    expect(connectionTarget('ftp://files.example.com/agent')).toEqual({ kind: 'unknown' });
    expect(connectionTarget('not a url')).toEqual({ kind: 'unknown' });
  });

  it.each([
    'https://redacted.invalid',
    'fabric://redacted.invalid',
    'a2a-proxy://redacted.invalid',
  ])('treats the redacted endpoint %s as unknown', endpoint => {
    expect(connectionTarget(endpoint)).toEqual({ kind: 'unknown' });
  });

  it('filters on the display name, every surface name and the runtime label', () => {
    expect(agentMatchesFilter(agent(), 'time')).toBe(true);
    expect(agentMatchesFilter(agent(), 'rick')).toBe(true);
    expect(agentMatchesFilter(agent(), 'morty')).toBe(true);
    expect(agentMatchesFilter(agent(), 'direct')).toBe(true);
    expect(agentMatchesFilter(agent(), 'a2a-proxy')).toBe(false);
    expect(agentMatchesFilter(agent(), 'summer')).toBe(false);
    expect(agentMatchesFilter(agent({ name: null }), 'time')).toBe(false);
    expect(agentMatchesFilter(agent({ name: null }), 'unnamed')).toBe(true);
    expect(agentMatchesFilter(agent(), '  ')).toBe(true);
  });

  it('picks a route icon', () => {
    expect(runtimeIcon('a2a-proxy')).toBe('fa-exchange-alt');
    expect(runtimeIcon('ftp')).toBe('fa-robot');
  });
});
