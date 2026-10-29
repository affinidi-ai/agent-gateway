import type { AgentRecord } from '../../../api';
import {
  agentMatchesFilter,
  agentMatchesStatus,
  connectionTarget,
  didSourceLabel,
  formatWindow,
  lastActivityLabel,
  otherSurfacesNote,
  protocolBadgeLabel,
  protocolBadgeTitle,
  runtimeIcon,
  runtimeLabel,
  shortenDid,
  statusLabel,
  trustRegistryLabels,
} from '../agentLabels';

const agent = (overrides: Partial<AgentRecord> = {}): AgentRecord => ({
  id: 's1',
  registration: 'unregistered',
  name: 'TimeAsker',
  surface_name: 'RICK',
  status: 'active',
  protocol: 'a2a',
  runtime: 'url',
  endpoint: 'http://localhost:9002',
  tags: [],
  trust_registry: { recognized: false, authorized: false },
  agent_did: null,
  did_surface_count: 0,
  identity_created_at: null,
  last_activity_at: null,
  ...overrides,
});

describe('agentLabels', () => {
  it.each([
    ['url', 'Direct URL', 'A2A'],
    ['a2a-proxy', 'A2A proxy', 'A2A via proxy'],
    ['gateway', 'Remote gateway', 'A2A via gateway'],
  ])('maps runtime %s to display labels', (runtime, label, badge) => {
    expect(runtimeLabel(runtime)).toBe(label);
    expect(protocolBadgeLabel('a2a', runtime)).toBe(badge);
  });

  it('never shows raw enum values', () => {
    expect(runtimeLabel('ftp')).toBe('Unknown runtime');
    expect(protocolBadgeLabel('mcp', 'gateway')).toBe('MCP via gateway');
    expect(protocolBadgeLabel('carrier-pigeon', 'url')).toBe('Other protocol');
    expect(statusLabel('disabled')).toBe('Disabled');
    expect(statusLabel('weird')).toBe('Unknown');
  });

  it('lists trust registry labels from the configuration', () => {
    expect(trustRegistryLabels({ recognized: false, authorized: false })).toEqual([]);
    expect(trustRegistryLabels({ recognized: true, authorized: true })).toEqual([
      'Recognised',
      'Authorised',
    ]);
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

  it('describes the DID source and other surfaces', () => {
    expect(didSourceLabel(agent())).toBeNull();
    expect(
      didSourceLabel(agent({ agent_did: 'did:web:a', identity_created_at: '2026-10-22T11:24:02Z' }))
    ).toBe('Managed identity, issued by this gateway');
    expect(didSourceLabel(agent({ agent_did: 'did:web:a' }))).toBe('Set on the surface');
    expect(otherSurfacesNote(1)).toBeNull();
    expect(otherSurfacesNote(2)).toBe('Also used on 1 other surface');
    expect(otherSurfacesNote(4)).toBe('Also used on 3 other surfaces');
  });

  it('parses the connection target and hides URL secrets', () => {
    expect(connectionTarget('http://localhost:9002')).toEqual({
      kind: 'url',
      display: 'http://localhost:9002',
      redacted: false,
    });
    expect(connectionTarget('https://user:pw@agent.example.com/a2a?api_key=s3cret#x')).toEqual({
      kind: 'url',
      display: 'https://agent.example.com/a2a',
      redacted: true,
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

  it('filters on the agent name, surface name and runtime label', () => {
    expect(agentMatchesFilter(agent(), 'time')).toBe(true);
    expect(agentMatchesFilter(agent(), 'rick')).toBe(true);
    expect(agentMatchesFilter(agent(), 'direct url')).toBe(true);
    expect(agentMatchesFilter(agent(), 'a2a-proxy')).toBe(false);
    expect(agentMatchesFilter(agent({ name: null }), 'time')).toBe(false);
    expect(agentMatchesFilter(agent(), '  ')).toBe(true);
  });

  it('filters on status', () => {
    expect(agentMatchesStatus(agent(), 'all')).toBe(true);
    expect(agentMatchesStatus(agent(), 'active')).toBe(true);
    expect(agentMatchesStatus(agent(), 'disabled')).toBe(false);
    expect(agentMatchesStatus(agent({ status: 'disabled' }), 'disabled')).toBe(true);
  });

  it('names the indirect runtimes for the protocol badge', () => {
    expect(protocolBadgeTitle('url')).toBeUndefined();
    expect(protocolBadgeTitle('a2a-proxy')).toContain('A2A proxy');
    expect(protocolBadgeTitle('gateway')).toContain('remote gateway');
    expect(runtimeIcon('a2a-proxy')).toBe('fa-exchange-alt');
    expect(runtimeIcon('ftp')).toBe('fa-robot');
  });
});
