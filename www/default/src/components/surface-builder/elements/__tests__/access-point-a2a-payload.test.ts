import { registry } from '../index';
import { buildSurfaceContext } from '../surfaceContext';
import type { PayloadContext } from '../types';

function makeCtx(nodes: any[], protocol: 'a2a' | 'ap2' | 'mcp' = 'a2a'): PayloadContext {
  return {
    protocol,
    surfaceMeta: { name: 'a2a-settings', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: type => nodes.filter(n => n.type === type),
    firstNodeOfType: type => nodes.find(n => n.type === type),
  };
}

const nodes = (apConfig: Record<string, unknown>, endpoint = 'https://agent.example') => [
  { id: 'access-point', type: 'access-point', config: { route: '/agent', ...apConfig } },
  { id: 'target', type: 'target', config: { endpoint } },
];

const accessPointPayload = (
  apConfig: Record<string, unknown>,
  endpoint?: string,
  protocol?: 'a2a' | 'ap2' | 'mcp'
) => (registry.buildPayload(makeCtx(nodes(apConfig, endpoint), protocol)) as any).access_point;

const definition = registry.get('access-point')!;

describe('Access Point A2A settings payload', () => {
  it('sends the defaults when nothing is selected', () => {
    expect(accessPointPayload({}).a2a).toEqual({
      accepted_versions: ['0.3', '1.0'],
      validate_messages: false,
    });
  });

  it('sends the selected versions in A2A order and the validation choice', () => {
    expect(
      accessPointPayload({ a2a_accepted_versions: ['1.0', '0.3'], a2a_validate_messages: true }).a2a
    ).toEqual({ accepted_versions: ['0.3', '1.0'], validate_messages: true });
    expect(accessPointPayload({ a2a_accepted_versions: ['1.0'] }).a2a).toEqual({
      accepted_versions: ['1.0'],
      validate_messages: false,
    });
  });

  it('sends the fixed A2A proxy settings for an A2A proxy target, whatever is selected', () => {
    expect(
      accessPointPayload(
        { a2a_accepted_versions: ['0.3'], a2a_validate_messages: true },
        'a2a-proxy://worker'
      ).a2a
    ).toEqual({ accepted_versions: ['1.0'], validate_messages: false });
  });

  it('sends no A2A settings on an MCP surface', () => {
    expect(accessPointPayload({}, undefined, 'mcp').a2a).toBeUndefined();
  });

  it('loads the stored block onto the flat panel fields', () => {
    const config = definition.configFromPayload!(
      {
        listen_address: '0.0.0.0:8443',
        route: '/agent',
        protocol: 'a2a',
        a2a: { accepted_versions: ['1.0'], validate_messages: true },
      },
      {}
    );
    expect(config.a2a_accepted_versions).toEqual(['1.0']);
    expect(config.a2a_validate_messages).toBe(true);
    expect(config.a2a).toBeUndefined();
  });

  it('loads the defaults when the stored surface has no block', () => {
    const config = definition.configFromPayload!(
      { listen_address: '0.0.0.0:8443', route: '/agent', protocol: 'a2a' },
      {}
    );
    expect(config.a2a_accepted_versions).toEqual(['0.3', '1.0']);
    expect(config.a2a_validate_messages).toBe(false);

    const mcp = definition.configFromPayload!(
      { listen_address: '0.0.0.0:8443', route: '/agent', protocol: 'mcp' },
      {}
    );
    expect(mcp.a2a_accepted_versions).toBeUndefined();
  });

  it('round-trips the block through the panel fields', () => {
    const stored = { accepted_versions: ['0.3'], validate_messages: true };
    const config = definition.configFromPayload!(
      { listen_address: '0.0.0.0:8443', route: '/agent', protocol: 'a2a', a2a: stored },
      {}
    );
    expect(accessPointPayload(config).a2a).toEqual(stored);
  });

  it('blocks saving an A2A surface with no version selected, except for an A2A proxy target', () => {
    const errorsFor = (endpoint: string, versions: string[]) => {
      const surfaceNodes = nodes({ a2a_accepted_versions: versions }, endpoint);
      return registry
        .getDependencyWarnings(
          'access-point',
          surfaceNodes[0].config,
          buildSurfaceContext('a2a', surfaceNodes as any)
        )
        .filter(w => w.severity === 'error');
    };

    expect(errorsFor('https://agent.example', [])).toEqual([
      { severity: 'error', message: 'Select at least one supported A2A version' },
    ]);
    expect(errorsFor('https://agent.example', ['1.0'])).toEqual([]);
    expect(errorsFor('a2a-proxy://worker', [])).toEqual([]);
  });
});
