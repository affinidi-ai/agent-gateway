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
      validation: 'envelope',
    });
  });

  it('sends the selected versions in A2A order and the validation level', () => {
    expect(
      accessPointPayload({ a2a_accepted_versions: ['1.0', '0.3'], a2a_validation: 'full' }).a2a
    ).toEqual({ accepted_versions: ['0.3', '1.0'], validation: 'full' });
    expect(
      accessPointPayload({ a2a_accepted_versions: ['1.0'], a2a_validation: 'off' }).a2a
    ).toEqual({
      accepted_versions: ['1.0'],
      validation: 'off',
    });
  });

  it('sends the default level for an unknown or missing node value', () => {
    expect(accessPointPayload({ a2a_validation: 'strict' }).a2a.validation).toBe('envelope');
    expect(accessPointPayload({ a2a_validate_messages: true }).a2a.validation).toBe('envelope');
  });

  it('sends no block for an A2A proxy target, so the stored settings are kept', () => {
    const ap = accessPointPayload(
      { a2a_accepted_versions: ['0.3'], a2a_validation: 'off' },
      'a2a-proxy://worker'
    );
    expect(ap).not.toHaveProperty('a2a');
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
        a2a: { accepted_versions: ['1.0'], validation: 'full' },
      },
      {}
    );
    expect(config.a2a_accepted_versions).toEqual(['1.0']);
    expect(config.a2a_validation).toBe('full');
    expect(config.a2a).toBeUndefined();
  });

  it('loads the defaults when the stored surface has no block, and drops a stale flat field', () => {
    const config = definition.configFromPayload!(
      {
        listen_address: '0.0.0.0:8443',
        route: '/agent',
        protocol: 'a2a',
        a2a_validate_messages: true,
      } as any,
      {}
    );
    expect(config.a2a_accepted_versions).toEqual(['0.3', '1.0']);
    expect(config.a2a_validation).toBe('envelope');
    expect(config.a2a_validate_messages).toBeUndefined();

    const mcp = definition.configFromPayload!(
      { listen_address: '0.0.0.0:8443', route: '/agent', protocol: 'mcp' },
      {}
    );
    expect(mcp.a2a_accepted_versions).toBeUndefined();
  });

  it('round-trips the block through the panel fields', () => {
    for (const validation of ['off', 'envelope', 'full']) {
      const stored = { accepted_versions: ['0.3'], validation };
      const config = definition.configFromPayload!(
        { listen_address: '0.0.0.0:8443', route: '/agent', protocol: 'a2a', a2a: stored },
        {}
      );
      expect(accessPointPayload(config).a2a).toEqual(stored);
    }
  });

  it('blocks saving an A2A surface with no version selected, except for an A2A proxy target', () => {
    const errorsFor = (endpoint: string, versions: string[], protocol: 'a2a' | 'ap2' = 'a2a') => {
      const surfaceNodes = nodes({ a2a_accepted_versions: versions }, endpoint);
      return registry
        .getDependencyWarnings(
          'access-point',
          surfaceNodes[0].config,
          buildSurfaceContext(protocol, surfaceNodes as any)
        )
        .filter(w => w.severity === 'error');
    };

    expect(errorsFor('https://agent.example', [])).toEqual([
      { severity: 'error', message: 'Select at least one supported A2A version' },
    ]);
    expect(errorsFor('https://agent.example', ['1.0'])).toEqual([]);
    expect(errorsFor('a2a-proxy://worker', [])).toEqual([]);
    expect(errorsFor('https://agent.example', [], 'ap2')).toEqual([
      { severity: 'error', message: 'Select at least one supported A2A version' },
    ]);
  });
});
