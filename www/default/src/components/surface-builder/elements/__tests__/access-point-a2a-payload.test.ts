import { registry } from '../index';
import { buildSurfaceContext } from '../surfaceContext';
import type { BaseSurfaceView, PayloadContext } from '../types';
import { withA2aValidationSettled } from '../access-point/a2aSettings';

function makeCtx(
  nodes: any[],
  protocol: 'a2a' | 'ap2' | 'mcp' = 'a2a',
  base?: BaseSurfaceView
): PayloadContext {
  return {
    protocol,
    surfaceMeta: { name: 'a2a-settings', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: type => nodes.filter(n => n.type === type),
    firstNodeOfType: type => nodes.find(n => n.type === type),
    base,
  };
}

const nodes = (apConfig: Record<string, unknown>, endpoint = 'https://agent.example') => [
  { id: 'access-point', type: 'access-point', config: { route: '/agent', ...apConfig } },
  { id: 'target', type: 'target', config: { endpoint } },
];

const accessPointPayload = (
  apConfig: Record<string, unknown>,
  endpoint?: string,
  protocol?: 'a2a' | 'ap2' | 'mcp',
  base?: BaseSurfaceView
) =>
  (registry.buildPayload(makeCtx(nodes(apConfig, endpoint), protocol, base)) as any).access_point;

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
  });

  it('sends only the validation level for an A2A proxy base Target, whose versions are fixed', () => {
    const settings = { a2a_accepted_versions: ['0.3', '1.0'], a2a_validation: 'full' };

    expect(accessPointPayload(settings, 'a2a-proxy://worker').a2a).toEqual({ validation: 'full' });
    expect(
      accessPointPayload(settings, 'https://agent.example', 'a2a', {
        targetEndpoint: 'a2a-proxy://worker',
      }).a2a
    ).toEqual({ validation: 'full' });
  });

  it('sends the whole block for a URL base Target, even with an A2A proxy variant in view', () => {
    expect(
      accessPointPayload(
        { a2a_accepted_versions: ['1.0'], a2a_validation: 'full' },
        'a2a-proxy://worker',
        'a2a',
        { targetEndpoint: 'https://agent.example' }
      ).a2a
    ).toEqual({ accepted_versions: ['1.0'], validation: 'full' });
  });

  it('records the fixed versions of a surface stored with an A2A proxy Target', () => {
    const stored = definition.configFromPayload!(
      {
        listen_address: '0.0.0.0:8443',
        route: '/agent',
        protocol: 'a2a',
        a2a: { accepted_versions: ['0.3', '1.0'], validation: 'envelope' },
      },
      { target: { endpoint: 'a2a-proxy://worker' } }
    );
    expect(stored.a2a_locked_versions).toEqual(['0.3', '1.0']);

    const url = definition.configFromPayload!(
      {
        listen_address: '0.0.0.0:8443',
        route: '/agent',
        protocol: 'a2a',
        a2a: { accepted_versions: ['0.3', '1.0'], validation: 'envelope' },
        a2a_locked_versions: ['0.3'],
      },
      { target: { endpoint: 'https://agent.example' } }
    );
    expect(url.a2a_locked_versions).toBeUndefined();
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

  it('loads the defaults when the stored surface has no block', () => {
    const config = definition.configFromPayload!(
      { listen_address: '0.0.0.0:8443', route: '/agent', protocol: 'a2a' },
      {}
    );
    expect(config.a2a_accepted_versions).toEqual(['0.3', '1.0']);
    expect(config.a2a_validation).toBe('envelope');

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

  it('gates the save on the base Target, not the Target of the variant in view', () => {
    const errorsFor = (endpoint: string, baseEndpoint: string) => {
      const surfaceNodes = nodes({ a2a_accepted_versions: [] }, endpoint);
      return registry
        .getDependencyWarnings(
          'access-point',
          surfaceNodes[0].config,
          buildSurfaceContext('a2a', surfaceNodes as any, { targetEndpoint: baseEndpoint })
        )
        .filter(w => w.severity === 'error');
    };

    expect(errorsFor('a2a-proxy://worker', 'https://agent.example')).toEqual([
      { severity: 'error', message: 'Select at least one supported A2A version' },
    ]);
    expect(errorsFor('https://agent.example', 'a2a-proxy://worker')).toEqual([]);
  });
});

describe('Access Point A2A settings on load', () => {
  const urlSlice = {
    listen_address: '0.0.0.0:8443',
    route: '/agent',
    protocol: 'a2a',
    a2a: { accepted_versions: ['0.3', '1.0'], validation: 'envelope' },
  };
  const accessPointNode = (payload: any) =>
    registry.nodesFromPayload(payload).find(n => n.type === 'access-point')!;

  it('drops stale fixed versions and block that the canvas blob carries for a URL Target', () => {
    const node = accessPointNode({
      name: 'a2a-settings',
      access_point: urlSlice,
      target: { endpoint: 'https://agent.example' },
      canvas: {
        version: 1,
        nodes: [
          {
            id: 'access-point',
            type: 'access-point',
            config: {
              route: '/agent',
              a2a_locked_versions: ['0.3', '1.0'],
              a2a: { accepted_versions: ['0.3'], validation: 'full' },
            },
          },
        ],
      },
    });

    expect(node.config.a2a_locked_versions).toBeUndefined();
    expect(node.config.a2a).toBeUndefined();
    expect(node.config.a2a_accepted_versions).toEqual(['0.3', '1.0']);
    expect(accessPointPayload(node.config).a2a).toEqual(urlSlice.a2a);
  });

  describe('Fixed versions of an A2A proxy surface, as the gateway serves them', () => {
    const proxyNode = (a2a: unknown) =>
      accessPointNode({
        name: 'a2a-settings',
        access_point: { ...urlSlice, ...(a2a === undefined ? { a2a: undefined } : { a2a }) },
        target: { endpoint: 'a2a-proxy://worker' },
      });

    it.each([
      [[], ['0.3', '1.0']],
      [['9.9'], ['0.3', '1.0']],
      [['1.0', '9.9'], ['1.0']],
      [['0.3'], ['0.3']],
    ])('serves %j as %j', (stored, served) => {
      const node = proxyNode({ accepted_versions: stored, validation: 'envelope' });
      expect(node.config.a2a_locked_versions).toEqual(served);
    });

    it('serves both versions for a surface stored without a block', () => {
      expect(proxyNode(undefined).config.a2a_locked_versions).toEqual(['0.3', '1.0']);
    });
  });

  it('keeps the fixed versions of a dashboard payload for an A2A proxy base Target', () => {
    const node = accessPointNode({
      name: 'a2a-settings',
      access_point: { ...urlSlice, a2a: { validation: 'envelope' } },
      target: { endpoint: 'a2a-proxy://worker' },
      canvas: {
        version: 1,
        nodes: [
          {
            id: 'access-point',
            type: 'access-point',
            config: {
              route: '/agent',
              a2a_accepted_versions: ['0.3', '1.0'],
              a2a_locked_versions: ['0.3', '1.0'],
            },
          },
        ],
      },
    });

    expect(node.config.a2a_locked_versions).toEqual(['0.3', '1.0']);
    expect(node.config.a2a_accepted_versions).toEqual(['0.3', '1.0']);
  });
});

describe('A2A validation level of the assembled wire payload', () => {
  const wire = (targetEndpoint: string, variants?: any[]) => ({
    access_point: { protocol: 'a2a', a2a: { validation: 'full' as const } },
    target: { endpoint: targetEndpoint },
    ...(variants ? { variants } : {}),
  });

  it('sets the JSON-RPC envelope when every Target is an A2A proxy', () => {
    expect(withA2aValidationSettled(wire('a2a-proxy://worker')).access_point?.a2a?.validation).toBe(
      'envelope'
    );
    expect(
      withA2aValidationSettled(
        wire('a2a-proxy://worker', [
          { overrides: { complete: true, target: { endpoint: 'a2a-proxy://other' } } },
          { overrides: {} },
          { overrides: { complete: true, target: { auth: { type: 'none' } } } },
        ])
      ).access_point?.a2a?.validation
    ).toBe('envelope');
  });

  it('keeps the level when a Target is a URL', () => {
    const urlBase = wire('https://agent.example');
    expect(withA2aValidationSettled(urlBase)).toBe(urlBase);
    const urlVariant = wire('a2a-proxy://worker', [
      { overrides: { complete: true, target: { endpoint: 'https://agent.example' } } },
    ]);
    expect(withA2aValidationSettled(urlVariant)).toBe(urlVariant);
  });

  it('leaves the input untouched', () => {
    const payload = wire('a2a-proxy://worker');
    withA2aValidationSettled(payload);
    expect(payload.access_point.a2a.validation).toBe('full');
  });
});
