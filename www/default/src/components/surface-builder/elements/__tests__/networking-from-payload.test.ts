import { buildCanvasBlob, registry } from '../index';
import {
  networkingConfigFromWire,
  networkingConfigToWire,
  networkingDefinition,
} from '../networking/definition';
import { nodesFromSurface } from '../../nodesFromSurface';

const incomplete = (c: any) => networkingDefinition.incompleteReason!(c);

describe('networking configFromPayload', () => {
  it('is registered on the definition', () => {
    expect(networkingDefinition.configFromPayload).toBeDefined();
  });

  it('hydrates the shape an AI agent writes through the management API', () => {
    const wire = {
      timeout: { request_secs: 30, connect_secs: 5, idle_secs: 90 },
      retry: { max_attempts: 3, backoff_multiplier: 2 },
      circuit_breaker: { failure_threshold: 5, timeout_secs: 30 },
    };
    const flat = networkingDefinition.configFromPayload!(wire);
    expect(flat).toEqual({
      timeout_secs: '30',
      connect_timeout_secs: '5',
      idle_timeout_secs: '90',
      retry_enabled: true,
      retry_max: '3',
      retry_backoff_multiplier: '2',
      circuit_breaker_enabled: true,
      cb_threshold: '5',
      cb_recovery_secs: '30',
    });
    expect(incomplete(flat)).toBeNull();
    expect(networkingConfigToWire(flat)).toEqual(wire);
  });

  it('round-trips a full wire payload including mirror and status codes', () => {
    const wire = {
      timeout: { request_secs: 20, connect_secs: 4, idle_secs: 60 },
      retry: {
        max_attempts: 4,
        initial_backoff_ms: 100,
        max_backoff_ms: 5000,
        backoff_multiplier: 1.5,
        retryable_status_codes: [502, 503],
      },
      circuit_breaker: {
        failure_threshold: 6,
        timeout_secs: 45,
        success_threshold: 2,
        window_secs: 60,
      },
      mirror: {
        endpoint: 'https://shadow.example',
        percentage: 25,
        wait_for_response: false,
        timeout_secs: 5,
      },
    };
    const flat = networkingConfigFromWire(wire);
    expect(flat.mirror_async).toBe(true);
    expect(networkingConfigToWire(flat)).toEqual(wire);
  });

  it('round-trips representative flat configs', () => {
    const flats = [
      { timeout_secs: '30' },
      { retry_enabled: true, retry_max: '2', retry_status_codes: '502,503' },
      {
        circuit_breaker_enabled: true,
        cb_threshold: '7',
        cb_recovery_secs: '10',
        cb_window_secs: '20',
      },
      {
        mirror_enabled: true,
        mirror_endpoint: 'https://m.example',
        mirror_percentage: '50',
        mirror_async: false,
        mirror_timeout_secs: '3',
      },
    ];
    for (const x of flats) {
      expect(networkingConfigFromWire(networkingConfigToWire(x))).toEqual(x);
    }
  });

  it('keeps empty and missing payloads incomplete, without invented defaults', () => {
    for (const w of [undefined, null, {}, 'x']) {
      const flat = networkingDefinition.configFromPayload!(w);
      expect(flat).toEqual({});
      expect(incomplete(flat)).not.toBeNull();
    }
  });
});

describe('networkingConfigFromWire edge cases', () => {
  it('maps a mirror that waits for its response to a synchronous mirror', () => {
    const flat = networkingConfigFromWire({
      mirror: { endpoint: 'https://shadow.example', percentage: 10, wait_for_response: true },
    });
    expect(flat).toEqual({
      mirror_enabled: true,
      mirror_endpoint: 'https://shadow.example',
      mirror_percentage: '10',
      mirror_async: false,
    });
  });

  it('leaves the mirror mode unset when the payload does not give one', () => {
    const flat = networkingConfigFromWire({ mirror: { endpoint: 'https://shadow.example' } });
    expect(flat).not.toHaveProperty('mirror_async');
    expect(networkingConfigToWire(flat)?.mirror).not.toHaveProperty('wait_for_response');
  });

  it('keeps a mirror without an endpoint visible as missing one', () => {
    const flat = networkingConfigFromWire({ mirror: { percentage: 50 } });
    expect(flat.mirror_endpoint).toBe('');
    const endpointRule = networkingDefinition.featureDependencies!.find(
      d => d.description === 'Mirror requires an endpoint'
    )!;
    expect(endpointRule.condition(flat)).toBe(true);
    expect(endpointRule.check(flat)).toBe(false);
  });

  it('omits an empty list of retryable status codes', () => {
    const flat = networkingConfigFromWire({
      retry: { max_attempts: 2, retryable_status_codes: [] },
    });
    expect(flat).toEqual({ retry_enabled: true, retry_max: '2' });
  });

  it('ignores blocks that are not objects', () => {
    const flat = networkingConfigFromWire({
      timeout: 30,
      retry: null,
      circuit_breaker: 'on',
      mirror: 'https://shadow.example',
    });
    expect(flat).toEqual({});
    expect(incomplete(flat)).not.toBeNull();
  });
});

describe('Networking set through the API on the canvas', () => {
  const wire = {
    timeout: { request_secs: 30, connect_secs: 5 },
    retry: { max_attempts: 3, retryable_status_codes: [502, 503] },
  };
  const surface = (extra: Record<string, any>): any => ({
    name: 'networking-api',
    status: 'active',
    tags: [],
    access_point: { route: '/api' },
    target: { endpoint: 'https://upstream.example' },
    ...extra,
  });
  const save = (nodes: any[]): any =>
    registry.buildPayload({
      protocol: 'a2a',
      surfaceMeta: { name: 'networking-api', tags: [], status: 'active' },
      allNodes: nodes,
      nodesOfType: type => nodes.filter(n => n.type === type),
      firstNodeOfType: type => nodes.find(n => n.type === type),
    });

  it('shows the Target Networking element configured and saves it unchanged', () => {
    const nodes = nodesFromSurface(
      surface({ target: { endpoint: 'https://upstream.example', networking: wire } })
    );
    const networking = nodes.filter(n => n.type === 'networking');

    expect(networking).toHaveLength(1);
    expect(networking[0].configured).toBe(true);
    expect(networking[0].config).toEqual({
      timeout_secs: '30',
      connect_timeout_secs: '5',
      retry_enabled: true,
      retry_max: '3',
      retry_status_codes: '502,503',
    });
    expect(save(nodes).target.networking).toEqual(wire);
  });

  it('shows a Transit Point Networking element configured and saves it unchanged', () => {
    const nodes = nodesFromSurface(
      surface({
        transit: {
          points: [
            {
              id: 'tp-1',
              alias: 'upstream',
              target_endpoint: 'https://tp.example',
              protocol: 'a2a',
              networking: wire,
            },
          ],
        },
      })
    );
    const tp = nodes.find(n => registry.isTransitPointType(n.type))!;
    const networking = nodes.filter(n => n.type === 'networking');

    expect(networking).toHaveLength(1);
    expect(networking[0].parentId).toBe(tp.id);
    expect(networking[0].configured).toBe(true);
    const saved = save(nodes);
    expect(saved.transit.points[0].networking).toEqual(wire);
    expect(saved.target.networking).toBeUndefined();
  });

  it('keeps Networking added in the builder after a save and a reload', () => {
    const dropped = [
      { id: 'access-point', type: 'access-point', config: { route: '/api' } },
      {
        id: 'target',
        type: 'target',
        parentId: 'access-point',
        config: { endpoint: 'https://upstream.example' },
      },
      {
        id: 'networking',
        type: 'networking',
        parentId: 'target',
        slotId: 'request:networking',
        config: { timeout_secs: '30' },
      },
    ];
    const first = save(dropped);
    first.canvas = buildCanvasBlob(dropped as any);

    const reloaded = nodesFromSurface(first);

    expect(reloaded.find(n => n.id === 'target')?.parentId).toBe('networking');
    expect(save(reloaded).target.networking).toEqual({ timeout: { request_secs: 30 } });
  });

  it('does not write a Networking node that is not on the way to the Target', () => {
    const nodes = [
      { id: 'access-point', type: 'access-point', config: { route: '/api' } },
      { id: 'target', type: 'target', parentId: 'access-point', config: {} },
      {
        id: 'networking',
        type: 'networking',
        parentId: 'access-point',
        config: { timeout_secs: '30' },
      },
    ];
    expect(save(nodes).target.networking).toBeUndefined();
  });

  it('adds no Networking element when the API set none', () => {
    const nodes = nodesFromSurface(surface({}));
    expect(nodes.some(n => n.type === 'networking')).toBe(false);
    expect(save(nodes).target.networking).toBeUndefined();
  });
});
