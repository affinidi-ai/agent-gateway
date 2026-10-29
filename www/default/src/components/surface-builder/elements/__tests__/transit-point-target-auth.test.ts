import { registry } from '../index';
import type { SurfaceContext } from '../types';

function makeCtx(nodes: any[]): SurfaceContext {
  return {
    protocol: 'a2a',
    surfaceMeta: { name: 'tp-auth', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: type => nodes.filter(n => n.type === type),
    firstNodeOfType: type => nodes.find(n => n.type === type),
  };
}

const point = (targetAuth?: unknown) => ({
  id: 'tp-uuid',
  alias: 'tp1',
  target_endpoint: 'https://upstream.example.com',
  protocol: 'a2a',
  ...(targetAuth === undefined ? {} : { target_auth: targetAuth }),
});

function hydrate(targetAuth?: unknown) {
  return registry.nodesFromPayload({
    access_point: { route: '/api' },
    target: { endpoint: 'https://upstream.example.com' },
    transit: { points: [point(targetAuth)] },
  });
}

function build(nodes: any[]) {
  const payload = registry.buildPayload(makeCtx(nodes)) as any;
  return payload.transit.points[0].target_auth;
}

function withConfig(nodes: any[], patch: Record<string, unknown>) {
  return nodes.map(n =>
    n.type === 'transit-point-a2a' ? { ...n, config: { ...n.config, ...patch } } : n
  );
}

describe('Transit Point Target Authentication variants the editor cannot edit', () => {
  const credentialProvider = {
    method: { credential_provider: { credential_provider_id: 'cp-1' } },
    fallback: 'reject',
  };
  const unknown = { method: { future_method: { x: 1 } }, fallback: 'passthrough' };

  it.each([
    ['credential_provider', credentialProvider],
    ['an unknown variant', unknown],
  ])('keeps %s on save when nothing was changed', (_name, auth) => {
    expect(build(hydrate(auth))).toEqual(auth);
  });

  it('removes it when the operator picks None', () => {
    expect(build(withConfig(hydrate(unknown), { auth_type: 'none' }))).toBeUndefined();
  });

  it('replaces it with a static secret when the operator picks a header type', () => {
    const out = build(
      withConfig(hydrate(unknown), {
        auth_type: 'bearer',
        auth_secret: 's1',
        auth_fallback: 'reject',
      })
    );
    expect(out).toEqual({
      method: {
        static_secret: {
          secret_id: 's1',
          header_name: 'Authorization',
          header_format: 'Bearer {value}',
        },
      },
      fallback: 'reject',
    });
  });

  it('still round-trips a static secret', () => {
    const nodes = hydrate({
      method: {
        static_secret: { secret_id: 's1', header_name: 'X-API-Key', header_format: '{value}' },
      },
      fallback: 'reject',
    });
    const out = build(
      withConfig(nodes, {
        auth_type: 'api_key',
        auth_secret: 's1',
        auth_header_name: 'X-API-Key',
        auth_header_format: '{value}',
      })
    );
    expect(out.method.static_secret).toEqual({
      secret_id: 's1',
      header_name: 'X-API-Key',
      header_format: '{value}',
    });
  });

  it('emits nothing for a point with no Target Authentication', () => {
    expect(build(hydrate())).toBeUndefined();
  });

  it('keeps a static secret on save when the panel was never opened', () => {
    const auth = {
      method: {
        static_secret: { secret_id: 's1', header_name: 'X-API-Key', header_format: '{value}' },
      },
      fallback: 'passthrough',
    };
    expect(build(hydrate(auth))).toEqual(auth);
  });
});
