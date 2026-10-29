import { registry } from '../index';
import type { SurfaceContext } from '../types';

function makeCtx(nodes: any[]): SurfaceContext {
  return {
    protocol: 'a2a',
    surfaceMeta: { name: 'target-auth', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: type => nodes.filter(n => n.type === type),
    firstNodeOfType: type => nodes.find(n => n.type === type),
  };
}

const accessPoint = {
  id: 'ap',
  type: 'access-point',
  label: 'AP',
  configured: true,
  config: { route: '/api' },
};

function targetNode(config: Record<string, unknown>) {
  return {
    id: 'target',
    type: 'target',
    label: 'T',
    configured: true,
    config: { endpoint: 'https://upstream.example.com', ...config },
  };
}

function targetPayload(auth: unknown) {
  return {
    access_point: { route: '/api' },
    target: { endpoint: 'https://upstream.example.com', auth },
  };
}

function rebuild(auth: unknown) {
  const nodes = registry.nodesFromPayload(targetPayload(auth));
  const payload = registry.buildPayload(makeCtx(nodes)) as any;
  return { nodes, auth: payload.target?.auth };
}

describe('managed agent Target Authentication round trip', () => {
  it('round-trips a credential_provider method with scopes and a custom header', () => {
    const auth = {
      method: {
        credential_provider: {
          credential_provider_id: 'cp-1',
          scopes: ['cloud-platform', 'email'],
          inject_as: { type: 'custom_header', name: 'X-Token', format: 'tok {value}' },
        },
      },
      fallback: 'passthrough',
    };
    const { nodes, auth: out } = rebuild(auth);
    const target = nodes.find(n => n.type === 'target')!;
    expect(target.config.target_auth_type).toBe('credential_provider');
    expect(target.config.target_auth_credential_provider_id).toBe('cp-1');
    expect(out).toEqual(auth);
  });

  it('round-trips a credential_provider method that uses the defaults', () => {
    const { auth: out } = rebuild({
      method: { credential_provider: { credential_provider_id: 'cp-1' } },
      fallback: 'reject',
    });
    expect(out).toEqual({
      method: {
        credential_provider: {
          credential_provider_id: 'cp-1',
          inject_as: { type: 'bearer_header' },
        },
      },
      fallback: 'reject',
    });
  });

  it('still round-trips a static_secret method', () => {
    const auth = {
      method: {
        static_secret: { secret_id: 's1', header_name: 'X-API-Key', header_format: '{value}' },
      },
      auth_type: 'api_key',
      fallback: 'reject',
    };
    expect(rebuild(auth).auth).toEqual(auth);
  });

  it('keeps an unknown variant byte for byte instead of dropping it on save', () => {
    const auth = { method: { future_method: { audience: 'x' } }, fallback: 'passthrough' };
    const { nodes, auth: out } = rebuild(auth);
    expect(nodes.find(n => n.type === 'target')!.config.target_auth_type).toBe('preserved');
    expect(out).toEqual(auth);
  });

  it('keeps a credential_lookup method', () => {
    const auth = { method: 'credential_lookup', target_identifier: 't', fallback: 'reject' };
    expect(rebuild(auth).auth).toEqual(auth);
  });

  it('drops the preserved variant once the operator picks another type', () => {
    const nodes = [
      accessPoint,
      targetNode({
        target_auth_enabled: true,
        target_auth_type: 'bearer',
        target_auth_raw: { method: { future_method: {} } },
        target_auth_secret_id: 's1',
      }),
    ];
    const payload = registry.buildPayload(makeCtx(nodes)) as any;
    expect(payload.target.auth.method).toEqual({
      static_secret: { secret_id: 's1', header_name: 'Authorization', header_format: '{value}' },
    });
  });

  it('emits no auth when the operator turns Target Authentication off', () => {
    const nodes = [
      accessPoint,
      targetNode({
        target_auth_enabled: false,
        target_auth_type: 'preserved',
        target_auth_raw: { method: { future_method: {} } },
      }),
    ];
    expect((registry.buildPayload(makeCtx(nodes)) as any).target.auth).toBeUndefined();
  });

  describe('validation', () => {
    const errorsFor = (config: Record<string, unknown>) =>
      registry.get('target')!.validate!({
        endpoint: 'https://upstream.example.com',
        target_auth_enabled: true,
        target_auth_type: 'credential_provider',
        ...config,
      });

    it('blocks Save for a credential_provider selection without a provider', () => {
      expect(errorsFor({})).toEqual([
        { field: 'target_auth_credential_provider_id', message: 'Select a credential provider.' },
      ]);
    });

    it('accepts a chosen provider on an https url', () => {
      expect(errorsFor({ target_auth_credential_provider_id: 'cp-1' })).toEqual([]);
    });

    it('rejects a custom header without a name or a {value} format', () => {
      const base = {
        target_auth_credential_provider_id: 'cp-1',
        target_auth_inject_as: 'custom_header',
      };
      expect(errorsFor({ ...base, target_auth_inject_format: '{value}' })).toEqual([
        { field: 'target_auth_credential_provider_id', message: 'Enter the header name.' },
      ]);
      expect(
        errorsFor({ ...base, target_auth_inject_name: 'X-T', target_auth_inject_format: 'x' })
      ).toEqual([
        {
          field: 'target_auth_credential_provider_id',
          message: 'The header format must contain {value}.',
        },
      ]);
    });

    it('rejects an http target and a non-url endpoint type', () => {
      expect(
        errorsFor({ target_auth_credential_provider_id: 'cp-1', endpoint: 'http://u.example.com' })
      ).toEqual([
        { field: 'endpoint', message: 'A credential provider needs an https:// target.' },
      ]);
      expect(
        errorsFor({
          target_auth_credential_provider_id: 'cp-1',
          endpoint_type: 'gateway',
          gateway_id: 'g',
          gateway_channel: 'c',
        })
      ).toEqual([
        {
          field: 'target_auth_type',
          message: 'A credential provider needs a direct https URL target.',
        },
      ]);
    });

    it('does not check the provider when Target Authentication is off', () => {
      expect(errorsFor({ target_auth_enabled: false })).toEqual([]);
    });
  });
});
