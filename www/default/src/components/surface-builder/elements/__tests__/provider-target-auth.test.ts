import { registry } from '../index';
import type { SurfaceContext } from '../types';
import { managedAgentDefinition } from '../managed-agent/definition';
import {
  isTargetAuthProviderType,
  providerTargetAuthFromApi,
  providerTargetAuthToApi,
} from '../_shared/providerTargetAuth';

function makeCtx(nodes: any[]): SurfaceContext {
  return {
    protocol: 'a2a',
    surfaceMeta: { name: 'provider-target-auth', tags: [], status: 'active' },
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

function target(config: Record<string, unknown>) {
  return {
    id: 'tg',
    type: 'target',
    label: 'T',
    configured: true,
    config: { endpoint: 'https://agent.example.com', ...config },
  };
}

const providerWire = {
  method: {
    credential_provider: {
      provider_id: 'prov-1',
      header_name: 'Authorization',
      header_format: 'Bearer {value}',
    },
  },
  fallback: 'reject',
};

describe('credential provider target auth wire shape', () => {
  it('writes the provider method with Bearer Authorization defaults', () => {
    expect(
      providerTargetAuthToApi({
        providerId: ' prov-1 ',
        headerName: '',
        headerFormat: '',
        fallback: 'reject',
      })
    ).toEqual(providerWire);
  });

  it('writes nothing until a provider is picked', () => {
    expect(
      providerTargetAuthToApi({
        providerId: '',
        headerName: 'X-Key',
        headerFormat: '{value}',
        fallback: 'passthrough',
      })
    ).toBeUndefined();
  });

  it('reads the provider method back and ignores a static secret', () => {
    expect(
      providerTargetAuthFromApi({
        method: { credential_provider: { provider_id: 'prov-2', header_name: 'X-Key' } },
        fallback: 'passthrough',
      })
    ).toEqual({
      providerId: 'prov-2',
      headerName: 'X-Key',
      headerFormat: 'Bearer {value}',
      fallback: 'passthrough',
    });
    expect(
      providerTargetAuthFromApi({
        method: { static_secret: { secret_id: 's', header_name: 'X', header_format: '{value}' } },
      })
    ).toBeNull();
    expect(providerTargetAuthFromApi('credential_lookup')).toBeNull();
  });

  it('offers only provider types that need no user', () => {
    for (const type of [
      'oauth2_client_credentials',
      'oauth2_jwt_bearer',
      'oauth2_client_credentials_jwt_auth',
      'api_key',
    ]) {
      expect(isTargetAuthProviderType(type)).toBe(true);
    }
    expect(isTargetAuthProviderType('oauth2_authorization_code')).toBe(false);
    expect(isTargetAuthProviderType(undefined)).toBe(false);
  });
});

describe('Managed Agent target auth from a credential provider', () => {
  it('saves the provider method on the target', () => {
    const payload: any = registry.buildPayload(
      makeCtx([
        accessPoint,
        target({
          target_auth_enabled: true,
          target_auth_source: 'provider',
          target_auth_provider_id: 'prov-1',
          target_auth_type: 'bearer',
          target_auth_header_name: 'Authorization',
          target_auth_header_format: 'Bearer {value}',
          target_auth_fallback: 'reject',
          target_auth_secret_id: 'left-over-secret',
        }),
      ])
    );
    expect(payload.target.auth).toEqual({ ...providerWire, auth_type: 'bearer' });
  });

  it('saves no target auth while the provider is unset', () => {
    const payload: any = registry.buildPayload(
      makeCtx([
        accessPoint,
        target({
          target_auth_enabled: true,
          target_auth_source: 'provider',
          target_auth_type: 'bearer',
        }),
      ])
    );
    expect(payload.target.auth).toBeUndefined();
  });

  it('keeps saving a static secret as before', () => {
    const payload: any = registry.buildPayload(
      makeCtx([
        accessPoint,
        target({
          target_auth_enabled: true,
          target_auth_secret_id: 'api-secret',
          target_auth_type: 'api_key',
          target_auth_header_name: 'X-API-Key',
          target_auth_header_format: '{value}',
        }),
      ])
    );
    expect(payload.target.auth.method).toEqual({
      static_secret: {
        secret_id: 'api-secret',
        header_name: 'X-API-Key',
        header_format: '{value}',
      },
    });
  });

  it('loads a stored provider method into the panel fields', () => {
    const config: any = managedAgentDefinition.configFromPayload!(
      { endpoint: 'https://agent.example.com', auth: providerWire },
      {}
    );
    expect(config).toMatchObject({
      target_auth_enabled: true,
      target_auth_source: 'provider',
      target_auth_provider_id: 'prov-1',
      target_auth_header_name: 'Authorization',
      target_auth_header_format: 'Bearer {value}',
      target_auth_type: 'bearer',
      target_auth_fallback: 'reject',
    });
    expect(config.auth).toBeUndefined();
  });
});

describe('Transit Point target auth from a credential provider', () => {
  function transitPoint(config: Record<string, unknown>) {
    return {
      id: 'tp-1',
      type: 'transit-point-a2a',
      label: '',
      configured: true,
      config: { target_endpoint: 'https://partner.example.com', ...config },
    };
  }

  it('saves the provider method on the Transit Point', () => {
    const payload: any = registry.buildPayload(
      makeCtx([
        accessPoint,
        target({}),
        transitPoint({
          auth_type: 'credential_provider',
          auth_provider_id: 'prov-1',
          auth_header_name: 'X-Partner-Token',
          auth_header_format: '{value}',
          auth_fallback: 'passthrough',
        }),
      ])
    );
    expect(payload.transit.points[0].target_auth).toEqual({
      method: {
        credential_provider: {
          provider_id: 'prov-1',
          header_name: 'X-Partner-Token',
          header_format: '{value}',
        },
      },
      fallback: 'passthrough',
    });
  });

  it('blocks save until a provider is picked', () => {
    const definition = registry.get('transit-point-a2a')!;
    const rule = definition.featureDependencies!.find(
      dependency => dependency.description === 'A credential provider target auth needs a provider'
    )!;
    const missing = { auth_type: 'credential_provider', auth_provider_id: '' };
    expect(rule.condition(missing, makeCtx([]))).toBe(true);
    expect(rule.check(missing, makeCtx([]))).toBe(false);
    expect(rule.check({ ...missing, auth_provider_id: 'prov-1' }, makeCtx([]))).toBe(true);
  });
});
