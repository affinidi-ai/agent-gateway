import { registry } from '../index';
import type { CanvasNode } from '../../SurfaceCanvas';

const SECRET_MESSAGE = 'Pick the secret whose value authenticates this Transit Point.';

function secretErrors(config: Record<string, unknown>) {
  const definition = registry.get('transit-point-a2a')!;
  return definition.validate!({ target_endpoint: 'https://partner.example.com', ...config }).filter(
    error => error.field === 'auth_secret'
  );
}

describe('Transit Point static-secret target auth', () => {
  it.each(['bearer', 'api_key', 'custom_header'])(
    'blocks save while a %s target auth has no secret',
    authType => {
      expect(secretErrors({ auth_type: authType, auth_secret: '' })).toEqual([
        { field: 'auth_secret', message: SECRET_MESSAGE },
      ]);
      expect(secretErrors({ auth_type: authType, auth_secret: '   ' })).toEqual([
        { field: 'auth_secret', message: SECRET_MESSAGE },
      ]);
      expect(secretErrors({ auth_type: authType })).toEqual([
        { field: 'auth_secret', message: SECRET_MESSAGE },
      ]);
    }
  );

  it('accepts a static-secret target auth with a secret', () => {
    expect(secretErrors({ auth_type: 'api_key', auth_secret: 'choose_mission_mcp_key' })).toEqual(
      []
    );
  });

  it('ignores the secret for no target auth and for a credential provider', () => {
    expect(secretErrors({ auth_type: 'none', auth_secret: '' })).toEqual([]);
    expect(secretErrors({ auth_secret: '' })).toEqual([]);
    expect(secretErrors({ auth_type: 'credential_provider', auth_secret: '' })).toEqual([]);
  });

  it('saves the chosen secret id as a static secret', () => {
    const nodes: CanvasNode[] = [
      { id: 'ap', type: 'access-point', label: 'AP', configured: true, config: { route: '/api' } },
      {
        id: 'tg',
        type: 'target',
        label: 'T',
        configured: true,
        config: { endpoint: 'https://agent.example.com' },
      },
      {
        id: 'tp-1',
        type: 'transit-point-a2a',
        label: '',
        configured: true,
        config: {
          target_endpoint: 'https://partner.example.com',
          auth_type: 'api_key',
          auth_secret: 'choose_mission_mcp_key',
          auth_header_name: 'x-api-key',
        },
      },
    ];
    const payload: any = registry.buildPayload({
      protocol: 'a2a',
      surfaceMeta: { name: 'secret-target-auth', tags: [], status: 'active' },
      allNodes: nodes,
      nodesOfType: type => nodes.filter(node => node.type === type),
      firstNodeOfType: type => nodes.find(node => node.type === type),
    });
    expect(payload.transit.points[0].target_auth).toEqual({
      method: {
        static_secret: {
          secret_id: 'choose_mission_mcp_key',
          header_name: 'x-api-key',
          header_format: '{value}',
        },
      },
      fallback: 'reject',
    });
  });
});
