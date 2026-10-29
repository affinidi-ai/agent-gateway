/**
 * Transit Settings offer no listener authentication: a stored
 * `transit.source_auth` neither hydrates the panel nor survives a save.
 */

import { registry } from '../index';
import type { SurfaceContext } from '../types';
import { AGENT_SURFACE_PATHS } from '../agentSurfaceSchema';
import { transitConfigConfigFromPayload } from '../transit-config/definition';

function makeCtx(nodes: any[]): SurfaceContext {
  return {
    protocol: 'a2a',
    surfaceMeta: { name: 'transit-source-auth', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: type => nodes.filter(n => n.type === type),
    firstNodeOfType: type => nodes.find(n => n.type === type),
  };
}

const baseNodes = [
  { id: 'ap', type: 'access-point', label: 'AP', configured: true, config: { route: '/api' } },
  {
    id: 'target',
    type: 'target',
    label: 'T',
    configured: true,
    config: { endpoint: 'https://upstream.example.com' },
  },
  {
    id: 'tp-1',
    type: 'transit-point-a2a',
    label: '',
    configured: true,
    config: { target_endpoint: 'https://upstream.example.com', alias: 'tp1' },
  },
];

const storedSourceAuth = {
  type: 'api_key',
  secret_id: 'transit-secret',
  extraction: { field: 'X-API-Key' },
};

describe('Transit Settings listener authentication', () => {
  it('does not hydrate listener authentication from a stored transit.source_auth', () => {
    const config = transitConfigConfigFromPayload({
      transit: { source_auth: storedSourceAuth, opa_policy_definition_id: 'policy-1' },
    });
    expect(config).toEqual({
      transit_token_mode: 'embedded',
      sign_requests: true,
      opa_policy_definition_id: 'policy-1',
    });
  });

  it('returns null when transit.source_auth is the only shared transit field', () => {
    expect(
      transitConfigConfigFromPayload({ transit: { source_auth: storedSourceAuth } })
    ).toBeNull();
  });

  it('never writes transit.source_auth, even from stale listener authentication fields', () => {
    const transitConfig = {
      id: 'transit-config',
      type: 'transit-config',
      label: '',
      configured: true,
      config: {
        transit_token_mode: 'embedded',
        sign_requests: true,
        listener_auth_type: 'api_key',
        listener_auth_header: 'X-API-Key',
        listener_auth_secret_id: 'transit-secret',
      },
    };
    const payload = registry.buildPayload(makeCtx([...baseNodes, transitConfig]));
    expect(payload.transit?.transit_token_mode).toBe('embedded');
    expect(payload.transit).not.toHaveProperty('source_auth');
  });

  it('is not a known surface path', () => {
    expect(AGENT_SURFACE_PATHS.has('transit.source_auth')).toBe(false);
  });
});
