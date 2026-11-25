import { buildCanvasBlob, registry } from '../index';
import { buildSurfaceContext } from '../surfaceContext';
import {
  INBOUND_API_KEY_NEEDS_API_KEY_CALLER,
  SELECT_OWN_API_KEY,
  TRANSIT_POINT_API_KEY_NEEDS_API_KEY_CALLER,
  TRANSIT_POINT_JWT_CLAIM_NEEDS_JWT_CALLER,
  TRANSIT_POINT_MTLS_NEEDS_MTLS_CALLER,
} from '../identity/definition';
import type { CanvasNode, PayloadContext } from '../types';

const inboundNode = { id: 'identity-inbound', slotId: 'request:identity-inbound' };
const protectedNode = { id: 'identity-protected', slotId: 'response:identity-protected' };

function makeCtx(nodes: any[]): PayloadContext {
  return {
    protocol: 'a2a',
    surfaceMeta: { name: 'from-api-key', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: (type: string) => nodes.filter(n => n.type === type),
    firstNodeOfType: (type: string) => nodes.find(n => n.type === type),
  } as unknown as PayloadContext;
}

const identity = (placement: { id: string; slotId: string }, config: Record<string, unknown>) =>
  ({ ...placement, type: 'identity', label: '', configured: true, config }) as CanvasNode;

const callerAuth = (method_type: string) =>
  ({
    id: 'caller-auth',
    type: 'caller-auth',
    label: '',
    configured: true,
    config: { method_type },
  }) as CanvasNode;

const accessPoint = {
  id: 'access-point',
  type: 'access-point',
  label: '',
  configured: true,
  config: { route: '/api' },
} as CanvasNode;

const fromApiKeyErrors = (nodes: CanvasNode[], node: CanvasNode) =>
  registry
    .getDependencyWarnings('identity', node.config, buildSurfaceContext('a2a', nodes), node)
    .filter(w => w.severity === 'error')
    .map(w => w.message);

describe('identity From API Key — payload', () => {
  it('drops api_key_id from the inbound slot', () => {
    const payload = registry.buildPayload(
      makeCtx([
        accessPoint,
        identity(inboundNode, { type: 'from_api_key', api_key_id: 'atgk_stale' }),
      ])
    );
    expect(payload.identity_slots.inbound).toEqual({ type: 'from_api_key' });
  });

  it('drops api_key_id from a node placed in the inbound slot by slot id only', () => {
    const payload = registry.buildPayload(
      makeCtx([
        accessPoint,
        identity(
          { id: 'identity-legacy', slotId: 'request:identity-inbound' },
          { type: 'from_api_key', api_key_id: 'atgk_stale' }
        ),
      ])
    );
    expect(payload.identity_slots.inbound).toEqual({ type: 'from_api_key' });
  });

  it('keeps api_key_id on the protected slot', () => {
    const payload = registry.buildPayload(
      makeCtx([
        accessPoint,
        identity(protectedNode, { type: 'from_api_key', api_key_id: 'atgk_agent' }),
      ])
    );
    expect(payload.identity_slots.protected).toEqual({
      type: 'from_api_key',
      api_key_id: 'atgk_agent',
    });
  });
});

describe('identity From API Key — canvas blob', () => {
  const blobConfig = (node: CanvasNode) =>
    buildCanvasBlob([{ ...node, position: { x: 0, y: 0 } }]).nodes.find(n => n.id === node.id)!
      .config;

  it('drops a stored api_key_id from the inbound node config', () => {
    const config = blobConfig(
      identity(inboundNode, { type: 'from_api_key', api_key_id: 'atgk_stale' })
    );
    expect(config).toEqual({ type: 'from_api_key' });
  });

  it('keeps api_key_id on the protected node config', () => {
    const config = blobConfig(
      identity(protectedNode, { type: 'from_api_key', api_key_id: 'atgk_agent' })
    );
    expect(config).toEqual({ type: 'from_api_key', api_key_id: 'atgk_agent' });
  });
});

describe('identity From API Key — completeness', () => {
  it('does not require a key on the inbound node', () => {
    expect(registry.getIncompleteReason('identity', { type: 'from_api_key' }, inboundNode)).toBe(
      null
    );
    expect(registry.isConfigured('identity', { type: 'from_api_key' }, inboundNode)).toBe(true);
  });

  it('requires a key on the protected node', () => {
    expect(registry.getIncompleteReason('identity', { type: 'from_api_key' }, protectedNode)).toBe(
      SELECT_OWN_API_KEY
    );
    expect(registry.isConfigured('identity', { type: 'from_api_key' }, protectedNode)).toBe(false);
    expect(
      registry.getIncompleteReason(
        'identity',
        { type: 'from_api_key', api_key_id: 'atgk_agent' },
        protectedNode
      )
    ).toBe(null);
  });

  it('requires a key when the caller has no node to place it', () => {
    expect(registry.getIncompleteReason('identity', { type: 'from_api_key' })).toBe(
      SELECT_OWN_API_KEY
    );
  });

  it('hydrates a stored inbound From API Key slot as configured', () => {
    const nodes = registry.nodesFromPayload({
      access_point: { route: '/api' },
      target: { endpoint: 'https://upstream.example.com' },
      identity_slots: { inbound: { type: 'from_api_key' } },
    });
    const inbound = nodes.find(n => n.id === 'identity-inbound');
    expect(inbound?.config?.type).toBe('from_api_key');
    expect(inbound?.configured).toBe(true);
  });
});

describe('identity From API Key — Caller Context dependency', () => {
  const inbound = identity(inboundNode, { type: 'from_api_key' });

  it('is an error behind a JWT Bearer Caller Context', () => {
    expect(fromApiKeyErrors([accessPoint, callerAuth('jwt_bearer'), inbound], inbound)).toEqual([
      INBOUND_API_KEY_NEEDS_API_KEY_CALLER,
    ]);
  });

  it('is an error without a Caller Context', () => {
    expect(fromApiKeyErrors([accessPoint, inbound], inbound)).toEqual([
      INBOUND_API_KEY_NEEDS_API_KEY_CALLER,
    ]);
  });

  it.each(['api_key', 'api_key_provider'])('passes behind a %s Caller Context', method => {
    expect(fromApiKeyErrors([accessPoint, callerAuth(method), inbound], inbound)).toEqual([]);
  });

  it('passes beside a Caller Context method that is not an API key', () => {
    const mixed = {
      ...callerAuth('jwt_bearer'),
      config: { methods: [{ method_type: 'jwt_bearer' }, { method_type: 'api_key' }] },
    };
    expect(fromApiKeyErrors([accessPoint, mixed, inbound], inbound)).toEqual([]);
  });

  it('is an error when no Caller Context method is an API key', () => {
    expect(fromApiKeyErrors([accessPoint, callerAuth('jwt_bearer'), inbound], inbound)).toEqual([
      INBOUND_API_KEY_NEEDS_API_KEY_CALLER,
    ]);
  });

  it('does not apply to the protected node', () => {
    const node = identity(protectedNode, { type: 'from_api_key', api_key_id: 'atgk_agent' });
    expect(fromApiKeyErrors([accessPoint, callerAuth('jwt_bearer'), node], node)).toEqual([]);
  });

  it('uses the backend refusal text', () => {
    expect(INBOUND_API_KEY_NEEDS_API_KEY_CALLER).toBe(
      "Identity 'From API Key' needs an API Key or API Key Provider Caller Context method"
    );
  });
});

const transitPoint = (sourceAuth?: Record<string, unknown>) =>
  ({
    id: 'tp-1',
    type: 'transit-point-a2a',
    label: '',
    configured: true,
    config: {
      alias: 'tr1',
      target_endpoint: 'https://delta.example.com',
      ...(sourceAuth ? { source_auth: sourceAuth } : {}),
    },
  }) as CanvasNode;
const tpIdentity = (config: Record<string, unknown>) =>
  ({
    id: 'identity-tp-1-request',
    type: 'identity',
    label: '',
    configured: true,
    parentId: 'tp-1',
    slotId: 'request:identity-managed_identity',
    config,
  }) as CanvasNode;
const apiKeyCaller = {
  type: 'api_key',
  extraction: { source: 'http_header', field: 'X-API-Key' },
  secret_id: 'agents',
};
const providerCaller = {
  type: 'api_key_provider',
  extraction: { source: 'http_header', field: 'X-API-Key' },
  agent_id: 'surface-1',
};
const jwtCaller = { type: 'jwt_bearer', jwt_verification_strategy_id: 's', audiences: ['tr1'] };
const mtlsCaller = { type: 'mtls', trust: { type: 'pinned', certificate_ids: ['c'] } };

const hydrateTransitPointIdentity = (
  sourceAuth: Record<string, unknown>,
  managedIdentity: Record<string, unknown>
) =>
  registry
    .nodesFromPayload({
      access_point: { route: '/api' },
      target: { endpoint: 'https://upstream.example.com' },
      transit: {
        points: [
          {
            id: 'tp-uuid',
            alias: 'tr1',
            target_endpoint: 'https://delta.example.com',
            protocol: 'a2a',
            source_auth: sourceAuth,
            managed_identity: managedIdentity,
          },
        ],
      },
    })
    .find(n => n.type === 'identity' && n.parentId);

describe('identity From API Key — Transit Point', () => {
  const callerBound = tpIdentity({ type: 'from_api_key' });

  it('writes managed_identity without api_key_id', () => {
    const payload = registry.buildPayload(
      makeCtx([accessPoint, transitPoint(apiKeyCaller), callerBound])
    );
    expect(payload.transit.points[0].managed_identity).toEqual({ type: 'from_api_key' });
  });

  it('keeps a stored api_key_id', () => {
    const stored = tpIdentity({ type: 'from_api_key', api_key_id: 'atgk_agent' });
    const payload = registry.buildPayload(makeCtx([accessPoint, transitPoint(jwtCaller), stored]));
    expect(payload.transit.points[0].managed_identity).toEqual({
      type: 'from_api_key',
      api_key_id: 'atgk_agent',
    });
    expect(fromApiKeyErrors([accessPoint, transitPoint(jwtCaller), stored], stored)).toEqual([]);
  });

  it('does not require a key', () => {
    expect(registry.getIncompleteReason('identity', { type: 'from_api_key' }, callerBound)).toBe(
      null
    );
  });

  it('hydrates a stored caller-bound setting as configured and round-trips it', () => {
    const node = hydrateTransitPointIdentity(apiKeyCaller, { type: 'from_api_key' });
    expect(node?.config).toEqual({ type: 'from_api_key' });
    expect(node?.configured).toBe(true);
  });

  it.each([
    ['api_key', apiKeyCaller],
    ['api_key_provider', providerCaller],
  ])('passes behind %s caller authentication', (_name, sourceAuth) => {
    expect(
      fromApiKeyErrors([accessPoint, transitPoint(sourceAuth), callerBound], callerBound)
    ).toEqual([]);
  });

  it.each([
    ['JWT Bearer', jwtCaller],
    ['no', undefined],
  ])('blocks Save behind %s caller authentication', (_name, sourceAuth) => {
    expect(
      fromApiKeyErrors([accessPoint, transitPoint(sourceAuth), callerBound], callerBound)
    ).toEqual([TRANSIT_POINT_API_KEY_NEEDS_API_KEY_CALLER]);
  });
});

describe('identity From JWT Claims — Transit Point', () => {
  const fromClaim = tpIdentity({ type: 'from_jwt_claim', claim: 'oid', namespace_claims: ['tid'] });

  it('writes managed_identity with its claim and namespace claims', () => {
    const payload = registry.buildPayload(
      makeCtx([accessPoint, transitPoint(jwtCaller), fromClaim])
    );
    expect(payload.transit.points[0].managed_identity).toEqual({
      type: 'from_jwt_claim',
      claim: 'oid',
      namespace_claims: ['tid'],
    });
  });

  it('writes the oid claim when none is set', () => {
    const payload = registry.buildPayload(
      makeCtx([accessPoint, transitPoint(jwtCaller), tpIdentity({ type: 'from_jwt_claim' })])
    );
    expect(payload.transit.points[0].managed_identity).toEqual({
      type: 'from_jwt_claim',
      claim: 'oid',
    });
  });

  it('passes behind JWT Bearer caller authentication, whatever the Caller Context', () => {
    expect(
      fromApiKeyErrors(
        [accessPoint, callerAuth('api_key'), transitPoint(jwtCaller), fromClaim],
        fromClaim
      )
    ).toEqual([]);
  });

  it.each([
    ['API key', apiKeyCaller],
    ['mTLS', mtlsCaller],
    ['no', undefined],
  ])('blocks Save behind %s caller authentication', (_name, sourceAuth) => {
    expect(
      fromApiKeyErrors(
        [accessPoint, callerAuth('jwt_bearer'), transitPoint(sourceAuth), fromClaim],
        fromClaim
      )
    ).toEqual([TRANSIT_POINT_JWT_CLAIM_NEEDS_JWT_CALLER]);
  });

  it('still needs a JWT Bearer Caller Context on the inbound identity', () => {
    const inbound = identity(inboundNode, { type: 'from_jwt_claim' });
    expect(fromApiKeyErrors([accessPoint, callerAuth('api_key'), inbound], inbound)).toHaveLength(
      1
    );
    expect(fromApiKeyErrors([accessPoint, callerAuth('jwt_bearer'), inbound], inbound)).toEqual([]);
  });

  it('hydrates a stored setting as configured', () => {
    const node = hydrateTransitPointIdentity(jwtCaller, {
      type: 'from_jwt_claim',
      claim: 'oid',
      namespace_claims: ['tid'],
    });
    expect(node?.config).toEqual({
      type: 'from_jwt_claim',
      claim: 'oid',
      namespace_claims: ['tid'],
    });
    expect(node?.configured).toBe(true);
  });

  it('uses the refusal text', () => {
    expect(TRANSIT_POINT_JWT_CLAIM_NEEDS_JWT_CALLER).toBe(
      "Identity 'From JWT Claims' on a Transit Point needs that Transit Point's caller authentication to be JWT Bearer"
    );
  });
});

describe('identity From mTLS certificate — Transit Point', () => {
  const callerBound = tpIdentity({ type: 'from_mtls' });

  it('writes managed_identity without certificate_id', () => {
    const payload = registry.buildPayload(
      makeCtx([accessPoint, transitPoint(mtlsCaller), callerBound])
    );
    expect(payload.transit.points[0].managed_identity).toEqual({ type: 'from_mtls' });
  });

  it('keeps a stored certificate_id and does not block Save', () => {
    const stored = tpIdentity({ type: 'from_mtls', certificate_id: 'cert-1' });
    const payload = registry.buildPayload(makeCtx([accessPoint, transitPoint(jwtCaller), stored]));
    expect(payload.transit.points[0].managed_identity).toEqual({
      type: 'from_mtls',
      certificate_id: 'cert-1',
    });
    expect(fromApiKeyErrors([accessPoint, transitPoint(jwtCaller), stored], stored)).toEqual([]);
  });

  it('does not require a certificate on a Transit Point', () => {
    expect(registry.getIncompleteReason('identity', { type: 'from_mtls' }, callerBound)).toBe(null);
  });

  it('still requires a certificate in other slots', () => {
    expect(registry.getIncompleteReason('identity', { type: 'from_mtls' }, protectedNode)).toBe(
      'Select a certificate'
    );
    expect(registry.getIncompleteReason('identity', { type: 'from_mtls' }, inboundNode)).toBe(
      'Select a certificate'
    );
  });

  it('passes behind mTLS caller authentication', () => {
    expect(
      fromApiKeyErrors([accessPoint, transitPoint(mtlsCaller), callerBound], callerBound)
    ).toEqual([]);
  });

  it.each([
    ['API key', apiKeyCaller],
    ['JWT Bearer', jwtCaller],
    ['no', undefined],
  ])('blocks Save behind %s caller authentication', (_name, sourceAuth) => {
    expect(
      fromApiKeyErrors([accessPoint, transitPoint(sourceAuth), callerBound], callerBound)
    ).toEqual([TRANSIT_POINT_MTLS_NEEDS_MTLS_CALLER]);
  });

  it('hydrates a stored setting without certificate_id as configured', () => {
    const node = hydrateTransitPointIdentity(mtlsCaller, { type: 'from_mtls' });
    expect(node?.config).toEqual({ type: 'from_mtls' });
    expect(node?.configured).toBe(true);
  });

  it('uses the refusal text', () => {
    expect(TRANSIT_POINT_MTLS_NEEDS_MTLS_CALLER).toBe(
      "Identity 'From mTLS certificate' on a Transit Point needs that Transit Point's caller authentication to be mTLS"
    );
  });
});
