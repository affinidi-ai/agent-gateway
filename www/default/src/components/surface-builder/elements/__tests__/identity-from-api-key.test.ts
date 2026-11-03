import { buildCanvasBlob, registry } from '../index';
import { buildSurfaceContext } from '../surfaceContext';
import { INBOUND_API_KEY_NEEDS_API_KEY_CALLER } from '../identity/definition';
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
      'Select an API key'
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
      'Select an API key'
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

  it('does not apply to the protected node', () => {
    const node = identity(protectedNode, { type: 'from_api_key', api_key_id: 'atgk_agent' });
    expect(fromApiKeyErrors([accessPoint, callerAuth('jwt_bearer'), node], node)).toEqual([]);
  });

  it('uses the backend refusal text', () => {
    expect(INBOUND_API_KEY_NEEDS_API_KEY_CALLER).toBe(
      "Identity 'From API Key' needs an API Key or API Key Provider as the first Caller Context method"
    );
  });
});
