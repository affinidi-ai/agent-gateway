import { registry } from '../index';
import { buildSurfaceContext } from '../surfaceContext';
import type { CanvasNode, PayloadContext } from '../types';
import { scrubVolatileTemplateFields } from '../../templates/scrubVolatile';

const JWT = {
  type: 'jwt_bearer',
  id: 'users-jwt',
  jwt_verification_strategy_id: 'idp',
  audiences: ['api://agent'],
  token_header: 'Authorization',
  token_scheme: 'Bearer',
  forward_header: false,
};
const API_KEY = {
  type: 'api_key',
  id: 'partner-key',
  extraction: { source: 'http_header', field: 'X-API-Key' },
  secret_id: 'partner-keys',
};

function stored(methods: unknown[], identitySlots: Record<string, unknown> = {}) {
  return {
    name: 'mixed',
    status: 'active',
    tags: [],
    access_point: {
      listen_address: 'https://gateway.example',
      route: '/a2a/alpha',
      protocol: 'a2a',
      caller_authentication: { methods },
    },
    target: { endpoint: 'https://agent.example' },
    identity_slots: identitySlots,
  };
}

function context(nodes: CanvasNode[]): PayloadContext {
  return {
    protocol: 'a2a',
    surfaceMeta: { name: 'mixed', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: type => nodes.filter(n => n.type === type),
    firstNodeOfType: type => nodes.find(n => n.type === type),
  };
}

const rebuild = (payload: unknown) => {
  const nodes = registry.nodesFromPayload(payload);
  return { nodes, payload: registry.buildPayload(context(nodes)) };
};

const inboundNode = (nodes: CanvasNode[]) => nodes.find(n => n.id === 'identity-inbound')!;

const errors = (nodes: CanvasNode[]) => {
  const node = inboundNode(nodes);
  return registry
    .getDependencyWarnings('identity', node.config, buildSurfaceContext('a2a', nodes), node)
    .filter(w => w.severity === 'error')
    .map(w => w.message);
};

describe('caller authentication method ids', () => {
  it('keeps each method id through a load and a save', () => {
    const { payload } = rebuild(stored([JWT, API_KEY]));
    expect(payload.access_point.caller_authentication.methods.map((m: any) => m.id)).toEqual([
      'users-jwt',
      'partner-key',
    ]);
  });

  it('gives a stored method without an id one in memory, unique and stable across loads', () => {
    const legacy = stored([
      { ...JWT, id: undefined },
      { ...API_KEY, id: undefined },
    ]);
    const ids = (nodes: CanvasNode[]) =>
      nodes.find(n => n.type === 'caller-auth')!.config.methods.map((m: any) => m.id);
    const first = ids(registry.nodesFromPayload(legacy));
    expect(first).toHaveLength(2);
    expect(first.every((id: unknown) => /^[a-z0-9-]{1,32}$/.test(String(id)))).toBe(true);
    expect(new Set(first).size).toBe(2);
    expect(ids(registry.nodesFromPayload(legacy))).toEqual(first);
  });

  it('saves a surface stored without ids without adding any', () => {
    const { payload } = rebuild(
      stored([
        { ...JWT, id: undefined },
        { ...API_KEY, id: undefined },
      ])
    );
    expect(payload.access_point.caller_authentication.methods.some((m: any) => 'id' in m)).toBe(
      false
    );
  });

  it('saves the id of a method without a stored one once an Identity names it', () => {
    const legacy = stored(
      [
        { ...JWT, id: undefined },
        { ...API_KEY, id: undefined },
      ],
      {
        inbound: { type: 'from_jwt_claim' },
      }
    );
    const nodes = registry.nodesFromPayload(legacy);
    const caller = nodes.find(n => n.type === 'caller-auth')!;
    const jwtId = caller.config.methods[0].id;
    inboundNode(nodes).config = { ...inboundNode(nodes).config, source_method: jwtId };
    const payload = registry.buildPayload(context(nodes));
    const methods = payload.access_point.caller_authentication.methods;
    expect(methods[0].id).toBe(jwtId);
    expect('id' in methods[1]).toBe(false);
    expect(payload.identity_slots.inbound_source_method).toBe(jwtId);
  });
});

describe('inbound identity source method — payload', () => {
  const selected = stored([JWT, API_KEY], {
    inbound: { type: 'from_jwt_claim', claim: 'oid' },
    inbound_source_method: 'users-jwt',
  });

  it('reads the selection into the inbound identity and writes it back', () => {
    const { nodes, payload } = rebuild(selected);
    expect(inboundNode(nodes).config.source_method).toBe('users-jwt');
    expect(payload.identity_slots.inbound_source_method).toBe('users-jwt');
    expect(payload.identity_slots.inbound.source_method).toBeUndefined();
  });

  it('writes no selection when none is set', () => {
    const { payload } = rebuild(
      stored([JWT], { inbound: { type: 'from_jwt_claim', claim: 'oid' } })
    );
    expect(payload.identity_slots.inbound_source_method).toBeUndefined();
  });

  it('writes no selection for an identity that does not read the caller credential', () => {
    const { nodes } = rebuild(selected);
    const node = inboundNode(nodes);
    node.config = { ...node.config, type: 'from_payload', source_method: 'users-jwt' };
    const payload = registry.buildPayload(context(nodes));
    expect(payload.identity_slots.inbound_source_method).toBeUndefined();
  });

  it('writes the selection for an inbound From API Key identity', () => {
    const { payload } = rebuild(
      stored([JWT, API_KEY], {
        inbound: { type: 'from_api_key' },
        inbound_source_method: 'partner-key',
      })
    );
    expect(payload.identity_slots.inbound_source_method).toBe('partner-key');
  });

  it('keeps the selection and the method ids in a template', () => {
    const scrubbed: any = scrubVolatileTemplateFields(selected);
    expect(scrubbed.identity_slots.inbound_source_method).toBe('users-jwt');
    expect(scrubbed.access_point.caller_authentication.methods.map((m: any) => m.id)).toEqual([
      'users-jwt',
      'partner-key',
    ]);
  });
});

describe('inbound identity source method — rules', () => {
  it('accepts From JWT Claims beside an API key method once a JWT method is selected', () => {
    const { nodes } = rebuild(
      stored([JWT, API_KEY], {
        inbound: { type: 'from_jwt_claim' },
        inbound_source_method: 'users-jwt',
      })
    );
    expect(errors(nodes)).toEqual([]);
  });

  it('reads the first JWT method when none is named beside an API key method', () => {
    const { nodes, payload } = rebuild(
      stored([API_KEY, JWT], { inbound: { type: 'from_jwt_claim' } })
    );
    expect(errors(nodes)).toEqual([]);
    expect(payload.identity_slots.inbound_source_method).toBe('users-jwt');
  });

  it('reads any method, and names none, while every method is a JWT method', () => {
    const second = { ...JWT, id: 'other-jwt' };
    const { nodes, payload } = rebuild(
      stored([JWT, second], { inbound: { type: 'from_jwt_claim' } })
    );
    expect(errors(nodes)).toEqual([]);
    expect(payload.identity_slots.inbound_source_method).toBeUndefined();
  });

  it('refuses From JWT Claims beside API key methods only, and points at the select', () => {
    const second = { ...API_KEY, id: 'other-key' };
    const { nodes } = rebuild(stored([API_KEY, second], { inbound: { type: 'from_jwt_claim' } }));
    expect(errors(nodes)).toEqual([
      'From JWT Claims requires a Caller Context whose methods are all JWT Bearer. Remove the other methods, choose the Identity source method, or change this extraction type.',
    ]);
  });

  it('accepts inbound From API Key beside a JWT method once an API key method is selected', () => {
    const { nodes } = rebuild(
      stored([JWT, API_KEY], {
        inbound: { type: 'from_api_key' },
        inbound_source_method: 'partner-key',
      })
    );
    expect(errors(nodes)).toEqual([]);
  });

  it('refuses a selection of a method that was removed while several remain', () => {
    const { nodes } = rebuild(
      stored([JWT, API_KEY], {
        inbound: { type: 'from_jwt_claim' },
        inbound_source_method: 'gone',
      })
    );
    expect(errors(nodes)).toEqual([
      'The Caller Context method this Identity reads was removed. Select another method.',
    ]);
  });

  it('ignores a selection once one method is left', () => {
    const { nodes, payload } = rebuild(
      stored([JWT], {
        inbound: { type: 'from_jwt_claim' },
        inbound_source_method: 'gone',
      })
    );
    expect(errors(nodes)).toEqual([]);
    expect(payload.identity_slots.inbound_source_method).toBeUndefined();
  });

  it('lets the payload own the selection, so a stale canvas blob cannot bring it back', () => {
    const removed = {
      ...stored([JWT, API_KEY], { inbound: { type: 'from_jwt_claim' } }),
      canvas: {
        version: 1,
        nodes: [
          {
            id: 'identity-inbound',
            type: 'identity',
            config: { type: 'from_jwt_claim', source_method: 'users-jwt' },
          },
        ],
      },
    };
    const nodes = registry.nodesFromPayload(removed);
    expect(inboundNode(nodes).config.source_method).toBeUndefined();
  });

  it('refuses a selection of a method of the wrong type', () => {
    const { nodes } = rebuild(
      stored([JWT, API_KEY], {
        inbound: { type: 'from_jwt_claim' },
        inbound_source_method: 'partner-key',
      })
    );
    expect(errors(nodes)).toEqual([
      'From JWT Claims reads a JWT Bearer method. Select a JWT Bearer method.',
    ]);
  });
});
