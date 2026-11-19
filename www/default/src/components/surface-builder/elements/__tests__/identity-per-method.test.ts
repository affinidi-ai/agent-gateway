import { registry } from '../index';
import { buildSurfaceContext } from '../surfaceContext';
import type { CanvasNode, PayloadContext } from '../types';
import { scrubVolatileTemplateFields } from '../../templates/scrubVolatile';
import { defaultMethodConfig } from '../caller-auth/methods';
import {
  INBOUND_API_KEY_NEEDS_API_KEY_CALLER,
  INBOUND_JWT_CLAIM_NEEDS_JWT_CALLER,
  METHOD_IDENTITY_BESIDE_PAYLOAD,
} from '../identity/definition';

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

const JWT_IDENTITY = { type: 'from_jwt_claim', claim: 'oid' };
const KEY_IDENTITY = { type: 'from_api_key' };

const callerMethods = (nodes: CanvasNode[]) =>
  nodes.find(n => n.type === 'caller-auth')!.config.methods;

describe('caller authentication method ids', () => {
  it('keeps each stored method id through a load and a save', () => {
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
    const ids = (nodes: CanvasNode[]) => callerMethods(nodes).map((m: any) => m.id);
    const first = ids(registry.nodesFromPayload(legacy));
    expect(first).toHaveLength(2);
    expect(first.every((id: unknown) => /^[a-z0-9-]{1,32}$/.test(String(id)))).toBe(true);
    expect(new Set(first).size).toBe(2);
    expect(ids(registry.nodesFromPayload(legacy))).toEqual(first);
  });

  it('saves a surface stored without ids without adding any, identities included', () => {
    const { payload } = rebuild(
      stored([
        { ...JWT, id: undefined, identity: JWT_IDENTITY },
        { ...API_KEY, id: undefined, identity: KEY_IDENTITY },
      ])
    );
    expect(payload.access_point.caller_authentication.methods.some((m: any) => 'id' in m)).toBe(
      false
    );
  });
});

describe('caller identity per method — payload', () => {
  const mixed = stored(
    [
      { ...JWT, identity: { ...JWT_IDENTITY, namespace_claims: ['iss'] } },
      { ...API_KEY, identity: KEY_IDENTITY },
    ],
    { inbound: { type: 'from_jwt_claim', claim: 'oid' } }
  );

  it('keeps each method identity through a load and a save', () => {
    const { payload } = rebuild(mixed);
    const methods = payload.access_point.caller_authentication.methods;
    expect(methods[0].identity).toEqual({
      type: 'from_jwt_claim',
      claim: 'oid',
      namespace_claims: ['iss'],
    });
    expect(methods[1].identity).toEqual({ type: 'from_api_key' });
  });

  it('writes no identity for a method that sets none', () => {
    const { payload } = rebuild(stored([JWT, API_KEY]));
    expect(
      payload.access_point.caller_authentication.methods.some((m: any) => 'identity' in m)
    ).toBe(false);
  });

  it('writes no identity its credential cannot supply', () => {
    const { nodes } = rebuild(stored([JWT, API_KEY]));
    const caller = nodes.find(n => n.type === 'caller-auth')!;
    caller.config = {
      ...caller.config,
      methods: [
        { ...caller.config.methods[0], identity: KEY_IDENTITY },
        { ...caller.config.methods[1], identity: JWT_IDENTITY },
      ],
    };
    const payload = registry.buildPayload(context(nodes));
    expect(
      payload.access_point.caller_authentication.methods.some((m: any) => 'identity' in m)
    ).toBe(false);
  });

  it('drops a method identity when the method changes type', () => {
    const method = callerMethods(registry.nodesFromPayload(mixed))[1];
    expect(defaultMethodConfig('jwt_bearer', method).identity).toBeUndefined();
  });

  it('lets the payload own the methods, so a stale canvas blob cannot bring an identity back', () => {
    const removed = {
      ...stored([JWT, API_KEY]),
      canvas: {
        version: 1,
        nodes: [
          {
            id: 'caller-auth',
            type: 'caller-auth',
            config: {
              methods: [
                { method_type: 'jwt_bearer', id: 'users-jwt', identity: JWT_IDENTITY },
                { method_type: 'api_key', id: 'partner-key', identity: KEY_IDENTITY },
              ],
            },
          },
        ],
      },
    };
    const methods = callerMethods(registry.nodesFromPayload(removed));
    expect(methods.some((m: any) => m.identity)).toBe(false);
  });

  it('keeps method ids and identities in a template', () => {
    const scrubbed: any = scrubVolatileTemplateFields(mixed);
    const methods = scrubbed.access_point.caller_authentication.methods;
    expect(methods.map((m: any) => m.id)).toEqual(['users-jwt', 'partner-key']);
    expect(methods.map((m: any) => m.identity.type)).toEqual(['from_jwt_claim', 'from_api_key']);
  });
});

describe('caller identity per method — rules', () => {
  it('accepts From JWT Claims beside an API key method, whose callers are refused', () => {
    const { nodes } = rebuild(stored([API_KEY, JWT], { inbound: { type: 'from_jwt_claim' } }));
    expect(errors(nodes)).toEqual([]);
  });

  it('refuses From JWT Claims with no JWT Bearer method to read', () => {
    const second = { ...API_KEY, id: 'other-key' };
    const { nodes } = rebuild(stored([API_KEY, second], { inbound: { type: 'from_jwt_claim' } }));
    expect(errors(nodes)).toEqual([INBOUND_JWT_CLAIM_NEEDS_JWT_CALLER]);
  });

  it('accepts From JWT Claims beside API key methods that identify their callers', () => {
    const { nodes } = rebuild(
      stored([{ ...API_KEY, identity: KEY_IDENTITY }], { inbound: { type: 'from_jwt_claim' } })
    );
    expect(errors(nodes)).toEqual([]);
  });

  it('refuses inbound From API Key with no API key method to read', () => {
    const { nodes } = rebuild(stored([JWT], { inbound: { type: 'from_api_key' } }));
    expect(errors(nodes)).toEqual([INBOUND_API_KEY_NEEDS_API_KEY_CALLER]);
  });

  it('accepts inbound From API Key beside a JWT method that identifies its callers', () => {
    const { nodes } = rebuild(
      stored([{ ...JWT, identity: JWT_IDENTITY }], { inbound: { type: 'from_api_key' } })
    );
    expect(errors(nodes)).toEqual([]);
  });

  it('refuses a method identity beside an inbound identity read from the payload', () => {
    const { nodes } = rebuild(
      stored([{ ...API_KEY, identity: KEY_IDENTITY }], {
        inbound: { type: 'payload_extraction', meta_field: 'agent', fields: ['id'] },
      })
    );
    expect(errors(nodes)).toEqual([METHOD_IDENTITY_BESIDE_PAYLOAD]);
  });
});
