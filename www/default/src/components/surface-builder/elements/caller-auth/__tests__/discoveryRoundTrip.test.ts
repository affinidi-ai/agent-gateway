import { registry } from '../../index';
import type { CanvasNode, PayloadContext } from '../../types';
import { computeOverridesFromPayload, resolveVariant } from '../../../variants/resolve';

const SETTING = {
  resource: 'https://gateway.example/mcp/alpha',
  authorization_servers: ['https://idp.example/realms/agents'],
  scopes: ['tools'],
};

const METHOD = {
  type: 'jwt_bearer',
  jwt_verification_strategy_id: 'idp',
  audiences: [],
  token_header: 'Authorization',
  token_scheme: 'Bearer',
  forward_header: false,
};

function stored(callerAuthentication: Record<string, unknown>, canvas?: unknown) {
  return {
    name: 'discovery',
    status: 'active',
    tags: [],
    access_point: {
      listen_address: 'https://gateway.example',
      route: '/mcp/alpha',
      protocol: 'mcp',
      caller_authentication: callerAuthentication,
    },
    target: { endpoint: 'https://tools.example/mcp' },
    ...(canvas ? { canvas } : {}),
  };
}

function context(nodes: CanvasNode[]): PayloadContext {
  return {
    protocol: 'mcp',
    surfaceMeta: { name: 'discovery', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: type => nodes.filter(n => n.type === type),
    firstNodeOfType: type => nodes.find(n => n.type === type),
  };
}

const callerAuthNode = (nodes: CanvasNode[]) => nodes.find(n => n.type === 'caller-auth');

/** Load a stored surface onto the canvas and build the payload a save sends. */
function rebuild(payload: unknown) {
  const nodes = registry.nodesFromPayload(payload);
  return { nodes, payload: registry.buildPayload(context(nodes)) };
}

describe('authorization server discovery round-trip', () => {
  it('loads a stored setting onto the caller-auth node and saves it unchanged', () => {
    const surface = stored({ methods: [METHOD], protected_resource: SETTING });
    const { nodes, payload } = rebuild(surface);

    expect(callerAuthNode(nodes)?.config.protected_resource).toEqual(SETTING);
    expect(payload.access_point.caller_authentication).toEqual({
      methods: [METHOD],
      protected_resource: SETTING,
    });
    expect(rebuild(payload).payload.access_point.caller_authentication).toEqual(
      surface.access_point.caller_authentication
    );
  });

  it('saves a setting without scopes without inventing any', () => {
    const setting = {
      resource: SETTING.resource,
      authorization_servers: SETTING.authorization_servers,
    };
    const { payload } = rebuild(stored({ methods: [METHOD], protected_resource: setting }));
    expect(payload.access_point.caller_authentication.protected_resource).toEqual(setting);
  });

  it('does not bring back a setting from a stale canvas copy once the surface has none', () => {
    const canvas = {
      version: 1,
      nodes: [
        {
          id: 'caller-auth',
          type: 'caller-auth',
          parentId: 'access-point',
          config: {
            method_type: 'jwt_bearer',
            jwt_strategy_id: 'idp',
            protected_resource: SETTING,
          },
        },
      ],
    };
    const { nodes, payload } = rebuild(stored({ methods: [METHOD] }, canvas));

    expect(callerAuthNode(nodes)?.config.protected_resource).toBeNull();
    expect(payload.access_point.caller_authentication).toEqual({ methods: [METHOD] });
  });

  it('sends no setting for a method other than JWT Bearer', () => {
    const node: CanvasNode = {
      id: 'caller-auth',
      type: 'caller-auth',
      label: '',
      configured: true,
      parentId: 'access-point',
      config: { method_type: 'did_auth', protected_resource: SETTING },
    };
    const payload = registry.buildPayload(context([node]));
    expect(payload.access_point.caller_authentication).toEqual({
      methods: [{ type: 'did_auth', extraction: { source: 'http_header' } }],
    });
  });

  it('keeps each variant’s own setting, or its absence, through the variant snapshot', () => {
    const base = stored({ methods: [METHOD], protected_resource: SETTING });
    const ownSetting = { ...SETTING, scopes: ['beta'] };
    const withOwn = rebuild(stored({ methods: [METHOD], protected_resource: ownSetting })).payload;
    const withNone = rebuild(stored({ methods: [METHOD] })).payload;

    const ownOverrides = computeOverridesFromPayload(withOwn);
    expect(ownOverrides.access_point?.caller_authentication).toEqual({
      methods: [METHOD],
      protected_resource: ownSetting,
    });
    expect(
      resolveVariant(base, ownOverrides).access_point.caller_authentication.protected_resource
    ).toEqual(ownSetting);
    expect(
      resolveVariant(base, computeOverridesFromPayload(withNone)).access_point.caller_authentication
    ).toEqual({ methods: [METHOD] });
  });
});
