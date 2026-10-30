import { registry } from '../index';
import type { CanvasNode, PayloadContext, Protocol, SurfaceContext } from '../types';

const def = registry.get('caller-auth')!;

const sliceFor = (config: Record<string, unknown>) => {
  const node: CanvasNode = {
    id: 'caller-auth',
    type: 'caller-auth',
    label: '',
    configured: true,
    config,
  };
  const slices = def.buildPayload!({
    firstNodeOfType: (t: string) => (t === 'caller-auth' ? node : undefined),
    surfaceMeta: {},
  } as unknown as PayloadContext);
  return (slices as Array<{ value: Record<string, any> }>)[0].value;
};

const methodFor = (config: Record<string, unknown>) => sliceFor(config).methods[0];

const BASE = {
  method_type: 'jwt_bearer',
  jwt_strategy_id: 's1',
  audiences: ['https://gw.example.com/a'],
};

const SETTING = { resource: 'https://gw.example.com/mcp' };

describe('caller-auth required_scopes round trip', () => {
  it('writes required_scopes on the jwt_bearer method', () => {
    expect(
      methodFor({ ...BASE, required_scopes: ['agent:invoke', 'read'] }).required_scopes
    ).toEqual(['agent:invoke', 'read']);
  });

  it('omits the field when no scope is required', () => {
    expect(methodFor({ ...BASE, required_scopes: [] })).not.toHaveProperty('required_scopes');
    expect(methodFor(BASE)).not.toHaveProperty('required_scopes');
  });

  it('sends no required scopes for a method other than JWT Bearer', () => {
    expect(
      methodFor({ method_type: 'did_auth', required_scopes: ['agent:invoke'] })
    ).not.toHaveProperty('required_scopes');
  });

  it('hydrates the scopes from a saved surface and writes them back unchanged', () => {
    const wire = {
      methods: [
        {
          type: 'jwt_bearer',
          jwt_verification_strategy_id: 's1',
          audiences: ['https://gw.example.com/a'],
          token_header: 'Authorization',
          token_scheme: 'Bearer',
          forward_header: false,
          required_scopes: ['agent:invoke'],
        },
      ],
    };
    const config = def.configFromPayload!(wire, {}) as Record<string, unknown>;
    expect(config.required_scopes).toEqual(['agent:invoke']);
    expect(sliceFor(config)).toEqual(wire);
  });

  it('keeps required_scopes and protected_resource side by side in one slice', () => {
    const wire = {
      methods: [
        {
          type: 'jwt_bearer',
          jwt_verification_strategy_id: 's1',
          audiences: [],
          token_header: 'Authorization',
          token_scheme: 'Bearer',
          forward_header: false,
          required_scopes: ['tools.call'],
        },
      ],
      protected_resource: SETTING,
    };
    const config = def.configFromPayload!(wire, {}) as Record<string, unknown>;
    expect(config.required_scopes).toEqual(['tools.call']);
    expect(config.protected_resource).toStrictEqual(SETTING);
    expect(sliceFor(config)).toStrictEqual(wire);
  });
});

describe('caller-auth required_scopes checks', () => {
  it('reports nothing for valid scopes or for a method other than JWT Bearer', () => {
    expect(def.validate!({ ...BASE, required_scopes: ['agent:invoke'] })).toEqual([]);
    expect(def.validate!({ method_type: 'did_auth', required_scopes: ['a b'] })).toEqual([]);
  });

  it('reports scopes the gateway refuses under required_scopes', () => {
    expect(def.validate!({ ...BASE, required_scopes: ['read', 'read'] })).toEqual([
      { field: 'required_scopes', message: 'read is already required.' },
    ]);
    expect(def.validate!({ ...BASE, required_scopes: ['a b'] })).toEqual([
      {
        field: 'required_scopes',
        message: 'A scope cannot contain spaces, double quotes or backslashes.',
      },
    ]);
  });
});

describe('caller-auth authorization server discovery dependencies', () => {
  const DISCOVERY = {
    method_type: 'jwt_bearer',
    jwt_strategy_id: 's1',
    audiences: [],
    protected_resource: SETTING,
  };
  const warningsOn = (config: Record<string, unknown>, protocol: Protocol, route = '/mcp') => {
    const context: SurfaceContext = {
      protocol,
      accessPoint: { route },
      target: {},
      transitPoints: [],
      allNodes: [],
    };
    return registry.getDependencyWarnings('caller-auth', config, context);
  };

  it.each<Protocol>(['a2a', 'ap2', 'mcp'])('lets a %s Access Point publish it', protocol => {
    expect(warningsOn(DISCOVERY, protocol)).toEqual([]);
  });

  it('refuses it on a DIDComm Access Point and off the Access Point route', () => {
    expect(warningsOn(DISCOVERY, 'didcomm')).toEqual([
      {
        severity: 'error',
        message: 'Authorization server discovery requires an A2A, AP2 or MCP Access Point',
      },
    ]);
    expect(warningsOn(DISCOVERY, 'a2a', '/agents')).toEqual([
      {
        severity: 'error',
        message: "The resource URL's path must be the Access Point route exactly",
      },
    ]);
  });

  it('has nothing to check while it is off', () => {
    expect(warningsOn({ ...DISCOVERY, protected_resource: null }, 'didcomm')).toEqual([]);
  });
});
