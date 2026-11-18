import { registry } from '../index';
import {
  PASSTHROUGH_NOTE,
  TARGET_AUTH_HTTPS_PROBLEM,
  TP_CALLER_CHECK_PROBLEM,
  UNKNOWN_METHOD_NOTE,
  storedTargetAuth,
} from '../_shared/providerTargetAuth';
import {
  staticSecretAuthType,
  transitPointTargetAuth,
  transitPointTargetAuthProblems,
} from '../transit-point/targetAuth';
import {
  providerAuth,
  roundTrip,
  staticSecret,
  unknownMethodAuth,
} from '../testing/targetAuthFixtures';

describe('Transit Point auth type of a stored static secret', () => {
  it('reads a Bearer format as bearer only under the Authorization header', () => {
    expect(staticSecretAuthType('Authorization', 'Bearer {value}')).toBe('bearer');
    expect(staticSecretAuthType('authorization', 'Bearer {value}')).toBe('custom_header');
    expect(staticSecretAuthType('X-Partner', 'Bearer {value}')).toBe('custom_header');
  });

  it('keeps the api key and custom header readings', () => {
    expect(staticSecretAuthType('X-API-Key', '{value}')).toBe('api_key');
    expect(staticSecretAuthType('X-Auth', 'Token {value}')).toBe('custom_header');
  });
});

describe('Transit Point Target authentication validation', () => {
  const tp = (over: Record<string, unknown> = {}) => ({
    target_endpoint: 'https://partner.example.com',
    auth_type: 'custom_header',
    auth_secret: 's',
    auth_header_name: 'X-Auth',
    auth_header_format: '{value}',
    ...over,
  });

  it('passes a valid setting', () => {
    expect(transitPointTargetAuthProblems(tp())).toEqual({
      errors: {},
      advisories: [],
      notes: [],
    });
  });

  it('blocks a bad header name and a bad format, and only advises on a Target that is not https', () => {
    expect(transitPointTargetAuthProblems(tp({ auth_header_name: 'Upgrade' })).errors).toEqual({
      auth_header_name: 'Header name must not be the reserved header Upgrade',
    });
    expect(transitPointTargetAuthProblems(tp({ auth_header_format: 'x' })).errors).toEqual({
      auth_header_format: 'Header format must contain {value} exactly once',
    });
    const fabric = transitPointTargetAuthProblems(tp({ target_endpoint: 'fabric://g/s' }));
    expect(fabric.errors).toEqual({});
    expect(fabric.advisories).toEqual([TARGET_AUTH_HTTPS_PROBLEM]);
  });

  it('advises, without blocking, on a Target credential on a Transit Point that checks no caller, and passes its twin', () => {
    const open = transitPointTargetAuthProblems(
      tp({ require_transit_token: false, allow_unauthenticated_callers: true })
    );
    expect(open.errors).toEqual({});
    expect(open.advisories).toEqual([TP_CALLER_CHECK_PROBLEM]);
    expect(
      transitPointTargetAuthProblems(
        tp({ require_transit_token: false, source_auth: { type: 'api_key' } })
      ).advisories
    ).toEqual([]);
  });

  it('blocks Save through the element validation', () => {
    expect(
      registry.getValidationErrors('transit-point-a2a', tp({ auth_header_name: 'Host' }))
    ).toContainEqual({
      field: 'auth_header_name',
      message: 'Header name must not be the reserved header Host',
    });
  });

  it('blocks a stored Transit Point header problem the operator did not edit', () => {
    const auth = staticSecret('Host', '{value}');
    const config = {
      target_endpoint: 'http://partner.example.com',
      _stored_target_auth: storedTargetAuth(auth),
      target_auth: auth,
    };
    expect(transitPointTargetAuthProblems(config)).toEqual({
      errors: { auth_header_name: 'Header name must not be the reserved header Host' },
      advisories: [TARGET_AUTH_HTTPS_PROBLEM],
      notes: [],
    });
  });

  it('advises on a proxy:// target endpoint, which the gateway exempts only on the Managed Agent', () => {
    expect(
      transitPointTargetAuthProblems(tp({ target_endpoint: 'proxy://docs' })).advisories
    ).toEqual([TARGET_AUTH_HTTPS_PROBLEM]);
  });
});

describe('Transit Point scopes', () => {
  const provider = (over: Record<string, unknown> = {}) => ({
    target_endpoint: 'https://partner.example.com',
    auth_type: 'credential_provider',
    auth_provider_id: 'prov-1',
    auth_header_name: 'Authorization',
    auth_header_format: 'Bearer {value}',
    auth_fallback: 'passthrough',
    _stored_target_auth: storedTargetAuth(providerAuth),
    ...over,
  });
  const scopes = (config: Record<string, unknown>) =>
    (transitPointTargetAuth(config) as any).method.credential_provider.scopes;

  it('writes the scopes the operator types', () => {
    expect(scopes(provider({ auth_scopes: ' a  b ' }))).toEqual(['a', 'b']);
  });

  it('clears stored scopes when the input is empty', () => {
    const auth = transitPointTargetAuth(provider({ auth_scopes: '' })) as any;
    expect(auth.method.credential_provider).not.toHaveProperty('scopes');
    expect(auth.future_field).toEqual({ keep: true });
  });

  it('keeps stored scopes while the form holds no scopes field', () => {
    expect(scopes(provider())).toEqual(['read', 'write']);
  });

  it('does not carry stored scopes to another provider', () => {
    const auth = transitPointTargetAuth(provider({ auth_provider_id: 'prov-2' })) as any;
    expect(auth.method.credential_provider).not.toHaveProperty('scopes');
    expect(auth).not.toHaveProperty('future_field');
  });
});

describe('a stored Transit Point method the panel cannot show', () => {
  const surface: any = {
    name: 'unknown-method',
    protocol: 'a2a',
    access_point: { route: '/unknown', listen_address: '0.0.0.0:8443', protocol: 'a2a' },
    target: { endpoint: 'https://agent.example.com' },
    transit: {
      points: [
        {
          id: 'tp-1',
          alias: 'partner',
          protocol: 'a2a',
          target_endpoint: 'https://partner.example.com',
          require_transit_token: true,
          target_auth: unknownMethodAuth,
        },
      ],
    },
  };

  it('is saved unchanged and noted', () => {
    expect(roundTrip(surface).transit.points[0].target_auth).toEqual(unknownMethodAuth);
    expect(
      transitPointTargetAuthProblems({
        target_endpoint: 'https://partner.example.com',
        _stored_target_auth: storedTargetAuth(unknownMethodAuth),
      }).notes
    ).toEqual([UNKNOWN_METHOD_NOTE]);
  });

  it('is replaced once the operator chooses a type', () => {
    const saved = roundTrip(surface, nodes => {
      Object.assign(nodes.find(n => n.type === 'transit-point-a2a').config, {
        auth_type: 'custom_header',
        auth_secret: 's',
        auth_header_name: 'X-Auth',
        auth_header_format: '{value}',
      });
    });
    expect(saved.transit.points[0].target_auth.method).toEqual({
      static_secret: { secret_id: 's', header_name: 'X-Auth', header_format: '{value}' },
    });
  });
});

describe('Transit Point Target authentication advice', () => {
  it('notes a passthrough fallback without blocking the save', () => {
    const problems = transitPointTargetAuthProblems({
      target_endpoint: 'https://partner.example.com',
      auth_type: 'custom_header',
      auth_secret: 's',
      auth_header_name: 'X-Auth',
      auth_header_format: '{value}',
      auth_fallback: 'passthrough',
    });
    expect(problems.notes).toEqual([PASSTHROUGH_NOTE]);
    expect(problems.errors).toEqual({});
  });
});
