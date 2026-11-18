import { registry } from '../index';
import { buildCanvasBlob } from '../registry';
import { managedAgentDefinition } from '../managed-agent/definition';
import {
  headerFormatProblem,
  headerNameProblem,
  RESERVED_HEADERS,
  isHttpsTarget,
  mergeTargetAuth,
  MA_CALLER_CHECK_PROBLEM,
  PASSTHROUGH_NOTE,
  TARGET_AUTH_HTTPS_PROBLEM,
  UNKNOWN_METHOD_NOTE,
  targetAuthHeader,
} from '../_shared/providerTargetAuth';
import {
  managedAgentTargetAuth,
  managedAgentTargetAuthProblems,
} from '../managed-agent/targetAuth';
import {
  makeCtx,
  maConfig,
  providerAuth,
  roundTrip,
  staticSecret,
  unknownMethodAuth,
} from '../testing/targetAuthFixtures';

describe('header and endpoint rules', () => {
  it.each([
    ['Authorization', null],
    ['X-Api-Key', null],
    ['X Api', 'Header name must be an HTTP header name'],
    ['', 'Header name must be an HTTP header name'],
    ['host', 'Header name must not be the reserved header Host'],
    ['TE', 'Header name must not be the reserved header TE'],
    ['Proxy-Connection', 'Header name must not be the reserved header Proxy-Connection'],
  ])('header name %p', (name, problem) => {
    expect(headerNameProblem(name)).toBe(problem);
  });

  it.each([
    ['{value}', null],
    ['Bearer {value}', null],
    ['Bearer', 'Header format must contain {value} exactly once'],
    ['{value}{value}', 'Header format must contain {value} exactly once'],
    ['Bearer {value}\r', 'Header format must not contain CR, LF or NUL'],
    ['{value}\nX: 1', 'Header format must not contain CR, LF or NUL'],
    ['{value}\0', 'Header format must not contain CR, LF or NUL'],
  ])('header format %p', (format, problem) => {
    expect(headerFormatProblem(format)).toBe(problem);
  });

  it('counts only an https URL with a host as https', () => {
    expect(isHttpsTarget('https://api.example.com/v1')).toBe(true);
    for (const endpoint of ['http://a.example', 'fabric://g/s', 'a2a-proxy://p', 'proxy://m', '']) {
      expect(isHttpsTarget(endpoint)).toBe(false);
    }
  });
});

describe('reserved header names', () => {
  it('lists the 23 names the gateway reserves', () => {
    expect(RESERVED_HEADERS).toHaveLength(23);
    expect(RESERVED_HEADERS).toEqual(
      expect.arrayContaining([
        'Proxy-Authorization',
        'X-Transit-Token',
        'Mcp-Session-Id',
        'Trailers',
      ])
    );
  });

  it.each(RESERVED_HEADERS)('refuses %s in any case and passes a prefixed twin', name => {
    expect(headerNameProblem(name)).toBe(`Header name must not be the reserved header ${name}`);
    expect(headerNameProblem(name.toLowerCase())).toBe(
      `Header name must not be the reserved header ${name}`
    );
    expect(headerNameProblem(`X-Partner-${name}`)).toBeNull();
  });
});

describe('Managed Agent Target authentication validation', () => {
  it('passes a valid setting', () => {
    expect(managedAgentTargetAuthProblems(maConfig())).toEqual({
      errors: {},
      advisories: [],
      notes: [],
    });
  });

  it('blocks a header name that is not a token or is reserved, and passes its twin', () => {
    expect(
      managedAgentTargetAuthProblems(maConfig({ target_auth_header_name: 'Host' })).errors
    ).toEqual({ target_auth_header_name: 'Header name must not be the reserved header Host' });
    expect(
      managedAgentTargetAuthProblems(maConfig({ target_auth_header_name: 'X Key' })).errors
    ).toEqual({ target_auth_header_name: 'Header name must be an HTTP header name' });
    expect(
      managedAgentTargetAuthProblems(maConfig({ target_auth_header_name: 'X-Host' })).errors
    ).toEqual({});
  });

  it('blocks a format without exactly one {value} or with CR, LF or NUL, and passes its twin', () => {
    expect(
      managedAgentTargetAuthProblems(maConfig({ target_auth_header_format: 'Bearer' })).errors
    ).toEqual({ target_auth_header_format: 'Header format must contain {value} exactly once' });
    expect(
      managedAgentTargetAuthProblems(maConfig({ target_auth_header_format: '{value}\r\nX: 1' }))
        .errors
    ).toEqual({ target_auth_header_format: 'Header format must not contain CR, LF or NUL' });
    expect(
      managedAgentTargetAuthProblems(maConfig({ target_auth_header_format: 'Token {value}' }))
        .errors
    ).toEqual({});
  });

  it('advises, without blocking, on a Managed Agent credential for a Target that is not https, and passes its twin', () => {
    for (const endpoint of ['http://agent.example.com', 'fabric://g/s', 'a2a-proxy://p']) {
      const problems = managedAgentTargetAuthProblems(maConfig({ endpoint }));
      expect(problems.errors).toEqual({});
      expect(problems.advisories).toEqual([TARGET_AUTH_HTTPS_PROBLEM]);
    }
    const https = managedAgentTargetAuthProblems(
      maConfig({ endpoint: 'https://agent.example.com' })
    );
    expect(https.errors).toEqual({});
    expect(https.advisories).toEqual([]);
  });

  it('blocks a credential provider method without a provider, and passes its twin', () => {
    const provider = maConfig({ target_auth_source: 'provider', target_auth_provider_id: '' });
    expect(Object.keys(managedAgentTargetAuthProblems(provider).errors)).toEqual([
      'target_auth_provider_id',
    ]);
    expect(
      managedAgentTargetAuthProblems({ ...provider, target_auth_provider_id: 'prov-1' }).errors
    ).toEqual({});
  });

  it('does not block Save through the element validation for a Target that is not https, and blocks a reserved header', () => {
    expect(registry.getValidationErrors('target', maConfig({ endpoint: 'http://a.test' }))).toEqual(
      []
    );
    expect(
      registry.getValidationErrors(
        'target',
        maConfig({ endpoint: 'http://a.test', target_auth_header_name: 'Host' })
      )
    ).toContainEqual({
      field: 'target_auth_header_name',
      message: 'Header name must not be the reserved header Host',
    });
  });

  it('blocks a stored header problem the operator did not edit, as the gateway refuses it on every save', () => {
    const config: any = managedAgentDefinition.configFromPayload!(
      { endpoint: 'http://agent.example.com', auth: staticSecret('Host', 'Bearer') },
      {}
    );
    const problems = managedAgentTargetAuthProblems(config);
    expect(problems.errors).toEqual({
      target_auth_header_name: 'Header name must not be the reserved header Host',
      target_auth_header_format: 'Header format must contain {value} exactly once',
    });
    expect(problems.advisories).toEqual([TARGET_AUTH_HTTPS_PROBLEM]);
    expect(registry.getValidationErrors('target', config)).toHaveLength(2);

    const fixed = managedAgentTargetAuthProblems({
      ...config,
      target_auth_header_name: 'X-Api-Key',
      target_auth_header_format: '{value}',
    });
    expect(fixed.errors).toEqual({});
  });

  it('blocks a stored line break at the end of a provider header name or format, and drops typed spaces', () => {
    const config: any = managedAgentDefinition.configFromPayload!(
      {
        endpoint: 'https://agent.example.com',
        auth: {
          method: {
            credential_provider: {
              provider_id: 'prov-1',
              header_name: 'X-Partner-Token\r\n',
              header_format: 'Token {value}\n',
            },
          },
          fallback: 'reject',
        },
      },
      {}
    );
    expect(managedAgentTargetAuthProblems(config).errors).toEqual({
      target_auth_header_name: 'Header name must be an HTTP header name',
      target_auth_header_format: 'Header format must not contain CR, LF or NUL',
    });
    expect(targetAuthHeader(managedAgentTargetAuth(config))).toEqual({
      headerName: 'X-Partner-Token\r\n',
      headerFormat: 'Token {value}\n',
    });

    const typed = {
      ...config,
      target_auth_header_name: ' X-Partner-Token ',
      target_auth_header_format: '\tToken {value} ',
    };
    expect(managedAgentTargetAuthProblems(typed).errors).toEqual({});
    expect(targetAuthHeader(managedAgentTargetAuth(typed))).toEqual({
      headerName: 'X-Partner-Token',
      headerFormat: 'Token {value}',
    });
  });
});

describe('lossless Target authentication save', () => {
  const apiSurface: any = {
    name: 'lossless',
    protocol: 'a2a',
    access_point: { route: '/lossless', listen_address: '0.0.0.0:8443', protocol: 'a2a' },
    target: { endpoint: 'https://agent.example.com', auth: providerAuth },
    transit: {
      points: [
        {
          id: 'tp-1',
          alias: 'partner',
          protocol: 'a2a',
          target_endpoint: 'https://partner.example.com',
          require_transit_token: true,
          target_auth: {
            ...staticSecret('X-Partner', 'Token {value}'),
            target_identifier: 'partner',
            future_field: 1,
          },
        },
      ],
    },
  };

  it('saves a loaded surface without edits with equal Target authentication', () => {
    const saved = roundTrip(apiSurface);
    expect(saved.target.auth).toEqual(apiSurface.target.auth);
    expect(saved.transit.points[0].target_auth).toEqual(apiSurface.transit.points[0].target_auth);
  });

  it('merges an edited field onto the stored one and keeps the fields the editor does not show', () => {
    const saved = roundTrip(apiSurface, nodes => {
      nodes.find(n => n.type === 'target').config.target_auth_header_name = 'X-Other';
      const point = nodes.find(n => n.type === 'transit-point-a2a').config;
      point.auth_type = 'custom_header';
      point.auth_secret = 's';
      point.auth_header_name = 'X-Changed';
      point.auth_header_format = 'Token {value}';
      point.auth_fallback = 'reject';
    });
    expect(saved.target.auth).toEqual({
      ...apiSurface.target.auth,
      method: {
        credential_provider: {
          ...apiSurface.target.auth.method.credential_provider,
          header_name: 'X-Other',
        },
      },
    });
    expect(saved.transit.points[0].target_auth.target_identifier).toBe('partner');
    expect(saved.transit.points[0].target_auth.future_field).toBe(1);
    expect(saved.transit.points[0].target_auth.method.static_secret.header_name).toBe('X-Changed');
  });

  it('writes and clears the scopes of a credential provider method', () => {
    const set = roundTrip(apiSurface, nodes => {
      nodes.find(n => n.type === 'target').config.target_auth_scopes = ' a  b ';
    });
    expect(set.target.auth.method.credential_provider.scopes).toEqual(['a', 'b']);
    const cleared = roundTrip(apiSurface, nodes => {
      nodes.find(n => n.type === 'target').config.target_auth_scopes = '';
    });
    expect(cleared.target.auth.method.credential_provider).not.toHaveProperty('scopes');
  });

  it('replaces the stored method when the kind changes and drops the auth when none is set', () => {
    expect(mergeTargetAuth(providerAuth, staticSecret('X', '{value}')).method).toEqual(
      staticSecret('X', '{value}').method
    );
    const none = roundTrip(apiSurface, nodes => {
      nodes.find(n => n.type === 'target').config.target_auth_enabled = false;
      nodes.find(n => n.type === 'transit-point-a2a').config.auth_type = 'none';
    });
    expect(none.target.auth).toBeUndefined();
    expect(none.transit.points[0].target_auth).toBeUndefined();
  });

  it('does not bring back a Target credential that the stored surface no longer has', () => {
    const first = roundTrip(apiSurface, nodes => {
      nodes.find(n => n.type === 'target').config.target_auth_header_name = 'X-Edited';
      const point = nodes.find(n => n.type === 'transit-point-a2a').config;
      point.auth_type = 'custom_header';
      point.auth_secret = 's';
      point.auth_header_name = 'X-Changed';
      point.auth_header_format = 'Token {value}';
      point.auth_fallback = 'reject';
    });
    expect(first.target.auth).toBeDefined();

    const blob = buildCanvasBlob(registry.nodesFromPayload(first).map(n => ({ ...n })));
    expect(blob.nodes.length).toBeGreaterThan(0);
    const moved = {
      ...first,
      canvas: blob,
      target: { ...first.target, endpoint: 'https://new-party.example.com', auth: undefined },
      transit: {
        points: first.transit.points.map((point: any) => ({
          ...point,
          target_endpoint: 'https://new-partner.example.com',
          target_auth: undefined,
        })),
      },
    };
    const saved = registry.buildPayload(makeCtx(registry.nodesFromPayload(moved))) as any;
    expect(saved.target.auth).toBeUndefined();
    expect(saved.transit.points[0].target_auth).toBeUndefined();
  });

  it('keeps the stored Target authentication copy out of the canvas blob', () => {
    const nodes = registry.nodesFromPayload(apiSurface);
    const hasCopy = nodes.some(n => n.config && '_stored_target_auth' in n.config);
    expect(hasCopy).toBe(true);
    const blob = buildCanvasBlob(nodes.map(n => ({ ...n })));
    for (const node of blob.nodes) {
      expect(node.config ?? {}).not.toHaveProperty('_stored_target_auth');
    }
  });
});

describe('header names as the gateway compares them', () => {
  it('refuses a reserved name written with underscores or another letter case', () => {
    expect(headerNameProblem('X_Transit_Token')).toBe(
      'Header name must not be the reserved header X-Transit-Token'
    );
    expect(headerNameProblem('x_caller_did')).toBe(
      'Header name must not be the reserved header X-Caller-Did'
    );
  });

  it('allows an underscore name that is not reserved', () => {
    expect(headerNameProblem('x_api_key')).toBeNull();
  });
});

describe('Managed Agent Target authentication advice', () => {
  it('advises when the Access Point checks no caller, and not when it does or is not known', () => {
    const problems = (accessPointChecksCallers?: boolean) =>
      managedAgentTargetAuthProblems(maConfig(), { accessPointChecksCallers });
    expect(problems(false).advisories).toEqual([MA_CALLER_CHECK_PROBLEM]);
    expect(problems(false).errors).toEqual({});
    expect(problems(true).advisories).toEqual([]);
    expect(problems().advisories).toEqual([]);
  });

  it('notes a passthrough fallback without blocking the save', () => {
    const passthrough = managedAgentTargetAuthProblems(
      maConfig({ target_auth_fallback: 'passthrough' })
    );
    expect(passthrough.notes).toEqual([PASSTHROUGH_NOTE]);
    expect(passthrough.errors).toEqual({});
    expect(managedAgentTargetAuthProblems(maConfig()).notes).toEqual([]);
  });

  it('gives no https advisory for a proxy:// Target, whose MCP proxy decides it', () => {
    expect(
      managedAgentTargetAuthProblems(maConfig({ endpoint: 'proxy://docs' })).advisories
    ).toEqual([]);
    expect(
      managedAgentTargetAuthProblems(maConfig({ endpoint: 'http://agent' })).advisories
    ).toEqual([TARGET_AUTH_HTTPS_PROBLEM]);
  });
});

describe('a stored Target authentication method the editor cannot show', () => {
  const surface: any = {
    name: 'unknown-method',
    protocol: 'a2a',
    access_point: { route: '/unknown', listen_address: '0.0.0.0:8443', protocol: 'a2a' },
    target: { endpoint: 'https://agent.example.com', auth: unknownMethodAuth },
  };

  it('is saved unchanged on the Managed Agent and noted', () => {
    expect(roundTrip(surface).target.auth).toEqual(unknownMethodAuth);
    const config = registry.nodesFromPayload(surface).find(n => n.type === 'target')?.config;
    expect(managedAgentTargetAuthProblems(config).notes).toEqual([UNKNOWN_METHOD_NOTE]);
  });

  it('is replaced once the operator chooses a secret, and removed when turned off', () => {
    const chosen = roundTrip(surface, nodes => {
      Object.assign(nodes.find(n => n.type === 'target').config, {
        target_auth_source: 'secret',
        target_auth_secret_id: 's',
        target_auth_type: 'custom',
        target_auth_header_name: 'X-Api-Key',
        target_auth_header_format: '{value}',
      });
    });
    expect(chosen.target.auth.method).toEqual(staticSecret('X-Api-Key', '{value}').method);
    const off = roundTrip(surface, nodes => {
      nodes.find(n => n.type === 'target').config.target_auth_enabled = false;
    });
    expect(off.target.auth).toBeUndefined();
  });

  it('sends nothing for a new setting with no secret chosen', () => {
    expect(managedAgentTargetAuth({ target_auth_enabled: true })).toBeUndefined();
  });
});

describe('unseen fields and a changed credential', () => {
  const provider = (providerId: string) => ({
    method: {
      credential_provider: {
        provider_id: providerId,
        header_name: 'Authorization',
        header_format: 'Bearer {value}',
      },
    },
    fallback: 'reject',
  });

  it('keeps unseen fields while the provider stays the same', () => {
    const merged = mergeTargetAuth(providerAuth, provider('prov-1')) as any;
    expect(merged.future_field).toEqual({ keep: true });
    expect(merged.method.credential_provider.scopes).toEqual(['read', 'write']);
  });

  it('drops unseen fields and stored scopes when another provider is picked', () => {
    const merged = mergeTargetAuth(providerAuth, provider('prov-2')) as any;
    expect(merged).toEqual(provider('prov-2'));
  });

  it('drops unseen fields when another secret is picked', () => {
    const stored = { ...staticSecret('X-Api-Key', '{value}'), future_field: 1 };
    const edited = {
      method: {
        static_secret: { secret_id: 'other', header_name: 'X-Api-Key', header_format: '{value}' },
      },
      fallback: 'reject',
    };
    expect(mergeTargetAuth(stored, edited)).toEqual(edited);
  });
});

describe('Target authentication and the canvas data', () => {
  const surface: any = {
    name: 'canvas',
    protocol: 'a2a',
    access_point: { route: '/canvas', listen_address: '0.0.0.0:8443', protocol: 'a2a' },
    target: { endpoint: 'https://agent.example.com', auth: providerAuth },
    transit: {
      points: [
        {
          id: 'tp-1',
          alias: 'partner',
          protocol: 'a2a',
          target_endpoint: 'https://partner.example.com',
          require_transit_token: true,
          target_auth: staticSecret('X-Auth', '{value}'),
        },
      ],
    },
  };
  const authKey =
    /^(target_auth|_stored_target_auth|auth_(type|secret|provider_id|scopes|fallback|header_name|header_format))/;

  it('writes no Target authentication key to the canvas data', () => {
    const nodes = registry.nodesFromPayload(surface);
    Object.assign(nodes.find(n => n.type === 'transit-point-a2a')!.config, {
      auth_type: 'custom_header',
      auth_secret: 's',
      auth_header_name: 'X-Auth',
      auth_header_format: '{value}',
    });
    const blob = buildCanvasBlob(nodes.map(n => ({ ...n })));
    const keys = blob.nodes.flatMap(node => Object.keys(node.config ?? {}));
    expect(keys.length).toBeGreaterThan(0);
    expect(keys.filter(key => authKey.test(key))).toEqual([]);
  });

  it('restores a Transit Point the stored surface no longer has without a Target authentication', () => {
    const blob = buildCanvasBlob(registry.nodesFromPayload(surface).map(n => ({ ...n })));
    const point = blob.nodes.find(node => node.type === 'transit-point-a2a')!;
    point.config = {
      ...point.config,
      auth_type: 'custom_header',
      auth_secret: 's',
      auth_header_name: 'X-Auth',
      auth_header_format: '{value}',
      target_auth: staticSecret('X-Auth', '{value}'),
    };
    const withoutPoint = { ...surface, canvas: blob, transit: { points: [] } };
    const restored = registry
      .nodesFromPayload(withoutPoint)
      .filter(n => n.type === 'transit-point-a2a');
    for (const node of restored) {
      expect(Object.keys(node.config ?? {}).filter(key => authKey.test(key))).toEqual([]);
    }
    const saved = registry.buildPayload(makeCtx(registry.nodesFromPayload(withoutPoint))) as any;
    for (const saved_point of saved.transit?.points ?? []) {
      expect(saved_point.target_auth).toBeUndefined();
    }
  });
});
