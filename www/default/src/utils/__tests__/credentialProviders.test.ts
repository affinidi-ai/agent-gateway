import {
  EMPTY_PROVIDER_FORM,
  PROVIDER_TYPES,
  buildProviderBody,
  filterProvidersForUse,
  keptProviderLabel,
  providerFormFromWire,
  providerPermits,
  providerSecretRefs,
  providersUsingSecret,
  providerTypeBadgeClass,
  providerTypeLabel,
  unknownProviderType,
  validateProviderForm,
  type CredentialProviderForm,
} from '../credentialProviders';

const jwtForm: CredentialProviderForm = {
  ...EMPTY_PROVIDER_FORM,
  name: 'Vertex',
  provider_id: 'vertex',
  provider_type: 'oauth2_jwt_bearer',
  token_endpoint: 'https://oauth2.googleapis.com/token',
  signing_key_secret_ref: 'sa-key',
  assertion_issuer: 'sa@project.iam',
  subject: 'sa@project.iam',
  key_id: 'abc',
  signing_algorithm: 'ES256',
  default_scopes: 'cloud-platform',
};

describe('provider type capabilities', () => {
  it('describes every provider type with a label and badge', () => {
    for (const t of PROVIDER_TYPES) {
      expect(providerTypeLabel(t)).not.toBe(t);
      expect(providerTypeBadgeClass(t)).toMatch(/^text-bg-/);
    }
    expect(PROVIDER_TYPES).toContain('oauth2_jwt_bearer');
  });

  it('rejects authorization_code for target authentication only', () => {
    expect(providerPermits('oauth2_authorization_code', 'target_authentication')).toBe(false);
    expect(providerPermits('oauth2_authorization_code', 'legacy_delegation')).toBe(true);
    for (const t of ['oauth2_client_credentials', 'oauth2_jwt_bearer', 'api_key']) {
      expect(providerPermits(t, 'target_authentication')).toBe(true);
    }
  });

  it('never permits an unknown provider type', () => {
    expect(providerPermits('future_type', 'target_authentication')).toBe(false);
    expect(providerTypeLabel('future_type')).toBe('future_type');
    expect(providerTypeBadgeClass('future_type')).toBe('text-bg-secondary');
  });

  it('filters a provider list by use', () => {
    const list = [
      { id: 'a', provider_type: 'oauth2_authorization_code' },
      { id: 'b', provider_type: 'oauth2_jwt_bearer' },
      { id: 'c', provider_type: 'api_key' },
      { id: 'd' },
    ];
    expect(filterProvidersForUse(list, 'target_authentication').map(p => p.id)).toEqual(['b', 'c']);
    expect(filterProvidersForUse(list, 'legacy_delegation').map(p => p.id)).toEqual([
      'a',
      'b',
      'c',
    ]);
  });
});

describe('keptProviderLabel', () => {
  const list = [{ id: 'a', name: 'Future', provider_type: 'future_type' }];

  it('names a saved provider that is no longer usable', () => {
    expect(keptProviderLabel(list, 'a')).toBe('Future (future_type, not usable here)');
  });

  it('falls back to the id for a provider that is not in the list', () => {
    expect(keptProviderLabel(list, 'gone')).toBe('gone (not in list)');
  });
});

describe('validateProviderForm', () => {
  it('accepts a complete JWT bearer provider without client refs', () => {
    expect(validateProviderForm(jwtForm)).toBeNull();
  });

  it('requires a signing key and an assertion issuer for JWT bearer', () => {
    expect(validateProviderForm({ ...jwtForm, signing_key_secret_ref: '' })).toBe(
      'Signing key secret is required.'
    );
    expect(validateProviderForm({ ...jwtForm, assertion_issuer: ' ' })).toBe(
      'Assertion issuer is required.'
    );
    expect(validateProviderForm({ ...jwtForm, token_endpoint: '' })).toBe(
      'Token endpoint is required for OAuth providers.'
    );
  });

  it('requires both or neither client refs for JWT bearer', () => {
    expect(validateProviderForm({ ...jwtForm, client_id_secret_ref: 'id' })).toBe(
      'Client Secret secret is required when a Client ID secret is set.'
    );
    expect(validateProviderForm({ ...jwtForm, client_secret_secret_ref: 'sec' })).toBe(
      'Client ID secret is required when a Client Secret secret is set.'
    );
    expect(
      validateProviderForm({
        ...jwtForm,
        client_id_secret_ref: 'id',
        client_secret_secret_ref: 'sec',
      })
    ).toBeNull();
  });

  it('keeps the existing OAuth and API key rules', () => {
    const cc = {
      ...EMPTY_PROVIDER_FORM,
      name: 'n',
      provider_id: 'p',
      provider_type: 'oauth2_client_credentials' as const,
      token_endpoint: 'https://t',
    };
    expect(validateProviderForm(cc)).toBe('Client ID secret is required for OAuth providers.');
    expect(validateProviderForm({ ...cc, provider_type: 'api_key', token_endpoint: '' })).toBe(
      'API Key secret is required.'
    );
    expect(validateProviderForm({ ...jwtForm, additional_params: '{bad' })).toBe(
      'Additional Parameters must be valid JSON.'
    );
  });
});

describe('buildProviderBody', () => {
  it('sends the JWT bearer fields and no client refs when none are set', () => {
    const body = buildProviderBody(jwtForm, null);
    expect(body).toMatchObject({
      provider_type: 'oauth2_jwt_bearer',
      token_endpoint: 'https://oauth2.googleapis.com/token',
      jwt_bearer: {
        signing_key_secret_ref: 'sa-key',
        signing_algorithm: 'ES256',
        assertion_issuer: 'sa@project.iam',
        assertion_subject: 'sa@project.iam',
        key_id: 'abc',
      },
      default_scopes: ['cloud-platform'],
    });
    expect(body).not.toHaveProperty('signing_key_secret_ref');
    expect(body).not.toHaveProperty('assertion_issuer');
    expect(body).not.toHaveProperty('client_id_secret_ref');
    expect(body).not.toHaveProperty('api_key_secret_ref');
    expect(body).not.toHaveProperty('callback_url');
  });

  it('omits an empty subject and key id and sends optional client refs when set', () => {
    const body = buildProviderBody(
      {
        ...jwtForm,
        subject: '',
        key_id: '',
        client_id_secret_ref: 'id',
        client_secret_secret_ref: 'sec',
      },
      null
    );
    expect(body.jwt_bearer).toEqual({
      signing_key_secret_ref: 'sa-key',
      signing_algorithm: 'ES256',
      assertion_issuer: 'sa@project.iam',
    });
    expect(body).toMatchObject({ client_id_secret_ref: 'id', client_secret_secret_ref: 'sec' });
  });

  it('builds the callback url only for authorization code providers', () => {
    const ac = {
      ...EMPTY_PROVIDER_FORM,
      name: 'gh',
      provider_id: 'gh',
      token_endpoint: 'https://t',
      client_id_secret_ref: 'a',
      client_secret_secret_ref: 'b',
      callback_host: 'https://gw.example.com',
    };
    expect(buildProviderBody(ac, '/oauth/callback')).toMatchObject({
      callback_url: 'https://gw.example.com/oauth/callback/gh',
    });
    expect(
      buildProviderBody({ ...ac, provider_type: 'oauth2_client_credentials' }, '/oauth/callback')
    ).not.toHaveProperty('callback_url');
  });

  it('sends the API key reference for api_key providers only', () => {
    const body = buildProviderBody(
      {
        ...EMPTY_PROVIDER_FORM,
        name: 'k',
        provider_id: 'k',
        provider_type: 'api_key',
        api_key_secret_ref: 'key',
      },
      null
    );
    expect(body).toMatchObject({ api_key_secret_ref: 'key' });
    expect(body).not.toHaveProperty('token_endpoint');
    expect(body).not.toHaveProperty('client_id_secret_ref');
  });
});

describe('providerFormFromWire', () => {
  it('hydrates the JWT bearer fields', () => {
    const form = providerFormFromWire(
      {
        name: 'Vertex',
        provider_id: 'vertex',
        provider_type: 'oauth2_jwt_bearer',
        token_endpoint: 'https://t',
        jwt_bearer: {
          signing_key_secret_ref: 'sa-key',
          signing_algorithm: 'ES256',
          assertion_issuer: 'iss',
          assertion_subject: 'sub',
          key_id: 'kid',
        },
        default_scopes: ['a', 'b'],
      },
      ''
    );
    expect(form).toMatchObject({
      provider_type: 'oauth2_jwt_bearer',
      signing_key_secret_ref: 'sa-key',
      signing_algorithm: 'ES256',
      assertion_issuer: 'iss',
      subject: 'sub',
      key_id: 'kid',
      default_scopes: 'a, b',
    });
  });

  it('round-trips a JWT bearer provider through the request body', () => {
    const body = buildProviderBody(jwtForm, null);
    expect(providerFormFromWire(body, '')).toMatchObject({
      ...jwtForm,
      token_refresh_enabled: true,
    });
  });
});

describe('updating an existing provider', () => {
  it('sends the selected type in the PUT body so a type change is saved', () => {
    expect(buildProviderBody(jwtForm, null, false).provider_type).toBe('oauth2_jwt_bearer');
    expect(
      buildProviderBody(
        { ...jwtForm, provider_type: 'api_key', api_key_secret_ref: 'k' },
        null,
        false
      ).provider_type
    ).toBe('api_key');
    expect(buildProviderBody(jwtForm, null, true).provider_type).toBe('oauth2_jwt_bearer');
  });

  it('sends null to clear the optional JWT bearer client references', () => {
    const body = buildProviderBody(jwtForm, null, false);
    expect(body.client_id_secret_ref).toBeNull();
    expect(body.client_secret_secret_ref).toBeNull();
  });

  it('keeps the client references when they are set', () => {
    const body = buildProviderBody(
      { ...jwtForm, client_id_secret_ref: 'id', client_secret_secret_ref: 'sec' },
      null,
      false
    );
    expect(body).toMatchObject({ client_id_secret_ref: 'id', client_secret_secret_ref: 'sec' });
  });

  it('reports a provider type the dashboard does not know', () => {
    expect(unknownProviderType({ provider_type: 'future_type' })).toBe('future_type');
    expect(unknownProviderType({ provider_type: 'api_key' })).toBeNull();
    expect(unknownProviderType({})).toBeNull();
  });
});

describe('providerSecretRefs', () => {
  it('lists every secret reference a provider holds', () => {
    expect(
      providerSecretRefs({
        client_id_secret_ref: 'id',
        client_secret_secret_ref: 'secret',
        api_key_secret_ref: 'key',
        jwt_bearer: { signing_key_secret_ref: 'signing' },
      })
    ).toEqual(['id', 'secret', 'key', 'signing']);
  });

  it('skips empty and missing references', () => {
    expect(providerSecretRefs({ client_id_secret_ref: '', jwt_bearer: {} })).toEqual([]);
    expect(providerSecretRefs({ name: 'No refs', client_secret_secret_ref: null })).toEqual([]);
  });
});

describe('providersUsingSecret', () => {
  const json = (body: unknown, ok = true) =>
    Promise.resolve({ ok, status: ok ? 200 : 500, json: async () => body } as Response);

  const stored: Record<string, unknown> = {
    a: { client_secret_secret_ref: 'shared' },
    b: { jwt_bearer: { signing_key_secret_ref: 'shared' } },
    c: { api_key_secret_ref: 'other' },
  };

  const fetcher = (failOn?: string) =>
    jest.fn((url: string) => {
      if (url === '/api/v1/credential-providers') {
        return json(['a', 'b', 'c'].map(id => ({ id, name: `Provider ${id}` })));
      }
      const id = decodeURIComponent(url.split('/').pop() ?? '');
      return id === failOn ? json({}, false) : json(stored[id]);
    });

  it('names the providers that reference the secret', async () => {
    expect(await providersUsingSecret(fetcher(), 'shared')).toEqual({
      ok: true,
      names: ['Provider a', 'Provider b'],
    });
  });

  it('returns no names for a secret nothing references', async () => {
    expect(await providersUsingSecret(fetcher(), 'unused')).toEqual({ ok: true, names: [] });
  });

  it('is not ok when the list or one provider cannot be read', async () => {
    expect(await providersUsingSecret(() => json([], false), 'shared')).toEqual({ ok: false });
    expect(await providersUsingSecret(fetcher('b'), 'shared')).toEqual({ ok: false });
    expect(
      await providersUsingSecret(() => Promise.reject(new Error('offline')), 'shared')
    ).toEqual({
      ok: false,
    });
  });
});
