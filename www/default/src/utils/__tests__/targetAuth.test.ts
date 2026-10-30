import {
  buildCredentialProviderAuth,
  credentialProviderAuthError,
  hasPreservedTargetAuth,
  injectionHeaderName,
  parseScopes,
  parseTargetAuth,
} from '../targetAuth';

describe('parseTargetAuth', () => {
  it('parses a static_secret method', () => {
    expect(
      parseTargetAuth({
        method: {
          static_secret: { secret_id: 's1', header_name: 'X-Key', header_format: '{value}' },
        },
        auth_type: 'api_key',
        fallback: 'passthrough',
      })
    ).toEqual({
      kind: 'static_secret',
      secretId: 's1',
      headerName: 'X-Key',
      headerFormat: '{value}',
      authType: 'api_key',
      fallback: 'passthrough',
    });
  });

  it('parses a credential_provider method with defaults', () => {
    expect(
      parseTargetAuth({ method: { credential_provider: { credential_provider_id: 'cp1' } } })
    ).toEqual({
      kind: 'credential_provider',
      credentialProviderId: 'cp1',
      scopes: [],
      injectAs: { type: 'bearer_header' },
      fallback: 'reject',
    });
  });

  it('parses scopes and a custom header injection', () => {
    expect(
      parseTargetAuth({
        method: {
          credential_provider: {
            credential_provider_id: 'cp1',
            scopes: ['a', 'b'],
            inject_as: { type: 'custom_header', name: 'X-Token', format: 'tok {value}' },
          },
        },
        fallback: 'passthrough',
      })
    ).toEqual({
      kind: 'credential_provider',
      credentialProviderId: 'cp1',
      scopes: ['a', 'b'],
      injectAs: { type: 'custom_header', name: 'X-Token', format: 'tok {value}' },
      fallback: 'passthrough',
    });
  });

  it('keeps an unknown variant verbatim as unsupported', () => {
    const raw = { method: { future_method: { x: 1 } }, fallback: 'reject' };
    expect(parseTargetAuth(raw)).toEqual({ kind: 'unsupported', raw });
  });

  it('keeps a credential_provider method with an unknown injection type as unsupported', () => {
    const raw = {
      method: {
        credential_provider: {
          credential_provider_id: 'cp1',
          inject_as: { type: 'meta', field: 'x' },
        },
      },
      fallback: 'reject',
    };
    expect(parseTargetAuth(raw)).toEqual({ kind: 'unsupported', raw });
  });

  it('keeps a credential_provider method with fields the form does not model as unsupported', () => {
    const extraProviderKey = {
      method: { credential_provider: { credential_provider_id: 'cp1', audience: 'a' } },
    };
    expect(parseTargetAuth(extraProviderKey)).toEqual({
      kind: 'unsupported',
      raw: extraProviderKey,
    });
    const extraInjectKey = {
      method: {
        credential_provider: {
          credential_provider_id: 'cp1',
          inject_as: { type: 'custom_header', name: 'X', format: '{value}', extra: 1 },
        },
      },
    };
    expect(parseTargetAuth(extraInjectKey)).toEqual({ kind: 'unsupported', raw: extraInjectKey });
    const badScopes = {
      method: { credential_provider: { credential_provider_id: 'cp1', scopes: ['a', 3] } },
    };
    expect(parseTargetAuth(badScopes)).toEqual({ kind: 'unsupported', raw: badScopes });
  });

  it('treats the credential_lookup string method as unsupported', () => {
    const raw = { method: 'credential_lookup', target_identifier: 't', fallback: 'reject' };
    expect(parseTargetAuth(raw)).toEqual({ kind: 'unsupported', raw });
  });

  it('returns null for a missing or non-object value', () => {
    expect(parseTargetAuth(undefined)).toBeNull();
    expect(parseTargetAuth('x')).toBeNull();
    expect(parseTargetAuth([])).toBeNull();
  });
});

describe('buildCredentialProviderAuth', () => {
  it('round-trips through parseTargetAuth', () => {
    const fields = {
      credentialProviderId: 'cp1',
      scopes: ['s1'],
      injectAs: { type: 'custom_header' as const, name: 'X-T', format: '{value}' },
      fallback: 'passthrough' as const,
    };
    expect(parseTargetAuth(buildCredentialProviderAuth(fields))).toEqual({
      kind: 'credential_provider',
      ...fields,
    });
  });

  it('omits empty scopes so the provider default scopes apply', () => {
    const wire = buildCredentialProviderAuth({
      credentialProviderId: 'cp1',
      scopes: [],
      injectAs: { type: 'bearer_header' },
      fallback: 'reject',
    });
    expect(wire).toEqual({
      method: {
        credential_provider: {
          credential_provider_id: 'cp1',
          inject_as: { type: 'bearer_header' },
        },
      },
      fallback: 'reject',
    });
  });
});

describe('credentialProviderAuthError', () => {
  const ok = {
    credentialProviderId: 'cp1',
    scopes: [],
    injectAs: { type: 'bearer_header' as const },
    fallback: 'reject' as const,
  };

  it('accepts a complete bearer configuration', () => {
    expect(credentialProviderAuthError(ok)).toBeNull();
  });

  it('requires a provider', () => {
    expect(credentialProviderAuthError({ ...ok, credentialProviderId: ' ' })).toBe(
      'Select a credential provider.'
    );
  });

  it('requires a header name and a {value} placeholder for a custom header', () => {
    const custom = (name: string, format: string) => ({
      ...ok,
      injectAs: { type: 'custom_header' as const, name, format },
    });
    expect(credentialProviderAuthError(custom('', '{value}'))).toBe('Enter the header name.');
    expect(credentialProviderAuthError(custom('X-T', 'nope'))).toBe(
      'The header format must contain {value}.'
    );
    expect(credentialProviderAuthError(custom('X-T', 'tok {value}'))).toBeNull();
  });

  it.each(['Host', 'content-length', 'Transfer-Encoding', ' CONNECTION '])(
    'rejects %s as a custom header name',
    name => {
      expect(
        credentialProviderAuthError({
          ...ok,
          injectAs: { type: 'custom_header', name, format: '{value}' },
        })
      ).toBe(`${name.trim()} cannot be used as the header name.`);
    }
  );
});

describe('helpers', () => {
  it('splits and de-duplicates scopes', () => {
    expect(parseScopes('a, b  a,c')).toEqual(['a', 'b', 'c']);
    expect(parseScopes('')).toEqual([]);
  });

  it('names the injected header', () => {
    expect(injectionHeaderName({ type: 'bearer_header' })).toBe('Authorization');
    expect(injectionHeaderName({ type: 'custom_header', name: ' X-T ', format: '{value}' })).toBe(
      'X-T'
    );
  });
});

describe('hasPreservedTargetAuth', () => {
  const cp = { method: { credential_provider: { credential_provider_id: 'cp1' } } };
  const ss = {
    method: { static_secret: { secret_id: 's', header_name: 'h', header_format: 'f' } },
  };

  it('preserves variants the form cannot edit while the operator has not picked a type', () => {
    expect(hasPreservedTargetAuth({ target_auth: cp })).toBe(true);
    expect(hasPreservedTargetAuth({ target_auth: { method: { future: {} } } })).toBe(true);
  });

  it('does not preserve once a type is picked, or for static secrets and no auth', () => {
    expect(hasPreservedTargetAuth({ target_auth: cp, auth_type: 'none' })).toBe(false);
    expect(hasPreservedTargetAuth({ target_auth: cp, auth_type: 'bearer' })).toBe(false);
    expect(hasPreservedTargetAuth({ target_auth: ss })).toBe(false);
    expect(hasPreservedTargetAuth({})).toBe(false);
  });
});
