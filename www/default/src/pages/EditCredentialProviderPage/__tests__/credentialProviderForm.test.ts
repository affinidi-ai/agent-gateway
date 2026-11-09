import {
  EMPTY_JWT_FIELDS,
  callbackUrlFor,
  callbackUrlToSave,
  isHttpsAddress,
  ProviderFormValues,
  entraRejectsResource,
  clientAuthenticationOf,
  jwtFieldsOf,
  jwtKeyUnidentified,
  missingProviderField,
  providerCredentialFields,
  providerTypeFields,
} from '../credentialProviderForm';

function form(values: Partial<ProviderFormValues>): ProviderFormValues {
  return {
    provider_type: 'oauth2_client_credentials',
    token_endpoint: 'https://login.example/token',
    client_id_secret_ref: 'CLIENT_ID',
    client_secret_secret_ref: 'CLIENT_SECRET',
    api_key_secret_ref: '',
    client_authentication: '',
    ...EMPTY_JWT_FIELDS,
    ...values,
  };
}

const jwtBearer = form({
  provider_type: 'oauth2_jwt_bearer',
  token_endpoint: 'https://oauth2.googleapis.com/token',
  client_id_secret_ref: '',
  client_secret_secret_ref: '',
  jwt_issuer: ' sa@project.iam.gserviceaccount.com ',
  jwt_signing_key_secret_ref: 'SA_KEY',
  jwt_key_id: 'kid-1',
  jwt_subject: 'user@example.com',
});

const jwtAuth = form({
  provider_type: 'oauth2_client_credentials_jwt_auth',
  client_secret_secret_ref: 'LEFT_OVER_SECRET',
  jwt_signing_key_secret_ref: 'CERT_KEY',
  jwt_certificate_secret_ref: 'CERT',
  jwt_signing_algorithm: 'RS256',
  jwt_issuer: 'not-used',
});

describe('credential provider form', () => {
  it('shows the client secret only for client-secret types and the JWT section only for JWT types', () => {
    expect(providerTypeFields('oauth2_client_credentials')).toMatchObject({
      clientSecret: true,
      jwt: false,
    });
    expect(providerTypeFields('oauth2_jwt_bearer')).toMatchObject({
      clientId: false,
      clientSecret: false,
      jwt: true,
      jwtIssuer: true,
      jwtCertificate: false,
    });
    expect(providerTypeFields('oauth2_jwt_bearer', 'none')).toMatchObject({
      clientId: true,
      clientSecret: false,
    });
    expect(providerTypeFields('oauth2_jwt_bearer', 'client_secret_basic')).toMatchObject({
      clientId: true,
      clientSecret: true,
    });
    expect(providerTypeFields('oauth2_jwt_bearer', 'client_secret_post')).toMatchObject({
      clientId: true,
      clientSecret: true,
    });
    expect(providerTypeFields('oauth2_client_credentials', 'none')).toMatchObject({
      clientId: true,
      clientSecret: true,
    });
    expect(providerTypeFields('oauth2_client_credentials_jwt_auth')).toMatchObject({
      clientId: true,
      clientSecret: false,
      jwt: true,
      jwtIssuer: false,
      jwtCertificate: true,
    });
  });

  it('names the first missing required field of each type', () => {
    expect(missingProviderField(jwtBearer)).toBeNull();
    expect(missingProviderField({ ...jwtBearer, jwt_issuer: ' ' })).toBe(
      'Issuer is required for JWT Bearer providers.'
    );
    expect(missingProviderField({ ...jwtBearer, jwt_signing_key_secret_ref: '' })).toBe(
      'Signing key secret is required.'
    );
    expect(missingProviderField({ ...jwtBearer, jwt_subject: ' ' })).toBe(
      'Subject is required for JWT Bearer providers.'
    );
    expect(missingProviderField({ ...jwtBearer, jwt_subject: 'user@example.com' })).toBeNull();
    expect(missingProviderField(jwtAuth)).toBeNull();
    expect(missingProviderField({ ...jwtAuth, jwt_certificate_secret_ref: '' })).toBeNull();
    expect(missingProviderField({ ...jwtAuth, client_id_secret_ref: '' })).toBe(
      'Client ID secret is required for OAuth providers.'
    );
    expect(missingProviderField(form({ client_secret_secret_ref: '' }))).toBe(
      'Client Secret secret is required for OAuth providers.'
    );
  });

  it('requires the client references the chosen client authentication needs', () => {
    const withClient = (values: Partial<ProviderFormValues>) =>
      missingProviderField({ ...jwtBearer, ...values });
    expect(withClient({ client_authentication: 'none' })).toBe(
      'Client ID secret is required for OAuth providers.'
    );
    expect(
      withClient({ client_authentication: 'none', client_id_secret_ref: 'HYDRA_ID' })
    ).toBeNull();
    for (const method of ['client_secret_basic', 'client_secret_post'] as const) {
      expect(withClient({ client_authentication: method, client_id_secret_ref: 'HYDRA_ID' })).toBe(
        'Client Secret secret is required for OAuth providers.'
      );
      expect(withClient({ client_authentication: method })).toBe(
        'Client ID secret is required for OAuth providers.'
      );
      expect(
        withClient({
          client_authentication: method,
          client_id_secret_ref: 'HYDRA_ID',
          client_secret_secret_ref: 'HYDRA_SECRET',
        })
      ).toBeNull();
    }
    expect(withClient({ client_id_secret_ref: '', client_secret_secret_ref: '' })).toBeNull();
  });

  it('sends a JWT Bearer provider with an empty client ID reference when no method is chosen', () => {
    expect(
      providerCredentialFields({
        ...jwtBearer,
        client_id_secret_ref: 'IGNORED',
        client_secret_secret_ref: 'IGNORED',
      })
    ).toEqual({
      token_endpoint: 'https://oauth2.googleapis.com/token',
      client_authentication: '',
      client_id_secret_ref: '',
      client_secret_secret_ref: '',
      jwt_signing_key_secret_ref: 'SA_KEY',
      jwt_certificate_secret_ref: '',
      jwt_audience: '',
      jwt_key_id: 'kid-1',
      jwt_issuer: 'sa@project.iam.gserviceaccount.com',
      jwt_subject: 'user@example.com',
      jwt_signing_algorithm: undefined,
    });
  });

  it('sends the client references each JWT Bearer client authentication uses', () => {
    const refs = { client_id_secret_ref: 'HYDRA_ID', client_secret_secret_ref: 'HYDRA_SECRET' };
    expect(
      providerCredentialFields({ ...jwtBearer, ...refs, client_authentication: 'none' })
    ).toMatchObject({
      client_authentication: 'none',
      client_id_secret_ref: 'HYDRA_ID',
      client_secret_secret_ref: '',
    });
    for (const method of ['client_secret_basic', 'client_secret_post'] as const) {
      expect(
        providerCredentialFields({ ...jwtBearer, ...refs, client_authentication: method })
      ).toMatchObject({
        client_authentication: method,
        client_id_secret_ref: 'HYDRA_ID',
        client_secret_secret_ref: 'HYDRA_SECRET',
      });
    }
  });

  it('sends the client ID reference of a method that shows its picker, and omits it for other types without one', () => {
    expect(
      providerCredentialFields({
        ...jwtBearer,
        client_authentication: 'none',
        client_id_secret_ref: 'HYDRA_ID',
      }).client_id_secret_ref
    ).toBe('HYDRA_ID');
    expect(providerCredentialFields(form({ provider_type: 'api_key' }))).not.toHaveProperty(
      'client_id_secret_ref'
    );
  });

  it('sends an empty client authentication for every other provider type', () => {
    expect(
      providerCredentialFields(form({ client_authentication: 'client_secret_basic' }))
    ).toMatchObject({
      client_authentication: '',
      client_id_secret_ref: 'CLIENT_ID',
      client_secret_secret_ref: 'CLIENT_SECRET',
    });
    expect(providerCredentialFields(form({ provider_type: 'api_key' }))).toMatchObject({
      client_authentication: '',
    });
    expect(providerCredentialFields(jwtAuth)).toMatchObject({ client_authentication: '' });
  });

  it('clears the client secret and issuer of a Client Credentials JWT provider', () => {
    expect(providerCredentialFields(jwtAuth)).toMatchObject({
      client_id_secret_ref: 'CLIENT_ID',
      client_secret_secret_ref: '',
      jwt_certificate_secret_ref: 'CERT',
      jwt_issuer: '',
      jwt_signing_algorithm: 'RS256',
    });
  });

  it('flags a signed JWT that names its key by neither certificate nor key ID', () => {
    const unidentified = (values: Partial<ProviderFormValues>) =>
      jwtKeyUnidentified({ ...jwtAuth, ...values });
    expect(unidentified({ jwt_certificate_secret_ref: 'CERT', jwt_key_id: '' })).toBe(false);
    expect(unidentified({ jwt_certificate_secret_ref: '', jwt_key_id: 'key1' })).toBe(false);
    expect(unidentified({ jwt_certificate_secret_ref: '', jwt_key_id: ' ' })).toBe(true);
    expect(jwtKeyUnidentified({ ...jwtBearer, jwt_key_id: '' })).toBe(true);
    expect(jwtKeyUnidentified(jwtBearer)).toBe(false);
    expect(jwtKeyUnidentified(form({}))).toBe(false);
  });

  it('flags a resource sent to a Microsoft identity platform v2.0 token endpoint', () => {
    const v2 = 'https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token';
    expect(entraRejectsResource(v2, 'https://ai.azure.com')).toBe(true);
    expect(entraRejectsResource(v2, ' ')).toBe(false);
    expect(entraRejectsResource(v2, null)).toBe(false);
    expect(entraRejectsResource(v2, undefined)).toBe(false);
    expect(
      entraRejectsResource(
        'https://login.microsoftonline.com/tenant-id/oauth2/token',
        'https://ai.azure.com'
      )
    ).toBe(false);
    expect(entraRejectsResource('https://oauth2.googleapis.com/token', 'https://api.example')).toBe(
      false
    );
    expect(
      entraRejectsResource(
        'https://LOGIN.MicrosoftOnline.US/tenant-id/oauth2/v2.0/token',
        'https://ai.azure.us'
      )
    ).toBe(true);
    expect(entraRejectsResource('not a url', 'https://ai.azure.com')).toBe(false);
  });

  it('drops a signing algorithm the selected type does not support', () => {
    expect(
      providerCredentialFields({ ...jwtAuth, jwt_signing_algorithm: 'ES256' }).jwt_signing_algorithm
    ).toBeUndefined();
    expect(
      providerCredentialFields({ ...jwtAuth, jwt_signing_algorithm: 'RS256' }).jwt_signing_algorithm
    ).toBe('RS256');
  });

  it('clears the JWT settings of a client-secret provider', () => {
    const fields = providerCredentialFields(
      form({ jwt_signing_key_secret_ref: 'OLD_KEY', jwt_issuer: 'old' })
    );
    expect(fields).toMatchObject({
      client_secret_secret_ref: 'CLIENT_SECRET',
      jwt_signing_key_secret_ref: '',
      jwt_issuer: '',
      jwt_signing_algorithm: undefined,
    });
  });

  it('loads the JWT settings of a stored provider and drops an unknown algorithm', () => {
    expect(
      jwtFieldsOf({
        jwt_signing_key_secret_ref: 'SA_KEY',
        jwt_signing_algorithm: 'ES256',
        jwt_issuer: 'sa@example',
      })
    ).toEqual({
      ...EMPTY_JWT_FIELDS,
      jwt_signing_key_secret_ref: 'SA_KEY',
      jwt_signing_algorithm: 'ES256',
      jwt_issuer: 'sa@example',
    });
    expect(jwtFieldsOf({ jwt_signing_algorithm: 'HS256' }).jwt_signing_algorithm).toBe('');
  });

  it('loads the client authentication of a stored provider and drops an unknown value', () => {
    expect(clientAuthenticationOf({ client_authentication: 'client_secret_post' })).toBe(
      'client_secret_post'
    );
    expect(clientAuthenticationOf({ client_authentication: 'none' })).toBe('none');
    expect(clientAuthenticationOf({ client_authentication: 'private_key_jwt' })).toBe('');
    expect(clientAuthenticationOf({})).toBe('');
  });
});

describe('isHttpsAddress', () => {
  it('accepts only an https address', () => {
    expect(isHttpsAddress('https://gw.example')).toBe(true);
    expect(isHttpsAddress('http://gw.example')).toBe(false);
    expect(isHttpsAddress('gw.example')).toBe(false);
    expect(isHttpsAddress('')).toBe(false);
  });
});

describe('callbackUrlFor', () => {
  it('keeps the stored callback path of an existing provider', () => {
    expect(callbackUrlFor('https://gw.example', '/old/route/github')).toBe(
      'https://gw.example/old/route/github'
    );
  });

  it('has no URL for a provider not yet created, whose path the gateway builds from its id', () => {
    expect(callbackUrlFor('https://gw.example', '')).toBe('');
  });
});

describe('callbackUrlToSave', () => {
  const stored = 'https://gw.example/prefix/v1/identity/oauth/callback/github';

  it('keeps a stored callback URL, reverse proxy prefix included, while its host is unchanged', () => {
    expect(
      callbackUrlToSave({
        storedUrl: stored,
        host: 'https://gw.example',
        storedPath: '/v1/identity/oauth/callback/github',
      })
    ).toBe(stored);
  });

  it('builds the URL from the stored path once the operator picks another host', () => {
    expect(
      callbackUrlToSave({
        storedUrl: stored,
        host: 'https://other.example',
        storedPath: '/v1/identity/oauth/callback/github',
      })
    ).toBe('https://other.example/v1/identity/oauth/callback/github');
  });

  it('rebuilds a stored callback URL whose path does not end in the stored callback path', () => {
    expect(
      callbackUrlToSave({
        storedUrl: 'https://gw.example/v1/identity/oauth/callback/GitHub',
        host: 'https://gw.example',
        storedPath: '/v1/identity/oauth/callback/github',
      })
    ).toBe('https://gw.example/v1/identity/oauth/callback/github');
  });

  it('rebuilds a stored callback URL that is not https', () => {
    expect(
      callbackUrlToSave({
        storedUrl: 'http://gw.example/prefix/v1/identity/oauth/callback/github',
        host: 'http://gw.example',
        storedPath: '/v1/identity/oauth/callback/github',
      })
    ).toBe('http://gw.example/v1/identity/oauth/callback/github');
  });

  it('keeps a stored callback URL when the listen address is written with its default port', () => {
    expect(
      callbackUrlToSave({
        storedUrl: stored,
        host: 'https://GW.example:443/',
        storedPath: '/v1/identity/oauth/callback/github',
      })
    ).toBe(stored);
  });

  it('has no URL when nothing is stored', () => {
    expect(
      callbackUrlToSave({
        storedUrl: '',
        host: 'https://gw.example',
        storedPath: '',
      })
    ).toBe('');
  });
});
