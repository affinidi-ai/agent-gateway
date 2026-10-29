import {
  EMPTY_JWT_FIELDS,
  ProviderFormValues,
  jwtFieldsOf,
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
    expect(missingProviderField(jwtAuth)).toBeNull();
    expect(missingProviderField({ ...jwtAuth, jwt_certificate_secret_ref: '' })).toBe(
      'Certificate secret is required.'
    );
    expect(missingProviderField({ ...jwtAuth, client_id_secret_ref: '' })).toBe(
      'Client ID secret is required for OAuth providers.'
    );
    expect(missingProviderField(form({ client_secret_secret_ref: '' }))).toBe(
      'Client Secret secret is required for OAuth providers.'
    );
  });

  it('sends a JWT Bearer provider without client credentials', () => {
    expect(providerCredentialFields(jwtBearer)).toEqual({
      token_endpoint: 'https://oauth2.googleapis.com/token',
      client_secret_secret_ref: '',
      jwt_signing_key_secret_ref: 'SA_KEY',
      jwt_certificate_secret_ref: '',
      jwt_audience: '',
      jwt_key_id: 'kid-1',
      jwt_issuer: 'sa@project.iam.gserviceaccount.com',
      jwt_subject: '',
      jwt_signing_algorithm: undefined,
    });
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
});
