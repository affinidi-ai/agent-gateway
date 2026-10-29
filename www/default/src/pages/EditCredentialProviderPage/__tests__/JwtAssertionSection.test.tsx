import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import JwtAssertionSection from '../JwtAssertionSection';
import { CredentialProviderType, EMPTY_JWT_FIELDS } from '../credentialProviderForm';

const renderSection = (providerType: CredentialProviderType) =>
  render(
    <MemoryRouter>
      <JwtAssertionSection
        providerType={providerType}
        form={EMPTY_JWT_FIELDS}
        secrets={[{ id: 's1', name: 'Service account key', secret_id: 'SA_KEY' }]}
        loadingSecrets={false}
        onChange={jest.fn()}
      />
    </MemoryRouter>
  );

const algorithms = () =>
  Array.from(
    (screen.getByTestId('credential-provider-jwt-algorithm-select') as HTMLSelectElement).options
  ).map(option => option.value);

describe('JwtAssertionSection', () => {
  it('asks a JWT Bearer provider for its issuer and key, offering RS256 first', () => {
    renderSection('oauth2_jwt_bearer');
    expect(screen.getByTestId('credential-provider-jwt-issuer-input')).toBeInTheDocument();
    expect(screen.getByTestId('credential-provider-jwt-subject-input')).toBeInTheDocument();
    expect(
      screen.getByTestId('credential-provider-jwt_signing_key_secret_ref-select')
    ).toBeInTheDocument();
    expect(
      screen.queryByTestId('credential-provider-jwt_certificate_secret_ref-select')
    ).not.toBeInTheDocument();
    expect(algorithms()).toEqual(['RS256', 'ES256']);
  });

  it('asks a Client Credentials JWT provider for its certificate, offering PS256 first', () => {
    renderSection('oauth2_client_credentials_jwt_auth');
    expect(
      screen.getByTestId('credential-provider-jwt_certificate_secret_ref-select')
    ).toBeInTheDocument();
    expect(screen.queryByTestId('credential-provider-jwt-issuer-input')).not.toBeInTheDocument();
    expect(algorithms()).toEqual(['PS256', 'RS256']);
  });

  it('renders nothing for a client-secret provider', () => {
    renderSection('oauth2_client_credentials');
    expect(screen.queryByTestId('credential-provider-jwt-section')).not.toBeInTheDocument();
  });
});
