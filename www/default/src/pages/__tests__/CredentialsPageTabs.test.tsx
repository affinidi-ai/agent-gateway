import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, useLocation } from 'react-router-dom';
import CredentialsPage from '../CredentialsPage';

let mockGranted = new Set<string>();
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => mockGranted.has(p), loading: false }),
}));
jest.mock('../SettingsPage/StrategiesTab', () => () => <div data-testid="strategies-tab" />);
jest.mock('../SettingsPage/CredentialProvidersTab', () => () => (
  <div data-testid="providers-tab" />
));
jest.mock('../CredentialsPage/CredentialTokensTab', () => () => <div data-testid="tokens-tab" />);
jest.mock('../CredentialsPage/CredentialAuditTab', () => () => <div data-testid="audit-tab" />);
jest.mock('../CredentialsPage/StsClientsTab', () => () => <div data-testid="sts-tab" />);

const Search = () => <div data-testid="search">{useLocation().search}</div>;

const visit = (path: string) =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <CredentialsPage />
      <Search />
    </MemoryRouter>
  );

afterEach(() => {
  mockGranted = new Set();
});

describe('CredentialsPage tab permissions', () => {
  it('opens on Credential Providers for credential_providers.view without settings.view', () => {
    mockGranted = new Set(['credential_providers.view']);
    visit('/credentials');

    expect(screen.getByTestId('credentials-credential-providers-tab-trigger')).toHaveAttribute(
      'aria-selected',
      'true'
    );
    expect(screen.getByTestId('providers-tab')).toBeInTheDocument();
    expect(screen.queryByTestId('credentials-jwt-verification-tab-trigger')).toBeNull();
  });

  it('opens on JWT Verification for settings.view', () => {
    mockGranted = new Set(['settings.view', 'credential_providers.view']);
    visit('/credentials');

    expect(screen.getByTestId('credentials-jwt-verification-tab-trigger')).toHaveAttribute(
      'aria-selected',
      'true'
    );
  });

  it('leaves the Credential Providers tab for a user without credential_providers.view', () => {
    mockGranted = new Set(['settings.view']);
    visit('/credentials?tab=credential-providers');

    expect(screen.queryByTestId('credentials-credential-providers-tab-trigger')).toBeNull();
    expect(screen.queryByTestId('providers-tab')).toBeNull();
    expect(screen.getByTestId('search')).toHaveTextContent('?tab=jwt-verification');
  });
});
