import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import { apiClient } from '../../api';
import CredentialsPage from '../CredentialsPage';
import {
  HOUR,
  answer,
  delegation,
  fromNow,
  requests,
  vaultReads,
} from '../CredentialsPage/vaultTestFixtures';

jest.mock('../../api', () => ({
  apiClient: { fetch: jest.fn() },
}));
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: () => true, loading: false }),
}));
jest.mock('../../utils/toaster', () => ({ showToast: jest.fn() }));
jest.mock('../SettingsPage/StrategiesTab', () => () => null);
jest.mock('../CredentialsPage/StsClientsTab', () => () => null);

const mockFetch = apiClient.fetch as jest.Mock;

const token = (id: string) =>
  delegation(id, { user_identity_hash: id.repeat(32), consent_expires_at: fromNow(5 * HOUR) });

const GITHUB = {
  id: 'cp-github',
  name: 'GitHub',
  provider_id: 'github',
  provider_type: 'oauth2_authorization_code',
  default_scopes: [],
  token_refresh_enabled: true,
  created_at: '2026-11-01T00:00:00Z',
  updated_at: '2026-11-01T00:00:00Z',
};

const renderPage = () =>
  render(
    <MemoryRouter initialEntries={['/credentials?tab=credential-tokens']}>
      <CredentialsPage />
    </MemoryRouter>
  );

describe('CredentialsPage delegation tabs', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    let deactivatedAt: string | null = null;
    mockFetch.mockImplementation((url: string, options?: { method?: string }) => {
      if (options?.method === 'POST') {
        deactivatedAt = url.endsWith('/deactivate') ? '2026-11-17T10:00:00Z' : null;
      }
      const github = { ...GITHUB, deactivated_at: deactivatedAt };
      return Promise.resolve(
        answer(
          options?.method === 'PUT'
            ? { consent_expires_at: fromNow(HOUR) }
            : options?.method === 'POST'
              ? github
              : url === '/api/v1/credential-providers'
                ? [github]
                : url === '/api/v1/delegation-vault'
                  ? [token('a1'), token('b2')]
                  : {}
        )
      );
    });
  });

  it('reads the vault once for both tabs', async () => {
    renderPage();
    expect(await screen.findByTestId('credential-token-row-a1')).toBeInTheDocument();
    expect(screen.getByTestId('delegated-access-row-a1')).toBeInTheDocument();

    expect(vaultReads()).toHaveLength(1);
  });

  it('drops a delegation revoked on Delegated Access from Credential Tokens too', async () => {
    renderPage();
    const revoke = await screen.findByTestId('delegated-access-revoke-button-a1');

    fireEvent.click(revoke);
    fireEvent.click(revoke);

    await waitFor(() => expect(screen.queryByTestId('delegated-access-row-a1')).toBeNull());
    expect(screen.queryByTestId('credential-token-row-a1')).toBeNull();
    expect(screen.getByTestId('credential-token-row-b2')).toBeInTheDocument();
    expect(screen.getByTestId('delegated-access-row-b2')).toBeInTheDocument();
    expect(requests('DELETE', '/api/v1/delegation-vault/a1')).toHaveLength(1);
  });

  it('shows a limit saved on Credential Tokens as the end on Delegated Access too', async () => {
    renderPage();
    fireEvent.click(await screen.findByTestId('credential-token-limit-button-a1'));
    expect(screen.getByTestId('delegated-access-ends-a1')).toHaveTextContent(/^in 4 hours/);
    fireEvent.change(screen.getByTestId('credential-token-limit-input-a1'), {
      target: { value: '2' },
    });
    fireEvent.click(screen.getByTestId('credential-token-limit-save-a1'));

    await waitFor(() =>
      expect(screen.getByTestId('delegated-access-ends-a1')).toHaveTextContent(
        /^in (59 minutes|1 hour)/
      )
    );
    expect(screen.getByTestId('delegated-access-ends-b2')).toHaveTextContent(/^in 4 hours/);
  });

  it('marks access as taking no new consent once its provider is deactivated on Credential Providers', async () => {
    renderPage();
    const deactivate = await screen.findByTestId('credential-provider-deactivate-button-cp-github');
    const listed = await screen.findByTestId('delegated-access-row-a1');
    expect(screen.queryByTestId('delegated-access-provider-deactivated-a1')).toBeNull();

    fireEvent.click(deactivate);
    fireEvent.click(deactivate);

    expect(await screen.findByTestId('delegated-access-provider-deactivated-a1')).toHaveTextContent(
      'No new consent'
    );
    expect(screen.getByTestId('delegated-access-row-a1')).toBe(listed);

    fireEvent.click(screen.getByTestId('credential-provider-activate-button-cp-github'));

    await waitFor(() =>
      expect(screen.queryByTestId('delegated-access-provider-deactivated-a1')).toBeNull()
    );
    expect(vaultReads()).toHaveLength(3);
  });
});
