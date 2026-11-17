import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import { apiClient } from '../../api';
import CredentialsPage from '../CredentialsPage';

jest.mock('../../api', () => ({
  apiClient: { fetch: jest.fn() },
}));
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: () => true, loading: false }),
}));
jest.mock('../../utils/toaster', () => ({ showToast: jest.fn() }));
jest.mock('../SettingsPage/StrategiesTab', () => () => null);
jest.mock('../SettingsPage/CredentialProvidersTab', () => () => null);
jest.mock('../CredentialsPage/StsClientsTab', () => () => null);

const mockFetch = apiClient.fetch as jest.Mock;

const HOUR = 3_600_000;
const fromNow = (ms: number) => new Date(Date.now() + ms).toISOString();

const token = (id: string) => ({
  id,
  agent_did: 'did:web:agent.example.com',
  user_identity_hash: id.repeat(32),
  credential_provider_id: 'cp-github',
  provider_id: 'github',
  token_type: 'bearer',
  scopes: ['repo'],
  expires_at: fromNow(HOUR),
  consent_granted_at: fromNow(-HOUR),
  consent_expires_at: fromNow(5 * HOUR),
  last_used_at: null,
  created_at: fromNow(-HOUR),
  updated_at: fromNow(-HOUR),
  is_expired: false,
  can_refresh: true,
});

const answer = (body: unknown) => ({
  ok: true,
  status: 200,
  statusText: 'OK',
  json: () => Promise.resolve(body),
  text: () => Promise.resolve(JSON.stringify(body)),
});

const requests = (method: string | undefined, url: string) =>
  mockFetch.mock.calls.filter(([asked, options]) => asked === url && options?.method === method);

const renderPage = () =>
  render(
    <MemoryRouter initialEntries={['/credentials?tab=credential-tokens']}>
      <CredentialsPage />
    </MemoryRouter>
  );

describe('CredentialsPage delegation tabs', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockFetch.mockImplementation((url: string, options?: { method?: string }) =>
      Promise.resolve(
        answer(
          options?.method === 'PUT'
            ? { consent_expires_at: fromNow(HOUR) }
            : url === '/api/v1/credential-providers'
              ? [{ id: 'cp-github', name: 'GitHub', provider_type: 'oauth2_authorization_code' }]
              : url === '/api/v1/delegation-vault'
                ? [token('a1'), token('b2')]
                : {}
        )
      )
    );
  });

  it('reads the vault once for both tabs', async () => {
    renderPage();
    expect(await screen.findByTestId('credential-token-row-a1')).toBeInTheDocument();
    expect(screen.getByTestId('delegated-access-row-a1')).toBeInTheDocument();

    expect(requests(undefined, '/api/v1/delegation-vault')).toHaveLength(1);
    expect(requests(undefined, '/api/v1/credential-providers')).toHaveLength(1);
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
});
