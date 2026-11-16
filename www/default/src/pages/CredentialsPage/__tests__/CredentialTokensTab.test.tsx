import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { apiClient } from '../../../api';
import { showToast } from '../../../utils/toaster';
import CredentialTokensTab from '../CredentialTokensTab';

jest.mock('../../../api', () => ({
  apiClient: { fetch: jest.fn() },
}));
jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: () => true, loading: false }),
}));
jest.mock('../../../utils/toaster', () => ({ showToast: jest.fn() }));

const mockFetch = apiClient.fetch as jest.Mock;

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const fromNow = (ms: number) => new Date(Date.now() + ms).toISOString();

const ALICE = 'a'.repeat(64);
const BOB = 'b'.repeat(64);

const token = (id: string, user: string, extra: Record<string, unknown> = {}) => ({
  id,
  agent_did: 'did:web:agent.example.com',
  user_identity_hash: user,
  credential_provider_id: 'cp-github',
  provider_id: 'github',
  token_type: 'bearer',
  scopes: ['repo'],
  expires_at: fromNow(HOUR),
  consent_granted_at: fromNow(-HOUR),
  last_used_at: null,
  created_at: fromNow(-HOUR),
  updated_at: fromNow(-HOUR),
  is_expired: false,
  can_refresh: true,
  ...extra,
});

const GITHUB = {
  id: 'cp-github',
  name: 'GitHub',
  provider_type: 'oauth2_authorization_code',
  token_refresh_enabled: true,
};

const renderTab = async (
  tokens: ReturnType<typeof token>[],
  props: React.ComponentProps<typeof CredentialTokensTab> = {},
  providers: unknown = [GITHUB]
) => {
  mockFetch.mockImplementation((url: string, options?: { method?: string }) =>
    Promise.resolve({
      ok: true,
      statusText: 'OK',
      json: () =>
        Promise.resolve(
          options?.method === 'DELETE'
            ? {}
            : url === '/api/v1/credential-providers'
              ? providers
              : tokens
        ),
    })
  );
  render(<CredentialTokensTab {...props} />);
  await screen.findByTestId(`credential-token-row-${tokens[0].id}`);
};

const row = (id: string) => screen.getByTestId(`credential-token-row-${id}`);
const consentEndOf = (id: string) => screen.getByTestId(`credential-token-consent-end-${id}`);
const deletes = () => mockFetch.mock.calls.filter(([, options]) => options?.method === 'DELETE');

describe('Credential Tokens tab', () => {
  beforeEach(() => jest.clearAllMocks());

  it('shows when each consent ends and marks one ending within a day or already ended', async () => {
    await renderTab([
      token('soon', ALICE, { consent_expires_at: fromNow(3 * HOUR + 5 * MINUTE) }),
      token('later', ALICE, { consent_expires_at: fromNow(12 * DAY + HOUR) }),
      token('unlimited', BOB),
      token('ended', BOB, { consent_expires_at: fromNow(-HOUR) }),
    ]);

    expect(consentEndOf('soon')).toHaveTextContent(/^Ends .+ \(in 3 hours\)$/);
    expect(within(row('soon')).getByText('Ending soon')).toBeInTheDocument();
    expect(consentEndOf('later')).toHaveTextContent(/^Ends .+ \(in 12 days\)$/);
    expect(within(row('later')).getByText('Active')).toBeInTheDocument();
    expect(consentEndOf('unlimited')).toHaveTextContent('No time limit');
    expect(within(row('unlimited')).getByText('Active')).toBeInTheDocument();
    expect(consentEndOf('ended')).toHaveTextContent(/^Ended /);
    expect(within(row('ended')).getByText('Consent ended')).toBeInTheDocument();
    expect(screen.getByText('Credential Delegation Tokens')).toBeInTheDocument();
    expect(screen.getByText('3 active')).toBeInTheDocument();
    expect(screen.getByTestId('credential-tokens-consent-ended-count')).toHaveTextContent(
      '1 consent ended'
    );
  });

  it('shows the access token expiry, and that it renews while the provider refreshes it', async () => {
    await renderTab(
      [
        token('renews', ALICE),
        token('no-refresh-token', ALICE, { can_refresh: false }),
        token('other-provider', BOB, { credential_provider_id: 'cp-manual' }),
        token('unknown-provider', BOB, { credential_provider_id: 'cp-deleted' }),
        token('ended', BOB, { consent_expires_at: fromNow(-HOUR) }),
      ],
      {},
      [GITHUB, { ...GITHUB, id: 'cp-manual', token_refresh_enabled: false }]
    );
    const accessToken = (id: string) => screen.getByTestId(`credential-token-access-token-${id}`);

    expect(screen.getByRole('columnheader', { name: 'Access Token' })).toBeInTheDocument();
    expect(screen.queryByRole('columnheader', { name: 'Token Expires' })).toBeNull();
    expect(accessToken('renews')).toHaveTextContent(/^\S.+Renews automatically$/);
    expect(accessToken('no-refresh-token')).not.toHaveTextContent('Renews automatically');
    expect(accessToken('other-provider')).not.toHaveTextContent('Renews automatically');
    expect(accessToken('unknown-provider')).not.toHaveTextContent('Renews automatically');
    expect(accessToken('ended')).not.toHaveTextContent('Renews automatically');
    expect(accessToken('ended')).toHaveTextContent(/^\S/);
  });

  it('keeps listing tokens while the providers cannot be read', async () => {
    await renderTab([token('t1', ALICE)], {}, { error: 'forbidden' });

    expect(row('t1')).toBeInTheDocument();
    expect(screen.getByTestId('credential-token-access-token-t1')).not.toHaveTextContent(
      'Renews automatically'
    );
  });

  it('names the end of a consent once in the expanded row', async () => {
    await renderTab([token('soon', ALICE, { consent_expires_at: fromNow(3 * HOUR + 5 * MINUTE) })]);
    fireEvent.click(row('soon'));

    expect(screen.getByRole('row', { name: /^Consent Ends/ })).toHaveTextContent(
      /^Consent Ends(?!Ends)\D.+\(in 3 hours\)$/
    );
  });

  it('revokes every delegation of a user only on a second click, with no browser dialog', async () => {
    const confirm = jest.spyOn(window, 'confirm');
    await renderTab([token('t1', ALICE), token('t2', ALICE), token('t3', BOB)]);
    const button = () => screen.getByTestId('credential-token-revoke-user-button-t1');

    fireEvent.click(button());
    expect(button()).toHaveTextContent(/^Revoke all 2 for this user\?$/);
    expect(button()).toHaveClass('btn-danger');
    expect(button()).not.toHaveClass('text-warning');
    expect(deletes()).toHaveLength(0);

    fireEvent.click(button());
    await waitFor(() => expect(deletes()).toHaveLength(1));
    expect(deletes()[0][0]).toBe(`/api/v1/delegation-vault/by-user/${ALICE}`);
    await waitFor(() =>
      expect(screen.queryByTestId('credential-token-row-t1')).not.toBeInTheDocument()
    );
    expect(screen.queryByTestId('credential-token-row-t2')).not.toBeInTheDocument();
    expect(screen.getByTestId('credential-token-row-t3')).toBeInTheDocument();
    expect(showToast).toHaveBeenCalledWith('success', 'All delegations for user revoked');
    expect(confirm).not.toHaveBeenCalled();
    confirm.mockRestore();
  });

  it('names the agent by its host name, with the whole DID in the tooltip', async () => {
    await renderTab([token('t1', ALICE, { agent_did: 'did:web:pr-reviewer.example.com' })]);

    expect(within(row('t1')).getByTitle('did:web:pr-reviewer.example.com')).toHaveTextContent(
      /^pr-reviewer\.example\.com$/
    );
  });

  it('revokes one delegation with a text button whose second click names it', async () => {
    const confirm = jest.spyOn(window, 'confirm');
    await renderTab([token('t1', ALICE), token('t2', BOB)]);
    const button = screen.getByTestId('credential-token-revoke-button-t1');
    expect(button).toHaveTextContent(/^Revoke$/);

    fireEvent.click(button);
    expect(button).toHaveTextContent(/^Revoke github access\?$/);
    expect(button).toHaveClass('btn-danger');
    expect(row('t1')).not.toHaveClass('table-active');
    fireEvent.click(screen.getByTestId('credential-token-revoke-cancel-button-t1'));
    expect(button).toHaveTextContent(/^Revoke$/);
    expect(deletes()).toHaveLength(0);

    fireEvent.click(button);
    fireEvent.click(button);
    await waitFor(() => expect(deletes()).toHaveLength(1));
    expect(deletes()[0][0]).toBe('/api/v1/delegation-vault/t1');
    await waitFor(() =>
      expect(screen.queryByTestId('credential-token-row-t1')).not.toBeInTheDocument()
    );
    expect(screen.getByTestId('credential-token-row-t2')).toBeInTheDocument();
    expect(confirm).not.toHaveBeenCalled();
    confirm.mockRestore();
  });

  it('keeps every delegation when the first click is not confirmed', async () => {
    await renderTab([token('t1', ALICE)]);
    fireEvent.click(screen.getByTestId('credential-token-revoke-user-button-t1'));
    expect(screen.getByTestId('credential-token-revoke-user-button-t1')).toHaveTextContent(
      "Revoke this user's only delegation?"
    );
    fireEvent.click(row('t1'));

    expect(deletes()).toHaveLength(0);
    expect(screen.getByTestId('credential-token-row-t1')).toBeInTheDocument();
  });

  it("opens a user's delegation audit from the expanded row when the page offers it", async () => {
    const onViewActivity = jest.fn();
    await renderTab([token('t1', ALICE)], { onViewActivity });
    expect(
      screen.queryByTestId('credential-token-view-activity-button-t1')
    ).not.toBeInTheDocument();

    fireEvent.click(row('t1'));
    fireEvent.click(screen.getByTestId('credential-token-view-activity-button-t1'));

    expect(onViewActivity).toHaveBeenCalledWith(ALICE);
  });

  it('offers no audit link when the page gives none', async () => {
    await renderTab([token('t1', ALICE)]);
    fireEvent.click(row('t1'));

    expect(screen.getByText('Consent Ends')).toBeInTheDocument();
    expect(
      screen.queryByTestId('credential-token-view-activity-button-t1')
    ).not.toBeInTheDocument();
  });
});
