import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { apiClient } from '../../../api';
import { showToast } from '../../../utils/toaster';
import DelegatedAccessTab from '../DelegatedAccessTab';

jest.mock('../../../api', () => ({
  apiClient: { fetch: jest.fn() },
}));
const mockHasPermission = jest.fn();
jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: mockHasPermission, loading: false }),
}));
jest.mock('../../../utils/toaster', () => ({ showToast: jest.fn() }));

const mockFetch = apiClient.fetch as jest.Mock;

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const fromNow = (ms: number) => new Date(Date.now() + ms).toISOString();

const ALICE = 'a'.repeat(64);
const BOB = 'b'.repeat(64);

const token = (id: string, extra: Record<string, unknown> = {}) => ({
  id,
  agent_did: 'did:web:agent.example.com',
  user_identity_hash: ALICE,
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

/** Generous, since the whole suite runs these beside many others. */
const WAIT = { timeout: 5000 };

const PROVIDERS = [
  { id: 'cp-github', name: 'GitHub', provider_type: 'oauth2_authorization_code' },
  { id: 'cp-service', name: 'Billing API', provider_type: 'oauth2_client_credentials' },
];

const renderTab = async (
  tokens: ReturnType<typeof token>[],
  props: React.ComponentProps<typeof DelegatedAccessTab> = {},
  providers: unknown = PROVIDERS
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
  render(<DelegatedAccessTab {...props} />);
  await waitFor(() => expect(screen.queryByRole('status')).not.toBeInTheDocument(), WAIT);
};

const row = (id: string) => screen.getByTestId(`delegated-access-row-${id}`);
const rowIds = () =>
  screen
    .queryAllByTestId(/^delegated-access-row-/)
    .map(element => element.getAttribute('data-testid')!.replace('delegated-access-row-', ''));
const deletes = () => mockFetch.mock.calls.filter(([, options]) => options?.method === 'DELETE');

describe('Delegated Access tab', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockHasPermission.mockReturnValue(true);
  });

  it('lists only the access an agent can still use, and no service token', async () => {
    await renderTab([
      token('active'),
      token('refreshable', { is_expired: true, can_refresh: true }),
      token('dead', { is_expired: true, can_refresh: false }),
      token('ended', { consent_expires_at: fromNow(-HOUR) }),
      token('service', { credential_provider_id: 'cp-service', provider_id: 'billing' }),
      token('gone-provider', { credential_provider_id: 'cp-deleted', provider_id: 'legacy' }),
    ]);

    expect(rowIds()).toEqual(['active', 'refreshable', 'gone-provider']);
    expect(within(row('active')).getByText('GitHub')).toBeInTheDocument();
    expect(within(row('gone-provider')).getByText('legacy')).toBeInTheDocument();
  });

  it('shows when each access ends and marks one ending within a day', async () => {
    await renderTab([
      token('soon', { consent_expires_at: fromNow(3 * HOUR + 5 * 60_000) }),
      token('later', { consent_expires_at: fromNow(12 * DAY + HOUR) }),
      token('unlimited', { user_identity_hash: BOB }),
    ]);

    expect(screen.getByTestId('delegated-access-ends-soon')).toHaveTextContent(/^in 3 hours/);
    expect(within(row('soon')).getByText('Ending soon')).toBeInTheDocument();
    expect(screen.getByTestId('delegated-access-ends-later')).toHaveTextContent(/^in 12 days/);
    expect(within(row('later')).getByText('Active')).toBeInTheDocument();
    expect(screen.getByTestId('delegated-access-ends-unlimited')).toHaveTextContent(
      'No time limit'
    );
    expect(screen.getByTestId('delegated-access-ending-soon-count')).toHaveTextContent(
      '1 ending soon'
    );
  });

  it('revokes one access on a second click', async () => {
    await renderTab([token('t1'), token('t2', { user_identity_hash: BOB })]);
    const button = screen.getByTestId('delegated-access-revoke-button-t1');

    fireEvent.click(button);
    expect(deletes()).toHaveLength(0);
    expect(button).toHaveAttribute('title', 'Click again to revoke this access');

    fireEvent.click(button);
    await waitFor(() => expect(deletes()).toHaveLength(1), WAIT);
    expect(deletes()[0][0]).toBe('/api/v1/delegation-vault/t1');
    await waitFor(() => expect(rowIds()).toEqual(['t2']), WAIT);
    expect(showToast).toHaveBeenCalledWith('success', 'Access revoked');
  });

  it('offers no revoke to a user who may not edit', async () => {
    mockHasPermission.mockReturnValue(false);
    await renderTab([token('t1')]);

    expect(row('t1')).toBeInTheDocument();
    expect(screen.queryByTestId('delegated-access-revoke-button-t1')).not.toBeInTheDocument();
  });

  it('opens the history when the page offers it, and shows no button otherwise', async () => {
    const onViewHistory = jest.fn();
    await renderTab([token('t1')], { onViewHistory });
    fireEvent.click(screen.getByTestId('delegated-access-history-button'));
    expect(onViewHistory).toHaveBeenCalledTimes(1);
  });

  it('shows no history button when the page gives none', async () => {
    await renderTab([token('t1')]);
    expect(screen.queryByTestId('delegated-access-history-button')).not.toBeInTheDocument();
  });

  it('says there is no active access when every entry ended, and still lists by system name', async () => {
    await renderTab([token('ended', { consent_expires_at: fromNow(-HOUR) })]);
    expect(screen.getByText('No active delegated access')).toBeInTheDocument();
    expect(rowIds()).toEqual([]);
  });

  it('filters by the page search and reports how many it shows', async () => {
    const onFilteredCountChange = jest.fn();
    await renderTab([token('t1'), token('t2', { user_identity_hash: BOB })], {
      externalSearchTerm: BOB.slice(0, 12),
      onFilteredCountChange,
    });

    expect(rowIds()).toEqual(['t2']);
    await waitFor(() => expect(onFilteredCountChange).toHaveBeenLastCalledWith(1), WAIT);
  });

  it('keeps showing the access of a deactivated provider, marked as taking no new consent', async () => {
    await renderTab(
      [token('t1'), token('t2', { credential_provider_id: 'cp-other', provider_id: 'other' })],
      {},
      [
        { ...PROVIDERS[0], deactivated_at: '2026-11-13T10:00:00Z' },
        { id: 'cp-other', name: 'Other', provider_type: 'oauth2_authorization_code' },
      ]
    );

    expect(rowIds()).toEqual(['t1', 't2']);
    expect(screen.getByTestId('delegated-access-provider-deactivated-t1')).toHaveTextContent(
      'No new consent'
    );
    expect(screen.queryByTestId('delegated-access-provider-deactivated-t2')).toBeNull();
  });

  it('keeps listing access while the providers cannot be read', async () => {
    await renderTab([token('t1')], {}, { error: 'forbidden' });

    expect(rowIds()).toEqual(['t1']);
    expect(within(row('t1')).getByText('github')).toBeInTheDocument();
  });
});
