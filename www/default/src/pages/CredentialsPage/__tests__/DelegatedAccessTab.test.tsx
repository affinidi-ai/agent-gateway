import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { apiClient } from '../../../api';
import { showToast } from '../../../utils/toaster';
import DelegatedAccessTab from '../DelegatedAccessTab';
import { useDelegationVault } from '../useDelegationVault';
import {
  BOB,
  DAY,
  HOUR,
  PROVIDERS,
  answer,
  delegation as token,
  fromNow,
  gatewayHolds,
  requests,
  vaultReads as reads,
} from '../vaultTestFixtures';

jest.mock('../../../api', () => ({
  apiClient: { fetch: jest.fn() },
}));
const mockHasPermission = jest.fn();
jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: mockHasPermission, loading: false }),
}));
jest.mock('../../../utils/toaster', () => ({ showToast: jest.fn() }));

const mockFetch = apiClient.fetch as jest.Mock;

type TabProps = Omit<React.ComponentProps<typeof DelegatedAccessTab>, 'vault'>;

/** The tab on the vault the Credentials page would hand it. */
const Tab: React.FC<TabProps> = props => (
  <DelegatedAccessTab {...props} vault={useDelegationVault()} />
);

/** Generous, since the whole suite runs these beside many others. */
const WAIT = { timeout: 5000 };

const renderTab = async (
  tokens: ReturnType<typeof token>[],
  props: TabProps = {},
  providers: unknown = PROVIDERS,
  change?: () => unknown
) => {
  gatewayHolds(tokens, providers, change);
  render(<Tab {...props} />);
  await waitFor(() => expect(screen.queryByRole('status')).not.toBeInTheDocument(), WAIT);
};

const row = (id: string) => screen.getByTestId(`delegated-access-row-${id}`);
const rowIds = () =>
  screen
    .queryAllByTestId(/^delegated-access-row-/)
    .map(element => element.getAttribute('data-testid')!.replace('delegated-access-row-', ''));
const deletes = () => requests('DELETE');

describe('Delegated Access tab', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockHasPermission.mockImplementation(
      (permission: string) => permission === 'delegation_vault.delete'
    );
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
      token('soon', {
        consent_granted_at: fromNow(-(3 * HOUR - 5 * 60_000)),
        consent_expires_at: fromNow(3 * HOUR + 5 * 60_000),
      }),
      token('later', {
        consent_granted_at: fromNow(-(18 * DAY - HOUR)),
        consent_expires_at: fromNow(12 * DAY + HOUR),
      }),
      token('unlimited', { user_identity_hash: BOB }),
    ]);

    expect(screen.getByTestId('delegated-access-ends-soon')).toHaveTextContent(
      /^in 3 hours6-hour limit\S/
    );
    expect(screen.getByTestId('delegated-access-ends-later')).toHaveTextContent(
      /^in 12 days30-day limit\S/
    );
    expect(within(row('soon')).getByText('Ending soon')).toBeInTheDocument();
    expect(within(row('later')).getByText('Active')).toBeInTheDocument();
    expect(screen.getByTestId('delegated-access-ends-unlimited')).toHaveTextContent(
      'No time limit'
    );
    expect(screen.getByTestId('delegated-access-ending-soon-count')).toHaveTextContent(
      '1 ending soon'
    );
  });

  it('revokes one access on a second click, which names what it ends', async () => {
    const confirm = jest.spyOn(window, 'confirm');
    await renderTab([token('t1'), token('t2', { user_identity_hash: BOB })]);
    const button = screen.getByTestId('delegated-access-revoke-button-t1');
    expect(button).toHaveTextContent(/^Revoke$/);

    fireEvent.click(button);
    expect(deletes()).toHaveLength(0);
    expect(button).toHaveTextContent(/^Revoke GitHub access\?$/);
    expect(button).toHaveClass('btn-danger');
    expect(button).toHaveAttribute('title', 'Click again to revoke this access');
    expect(screen.getByTestId('delegated-access-revoke-cancel-button-t1')).toHaveTextContent(
      'Cancel'
    );

    fireEvent.click(button);
    await waitFor(() => expect(deletes()).toHaveLength(1), WAIT);
    expect(deletes()[0][0]).toBe('/api/v1/delegation-vault/t1');
    await waitFor(() => expect(rowIds()).toEqual(['t2']), WAIT);
    expect(showToast).toHaveBeenCalledWith('success', 'Access revoked');
    expect(confirm).not.toHaveBeenCalled();
    confirm.mockRestore();
  });

  it('keeps the access when the revoke is cancelled', async () => {
    await renderTab([token('t1')]);
    const button = screen.getByTestId('delegated-access-revoke-button-t1');

    fireEvent.click(button);
    fireEvent.click(screen.getByTestId('delegated-access-revoke-cancel-button-t1'));

    expect(button).toHaveTextContent(/^Revoke$/);
    expect(screen.queryByTestId('delegated-access-revoke-cancel-button-t1')).toBeNull();
    expect(deletes()).toHaveLength(0);
    expect(rowIds()).toEqual(['t1']);
  });

  it('names the agent by its host name, with the whole DID in the tooltip', async () => {
    await renderTab([token('t1', { agent_did: 'did:web:pr-reviewer.example.com' })]);

    expect(within(row('t1')).getByTitle('did:web:pr-reviewer.example.com')).toHaveTextContent(
      /^pr-reviewer\.example\.com$/
    );
  });

  it('offers no revoke to a user who may not delete from the vault', async () => {
    mockHasPermission.mockImplementation((permission: string) => permission === 'settings.edit');
    await renderTab([token('t1')]);

    expect(row('t1')).toBeInTheDocument();
    expect(screen.queryByTestId('delegated-access-revoke-button-t1')).not.toBeInTheDocument();
    expect(screen.queryByRole('columnheader', { name: 'Actions' })).toBeNull();
    expect(mockHasPermission).toHaveBeenCalledWith('delegation_vault.delete');
  });

  it('says why a revoke was refused, in the words of the gateway, and keeps the access', async () => {
    await renderTab([token('t1')], {}, PROVIDERS, () =>
      answer({ error: 'Failed to revoke' }, 500, 'Internal Server Error')
    );
    const button = screen.getByTestId('delegated-access-revoke-button-t1');

    fireEvent.click(button);
    fireEvent.click(button);

    await waitFor(
      () => expect(showToast).toHaveBeenCalledWith('error', 'Not revoked: Failed to revoke'),
      WAIT
    );
    expect(rowIds()).toEqual(['t1']);
    expect(showToast).not.toHaveBeenCalledWith('success', expect.anything());
  });

  it('says the access could not be read, not that there is none, and reads again on Retry', async () => {
    let refuse = true;
    mockFetch.mockImplementation((url: string) =>
      Promise.resolve(
        url === '/api/v1/credential-providers'
          ? answer(PROVIDERS)
          : refuse
            ? answer('', 403, 'Forbidden')
            : answer([token('t1')])
      )
    );
    render(<Tab />);

    expect(await screen.findByTestId('delegated-access-read-error')).toHaveTextContent(
      'Failed to load delegations: Forbidden (403)'
    );
    expect(screen.queryByText('No active delegated access')).toBeNull();
    expect(screen.queryByLabelText(/active delegations/)).toBeNull();

    refuse = false;
    fireEvent.click(screen.getByTestId('delegated-access-read-error-retry'));

    await waitFor(() => expect(rowIds()).toEqual(['t1']), WAIT);
    expect(screen.queryByTestId('delegated-access-read-error')).toBeNull();
    expect(rowIds().length).toBe(1);
    expect(reads()).toHaveLength(2);
  });

  it('shows the last page left once the only access of a later page is revoked', async () => {
    const ids = Array.from({ length: 11 }, (_, index) => `t${String(index + 1).padStart(2, '0')}`);
    await renderTab(ids.map(id => token(id)));
    fireEvent.click(screen.getByRole('button', { name: '2' }));
    expect(rowIds()).toEqual(['t11']);

    const revoke = screen.getByTestId('delegated-access-revoke-button-t11');
    fireEvent.click(revoke);
    fireEvent.click(revoke);

    await waitFor(() => expect(rowIds()).toEqual(ids.slice(0, 10)), WAIT);
  });

  it('opens the history when the page offers it, and shows no button otherwise', async () => {
    const onViewHistory = jest.fn();
    await renderTab([token('t1')], { onViewHistory });
    fireEvent.click(screen.getByTestId('delegated-access-history-button'));
    expect(onViewHistory).toHaveBeenCalledTimes(1);
  });

  it('shows no history button, and points at no history, when the page gives none', async () => {
    await renderTab([token('t1'), token('t2', { user_identity_hash: BOB })]);

    expect(screen.queryByTestId('delegated-access-history-button')).not.toBeInTheDocument();
    expect(screen.getByText('Active access only.')).toBeInTheDocument();
    expect(screen.queryByText(/in the history/)).toBeNull();
    expect(rowIds().length).toBe(2);
  });

  it('points at the history beside its button', async () => {
    await renderTab([token('t1')], { onViewHistory: jest.fn() });

    expect(
      screen.getByText('Active access only. Ended and revoked access is in the history.')
    ).toBeInTheDocument();
  });

  it('says there is no active access when every entry ended', async () => {
    await renderTab([token('ended', { consent_expires_at: fromNow(-HOUR) })]);
    expect(screen.getByText('No active delegated access')).toBeInTheDocument();
    expect(screen.queryByText(/in the history/)).toBeNull();
    expect(rowIds()).toEqual([]);
  });

  it('says where ended access is when there is none active and the history can be opened', async () => {
    await renderTab([], { onViewHistory: jest.fn() });

    expect(
      screen.getByText(/Access that ended or was revoked is in the history\.$/)
    ).toBeInTheDocument();
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
