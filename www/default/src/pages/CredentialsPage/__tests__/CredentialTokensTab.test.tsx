import React from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { apiClient } from '../../../api';
import { showToast } from '../../../utils/toaster';
import CredentialTokensTab from '../CredentialTokensTab';
import { useDelegationVault } from '../useDelegationVault';
import {
  ALICE,
  BOB,
  DAY,
  GITHUB,
  HOUR,
  MINUTE,
  answer,
  delegation,
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

type TabProps = Omit<React.ComponentProps<typeof CredentialTokensTab>, 'vault'>;

/** The tab on the vault the Credentials page would hand it. */
const Tab: React.FC<TabProps> = props => (
  <CredentialTokensTab {...props} vault={useDelegationVault()} />
);

const token = (id: string, user: string, extra: Record<string, unknown> = {}) =>
  delegation(id, { user_identity_hash: user, ...extra });

const renderTab = async (
  tokens: ReturnType<typeof token>[],
  props: TabProps = {},
  providers: unknown = [GITHUB]
) => {
  gatewayHolds(tokens, providers);
  render(<Tab {...props} />);
  await screen.findByTestId(`credential-token-row-${tokens[0].id}`);
};

const row = (id: string) => screen.getByTestId(`credential-token-row-${id}`);
const rowIds = () =>
  screen
    .queryAllByTestId(/^credential-token-row-/)
    .map(element => element.getAttribute('data-testid')!.replace('credential-token-row-', ''));
const consentEndOf = (id: string) => screen.getByTestId(`credential-token-consent-end-${id}`);
const deletes = () => requests('DELETE');

describe('Credential Tokens tab', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockHasPermission.mockImplementation(
      (permission: string) => permission === 'delegation_vault.delete'
    );
  });

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
  });

  it('shows its title alone in its header, with no count of tokens or of statuses', async () => {
    await renderTab([
      token('active', ALICE),
      token('refreshable', ALICE, { is_expired: true }),
      token('expired', BOB, { is_expired: true, can_refresh: false }),
      token('ended', BOB, { consent_expires_at: fromNow(-HOUR) }),
    ]);

    expect(screen.getByRole('heading', { name: /Credential Delegation Tokens/ })).toHaveTextContent(
      /^\s*Credential Delegation Tokens\s*$/
    );
    expect(screen.queryByTestId('credential-tokens-consent-ended-count')).toBeNull();
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

  it("names each token's provider by its name, else by its provider id", async () => {
    await renderTab([
      token('known', ALICE),
      token('gone', BOB, { credential_provider_id: 'cp-deleted', provider_id: 'legacy' }),
    ]);

    expect(within(row('known')).getAllByRole('cell')[0]).toHaveTextContent(/^GitHub$/);
    expect(within(row('gone')).getAllByRole('cell')[0]).toHaveTextContent(/^legacy$/);
  });

  it("finds a token by its provider's name", async () => {
    await renderTab(
      [
        token('scm', ALICE, { credential_provider_id: 'cp-scm', provider_id: 'scm' }),
        token('other', BOB),
      ],
      { externalSearchTerm: 'source control' },
      [GITHUB, { ...GITHUB, id: 'cp-scm', name: 'Source Control' }]
    );

    expect(row('scm')).toBeInTheDocument();
    expect(screen.queryByTestId('credential-token-row-other')).toBeNull();
  });

  it('keeps listing tokens while the providers cannot be read', async () => {
    await renderTab([token('t1', ALICE)], {}, { error: 'forbidden' });

    expect(row('t1')).toBeInTheDocument();
    expect(within(row('t1')).getAllByRole('cell')[0]).toHaveTextContent(/^github$/);
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
    expect(button).toHaveTextContent(/^Revoke GitHub access\?$/);
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

  const puts = () => requests('PUT');
  /** Answers every later request with `body`, as a success or as a `400`. */
  const answerWith = (ok: boolean, body: unknown) =>
    mockFetch.mockImplementation(() =>
      Promise.resolve(ok ? answer(body) : answer(body, 400, 'Bad Request'))
    );
  const limitPart = (part: string, id = 't1') =>
    screen.getByTestId(`credential-token-limit-${part}-${id}`);
  const sixHourConsent = (id: string, user: string) =>
    token(id, user, { consent_expires_at: fromNow(5 * HOUR) });

  it('offers Limit duration beside Revoke only for a consent an agent can still act under', async () => {
    await renderTab(
      [
        sixHourConsent('active', ALICE),
        token('unlimited', ALICE),
        token('ended', BOB, { consent_expires_at: fromNow(-HOUR) }),
        token('unusable', BOB, { is_expired: true, can_refresh: false }),
        token('service', BOB, { credential_provider_id: 'cp-service' }),
        token('unknown', BOB, { credential_provider_id: 'cp-deleted' }),
      ],
      {},
      [GITHUB, { ...GITHUB, id: 'cp-service', provider_type: 'oauth2_client_credentials' }]
    );

    for (const id of ['active', 'unlimited']) {
      const cells = within(row(id)).getAllByRole('cell');
      const actions = within(cells[cells.length - 1]);
      expect(actions.getByTestId(`credential-token-limit-button-${id}`)).toHaveTextContent(
        /^Limit duration$/
      );
      expect(actions.getByTestId(`credential-token-revoke-button-${id}`)).toBeInTheDocument();
    }
    for (const id of ['ended', 'unusable', 'service', 'unknown']) {
      expect(screen.queryByTestId(`credential-token-limit-button-${id}`)).toBeNull();
    }
  });

  it('limits one consent in place: previews its new end, saves it and shows it in the row', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm');
    await renderTab([sixHourConsent('t1', ALICE), token('t2', BOB)]);

    fireEvent.click(screen.getByTestId('credential-token-limit-button-t1'));

    expect(limitPart('panel')).toHaveTextContent('Limit duration · GitHub');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(row('t1')).not.toHaveClass('table-active');
    expect(limitPart('input')).toHaveValue(6);
    expect(limitPart('unit')).toHaveValue('hours');
    expect(limitPart('preview')).toHaveTextContent(
      /^It already ends .+\. A limit only brings the end forward\.$/
    );
    expect(limitPart('save')).toBeDisabled();

    fireEvent.change(limitPart('input'), { target: { value: '2' } });
    expect(limitPart('preview')).toHaveTextContent(
      /^Consent given .+\. With this limit it ends .+ \(in (59 minutes|1 hour)\)\.$/
    );
    expect(limitPart('save')).toBeEnabled();

    answerWith(true, { ...token('t1', ALICE), consent_expires_at: fromNow(HOUR) });
    fireEvent.click(limitPart('save'));

    await waitFor(() => expect(screen.queryByTestId('credential-token-limit-panel-t1')).toBeNull());
    expect(puts()).toHaveLength(1);
    const [url, options] = puts()[0];
    expect(url).toBe('/api/v1/delegation-vault/t1/consent-limit');
    expect(JSON.parse(options.body)).toEqual({ max_consent_age_secs: 7200 });
    expect(consentEndOf('t1')).toHaveTextContent(/\(in (59 minutes|1 hour)\)$/);
    expect(consentEndOf('t2')).toHaveTextContent('No time limit');
    expect(showToast).toHaveBeenCalledWith(
      'success',
      expect.stringMatching(/^Limit saved\. GitHub access ends /)
    );
    expect(confirmSpy).not.toHaveBeenCalled();
    confirmSpy.mockRestore();
  });

  it('offers no Save for a limit that would end the consent now, extend it, or is no limit', async () => {
    await renderTab([sixHourConsent('t1', ALICE)]);
    fireEvent.click(screen.getByTestId('credential-token-limit-button-t1'));

    const refused: [string, string, RegExp][] = [
      ['12', 'hours', /A limit only brings the end forward\.$/],
      ['30', 'minutes', /^This consent is already older than that\. Use Revoke to end it now\.$/],
      ['', 'hours', /^Enter a whole number from 1 minute to 365 days\.$/],
      ['1.5', 'hours', /^Enter a whole number from 1 minute to 365 days\.$/],
      ['400', 'days', /^Enter a whole number from 1 minute to 365 days\.$/],
    ];
    for (const [amount, unit, preview] of refused) {
      fireEvent.change(limitPart('input'), { target: { value: amount } });
      fireEvent.change(limitPart('unit'), { target: { value: unit } });
      expect(limitPart('preview')).toHaveTextContent(preview);
      expect(limitPart('save')).toBeDisabled();
    }
    expect(puts()).toHaveLength(0);
  });

  it('shows what the gateway says when it refuses a limit, and keeps the panel open', async () => {
    await renderTab([sixHourConsent('t1', ALICE)]);
    fireEvent.click(screen.getByTestId('credential-token-limit-button-t1'));
    fireEvent.change(limitPart('input'), { target: { value: '2' } });

    answerWith(false, {
      code: 'limit_not_sooner',
      error: 'The consent already ends at this limit or before it. A consent is never extended',
    });
    fireEvent.click(limitPart('save'));

    expect(await screen.findByTestId('credential-token-limit-error-t1')).toHaveTextContent(
      'The consent already ends at this limit or before it. A consent is never extended'
    );
    expect(limitPart('input')).toHaveAttribute('aria-invalid', 'true');
    expect(limitPart('panel')).toBeInTheDocument();
    expect(consentEndOf('t1')).toHaveTextContent(/\(in 4 hours\)$/);
    expect(showToast).not.toHaveBeenCalledWith('success', expect.anything());

    fireEvent.change(limitPart('input'), { target: { value: '3' } });
    expect(screen.queryByTestId('credential-token-limit-error-t1')).toBeNull();
  });

  it('closes the limit panel on Cancel or a second click, and sends nothing', async () => {
    await renderTab([sixHourConsent('t1', ALICE)]);
    const button = screen.getByTestId('credential-token-limit-button-t1');

    fireEvent.click(button);
    expect(button).toHaveAttribute('aria-expanded', 'true');
    fireEvent.click(limitPart('cancel'));
    expect(screen.queryByTestId('credential-token-limit-panel-t1')).toBeNull();
    expect(button).toHaveAttribute('aria-expanded', 'false');

    fireEvent.click(button);
    expect(limitPart('panel')).toBeInTheDocument();
    fireEvent.click(button);
    expect(screen.queryByTestId('credential-token-limit-panel-t1')).toBeNull();
    expect(puts()).toHaveLength(0);
    expect(row('t1')).toBeInTheDocument();
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

  it('opens the detail of a token from a button a keyboard reaches', async () => {
    await renderTab([token('t1', ALICE)]);
    const expand = screen.getByTestId('credential-token-expand-button-t1');
    expect(expand).toHaveAttribute('aria-expanded', 'false');
    expect(expand).toHaveAccessibleName(/^Details of GitHub access for user a{8}.+a{8}$/);

    fireEvent.click(expand);
    expect(expand).toHaveAttribute('aria-expanded', 'true');
    const detail = screen.getByTestId('credential-token-detail-t1');
    expect(expand).toHaveAttribute('aria-controls', detail.id);
    expect(detail).toHaveTextContent('Consent Ends');

    fireEvent.click(expand);
    expect(expand).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByText('Consent Ends')).toBeNull();
  });

  it('offers no way to change a delegation to a user who may not delete from the vault', async () => {
    mockHasPermission.mockImplementation((permission: string) => permission === 'settings.edit');
    await renderTab([sixHourConsent('t1', ALICE)]);

    expect(row('t1')).toBeInTheDocument();
    expect(screen.queryByRole('columnheader', { name: 'Actions' })).toBeNull();
    for (const control of ['limit-button', 'revoke-button', 'revoke-user-button']) {
      expect(screen.queryByTestId(`credential-token-${control}-t1`)).toBeNull();
    }
    expect(mockHasPermission).toHaveBeenCalledWith('delegation_vault.delete');
  });

  it('says why a revoke was refused, in the words of the gateway, and keeps the delegation', async () => {
    gatewayHolds([token('t1', ALICE)], [GITHUB], () =>
      answer({ error: 'Failed to revoke' }, 500, 'Internal Server Error')
    );
    render(<Tab />);
    const button = await screen.findByTestId('credential-token-revoke-button-t1');

    fireEvent.click(button);
    fireEvent.click(button);

    await waitFor(() =>
      expect(showToast).toHaveBeenCalledWith('error', 'Not revoked: Failed to revoke')
    );
    expect(rowIds()).toEqual(['t1']);
    expect(showToast).not.toHaveBeenCalledWith('success', expect.anything());
  });

  it("names the status of a refused revoke of a user's delegations when the gateway gave no words", async () => {
    gatewayHolds([token('t1', ALICE), token('t2', ALICE)], [GITHUB], () =>
      answer('', 403, 'Forbidden')
    );
    render(<Tab />);
    const button = () => screen.getByTestId('credential-token-revoke-user-button-t1');
    await screen.findByTestId('credential-token-row-t1');

    fireEvent.click(button());
    fireEvent.click(button());

    await waitFor(() =>
      expect(showToast).toHaveBeenCalledWith('error', 'Not revoked: Forbidden (403)')
    );
    expect(rowIds()).toEqual(['t1', 't2']);
  });

  it('says a revoke did not reach the gateway and keeps the delegation', async () => {
    gatewayHolds([token('t1', ALICE)], [GITHUB], () =>
      Promise.reject(new TypeError('Failed to fetch'))
    );
    render(<Tab />);
    const button = await screen.findByTestId('credential-token-revoke-button-t1');

    fireEvent.click(button);
    fireEvent.click(button);

    await waitFor(() =>
      expect(showToast).toHaveBeenCalledWith(
        'error',
        'Not revoked: The gateway could not be reached.'
      )
    );
    expect(rowIds()).toEqual(['t1']);
  });

  it('says the delegations could not be read, not that there are none, and reads again on Retry', async () => {
    let refuse = true;
    mockFetch.mockImplementation((url: string) =>
      Promise.resolve(
        url === '/api/v1/credential-providers'
          ? answer([GITHUB])
          : refuse
            ? answer({ error: 'Failed to list tokens' }, 500, 'Internal Server Error')
            : answer([token('t1', ALICE)])
      )
    );
    render(<Tab />);

    expect(await screen.findByTestId('credential-tokens-read-error')).toHaveTextContent(
      'Failed to load delegations: Failed to list tokens'
    );
    expect(screen.queryByText('No delegation tokens yet')).toBeNull();
    expect(rowIds()).toEqual([]);

    refuse = false;
    fireEvent.click(screen.getByTestId('credential-tokens-read-error-retry'));

    expect(await screen.findByTestId('credential-token-row-t1')).toBeInTheDocument();
    expect(screen.queryByTestId('credential-tokens-read-error')).toBeNull();
    expect(reads()).toHaveLength(2);
  });

  it('says the gateway could not be reached when the read gets no answer', async () => {
    mockFetch.mockRejectedValue(new TypeError('Failed to fetch'));
    render(<Tab />);

    expect(await screen.findByTestId('credential-tokens-read-error')).toHaveTextContent(
      'Failed to load delegations: The gateway could not be reached.'
    );
    expect(screen.queryByText('No delegation tokens yet')).toBeNull();
  });

  it('says there are no tokens only when the gateway lists none', async () => {
    gatewayHolds([]);
    render(<Tab />);

    expect(await screen.findByText('No delegation tokens yet')).toBeInTheDocument();
    expect(screen.queryByTestId('credential-tokens-read-error')).toBeNull();
  });

  it('shows the last page left once the only delegation of a later page is revoked', async () => {
    const ids = Array.from({ length: 11 }, (_, index) => `t${String(index + 1).padStart(2, '0')}`);
    await renderTab(ids.map(id => token(id, id === 't11' ? BOB : ALICE)));
    fireEvent.click(screen.getByRole('button', { name: '2' }));
    expect(rowIds()).toEqual(['t11']);

    const revoke = screen.getByTestId('credential-token-revoke-button-t11');
    fireEvent.click(revoke);
    fireEvent.click(revoke);

    await waitFor(() => expect(rowIds()).toEqual(ids.slice(0, 10)));
  });

  it('opens the limit panel of a consent with no time limit empty, in hours, with no Save', async () => {
    await renderTab([token('t1', ALICE)]);
    fireEvent.click(screen.getByTestId('credential-token-limit-button-t1'));

    expect(limitPart('input')).toHaveValue(null);
    expect(limitPart('unit')).toHaveValue('hours');
    expect(limitPart('preview')).toHaveTextContent(
      /^Enter a whole number from 1 minute to 365 days\.$/
    );
    expect(limitPart('save')).toBeDisabled();
  });

  it('moves the focus into the limit panel when it opens, and back to its button when it closes', async () => {
    await renderTab([sixHourConsent('t1', ALICE)]);
    const button = screen.getByTestId('credential-token-limit-button-t1');

    fireEvent.click(button);
    expect(limitPart('input')).toHaveFocus();
    expect(button).toHaveAttribute('aria-controls', 'credential-token-limit-panel-t1');
    expect(limitPart('panel')).toHaveAccessibleName('Limit duration · GitHub');
    fireEvent.click(limitPart('cancel'));
    expect(button).toHaveFocus();

    fireEvent.click(button);
    expect(limitPart('input')).toHaveFocus();
    fireEvent.change(limitPart('input'), { target: { value: '2' } });
    answerWith(true, { consent_expires_at: fromNow(HOUR) });
    fireEvent.click(limitPart('save'));

    await waitFor(() => expect(screen.queryByTestId('credential-token-limit-panel-t1')).toBeNull());
    expect(button).toHaveFocus();
  });

  it('says a limit did not reach the gateway, ties that to the field and lets it be saved again', async () => {
    await renderTab([sixHourConsent('t1', ALICE)]);
    fireEvent.click(screen.getByTestId('credential-token-limit-button-t1'));
    fireEvent.change(limitPart('input'), { target: { value: '2' } });

    mockFetch.mockRejectedValue(new TypeError('Failed to fetch'));
    fireEvent.click(limitPart('save'));

    expect(await screen.findByTestId('credential-token-limit-error-t1')).toHaveTextContent(
      /^The gateway could not be reached\.$/
    );
    expect(limitPart('input')).toHaveAttribute(
      'aria-describedby',
      'credential-token-limit-preview-t1 credential-token-limit-error-t1'
    );
    expect(limitPart('save')).toBeEnabled();
    expect(consentEndOf('t1')).toHaveTextContent(/\(in 4 hours\)$/);
    expect(showToast).not.toHaveBeenCalled();
  });

  /** Holds every later request until the function it returns is called with the answer. */
  const holdRequests = () => {
    let finish: (value: unknown) => void = () => undefined;
    mockFetch.mockImplementation(
      () =>
        new Promise(resolve => {
          finish = resolve;
        })
    );
    return (value: unknown) => act(async () => finish(value));
  };

  it('sends a limit once, however often Save is clicked while it is being saved', async () => {
    await renderTab([sixHourConsent('t1', ALICE)]);
    fireEvent.click(screen.getByTestId('credential-token-limit-button-t1'));
    fireEvent.change(limitPart('input'), { target: { value: '2' } });

    const finish = holdRequests();
    fireEvent.click(limitPart('save'));
    expect(limitPart('save')).toBeDisabled();
    expect(limitPart('save')).toHaveAttribute('aria-busy', 'true');
    expect(limitPart('cancel')).toBeDisabled();
    fireEvent.click(limitPart('save'));
    expect(puts()).toHaveLength(1);

    await finish(answer({ consent_expires_at: fromNow(HOUR) }));
    await waitFor(() => expect(screen.queryByTestId('credential-token-limit-panel-t1')).toBeNull());
    expect(puts()).toHaveLength(1);
  });

  it("keeps another delegation's limit panel open when an earlier save finishes", async () => {
    await renderTab([sixHourConsent('t1', ALICE), sixHourConsent('t2', BOB)]);
    fireEvent.click(screen.getByTestId('credential-token-limit-button-t1'));
    fireEvent.change(limitPart('input'), { target: { value: '2' } });
    const finish = holdRequests();
    fireEvent.click(limitPart('save'));

    fireEvent.click(screen.getByTestId('credential-token-limit-button-t2'));
    expect(screen.queryByTestId('credential-token-limit-panel-t1')).toBeNull();
    expect(limitPart('input', 't2')).toHaveFocus();
    await finish(answer({ consent_expires_at: fromNow(HOUR) }));

    await waitFor(() =>
      expect(consentEndOf('t1')).toHaveTextContent(/\(in (59 minutes|1 hour)\)$/)
    );
    expect(limitPart('panel', 't2')).toBeInTheDocument();
    expect(limitPart('input', 't2')).toHaveFocus();
    expect(consentEndOf('t2')).toHaveTextContent(/\(in 4 hours\)$/);
    expect(showToast).toHaveBeenCalledWith(
      'success',
      expect.stringMatching(/^Limit saved\. GitHub access ends /)
    );
  });

  it('says so when the gateway saves a limit without saying when the consent now ends', async () => {
    await renderTab([sixHourConsent('t1', ALICE)]);
    fireEvent.click(screen.getByTestId('credential-token-limit-button-t1'));
    fireEvent.change(limitPart('input'), { target: { value: '2' } });

    answerWith(true, { id: 't1' });
    fireEvent.click(limitPart('save'));

    expect(await screen.findByTestId('credential-token-limit-error-t1')).toHaveTextContent(
      'The gateway saved the limit but did not say when the consent now ends.'
    );
    expect(showToast).not.toHaveBeenCalledWith('success', expect.anything());
    await waitFor(() => expect(reads()).toHaveLength(2));
  });

  /** A gateway whose vault holds `held()` whenever it is read, and answers a change with `change`. */
  const gatewayReads = (held: () => unknown[], change: () => unknown) =>
    mockFetch.mockImplementation((url: string, options?: { method?: string }) =>
      Promise.resolve(
        options?.method
          ? change()
          : answer(url === '/api/v1/credential-providers' ? [GITHUB] : held())
      )
    );

  it('drops a delegation the gateway no longer holds once its revoke is refused as not found', async () => {
    let held = [token('t1', ALICE), token('t2', BOB)];
    gatewayReads(
      () => held,
      () => {
        held = held.slice(1);
        return answer({ error: 'Delegation token not found' }, 404, 'Not Found');
      }
    );
    render(<Tab />);
    const button = await screen.findByTestId('credential-token-revoke-button-t1');
    const kept = row('t2');

    fireEvent.click(button);
    fireEvent.click(button);

    await waitFor(() => expect(rowIds()).toEqual(['t2']));
    expect(showToast).toHaveBeenCalledWith('error', 'Not revoked: Delegation token not found');
    expect(row('t2')).toBe(kept);
    expect(reads()).toHaveLength(2);
  });

  it('reads the vault again when a limit is refused because the consent changed', async () => {
    let held = [sixHourConsent('t1', ALICE)];
    gatewayReads(
      () => held,
      () => {
        held = [token('t1', ALICE, { consent_expires_at: fromNow(9 * HOUR) })];
        return answer(
          {
            code: 'consent_changed',
            error: 'The consent changed while it was being limited. Read it again',
          },
          409,
          'Conflict'
        );
      }
    );
    render(<Tab />);
    fireEvent.click(await screen.findByTestId('credential-token-limit-button-t1'));
    fireEvent.change(limitPart('input'), { target: { value: '2' } });
    fireEvent.click(limitPart('save'));

    expect(await screen.findByTestId('credential-token-limit-error-t1')).toHaveTextContent(
      'The consent changed while it was being limited. Read it again'
    );
    await waitFor(() => expect(consentEndOf('t1')).toHaveTextContent(/\(in 8 hours\)$/));
    expect(limitPart('panel')).toBeInTheDocument();
    expect(reads()).toHaveLength(2);
  });

  it('closes the limit panel once the search hides its row, and leaves it closed when the row is back', async () => {
    gatewayHolds([sixHourConsent('t1', ALICE)], [GITHUB]);
    const { rerender } = render(<Tab />);
    fireEvent.click(await screen.findByTestId('credential-token-limit-button-t1'));
    expect(limitPart('panel')).toBeInTheDocument();

    rerender(<Tab externalSearchTerm="no such token" />);
    expect(rowIds()).toEqual([]);
    rerender(<Tab externalSearchTerm="" />);

    expect(rowIds()).toEqual(['t1']);
    expect(screen.queryByTestId('credential-token-limit-panel-t1')).toBeNull();
  });

  it('closes the limit panel when another page is opened', async () => {
    const ids = Array.from({ length: 11 }, (_, index) => `t${String(index + 1).padStart(2, '0')}`);
    await renderTab(ids.map(id => sixHourConsent(id, ALICE)));
    fireEvent.click(screen.getByTestId('credential-token-limit-button-t01'));
    expect(limitPart('panel', 't01')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: '2' }));
    fireEvent.click(screen.getByRole('button', { name: '1' }));

    expect(rowIds()).toHaveLength(10);
    expect(screen.queryByTestId('credential-token-limit-panel-t01')).toBeNull();
  });
});
