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

  const puts = () => mockFetch.mock.calls.filter(([, options]) => options?.method === 'PUT');
  /** Answers every later request with `answer`, as a success or as a `400`. */
  const answerWith = (ok: boolean, answer: unknown) =>
    mockFetch.mockImplementation(() =>
      Promise.resolve({
        ok,
        status: ok ? 200 : 400,
        statusText: ok ? 'OK' : 'Bad Request',
        json: () => Promise.resolve(answer),
      })
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
});
