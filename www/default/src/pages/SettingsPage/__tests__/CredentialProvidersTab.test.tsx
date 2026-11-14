import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import CredentialProvidersTab, { providerDeleteError } from '../CredentialProvidersTab';
import { apiClient } from '../../../api';

jest.mock('../../../api', () => ({
  apiClient: { get: jest.fn(), put: jest.fn(), post: jest.fn(), fetch: jest.fn() },
}));
const mockHasPermission = jest.fn();
jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: mockHasPermission, loading: false }),
}));
jest.mock('../../../utils/toaster', () => ({ showToast: jest.fn() }));

const mockFetch = apiClient.fetch as jest.Mock;

const item = (name: string, token_endpoint: string, resource: string | null) => ({
  id: name,
  name,
  provider_id: name,
  provider_type: 'oauth2_client_credentials',
  token_endpoint,
  resource,
  default_scopes: [],
  token_refresh_enabled: false,
  created_at: '2026-10-30T00:00:00Z',
  updated_at: '2026-10-30T00:00:00Z',
});

describe('CredentialProvidersTab', () => {
  it('flags only the Entra v2.0 provider that sets a resource', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve([
          item(
            'entra-resource',
            'https://login.microsoftonline.com/t/oauth2/v2.0/token',
            'https://ai.azure.com'
          ),
          item('entra-scope', 'https://login.microsoftonline.com/t/oauth2/v2.0/token', null),
          item('google', 'https://oauth2.googleapis.com/token', 'https://api.example'),
        ]),
    });
    render(
      <MemoryRouter>
        <CredentialProvidersTab />
      </MemoryRouter>
    );
    const flagged = await screen.findByRole('row', { name: /^entra-resource/ });
    const badge = within(flagged).getByTestId('credential-provider-entra-resource-badge');
    expect(badge).toHaveAttribute('title', expect.stringContaining('AADSTS901002'));
    expect(screen.getAllByTestId('credential-provider-entra-resource-badge')).toHaveLength(1);
  });

  it('flags an external consent Entra v2.0 provider only while it sends its resource', async () => {
    const external = (name: string, send_resource?: boolean) => ({
      ...item(
        name,
        'https://login.microsoftonline.com/t/oauth2/v2.0/token',
        'https://graph.microsoft.com'
      ),
      provider_type: 'oauth2_authorization_code',
      issuer: 'https://login.microsoftonline.com/t/v2.0',
      ...(send_resource === undefined ? {} : { send_resource }),
    });
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve([external('entra-sends'), external('entra-quiet', false)]),
    });
    render(
      <MemoryRouter>
        <CredentialProvidersTab />
      </MemoryRouter>
    );
    const flagged = await screen.findByRole('row', { name: /^entra-sends/ });
    const badge = within(flagged).getByTestId('credential-provider-entra-resource-badge');
    expect(badge).toHaveAttribute(
      'title',
      expect.stringContaining('re-create the provider with send_resource set to false')
    );
    expect(screen.getAllByTestId('credential-provider-entra-resource-badge')).toHaveLength(1);
  });

  it('says why a delete was refused, naming the surface that binds the provider', () => {
    const body = JSON.stringify({
      error: 'The credential provider is bound by an agent surface; remove the binding first',
      code: 'provider_in_use',
      surface_id: 'billing-agent',
    });
    expect(providerDeleteError(409, body, '')).toBe(
      'The credential provider is bound by an agent surface; remove the binding first (surface billing-agent) (409)'
    );
    expect(
      providerDeleteError(503, JSON.stringify({ error: 'The vault is unavailable' }), '')
    ).toBe('The vault is unavailable (503)');
    expect(providerDeleteError(500, '', '')).toBe('Request failed (500)');
  });

  describe('client authentication badge', () => {
    const renderList = async (records: Record<string, unknown>[]) => {
      mockFetch.mockResolvedValue({ ok: true, json: () => Promise.resolve(records) });
      render(
        <MemoryRouter>
          <CredentialProvidersTab />
        </MemoryRouter>
      );
      await screen.findByRole('row', { name: new RegExp(`^${records[0].name}`) });
    };
    const jwt = (name: string, extra: Record<string, unknown>) => ({
      ...item(name, 'https://hydra.example/token', null),
      provider_type: 'oauth2_jwt_bearer',
      ...extra,
    });

    it.each([
      ['none', 'Client ID only'],
      ['client_secret_basic', 'HTTP Basic'],
      ['client_secret_post', 'Form body'],
    ])('badges a JWT Bearer provider whose client authentication is %s', async (method, label) => {
      await renderList([jwt('hydra', { client_authentication: method })]);
      const row = screen.getByRole('row', { name: /^hydra/ });
      const badge = within(row).getByTestId('credential-provider-client-authentication-badge');
      expect(badge).toHaveTextContent(label);
      expect(badge).toHaveClass('text-bg-secondary');
    });

    it('shows no badge for a client authentication the dashboard does not know', async () => {
      await renderList([jwt('odd', { client_authentication: 'private_key_jwt' })]);
      expect(
        screen.queryByTestId('credential-provider-client-authentication-badge')
      ).not.toBeInTheDocument();
    });

    it('shows no badge without a client authentication or on another type', async () => {
      await renderList([
        jwt('google', {}),
        item('cc', 'https://idp.example/token', null),
        { ...item('cc2', 'https://idp.example/token', null), client_authentication: 'none' },
      ]);
      expect(
        screen.queryByTestId('credential-provider-client-authentication-badge')
      ).not.toBeInTheDocument();
    });
  });
});

describe('CredentialProvidersTab deactivation', () => {
  const consented = (id: string, deactivated_at?: string) => ({
    ...item(id, 'https://github.com/login/oauth/access_token', null),
    provider_type: 'oauth2_authorization_code',
    ...(deactivated_at ? { deactivated_at } : {}),
  });
  const posts = () => mockFetch.mock.calls.filter(([, options]) => options?.method === 'POST');

  const renderTab = async (
    providers: Record<string, unknown>[],
    answer?: Record<string, unknown>
  ) => {
    mockHasPermission.mockReturnValue(true);
    mockFetch.mockImplementation((_url: string, options?: { method?: string }) =>
      Promise.resolve({
        ok: true,
        statusText: 'OK',
        text: () => Promise.resolve(''),
        json: () => Promise.resolve(options?.method === 'POST' ? answer : providers),
      })
    );
    render(
      <MemoryRouter>
        <CredentialProvidersTab />
      </MemoryRouter>
    );
    await screen.findByRole('row', { name: new RegExp(`^${providers[0].name}`) });
  };

  it('deactivates a provider a person consents to only on a second click, and never deletes it', async () => {
    await renderTab([consented('github')], {
      ...consented('github'),
      deactivated_at: '2026-11-13T10:00:00Z',
    });
    expect(screen.queryByTestId('credential-provider-delete-button-github')).toBeNull();
    const button = screen.getByTestId('credential-provider-deactivate-button-github');

    fireEvent.click(button);
    expect(button).toHaveTextContent('Click again to deactivate');
    expect(posts()).toHaveLength(0);

    fireEvent.click(button);
    await waitFor(() => expect(posts()).toHaveLength(1));
    expect(posts()[0][0]).toBe('/api/v1/credential-providers/github/deactivate');
    expect(
      await screen.findByTestId('credential-provider-deactivated-badge-github')
    ).toHaveTextContent('Deactivated');
    expect(screen.getByRole('row', { name: /^github/ })).toBeInTheDocument();
    expect(screen.queryByTestId('credential-provider-deactivate-button-github')).toBeNull();
    expect(screen.getByTestId('credential-provider-activate-button-github')).toBeInTheDocument();
  });

  it('activates a deactivated provider again', async () => {
    await renderTab([consented('github', '2026-11-13T10:00:00Z')], consented('github'));
    expect(screen.getByTestId('credential-provider-deactivated-badge-github')).toBeInTheDocument();

    fireEvent.click(screen.getByTestId('credential-provider-activate-button-github'));

    await waitFor(() => expect(posts()).toHaveLength(1));
    expect(posts()[0][0]).toBe('/api/v1/credential-providers/github/activate');
    await waitFor(() =>
      expect(screen.queryByTestId('credential-provider-deactivated-badge-github')).toBeNull()
    );
    expect(screen.getByTestId('credential-provider-deactivate-button-github')).toBeInTheDocument();
  });

  it('keeps Delete, and offers no Deactivate, on a provider nobody consents to', async () => {
    await renderTab([item('billing', 'https://oauth2.googleapis.com/token', null)]);

    expect(screen.getByTestId('credential-provider-delete-button-billing')).toBeInTheDocument();
    expect(screen.queryByTestId('credential-provider-deactivate-button-billing')).toBeNull();
    expect(screen.queryByTestId('credential-provider-activate-button-billing')).toBeNull();
  });
});
