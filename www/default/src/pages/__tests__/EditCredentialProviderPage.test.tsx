import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import EditCredentialProviderPage from '../EditCredentialProviderPage';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({
  apiClient: { get: jest.fn(), put: jest.fn(), post: jest.fn(), fetch: jest.fn() },
}));
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: () => true, loading: false }),
}));
jest.mock('../../context/PageTitleContext', () => ({ usePageTitle: () => undefined }));

const mockFetch = apiClient.fetch as jest.Mock;

const ENTRA_V2 = 'https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token';
const WARNING = 'credential-provider-entra-resource-warning';

const provider = (resource: string | null) => ({
  id: 'p1',
  name: 'Foundry',
  provider_id: 'foundry',
  provider_type: 'oauth2_client_credentials',
  token_endpoint: ENTRA_V2,
  client_id_secret_ref: 'CLIENT_ID',
  client_secret_secret_ref: 'CLIENT_SECRET',
  default_scopes: [],
  token_refresh_enabled: false,
  resource,
});

const renderPage = (record: ReturnType<typeof provider>) => {
  mockFetch.mockImplementation((url: string) =>
    Promise.resolve(
      url.startsWith('/api/v1/credential-providers/')
        ? { ok: true, json: () => Promise.resolve(record) }
        : { ok: false, json: () => Promise.resolve([]) }
    )
  );
  return render(
    <MemoryRouter initialEntries={['/credential-providers/p1']}>
      <Routes>
        <Route path="/credential-providers/:id" element={<EditCredentialProviderPage />} />
      </Routes>
    </MemoryRouter>
  );
};

describe('EditCredentialProviderPage Entra resource warning', () => {
  beforeEach(() => jest.clearAllMocks());

  it('warns that an Entra v2.0 endpoint rejects the resource the provider sets', async () => {
    renderPage(provider('https://ai.azure.com'));
    expect(await screen.findByTestId(WARNING)).toHaveTextContent(
      'This provider sets resource "https://ai.azure.com", which the Microsoft identity platform v2.0 token endpoint rejects (AADSTS901002)'
    );
    expect(screen.getByTestId(WARNING)).toHaveTextContent('"https://ai.azure.com/.default"');
  });

  it('does not warn without a resource', async () => {
    renderPage(provider(null));
    expect(await screen.findByDisplayValue(ENTRA_V2)).toBeInTheDocument();
    expect(screen.queryByTestId(WARNING)).not.toBeInTheDocument();
  });

  it('stops warning once the token endpoint is not an Entra v2.0 endpoint', async () => {
    renderPage(provider('https://ai.azure.com'));
    await screen.findByTestId(WARNING);
    fireEvent.change(screen.getByDisplayValue(ENTRA_V2), {
      target: { value: 'https://oauth2.googleapis.com/token' },
    });
    expect(screen.queryByTestId(WARNING)).not.toBeInTheDocument();
  });
});

describe('EditCredentialProviderPage external consent provider', () => {
  beforeEach(() => jest.clearAllMocks());

  it('shows the fixed settings as read-only and saves only the editable fields', async () => {
    const external = {
      id: 'p1',
      name: 'Linear',
      provider_id: 'linear',
      provider_type: 'oauth2_authorization_code',
      issuer: 'https://linear.example',
      authorization_endpoint: 'https://linear.example/authorize',
      token_endpoint: 'https://linear.example/token',
      token_endpoint_auth_method: 'none',
      client_id: 'client-1',
      callback_url: 'https://gateway.example/callback/linear',
      resource: 'https://linear.example/mcp',
      default_scopes: ['read'],
      token_refresh_enabled: true,
    };
    mockFetch.mockImplementation((url: string) =>
      Promise.resolve(
        url.startsWith('/api/v1/credential-providers/')
          ? { ok: true, json: () => Promise.resolve(external), text: () => Promise.resolve('') }
          : { ok: false, json: () => Promise.resolve([]) }
      )
    );
    render(
      <MemoryRouter initialEntries={['/credential-providers/p1']}>
        <Routes>
          <Route path="/credential-providers/:id" element={<EditCredentialProviderPage />} />
        </Routes>
      </MemoryRouter>
    );
    expect(await screen.findByTestId('credential-provider-external-notice')).toHaveTextContent(
      'https://linear.example'
    );
    expect(screen.queryByLabelText(/Provider Type/)).not.toBeInTheDocument();
    fireEvent.change(screen.getByDisplayValue('read'), { target: { value: 'read, write' } });
    fireEvent.click(screen.getByTestId('credential-provider-editor-save-button'));
    await waitFor(() =>
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/credential-providers/p1',
        expect.objectContaining({ method: 'PUT' })
      )
    );
    const [, init] = mockFetch.mock.calls.find(([, options]) => options?.method === 'PUT')!;
    expect(JSON.parse(init.body)).toEqual({
      name: 'Linear',
      default_scopes: ['read', 'write'],
      token_refresh_enabled: true,
    });
  });
});

describe('EditCredentialProviderPage tenant-aware secrets and https error', () => {
  beforeEach(() => jest.clearAllMocks());

  const secrets = [
    { id: 's1', secret_id: 'WIDE_ID', name: 'Wide id', tenant_id: null },
    { id: 's2', secret_id: 'ACME_ID', name: 'Acme id', tenant_id: 'acme' },
    { id: 's3', secret_id: 'ACME_SECRET', name: 'Acme secret', tenant_id: 'acme' },
    { id: 's4', secret_id: 'OTHER_ID', name: 'Other id', tenant_id: 'other' },
  ];

  const optionTexts = (el: HTMLElement) =>
    within(el)
      .getAllByRole('option')
      .map(o => o.textContent);

  const renderWith = (record: Record<string, unknown>) => {
    mockFetch.mockImplementation((url: string) => {
      if (url.startsWith('/api/v1/credential-providers/')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(record) });
      }
      if (url.startsWith('/api/v1/secrets/')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(secrets) });
      }
      return Promise.resolve({ ok: false, json: () => Promise.resolve([]) });
    });
    return render(
      <MemoryRouter initialEntries={['/credential-providers/p1']}>
        <Routes>
          <Route path="/credential-providers/:id" element={<EditCredentialProviderPage />} />
        </Routes>
      </MemoryRouter>
    );
  };

  it('offers only the tenant provider its own tenant secrets and labels a stored appliance-wide one', async () => {
    renderWith({
      ...provider(null),
      tenant_id: 'acme',
      client_id_secret_ref: 'WIDE_ID',
      client_secret_secret_ref: 'ACME_SECRET',
    });
    await screen.findByDisplayValue(ENTRA_V2);
    const clientId = screen.getByRole('combobox', { name: /^Client ID Secret/ });
    expect(optionTexts(clientId)).toEqual([
      '-- Select a secret --',
      'Acme id (ACME_ID)',
      'Acme secret (ACME_SECRET)',
      'Wide id (WIDE_ID, appliance-wide, stops working when enforced)',
    ]);
    expect(clientId.value).toBe('WIDE_ID');
    const clientSecret = screen.getByRole('combobox', { name: /^Client Secret/ });
    expect(optionTexts(clientSecret)).toEqual([
      '-- Select a secret --',
      'Acme id (ACME_ID)',
      'Acme secret (ACME_SECRET)',
    ]);
  });

  it('offers an appliance-wide provider only appliance-wide secrets', async () => {
    renderWith({ ...provider(null), client_id_secret_ref: 'WIDE_ID' });
    await screen.findByDisplayValue(ENTRA_V2);
    const clientId = screen.getByRole('combobox', { name: /^Client ID Secret/ });
    expect(optionTexts(clientId)).toEqual(['-- Select a secret --', 'Wide id (WIDE_ID)']);
  });

  it('warns about an http token endpoint without marking the field invalid, and not for https', async () => {
    renderWith({ ...provider(null), token_endpoint: 'http://idp.internal/token' });
    const warning = await screen.findByTestId('credential-provider-token-endpoint-https-warning');
    expect(warning).toHaveClass('alert-warning');
    expect(warning).toHaveTextContent('credential_policy.insecure_token_endpoints');
    expect(warning).toHaveTextContent(
      'New or changed http token endpoints are refused unless listed by exact URL'
    );
    expect(warning).toHaveTextContent('still accepted while token_endpoint_https is warn');
    expect(warning).not.toHaveTextContent('refuses to save any other http endpoint');
    const input = screen.getByDisplayValue('http://idp.internal/token');
    expect(input).not.toHaveClass('is-invalid');
    fireEvent.change(input, { target: { value: 'https://idp.internal/token' } });
    expect(
      screen.queryByTestId('credential-provider-token-endpoint-https-warning')
    ).not.toBeInTheDocument();
  });
});

describe('EditCredentialProviderPage callback URL', () => {
  beforeEach(() => jest.clearAllMocks());

  it('saves a callback URL ending in the provider stored callback path', async () => {
    const record = {
      id: 'p1',
      name: 'GitHub',
      provider_id: 'github',
      provider_type: 'oauth2_authorization_code',
      authorization_endpoint: 'https://github.com/login/oauth/authorize',
      token_endpoint: 'https://github.com/login/oauth/access_token',
      client_id_secret_ref: 'CLIENT_ID',
      client_secret_secret_ref: 'CLIENT_SECRET',
      default_scopes: ['repo'],
      token_refresh_enabled: true,
      callback_path: '/old/route/github',
      callback_url: 'https://gw.example/old/route/github',
    };
    mockFetch.mockImplementation((url: string) => {
      if (url.startsWith('/api/v1/credential-providers/')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(record),
          text: () => Promise.resolve(''),
        });
      }
      if (url === '/api/v1/config/surface-routing') {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              available_listen_addresses: ['https://gw.example'],
              oauth_callback_route: '/v1/identity/oauth/callback',
            }),
        });
      }
      return Promise.resolve({ ok: false, json: () => Promise.resolve([]) });
    });
    render(
      <MemoryRouter initialEntries={['/credential-providers/p1']}>
        <Routes>
          <Route path="/credential-providers/:id" element={<EditCredentialProviderPage />} />
        </Routes>
      </MemoryRouter>
    );
    expect(await screen.findByText('https://gw.example/old/route/github')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('credential-provider-editor-save-button'));
    await waitFor(() =>
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/credential-providers/p1',
        expect.objectContaining({ method: 'PUT' })
      )
    );
    const [, init] = mockFetch.mock.calls.find(([, options]) => options?.method === 'PUT')!;
    expect(JSON.parse(init.body).callback_url).toBe('https://gw.example/old/route/github');
  });
});
