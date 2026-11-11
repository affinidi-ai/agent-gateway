import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import EditCredentialProviderPage from '../EditCredentialProviderPage';
import { apiClient } from '../../api';
import { showToast } from '../../utils/toaster';

jest.mock('../../api', () => ({
  apiClient: { get: jest.fn(), put: jest.fn(), post: jest.fn(), fetch: jest.fn() },
}));
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: () => true, loading: false }),
}));
jest.mock('../../context/PageTitleContext', () => ({ usePageTitle: () => undefined }));
jest.mock('../../utils/toaster', () => ({ showToast: jest.fn() }));

const mockFetch = apiClient.fetch as jest.Mock;
const mockShowToast = showToast as jest.Mock;

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

  const entraExternal = (send_resource?: boolean) => ({
    id: 'p1',
    name: 'Mail',
    provider_id: 'mail',
    provider_type: 'oauth2_authorization_code',
    issuer: 'https://login.microsoftonline.com/tenant-id/v2.0',
    authorization_endpoint: 'https://login.microsoftonline.com/tenant-id/oauth2/v2.0/authorize',
    token_endpoint: ENTRA_V2,
    token_endpoint_auth_method: 'none',
    client_id: 'client-1',
    callback_url: 'https://gateway.example/callback/mail',
    resource: 'https://graph.microsoft.com',
    default_scopes: ['Mail.Read'],
    token_refresh_enabled: true,
    ...(send_resource === undefined ? {} : { send_resource }),
  });

  const renderExternal = (record: Record<string, unknown>) => {
    mockFetch.mockImplementation((url: string) =>
      Promise.resolve(
        url.startsWith('/api/v1/credential-providers/')
          ? { ok: true, json: () => Promise.resolve(record) }
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
  };

  it('tells an Entra v2.0 provider that sends its resource to re-create it without sending it', async () => {
    renderExternal(entraExternal());
    expect(await screen.findByTestId(WARNING)).toHaveTextContent(
      're-create the provider with send_resource set to false'
    );
  });

  it('does not warn an Entra v2.0 provider that leaves its resource out', async () => {
    renderExternal(entraExternal(false));
    await screen.findByTestId('credential-provider-external-notice');
    expect(screen.queryByTestId(WARNING)).not.toBeInTheDocument();
  });

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
    expect(warning).toHaveTextContent('on a provider whose type is unchanged');
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

  const renderProvider = (record: Record<string, unknown>) => {
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
  };

  it('saves a stored callback URL behind a reverse proxy prefix unchanged', async () => {
    renderProvider({
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
      callback_path: '/v1/identity/oauth/callback/github',
      callback_url: 'https://gw.example/prefix/v1/identity/oauth/callback/github',
    });
    expect(
      await screen.findByText('https://gw.example/prefix/v1/identity/oauth/callback/github')
    ).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('credential-provider-editor-save-button'));
    await waitFor(() =>
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/credential-providers/p1',
        expect.objectContaining({ method: 'PUT' })
      )
    );
    const [, init] = mockFetch.mock.calls.find(([, options]) => options?.method === 'PUT')!;
    expect(JSON.parse(init.body).callback_url).toBe(
      'https://gw.example/prefix/v1/identity/oauth/callback/github'
    );
  });

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

  const CREATED = {
    id: 'cp-1',
    name: 'GitHub',
    provider_id: 'github',
    provider_type: 'oauth2_authorization_code',
    token_endpoint: 'https://github.com/login/oauth/access_token',
    client_id_secret_ref: 'CLIENT_ID',
    client_secret_secret_ref: 'CLIENT_SECRET',
    default_scopes: [],
    token_refresh_enabled: true,
    callback_path: '/v1/identity/oauth/callback/cp-1',
  };

  const renderNewProvider = (putAnswer: { ok: boolean; text?: string }) => {
    mockFetch.mockImplementation((url: string, init?: RequestInit) => {
      if (url === '/api/v1/config/surface-routing') {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              available_listen_addresses: ['https://gw.example', 'http://gw.internal'],
              oauth_callback_route: '/v1/identity/oauth/callback',
              gateway_base_url: 'https://gateway.example',
            }),
        });
      }
      if (url === '/api/v1/secrets/') {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve([
              { id: 's1', secret_id: 'CLIENT_ID', name: 'Client id', tenant_id: null },
              { id: 's2', secret_id: 'CLIENT_SECRET', name: 'Client secret', tenant_id: null },
            ]),
        });
      }
      if (url === '/api/v1/credential-providers' && init?.method === 'POST') {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(CREATED) });
      }
      if (url === '/api/v1/credential-providers/cp-1' && init?.method === 'PUT') {
        return Promise.resolve({
          ok: putAnswer.ok,
          status: putAnswer.ok ? 200 : 400,
          statusText: putAnswer.ok ? 'OK' : 'Bad Request',
          json: () => Promise.resolve({}),
          text: () => Promise.resolve(putAnswer.text ?? ''),
        });
      }
      if (url === '/api/v1/credential-providers/cp-1') {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(CREATED) });
      }
      return Promise.resolve({ ok: false, json: () => Promise.resolve([]) });
    });
    render(
      <MemoryRouter initialEntries={['/credential-providers/new']}>
        <Routes>
          <Route path="/credential-providers/new" element={<EditCredentialProviderPage />} />
          <Route path="/credential-providers/:id" element={<EditCredentialProviderPage />} />
        </Routes>
      </MemoryRouter>
    );
  };

  const fillProvider = async (providerType?: string) => {
    await screen.findByRole('option', { name: 'https://gw.example' });
    await screen.findAllByRole('option', { name: /CLIENT_SECRET/ });
    if (providerType) {
      fireEvent.change(screen.getByRole('combobox', { name: /^Provider Type/ }), {
        target: { value: providerType },
      });
    }
    fireEvent.change(screen.getByRole('textbox', { name: /^Name/ }), {
      target: { value: 'GitHub' },
    });
    fireEvent.change(screen.getByRole('textbox', { name: /^Token Endpoint/ }), {
      target: { value: 'https://github.com/login/oauth/access_token' },
    });
    fireEvent.change(screen.getByRole('combobox', { name: /^Client ID Secret/ }), {
      target: { value: 'CLIENT_ID' },
    });
    fireEvent.change(screen.getByRole('combobox', { name: /^Client Secret/ }), {
      target: { value: 'CLIENT_SECRET' },
    });
  };

  const chooseHost = (host = 'https://gw.example') =>
    fireEvent.change(screen.getByRole('combobox', { name: /^Callback URL Host/ }), {
      target: { value: host },
    });

  const calls = (method: string) =>
    mockFetch.mock.calls.filter(([, options]) => options?.method === method);

  it('creates a provider without a callback URL, then saves the one the created path gives', async () => {
    renderNewProvider({ ok: true });
    await fillProvider();
    chooseHost();
    expect(
      await screen.findByTestId('credential-provider-callback-url-after-create')
    ).toBeInTheDocument();

    fireEvent.click(screen.getByTestId('credential-provider-editor-save-button'));
    await waitFor(() => expect(calls('PUT')).toHaveLength(1));
    const [[, created]] = calls('POST');
    expect(JSON.parse(created.body)).not.toHaveProperty('callback_url');
    const [[url, updated]] = calls('PUT');
    expect(url).toBe('/api/v1/credential-providers/cp-1');
    expect(JSON.parse(updated.body)).toEqual({
      callback_url: 'https://gw.example/v1/identity/oauth/callback/cp-1',
    });
    await waitFor(() =>
      expect(mockFetch).toHaveBeenCalledWith('/api/v1/credential-providers/cp-1')
    );
    expect(await screen.findByRole('button', { name: /Save/ })).toBeInTheDocument();
  });

  it('creates a provider with no host in one request and shows the gateway Callback URL it gets', async () => {
    renderNewProvider({ ok: true });
    await fillProvider();
    fireEvent.click(screen.getByTestId('credential-provider-editor-save-button'));

    await waitFor(() =>
      expect(mockFetch).toHaveBeenCalledWith('/api/v1/credential-providers/cp-1')
    );
    expect(calls('POST')).toHaveLength(1);
    expect(calls('PUT')).toHaveLength(0);
    expect(await screen.findByTestId('credential-provider-callback-url')).toHaveTextContent(
      'https://gateway.example/v1/identity/oauth/callback/cp-1'
    );
  });

  it('opens the created provider when its callback URL is refused, so saving again updates it', async () => {
    renderNewProvider({
      ok: false,
      text: JSON.stringify({ error: 'callback_url must be an https URL with a host' }),
    });
    await fillProvider();
    chooseHost();
    fireEvent.click(screen.getByTestId('credential-provider-editor-save-button'));

    await waitFor(() =>
      expect(mockShowToast).toHaveBeenCalledWith(
        'error',
        expect.stringContaining('Provider created, but its Callback URL was not saved')
      )
    );
    expect(mockShowToast.mock.calls[0][1]).toContain(
      'callback_url must be an https URL with a host'
    );
    await waitFor(() =>
      expect(mockFetch).toHaveBeenCalledWith('/api/v1/credential-providers/cp-1')
    );
    expect(await screen.findByRole('button', { name: /Save/ })).toBeInTheDocument();

    chooseHost();
    fireEvent.click(screen.getByTestId('credential-provider-editor-save-button'));
    await waitFor(() => expect(calls('PUT')).toHaveLength(2));
    expect(calls('POST')).toHaveLength(1);
    const [, [, retried]] = calls('PUT');
    expect(JSON.parse(retried.body).callback_url).toBe(
      'https://gw.example/v1/identity/oauth/callback/cp-1'
    );
  });

  it('keeps showing the stored Callback URL when the host is cleared, since it stays in use', async () => {
    mockFetch.mockImplementation((url: string) => {
      if (url === '/api/v1/config/surface-routing') {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              available_listen_addresses: ['https://gw.example'],
              gateway_base_url: 'https://gateway.example',
            }),
        });
      }
      if (url === '/api/v1/credential-providers/cp-1') {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              ...CREATED,
              callback_url: 'https://gw.example/v1/identity/oauth/callback/cp-1',
            }),
        });
      }
      return Promise.resolve({ ok: false, json: () => Promise.resolve([]) });
    });
    render(
      <MemoryRouter initialEntries={['/credential-providers/cp-1']}>
        <Routes>
          <Route path="/credential-providers/:id" element={<EditCredentialProviderPage />} />
        </Routes>
      </MemoryRouter>
    );
    await screen.findByRole('option', { name: 'https://gw.example' });
    chooseHost('');
    expect(await screen.findByTestId('credential-provider-callback-url')).toHaveTextContent(
      'https://gw.example/v1/identity/oauth/callback/cp-1'
    );
  });

  it('refuses an http Callback URL Host before creating anything', async () => {
    renderNewProvider({ ok: true });
    await fillProvider();
    chooseHost('http://gw.internal');
    fireEvent.click(screen.getByTestId('credential-provider-editor-save-button'));

    expect(
      await screen.findByText(/The Callback URL Host must be an https address/)
    ).toBeInTheDocument();
    expect(calls('POST')).toHaveLength(0);
    expect(calls('PUT')).toHaveLength(0);
  });

  it('creates a provider of another type with one request and no callback URL save', async () => {
    renderNewProvider({ ok: true });
    await fillProvider('oauth2_client_credentials');
    fireEvent.click(screen.getByTestId('credential-provider-editor-save-button'));

    await waitFor(() => expect(calls('POST')).toHaveLength(1));
    await waitFor(() => expect(mockShowToast).toHaveBeenCalledWith('success', 'Provider created'));
    expect(calls('PUT')).toHaveLength(0);
    expect(mockFetch).not.toHaveBeenCalledWith('/api/v1/credential-providers/cp-1');
  });
});

describe('EditCredentialProviderPage JWT Bearer client authentication', () => {
  beforeEach(() => jest.clearAllMocks());

  const secrets = [
    { id: 's1', secret_id: 'HYDRA_ID', name: 'Hydra id', tenant_id: null },
    { id: 's2', secret_id: 'HYDRA_SECRET', name: 'Hydra secret', tenant_id: null },
    { id: 's3', secret_id: 'SA_KEY', name: 'Key', tenant_id: null },
  ];

  const jwtBearer = (extra: Record<string, unknown> = {}) => ({
    id: 'p1',
    name: 'Hydra',
    provider_id: 'hydra',
    provider_type: 'oauth2_jwt_bearer',
    token_endpoint: 'https://hydra.example/oauth2/token',
    jwt_issuer: 'issuer',
    jwt_subject: 'subject',
    jwt_signing_key_secret_ref: 'SA_KEY',
    default_scopes: [],
    token_refresh_enabled: false,
    ...extra,
  });

  const renderJwt = (record: Record<string, unknown>, putResponse: object = { ok: true }) => {
    mockFetch.mockImplementation((url: string, init?: { method?: string }) => {
      if (init?.method === 'PUT') return Promise.resolve(putResponse);
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

  const select = () =>
    screen.getByTestId('credential-provider-client-authentication-select') as HTMLSelectElement;

  const savedBody = () => {
    const put = mockFetch.mock.calls.find(([, init]) => init?.method === 'PUT');
    return JSON.parse(put[1].body);
  };

  it('offers the four client authentication choices, with none sent by default', async () => {
    renderJwt(jwtBearer());
    await screen.findByDisplayValue('https://hydra.example/oauth2/token');
    expect(select().value).toBe('');
    expect(Array.from(select().options).map(o => [o.value, o.textContent])).toEqual([
      ['', 'Not sent (default)'],
      ['none', 'Client ID only (public client)'],
      ['client_secret_basic', 'HTTP Basic'],
      ['client_secret_post', 'Form body'],
    ]);
    expect(screen.queryByRole('combobox', { name: /^Client ID Secret/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('combobox', { name: /^Client Secret/ })).not.toBeInTheDocument();
  });

  it('shows the client pickers a stored method needs and saves them', async () => {
    renderJwt(
      jwtBearer({
        client_authentication: 'client_secret_basic',
        client_id_secret_ref: 'HYDRA_ID',
        client_secret_secret_ref: 'HYDRA_SECRET',
      })
    );
    await screen.findByDisplayValue('https://hydra.example/oauth2/token');
    expect(select().value).toBe('client_secret_basic');
    expect(screen.getByRole('combobox', { name: /^Client ID Secret/ })).toHaveValue('HYDRA_ID');
    expect(screen.getByRole('combobox', { name: /^Client Secret/ })).toHaveValue('HYDRA_SECRET');

    fireEvent.click(screen.getByRole('button', { name: /save/i }));
    await waitFor(() => expect(savedBody().client_authentication).toBe('client_secret_basic'));
    expect(savedBody()).toMatchObject({
      client_id_secret_ref: 'HYDRA_ID',
      client_secret_secret_ref: 'HYDRA_SECRET',
    });
  });

  it('hides the client secret picker for a public client and saves it blank', async () => {
    renderJwt(jwtBearer({ client_authentication: 'none', client_id_secret_ref: 'HYDRA_ID' }));
    await screen.findByDisplayValue('https://hydra.example/oauth2/token');
    expect(screen.getByRole('combobox', { name: /^Client ID Secret/ })).toBeInTheDocument();
    expect(screen.queryByRole('combobox', { name: /^Client Secret/ })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /save/i }));
    await waitFor(() => expect(savedBody().client_authentication).toBe('none'));
    expect(savedBody()).toMatchObject({
      client_id_secret_ref: 'HYDRA_ID',
      client_secret_secret_ref: '',
    });
  });

  it('shows no client pickers again once the method is cleared, and saves an empty method', async () => {
    renderJwt(jwtBearer({ client_authentication: 'none', client_id_secret_ref: 'HYDRA_ID' }));
    await screen.findByDisplayValue('https://hydra.example/oauth2/token');
    fireEvent.change(select(), { target: { value: '' } });
    expect(screen.queryByRole('combobox', { name: /^Client ID Secret/ })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /save/i }));
    await waitFor(() => expect(savedBody().client_authentication).toBe(''));
    expect(savedBody().client_id_secret_ref).toBe('');
  });

  it('clears the client secret when switching from HTTP Basic to Client ID only', async () => {
    renderJwt(
      jwtBearer({
        client_authentication: 'client_secret_basic',
        client_id_secret_ref: 'HYDRA_ID',
        client_secret_secret_ref: 'HYDRA_SECRET',
      })
    );
    await screen.findByDisplayValue('https://hydra.example/oauth2/token');
    fireEvent.change(select(), { target: { value: 'none' } });
    expect(screen.queryByRole('combobox', { name: /^Client Secret/ })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /save/i }));
    await waitFor(() => expect(savedBody().client_authentication).toBe('none'));
    expect(savedBody()).toMatchObject({
      client_id_secret_ref: 'HYDRA_ID',
      client_secret_secret_ref: '',
    });
  });

  it('shows the API refusal of a save on the page', async () => {
    renderJwt(jwtBearer({ client_authentication: 'none', client_id_secret_ref: 'HYDRA_ID' }), {
      ok: false,
      status: 400,
      statusText: 'Bad Request',
      text: () => Promise.resolve('{"error":"token_endpoint must be an https URL"}'),
    });
    await screen.findByDisplayValue('https://hydra.example/oauth2/token');
    fireEvent.click(screen.getByRole('button', { name: /save/i }));
    expect(await screen.findByText(/token_endpoint must be an https URL/)).toBeInTheDocument();
  });

  it('titles the client pickers of a JWT Bearer provider as a client identity', async () => {
    renderJwt(jwtBearer({ client_authentication: 'none', client_id_secret_ref: 'HYDRA_ID' }));
    await screen.findByDisplayValue('https://hydra.example/oauth2/token');
    expect(screen.getByTestId('credential-provider-client-heading')).toHaveTextContent(
      'Client identity (secret references)'
    );
  });

  it('keeps the OAuth heading on a Client Credentials provider', async () => {
    renderJwt({
      ...jwtBearer(),
      provider_type: 'oauth2_client_credentials',
      client_id_secret_ref: 'HYDRA_ID',
    });
    await screen.findByDisplayValue('https://hydra.example/oauth2/token');
    expect(screen.getByTestId('credential-provider-client-heading')).toHaveTextContent(
      'OAuth Client Credentials (Secret References)'
    );
  });

  it('does not offer client authentication on a Client Credentials provider', async () => {
    renderJwt({ ...jwtBearer(), provider_type: 'oauth2_client_credentials' });
    await screen.findByDisplayValue('https://hydra.example/oauth2/token');
    expect(
      screen.queryByTestId('credential-provider-client-authentication-select')
    ).not.toBeInTheDocument();
  });
});

describe('EditCredentialProviderPage client authentication requests', () => {
  beforeEach(() => jest.clearAllMocks());

  const secrets = [
    { id: 's1', secret_id: 'HYDRA_ID', name: 'Hydra id', tenant_id: null },
    { id: 's2', secret_id: 'HYDRA_SECRET', name: 'Hydra secret', tenant_id: null },
    { id: 's3', secret_id: 'SA_KEY', name: 'Key', tenant_id: null },
  ];

  const setup = (path: string, record?: Record<string, unknown>) => {
    mockFetch.mockImplementation((url: string, init?: { method?: string }) => {
      if (init?.method === 'PUT' || init?.method === 'POST') return Promise.resolve({ ok: true });
      if (url.startsWith('/api/v1/credential-providers/') && record) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(record) });
      }
      if (url.startsWith('/api/v1/secrets/')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(secrets) });
      }
      return Promise.resolve({ ok: false, json: () => Promise.resolve([]) });
    });
    return render(
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/credential-providers/:id" element={<EditCredentialProviderPage />} />
        </Routes>
      </MemoryRouter>
    );
  };

  const stored = (extra: Record<string, unknown>) => ({
    id: 'p1',
    name: 'Hydra',
    provider_id: 'hydra',
    provider_type: 'oauth2_jwt_bearer',
    token_endpoint: 'https://hydra.example/oauth2/token',
    jwt_issuer: 'issuer',
    jwt_subject: 'subject',
    jwt_signing_key_secret_ref: 'SA_KEY',
    default_scopes: [],
    token_refresh_enabled: false,
    ...extra,
  });

  const savedRequest = (method: string) => {
    const call = mockFetch.mock.calls.find(([, init]) => init?.method === method);
    return { url: call[0] as string, body: JSON.parse(call[1].body) };
  };

  const type = (label: RegExp, value: string) =>
    fireEvent.change(screen.getByLabelText(label), { target: { value } });

  it('creates a JWT Bearer provider with the form body method', async () => {
    setup('/credential-providers/new');
    await screen.findByTestId('credential-provider-type-select');
    type(/^Name/, 'Hydra');
    fireEvent.change(screen.getByTestId('credential-provider-type-select'), {
      target: { value: 'oauth2_jwt_bearer' },
    });
    type(/^Token Endpoint/, 'https://hydra.example/oauth2/token');
    fireEvent.change(screen.getByTestId('credential-provider-jwt-issuer-input'), {
      target: { value: 'issuer' },
    });
    fireEvent.change(screen.getByTestId('credential-provider-jwt-subject-input'), {
      target: { value: 'subject' },
    });
    await waitFor(() =>
      expect(
        screen.getByTestId('credential-provider-jwt_signing_key_secret_ref-select')
      ).not.toBeDisabled()
    );
    fireEvent.change(screen.getByTestId('credential-provider-jwt_signing_key_secret_ref-select'), {
      target: { value: 'SA_KEY' },
    });
    fireEvent.change(screen.getByTestId('credential-provider-client-authentication-select'), {
      target: { value: 'client_secret_post' },
    });
    fireEvent.change(screen.getByRole('combobox', { name: /^Client ID Secret/ }), {
      target: { value: 'HYDRA_ID' },
    });
    fireEvent.change(screen.getByRole('combobox', { name: /^Client Secret/ }), {
      target: { value: 'HYDRA_SECRET' },
    });
    fireEvent.click(screen.getByRole('button', { name: /create/i }));
    await waitFor(() =>
      expect(mockFetch.mock.calls.some(([, i]) => i?.method === 'POST')).toBe(true)
    );
    const { url, body } = savedRequest('POST');
    expect(url).toBe('/api/v1/credential-providers');
    expect(body).toMatchObject({
      provider_type: 'oauth2_jwt_bearer',
      client_authentication: 'client_secret_post',
      client_id_secret_ref: 'HYDRA_ID',
      client_secret_secret_ref: 'HYDRA_SECRET',
    });
  });

  it('sends an empty client authentication when a JWT Bearer provider becomes Client Credentials', async () => {
    setup(
      '/credential-providers/p1',
      stored({
        client_authentication: 'client_secret_basic',
        client_id_secret_ref: 'HYDRA_ID',
        client_secret_secret_ref: 'HYDRA_SECRET',
      })
    );
    await screen.findByDisplayValue('https://hydra.example/oauth2/token');
    fireEvent.change(screen.getByTestId('credential-provider-type-select'), {
      target: { value: 'oauth2_client_credentials' },
    });
    fireEvent.click(screen.getByRole('button', { name: /save/i }));
    await waitFor(() =>
      expect(mockFetch.mock.calls.some(([, i]) => i?.method === 'PUT')).toBe(true)
    );
    const { body } = savedRequest('PUT');
    expect(body.provider_type).toBe('oauth2_client_credentials');
    expect(body.client_authentication).toBe('');
    expect(body).toMatchObject({
      client_id_secret_ref: 'HYDRA_ID',
      client_secret_secret_ref: 'HYDRA_SECRET',
    });
  });

  it('clears stale client references of a JWT Bearer provider with no method', async () => {
    setup(
      '/credential-providers/p1',
      stored({ client_id_secret_ref: 'HYDRA_ID', client_secret_secret_ref: 'HYDRA_SECRET' })
    );
    await screen.findByDisplayValue('https://hydra.example/oauth2/token');
    fireEvent.click(screen.getByRole('button', { name: /save/i }));
    await waitFor(() =>
      expect(mockFetch.mock.calls.some(([, i]) => i?.method === 'PUT')).toBe(true)
    );
    const { body } = savedRequest('PUT');
    expect(body.client_authentication).toBe('');
    expect(body.client_id_secret_ref).toBe('');
    expect(body.client_secret_secret_ref).toBe('');
  });
});

describe('EditCredentialProviderPage consent confirmation', () => {
  beforeEach(() => jest.clearAllMocks());

  const SWITCH = 'credential-provider-consent-confirmation-switch';
  const SECTION = 'credential-provider-consent-confirmation-section';
  const REDIRECT_URI = 'credential-provider-consent-confirmation-redirect-uri';
  const CALLBACK = 'https://gw.example/prefix/v1/identity/oauth/callback/p1';
  const SETTING = {
    client_id_secret_ref: 'LOGIN_CLIENT_ID',
    client_secret_secret_ref: 'LOGIN_SECRET',
    authorization_endpoint: 'https://idp.example/authorize',
    token_endpoint: 'https://idp.example/token',
    jwt_verification_strategy_id: 'strategy-1',
  };

  const legacy = (extra: Record<string, unknown> = {}) => ({
    id: 'p1',
    name: 'GitHub',
    provider_id: 'github',
    provider_type: 'oauth2_authorization_code',
    authorization_endpoint: 'https://github.com/login/oauth/authorize',
    token_endpoint: 'https://github.com/login/oauth/access_token',
    client_id_secret_ref: 'CLIENT_ID',
    client_secret_secret_ref: 'CLIENT_SECRET',
    default_scopes: [],
    token_refresh_enabled: true,
    callback_path: '/v1/identity/oauth/callback/p1',
    callback_url: CALLBACK,
    ...extra,
  });

  const setup = (
    record: Record<string, unknown>,
    strategies: () => Promise<unknown> = () =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve([{ id: 'strategy-1', name: 'Entra callers' }]),
      })
  ) => {
    mockFetch.mockImplementation((url: string, init?: { method?: string }) => {
      if (init?.method === 'PUT') return Promise.resolve({ ok: true });
      if (url.startsWith('/api/v1/credential-providers/')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(record) });
      }
      if (url.startsWith('/api/v1/secrets/')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve([
              { id: 's1', secret_id: 'LOGIN_SECRET', name: 'Login secret', tenant_id: null },
              {
                id: 's2',
                secret_id: 'LOGIN_CLIENT_ID',
                name: 'Login client ID',
                tenant_id: null,
              },
            ]),
        });
      }
      if (url === '/api/v1/jwt-verification-strategies') return strategies();
      return Promise.resolve({ ok: false, json: () => Promise.resolve([]) });
    });
    render(
      <MemoryRouter initialEntries={['/credential-providers/p1']}>
        <Routes>
          <Route path="/credential-providers/:id" element={<EditCredentialProviderPage />} />
        </Routes>
      </MemoryRouter>
    );
  };

  const savedBody = async () => {
    fireEvent.click(screen.getByTestId('credential-provider-editor-save-button'));
    await waitFor(() =>
      expect(mockFetch.mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(true)
    );
    const [, init] = mockFetch.mock.calls.find(([, options]) => options?.method === 'PUT')!;
    return JSON.parse(init.body);
  };

  it('shows the section, switched off, only on a legacy authorization code provider', async () => {
    setup(legacy());
    expect(await screen.findByTestId(SWITCH)).not.toBeChecked();
    expect(screen.queryByTestId(REDIRECT_URI)).not.toBeInTheDocument();
    fireEvent.change(screen.getByTestId('credential-provider-type-select'), {
      target: { value: 'oauth2_client_credentials' },
    });
    expect(screen.queryByTestId(SECTION)).not.toBeInTheDocument();
  });

  it('does not show the section on an external consent provider', async () => {
    setup(legacy({ issuer: 'https://linear.example' }));
    await screen.findByTestId('credential-provider-external-notice');
    expect(screen.queryByTestId(SECTION)).not.toBeInTheDocument();
  });

  it('shows a stored setting switched on with the Callback URL plus /confirm', async () => {
    setup(legacy({ consent_confirmation: SETTING }));
    expect(await screen.findByTestId(SWITCH)).toBeChecked();
    expect(screen.getByTestId(REDIRECT_URI)).toHaveValue(`${CALLBACK}/confirm`);
    const where = screen.getByTestId('credential-provider-consent-confirmation-redirect-uri-where');
    expect(where).toHaveTextContent(
      `Add this URI to the allowed redirect URIs of the login client whose ID is in secret ${SETTING.client_id_secret_ref} at your identity provider.`
    );
    expect(where).toHaveTextContent('Callback URL above');
    expect(where).toHaveTextContent(
      'This URI follows the Callback URL, so register it again whenever the Callback URL changes.'
    );
    expect(await screen.findByRole('option', { name: 'Entra callers' })).toBeInTheDocument();
    expect(
      screen.getByTestId('credential-provider-consent-confirmation-strategy-select')
    ).toHaveValue('strategy-1');
  });

  it('says the strategies could not be loaded, without calling the stored one not found', async () => {
    setup(legacy({ consent_confirmation: SETTING }), () =>
      Promise.resolve({ ok: false, status: 403, json: () => Promise.resolve({}) })
    );
    expect(
      await screen.findByTestId('credential-provider-consent-confirmation-strategies-failed')
    ).toHaveTextContent('Strategies could not be loaded');
    const select = screen.getByTestId('credential-provider-consent-confirmation-strategy-select');
    expect(select).toHaveValue('strategy-1');
    expect(within(select).queryByText(/not found/)).not.toBeInTheDocument();
  });

  it("offers only the provider tenant's own and appliance-wide strategies", async () => {
    setup(legacy({ tenant_id: 'tenant-a' }), () =>
      Promise.resolve({
        ok: true,
        json: () =>
          Promise.resolve([
            { id: 'own', name: 'Own callers', tenant_id: 'tenant-a' },
            { id: 'shared', name: 'Shared callers', tenant_id: null },
            { id: 'other', name: 'Other callers', tenant_id: 'tenant-b' },
          ]),
      })
    );
    fireEvent.click(await screen.findByTestId(SWITCH));
    expect(await screen.findByRole('option', { name: 'Own callers' })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'Shared callers' })).toBeInTheDocument();
    expect(screen.queryByRole('option', { name: /Other callers/ })).not.toBeInTheDocument();
  });

  it('says where the redirect URI will show on a stored provider without a Callback URL', async () => {
    setup(legacy({ consent_confirmation: SETTING, callback_url: null }));
    expect(
      await screen.findByTestId(
        'credential-provider-consent-confirmation-redirect-uri-after-create'
      )
    ).toHaveTextContent(
      'The Confirmation redirect URI is shown once the provider has a Callback URL, since it is the Callback URL followed by /confirm.'
    );
    expect(screen.queryByTestId(REDIRECT_URI)).not.toBeInTheDocument();
  });

  it('sends the setting once switched on and filled in', async () => {
    setup(legacy());
    fireEvent.click(await screen.findByTestId(SWITCH));
    const type = (testId: string, value: string) =>
      fireEvent.change(screen.getByTestId(`credential-provider-consent-confirmation-${testId}`), {
        target: { value },
      });
    type('authorization-endpoint-input', 'https://idp.example/authorize');
    type('token-endpoint-input', 'https://idp.example/token');
    await screen.findAllByRole('option', { name: /LOGIN_SECRET/ });
    fireEvent.change(screen.getByTestId('credential-provider-cc_client_id_secret_ref-select'), {
      target: { value: 'LOGIN_CLIENT_ID' },
    });
    fireEvent.change(screen.getByTestId('credential-provider-cc_client_secret_secret_ref-select'), {
      target: { value: 'LOGIN_SECRET' },
    });
    await screen.findByRole('option', { name: 'Entra callers' });
    type('strategy-select', 'strategy-1');
    expect((await savedBody()).consent_confirmation).toEqual(SETTING);
  });

  it('refuses to save a switched-on setting with a required field empty', async () => {
    setup(legacy());
    fireEvent.click(await screen.findByTestId(SWITCH));
    fireEvent.click(screen.getByTestId('credential-provider-editor-save-button'));
    expect(
      await screen.findByText('Login Client ID is required for consent confirmation.')
    ).toBeInTheDocument();
    expect(mockFetch.mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(false);
  });

  it('sends null when a stored setting is switched off', async () => {
    setup(legacy({ consent_confirmation: SETTING }));
    fireEvent.click(await screen.findByTestId(SWITCH));
    const body = await savedBody();
    expect(body).toHaveProperty('consent_confirmation', null);
  });

  it('leaves the field out while the switch stays off', async () => {
    setup(legacy());
    await screen.findByTestId(SWITCH);
    expect(await savedBody()).not.toHaveProperty('consent_confirmation');
  });
});
