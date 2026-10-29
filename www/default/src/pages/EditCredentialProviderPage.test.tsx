import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { PageTitleProvider } from '../context/PageTitleContext';
import EditCredentialProviderPage from './EditCredentialProviderPage';

const mockFetch = jest.fn();

jest.mock('../api', () => ({
  apiClient: { fetch: (...args: unknown[]) => mockFetch(...args) },
}));
jest.mock('../utils/toaster', () => ({ showToast: jest.fn() }));
const mockHasPermission = jest.fn();
jest.mock('../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: mockHasPermission }),
}));

const secrets = [
  { id: 's1', name: 'Signing key', secret_id: 'sa-key' },
  { id: 's2', name: 'Client id', secret_id: 'client-id' },
  { id: 's3', name: 'Client secret', secret_id: 'client-secret' },
];

const json = (body: unknown) => ({ ok: true, json: async () => body, text: async () => '' });

function route(url: string, body: unknown) {
  mockFetch.mockImplementation(async (u: string, init?: { method?: string }) => {
    if (u === '/api/v1/secrets/') return json(secrets);
    if (u === '/api/v1/config/surface-routing') {
      return json({ available_listen_addresses: [], oauth_callback_route: '/oauth/callback' });
    }
    if (u === url && (!init || !init.method)) return json(body);
    return json({});
  });
}

const renderPage = (path: string) =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <PageTitleProvider>
        <Routes>
          <Route path="/credential-providers/new" element={<EditCredentialProviderPage />} />
          <Route path="/credential-providers/:id" element={<EditCredentialProviderPage />} />
          <Route path="/settings" element={<div data-testid="settings" />} />
        </Routes>
      </PageTitleProvider>
    </MemoryRouter>
  );

const savedRequest = () => {
  const call = mockFetch.mock.calls.find(([, init]) => init && init.method);
  return call ? { url: call[0], method: call[1].method, body: JSON.parse(call[1].body) } : null;
};

beforeEach(() => {
  jest.clearAllMocks();
  mockHasPermission.mockReturnValue(true);
  route('', {});
});

describe('Edit credential provider, JWT bearer', () => {
  it('offers the JWT bearer type with its own fields and the encryption banner', async () => {
    renderPage('/credential-providers/new');
    await screen.findByLabelText(/^Provider Type/);
    const select = screen.getByLabelText(/^Provider Type/);
    expect(
      within(select)
        .getAllByRole('option')
        .map(o => o.getAttribute('value'))
    ).toEqual([
      'oauth2_authorization_code',
      'oauth2_client_credentials',
      'oauth2_jwt_bearer',
      'api_key',
    ]);
    expect(screen.queryByTestId('jwt-bearer-section')).not.toBeInTheDocument();

    fireEvent.change(select, { target: { value: 'oauth2_jwt_bearer' } });

    expect(screen.getByTestId('jwt-bearer-section')).toBeInTheDocument();
    expect(screen.getByTestId('jwt-bearer-encryption-banner')).toHaveTextContent(
      'Encryption at rest is off by default'
    );
    expect(screen.getByLabelText(/^Signing Key Secret/)).toBeRequired();
    expect(screen.getByLabelText(/^Assertion Issuer/)).toBeRequired();
    expect(screen.getByLabelText(/^Subject/)).not.toBeRequired();
    expect(screen.getByLabelText(/^Key ID/)).not.toBeRequired();
    expect(screen.getByLabelText(/^Algorithm/)).toHaveValue('RS256');
    expect(screen.getByLabelText(/^Client ID Secret/)).not.toBeRequired();
    expect(screen.queryByLabelText(/^Callback URL Host/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^Authorization Endpoint/)).not.toBeInTheDocument();
  });

  it('creates a JWT bearer provider with the signing fields', async () => {
    renderPage('/credential-providers/new');
    await screen.findByLabelText(/^Provider Type/);
    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'Vertex' } });
    fireEvent.change(screen.getByLabelText(/^Provider Type/), {
      target: { value: 'oauth2_jwt_bearer' },
    });
    fireEvent.change(screen.getByLabelText(/^Token Endpoint/), {
      target: { value: 'https://oauth2.googleapis.com/token' },
    });
    await waitFor(() => expect(screen.getByLabelText(/^Signing Key Secret/)).not.toBeDisabled());
    fireEvent.change(screen.getByLabelText(/^Signing Key Secret/), { target: { value: 'sa-key' } });
    fireEvent.change(screen.getByLabelText(/^Algorithm/), { target: { value: 'ES256' } });
    fireEvent.change(screen.getByLabelText(/^Assertion Issuer/), {
      target: { value: 'sa@project.iam' },
    });
    fireEvent.change(screen.getByLabelText(/^Key ID/), { target: { value: 'kid-1' } });
    fireEvent.click(screen.getByRole('button', { name: /Create/ }));

    await waitFor(() => expect(savedRequest()).not.toBeNull());
    const req = savedRequest()!;
    expect(req.url).toBe('/api/v1/credential-providers');
    expect(req.method).toBe('POST');
    expect(req.body).toMatchObject({
      name: 'Vertex',
      provider_id: 'vertex',
      provider_type: 'oauth2_jwt_bearer',
      token_endpoint: 'https://oauth2.googleapis.com/token',
      jwt_bearer: {
        signing_key_secret_ref: 'sa-key',
        signing_algorithm: 'ES256',
        assertion_issuer: 'sa@project.iam',
        key_id: 'kid-1',
      },
    });
    expect(req.body).not.toHaveProperty('client_id_secret_ref');
    expect((req.body as { jwt_bearer: object }).jwt_bearer).not.toHaveProperty('assertion_subject');
  });

  it('does not save and shows the reason when the signing key is missing', async () => {
    renderPage('/credential-providers/new');
    await screen.findByLabelText(/^Provider Type/);
    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'Vertex' } });
    fireEvent.change(screen.getByLabelText(/^Provider Type/), {
      target: { value: 'oauth2_jwt_bearer' },
    });
    fireEvent.change(screen.getByLabelText(/^Token Endpoint/), { target: { value: 'https://t' } });
    fireEvent.change(screen.getByLabelText(/^Assertion Issuer/), { target: { value: 'iss' } });
    fireEvent.click(screen.getByRole('button', { name: /Create/ }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Signing key secret is required.');
    expect(savedRequest()).toBeNull();
  });

  it('loads a saved JWT bearer provider into the form', async () => {
    route('/api/v1/credential-providers/cp-1', {
      id: 'cp-1',
      name: 'Vertex',
      provider_id: 'vertex',
      provider_type: 'oauth2_jwt_bearer',
      token_endpoint: 'https://t',
      jwt_bearer: {
        signing_key_secret_ref: 'sa-key',
        signing_algorithm: 'ES256',
        assertion_issuer: 'iss',
        assertion_subject: 'sub',
        key_id: 'kid',
      },
      default_scopes: ['a'],
    });
    renderPage('/credential-providers/cp-1');
    await waitFor(() => expect(screen.getByLabelText(/^Assertion Issuer/)).toHaveValue('iss'));
    expect(screen.getByLabelText(/^Subject/)).toHaveValue('sub');
    expect(screen.getByLabelText(/^Key ID/)).toHaveValue('kid');
    expect(screen.getByLabelText(/^Algorithm/)).toHaveValue('ES256');
    expect(screen.getByLabelText(/^Default Scopes/)).toHaveValue('a');
  });

  it('keeps the OAuth client secret fields required for client credentials', async () => {
    renderPage('/credential-providers/new');
    await screen.findByLabelText(/^Provider Type/);
    fireEvent.change(screen.getByLabelText(/^Provider Type/), {
      target: { value: 'oauth2_client_credentials' },
    });
    expect(screen.getByLabelText(/^Client ID Secret/)).toBeRequired();
    expect(screen.getByLabelText(/^Client Secret/)).toBeRequired();
    expect(screen.queryByTestId('jwt-bearer-section')).not.toBeInTheDocument();
  });

  it('shows a saved provider read-only without credential_providers.edit', async () => {
    mockHasPermission.mockImplementation((p: string) => p === 'credential_providers.view');
    route('/api/v1/credential-providers/cp-1', {
      id: 'cp-1',
      name: 'Vertex',
      provider_id: 'vertex',
      provider_type: 'oauth2_jwt_bearer',
      token_endpoint: 'https://t',
      jwt_bearer: { signing_key_secret_ref: 'sa-key', assertion_issuer: 'iss' },
    });
    renderPage('/credential-providers/cp-1');
    await waitFor(() => expect(screen.getByLabelText(/^Assertion Issuer/)).toHaveValue('iss'));
    expect(screen.getByLabelText(/^Assertion Issuer/)).toBeDisabled();
    expect(screen.queryByRole('button', { name: /Save/ })).not.toBeInTheDocument();
    expect(screen.getByTestId('provider-read-only')).toHaveTextContent(
      'Your role can view this provider but not change it.'
    );
    fireEvent.keyDown(document, { key: 's', ctrlKey: true });
    expect(savedRequest()).toBeNull();
  });

  it('says nothing about a read-only role when the role can edit', async () => {
    route('/api/v1/credential-providers/cp-1', {
      id: 'cp-1',
      name: 'Vertex',
      provider_id: 'vertex',
      provider_type: 'oauth2_jwt_bearer',
      token_endpoint: 'https://t',
      jwt_bearer: { signing_key_secret_ref: 'sa-key', assertion_issuer: 'iss' },
    });
    renderPage('/credential-providers/cp-1');
    await waitFor(() => expect(screen.getByLabelText(/^Assertion Issuer/)).toHaveValue('iss'));
    expect(screen.queryByTestId('provider-read-only')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Save/ })).toBeInTheDocument();
  });

  it('asks for a letter or number in the name when the name gives no provider ID', async () => {
    renderPage('/credential-providers/new');
    await screen.findByLabelText(/^Provider Type/);
    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: '東京' } });
    fireEvent.change(screen.getByLabelText(/^Provider Type/), {
      target: { value: 'oauth2_jwt_bearer' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Create/ }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Name must contain at least one letter or number.'
    );
    expect(savedRequest()).toBeNull();
  });

  it('saves a type change on an existing provider', async () => {
    route('/api/v1/credential-providers/cp-1', {
      id: 'cp-1',
      name: 'Svc',
      provider_id: 'svc',
      provider_type: 'oauth2_client_credentials',
      token_endpoint: 'https://t',
      client_id_secret_ref: 'client-id',
      client_secret_secret_ref: 'client-secret',
    });
    renderPage('/credential-providers/cp-1');
    await waitFor(() =>
      expect(screen.getByLabelText(/^Provider Type/)).toHaveValue('oauth2_client_credentials')
    );
    fireEvent.change(screen.getByLabelText(/^Provider Type/), { target: { value: 'api_key' } });
    fireEvent.change(await screen.findByLabelText(/^API Key/), { target: { value: 'sa-key' } });
    fireEvent.click(screen.getByRole('button', { name: /Save/ }));
    await waitFor(() => expect(savedRequest()).not.toBeNull());
    expect(savedRequest()).toMatchObject({
      method: 'PUT',
      url: '/api/v1/credential-providers/cp-1',
      body: { provider_type: 'api_key', api_key_secret_ref: 'sa-key' },
    });
  });

  it('cannot save a provider of a type the dashboard does not know', async () => {
    route('/api/v1/credential-providers/cp-1', {
      id: 'cp-1',
      name: 'Future',
      provider_id: 'future',
      provider_type: 'future_type',
    });
    renderPage('/credential-providers/cp-1');
    expect(await screen.findByTestId('provider-unknown-type')).toBeInTheDocument();
    expect(screen.getByLabelText(/^Provider Type/)).toBeDisabled();
    expect(screen.queryByRole('button', { name: /Save/ })).not.toBeInTheDocument();
    expect(screen.queryByTestId('provider-read-only')).not.toBeInTheDocument();
    fireEvent.keyDown(document, { key: 's', ctrlKey: true });
    expect(savedRequest()).toBeNull();
  });
});
