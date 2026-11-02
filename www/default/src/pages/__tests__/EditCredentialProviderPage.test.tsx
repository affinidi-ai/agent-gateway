import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
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
