import React from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
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

  it('shows an https error for an http token endpoint and none for https', async () => {
    renderWith({ ...provider(null), token_endpoint: 'http://idp.internal/token' });
    const error = await screen.findByTestId('credential-provider-token-endpoint-https-error');
    expect(error).toHaveTextContent('credential_policy.insecure_token_endpoints');
    fireEvent.change(screen.getByDisplayValue('http://idp.internal/token'), {
      target: { value: 'https://idp.internal/token' },
    });
    expect(
      screen.queryByTestId('credential-provider-token-endpoint-https-error')
    ).not.toBeInTheDocument();
  });
});
