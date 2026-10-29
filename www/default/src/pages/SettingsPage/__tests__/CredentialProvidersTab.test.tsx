import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import CredentialProvidersTab from '../CredentialProvidersTab';

const mockFetch = jest.fn();
const mockHasPermission = jest.fn();

jest.mock('../../../api', () => ({
  apiClient: { fetch: (...args: unknown[]) => mockFetch(...args) },
}));
jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: mockHasPermission }),
}));

const provider = (id: string, type: string) => ({
  id,
  name: `Provider ${id}`,
  provider_id: id,
  provider_type: type,
  default_scopes: [],
  token_refresh_enabled: false,
  created_at: '2026-10-12T08:58:00Z',
  updated_at: '2026-10-12T08:58:00Z',
});

const grant = (...allowed: string[]) =>
  mockHasPermission.mockImplementation((p: string) => allowed.includes(p));

const renderTab = () =>
  render(
    <MemoryRouter>
      <CredentialProvidersTab />
    </MemoryRouter>
  );

beforeEach(() => {
  jest.clearAllMocks();
  mockFetch.mockResolvedValue({
    ok: true,
    json: async () => [
      provider('a', 'oauth2_authorization_code'),
      provider('b', 'oauth2_client_credentials'),
      provider('c', 'oauth2_jwt_bearer'),
      provider('d', 'api_key'),
      provider('e', 'something_new'),
    ],
  });
});

describe('Credential providers list', () => {
  it('labels every provider type, including JWT Bearer and an unknown one', async () => {
    grant('credential_providers.view');
    renderTab();
    await screen.findByText('Provider c');
    expect(screen.getByText('Authorization Code')).toBeInTheDocument();
    expect(screen.getByText('Client Credentials')).toBeInTheDocument();
    expect(screen.getByText('JWT Bearer')).toHaveClass('text-bg-success');
    expect(screen.getByText('API Key')).toBeInTheDocument();
    expect(screen.getByText('something_new')).toHaveClass('text-bg-secondary');
  });

  it('hides add and delete without credential_providers.edit and .delete', async () => {
    grant('credential_providers.view');
    renderTab();
    await screen.findByText('Provider a');
    expect(screen.queryByText('Add Provider')).not.toBeInTheDocument();
    expect(screen.queryByTitle(/^Delete /)).not.toBeInTheDocument();
  });

  it('shows add with edit and delete with delete, independent of settings.edit', async () => {
    grant('credential_providers.view', 'credential_providers.edit', 'credential_providers.delete');
    renderTab();
    await screen.findByText('Provider a');
    expect(screen.getByText('Add Provider')).toBeInTheDocument();
    expect(screen.getAllByTitle(/^Delete /)).toHaveLength(5);
  });

  it('does not offer delete to a role with edit but not delete', async () => {
    grant('credential_providers.view', 'credential_providers.edit');
    renderTab();
    await screen.findByText('Provider a');
    expect(screen.getByText('Add Provider')).toBeInTheDocument();
    expect(screen.queryByTitle(/^Delete /)).not.toBeInTheDocument();
  });

  it('shows a no-access notice and skips the list call without credential_providers.view', async () => {
    grant('settings.edit');
    renderTab();
    expect(await screen.findByTestId('credential-providers-no-access')).toBeInTheDocument();
    await waitFor(() => expect(mockFetch).not.toHaveBeenCalled());
    expect(screen.queryByText('Add Provider')).not.toBeInTheDocument();
    expect(screen.queryByText('No credential providers yet')).not.toBeInTheDocument();
  });
});

describe('Deleting a credential provider', () => {
  const list = {
    ok: true,
    json: async () => [provider('a', 'oauth2_client_credentials')],
  };

  const deleteProvider = async () => {
    grant('credential_providers.view', 'credential_providers.delete');
    renderTab();
    fireEvent.click(await screen.findByTitle('Delete "Provider a"'));
    fireEvent.click(await screen.findByTitle('Click again to confirm deletion'));
  };

  it("shows the gateway's reason when a surface still uses the provider", async () => {
    mockFetch.mockImplementation(async (_url: string, init?: { method?: string }) =>
      init?.method === 'DELETE'
        ? {
            ok: false,
            status: 409,
            statusText: 'Conflict',
            text: async () =>
              JSON.stringify({
                error: "A surface's Target Authentication uses this credential provider",
              }),
          }
        : list
    );
    await deleteProvider();

    const alert = await screen.findByTestId('credential-provider-delete-error');
    expect(alert).toHaveAttribute('role', 'alert');
    expect(alert).toHaveTextContent(
      'Failed to delete provider "Provider a": A surface\'s Target Authentication uses this credential provider (409)'
    );
    expect(alert).not.toHaveTextContent('Conflict');
    expect(screen.getByText('Provider a')).toBeInTheDocument();
  });

  it('falls back to the status text when the body has no message', async () => {
    mockFetch.mockImplementation(async (_url: string, init?: { method?: string }) =>
      init?.method === 'DELETE'
        ? { ok: false, status: 500, statusText: 'Internal Server Error', text: async () => '' }
        : list
    );
    await deleteProvider();

    expect(await screen.findByTestId('credential-provider-delete-error')).toHaveTextContent(
      'Failed to delete provider "Provider a": Internal Server Error (500)'
    );
  });

  it('removes the row and shows no error when the delete succeeds', async () => {
    mockFetch.mockImplementation(async (_url: string, init?: { method?: string }) =>
      init?.method === 'DELETE' ? { ok: true, status: 204, text: async () => '' } : list
    );
    await deleteProvider();

    await waitFor(() => expect(screen.queryByText('Provider a')).not.toBeInTheDocument());
    expect(screen.queryByTestId('credential-provider-delete-error')).not.toBeInTheDocument();
  });
});
