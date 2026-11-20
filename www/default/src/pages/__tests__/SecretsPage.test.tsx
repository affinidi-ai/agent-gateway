import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import SecretsPage from '../SecretsPage';
import { apiClient } from '../../api';
import { showToast } from '../../utils/toaster';

jest.mock('../../utils/toaster', () => ({ showToast: jest.fn() }));

jest.mock('../../api', () => ({
  apiClient: {
    fetch: jest.fn(),
    listSurfaces: jest.fn(),
    listAllApiKeys: jest.fn(),
    listAccessTokens: jest.fn(),
    deleteApiKey: jest.fn(),
    revokeApiKey: jest.fn(),
  },
}));

jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    permissions: {
      'access_tokens.view': true,
      'access_tokens.edit': true,
      'access_tokens.delete': true,
    },
    loading: false,
    error: null,
    refetchPermissions: jest.fn(),
    hasPermission: () => true,
  }),
}));

const mockNavigate = jest.fn();
jest.mock('react-router-dom', () => ({
  ...jest.requireActual('react-router-dom'),
  useNavigate: () => mockNavigate,
}));

const mockCertificates = [
  {
    id: 'cert-server',
    name: 'Server Leaf Cert',
    certificate_id: 'cert-server-id',
    tags: [],
    created_at: '2026-07-01T10:00:00Z',
    updated_at: '2026-07-01T10:00:00Z',
    active: true,
    kind: 'server_leaf' as const,
  },
  {
    id: 'cert-client',
    name: 'Client Leaf Cert',
    certificate_id: 'cert-client-id',
    tags: [],
    created_at: '2026-07-02T10:00:00Z',
    updated_at: '2026-07-02T10:00:00Z',
    active: true,
    kind: 'client_leaf' as const,
  },
];

const mockSecrets = [
  {
    id: 'secret-1',
    name: 'Gateway Secret',
    secret_id: 'gateway-secret',
    description: 'A test secret',
    secret_type: 'General',
    tags: [],
    created_at: '2026-07-01T10:00:00Z',
    updated_at: '2026-07-03T12:30:00',
  },
];

function mockFetchByUrl() {
  (apiClient.fetch as jest.Mock).mockImplementation((url: string) => {
    if (url.startsWith('/api/v1/certificates/')) {
      return Promise.resolve({ ok: true, json: () => Promise.resolve(mockCertificates) });
    }
    if (url.startsWith('/api/v1/secrets')) {
      return Promise.resolve({ ok: true, json: () => Promise.resolve(mockSecrets) });
    }
    // secrets and everything else
    return Promise.resolve({ ok: true, json: () => Promise.resolve([]) });
  });
  (apiClient.listSurfaces as jest.Mock).mockResolvedValue([]);
  (apiClient.listAllApiKeys as jest.Mock).mockResolvedValue([]);
  (apiClient.listAccessTokens as jest.Mock).mockResolvedValue([]);
}

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <SecretsPage />
    </MemoryRouter>
  );
}

describe('SecretsPage certificate kind deep-link', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockFetchByUrl();
  });

  it('seeds the kind filter from the `kind` query param and shows only matching certs', async () => {
    renderAt('/secrets?tab=certificates&kind=client_leaf');

    await waitFor(() => {
      expect(screen.getByText('Client Leaf Cert')).toBeInTheDocument();
    });

    // The client-leaf cert is shown; the server-leaf cert is filtered out.
    expect(screen.queryByText('Server Leaf Cert')).not.toBeInTheDocument();

    // The filter dropdown reflects the deep-linked kind.
    const filter = screen.getByLabelText('Kind:') as HTMLSelectElement;
    expect(filter.value).toBe('client_leaf');
  });

  it('falls back to `all` when the `kind` query param is invalid', async () => {
    renderAt('/secrets?tab=certificates&kind=not-a-kind');

    await waitFor(() => {
      expect(screen.getByText('Client Leaf Cert')).toBeInTheDocument();
    });

    // No filtering — both certs are shown.
    expect(screen.getByText('Server Leaf Cert')).toBeInTheDocument();

    const filter = screen.getByLabelText('Kind:') as HTMLSelectElement;
    expect(filter.value).toBe('all');
  });
});

describe('SecretsPage secret timestamps', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockFetchByUrl();
  });

  it('displays the last updated date in the secret list', async () => {
    renderAt('/secrets?tab=secrets');

    await waitFor(() => {
      expect(screen.getByText('Gateway Secret')).toBeInTheDocument();
    });

    expect(screen.getByText('Updated')).toBeInTheDocument();
    expect(screen.getByText('July 3, 2026')).toBeInTheDocument();
  });
});

describe('SecretsPage secret delete', () => {
  let deleted = false;
  let deleteReplies: Array<{ status: number; body: unknown }>;

  beforeEach(() => {
    jest.clearAllMocks();
    mockFetchByUrl();
    deleted = false;
    deleteReplies = [];
    const listing = (apiClient.fetch as jest.Mock).getMockImplementation()!;
    (apiClient.fetch as jest.Mock).mockImplementation(async (url: string, init?: RequestInit) => {
      if (init?.method === 'DELETE') {
        const reply = deleteReplies.shift() ?? { status: 204, body: null };
        deleted = reply.status < 300;
        return {
          ok: reply.status < 300,
          status: reply.status,
          statusText: reply.status === 409 ? 'Conflict' : 'OK',
          text: () => Promise.resolve(reply.body ? JSON.stringify(reply.body) : ''),
        };
      }
      const response = await listing(url, init);
      if (deleted && url === '/api/v1/secrets/') {
        const rows = await response.json();
        return { ...response, json: () => Promise.resolve(rows.slice(1)) };
      }
      return response;
    });
  });

  const clickDelete = async () => {
    const remove = await screen.findByTitle('Delete secret');
    await userEvent.click(remove);
    await userEvent.click(remove);
  };

  const inUse = {
    message: 'The secret is in use; remove its references first, or delete it with force=true',
    references: [
      { kind: 'surface', id: 's1', name: 'Billing surface' },
      { kind: 'credential_provider', id: 'p1', name: 'Calendar provider' },
    ],
    hidden_references: 2,
  };

  it('deletes an unreferenced secret directly', async () => {
    renderAt('/secrets?tab=secrets');
    await clickDelete();

    await waitFor(() => expect(screen.queryByText('Gateway Secret')).not.toBeInTheDocument());
    expect(apiClient.fetch).toHaveBeenCalledWith('/api/v1/secrets/secret-1', { method: 'DELETE' });
    expect(screen.queryByTestId('confirm-delete-secret-modal')).not.toBeInTheDocument();
  });

  it('names the references and the hidden count before deleting a secret in use', async () => {
    deleteReplies = [{ status: 409, body: inUse }];
    renderAt('/secrets?tab=secrets');
    await clickDelete();

    const references = await screen.findByTestId('confirm-delete-secret-references');
    expect(references).toHaveTextContent('Surface: Billing surface');
    expect(references).toHaveTextContent('Credential provider: Calendar provider');
    expect(screen.getByTestId('confirm-delete-secret-references-hidden')).toHaveTextContent(
      'and 2 more you cannot view'
    );
    expect(screen.getByRole('button', { name: 'Delete secret anyway' })).toBeInTheDocument();
  });

  it('sends nothing more when the dialog is cancelled', async () => {
    deleteReplies = [{ status: 409, body: inUse }];
    renderAt('/secrets?tab=secrets');
    await clickDelete();
    await userEvent.click(await screen.findByTestId('confirm-delete-secret-cancel'));

    await waitFor(() =>
      expect(screen.queryByTestId('confirm-delete-secret-modal')).not.toBeInTheDocument()
    );
    const deletes = (apiClient.fetch as jest.Mock).mock.calls.filter(
      ([, init]) => init?.method === 'DELETE'
    );
    expect(deletes).toEqual([['/api/v1/secrets/secret-1', { method: 'DELETE' }]]);
    expect(screen.getByText('Gateway Secret')).toBeInTheDocument();
  });

  it('deletes with force=true after Delete secret anyway and removes the row', async () => {
    deleteReplies = [{ status: 409, body: inUse }];
    renderAt('/secrets?tab=secrets');
    await clickDelete();
    await userEvent.click(await screen.findByRole('button', { name: 'Delete secret anyway' }));

    await waitFor(() => expect(screen.queryByText('Gateway Secret')).not.toBeInTheDocument());
    expect(apiClient.fetch).toHaveBeenCalledWith('/api/v1/secrets/secret-1?force=true', {
      method: 'DELETE',
    });
    expect(screen.queryByTestId('confirm-delete-secret-modal')).not.toBeInTheDocument();
  });

  it('shows an integration endpoint refusal inline with no override', async () => {
    const message = 'The secret is used by these integration endpoints: Ops webhook';
    deleteReplies = [{ status: 409, body: { message } }];
    renderAt('/secrets?tab=secrets');
    await clickDelete();

    expect(await screen.findByTestId('secrets-delete-error')).toHaveTextContent(
      `Delete failed: ${message} (409)`
    );
    expect(screen.queryByRole('button', { name: 'Delete secret anyway' })).not.toBeInTheDocument();
    expect(showToast).not.toHaveBeenCalled();
    expect(apiClient.fetch).toHaveBeenCalledWith('/api/v1/secrets/secret-1', { method: 'DELETE' });
  });
});

describe('SecretsPage API key delete', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockFetchByUrl();
  });

  const key = {
    key_id: 'atgk_named',
    agent_id: 'owner-a',
    client_id: 'client-a',
    status: 'active',
    created_at: '2026-07-01T10:00:00Z',
  };

  it('deletes an API key only after the operator confirms it in the dialog', async () => {
    (apiClient.listAllApiKeys as jest.Mock).mockResolvedValue([key]);
    (apiClient.deleteApiKey as jest.Mock).mockResolvedValue(undefined);
    renderAt('/secrets?tab=api-keys');

    await userEvent.click(await screen.findByTestId('api-keys-delete-button-atgk_named'));

    const dialog = screen.getByTestId('api-key-delete-dialog');
    expect(dialog).toHaveTextContent('client-a');
    expect(dialog).toHaveTextContent('will stop working until you pick another key');
    expect(screen.getByRole('dialog', { name: 'Delete API key' })).toBe(dialog);
    const confirm = screen.getByTestId('api-key-delete-dialog-confirm');
    expect(confirm).toBeEnabled();
    expect(apiClient.deleteApiKey).not.toHaveBeenCalled();

    const listings = (apiClient.listAllApiKeys as jest.Mock).mock.calls.length;
    await userEvent.click(confirm);

    await waitFor(() =>
      expect(apiClient.deleteApiKey).toHaveBeenCalledWith('owner-a', 'atgk_named')
    );
    await waitFor(() => expect(screen.queryByTestId('api-key-delete-dialog')).toBeNull());
    expect(showToast).toHaveBeenCalledWith('success', 'API key deleted');
    await waitFor(() =>
      expect((apiClient.listAllApiKeys as jest.Mock).mock.calls.length).toBeGreaterThan(listings)
    );
  });

  it('deletes nothing when the dialog is cancelled', async () => {
    (apiClient.listAllApiKeys as jest.Mock).mockResolvedValue([key]);
    renderAt('/secrets?tab=api-keys');

    await userEvent.click(await screen.findByTestId('api-keys-delete-button-atgk_named'));
    await userEvent.click(screen.getByText('Cancel'));

    expect(screen.queryByTestId('api-key-delete-dialog')).toBeNull();
    expect(apiClient.deleteApiKey).not.toHaveBeenCalled();
    expect(showToast).not.toHaveBeenCalled();
  });

  it('deletes nothing when the dialog is closed', async () => {
    (apiClient.listAllApiKeys as jest.Mock).mockResolvedValue([key]);
    renderAt('/secrets?tab=api-keys');

    await userEvent.click(await screen.findByTestId('api-keys-delete-button-atgk_named'));
    await userEvent.click(screen.getByRole('button', { name: 'Close' }));

    expect(screen.queryByTestId('api-key-delete-dialog')).toBeNull();
    expect(apiClient.deleteApiKey).not.toHaveBeenCalled();
  });

  it('shows why a delete failed', async () => {
    const message = 'Internal server error (500)';
    (apiClient.listAllApiKeys as jest.Mock).mockResolvedValue([key]);
    (apiClient.deleteApiKey as jest.Mock).mockRejectedValue(new Error(message));
    renderAt('/secrets?tab=api-keys');

    await userEvent.click(await screen.findByTestId('api-keys-delete-button-atgk_named'));
    await userEvent.click(screen.getByTestId('api-key-delete-dialog-confirm'));

    await waitFor(() =>
      expect(showToast).toHaveBeenCalledWith('error', `Delete failed: ${message}`, {
        autoRemove: false,
      })
    );
  });
});

describe('SecretsPage API key revoke', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockFetchByUrl();
  });

  const key = {
    key_id: 'atgk_named',
    agent_id: 'owner-a',
    client_id: 'client-a',
    status: 'active',
    created_at: '2026-07-01T10:00:00Z',
  };

  const openDialog = async () => {
    (apiClient.listAllApiKeys as jest.Mock).mockResolvedValue([key]);
    renderAt('/secrets?tab=api-keys');
    await userEvent.click(await screen.findByTestId('api-keys-revoke-button-atgk_named'));
    return screen.getByTestId('api-key-revoke-dialog');
  };

  it('revokes an API key only after the operator confirms it in the dialog', async () => {
    (apiClient.revokeApiKey as jest.Mock).mockResolvedValue(undefined);
    const dialog = await openDialog();

    expect(screen.getByRole('dialog', { name: 'Revoke API key' })).toBe(dialog);
    expect(dialog).toHaveTextContent('client-a');
    expect(dialog).toHaveTextContent('atgk_named');
    expect(dialog).toHaveTextContent('Surfaces that use this key will stop serving');
    expect(dialog).toHaveTextContent("A revoked key can't be restored");
    expect(dialog).toHaveTextContent('gives the surface a new DID');
    expect(apiClient.revokeApiKey).not.toHaveBeenCalled();

    const listings = (apiClient.listAllApiKeys as jest.Mock).mock.calls.length;
    await userEvent.click(screen.getByTestId('api-key-revoke-dialog-confirm'));

    await waitFor(() =>
      expect(apiClient.revokeApiKey).toHaveBeenCalledWith('owner-a', 'atgk_named', 'dashboard')
    );
    expect(apiClient.revokeApiKey).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(screen.queryByTestId('api-key-revoke-dialog')).toBeNull());
    expect(showToast).toHaveBeenCalledWith('success', 'API key revoked');
    await waitFor(() =>
      expect((apiClient.listAllApiKeys as jest.Mock).mock.calls.length).toBeGreaterThan(listings)
    );
  });

  it('revokes nothing when the dialog is cancelled', async () => {
    await openDialog();
    await userEvent.click(screen.getByText('Cancel'));

    expect(screen.queryByTestId('api-key-revoke-dialog')).toBeNull();
    expect(apiClient.revokeApiKey).not.toHaveBeenCalled();
    expect(showToast).not.toHaveBeenCalled();
  });

  it('revokes nothing when the dialog is closed', async () => {
    await openDialog();
    await userEvent.click(screen.getByRole('button', { name: 'Close' }));

    expect(screen.queryByTestId('api-key-revoke-dialog')).toBeNull();
    expect(apiClient.revokeApiKey).not.toHaveBeenCalled();
  });

  it('shows why a revoke failed in an error toast', async () => {
    const message = 'Internal server error (500)';
    (apiClient.revokeApiKey as jest.Mock).mockRejectedValue(new Error(message));
    await openDialog();

    await userEvent.click(screen.getByTestId('api-key-revoke-dialog-confirm'));

    await waitFor(() =>
      expect(showToast).toHaveBeenCalledWith('error', `Revoke failed: ${message}`, {
        autoRemove: false,
      })
    );
    expect(screen.queryByTestId('api-key-revoke-dialog')).toBeNull();
  });
});
