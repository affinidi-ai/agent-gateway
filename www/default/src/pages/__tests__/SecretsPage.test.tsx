import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
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
  beforeEach(() => {
    jest.clearAllMocks();
    mockFetchByUrl();
  });

  it('shows why a secret was not deleted', async () => {
    const message = 'The secret is used by these integration endpoints: Ops webhook';
    const listing = (apiClient.fetch as jest.Mock).getMockImplementation()!;
    (apiClient.fetch as jest.Mock).mockImplementation((url: string, init?: RequestInit) =>
      init?.method === 'DELETE'
        ? Promise.resolve({
            ok: false,
            status: 409,
            statusText: 'Conflict',
            text: () => Promise.resolve(JSON.stringify({ message })),
          })
        : listing(url, init)
    );
    renderAt('/secrets?tab=secrets');

    const remove = await screen.findByTitle('Delete secret');
    await userEvent.click(remove);
    await userEvent.click(remove);

    await waitFor(() =>
      expect(showToast).toHaveBeenCalledWith('error', `Delete failed: ${message} (409)`, {
        autoRemove: false,
      })
    );
    expect(apiClient.fetch).toHaveBeenCalledWith('/api/v1/secrets/secret-1', { method: 'DELETE' });
  });
});

describe('SecretsPage secret deletion', () => {
  const requests = () =>
    (apiClient.fetch as jest.Mock).mock.calls as Array<[string, { method?: string } | undefined]>;
  const deletes = () => requests().filter(([, init]) => init?.method === 'DELETE');

  const json = (body: unknown) => Promise.resolve({ ok: true, json: () => Promise.resolve(body) });

  const withProviders = (providers: Record<string, Record<string, unknown>>) =>
    (apiClient.fetch as jest.Mock).mockImplementation((url: string, init?: { method?: string }) => {
      if (url === '/api/v1/credential-providers') {
        return json(Object.keys(providers).map(id => ({ id, name: `Provider ${id}` })));
      }
      if (url.startsWith('/api/v1/credential-providers/')) {
        return json(providers[url.split('/').pop() as string]);
      }
      if (url.startsWith('/api/v1/certificates/')) return json([]);
      if (url.startsWith('/api/v1/secrets')) {
        return init?.method === 'DELETE' ? json({}) : json(mockSecrets);
      }
      return json([]);
    });

  const clickDelete = () => {
    fireEvent.click(screen.getByTitle('Delete secret'));
    fireEvent.click(screen.getByTitle('Click again to confirm deletion'));
  };

  const openList = async () => {
    renderAt('/secrets?tab=secrets');
    await screen.findByText('Gateway Secret');
  };

  beforeEach(() => {
    jest.clearAllMocks();
    (apiClient.listSurfaces as jest.Mock).mockResolvedValue([]);
    (apiClient.listAllApiKeys as jest.Mock).mockResolvedValue([]);
    (apiClient.listAccessTokens as jest.Mock).mockResolvedValue([]);
  });

  it('warns with the provider names and deletes after the operator confirms', async () => {
    withProviders({
      p1: { client_secret_secret_ref: 'gateway-secret' },
      p2: { api_key_secret_ref: 'another-secret' },
    });
    await openList();
    clickDelete();

    const warning = await screen.findByTestId('secret-delete-warning');
    expect(warning).toHaveTextContent('Delete secret "Gateway Secret"?');
    expect(
      screen.getAllByTestId('secret-delete-warning-provider').map(li => li.textContent)
    ).toEqual(['Provider p1']);
    expect(deletes()).toHaveLength(0);

    fireEvent.click(screen.getByTestId('secret-delete-warning-confirm-button'));
    await waitFor(() => expect(deletes()).toHaveLength(1));
    expect(deletes()[0][0]).toBe('/api/v1/secrets/secret-1');
    await waitFor(() =>
      expect(screen.queryByTestId('secret-delete-warning')).not.toBeInTheDocument()
    );
  });

  it('keeps the secret when the warning is cancelled', async () => {
    withProviders({ p1: { client_secret_secret_ref: 'gateway-secret' } });
    await openList();
    clickDelete();
    fireEvent.click(await screen.findByTestId('secret-delete-warning-cancel-button'));

    expect(screen.queryByTestId('secret-delete-warning')).not.toBeInTheDocument();
    expect(deletes()).toHaveLength(0);
  });

  it('deletes a secret that no provider references without a warning', async () => {
    withProviders({ p1: { client_secret_secret_ref: 'another-secret' } });
    await openList();
    clickDelete();

    await waitFor(() => expect(deletes()).toHaveLength(1));
    expect(deletes()[0][0]).toBe('/api/v1/secrets/secret-1');
    expect(screen.queryByTestId('secret-delete-warning')).not.toBeInTheDocument();
  });
});
