import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import SecretsPage from '../SecretsPage';
import { apiClient } from '../../api';

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

function mockFetchByUrl() {
  (apiClient.fetch as jest.Mock).mockImplementation((url: string) => {
    if (url.startsWith('/api/v1/certificates/')) {
      return Promise.resolve({ ok: true, json: () => Promise.resolve(mockCertificates) });
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
