import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import AuthoritiesPage from '../AuthoritiesPage';
import { ApiError, apiClient } from '../../api';

jest.mock('../../api', () => {
  const actual = jest.requireActual('../../api');
  return {
    ApiError: actual.ApiError,
    apiClient: {
      get: jest.fn(),
      deleteAuthority: jest.fn(),
      listTrustRegistries: jest.fn(),
    },
  };
});

jest.mock('../../utils/authoritiesCache', () => ({
  clearAuthoritiesCache: jest.fn(),
}));

jest.mock('../../utils/stringUtils', () => ({
  topAndTail: (s: string) => s,
}));

const mockNavigate = jest.fn();
jest.mock('react-router-dom', () => ({
  ...jest.requireActual('react-router-dom'),
  useNavigate: () => mockNavigate,
}));

const mockAuthorities = [
  {
    id: 'auth-1',
    name: 'Acme Authority',
    description: 'Trust anchor for Acme',
    did: 'did:web:acme.example.com',
    created_at: '2026-07-01T10:00:00Z',
    updated_at: '2026-07-01T10:00:00Z',
  },
  {
    id: 'auth-2',
    name: 'Globex Root',
    did: 'did:web:globex.example.com',
    created_at: '2026-07-02T10:00:00Z',
    updated_at: '2026-07-02T10:00:00Z',
  },
];

function renderPage(overrides: Partial<React.ComponentProps<typeof AuthoritiesPage>> = {}) {
  return render(
    <MemoryRouter>
      <AuthoritiesPage {...overrides} />
    </MemoryRouter>
  );
}

describe('AuthoritiesPage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders the empty state when the API returns no authorities', async () => {
    (apiClient.get as jest.Mock).mockResolvedValue({ data: [] });

    renderPage();

    await waitFor(() => {
      expect(screen.getByText(/Add your first authority/i)).toBeInTheDocument();
    });
    expect(screen.queryByRole('button', { name: /Add First Authority/i })).not.toBeInTheDocument();
  });

  it('renders each authority row with name and DID', async () => {
    (apiClient.get as jest.Mock).mockResolvedValue({ data: mockAuthorities });

    renderPage();

    await waitFor(() => {
      expect(screen.getByText('Acme Authority')).toBeInTheDocument();
    });
    expect(screen.getByText('Globex Root')).toBeInTheDocument();
    expect(screen.getByText('did:web:acme.example.com')).toBeInTheDocument();
    expect(screen.getByText('did:web:globex.example.com')).toBeInTheDocument();
  });

  it('filters authorities by external search term', async () => {
    (apiClient.get as jest.Mock).mockResolvedValue({ data: mockAuthorities });

    renderPage({ externalSearchTerm: 'globex' });

    await waitFor(() => {
      expect(screen.getByText('Globex Root')).toBeInTheDocument();
    });
    expect(screen.queryByText('Acme Authority')).not.toBeInTheDocument();
  });

  it('routes to /authorities/new when Add Authority is clicked (no onAdd override)', async () => {
    (apiClient.get as jest.Mock).mockResolvedValue({ data: mockAuthorities });

    renderPage();

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Add Authority/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Add Authority/i }));
    expect(mockNavigate).toHaveBeenCalledWith('/authorities/new');
  });

  it('invokes onAdd instead of navigating when the prop is provided', async () => {
    (apiClient.get as jest.Mock).mockResolvedValue({ data: mockAuthorities });
    const onAdd = jest.fn();

    renderPage({ onAdd });

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Add Authority/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Add Authority/i }));
    expect(onAdd).toHaveBeenCalledTimes(1);
    expect(mockNavigate).not.toHaveBeenCalled();
  });

  it('hides the Add button when hideAddButton is set', async () => {
    (apiClient.get as jest.Mock).mockResolvedValue({ data: mockAuthorities });

    renderPage({ hideAddButton: true });

    await waitFor(() => {
      expect(screen.getByText('Acme Authority')).toBeInTheDocument();
    });
    expect(screen.queryByRole('button', { name: /Add Authority/i })).not.toBeInTheDocument();
  });

  it('reports the filtered count via onFilteredCountChange', async () => {
    (apiClient.get as jest.Mock).mockResolvedValue({ data: mockAuthorities });
    const onFilteredCountChange = jest.fn();

    renderPage({ onFilteredCountChange, externalSearchTerm: 'acme' });

    await waitFor(() => {
      expect(onFilteredCountChange).toHaveBeenCalledWith(1);
    });
  });

  it('surfaces API errors', async () => {
    (apiClient.get as jest.Mock).mockRejectedValue(new Error('boom'));

    renderPage();

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/boom/i);
    });
  });
});

describe('AuthoritiesPage — delete', () => {
  const IN_USE = {
    message: 'The Authority is used by Trust Checks or Trust Recorder entries.',
    references: [
      {
        kind: 'surface',
        id: 'surface-1',
        name: 'Orders',
        uses: [
          {
            element: 'trust_check',
            id: 'tc-1',
            name: 'Agent recognised',
            placement: 'access_point',
          },
          { element: 'trust_recorder', trust_registry_id: 'tr-1', variant: 'staging' },
        ],
      },
      {
        kind: 'sts_client',
        id: 'sts-1',
        name: 'Exchange',
        uses: [{ element: 'trust_check', id: 'tc-9' }],
      },
    ],
    hidden_references: 3,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    (apiClient.get as jest.Mock).mockResolvedValue({ data: mockAuthorities });
    (apiClient.listTrustRegistries as jest.Mock).mockResolvedValue([
      { id: 'tr-1', name: 'Partner registry' },
    ]);
  });

  async function deleteFirst() {
    renderPage();
    const button = await screen.findByTestId('authorities-delete-button-auth-1');
    fireEvent.click(button);
    fireEvent.click(button);
  }

  it('lists what uses the Authority when the gateway refuses with 409', async () => {
    (apiClient.deleteAuthority as jest.Mock).mockRejectedValue(
      new ApiError('in use (409)', 409, undefined, JSON.stringify(IN_USE))
    );

    await deleteFirst();

    const dialog = await screen.findByTestId('authority-in-use-dialog');
    expect(apiClient.deleteAuthority).toHaveBeenCalledWith('auth-1');
    expect(screen.getByRole('dialog', { name: 'Authority in use' })).toBe(dialog);
    expect(dialog).toHaveTextContent('Acme Authority is used by Trust Checks');
    expect(screen.getByTestId('authority-in-use-dialog-surface-link-surface-1')).toHaveAttribute(
      'href',
      '/surfaces/surface-1'
    );
    expect(screen.getByTestId('authority-in-use-dialog-surface-surface-1')).toHaveTextContent(
      'Trust Check “Agent recognised” on the Access Point'
    );
    await waitFor(() =>
      expect(screen.getByTestId('authority-in-use-dialog-surface-surface-1')).toHaveTextContent(
        'Trust Recorder entry for Partner registry in variant staging'
      )
    );
    expect(screen.getByTestId('authority-in-use-dialog-sts-client-sts-1')).toHaveTextContent(
      'STS client Exchange'
    );
    expect(screen.getByTestId('authority-in-use-dialog-hidden')).toHaveTextContent(
      "3 more you can't view."
    );
    expect(screen.queryByRole('button', { name: /delete anyway/i })).toBeNull();
    expect(screen.queryByText(/Failed to delete authority/)).toBeNull();

    fireEvent.click(screen.getByTestId('authority-in-use-dialog-close'));
    expect(screen.queryByTestId('authority-in-use-dialog')).toBeNull();
  });

  it('shows no hidden count when every user is visible', async () => {
    (apiClient.deleteAuthority as jest.Mock).mockRejectedValue(
      new ApiError(
        'in use (409)',
        409,
        undefined,
        JSON.stringify({ ...IN_USE, hidden_references: 0 })
      )
    );

    await deleteFirst();

    await screen.findByTestId('authority-in-use-dialog');
    expect(screen.queryByTestId('authority-in-use-dialog-hidden')).toBeNull();
  });

  it('keeps the error alert for any other failure', async () => {
    (apiClient.deleteAuthority as jest.Mock).mockRejectedValue(
      new ApiError('Forbidden (403)', 403, undefined, '{"message":"Forbidden"}')
    );

    await deleteFirst();

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Forbidden (403)'));
    expect(screen.queryByTestId('authority-in-use-dialog')).toBeNull();
  });

  it('reloads the list after a successful delete', async () => {
    (apiClient.deleteAuthority as jest.Mock).mockResolvedValue(undefined);

    await deleteFirst();

    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent('Authority deleted successfully')
    );
    expect(apiClient.get).toHaveBeenCalledTimes(2);
  });
});
