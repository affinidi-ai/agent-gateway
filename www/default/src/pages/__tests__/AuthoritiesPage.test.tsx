import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import AuthoritiesPage from '../AuthoritiesPage';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({
  apiClient: {
    get: jest.fn(),
    delete: jest.fn(),
  },
}));

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
