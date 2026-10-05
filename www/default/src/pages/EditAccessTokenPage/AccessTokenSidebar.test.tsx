import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { apiClient } from '../../api';
import AccessTokenSidebar from './AccessTokenSidebar';
import { accessToken as token } from './accessTokenTestFixtures';

jest.mock('../../api', () => ({
  apiClient: {
    get: jest.fn(),
  },
}));

describe('AccessTokenSidebar', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (apiClient.get as jest.Mock).mockResolvedValue({
      data: {
        first_name: 'Ada',
        last_name: 'Lovelace',
        email: 'ada@example.com',
      },
    });
  });

  it('shows Access Token guidance while creating', () => {
    render(<AccessTokenSidebar meta={null} />);

    expect(screen.getByTestId('access-token-about-card')).toHaveTextContent(
      'Authorization: Bearer <token>'
    );
    expect(screen.getByTestId('access-token-about-card')).toHaveTextContent(
      "Leave scopes empty to grant the bound user's full role"
    );
    expect(screen.queryByTestId('access-token-details-card')).not.toBeInTheDocument();
  });

  it('resolves and shows edit-mode token metadata and bound user details', async () => {
    render(<AccessTokenSidebar meta={token} />);

    expect(screen.getByTestId('access-token-details-card')).toHaveTextContent(
      'Access Token Details'
    );
    await waitFor(() =>
      expect(screen.getByTestId('access-token-bound-user')).toHaveTextContent('Ada Lovelace')
    );
    expect(apiClient.get).toHaveBeenCalledWith('/users/admin-1');
    expect(screen.getByTestId('access-token-bound-user')).toHaveTextContent('ada@example.com');
    expect(screen.getByTestId('access-token-bound-user')).toHaveTextContent('admin-1');
    expect(screen.getByTestId('access-token-details-card')).toHaveTextContent('Active');
    expect(screen.getByTestId('access-token-about-card')).toBeVisible();
  });

  it('keeps the bound user UUID when profile lookup fails', async () => {
    (apiClient.get as jest.Mock).mockRejectedValueOnce(new Error('forbidden'));
    render(<AccessTokenSidebar meta={token} />);

    await waitFor(() => expect(apiClient.get).toHaveBeenCalledWith('/users/admin-1'));
    expect(screen.getByTestId('access-token-bound-user')).toHaveTextContent('admin-1');
  });

  it('renders a revoked token status in red', () => {
    render(
      <AccessTokenSidebar meta={{ ...token, active: false, revoked_at: '2026-09-09T10:00:00Z' }} />
    );

    expect(screen.getByText('Revoked')).toHaveClass('text-bg-danger');
  });
});
