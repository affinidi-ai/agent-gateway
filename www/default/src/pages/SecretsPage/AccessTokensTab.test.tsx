import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { MemoryRouter, useLocation } from 'react-router-dom';
import AccessTokensTab from './AccessTokensTab';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({
  apiClient: {
    listAccessTokens: jest.fn(),
    revokeAccessToken: jest.fn(),
  },
}));

jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    permissions: {
      'access_tokens.view': true,
      'access_tokens.edit': true,
      'access_tokens.delete': true,
      'gateways.view': true,
    },
    loading: false,
    error: null,
    refetchPermissions: jest.fn(),
    hasPermission: () => true,
  }),
}));

jest.mock('../../utils/toaster', () => ({ showToast: jest.fn() }));

const token = {
  id: 'agat_token1',
  name: 'Automation',
  description: 'CI token',
  user_id: 'admin-1',
  scopes: ['gateways.view'],
  resource_pattern: null,
  required_headers: [],
  created_by: 'admin-1',
  created_at: '2026-09-08T10:00:00Z',
  active: true,
};

const LocationProbe = () => {
  const location = useLocation();
  return <output data-testid="location">{`${location.pathname}${location.search}`}</output>;
};

const renderTab = () =>
  render(
    <MemoryRouter initialEntries={['/secrets?tab=access-tokens']}>
      <AccessTokensTab searchTerm="" />
      <LocationProbe />
    </MemoryRouter>
  );

describe('AccessTokensTab', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (apiClient.listAccessTokens as jest.Mock).mockResolvedValue([token]);
    (apiClient.revokeAccessToken as jest.Mock).mockResolvedValue(undefined);
  });

  it('navigates to the full-page create route', async () => {
    renderTab();
    await screen.findByTestId('access-token-row-agat_token1');

    await userEvent.click(screen.getByTestId('access-token-new-button'));
    expect(screen.getByTestId('location')).toHaveTextContent('/access-tokens/new');
  });

  it('opens the edit page when the token row is clicked', async () => {
    renderTab();
    const row = await screen.findByTestId('access-token-row-agat_token1');

    expect(screen.queryByTestId('access-token-edit-agat_token1')).not.toBeInTheDocument();
    await userEvent.click(row);
    expect(screen.getByTestId('location')).toHaveTextContent('/access-tokens/agat_token1');
  });

  it('uses the danger revoke action without opening the row', async () => {
    renderTab();
    const revoke = await screen.findByTestId('access-token-revoke-agat_token1');
    expect(revoke).toHaveClass('btn-danger');
    await userEvent.click(revoke);
    await userEvent.click(revoke);

    await waitFor(() => expect(apiClient.revokeAccessToken).toHaveBeenCalledWith('agat_token1'));
    expect(screen.getByTestId('location')).toHaveTextContent('/secrets?tab=access-tokens');
  });

  it('renders revoked status in red', async () => {
    (apiClient.listAccessTokens as jest.Mock).mockResolvedValueOnce([
      { ...token, active: false, revoked_at: '2026-09-09T10:00:00Z' },
    ]);
    renderTab();

    await userEvent.click(await screen.findByTestId('access-token-show-revoked'));
    expect(await screen.findByText('Revoked')).toHaveClass('text-bg-danger');
  });
});
