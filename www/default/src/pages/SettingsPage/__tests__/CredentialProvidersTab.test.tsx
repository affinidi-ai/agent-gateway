import React from 'react';
import { render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import CredentialProvidersTab from '../CredentialProvidersTab';
import { apiClient } from '../../../api';

jest.mock('../../../api', () => ({
  apiClient: { get: jest.fn(), put: jest.fn(), post: jest.fn(), fetch: jest.fn() },
}));
jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: () => false, loading: false }),
}));

const mockFetch = apiClient.fetch as jest.Mock;

const item = (name: string, token_endpoint: string, resource: string | null) => ({
  id: name,
  name,
  provider_id: name,
  provider_type: 'oauth2_client_credentials',
  token_endpoint,
  resource,
  default_scopes: [],
  token_refresh_enabled: false,
  created_at: '2026-10-30T00:00:00Z',
  updated_at: '2026-10-30T00:00:00Z',
});

describe('CredentialProvidersTab', () => {
  it('flags only the Entra v2.0 provider that sets a resource', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve([
          item(
            'entra-resource',
            'https://login.microsoftonline.com/t/oauth2/v2.0/token',
            'https://ai.azure.com'
          ),
          item('entra-scope', 'https://login.microsoftonline.com/t/oauth2/v2.0/token', null),
          item('google', 'https://oauth2.googleapis.com/token', 'https://api.example'),
        ]),
    });
    render(
      <MemoryRouter>
        <CredentialProvidersTab />
      </MemoryRouter>
    );
    const flagged = await screen.findByRole('row', { name: /^entra-resource/ });
    const badge = within(flagged).getByTestId('credential-provider-entra-resource-badge');
    expect(badge).toHaveAttribute('title', expect.stringContaining('AADSTS901002'));
    expect(screen.getAllByTestId('credential-provider-entra-resource-badge')).toHaveLength(1);
  });
});
