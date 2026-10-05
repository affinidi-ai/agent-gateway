import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { apiClient } from '../../api';
import { PageTitleProvider } from '../../context/PageTitleContext';
import { showToast } from '../../utils/toaster';
import { toLocalDateTimeInput } from '../SecretsPage/accessTokenHelpers';
import EditAccessTokenPage from '.';
import { accessToken as token, createdAccessToken as created } from './accessTokenTestFixtures';

/* eslint-disable no-template-curly-in-string */

jest.mock('../../api', () => ({
  apiClient: {
    get: jest.fn().mockResolvedValue({ data: {} }),
    getAccessToken: jest.fn(),
    createAccessToken: jest.fn(),
    updateAccessToken: jest.fn(),
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
    hasPermission: () => true,
  }),
}));

jest.mock('../../utils/toaster', () => ({ showToast: jest.fn() }));

const LocationProbe = () => {
  const location = useLocation();
  return <output data-testid="location">{`${location.pathname}${location.search}`}</output>;
};

const renderPage = (path = '/access-tokens/new') =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <PageTitleProvider>
        <Routes>
          <Route path="/access-tokens/new" element={<EditAccessTokenPage />} />
          <Route path="/access-tokens/:id" element={<EditAccessTokenPage />} />
          <Route path="/secrets" element={<div data-testid="access-token-list-page" />} />
        </Routes>
        <LocationProbe />
      </PageTitleProvider>
    </MemoryRouter>
  );

describe('EditAccessTokenPage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: jest.fn().mockResolvedValue(undefined) },
    });
    (apiClient.get as jest.Mock).mockResolvedValue({ data: {} });
    (apiClient.getAccessToken as jest.Mock).mockResolvedValue(token);
    (apiClient.createAccessToken as jest.Mock).mockResolvedValue(created);
    (apiClient.updateAccessToken as jest.Mock).mockResolvedValue(token);
    (apiClient.revokeAccessToken as jest.Mock).mockResolvedValue(undefined);
  });

  it('creates a token and replaces the full page with its one-time secret', async () => {
    renderPage();
    await userEvent.type(screen.getByTestId('access-token-name'), 'Deploy token');
    await userEvent.click(screen.getByTestId('access-token-form-save-button'));

    await waitFor(() => expect(apiClient.createAccessToken).toHaveBeenCalled());
    expect(await screen.findByTestId('page-access-token-created')).toBeVisible();
    expect(screen.getByTestId('access-token-secret')).toHaveValue('agpat_once-only');

    await userEvent.click(screen.getByTestId('access-token-done-button'));
    expect(screen.getByTestId('location')).toHaveTextContent('/secrets?tab=access-tokens');
  });

  it('adds and removes permission scopes as pills', async () => {
    renderPage();

    await userEvent.click(screen.getByTestId('access-token-scope-add-gateways.view'));
    expect(screen.getByTestId('access-token-selected-scope-gateways.view')).toBeVisible();
    expect(screen.queryByTestId('access-token-scope-add-gateways.view')).not.toBeInTheDocument();

    await userEvent.click(screen.getByTestId('access-token-scope-remove-gateways.view'));
    expect(
      screen.queryByTestId('access-token-selected-scope-gateways.view')
    ).not.toBeInTheDocument();
    expect(screen.getByTestId('access-token-scope-add-gateways.view')).toBeVisible();
  });

  it('blocks stale stored scopes until the operator removes their pills', async () => {
    (apiClient.getAccessToken as jest.Mock).mockResolvedValueOnce({
      ...token,
      scopes: ['gateways.view', 'removed.scope'],
    });
    renderPage('/access-tokens/agat_token1');

    expect(await screen.findByTestId('access-token-unavailable-scopes')).toHaveTextContent(
      'Remove the red unavailable scopes'
    );
    expect(screen.getByTestId('access-token-form-save-button')).toBeEnabled();
    await userEvent.click(screen.getByTestId('access-token-form-save-button'));
    expect(apiClient.updateAccessToken).not.toHaveBeenCalled();
    await userEvent.click(
      screen.getByTestId('access-token-remove-unavailable-scope-removed.scope')
    );
    expect(screen.queryByTestId('access-token-unavailable-scopes')).not.toBeInTheDocument();
    expect(screen.getByTestId('access-token-form-save-button')).toBeEnabled();
  });

  it('creates an expiring token from an exact local date and time', async () => {
    renderPage();
    await userEvent.type(screen.getByTestId('access-token-name'), 'Expiring token');

    const never = screen.getByTestId('access-token-never-expires');
    const expiry = screen.getByTestId('access-token-expiry-date-time');
    expect(never).toBeChecked();
    expect(expiry).toBeDisabled();

    await userEvent.click(never);
    const localValue = toLocalDateTimeInput(new Date(Date.now() + 6 * 60 * 60 * 1000));
    fireEvent.change(expiry, { target: { value: localValue } });
    await userEvent.click(screen.getByTestId('access-token-form-save-button'));

    await waitFor(() =>
      expect(apiClient.createAccessToken).toHaveBeenCalledWith(
        expect.objectContaining({ expires_at: new Date(localValue).toISOString() })
      )
    );
  });

  it('blocks invalid expiration and tenant patterns', async () => {
    renderPage();
    await userEvent.type(screen.getByTestId('access-token-name'), 'Invalid token');
    await userEvent.click(screen.getByTestId('access-token-never-expires'));
    fireEvent.change(screen.getByTestId('access-token-expiry-date-time'), {
      target: { value: toLocalDateTimeInput(new Date(Date.now() - 60 * 60 * 1000)) },
    });
    await userEvent.click(screen.getByTestId('access-token-resource-scope-toggle'));
    fireEvent.change(screen.getByTestId('access-token-resource-pattern'), {
      target: { value: 'TENANT:${account}:${region}:.*' },
    });

    expect(screen.getByTestId('access-token-expiry-error')).toHaveTextContent(
      'Expiration must be in the future.'
    );
    expect(
      screen.getByText('Resource pattern may select a tenant from only one distinct header.')
    ).toBeVisible();
    expect(screen.getByTestId('access-token-form-save-button')).toBeEnabled();
    await userEvent.click(screen.getByTestId('access-token-form-save-button'));
    expect(apiClient.createAccessToken).not.toHaveBeenCalled();
  });

  it('warns when the holder selects a tenant through a matching header value', async () => {
    renderPage();
    await userEvent.click(screen.getByTestId('access-token-resource-scope-toggle'));
    fireEvent.change(screen.getByTestId('access-token-resource-pattern'), {
      target: { value: 'TENANT:${account}:secrets:.*' },
    });

    expect(screen.getByTestId('access-token-tenant-selection-warning')).toHaveTextContent(
      'Use an exact-value pattern for a single-tenant token'
    );
  });

  it('ignores a create response after the page unmounts', async () => {
    let resolveCreate: (value: typeof created) => void = () => {};
    (apiClient.createAccessToken as jest.Mock).mockImplementationOnce(
      () => new Promise(resolve => (resolveCreate = resolve))
    );
    const view = renderPage();
    await userEvent.type(screen.getByTestId('access-token-name'), 'Slow token');
    await userEvent.click(screen.getByTestId('access-token-form-save-button'));
    expect(screen.getByTestId('access-token-back-button')).toBeDisabled();

    view.unmount();
    await act(async () => resolveCreate(created));
    expect(showToast).not.toHaveBeenCalled();
  });

  it('reports clipboard rejection without claiming success', async () => {
    (navigator.clipboard.writeText as jest.Mock).mockRejectedValueOnce(new Error('denied'));
    renderPage();
    await userEvent.type(screen.getByTestId('access-token-name'), 'Copy test');
    await userEvent.click(screen.getByTestId('access-token-form-save-button'));

    const copy = await screen.findByTestId('access-token-copy-secret-button');
    await userEvent.click(copy);
    expect(showToast).toHaveBeenCalledWith(
      'error',
      'Could not copy the token. Select the secret and copy it manually.'
    );
    expect(copy).toHaveTextContent('Copy');
    expect(copy).not.toHaveTextContent('Copied');
  });
});
