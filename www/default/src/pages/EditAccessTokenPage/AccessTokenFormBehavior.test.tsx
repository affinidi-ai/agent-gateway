import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { apiClient } from '../../api';
import { PageTitleProvider } from '../../context/PageTitleContext';
import { showToast } from '../../utils/toaster';
import EditAccessTokenPage from '.';
import { accessToken as token, createdAccessToken as created } from './accessTokenTestFixtures';

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

describe('Access token form behavior', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (apiClient.get as jest.Mock).mockResolvedValue({ data: {} });
    (apiClient.getAccessToken as jest.Mock).mockResolvedValue(token);
    (apiClient.createAccessToken as jest.Mock).mockResolvedValue(created);
    (apiClient.updateAccessToken as jest.Mock).mockResolvedValue(token);
  });

  it('shows required-field errors after submit instead of disabling save', async () => {
    renderPage();

    const name = screen.getByTestId('access-token-name');
    expect(name).toBeRequired();
    expect(name).toHaveAttribute('placeholder', 'e.g. external');
    expect(screen.getByTestId('access-token-save-button')).toBeEnabled();
    expect(screen.getByTestId('access-token-form-save-button')).toBeEnabled();

    await userEvent.click(screen.getByTestId('access-token-form-save-button'));

    const validationAlert = await screen.findByTestId('access-token-validation-alert');
    expect(validationAlert).toHaveClass('alert-danger');
    expect(screen.getByTestId('access-token-validation-alert-icon')).toBeInTheDocument();
    expect(validationAlert).toHaveTextContent('Please correct the highlighted fields');
    expect(await screen.findByTestId('access-token-name-error')).toHaveTextContent(
      'Name is required.'
    );
    expect(apiClient.createAccessToken).not.toHaveBeenCalled();
  });

  it('validates added header fields as required', async () => {
    renderPage();
    await userEvent.type(screen.getByTestId('access-token-name'), 'Automation');
    await userEvent.click(screen.getByTestId('access-token-resource-scope-toggle'));
    await userEvent.click(screen.getByTestId('access-token-add-header'));

    expect(screen.getByTestId('access-token-header-name-0')).toBeRequired();
    expect(screen.getByTestId('access-token-header-pattern-0')).toBeRequired();
    await userEvent.click(screen.getByTestId('access-token-form-save-button'));

    expect(screen.getByTestId('access-token-header-name-error-0')).toHaveTextContent(
      'Header name is required.'
    );
    expect(screen.getByTestId('access-token-header-pattern-error-0')).toHaveTextContent(
      'Validation pattern is required.'
    );
    expect(apiClient.createAccessToken).not.toHaveBeenCalled();
  });

  it('uses concise scope terminology and displays Never in the expiry input', () => {
    renderPage();

    expect(screen.getByTestId('access-token-description').tagName).toBe('INPUT');
    expect(screen.getByText('Selected scopes')).toBeVisible();
    expect(screen.getByLabelText('Available scopes')).toBeVisible();
    expect(screen.getByTestId('access-token-scope-filter')).toHaveAttribute(
      'placeholder',
      'Filter scopes...'
    );
    expect(screen.getByTestId('access-token-expiry-date-time')).toHaveValue('Never');
    expect(screen.getByTestId('access-token-expiry-date-time')).toBeDisabled();
  });

  it('uses the shared collapsible card styling for advanced resource scoping', async () => {
    renderPage();

    expect(screen.getByTestId('access-token-resource-scope')).toHaveClass('card', 'shadow', 'mb-4');
    expect(screen.getByTestId('access-token-resource-scope-toggle')).toHaveClass(
      'card-header',
      'py-3',
      'cursor-pointer'
    );
    expect(screen.queryByTestId('access-token-resource-scope-content')).not.toBeInTheDocument();

    await userEvent.click(screen.getByTestId('access-token-resource-scope-toggle'));
    expect(screen.getByTestId('access-token-resource-scope-content')).toBeVisible();
  });

  it('aligns the live scope tester with the canonical layout', async () => {
    renderPage();
    await userEvent.click(screen.getByTestId('access-token-resource-scope-toggle'));
    expect(screen.queryByTestId('access-token-scope-preview')).not.toBeInTheDocument();

    await userEvent.click(screen.getByTestId('access-token-add-header'));
    await userEvent.type(screen.getByTestId('access-token-header-name-0'), 'account');
    fireEvent.change(screen.getByTestId('access-token-header-pattern-0'), {
      target: { value: 'tenant-a' },
    });
    fireEvent.change(screen.getByTestId('access-token-resource-pattern'), {
      target: { value: 'TENANT:${account}:gateways:.*' },
    });

    expect(screen.getByTestId('access-token-scope-preview')).toHaveClass(
      'card',
      'bg-light',
      'border-0'
    );
    expect(screen.getByText('Test this scope')).toBeVisible();
    expect(screen.getByText('Patterns must match the entire sample value.')).toBeVisible();
    expect(screen.getByTestId('access-token-header-pattern-0')).toHaveAttribute(
      'placeholder',
      'e.g. \\d{4}'
    );
    fireEvent.change(screen.getByTestId('access-token-test-header-0'), {
      target: { value: 'tenant-a' },
    });
    fireEvent.change(screen.getByTestId('access-token-test-id'), {
      target: { value: 'gateway-1' },
    });

    expect(screen.getByTestId('access-token-test-result')).toHaveTextContent('allowed');
    expect(screen.getByTestId('access-token-canonical-target')).toHaveTextContent(
      'TENANT:tenant-a:gateways:gateway-1'
    );
  });

  it('places expiry last and saves with Cmd or Ctrl plus S', async () => {
    renderPage();
    const resourceScope = screen.getByTestId('access-token-resource-scope');
    const expiry = screen.getByTestId('access-token-expiry-date-time');
    expect(
      resourceScope.compareDocumentPosition(expiry) & Node.DOCUMENT_POSITION_FOLLOWING
    ).toBeTruthy();

    await userEvent.type(screen.getByTestId('access-token-name'), 'Keyboard token');
    fireEvent.keyDown(window, { key: 's', metaKey: true });

    await waitFor(() => expect(apiClient.createAccessToken).toHaveBeenCalled());
  });

  it('saves and keeps an existing token editor open with the form button', async () => {
    renderPage('/access-tokens/agat_token1');
    const name = await screen.findByTestId('access-token-name');
    await userEvent.clear(name);
    await userEvent.type(name, 'Updated automation');

    await userEvent.click(screen.getByTestId('access-token-form-save-button'));

    await waitFor(() => expect(apiClient.updateAccessToken).toHaveBeenCalled());
    await waitFor(() => expect(showToast).toHaveBeenCalledWith('success', 'Access token updated'));
    expect(screen.getByTestId('location')).toHaveTextContent('/access-tokens/agat_token1');
    expect(screen.getByTestId('page-access-token')).toBeVisible();
  });

  it('saves and keeps an existing token editor open with Cmd or Ctrl plus S', async () => {
    renderPage('/access-tokens/agat_token1');
    const name = await screen.findByTestId('access-token-name');
    await userEvent.clear(name);
    await userEvent.type(name, 'Updated automation');

    fireEvent.keyDown(window, { key: 's', metaKey: true });

    await waitFor(() => expect(apiClient.updateAccessToken).toHaveBeenCalled());
    await waitFor(() => expect(showToast).toHaveBeenCalledWith('success', 'Access token updated'));
    expect(screen.getByTestId('location')).toHaveTextContent('/access-tokens/agat_token1');
    expect(screen.getByTestId('page-access-token')).toBeVisible();
  });
});
