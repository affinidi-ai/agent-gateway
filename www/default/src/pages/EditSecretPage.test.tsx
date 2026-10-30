import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { apiClient } from '../api';
import { PageTitleProvider } from '../context/PageTitleContext';
import EditSecretPage from './EditSecretPage';

jest.mock('../api', () => ({
  apiClient: {
    get: jest.fn(),
    post: jest.fn(),
    put: jest.fn(),
    delete: jest.fn(),
    fetch: jest.fn(),
  },
}));

jest.mock('../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: () => true }),
}));

jest.mock('../utils/toaster', () => ({ showToast: jest.fn() }));

const storedSecret = {
  id: 'secret-1',
  name: 'OpenAI key',
  secret_id: 'openai_key',
  secret_type: 'ApiKey',
  tags: [],
  created_at: '2026-10-12T08:58:00Z',
  updated_at: '2026-10-12T08:58:00Z',
};

const renderPage = (path: string) =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <PageTitleProvider>
        <Routes>
          <Route path="/secrets/new" element={<EditSecretPage />} />
          <Route path="/secrets/:id" element={<EditSecretPage />} />
          <Route path="/secrets" element={<div data-testid="secrets-list-page" />} />
        </Routes>
      </PageTitleProvider>
    </MemoryRouter>
  );

describe('EditSecretPage', () => {
  const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto');

  afterEach(() => {
    if (originalCrypto) {
      Object.defineProperty(globalThis, 'crypto', originalCrypto);
    } else {
      delete (globalThis as { crypto?: Crypto }).crypto;
    }
  });

  beforeEach(() => {
    jest.clearAllMocks();
    (apiClient.get as jest.Mock).mockImplementation((url: string) => {
      if (url === '/secrets/secret-1') return Promise.resolve({ data: storedSecret });
      if (url === '/secrets/') return Promise.resolve({ data: [storedSecret] });
      return Promise.resolve({ data: {} });
    });
    (apiClient.put as jest.Mock).mockImplementation(
      (_url: string, { name, description, secret_type, tags }: Record<string, any>) =>
        Promise.resolve({ data: { ...storedSecret, name, description, secret_type, tags } })
    );
  });

  it('shows a single save button in edit mode', async () => {
    renderPage('/secrets/secret-1');
    await screen.findByDisplayValue('OpenAI key');

    const saveButtons = screen.getAllByRole('button', { name: /save/i });
    expect(saveButtons).toHaveLength(1);
    expect(saveButtons[0]).toBe(screen.getByTestId('secret-save-button'));
    expect(saveButtons[0]).toHaveTextContent('Save Changes');
  });

  it('hides the stored value and offers no reveal toggle until a new value is entered', async () => {
    renderPage('/secrets/secret-1');
    await screen.findByDisplayValue('OpenAI key');

    const valueInput = screen.getByTestId('secret-value-input');
    expect(valueInput).toBeDisabled();
    expect(valueInput).toHaveValue('');
    expect(valueInput).toHaveAttribute('placeholder', 'Stored value is hidden');
    expect(screen.queryByTestId('secret-value-reveal-checkbox')).not.toBeInTheDocument();
  });

  it('reveals a replacement value typed in edit mode and saves it', async () => {
    renderPage('/secrets/secret-1');
    await screen.findByDisplayValue('OpenAI key');

    await userEvent.click(screen.getByLabelText('Update Secret Value'));
    await userEvent.type(screen.getByTestId('secret-value-input'), 'sk-new');
    expect(screen.getByTestId('secret-value-input')).toHaveAttribute('type', 'password');

    await userEvent.click(screen.getByTestId('secret-value-reveal-checkbox'));
    const revealed = screen.getByTestId('secret-value-input');
    expect(revealed.tagName).toBe('TEXTAREA');
    expect(revealed).toHaveValue('sk-new');

    await userEvent.click(screen.getByTestId('secret-save-button'));
    await waitFor(() =>
      expect(apiClient.put).toHaveBeenCalledWith(
        '/secrets/secret-1',
        expect.objectContaining({ update_value: true, value: 'sk-new' })
      )
    );
  });

  it('never fills the value field from the loaded secret', async () => {
    (apiClient.get as jest.Mock).mockImplementation((url: string) =>
      Promise.resolve({
        data: url === '/secrets/secret-1' ? { ...storedSecret, value: 'sk-stored' } : {},
      })
    );
    renderPage('/secrets/secret-1');
    await screen.findByDisplayValue('OpenAI key');

    expect(screen.getByTestId('secret-value-input')).toHaveValue('');
    await userEvent.click(screen.getByLabelText('Update Secret Value'));
    expect(screen.getByTestId('secret-value-input')).toHaveValue('');
  });

  it('discards a typed value when the update is cancelled', async () => {
    renderPage('/secrets/secret-1');
    await screen.findByDisplayValue('OpenAI key');

    await userEvent.click(screen.getByLabelText('Update Secret Value'));
    await userEvent.type(screen.getByTestId('secret-value-input'), 'sk-cancelled');
    await userEvent.click(screen.getByTestId('secret-value-reveal-checkbox'));
    expect(screen.getByTestId('secret-value-input').tagName).toBe('TEXTAREA');

    await userEvent.click(screen.getByLabelText('Update Secret Value'));
    const hidden = screen.getByTestId('secret-value-input');
    expect(hidden).toHaveAttribute('type', 'password');
    expect(hidden).toBeDisabled();
    expect(hidden).toHaveValue('');
    expect(hidden).toHaveAttribute('placeholder', 'Stored value is hidden');
    expect(screen.queryByTestId('secret-value-reveal-checkbox')).not.toBeInTheDocument();

    await userEvent.click(screen.getByLabelText('Update Secret Value'));
    const reopened = screen.getByTestId('secret-value-input');
    expect(reopened).toHaveAttribute('type', 'password');
    expect(reopened).toHaveValue('');
    expect(screen.getByTestId('secret-value-reveal-checkbox')).not.toBeChecked();

    await userEvent.click(screen.getByLabelText('Update Secret Value'));
    expect(screen.getByTestId('secret-save-button')).toBeDisabled();
    fireEvent.keyDown(window, { key: 's', ctrlKey: true });
    expect(apiClient.put).not.toHaveBeenCalled();
  });

  it('keeps other edits when a value update is cancelled', async () => {
    renderPage('/secrets/secret-1');
    const nameInput = await screen.findByDisplayValue('OpenAI key');

    await userEvent.click(screen.getByLabelText('Update Secret Value'));
    await userEvent.type(nameInput, ' v2');
    await userEvent.type(screen.getByTestId('secret-value-input'), 'sk-cancelled');
    await userEvent.click(screen.getByLabelText('Update Secret Value'));

    const saveButton = screen.getByTestId('secret-save-button');
    expect(saveButton).toBeEnabled();
    await userEvent.click(saveButton);
    await waitFor(() => expect(apiClient.put).toHaveBeenCalled());
    const [, payload] = (apiClient.put as jest.Mock).mock.calls[0];
    expect(payload.name).toBe('OpenAI key v2');
    expect(payload.update_value).toBe(false);
    expect(payload).not.toHaveProperty('value');
    await waitFor(() => expect(saveButton).toBeDisabled());
  });

  it('treats a tag added and then removed as no change', async () => {
    renderPage('/secrets/secret-1');
    await screen.findByDisplayValue('OpenAI key');

    await userEvent.type(screen.getByLabelText('Tags'), 'prod{Enter}');
    expect(screen.getByTestId('secret-save-button')).toBeEnabled();

    const tagBadge = screen.getByText('prod', { selector: 'span' });
    await userEvent.click(within(tagBadge).getByRole('button'));
    expect(screen.getByTestId('secret-save-button')).toBeDisabled();
  });

  it('hides the saved value after a successful update', async () => {
    renderPage('/secrets/secret-1');
    await screen.findByDisplayValue('OpenAI key');

    await userEvent.click(screen.getByLabelText('Update Secret Value'));
    await userEvent.type(screen.getByTestId('secret-value-input'), 'sk-saved');
    await userEvent.click(screen.getByTestId('secret-value-reveal-checkbox'));
    await userEvent.click(screen.getByTestId('secret-save-button'));

    await waitFor(() =>
      expect(screen.getByTestId('secret-value-input')).toHaveAttribute(
        'placeholder',
        'Stored value is hidden'
      )
    );
    const valueInput = screen.getByTestId('secret-value-input');
    expect(valueInput).toHaveAttribute('type', 'password');
    expect(valueInput).toBeDisabled();
    expect(valueInput).toHaveValue('');
    expect(screen.getByLabelText('Update Secret Value')).not.toBeChecked();
    expect(screen.queryByTestId('secret-value-reveal-checkbox')).not.toBeInTheDocument();
    expect(screen.getByTestId('secret-save-button')).toBeDisabled();
  });

  it('enables the value update when a value is generated in edit mode', async () => {
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: jest.requireActual('crypto').webcrypto,
    });
    renderPage('/secrets/secret-1');
    await screen.findByDisplayValue('OpenAI key');

    await userEvent.click(screen.getByRole('button', { name: /generate/i }));
    expect(screen.getByLabelText('Update Secret Value')).toBeChecked();
    const valueInput = screen.getByTestId('secret-value-input');
    expect(valueInput).toBeEnabled();
    expect(screen.getByTestId('secret-value-reveal-checkbox')).toBeInTheDocument();

    await userEvent.click(screen.getByTestId('secret-save-button'));
    await waitFor(() => expect(apiClient.put).toHaveBeenCalled());
    const [, payload] = (apiClient.put as jest.Mock).mock.calls[0];
    expect(payload.update_value).toBe(true);
    expect(payload.value).toHaveLength(32);
  });

  it('saves with Ctrl+S', async () => {
    renderPage('/secrets/secret-1');
    const nameInput = await screen.findByDisplayValue('OpenAI key');

    await userEvent.type(nameInput, ' v2');
    fireEvent.keyDown(window, { key: 's', ctrlKey: true });

    await waitFor(() =>
      expect(apiClient.put).toHaveBeenCalledWith(
        '/secrets/secret-1',
        expect.objectContaining({ name: 'OpenAI key v2', update_value: false })
      )
    );
  });

  it('does not save with Ctrl+S when nothing changed', async () => {
    renderPage('/secrets/secret-1');
    await screen.findByDisplayValue('OpenAI key');

    fireEvent.keyDown(window, { key: 's', ctrlKey: true });
    expect(apiClient.put).not.toHaveBeenCalled();
  });

  it('reveals the value typed when creating a secret', async () => {
    renderPage('/secrets/new');
    const valueInput = await screen.findByTestId('secret-value-input');

    await userEvent.type(valueInput, 'sk-created');
    await userEvent.click(screen.getByTestId('secret-value-reveal-checkbox'));

    const revealed = screen.getByTestId('secret-value-input');
    expect(revealed.tagName).toBe('TEXTAREA');
    expect(revealed).toHaveValue('sk-created');
    expect(screen.getByTestId('secret-save-button')).toHaveTextContent('Create Secret');
  });

  describe('deleting', () => {
    const json = (body: unknown) => Promise.resolve({ ok: true, json: async () => body });

    const providerRefs = (refs: Record<string, unknown>) =>
      (apiClient.fetch as jest.Mock).mockImplementation((url: string) =>
        url === '/api/v1/credential-providers'
          ? json([{ id: 'p1', name: 'Hop 2 provider' }])
          : json(refs)
      );

    const clickDelete = async () => {
      await screen.findByDisplayValue('OpenAI key');
      fireEvent.click(screen.getByTitle('Delete this secret'));
      fireEvent.click(screen.getByTitle('Click again to confirm deletion'));
    };

    it('warns with the provider names, then deletes and leaves for the list after confirmation', async () => {
      providerRefs({ client_secret_secret_ref: 'openai_key' });
      (apiClient.delete as jest.Mock).mockResolvedValue({});
      renderPage('/secrets/secret-1');
      await clickDelete();

      const warning = await screen.findByTestId('secret-delete-warning');
      expect(warning).toHaveTextContent('Hop 2 provider');
      expect(apiClient.delete).not.toHaveBeenCalled();

      fireEvent.click(screen.getByTestId('secret-delete-warning-confirm-button'));
      await waitFor(() => expect(apiClient.delete).toHaveBeenCalledWith('/secrets/secret-1'));
      expect(await screen.findByTestId('secrets-list-page')).toBeInTheDocument();
    });

    it('deletes without a warning when no provider references the secret', async () => {
      providerRefs({ client_secret_secret_ref: 'another_secret' });
      (apiClient.delete as jest.Mock).mockResolvedValue({});
      renderPage('/secrets/secret-1');
      await clickDelete();

      await waitFor(() => expect(apiClient.delete).toHaveBeenCalledWith('/secrets/secret-1'));
      expect(screen.queryByTestId('secret-delete-warning')).not.toBeInTheDocument();
    });
  });
});
