import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import ApiKeyDetailPage from '../ApiKeyDetailPage';
import { apiClient } from '../../api';
import { showToast } from '../../utils/toaster';

jest.mock('../../utils/toaster', () => ({ showToast: jest.fn() }));

jest.mock('../../api', () => ({
  apiClient: {
    getApiKey: jest.fn(),
    deleteApiKey: jest.fn(),
  },
}));

jest.mock('../../context/AppContext', () => ({
  useApp: () => ({ getCurrentStats: () => ({ channels: [] }) }),
}));

const mockNavigate = jest.fn();
jest.mock('../../hooks/useSafeNavigate', () => ({
  useSafeNavigate: () => ({ navigate: mockNavigate }),
}));

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/api-keys/owner-a/atgk_named']}>
      <Routes>
        <Route path="/api-keys/:agentId/:keyId" element={<ApiKeyDetailPage />} />
      </Routes>
    </MemoryRouter>
  );
}

describe('ApiKeyDetailPage delete', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (apiClient.getApiKey as jest.Mock).mockResolvedValue({
      key_id: 'atgk_named',
      agent_id: 'owner-a',
      client_id: 'client-a',
      status: 'active',
      created_at: '2026-07-01T10:00:00Z',
      labels: {},
      issuer: { actor: 'admin', method: 'api' },
    });
  });

  it('shows why a delete failed and stays on the page', async () => {
    const message = 'Internal server error (500)';
    (apiClient.deleteApiKey as jest.Mock).mockRejectedValue(new Error(message));
    renderPage();

    await userEvent.click(await screen.findByTitle('Delete this API key'));
    await userEvent.click(screen.getByTestId('api-key-delete-dialog-confirm'));

    await waitFor(() =>
      expect(showToast).toHaveBeenCalledWith('error', `Delete failed: ${message}`, {
        autoRemove: false,
      })
    );
    expect(apiClient.deleteApiKey).toHaveBeenCalledWith('owner-a', 'atgk_named');
    expect(screen.queryByTestId('api-key-delete-dialog')).toBeNull();
    expect(mockNavigate).not.toHaveBeenCalled();
  });

  it('asks for confirmation, then deletes and returns to the secrets page', async () => {
    (apiClient.deleteApiKey as jest.Mock).mockResolvedValue(undefined);
    renderPage();

    await userEvent.click(await screen.findByTitle('Delete this API key'));

    const dialog = screen.getByTestId('api-key-delete-dialog');
    expect(dialog).toHaveTextContent('client-a');
    expect(dialog).toHaveTextContent('Surfaces that use it will stop working');
    const confirm = screen.getByTestId('api-key-delete-dialog-confirm');
    expect(confirm).toBeEnabled();
    expect(apiClient.deleteApiKey).not.toHaveBeenCalled();

    await userEvent.click(confirm);

    await waitFor(() => expect(mockNavigate).toHaveBeenCalledWith('/secrets'));
    expect(apiClient.deleteApiKey).toHaveBeenCalledTimes(1);
    expect(apiClient.deleteApiKey).toHaveBeenCalledWith('owner-a', 'atgk_named');
    expect(showToast).toHaveBeenCalledWith('success', 'API key deleted');
  });
});

describe('ApiKeyDetailPage surface deleted', () => {
  const key = {
    key_id: 'atgk_named',
    agent_id: 'owner-a',
    client_id: 'client-a',
    status: 'active',
    created_at: '2026-07-01T10:00:00Z',
    labels: {},
    issuer: { actor: 'admin', method: 'api' },
  };

  beforeEach(() => jest.clearAllMocks());

  it('says the key is no longer in use when its surface was deleted', async () => {
    (apiClient.getApiKey as jest.Mock).mockResolvedValue({ ...key, surface_deleted: true });
    renderPage();

    expect(await screen.findByTestId('api-key-surface-deleted-info')).toHaveTextContent(
      'This API key is no longer in use because the associated surface has been deleted.'
    );
  });

  it.each([false, undefined])('shows no message when surface_deleted is %s', async value => {
    (apiClient.getApiKey as jest.Mock).mockResolvedValue({ ...key, surface_deleted: value });
    renderPage();

    expect(await screen.findByText('client-a')).toBeInTheDocument();
    expect(screen.queryByTestId('api-key-surface-deleted-info')).toBeNull();
  });
});
