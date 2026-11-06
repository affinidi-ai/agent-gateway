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

  it('shows the surfaces that still name the key when the gateway refuses the delete', async () => {
    const message =
      'API key is named by surface(s) user-a; remove it from them before deleting the key (409)';
    (apiClient.deleteApiKey as jest.Mock).mockRejectedValue(new Error(message));
    renderPage();

    const remove = await screen.findByTitle('Delete this API key');
    await userEvent.click(remove);
    await userEvent.click(remove);

    await waitFor(() =>
      expect(showToast).toHaveBeenCalledWith('error', `Delete failed: ${message}`, {
        autoRemove: false,
      })
    );
    expect(apiClient.deleteApiKey).toHaveBeenCalledWith('owner-a', 'atgk_named');
    expect(mockNavigate).not.toHaveBeenCalled();
  });

  it('returns to the secrets page after a delete', async () => {
    (apiClient.deleteApiKey as jest.Mock).mockResolvedValue({});
    renderPage();

    const remove = await screen.findByTitle('Delete this API key');
    await userEvent.click(remove);
    await userEvent.click(remove);

    await waitFor(() => expect(mockNavigate).toHaveBeenCalledWith('/secrets'));
    expect(showToast).toHaveBeenCalledWith('success', 'API key deleted');
  });
});
