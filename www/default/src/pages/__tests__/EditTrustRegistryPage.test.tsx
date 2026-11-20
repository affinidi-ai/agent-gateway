import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import EditTrustRegistryPage from '../EditTrustRegistryPage';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({
  apiClient: {
    get: jest.fn(),
  },
}));

jest.mock('../../hooks/useSafeNavigate', () => ({
  useSafeNavigate: () => ({ navigate: jest.fn() }),
}));

const mockGet = apiClient.get as jest.Mock;

const registry = (name: string, description: string) => ({
  data: {
    id: 'tr-1',
    name,
    description,
    oob_url: 'https://registry.example/oob',
    connection_status: 'connected',
    status: 'active',
    created_at: '2026-11-18T10:00:00Z',
    updated_at: '2026-11-18T10:00:00Z',
  },
});

const renderPage = () =>
  render(
    <MemoryRouter initialEntries={['/trust-registries/tr-1']}>
      <Routes>
        <Route path="/trust-registries/:id" element={<EditTrustRegistryPage />} />
      </Routes>
    </MemoryRouter>
  );

const refreshDashboard = () =>
  act(() => {
    window.dispatchEvent(new CustomEvent('ws-message', { detail: { type: 'refresh_dashboard' } }));
  });

describe('EditTrustRegistryPage', () => {
  beforeEach(() => {
    mockGet.mockReset();
  });

  it('keeps an edited field and updates an untouched one when the dashboard refreshes', async () => {
    mockGet
      .mockResolvedValueOnce(registry('Registry', 'Stored description'))
      .mockResolvedValueOnce(registry('Registry renamed', 'Newer description'));
    renderPage();
    const name = await screen.findByLabelText('Name *');

    fireEvent.change(name, { target: { value: 'My unsaved name' } });
    refreshDashboard();

    await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(2));
    await waitFor(() =>
      expect(screen.getByLabelText('Description')).toHaveValue('Newer description')
    );
    expect(screen.getByLabelText('Name *')).toHaveValue('My unsaved name');
    expect(screen.getByLabelText('Name *')).toBe(name);
  });

  it('takes the refreshed values while nothing was edited', async () => {
    mockGet
      .mockResolvedValueOnce(registry('Registry', 'Stored description'))
      .mockResolvedValueOnce(registry('Registry renamed', 'Newer description'));
    renderPage();
    await screen.findByLabelText('Name *');

    refreshDashboard();

    await waitFor(() => expect(screen.getByLabelText('Name *')).toHaveValue('Registry renamed'));
    expect(screen.getByLabelText('Description')).toHaveValue('Newer description');
  });
});
