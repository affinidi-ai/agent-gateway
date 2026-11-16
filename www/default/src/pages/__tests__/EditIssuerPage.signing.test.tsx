import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import EditIssuerPage from '../EditIssuerPage';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({
  apiClient: {
    get: jest.fn(),
    put: jest.fn(),
    post: jest.fn(),
    delete: jest.fn(),
    fetch: jest.fn(),
    listTrustRegistries: jest.fn(),
    getGatewayDidDocument: jest.fn(),
  },
}));
jest.mock('../../hooks/useSafeNavigate', () => ({
  useSafeNavigate: () => ({ navigate: jest.fn() }),
}));
jest.mock('../../utils/toaster', () => ({ showToast: jest.fn() }));

const api = apiClient as unknown as Record<string, jest.Mock>;

const agent = {
  id: 'agent-1',
  name: 'Production agent',
  enabled: true,
  transport: 'https',
  endpoint: 'https://vta.example.com',
  vta_did: 'did:webvh:abc:vta.example.com',
  default_context_id: 'gateway',
  status: 'connected',
  pairing: { state: 'connected' },
  keys: { active: { key_id: 'key-1' } },
};

const issuer = (signing?: Record<string, string>) => ({
  id: 'issuer-1',
  name: 'Research',
  description: 'Research team',
  did: 'did:webvh:abc:localhost%3A8080:issuers:issuer-1',
  ...(signing ? { signing } : {}),
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
});

const open = async (id: string, signing?: Record<string, string>) => {
  api.get.mockResolvedValue({ data: id === 'new' ? undefined : issuer(signing) });
  api.put.mockResolvedValue({ data: {} });
  api.post.mockResolvedValue({ data: {} });
  api.listTrustRegistries.mockResolvedValue([]);
  api.getGatewayDidDocument.mockResolvedValue({});
  api.fetch.mockImplementation((url: string) =>
    Promise.resolve({
      ok: true,
      json: () =>
        Promise.resolve(
          url.includes('/vta/status') ? { default_resolution: { backend: 'local' } } : [agent]
        ),
    })
  );
  render(
    <MemoryRouter initialEntries={[`/issuers/${id}`]}>
      <Routes>
        <Route path="/issuers/:id" element={<EditIssuerPage />} />
      </Routes>
    </MemoryRouter>
  );
  await screen.findByTestId('issuer-signing');
};

const typeSelect = () => screen.getByTestId('surface-signing-type-select') as HTMLSelectElement;

describe('EditIssuerPage signing', () => {
  it('shows an issuer that follows the appliance default as inheriting', async () => {
    await open('issuer-1');

    expect(typeSelect()).toHaveValue('local');
    expect(screen.getByTestId('surface-signing-inherited')).toHaveTextContent(
      "Choose a type to set this issuer's own."
    );
  });

  it('shows the trust agent an issuer signs through, and saves a change to Local', async () => {
    await open('issuer-1', {
      backend: 'vta',
      connection_id: 'agent-1',
      context_id: 'gateway',
      key_id: 'key-1',
    });

    await waitFor(() => expect(typeSelect()).toHaveValue('remote'));
    expect(await screen.findByRole('option', { name: 'Production agent' })).toBeInTheDocument();
    expect(screen.getByTestId('surface-signing-agent-select')).toHaveValue('agent-1');

    await userEvent.selectOptions(typeSelect(), 'local');
    await userEvent.click(screen.getByTestId('issuer-editor-save-button'));

    await waitFor(() => expect(api.put).toHaveBeenCalled());
    expect(api.put).toHaveBeenCalledWith('/issuers/issuer-1', {
      name: 'Research',
      description: 'Research team',
      signing: { backend: 'local' },
    });
  });

  it('saves a chosen trust agent with its context and key', async () => {
    await open('issuer-1');

    await userEvent.selectOptions(typeSelect(), 'remote');
    await screen.findByRole('option', { name: 'Production agent' });
    await userEvent.selectOptions(screen.getByTestId('surface-signing-agent-select'), 'agent-1');
    await userEvent.click(screen.getByTestId('issuer-editor-save-button'));

    await waitFor(() => expect(api.put).toHaveBeenCalled());
    expect(api.put.mock.calls[0][1].signing).toEqual({
      backend: 'vta',
      connection_id: 'agent-1',
      context_id: 'gateway',
      key_id: 'key-1',
    });
  });

  it('sends an empty block to hand the issuer back to the appliance default', async () => {
    await open('issuer-1', { backend: 'local' });

    await userEvent.click(screen.getByTestId('surface-signing-reset'));
    await userEvent.click(screen.getByTestId('issuer-editor-save-button'));

    await waitFor(() => expect(api.put).toHaveBeenCalled());
    expect(api.put.mock.calls[0][1].signing).toEqual({});
  });
});
