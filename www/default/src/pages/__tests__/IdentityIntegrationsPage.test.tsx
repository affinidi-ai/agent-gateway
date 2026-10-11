import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import IdentityIntegrationsPage from '../IdentityIntegrationsPage';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({
  apiClient: {
    get: jest.fn(),
    put: jest.fn(),
  },
}));

jest.mock('../../utils/runtimeVariables', () => ({
  getRuntimeVariablesForCategories: jest.fn().mockResolvedValue({}),
}));

const mockGet = apiClient.get as jest.Mock;
const mockPut = apiClient.put as jest.Mock;

const CONFIG = {
  categories: [
    {
      enum_value: 'identity',
      metadata: {
        event_types: [
          { event_type: 'identity.created', name: 'Identity Created', description: 'Created' },
          { event_type: 'identity.updated', name: 'Identity Updated', description: 'Updated' },
        ],
      },
    },
  ],
};

const respond = (stored: () => Promise<unknown>) => {
  mockGet.mockImplementation((url: string) => {
    switch (url) {
      case '/identities/integrations':
        return stored();
      case '/integrations':
        return Promise.resolve({
          data: [{ id: 'int-general', name: 'Agent Watch', type: 'webhook', category: 'general' }],
        });
      case '/integrations/config':
        return Promise.resolve({ data: CONFIG });
      default:
        return Promise.reject(new Error(`unexpected GET ${url}`));
    }
  });
};

const renderPage = () =>
  render(
    <MemoryRouter>
      <IdentityIntegrationsPage />
    </MemoryRouter>
  );

const saveButton = () => screen.getByTestId('identity-integrations-save-button');

describe('IdentityIntegrationsPage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('shows a load failure and offers no editor that could overwrite the stored mappings', async () => {
    respond(() => Promise.reject(new Error('Forbidden (403)')));
    renderPage();

    expect(await screen.findByText(/Forbidden \(403\)/)).toBeInTheDocument();
    expect(screen.queryByTestId('integrations-step-select')).not.toBeInTheDocument();
    expect(screen.queryByTestId('identity-integrations-save-button')).not.toBeInTheDocument();
  });

  it('keeps Save disabled until the attached integration names an event', async () => {
    respond(() => Promise.resolve({ data: { integration_integrations: [] } }));
    renderPage();

    fireEvent.change(await screen.findByTestId('integrations-step-select'), {
      target: { value: 'int-general' },
    });
    expect(saveButton()).toBeDisabled();

    fireEvent.click(screen.getByTestId('integration-0-event-identity.created'));
    expect(saveButton()).toBeEnabled();
  });

  it('shows a stored mapping whose integration is gone and saves once it is removed', async () => {
    respond(() =>
      Promise.resolve({
        data: {
          integration_integrations: [
            { integration_id: 'int-deleted', variables: {}, event_types: ['identity.created'] },
            { integration_id: 'int-general', variables: {}, event_types: ['identity.created'] },
          ],
        },
      })
    );
    mockPut.mockResolvedValue({ data: {} });
    renderPage();

    const orphan = await screen.findByTestId('integration-0-unavailable');
    expect(within(orphan).getByText('int-deleted')).toBeInTheDocument();
    fireEvent.click(screen.getByText('Agent Watch'));
    fireEvent.click(screen.getByTestId('integration-1-event-identity.updated'));
    expect(saveButton()).toBeDisabled();

    fireEvent.click(within(orphan).getByTitle('Remove integration'));
    expect(saveButton()).toBeEnabled();
    fireEvent.click(saveButton());

    await waitFor(() =>
      expect(mockPut).toHaveBeenCalledWith('/identities/integrations', {
        integration_integrations: [
          {
            integration_id: 'int-general',
            variables: {},
            event_types: ['identity.created', 'identity.updated'],
          },
        ],
      })
    );
  });

  it('shows a save failure instead of reporting success', async () => {
    respond(() => Promise.resolve({ data: { integration_integrations: [] } }));
    mockPut.mockRejectedValue(new Error('Integration reference is not accessible (400)'));
    renderPage();

    fireEvent.change(await screen.findByTestId('integrations-step-select'), {
      target: { value: 'int-general' },
    });
    fireEvent.click(screen.getByTestId('integration-0-event-identity.created'));
    fireEvent.click(saveButton());

    expect(
      await screen.findByText(/Integration reference is not accessible \(400\)/)
    ).toBeInTheDocument();
    expect(screen.queryByText(/updated successfully/)).not.toBeInTheDocument();
  });
});
