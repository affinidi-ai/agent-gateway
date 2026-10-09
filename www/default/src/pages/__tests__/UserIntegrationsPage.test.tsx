/* eslint-disable no-template-curly-in-string */
import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import UserIntegrationsPage from '../UserIntegrationsPage';
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

const AVAILABLE = [
  {
    id: 'int-general',
    name: 'Agent Watch',
    type: 'webhook',
    category: 'general',
    content: { event: '${EVENT_TYPE}' },
  },
];

const CONFIG = {
  categories: [
    {
      enum_value: 'user',
      metadata: {
        event_types: [
          { event_type: 'user.created', name: 'New User Registered', description: 'Registered' },
          { event_type: 'user.login', name: 'User Login', description: 'Signed in' },
        ],
      },
    },
  ],
};

const respond = (stored: () => Promise<unknown>) => {
  mockGet.mockImplementation((url: string) => {
    switch (url) {
      case '/users/integrations':
        return stored();
      case '/integrations':
        return Promise.resolve({ data: AVAILABLE });
      case '/integrations/config':
        return Promise.resolve({ data: CONFIG });
      default:
        return Promise.reject(new Error(`unexpected GET ${url}`));
    }
  });
};

const nothingStored = () => Promise.resolve({ data: { integration_integrations: [] } });

const renderPage = () =>
  render(
    <MemoryRouter>
      <UserIntegrationsPage />
    </MemoryRouter>
  );

const saveButton = () => screen.getByTestId('user-integrations-save-button');

const attachWithEvent = async () => {
  fireEvent.change(await screen.findByTestId('integrations-step-select'), {
    target: { value: 'int-general' },
  });
  fireEvent.click(screen.getByTestId('integration-0-event-user.created'));
};

describe('UserIntegrationsPage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('shows a load failure and offers no editor that could overwrite the stored mappings', async () => {
    respond(() => Promise.reject(new Error('Forbidden (403)')));
    renderPage();

    expect(await screen.findByText(/Forbidden \(403\)/)).toBeInTheDocument();
    expect(screen.queryByTestId('integrations-step-select')).not.toBeInTheDocument();
    expect(screen.queryByTestId('user-integrations-save-button')).not.toBeInTheDocument();
  });

  it('keeps Save disabled until the attached integration names an event', async () => {
    respond(nothingStored);
    renderPage();

    fireEvent.change(await screen.findByTestId('integrations-step-select'), {
      target: { value: 'int-general' },
    });
    expect(saveButton()).toBeDisabled();

    fireEvent.click(screen.getByTestId('integration-0-event-user.created'));
    expect(saveButton()).toBeEnabled();
  });

  it('saves the attached integration with its chosen events', async () => {
    respond(nothingStored);
    mockPut.mockResolvedValue({ data: {} });
    renderPage();

    await attachWithEvent();
    fireEvent.click(saveButton());

    await waitFor(() =>
      expect(mockPut).toHaveBeenCalledWith('/users/integrations', {
        integration_integrations: [
          { integration_id: 'int-general', variables: {}, event_types: ['user.created'] },
        ],
      })
    );
    expect(await screen.findByText(/updated successfully/)).toBeInTheDocument();
  });

  it('shows a save failure instead of reporting success', async () => {
    respond(nothingStored);
    mockPut.mockRejectedValue(new Error('Unknown event type (400)'));
    renderPage();

    await attachWithEvent();
    fireEvent.click(saveButton());

    expect(await screen.findByText(/Unknown event type \(400\)/)).toBeInTheDocument();
    expect(screen.queryByText(/updated successfully/)).not.toBeInTheDocument();
  });
});
