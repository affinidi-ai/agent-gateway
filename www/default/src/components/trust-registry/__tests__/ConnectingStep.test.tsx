import React from 'react';
import { act, render, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import ConnectingStep from '../ConnectingStep';
import { apiClient } from '../../../api';

jest.mock('../../../api', () => ({
  apiClient: {
    post: jest.fn(),
  },
}));

describe('ConnectingStep', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.runOnlyPendingTimers();
    jest.useRealTimers();
  });

  it('completes the connection flow under React StrictMode', async () => {
    const trustRegistry = {
      id: 'tr-1',
      connection_status: 'connecting',
    };
    const onComplete = jest.fn();
    const onError = jest.fn();

    (apiClient.post as jest.Mock).mockResolvedValue({ data: trustRegistry });

    render(
      <React.StrictMode>
        <ConnectingStep
          name="Local TR Web"
          description="main-based did:web validation"
          oobUrl="http://localhost:7037/oob?_oobid=test"
          didMethod="web"
          onComplete={onComplete}
          onError={onError}
          onBack={jest.fn()}
          onCancel={jest.fn()}
        />
      </React.StrictMode>
    );

    await act(async () => {
      jest.advanceTimersByTime(400);
    });

    await waitFor(() => {
      expect(apiClient.post).toHaveBeenCalledTimes(1);
    });

    expect(apiClient.post).toHaveBeenCalledWith('/trust-registries', {
      name: 'Local TR Web',
      description: 'main-based did:web validation',
      oob_url: 'http://localhost:7037/oob?_oobid=test',
      did_method: 'web',
    });

    await act(async () => {
      jest.advanceTimersByTime(900);
    });

    await waitFor(() => {
      expect(onComplete).toHaveBeenCalledWith(trustRegistry);
    });

    expect(onError).not.toHaveBeenCalled();
  });
});
