import React from 'react';
import { render, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import ConnectStep from '../ConnectStep';
import { apiClient } from '../../../api';

jest.mock('../../../api', () => ({
  apiClient: {
    post: jest.fn(),
  },
}));

const mockedPost = apiClient.post as jest.Mock;

const renderStep = (acceptorMediatorId: string) =>
  render(
    <ConnectStep
      oobLink="https://mediator.example.com/oob?_oobid=abc"
      secret="secret"
      name="Partner"
      description=""
      acceptorMediatorId={acceptorMediatorId}
      onConnected={jest.fn()}
      onBack={jest.fn()}
      onCancel={jest.fn()}
    />
  );

const sentBody = async () => {
  await waitFor(() => expect(mockedPost).toHaveBeenCalled(), { timeout: 2000 });
  return mockedPost.mock.calls[0][1];
};

describe('ConnectStep', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockedPost.mockResolvedValue({ data: { gateway: {} } });
  });

  it('sends the selected acceptor mediator', async () => {
    renderStep('m-ok');

    expect((await sentBody()).acceptor_mediator_id).toBe('m-ok');
  });

  it('leaves the acceptor mediator out for the default', async () => {
    renderStep('');

    expect((await sentBody()).acceptor_mediator_id).toBeUndefined();
  });
});
