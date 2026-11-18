import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import ConnectStep from '../ConnectStep';
import { apiClient } from '../../../api';

jest.mock('../../../api', () => ({
  apiClient: {
    post: jest.fn(),
  },
}));

const mockedPost = apiClient.post as jest.Mock;

const renderStep = (acceptorMediatorId: string, endpoint?: string, onBack?: () => void) =>
  render(
    <ConnectStep
      endpoint={endpoint}
      oobLink="https://mediator.example.com/oob?_oobid=abc"
      secret="secret"
      name="Partner"
      description=""
      acceptorMediatorId={acceptorMediatorId}
      onConnected={jest.fn()}
      onBack={onBack}
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

  it('posts to the gateway route by default', async () => {
    renderStep('');

    await sentBody();
    expect(mockedPost.mock.calls[0][0]).toBe('/gateways/connect-via-oob');
  });

  it('posts to the given route', async () => {
    renderStep('', '/payment-gateways/connect-via-oob');

    await sentBody();
    expect(mockedPost.mock.calls[0][0]).toBe('/payment-gateways/connect-via-oob');
  });

  it('offers Back on a failure only when there is a step to go back to', async () => {
    mockedPost.mockRejectedValue(new Error('Mediator unreachable (502)'));
    const { unmount } = renderStep('');
    expect(await screen.findByTestId('wizard-oob-connect-retry-button')).toBeInTheDocument();
    expect(screen.queryByTestId('wizard-back')).not.toBeInTheDocument();
    unmount();

    renderStep('', undefined, jest.fn());
    expect(await screen.findByTestId('wizard-back')).toBeInTheDocument();
  });
});
