import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import EnterDetailsStep from '../EnterDetailsStep';
import { useApp } from '../../../context/AppContext';
import { apiClient } from '../../../api';

jest.mock('../../../context/AppContext', () => ({
  useApp: jest.fn(),
}));

jest.mock('../../../api', () => ({
  apiClient: {
    get: jest.fn(),
  },
}));

const mockedUseApp = useApp as jest.Mock;
const mockedGet = apiClient.get as jest.Mock;

const withFlag = (enabled?: boolean) =>
  mockedUseApp.mockReturnValue({
    state: {
      settings: { feature_flags: enabled === undefined ? {} : { mediator_federation: enabled } },
    },
  });

const renderStep = (onNext = jest.fn()) =>
  render(<EnterDetailsStep onNext={onNext} onCancel={jest.fn()} />);

describe('EnterDetailsStep mediator picker', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('is hidden and loads no mediators while the flag is off', () => {
    withFlag(undefined);
    renderStep();

    expect(screen.queryByTestId('wizard-oob-acceptor-mediator')).not.toBeInTheDocument();
    expect(mockedGet).not.toHaveBeenCalled();
  });

  it('lists only active, registered mediators while the flag is on', async () => {
    withFlag(true);
    mockedGet.mockResolvedValue({
      data: [
        { id: 'm-ok', name: 'Own mediator', status: 'active', registered: true },
        { id: 'm-disabled', name: 'Disabled mediator', status: 'disabled', registered: true },
        {
          id: 'm-unregistered',
          name: 'Unregistered mediator',
          status: 'active',
          registered: false,
        },
      ],
    });
    renderStep();

    expect(await screen.findByRole('option', { name: 'Own mediator' })).toBeInTheDocument();
    expect(mockedGet).toHaveBeenCalledWith('/mediators');
    expect(screen.queryByRole('option', { name: 'Disabled mediator' })).not.toBeInTheDocument();
    expect(screen.queryByRole('option', { name: 'Unregistered mediator' })).not.toBeInTheDocument();
    expect(screen.queryByTestId('wizard-oob-acceptor-mediator-empty')).not.toBeInTheDocument();
  });

  it('says so when no mediator can be selected', async () => {
    withFlag(true);
    mockedGet.mockResolvedValue({ data: [] });
    renderStep();

    expect(await screen.findByTestId('wizard-oob-acceptor-mediator-empty')).toBeInTheDocument();
  });

  it('says so when the mediators cannot be loaded', async () => {
    withFlag(true);
    mockedGet.mockRejectedValue(new Error('forbidden'));
    renderStep();

    expect(
      await screen.findByTestId('wizard-oob-acceptor-mediator-load-error')
    ).toBeInTheDocument();
    expect(screen.queryByTestId('wizard-oob-acceptor-mediator-empty')).not.toBeInTheDocument();
  });

  it('ignores a response that is not a list', async () => {
    withFlag(true);
    mockedGet.mockResolvedValue({ data: { error: 'unexpected' } });
    renderStep();

    expect(await screen.findByTestId('wizard-oob-acceptor-mediator-empty')).toBeInTheDocument();
  });

  it('passes the selected mediator id on', async () => {
    withFlag(true);
    mockedGet.mockResolvedValue({
      data: [{ id: 'm-ok', name: 'Own mediator', status: 'active', registered: true }],
    });
    const onNext = jest.fn();
    renderStep(onNext);
    await screen.findByRole('option', { name: 'Own mediator' });

    fireEvent.change(screen.getByLabelText(/Gateway Name/), { target: { value: 'Partner' } });
    fireEvent.change(screen.getByTestId('wizard-oob-acceptor-mediator'), {
      target: { value: 'm-ok' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Next/ }));

    await waitFor(() => expect(onNext).toHaveBeenCalledWith('Partner', '', 'web', 'm-ok'));
  });
});
