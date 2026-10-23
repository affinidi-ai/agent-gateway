import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import SelectMediatorStep from './SelectMediatorStep';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({
  apiClient: { get: jest.fn() },
}));
jest.mock('../shared/Link', () => ({
  Link: ({ children }: { children: React.ReactNode }) => <a href="/mediators/wizard">{children}</a>,
}));

const get = apiClient.get as jest.Mock;
const entry = { id: 'directory:a', did: 'did:web:m.example', name: 'Shared', provided: true };

const renderStep = () => render(<SelectMediatorStep onNext={jest.fn()} onCancel={jest.fn()} />);

describe('SelectMediatorStep', () => {
  beforeEach(() => get.mockReset());

  it('offers a refresh that picks up a directory that answered after the first load', async () => {
    get.mockResolvedValueOnce({ data: [] }).mockResolvedValueOnce({ data: [entry] });
    renderStep();
    await userEvent.click(await screen.findByTestId('wizard-mediator-refresh-button'));
    const select = await screen.findByTestId('connection-point-mediator-select');
    await waitFor(() => expect(select).toHaveValue('directory:a'));
    expect(get).toHaveBeenCalledTimes(2);
  });

  it('can refresh a non-empty list to pick up a directory entry that appeared later', async () => {
    const stored = { id: 'own', did: 'did:web:own.example', name: 'Own' };
    get.mockResolvedValueOnce({ data: [stored] }).mockResolvedValueOnce({ data: [stored, entry] });
    renderStep();
    await userEvent.click(await screen.findByTestId('wizard-mediator-refresh-button'));
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
    expect(await screen.findByRole('option', { name: /Shared/ })).toBeInTheDocument();
  });

  it('keeps the mediator the user picked when the list is refreshed', async () => {
    const stored = { id: 'own', did: 'did:web:own.example', name: 'Own' };
    get.mockResolvedValueOnce({ data: [entry, stored] }).mockResolvedValueOnce({
      data: [entry, stored],
    });
    renderStep();
    const select = await screen.findByTestId('connection-point-mediator-select');
    await waitFor(() => expect(select).toHaveValue('directory:a'));
    await userEvent.selectOptions(select, 'own');
    await userEvent.click(screen.getByTestId('wizard-mediator-refresh-button'));
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
    await waitFor(() =>
      expect(screen.getByTestId('connection-point-mediator-select')).toHaveValue('own')
    );
  });

  it('shows a failed load instead of the empty-list message alone, and can retry', async () => {
    jest.spyOn(console, 'error').mockImplementation(() => undefined);
    get.mockRejectedValueOnce(new Error('boom')).mockResolvedValueOnce({ data: [entry] });
    renderStep();
    expect(await screen.findByTestId('wizard-mediator-load-error')).toHaveTextContent(
      'Failed to load mediators'
    );
    await userEvent.click(screen.getByTestId('wizard-mediator-refresh-button'));
    expect(await screen.findByTestId('connection-point-mediator-select')).toBeInTheDocument();
  });
});
