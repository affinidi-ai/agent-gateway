import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import CreateGatewayConnectionPointWizardPage from '../CreateGatewayConnectionPointWizardPage';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({ apiClient: { post: jest.fn(), get: jest.fn() } }));

jest.mock(
  '../../components/gateway-create-connection-point/SelectMediatorStep',
  () =>
    ({ onNext }: { onNext: (id: string) => void }) => (
      <button onClick={() => onNext('mediator-1')}>pick mediator</button>
    )
);

jest.mock(
  '../../components/gateway-create-connection-point/EnterDetailsStep',
  () =>
    ({ onCreate }: { onCreate: (...args: unknown[]) => void }) => (
      <button
        onClick={() => onCreate('gw-1', 'Partner link', 'For the partner', 's3cr3t', 3600, 'peer')}
      >
        create
      </button>
    )
);

jest.mock(
  '../../components/gateway-create-connection-point/CompleteStep',
  () =>
    ({ connectionPoint }: { connectionPoint: { name: string } }) => (
      <div>created {connectionPoint.name}</div>
    )
);

const post = apiClient.post as jest.Mock;

beforeEach(() => {
  post.mockReset();
  (apiClient.get as jest.Mock).mockReset().mockResolvedValue({ data: [] });
});

function renderWizard() {
  render(
    <MemoryRouter>
      <CreateGatewayConnectionPointWizardPage />
    </MemoryRouter>
  );
}

test('creates the connection point from its details, with no integration step', async () => {
  post.mockResolvedValue({ data: { connection_point: { name: 'Partner link' } } });
  renderWizard();

  expect(screen.queryByText('Integrations')).not.toBeInTheDocument();
  fireEvent.click(screen.getByText('pick mediator'));
  fireEvent.click(screen.getByText('create'));

  expect(await screen.findByText('created Partner link')).toBeInTheDocument();
  expect(post).toHaveBeenCalledWith('/connection-points', {
    gateway_id: 'gw-1',
    mediator_id: 'mediator-1',
    name: 'Partner link',
    description: 'For the partner',
    secret: 's3cr3t',
    expiry_seconds: 3600,
    did_method: 'peer',
  });
});

test('a failed creation shows why and stays on the details', async () => {
  post.mockRejectedValue(new Error('Mediator unreachable (502)'));
  renderWizard();

  fireEvent.click(screen.getByText('pick mediator'));
  fireEvent.click(screen.getByText('create'));

  expect(await screen.findByRole('alert')).toHaveTextContent('Mediator unreachable (502)');
  expect(await screen.findByText('create')).toBeInTheDocument();
});
