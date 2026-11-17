import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import CreateGatewayConnectionPointWizardPage from '../CreateGatewayConnectionPointWizardPage';
import { ApiError, apiClient } from '../../api';

jest.mock('../../api', () => ({
  ApiError: jest.requireActual('../../api').ApiError,
  apiClient: { post: jest.fn(), get: jest.fn() },
}));

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
    await_mediator_access: true,
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

const paused = {
  data: {
    connection_point: { id: 'cp-1', name: 'Partner link' },
    mediator_access: {
      mediator_did: 'did:web:mediator',
      mediator_name: 'Test mediator',
      dids: [
        { role: 'connection_point', did: 'did:peer:2.cp', mediator_did: 'did:web:mediator' },
        { role: 'permanent', did: 'did:peer:2.perm', mediator_did: 'did:web:mediator' },
      ],
    },
  },
};

const refused = () =>
  new ApiError(
    'refused',
    409,
    'mediator_access_refused',
    JSON.stringify({
      code: 'mediator_access_refused',
      role: 'connection_point',
      did: 'did:peer:2.cp',
    })
  );

test('a mediator that admits the new DIDs goes straight to Complete, with no pause to answer', async () => {
  post
    .mockResolvedValueOnce(paused)
    .mockResolvedValueOnce({ data: { connection_point: { id: 'cp-1', name: 'Partner link' } } });
  renderWizard();

  fireEvent.click(screen.getByText('pick mediator'));
  fireEvent.click(screen.getByText('create'));

  expect(await screen.findByText('created Partner link')).toBeInTheDocument();
  expect(post).toHaveBeenLastCalledWith('/connection-points/cp-1/continue', {});
  expect(screen.queryByTestId('mediator-access-explanation')).not.toBeInTheDocument();
  expect(screen.queryByText('Mediator Access')).not.toBeInTheDocument();
});

test('a mediator that refuses the first try shows the DIDs to allow, without a "still refuses" alert', async () => {
  post.mockResolvedValueOnce(paused).mockRejectedValueOnce(refused());
  renderWizard();

  fireEvent.click(screen.getByText('pick mediator'));
  fireEvent.click(screen.getByText('create'));

  expect(await screen.findByTestId('mediator-access-explanation')).toHaveTextContent(
    'DIDComm Mediator Test mediator most probably uses Explicit Allow'
  );
  expect(screen.getByTestId('mediator-access-did-connection_point')).toBeInTheDocument();
  expect(screen.queryByTestId('mediator-access-refused')).not.toBeInTheDocument();
  expect(screen.getByText('Copy All DIDs as a Bundle')).toBeInTheDocument();
});

test('Continue after the DIDs are still refused says which one', async () => {
  post
    .mockResolvedValueOnce(paused)
    .mockRejectedValueOnce(refused())
    .mockRejectedValueOnce(refused());
  renderWizard();

  fireEvent.click(screen.getByText('pick mediator'));
  fireEvent.click(screen.getByText('create'));
  fireEvent.click(await screen.findByTestId('mediator-access-continue-button'));

  expect(await screen.findByTestId('mediator-access-refused')).toHaveTextContent(
    'still refuses the Connection Point DID'
  );
  expect(post).toHaveBeenCalledTimes(3);
});

test('continuing from Connections shows the DIDs at once, without testing the connection', async () => {
  (apiClient.get as jest.Mock).mockImplementation((url: string) =>
    Promise.resolve(
      url.endsWith('/mediator-access')
        ? { data: paused.data.mediator_access }
        : { data: { id: 'cp-1', mediator_id: 'mediator-1' } }
    )
  );
  render(
    <MemoryRouter initialEntries={['/gateways/publish?resume=cp-1']}>
      <CreateGatewayConnectionPointWizardPage />
    </MemoryRouter>
  );

  expect(await screen.findByTestId('mediator-access-did-connection_point')).toBeInTheDocument();
  expect(screen.getByText('Copy All DIDs as a Bundle')).toBeInTheDocument();
  expect(post).not.toHaveBeenCalled();
});
