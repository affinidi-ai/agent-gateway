import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, useNavigate } from 'react-router-dom';
import AddGatewayViaOOBWizardPage from '../AddGatewayViaOOBWizardPage';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({ apiClient: { post: jest.fn(), get: jest.fn() } }));

jest.mock(
  '../../components/gateway-add-via-oob/EnterDetailsStep',
  () =>
    ({ onNext }: { onNext: (...args: string[]) => void }) => (
      <button onClick={() => onNext('Partner', 'For the partner', 'peer', '')}>details</button>
    )
);

jest.mock(
  '../../components/gateway-add-via-oob/EnterOOBLinkStep',
  () =>
    ({ onNext }: { onNext: (link: string, secret: string) => void }) => (
      <button onClick={() => onNext('https://a.example/oob', 's3cr3t')}>link</button>
    )
);

// The Connect step continues the paused gateway; here the mediator always refuses it.
const mockConnectMounts = jest.fn();
jest.mock(
  '../../components/gateway-add-via-oob/ConnectStep',
  () =>
    ({ continueGatewayId, onRefused, onBack }: any) => {
      mockConnectMounts(continueGatewayId);
      return (
        <>
          <button
            onClick={() =>
              onRefused({ did: 'did:peer:2.tmp', label: 'Temporary DID for the handshake' })
            }
          >
            refuse
          </button>
          {onBack && <button onClick={onBack}>back</button>}
        </>
      );
    }
);

const post = apiClient.post as jest.Mock;

const paused = {
  data: {
    gateway: { id: 'gw-1' },
    mediator_access: {
      mediator_did: 'did:web:mediator',
      mediator_name: 'Test mediator',
      dids: [
        { role: 'temporary', did: 'did:peer:2.tmp', mediator_did: 'did:web:mediator' },
        { role: 'permanent', did: 'did:peer:2.perm', mediator_did: 'did:web:mediator' },
      ],
    },
  },
};

beforeEach(() => {
  post.mockReset().mockResolvedValue(paused);
  mockConnectMounts.mockReset();
});

function startPairing() {
  render(
    <MemoryRouter>
      <AddGatewayViaOOBWizardPage />
    </MemoryRouter>
  );
  fireEvent.click(screen.getByText('details'));
  fireEvent.click(screen.getByText('link'));
}

test('a paused gateway tries the mediator before asking anything', async () => {
  startPairing();

  expect(await screen.findByText('refuse')).toBeInTheDocument();
  expect(mockConnectMounts).toHaveBeenCalledWith('gw-1');
  expect(screen.queryByTestId('wizard-step-mediator-access')).not.toBeInTheDocument();
  expect(screen.queryByText('Mediator Access')).not.toBeInTheDocument();
});

test('a refused first try shows the DIDs to allow, without a "still refuses" alert', async () => {
  startPairing();
  fireEvent.click(await screen.findByText('refuse'));

  expect(await screen.findByTestId('mediator-access-explanation')).toHaveTextContent(
    'This Test mediator most probably uses Explicit Allow'
  );
  expect(screen.queryByTestId('mediator-access-refused')).not.toBeInTheDocument();
  expect(screen.getByText('Mediator Access')).toBeInTheDocument();
});

test('a refusal after the user pressed Continue says which DID', async () => {
  startPairing();
  fireEvent.click(await screen.findByText('refuse'));
  fireEvent.click(await screen.findByTestId('mediator-access-continue-button'));
  fireEvent.click(await screen.findByText('refuse'));

  expect(await screen.findByTestId('mediator-access-refused')).toHaveTextContent(
    'still refuses the Temporary DID for the handshake'
  );
});

test('continuing from Connections shows the DIDs at once, without testing the connection', async () => {
  (apiClient.get as jest.Mock).mockImplementation((url: string) =>
    Promise.resolve(
      url.endsWith('/mediator-access')
        ? { data: paused.data.mediator_access }
        : { data: { id: 'gw-1', name: 'Partner' } }
    )
  );
  render(
    <MemoryRouter initialEntries={['/gateways/connect?resume=gw-1']}>
      <AddGatewayViaOOBWizardPage />
    </MemoryRouter>
  );

  expect(await screen.findByTestId('mediator-access-did-temporary')).toBeInTheDocument();
  expect(mockConnectMounts).not.toHaveBeenCalled();
  expect(post).not.toHaveBeenCalled();
});

test('a failure of the first try offers no Back to the DIDs to allow', async () => {
  startPairing();

  expect(await screen.findByText('refuse')).toBeInTheDocument();
  expect(screen.queryByText('back')).not.toBeInTheDocument();
});

/** Navigates within the same router, so the wizard stays mounted and only `?resume=` changes. */
function GoTo({ to }: { to: string }) {
  const navigate = useNavigate();
  return <button onClick={() => navigate(to)}>switch pairing</button>;
}

/** GETs that answer only when the test says so, keyed by URL. */
function deferGets() {
  const answers: Record<string, { resolve: (v: unknown) => void; reject: (e: Error) => void }> = {};
  (apiClient.get as jest.Mock).mockImplementation(
    (url: string) => new Promise((resolve, reject) => (answers[url] = { resolve, reject }))
  );
  return answers;
}

test.each(['answers', 'fails'])(
  'a resume for the previous gateway that %s late changes nothing',
  async outcome => {
    const answers = deferGets();
    const access = (did: string) => ({
      data: {
        ...paused.data.mediator_access,
        dids: [{ role: 'temporary', did, mediator_did: 'did:web:mediator' }],
      },
    });
    render(
      <MemoryRouter initialEntries={['/gateways/connect?resume=gw-1']}>
        <GoTo to="/gateways/connect?resume=gw-2" />
        <AddGatewayViaOOBWizardPage />
      </MemoryRouter>
    );
    fireEvent.click(screen.getByText('switch pairing'));

    await act(async () => {
      answers['/gateways/gw-2'].resolve({ data: { id: 'gw-2', name: 'Second' } });
      answers['/gateways/gw-2/mediator-access'].resolve(access('did:peer:2.second'));
    });
    await act(async () => {
      if (outcome === 'answers') {
        answers['/gateways/gw-1'].resolve({ data: { id: 'gw-1', name: 'First' } });
        answers['/gateways/gw-1/mediator-access'].resolve(access('did:peer:2.first'));
      } else {
        answers['/gateways/gw-1'].reject(new Error('Gateway not found'));
      }
    });

    expect(screen.getByTestId('mediator-access-did-temporary')).toHaveTextContent(
      'did:peer:2.second'
    );
    expect(screen.queryByTestId('wizard-resume-unavailable-message')).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId('mediator-access-continue-button'));
    expect(mockConnectMounts).toHaveBeenLastCalledWith('gw-2');
  }
);
