import React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import ConnectTrustAgentWizardPage from '../ConnectTrustAgentWizardPage';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({ apiClient: { fetch: jest.fn() } }));
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: () => true }),
}));
jest.mock('../../utils/toaster', () => ({ showToast: jest.fn() }));

const mockFetch = apiClient.fetch as jest.Mock;

const pending = {
  id: 'agent-1',
  name: 'Production agent',
  enabled: true,
  transport: 'https',
  endpoint: 'https://vta.example.com',
  vta_did: 'did:webvh:abc:vta.example.com',
  default_context_id: 'gateway',
  status: 'unpaired',
  pairing: { state: 'pending' },
  keys: {},
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};
const connected = {
  ...pending,
  status: 'connected',
  pairing: { state: 'connected', granted_role: 'initiator', granted_contexts: ['gateway'] },
  keys: { active: { key_id: 'key-1' } },
};
const grantCommand =
  'vta acl create --did did:webvh:gw:localhost%3A8080:vta-auth:agent-1 --role initiator --contexts gateway --capabilities context-create,key-mint,sign-jws,sign-document --label agent-gateway';

type Handler = (init?: { method?: string; body?: string }) => unknown;
let handlers: Record<string, Handler>;
let calls: { url: string; method: string; body?: string }[];

const json = (body: unknown, status = 200) => ({
  ok: status < 300,
  status,
  json: () => Promise.resolve(body),
  text: () => Promise.resolve(JSON.stringify(body)),
});

beforeEach(() => {
  calls = [];
  handlers = {
    'GET /api/v1/vta/connections': () => json([]),
    'GET /api/v1/vta/status': () => json({ enabled: false, tier: 'local' }),
    'GET /api/v1/settings': () => json({}),
    'POST /api/v1/vta/connections': () => json(pending, 201),
    'POST /api/v1/vta/connections/agent-1/pair': () =>
      json({
        connection_id: 'agent-1',
        control_did: 'did:webvh:gw:localhost%3A8080:vta-auth:agent-1',
        vta_did: pending.vta_did,
        endpoint: pending.endpoint,
        context_id: 'gateway',
        requested_role: 'initiator',
        expires_at: '2999-01-01T00:00:00Z',
        grant_command: grantCommand,
      }),
    'POST /api/v1/vta/connections/agent-1/verify': () => json(connected),
  };
  mockFetch.mockReset();
  mockFetch.mockImplementation((url: string, init?: { method?: string; body?: string }) => {
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: init?.body });
    const handler = handlers[`${method} ${url}`];
    return Promise.resolve(handler ? handler(init) : json({ error: 'unexpected' }, 500));
  });
});

const Where: React.FC = () => {
  const location = useLocation();
  return <div data-testid="where">{location.pathname + location.search}</div>;
};

const mountWizard = (path = '/connections/trust-agents/connect') =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route
          path="*"
          element={
            <>
              <ConnectTrustAgentWizardPage />
              <Where />
            </>
          }
        />
      </Routes>
    </MemoryRouter>
  );

const fillDetails = async () => {
  await userEvent.type(screen.getByTestId('wizard-trust-agent-name-input'), 'Production agent');
  await userEvent.type(
    screen.getByTestId('wizard-trust-agent-endpoint-input'),
    'https://vta.example.com'
  );
  await userEvent.type(screen.getByTestId('wizard-trust-agent-did-input'), pending.vta_did);
  await userEvent.type(screen.getByTestId('wizard-trust-agent-context-input'), 'gateway');
};

describe('ConnectTrustAgentWizardPage', () => {
  it('is a full page with a step bar, not a pop-up', () => {
    mountWizard();

    expect(screen.getByTestId('wizard-add-trust-agent')).toBeInTheDocument();
    expect(screen.getByTestId('wizard-progress')).toBeInTheDocument();
    expect(screen.getByTestId('wizard-progress-step-details')).toHaveAttribute(
      'aria-current',
      'step'
    );
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('cannot go on until all four details are entered', async () => {
    mountWizard();
    const next = screen.getByTestId('wizard-next');
    expect(next).toBeDisabled();

    await userEvent.type(screen.getByTestId('wizard-trust-agent-name-input'), 'Production agent');
    expect(next).toBeDisabled();

    await fillDetailsExceptName();
    expect(next).toBeEnabled();
  });

  it('creates the connection, shows the grant command it prints, verifies and completes', async () => {
    mountWizard();
    await fillDetails();

    await userEvent.click(screen.getByTestId('wizard-next'));

    const create = calls.find(c => c.method === 'POST' && c.url === '/api/v1/vta/connections');
    expect(JSON.parse(create?.body ?? '{}')).toMatchObject({
      name: 'Production agent',
      endpoint: 'https://vta.example.com',
      vta_did: pending.vta_did,
      default_context_id: 'gateway',
      transport: 'https',
    });
    expect(await screen.findByTestId('wizard-step-grant')).toBeInTheDocument();
    expect(await screen.findByText(grantCommand)).toBeInTheDocument();
    expect(screen.getByTestId('wizard-progress-step-grant')).toHaveAttribute(
      'aria-current',
      'step'
    );

    await userEvent.click(screen.getByTestId('wizard-next'));

    expect(await screen.findByTestId('wizard-step-complete')).toBeInTheDocument();
    expect(calls.some(c => c.url === '/api/v1/vta/connections/agent-1/verify')).toBe(true);
  });

  it('says why when the connection cannot be created, and stays on the details', async () => {
    handlers['POST /api/v1/vta/connections'] = () =>
      json({ error: 'a connection to that agent already exists' }, 409);
    mountWizard();
    await fillDetails();

    await userEvent.click(screen.getByTestId('wizard-next'));

    expect(await screen.findByTestId('wizard-trust-agent-error')).toHaveTextContent(
      /already exists/
    );
    expect(screen.getByTestId('wizard-step-details')).toBeInTheDocument();
  });

  it('stays on Verify with the reason and a retry when the grant is not there yet', async () => {
    handlers['POST /api/v1/vta/connections/agent-1/verify'] = () =>
      json({ ...pending, pairing: { state: 'pending', last_error: 'permission denied' } }, 409);
    mountWizard();
    await fillDetails();
    await userEvent.click(screen.getByTestId('wizard-next'));
    await screen.findByTestId('wizard-step-grant');

    await userEvent.click(screen.getByTestId('wizard-next'));

    expect(await screen.findByTestId('wizard-step-verify')).toBeInTheDocument();
    expect(await screen.findByText(/permission denied/i)).toBeInTheDocument();
    expect(screen.queryByTestId('wizard-step-complete')).not.toBeInTheDocument();
  });

  it('resumes a created connection at the grant step and issues its command again', async () => {
    handlers['GET /api/v1/vta/connections'] = () => json([pending]);
    mountWizard('/connections/trust-agents/connect?id=agent-1');

    expect(await screen.findByTestId('wizard-step-grant')).toBeInTheDocument();
    expect(await screen.findByText(grantCommand)).toBeInTheDocument();
    expect(screen.queryByTestId('wizard-step-details')).not.toBeInTheDocument();
  });

  it('resumes a connected one at the last step', async () => {
    handlers['GET /api/v1/vta/connections'] = () => json([connected]);
    mountWizard('/connections/trust-agents/connect?id=agent-1');

    expect(await screen.findByTestId('wizard-step-complete')).toBeInTheDocument();
  });

  it('goes back to the Trust Agents tab when cancelled', async () => {
    mountWizard();

    await userEvent.click(screen.getByTestId('wizard-cancel'));

    expect(screen.getByTestId('where')).toHaveTextContent('/connections?tab=trust-agents');
  });
});

async function fillDetailsExceptName() {
  await userEvent.type(
    screen.getByTestId('wizard-trust-agent-endpoint-input'),
    'https://vta.example.com'
  );
  await userEvent.type(screen.getByTestId('wizard-trust-agent-did-input'), pending.vta_did);
  await userEvent.type(screen.getByTestId('wizard-trust-agent-context-input'), 'gateway');
}
