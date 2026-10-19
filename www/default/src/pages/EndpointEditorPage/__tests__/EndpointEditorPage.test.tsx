import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import EndpointEditorPage from '..';
import * as api from '../../../integrationsApi';
import { showToast } from '../../../utils/toaster';

jest.mock('../../../utils/toaster', () => ({ showToast: jest.fn() }));

jest.mock('../../../hooks/useApplianceSecrets', () => ({
  useApplianceSecrets: () => [{ id: 'slack-hook', name: 'Slack hook' }],
}));

let mockPermissions: Record<string, boolean> = {};
jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    hasPermission: (feature: string) => mockPermissions[feature] === true,
  }),
}));

jest.mock('../../../integrationsApi', () => ({
  getEndpoint: jest.fn(),
  createEndpoint: jest.fn(),
  updateEndpoint: jest.fn(),
  testEndpoint: jest.fn(),
  listIntegrations: jest.fn(),
  listEventSets: jest.fn(),
}));

const mocked = api as jest.Mocked<typeof api>;

function stored(overrides: Partial<api.Endpoint> = {}): api.Endpoint {
  return {
    id: 'e1',
    name: 'Ops mail',
    description: 'Mail to ops',
    type: 'email',
    configuration: {
      smtp_host: 'smtp.example.com',
      smtp_port: 587,
      smtp_username: 'mailer',
      from: 'gateway@example.com',
      to: ['ops@example.com'],
      use_tls: true,
      use_starttls: true,
    },
    status: 'active',
    secrets: ['smtp_password'],
    created_at: '2026-10-15T00:00:00Z',
    updated_at: '2026-10-15T00:00:00Z',
    ...overrides,
  };
}

function Location() {
  const location = useLocation();
  return <div data-testid="location">{location.pathname + location.search}</div>;
}

function renderEditor(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/integrations/endpoints/new" element={<EndpointEditorPage />} />
        <Route path="/integrations/endpoints/:id" element={<EndpointEditorPage />} />
        <Route path="/integrations" element={<div>integrations page</div>} />
      </Routes>
      <Location />
    </MemoryRouter>
  );
}

const type = (label: string | RegExp, value: string) =>
  fireEvent.change(screen.getByLabelText(label), { target: { value } });

beforeEach(() => {
  jest.clearAllMocks();
  mockPermissions = { 'integrations.edit': true };
  mocked.getEndpoint.mockResolvedValue(stored());
  mocked.createEndpoint.mockImplementation(async request => ({
    ...stored(),
    ...request,
    id: 'new-id',
    status: request.status ?? 'active',
    secrets: [],
  }));
  mocked.updateEndpoint.mockImplementation(async (id, request) => ({
    ...stored(),
    ...request,
    id,
  }));
});

describe('a new endpoint', () => {
  test('is created with the fields of its type and opens the endpoints tab', async () => {
    renderEditor('/integrations/endpoints/new?type=slack');

    type(/^name/i, 'Ops Slack');
    type(/incoming webhook url/i, 'https://hooks.slack.com/services/T/B/x');
    type(/sender name/i, 'Gateway');
    fireEvent.click(screen.getByRole('button', { name: /save/i }));

    await waitFor(() =>
      expect(mocked.createEndpoint).toHaveBeenCalledWith({
        name: 'Ops Slack',
        description: '',
        type: 'slack',
        configuration: {
          webhook_url: 'https://hooks.slack.com/services/T/B/x',
          bot_name: 'Gateway',
        },
        status: 'active',
      })
    );
    await waitFor(() =>
      expect(screen.getByTestId('location')).toHaveTextContent('/integrations?tab=endpoints')
    );
    expect(showToast).toHaveBeenCalledWith('success', 'Endpoint Ops Slack saved');
  });

  test('a secret field can reference a stored secret', async () => {
    renderEditor('/integrations/endpoints/new?type=slack');

    type(/^name/i, 'Ops Slack');
    type(/use a stored secret/i, 'slack-hook');
    fireEvent.click(screen.getByRole('button', { name: /save/i }));

    await waitFor(() =>
      expect(mocked.createEndpoint).toHaveBeenCalledWith(
        expect.objectContaining({ configuration: { webhook_url: '$SECRET:slack-hook' } })
      )
    );
  });

  test('webhook headers offer no stored secret picker, since only header values resolve', () => {
    renderEditor('/integrations/endpoints/new?type=webhook');

    expect(screen.getAllByLabelText(/use a stored secret/i)).toHaveLength(1);
    expect(screen.getByLabelText(/headers/i).tagName).toBe('TEXTAREA');
  });

  test('changing the type shows that type’s fields', () => {
    renderEditor('/integrations/endpoints/new');

    type(/^type/i, 'stream');
    expect(screen.getByLabelText(/brokers/i)).toBeInTheDocument();
    expect(screen.queryByLabelText(/sasl username/i)).not.toBeInTheDocument();

    type(/authentication/i, 'sasl');
    expect(screen.getByLabelText(/sasl username/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/sasl password/i)).toBeInTheDocument();

    type(/platform/i, 'redis');
    expect(screen.queryByLabelText(/brokers/i)).not.toBeInTheDocument();
    expect(screen.getByLabelText(/redis url/i)).toBeInTheDocument();
  });

  test('is not saved while required fields are empty, and says which', () => {
    renderEditor('/integrations/endpoints/new?type=webhook');

    fireEvent.click(screen.getByRole('button', { name: /save/i }));

    expect(mocked.createEndpoint).not.toHaveBeenCalled();
    expect(screen.getByRole('alert')).toHaveTextContent('Fill in: Name, URL');
  });

  test('a refusal from the gateway is shown and the form kept', async () => {
    mocked.createEndpoint.mockRejectedValue(
      new Error('Invalid webhook URL: private address (400)')
    );
    renderEditor('/integrations/endpoints/new?type=webhook');

    type(/^name/i, 'Internal');
    type(/^url/i, 'https://10.0.0.1/hook');
    fireEvent.click(screen.getByRole('button', { name: /save/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Invalid webhook URL: private address (400)'
    );
    expect(screen.getByLabelText(/^name/i)).toHaveValue('Internal');
  });

  test('cannot be tested before it is saved', () => {
    renderEditor('/integrations/endpoints/new?type=slack');

    expect(screen.queryByRole('button', { name: /send test/i })).not.toBeInTheDocument();
  });
});

describe('a stored endpoint', () => {
  test('loads with its type fixed and its secret kept', async () => {
    renderEditor('/integrations/endpoints/e1');

    expect(await screen.findByDisplayValue('Ops mail')).toBeInTheDocument();
    expect(screen.queryByLabelText(/^type/i)).not.toBeInTheDocument();
    expect(screen.getByText('email')).toBeInTheDocument();
    expect(screen.getByText(/a value is stored/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^to/i)).toHaveValue('ops@example.com');
  });

  test('is updated without its untouched secret, with cc and bcc as lists', async () => {
    renderEditor('/integrations/endpoints/e1');
    await screen.findByDisplayValue('Ops mail');

    type(/^cc/i, 'lead@example.com');
    type(/^bcc/i, 'audit@example.com, archive@example.com');
    fireEvent.click(screen.getByRole('button', { name: /save/i }));

    await waitFor(() =>
      expect(mocked.updateEndpoint).toHaveBeenCalledWith('e1', {
        name: 'Ops mail',
        description: 'Mail to ops',
        configuration: {
          smtp_host: 'smtp.example.com',
          smtp_port: 587,
          smtp_username: 'mailer',
          from: 'gateway@example.com',
          to: ['ops@example.com'],
          cc: ['lead@example.com'],
          bcc: ['audit@example.com', 'archive@example.com'],
          use_tls: true,
          use_starttls: true,
        },
        status: 'active',
      })
    );
  });

  test('a cleared optional secret is sent as null', async () => {
    mocked.getEndpoint.mockResolvedValue(
      stored({
        type: 'webhook',
        configuration: { url: 'https://ops.example.com/hook', method: 'POST' },
        secrets: ['signing_secret'],
      })
    );
    renderEditor('/integrations/endpoints/e1');
    await screen.findByDisplayValue('https://ops.example.com/hook');

    fireEvent.click(screen.getByRole('button', { name: /clear signing secret/i }));
    fireEvent.click(screen.getByRole('button', { name: /save/i }));

    await waitFor(() =>
      expect(mocked.updateEndpoint).toHaveBeenCalledWith(
        'e1',
        expect.objectContaining({
          configuration: {
            url: 'https://ops.example.com/hook',
            method: 'POST',
            signing_secret: null,
          },
        })
      )
    );
  });

  test('switching SASL off clears the stored SASL password instead of keeping it unseen', async () => {
    mocked.getEndpoint.mockResolvedValue(
      stored({
        type: 'stream',
        configuration: {
          platform: 'kafka',
          topic: 'events',
          brokers: 'b:9092',
          auth_type: 'sasl',
          sasl_username: 'svc',
        },
        secrets: ['sasl_password'],
      })
    );
    renderEditor('/integrations/endpoints/e1');
    await screen.findByDisplayValue('events');

    fireEvent.change(screen.getByTestId('endpoint-auth_type-input'), { target: { value: 'none' } });
    fireEvent.click(screen.getByTestId('endpoint-save-button'));

    await waitFor(() =>
      expect(mocked.updateEndpoint).toHaveBeenCalledWith(
        'e1',
        expect.objectContaining({
          configuration: {
            platform: 'kafka',
            topic: 'events',
            brokers: 'b:9092',
            auth_type: 'none',
            sasl_password: null,
          },
        })
      )
    );
  });

  test('can be disabled', async () => {
    renderEditor('/integrations/endpoints/e1');
    await screen.findByDisplayValue('Ops mail');

    fireEvent.click(screen.getByLabelText(/^active/i));
    fireEvent.click(screen.getByRole('button', { name: /save/i }));

    await waitFor(() =>
      expect(mocked.updateEndpoint).toHaveBeenCalledWith(
        'e1',
        expect.objectContaining({ status: 'disabled' })
      )
    );
  });

  test('sends a test message as saved, and asks to save changes first', async () => {
    mocked.testEndpoint.mockResolvedValue({ delivered: true, event_type: 'integration.test' });
    renderEditor('/integrations/endpoints/e1');
    await screen.findByDisplayValue('Ops mail');

    fireEvent.click(screen.getByRole('button', { name: /send test/i }));
    await waitFor(() =>
      expect(showToast).toHaveBeenCalledWith('success', 'Test message sent to Ops mail')
    );
    expect(mocked.testEndpoint).toHaveBeenCalledWith('e1');

    type(/^name/i, 'Ops mail 2');
    expect(screen.getByRole('button', { name: /send test/i })).toBeDisabled();
  });

  test('a failed test shows why', async () => {
    mocked.testEndpoint.mockRejectedValue(new Error('SMTP authentication failed (502)'));
    renderEditor('/integrations/endpoints/e1');
    await screen.findByDisplayValue('Ops mail');

    fireEvent.click(screen.getByRole('button', { name: /send test/i }));

    await waitFor(() =>
      expect(showToast).toHaveBeenCalledWith(
        'error',
        'Test failed: SMTP authentication failed (502)',
        expect.anything()
      )
    );
  });

  test('one that cannot be loaded says why', async () => {
    mocked.getEndpoint.mockRejectedValue(new Error('Not found (404)'));

    renderEditor('/integrations/endpoints/missing');

    expect(await screen.findByRole('alert')).toHaveTextContent('Not found (404)');
    expect(screen.queryByRole('button', { name: /save/i })).not.toBeInTheDocument();
  });

  test('exposes the test ids ui-tests use', async () => {
    renderEditor('/integrations/endpoints/e1');
    await screen.findByDisplayValue('Ops mail');

    for (const id of [
      'page-endpoint-editor',
      'endpoint-save-button',
      'endpoint-cancel-button',
      'endpoint-test-button',
      'endpoint-name-input',
      'endpoint-active-switch',
      'endpoint-smtp_host-input',
      'endpoint-smtp_password-replace-button',
    ]) {
      expect(screen.getByTestId(id)).toBeInTheDocument();
    }

    fireEvent.click(screen.getByTestId('endpoint-smtp_password-replace-button'));
    expect(screen.getByTestId('endpoint-smtp_password-input')).toBeInTheDocument();
    expect(screen.getByTestId('endpoint-smtp_password-keep-button')).toBeInTheDocument();
    expect(screen.getByTestId('endpoint-smtp_password-stored-secret-select')).toBeInTheDocument();
  });

  test('an optional stored secret exposes its clear and undo buttons', async () => {
    mocked.getEndpoint.mockResolvedValue(
      stored({
        type: 'webhook',
        configuration: { url: 'https://ops.example.com/hook' },
        secrets: ['signing_secret'],
      })
    );
    renderEditor('/integrations/endpoints/e1');
    await screen.findByDisplayValue('https://ops.example.com/hook');

    fireEvent.click(screen.getByTestId('endpoint-signing_secret-clear-button'));
    expect(screen.getByTestId('endpoint-signing_secret-undo-button')).toBeInTheDocument();
  });
});

test('without audit.view an endpoint is saved with no audit note, whatever delivers through it', async () => {
  renderEditor('/integrations/endpoints/e1');
  await screen.findByDisplayValue('Ops mail');

  const save = screen.getByTestId('endpoint-save-button');
  expect(save).toBeEnabled();
  expect(save).not.toHaveAttribute('title');
  expect(screen.queryByTestId('endpoint-audit-view-note')).not.toBeInTheDocument();
  expect(screen.queryByText(/audit\.view/)).not.toBeInTheDocument();
  expect(mocked.listIntegrations).not.toHaveBeenCalled();
  expect(mocked.listEventSets).not.toHaveBeenCalled();

  fireEvent.click(save);
  await waitFor(() => expect(mocked.updateEndpoint).toHaveBeenCalled());
});

test('a new endpoint exposes its type select', () => {
  renderEditor('/integrations/endpoints/new');

  expect(screen.getByTestId('endpoint-type-select')).toBeInTheDocument();
});
