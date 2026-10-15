import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import EndpointEditorPage from '..';
import * as api from '../../../integrationsApi';
import { showToast } from '../../../utils/toaster';

jest.mock('../../../utils/toaster', () => ({ showToast: jest.fn() }));

jest.mock('../../../integrationsApi', () => ({
  getEndpoint: jest.fn(),
  createEndpoint: jest.fn(),
  updateEndpoint: jest.fn(),
  testEndpoint: jest.fn(),
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
});
