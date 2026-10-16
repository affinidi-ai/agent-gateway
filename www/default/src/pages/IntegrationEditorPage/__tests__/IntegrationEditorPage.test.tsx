/* eslint-disable no-template-curly-in-string -- ${NAME} is the gateway's placeholder syntax */
import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import IntegrationEditorPage from '..';
import * as api from '../../../integrationsApi';
import { showToast } from '../../../utils/toaster';

jest.mock('../../../utils/toaster', () => ({ showToast: jest.fn() }));

let mockPermissions: Record<string, boolean> = {};
jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    hasPermission: (feature: string) => mockPermissions[feature] === true,
  }),
}));

jest.mock('../../../integrationsApi', () => ({
  getCatalog: jest.fn(),
  listEndpoints: jest.fn(),
  listEventSets: jest.fn(),
  getIntegration: jest.fn(),
  createIntegration: jest.fn(),
  updateIntegration: jest.fn(),
  testDraftIntegration: jest.fn(),
}));

const mocked = api as jest.Mocked<typeof api>;

const CATALOG: api.IntegrationCatalog = {
  events: [
    {
      id: 'gateway.created',
      name: 'Gateway Created',
      description: '',
      family: 'gateway',
      family_label: 'Gateway',
      variables: ['EVENT_NAME', 'GATEWAY_NAME'],
    },
    {
      id: 'audit.policy_decision',
      name: 'Policy Decision',
      description: '',
      family: 'audit',
      family_label: 'Governance Audit',
      group: 'policy',
      group_label: 'Policy',
      variables: ['EVENT_NAME', 'AUDIT_DECISION'],
    },
  ],
  variables: [
    { name: 'EVENT_NAME', label: 'Event name', description: 'The event name' },
    { name: 'GATEWAY_NAME', label: 'Gateway', description: 'The gateway that changed' },
    { name: 'AUDIT_DECISION', label: 'Decision', description: 'Allow or deny' },
  ],
  endpoint_types: [],
  variable_pattern: '\\$\\{([^:}]+)(?::[^}]+)?\\}',
};

const endpoint = (id: string, name: string, type: api.EndpointType): api.Endpoint => ({
  id,
  name,
  description: '',
  type,
  configuration: {},
  status: 'active',
  secrets: [],
  created_at: '',
  updated_at: '',
});

const eventSet = (id: string, name: string, events: string[]): api.EventSet => ({
  id,
  name,
  description: '',
  events,
  created_at: '',
  updated_at: '',
});

const STORED: api.Integration = {
  id: 'i1',
  name: 'Gateway alerts',
  description: 'Tell ops',
  endpoint_id: 'slack',
  event_set_id: 'gateways',
  content: { text: 'New gateway ${GATEWAY_NAME}' },
  status: 'active',
  created_at: '',
  updated_at: '',
};

function Location() {
  const location = useLocation();
  return <div data-testid="location">{location.pathname + location.search}</div>;
}

function renderEditor(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/integrations/new" element={<IntegrationEditorPage />} />
        <Route path="/integrations/:id" element={<IntegrationEditorPage />} />
        <Route path="/integrations" element={<div>integrations page</div>} />
      </Routes>
      <Location />
    </MemoryRouter>
  );
}

const choose = (label: RegExp, value: string) =>
  fireEvent.change(screen.getByLabelText(label), { target: { value } });

async function newIntegration() {
  renderEditor('/integrations/new');
  await screen.findByLabelText(/^endpoint/i);
}

beforeEach(() => {
  jest.clearAllMocks();
  mockPermissions = { 'integrations.edit': true, 'audit.view': true };
  mocked.getCatalog.mockResolvedValue(CATALOG);
  mocked.listEndpoints.mockResolvedValue([
    endpoint('slack', 'Ops Slack', 'slack'),
    endpoint('hook', 'Ops webhook', 'webhook'),
  ]);
  mocked.listEventSets.mockResolvedValue([
    eventSet('gateways', 'Gateway changes', ['gateway.created']),
    eventSet('governance', 'Governance', ['audit.policy_decision']),
  ]);
  mocked.getIntegration.mockResolvedValue(STORED);
  mocked.createIntegration.mockImplementation(async request => ({
    ...STORED,
    ...request,
    id: 'new',
    status: request.status ?? 'active',
  }));
  mocked.updateIntegration.mockImplementation(async (id, request) => ({
    ...STORED,
    ...request,
    id,
    status: request.status ?? 'active',
  }));
});

test('creates an integration from an endpoint, an event set and a template', async () => {
  await newIntegration();

  choose(/^name/i, 'Gateway alerts');
  choose(/^endpoint/i, 'slack');
  choose(/^event set/i, 'gateways');
  choose(/^message/i, 'New gateway ${GATEWAY_NAME}');
  fireEvent.click(screen.getByRole('button', { name: /^save/i }));

  await waitFor(() =>
    expect(mocked.createIntegration).toHaveBeenCalledWith({
      name: 'Gateway alerts',
      description: '',
      endpoint_id: 'slack',
      event_set_id: 'gateways',
      content: { text: 'New gateway ${GATEWAY_NAME}' },
      status: 'active',
    })
  );
  await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent(/^\/integrations$/));
  expect(showToast).toHaveBeenCalledWith('success', 'Integration Gateway alerts saved');
});

test('the template follows the endpoint type and starts over when the type changes', async () => {
  await newIntegration();
  expect(screen.getByText(/pick an endpoint to write its template/i)).toBeInTheDocument();

  choose(/^endpoint/i, 'slack');
  choose(/^message/i, 'hello');
  choose(/^endpoint/i, 'hook');

  expect(screen.queryByLabelText(/^message/i)).not.toBeInTheDocument();
  expect(screen.getByLabelText(/^payload/i)).toHaveValue('');
});

test('lists the variables the chosen event set fills', async () => {
  await newIntegration();
  choose(/^endpoint/i, 'slack');

  choose(/^event set/i, 'gateways');

  expect(screen.getByText('The gateway that changed')).toBeInTheDocument();
  expect(screen.queryByText('Allow or deny')).not.toBeInTheDocument();
});

test('offers audit delivery limits only for event sets with audit events', async () => {
  await newIntegration();
  choose(/^name/i, 'SIEM');
  choose(/^endpoint/i, 'hook');

  choose(/^event set/i, 'gateways');
  expect(screen.queryByTestId('integration-audit-limits')).not.toBeInTheDocument();

  choose(/^event set/i, 'governance');
  fireEvent.change(screen.getByTestId('integration-audit-max-attempts-input'), {
    target: { value: '10' },
  });
  fireEvent.click(screen.getByRole('button', { name: /^save/i }));

  await waitFor(() =>
    expect(mocked.createIntegration).toHaveBeenCalledWith(
      expect.objectContaining({ event_set_id: 'governance', audit_max_attempts: 10 })
    )
  );
  expect(mocked.createIntegration.mock.calls[0][0]).not.toHaveProperty('audit_drop_after_secs');
});

test('names what is missing before saving', async () => {
  await newIntegration();

  fireEvent.click(screen.getByRole('button', { name: /^save/i }));

  expect(screen.getByRole('alert')).toHaveTextContent('Fill in: Name, Endpoint, Event set');
  expect(mocked.createIntegration).not.toHaveBeenCalled();
});

test('is not saved while the template uses variables no event fills', async () => {
  await newIntegration();
  choose(/^name/i, 'Alerts');
  choose(/^endpoint/i, 'slack');
  choose(/^event set/i, 'gateways');
  choose(/^message/i, '${AUDIT_DECISION}');

  fireEvent.click(screen.getByRole('button', { name: /^save/i }));

  expect(mocked.createIntegration).not.toHaveBeenCalled();
});

test('is not saved while the payload is not a JSON object', async () => {
  await newIntegration();
  choose(/^name/i, 'Hook');
  choose(/^endpoint/i, 'hook');
  choose(/^event set/i, 'gateways');
  choose(/^payload/i, '{"broken": ');

  fireEvent.click(screen.getByRole('button', { name: /^save/i }));

  expect(screen.getByRole('alert')).toHaveTextContent(/payload must be a json object/i);
  expect(mocked.createIntegration).not.toHaveBeenCalled();
});

test('edits a stored integration', async () => {
  renderEditor('/integrations/i1');

  expect(await screen.findByDisplayValue('Gateway alerts')).toBeInTheDocument();
  expect(screen.getByLabelText(/^endpoint/i)).toHaveValue('slack');
  expect(screen.getByLabelText(/^message/i)).toHaveValue('New gateway ${GATEWAY_NAME}');

  fireEvent.click(screen.getByLabelText(/^active/i));
  fireEvent.click(screen.getByRole('button', { name: /^save/i }));

  await waitFor(() =>
    expect(mocked.updateIntegration).toHaveBeenCalledWith('i1', {
      name: 'Gateway alerts',
      description: 'Tell ops',
      endpoint_id: 'slack',
      event_set_id: 'gateways',
      content: { text: 'New gateway ${GATEWAY_NAME}' },
      status: 'disabled',
    })
  );
});

test('a save the gateway refuses shows why', async () => {
  mocked.updateIntegration.mockRejectedValue(new Error('Endpoint not found (400)'));
  renderEditor('/integrations/i1');
  await screen.findByDisplayValue('Gateway alerts');

  fireEvent.click(screen.getByRole('button', { name: /^save/i }));

  expect(await screen.findByRole('alert')).toHaveTextContent('Endpoint not found (400)');
});

test('sends a test of the integration as it stands on screen', async () => {
  mocked.testDraftIntegration.mockResolvedValue({ delivered: true, event_type: 'gateway.created' });
  renderEditor('/integrations/i1');
  await screen.findByDisplayValue('Gateway alerts');

  choose(/^message/i, 'Edited ${GATEWAY_NAME}');
  fireEvent.click(screen.getByRole('button', { name: /send test/i }));

  await waitFor(() =>
    expect(showToast).toHaveBeenCalledWith(
      'success',
      'Test message for gateway.created sent to Ops Slack'
    )
  );
  expect(mocked.testDraftIntegration).toHaveBeenCalledWith(
    expect.objectContaining({ content: { text: 'Edited ${GATEWAY_NAME}' } })
  );
});

test('a failed test shows why', async () => {
  mocked.testDraftIntegration.mockRejectedValue(new Error('webhook_url rejected (502)'));
  renderEditor('/integrations/i1');
  await screen.findByDisplayValue('Gateway alerts');

  fireEvent.click(screen.getByRole('button', { name: /send test/i }));

  await waitFor(() =>
    expect(showToast).toHaveBeenCalledWith(
      'error',
      'Test failed: webhook_url rejected (502)',
      expect.anything()
    )
  );
});

test('cannot test before an endpoint and an event set are chosen', async () => {
  await newIntegration();

  expect(screen.getByRole('button', { name: /send test/i })).toBeDisabled();
});

test('a draft with a broken payload cannot be tested until it is fixed', async () => {
  await newIntegration();
  choose(/^name/i, 'Hook');
  choose(/^endpoint/i, 'hook');
  choose(/^event set/i, 'gateways');
  const send = screen.getByTestId('integration-test-button');
  expect(send).toBeEnabled();

  choose(/^payload/i, '{"gateway": "${GATEWAY_NAME}",}');
  expect(send).toBeDisabled();
  expect(send).toHaveAttribute('title', 'The payload must be a JSON object.');
  fireEvent.click(send);
  expect(mocked.testDraftIntegration).not.toHaveBeenCalled();

  choose(/^payload/i, '{"gateway": "${GATEWAY_NAME}"}');
  expect(send).toBeEnabled();
});

test('a saved integration with a broken payload cannot be tested either', async () => {
  mocked.getIntegration.mockResolvedValue({
    ...STORED,
    endpoint_id: 'hook',
    content: { gateway: '${GATEWAY_NAME}' },
  });
  renderEditor('/integrations/i1');
  await screen.findByDisplayValue('Gateway alerts');

  choose(/^payload/i, '{"gateway": ');

  expect(screen.getByTestId('integration-test-button')).toBeDisabled();
  expect(screen.getByTestId('integration-save-button')).toBeEnabled();
});

test('a template using variables no event fills cannot be tested', async () => {
  await newIntegration();
  choose(/^name/i, 'Alerts');
  choose(/^endpoint/i, 'slack');
  choose(/^event set/i, 'gateways');

  choose(/^message/i, '${AUDIT_DECISION}');

  expect(screen.getByTestId('integration-test-button')).toBeDisabled();
});

test('points to creating an endpoint or event set when there are none', async () => {
  mocked.listEndpoints.mockResolvedValue([]);
  mocked.listEventSets.mockResolvedValue([]);

  renderEditor('/integrations/new');

  expect(await screen.findByRole('link', { name: /add an endpoint/i })).toHaveAttribute(
    'href',
    '/integrations/endpoints/new'
  );
  expect(screen.getByRole('link', { name: /add an event set/i })).toHaveAttribute(
    'href',
    '/integrations/event-sets/new'
  );
});

test('an integration that cannot be loaded says why', async () => {
  mocked.getIntegration.mockRejectedValue(new Error('Not found (404)'));

  renderEditor('/integrations/missing');

  expect(await screen.findByRole('alert')).toHaveTextContent('Not found (404)');
});

describe('without audit.view', () => {
  const AUDIT_VIEW_NEEDED = 'Audit events need the audit.view permission.';

  beforeEach(() => {
    mockPermissions = { 'integrations.edit': true };
  });

  test('an audit event set cannot be saved or tested, and a gateway one can', async () => {
    await newIntegration();
    choose(/^name/i, 'SIEM');
    choose(/^endpoint/i, 'hook');
    const save = screen.getByTestId('integration-save-button');
    const send = screen.getByTestId('integration-test-button');

    choose(/^event set/i, 'governance');
    expect(save).toBeDisabled();
    expect(save).toHaveAttribute('title', AUDIT_VIEW_NEEDED);
    expect(send).toBeDisabled();
    expect(send).toHaveAttribute('title', AUDIT_VIEW_NEEDED);
    expect(screen.getByTestId('integration-audit-view-note')).toHaveTextContent(AUDIT_VIEW_NEEDED);

    choose(/^event set/i, 'gateways');
    expect(save).toBeEnabled();
    expect(send).toBeEnabled();
    expect(screen.queryByTestId('integration-audit-view-note')).not.toBeInTheDocument();
  });

  test('a stored audit integration starts locked, even when moved to a gateway set', async () => {
    mocked.getIntegration.mockResolvedValue({
      ...STORED,
      endpoint_id: 'hook',
      event_set_id: 'governance',
      content: {},
    });
    renderEditor('/integrations/i1');
    await screen.findByDisplayValue('Gateway alerts');
    const save = screen.getByTestId('integration-save-button');
    expect(save).toBeDisabled();
    expect(screen.getByTestId('integration-test-button')).toBeDisabled();

    // The gateway refuses a change to an integration that receives audit events now, too.
    choose(/^event set/i, 'gateways');
    expect(save).toBeDisabled();
    // Submitting from a field, as Enter does, is refused too.
    fireEvent.submit(screen.getByTestId('integration-name-input'));
    expect(mocked.updateIntegration).not.toHaveBeenCalled();
  });

  test('a gateway integration is unaffected', async () => {
    renderEditor('/integrations/i1');
    await screen.findByDisplayValue('Gateway alerts');

    expect(screen.getByTestId('integration-save-button')).toBeEnabled();
    expect(screen.getByTestId('integration-test-button')).toBeEnabled();
  });
});

test('with audit.view an audit event set can be saved and tested', async () => {
  await newIntegration();
  choose(/^name/i, 'SIEM');
  choose(/^endpoint/i, 'hook');
  choose(/^event set/i, 'governance');

  expect(screen.getByTestId('integration-save-button')).toBeEnabled();
  expect(screen.getByTestId('integration-test-button')).toBeEnabled();
  expect(screen.queryByTestId('integration-audit-view-note')).not.toBeInTheDocument();
});

test('exposes the test ids ui-tests use', async () => {
  renderEditor('/integrations/i1');
  await screen.findByDisplayValue('Gateway alerts');

  for (const id of [
    'page-integration-editor',
    'integration-save-button',
    'integration-cancel-button',
    'integration-test-button',
    'integration-name-input',
    'integration-endpoint-select',
    'integration-event-set-select',
    'integration-active-switch',
    'template-text-input',
    'template-insert-GATEWAY_NAME-button',
  ]) {
    expect(screen.getByTestId(id)).toBeInTheDocument();
  }
});
