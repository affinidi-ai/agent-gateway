import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import IntegrationsPage from '..';
import * as api from '../../../integrationsApi';
import { showToast } from '../../../utils/toaster';

let mockPermissions: Record<string, boolean> = {};

jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    loading: false,
    hasPermission: (feature: string) => mockPermissions[feature] === true,
  }),
}));

jest.mock('../../../hooks/useLimitGuard', () => ({
  useLimitGuard: () => ({
    guard: (_kind: string, action: () => void) => action(),
    balloonNode: null,
  }),
}));

jest.mock('../../../utils/toaster', () => ({ showToast: jest.fn() }));

jest.mock('../../../integrationsApi', () => ({
  listIntegrations: jest.fn(),
  listEndpoints: jest.fn(),
  listEventSets: jest.fn(),
  deleteIntegration: jest.fn(),
  testIntegration: jest.fn(),
}));

const mocked = api as jest.Mocked<typeof api>;

const endpoint: api.Endpoint = {
  id: 'e1',
  name: 'Ops Slack',
  description: '',
  type: 'slack',
  configuration: {},
  status: 'active',
  secrets: ['webhook_url'],
  created_at: '2026-10-15T00:00:00Z',
  updated_at: '2026-10-15T00:00:00Z',
};

const eventSet: api.EventSet = {
  id: 's1',
  name: 'Gateway changes',
  description: '',
  events: ['gateway.created', 'gateway.deleted'],
  created_at: '2026-10-15T00:00:00Z',
  updated_at: '2026-10-15T00:00:00Z',
};

function integration(overrides: Partial<api.Integration> = {}): api.Integration {
  return {
    id: 'i1',
    name: 'Gateway alerts',
    description: 'Tell ops about gateways',
    endpoint_id: 'e1',
    event_set_id: 's1',
    content: {},
    status: 'active',
    created_at: '2026-10-15T00:00:00Z',
    updated_at: '2026-10-15T00:00:00Z',
    ...overrides,
  };
}

function Location() {
  const location = useLocation();
  return <div data-testid="location">{location.pathname + location.search}</div>;
}

function renderPage(path = '/integrations') {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/integrations" element={<IntegrationsPage />} />
        <Route path="*" element={<div>elsewhere</div>} />
      </Routes>
      <Location />
    </MemoryRouter>
  );
}

beforeEach(() => {
  jest.clearAllMocks();
  mockPermissions = { 'integrations.view': true };
  mocked.listIntegrations.mockResolvedValue([integration()]);
  mocked.listEndpoints.mockResolvedValue([endpoint]);
  mocked.listEventSets.mockResolvedValue([eventSet]);
  mocked.deleteIntegration.mockResolvedValue();
});

const row = (name: string) => screen.findByRole('row', { name: new RegExp(name) });

test('lists integrations with their endpoint, event set and status', async () => {
  renderPage();

  const cells = within(await row('Gateway alerts'));
  expect(cells.getByText('Tell ops about gateways')).toBeInTheDocument();
  expect(cells.getByText('Ops Slack')).toBeInTheDocument();
  expect(cells.getByText('slack')).toBeInTheDocument();
  expect(cells.getByText('Gateway changes')).toBeInTheDocument();
  expect(cells.getByText('2 events')).toBeInTheDocument();
  expect(cells.getByText('active')).toBeInTheDocument();
});

test('names a missing endpoint or event set instead of failing', async () => {
  mocked.listIntegrations.mockResolvedValue([
    integration({ endpoint_id: 'gone', event_set_id: 'gone' }),
  ]);

  renderPage();

  const cells = within(await row('Gateway alerts'));
  expect(cells.getByText('Missing endpoint')).toBeInTheDocument();
  expect(cells.getByText('Missing event set')).toBeInTheDocument();
});

test('filters by integration, endpoint and event set names', async () => {
  mocked.listIntegrations.mockResolvedValue([
    integration(),
    integration({ id: 'i2', name: 'Audit to SIEM', endpoint_id: 'other', event_set_id: 'other' }),
  ]);
  renderPage();
  await row('Gateway alerts');
  const filter = screen.getByPlaceholderText(/filter/i);

  fireEvent.change(filter, { target: { value: 'ops slack' } });
  expect(screen.getByText('Gateway alerts')).toBeInTheDocument();
  expect(screen.queryByText('Audit to SIEM')).not.toBeInTheDocument();

  fireEvent.change(filter, { target: { value: 'siem' } });
  expect(screen.queryByText('Gateway alerts')).not.toBeInTheDocument();
  expect(screen.getByText('Audit to SIEM')).toBeInTheDocument();

  fireEvent.change(filter, { target: { value: 'nothing like it' } });
  expect(screen.getByText(/no integrations match/i)).toBeInTheDocument();
});

test('a viewer sees the list but no actions, and rows do not open the editor', async () => {
  renderPage();
  const cells = within(await row('Gateway alerts'));

  expect(screen.queryByRole('button', { name: /add integration/i })).not.toBeInTheDocument();
  expect(cells.queryByRole('button', { name: /test/i })).not.toBeInTheDocument();
  expect(cells.queryByRole('button', { name: /edit/i })).not.toBeInTheDocument();
  expect(cells.queryByRole('button', { name: /delete/i })).not.toBeInTheDocument();

  fireEvent.click(screen.getByText('Gateway alerts'));
  expect(screen.getByTestId('location')).toHaveTextContent('/integrations');
});

test('an editor adds and opens integrations', async () => {
  mockPermissions = { 'integrations.view': true, 'integrations.edit': true };
  renderPage();

  fireEvent.click(within(await row('Gateway alerts')).getByRole('button', { name: /edit/i }));
  expect(screen.getByTestId('location')).toHaveTextContent('/integrations/i1');
});

test('the add button opens a new integration', async () => {
  mockPermissions = { 'integrations.view': true, 'integrations.edit': true };
  renderPage();
  await row('Gateway alerts');

  fireEvent.click(screen.getByRole('button', { name: /add integration/i }));

  expect(screen.getByTestId('location')).toHaveTextContent('/integrations/new');
});

test('a test send reports the event it was sent for', async () => {
  mockPermissions = { 'integrations.view': true, 'integrations.edit': true };
  mocked.testIntegration.mockResolvedValue({ delivered: true, event_type: 'gateway.created' });
  renderPage();

  fireEvent.click(within(await row('Gateway alerts')).getByRole('button', { name: /test/i }));

  await waitFor(() =>
    expect(showToast).toHaveBeenCalledWith(
      'success',
      'Test message for gateway.created sent to Ops Slack'
    )
  );
  expect(mocked.testIntegration).toHaveBeenCalledWith('i1');
  expect(screen.getByTestId('location')).toHaveTextContent('/integrations');
});

test('a failed test send shows why', async () => {
  mockPermissions = { 'integrations.view': true, 'integrations.edit': true };
  mocked.testIntegration.mockRejectedValue(new Error('webhook_url rejected (502)'));
  renderPage();

  fireEvent.click(within(await row('Gateway alerts')).getByRole('button', { name: /test/i }));

  await waitFor(() =>
    expect(showToast).toHaveBeenCalledWith(
      'error',
      'Test failed: webhook_url rejected (502)',
      expect.anything()
    )
  );
});

test('integrations.delete removes an integration after confirmation', async () => {
  mockPermissions = { 'integrations.view': true, 'integrations.delete': true };
  renderPage();
  const remove = within(await row('Gateway alerts')).getByRole('button', { name: /delete/i });

  mocked.listIntegrations.mockResolvedValue([]);
  fireEvent.click(remove);
  fireEvent.click(remove);

  await waitFor(() => expect(mocked.deleteIntegration).toHaveBeenCalledWith('i1'));
  expect(await screen.findByText(/add your first integration/i)).toBeInTheDocument();
});

test('an integration receiving audit events is deleted only with audit.view', async () => {
  mocked.listIntegrations.mockResolvedValue([
    integration(),
    integration({ id: 'i2', name: 'Audit to SIEM', event_set_id: 's2' }),
  ]);
  mocked.listEventSets.mockResolvedValue([
    eventSet,
    { ...eventSet, id: 's2', name: 'Governance', events: ['audit.policy_decision'] },
  ]);
  mockPermissions = { 'integrations.view': true, 'integrations.delete': true };
  renderPage();

  const audit = within(await row('Audit to SIEM')).getByRole('button', { name: /delete/i });
  expect(audit).toBeDisabled();
  expect(audit).toHaveAttribute('title', 'Audit events need the audit.view permission.');
  expect(
    within(await row('Gateway alerts')).getByRole('button', { name: /delete/i })
  ).toBeEnabled();
});

test('with audit.view an audit integration can be deleted', async () => {
  mocked.listIntegrations.mockResolvedValue([integration({ event_set_id: 's2' })]);
  mocked.listEventSets.mockResolvedValue([
    { ...eventSet, id: 's2', name: 'Governance', events: ['audit.policy_decision'] },
  ]);
  mockPermissions = { 'integrations.view': true, 'integrations.delete': true, 'audit.view': true };
  renderPage();

  expect(
    within(await row('Gateway alerts')).getByRole('button', { name: /delete/i })
  ).toBeEnabled();
});

test('a failed delete shows why and keeps the integration', async () => {
  mockPermissions = { 'integrations.view': true, 'integrations.delete': true };
  mocked.deleteIntegration.mockRejectedValue(new Error('Forbidden (403)'));
  renderPage();
  const remove = within(await row('Gateway alerts')).getByRole('button', { name: /delete/i });

  fireEvent.click(remove);
  fireEvent.click(remove);

  await waitFor(() =>
    expect(showToast).toHaveBeenCalledWith(
      'error',
      'Delete failed: Forbidden (403)',
      expect.anything()
    )
  );
  expect(screen.getByText('Gateway alerts')).toBeInTheDocument();
});

test('a failed load shows the reason', async () => {
  mocked.listEndpoints.mockRejectedValue(new Error('Internal error (500)'));

  renderPage();

  expect(await screen.findByRole('alert')).toHaveTextContent('Internal error (500)');
});

test('an empty list invites the first integration', async () => {
  mocked.listIntegrations.mockResolvedValue([]);

  renderPage();

  expect(await screen.findByText(/add your first integration/i)).toBeInTheDocument();
});

test('exposes the test ids ui-tests use', async () => {
  mockPermissions = {
    'integrations.view': true,
    'integrations.edit': true,
    'integrations.delete': true,
  };
  renderPage();

  const row = await screen.findByTestId('integration-row-i1');
  expect(screen.getByTestId('page-integrations')).toBeInTheDocument();
  for (const tab of ['integrations', 'endpoints', 'event-sets']) {
    expect(screen.getByTestId(`integrations-tab-${tab}`)).toBeInTheDocument();
  }
  expect(screen.getByTestId('integrations-add-button')).toBeInTheDocument();
  for (const action of ['test', 'edit', 'delete']) {
    expect(within(row).getByTestId(`integration-${action}-button`)).toBeInTheDocument();
  }

  fireEvent.click(screen.getByTestId('integrations-tab-endpoints'));
  const endpointRow = await screen.findByTestId('endpoint-row-e1');
  expect(screen.getByTestId('endpoints-add-button')).toBeInTheDocument();
  for (const action of ['test', 'edit', 'delete']) {
    expect(within(endpointRow).getByTestId(`endpoint-${action}-button`)).toBeInTheDocument();
  }

  fireEvent.click(screen.getByTestId('integrations-tab-event-sets'));
  const eventSetRow = await screen.findByTestId('event-set-row-s1');
  expect(screen.getByTestId('event-sets-add-button')).toBeInTheDocument();
  for (const action of ['edit', 'delete']) {
    expect(within(eventSetRow).getByTestId(`event-set-${action}-button`)).toBeInTheDocument();
  }
});
