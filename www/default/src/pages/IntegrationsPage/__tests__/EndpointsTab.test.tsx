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
  deleteEndpoint: jest.fn(),
  testEndpoint: jest.fn(),
}));

const mocked = api as jest.Mocked<typeof api>;

function endpoint(overrides: Partial<api.Endpoint> = {}): api.Endpoint {
  return {
    id: 'e1',
    name: 'Ops Slack',
    description: 'The ops channel',
    type: 'slack',
    configuration: {},
    status: 'active',
    secrets: ['webhook_url'],
    created_at: '2026-10-15T00:00:00Z',
    updated_at: '2026-10-15T00:00:00Z',
    ...overrides,
  };
}

function integration(id: string, name: string, endpointId: string): api.Integration {
  return {
    id,
    name,
    description: '',
    endpoint_id: endpointId,
    event_set_id: 's1',
    content: {},
    status: 'active',
    created_at: '2026-10-15T00:00:00Z',
    updated_at: '2026-10-15T00:00:00Z',
  };
}

function Location() {
  const location = useLocation();
  return <div data-testid="location">{location.pathname + location.search}</div>;
}

function renderPage(path = '/integrations?tab=endpoints') {
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

const row = (name: string) => screen.findByRole('row', { name: new RegExp(name) });

beforeEach(() => {
  jest.clearAllMocks();
  mockPermissions = { 'integrations.view': true };
  mocked.listEndpoints.mockResolvedValue([
    endpoint(),
    endpoint({
      id: 'e2',
      name: 'SIEM stream',
      description: '',
      type: 'stream',
      status: 'disabled',
    }),
  ]);
  mocked.listIntegrations.mockResolvedValue([
    integration('i1', 'Gateway alerts', 'e1'),
    integration('i2', 'User alerts', 'e1'),
  ]);
  mocked.listEventSets.mockResolvedValue([]);
  mocked.deleteEndpoint.mockResolvedValue();
});

test('lists endpoints with their type, status and how many integrations use them', async () => {
  renderPage();

  const slack = within(await row('Ops Slack'));
  expect(slack.getByText('The ops channel')).toBeInTheDocument();
  expect(slack.getByText('slack')).toBeInTheDocument();
  expect(slack.getByText('active')).toBeInTheDocument();
  expect(slack.getByText('2 integrations')).toBeInTheDocument();

  const siem = within(await row('SIEM stream'));
  expect(siem.getByText('stream')).toBeInTheDocument();
  expect(siem.getByText('disabled')).toBeInTheDocument();
  expect(siem.getByText('Not used')).toBeInTheDocument();
});

test('switching tabs keeps the tab in the URL', async () => {
  renderPage('/integrations');
  await screen.findByRole('tab', { name: /endpoints/i });

  fireEvent.click(screen.getByRole('tab', { name: /endpoints/i }));

  expect(await row('Ops Slack')).toBeInTheDocument();
  expect(screen.getByTestId('location')).toHaveTextContent('/integrations?tab=endpoints');
});

test('an unknown tab opens the integrations tab', async () => {
  renderPage('/integrations?tab=nonsense');

  expect(
    await screen.findByRole('tab', { name: /integrations/i, selected: true })
  ).toBeInTheDocument();
});

test('the filter applies to endpoint names and types', async () => {
  renderPage();
  await row('Ops Slack');

  fireEvent.change(screen.getByPlaceholderText(/filter/i), { target: { value: 'stream' } });

  expect(screen.queryByText('Ops Slack')).not.toBeInTheDocument();
  expect(screen.getByText('SIEM stream')).toBeInTheDocument();
});

test('a viewer sees no endpoint actions', async () => {
  renderPage();
  const slack = within(await row('Ops Slack'));

  expect(screen.queryByRole('button', { name: /add endpoint/i })).not.toBeInTheDocument();
  expect(slack.queryByRole('button', { name: /test|edit|delete/i })).not.toBeInTheDocument();
});

test('an editor adds and opens endpoints', async () => {
  mockPermissions = { 'integrations.view': true, 'integrations.edit': true };
  renderPage();

  fireEvent.click(within(await row('Ops Slack')).getByRole('button', { name: /edit/i }));
  expect(screen.getByTestId('location')).toHaveTextContent('/integrations/endpoints/e1');
});

test('the add button opens a new endpoint', async () => {
  mockPermissions = { 'integrations.view': true, 'integrations.edit': true };
  renderPage();
  await row('Ops Slack');

  fireEvent.click(screen.getByRole('button', { name: /add endpoint/i }));

  expect(screen.getByTestId('location')).toHaveTextContent('/integrations/endpoints/new');
});

test('a test send through an endpoint reports where it went', async () => {
  mockPermissions = { 'integrations.view': true, 'integrations.edit': true };
  mocked.testEndpoint.mockResolvedValue({ delivered: true, event_type: 'integration.test' });
  renderPage();

  fireEvent.click(within(await row('Ops Slack')).getByRole('button', { name: /test/i }));

  await waitFor(() =>
    expect(showToast).toHaveBeenCalledWith('success', 'Test message sent to Ops Slack')
  );
  expect(mocked.testEndpoint).toHaveBeenCalledWith('e1');
});

test('a failed endpoint test shows why', async () => {
  mockPermissions = { 'integrations.view': true, 'integrations.edit': true };
  mocked.testEndpoint.mockRejectedValue(new Error('Secret slack-hook not found (502)'));
  renderPage();

  fireEvent.click(within(await row('Ops Slack')).getByRole('button', { name: /test/i }));

  await waitFor(() =>
    expect(showToast).toHaveBeenCalledWith(
      'error',
      'Test failed: Secret slack-hook not found (502)',
      expect.anything()
    )
  );
});

test('an endpoint in use cannot be deleted and names its integrations', async () => {
  mockPermissions = { 'integrations.view': true, 'integrations.delete': true };
  renderPage();

  const remove = within(await row('Ops Slack')).getByRole('button', { name: /delete/i });

  expect(remove).toBeDisabled();
  expect(remove).toHaveAttribute('title', 'Used by Gateway alerts, User alerts');
});

test('an unused endpoint is deleted after confirmation', async () => {
  mockPermissions = { 'integrations.view': true, 'integrations.delete': true };
  renderPage();
  const remove = within(await row('SIEM stream')).getByRole('button', { name: /delete/i });

  mocked.listEndpoints.mockResolvedValue([endpoint()]);
  fireEvent.click(remove);
  fireEvent.click(remove);

  await waitFor(() => expect(mocked.deleteEndpoint).toHaveBeenCalledWith('e2'));
  await waitFor(() => expect(screen.queryByText('SIEM stream')).not.toBeInTheDocument());
});

test('a delete refused by the gateway shows why', async () => {
  mockPermissions = { 'integrations.view': true, 'integrations.delete': true };
  mocked.deleteEndpoint.mockRejectedValue(
    new Error('The endpoint is used by these integrations: Late arrival (409)')
  );
  renderPage();
  const remove = within(await row('SIEM stream')).getByRole('button', { name: /delete/i });

  fireEvent.click(remove);
  fireEvent.click(remove);

  await waitFor(() =>
    expect(showToast).toHaveBeenCalledWith(
      'error',
      'Delete failed: The endpoint is used by these integrations: Late arrival (409)',
      expect.anything()
    )
  );
});

test('no endpoints yet invites the first one', async () => {
  mocked.listEndpoints.mockResolvedValue([]);

  renderPage();

  expect(await screen.findByText(/add your first endpoint/i)).toBeInTheDocument();
});
