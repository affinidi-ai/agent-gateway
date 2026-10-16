import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import EventSetEditorPage from '..';
import * as api from '../../../integrationsApi';
import { showToast } from '../../../utils/toaster';

jest.mock('../../../utils/toaster', () => ({ showToast: jest.fn() }));

let mockPermissions: Record<string, boolean> = {};

jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    loading: false,
    hasPermission: (feature: string) => mockPermissions[feature] === true,
  }),
}));

jest.mock('../../../integrationsApi', () => ({
  getCatalog: jest.fn(),
  getEventSet: jest.fn(),
  listIntegrations: jest.fn(),
  createEventSet: jest.fn(),
  updateEventSet: jest.fn(),
}));

const mocked = api as jest.Mocked<typeof api>;

const event = (
  id: string,
  name: string,
  family: string,
  familyLabel: string,
  group?: [string, string]
): api.CatalogEvent => ({
  id,
  name,
  description: `${name} happened`,
  family,
  family_label: familyLabel,
  ...(group ? { group: group[0], group_label: group[1] } : {}),
  variables: [],
});

const CATALOG: api.IntegrationCatalog = {
  events: [
    event('gateway.created', 'Gateway Created', 'gateway', 'Gateway'),
    event('gateway.deleted', 'Gateway Deleted', 'gateway', 'Gateway'),
    event('user.login', 'User Login', 'user', 'User'),
    event('audit.policy_decision', 'Policy Decision', 'audit', 'Governance Audit', [
      'policy',
      'Policy',
    ]),
    event('audit.auth_failed', 'Authentication Failed', 'audit', 'Governance Audit', [
      'requests',
      'Requests',
    ]),
  ],
  variables: [],
  endpoint_types: [],
  variable_pattern: '\\$\\{([^:}]+)(?::[^}]+)?\\}',
};

const STORED: api.EventSet = {
  id: 's1',
  name: 'Gateway changes',
  description: 'Created and deleted gateways',
  events: ['gateway.created', 'gateway.deleted'],
  created_at: '2026-10-15T00:00:00Z',
  updated_at: '2026-10-15T00:00:00Z',
};

function Location() {
  const location = useLocation();
  return <div data-testid="location">{location.pathname + location.search}</div>;
}

function renderEditor(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/integrations/event-sets/new" element={<EventSetEditorPage />} />
        <Route path="/integrations/event-sets/:id" element={<EventSetEditorPage />} />
        <Route path="/integrations" element={<div>integrations page</div>} />
      </Routes>
      <Location />
    </MemoryRouter>
  );
}

const type = (label: RegExp, value: string) =>
  fireEvent.change(screen.getByLabelText(label), { target: { value } });

beforeEach(() => {
  jest.clearAllMocks();
  mockPermissions = { 'integrations.edit': true, 'audit.view': true };
  mocked.getCatalog.mockResolvedValue(CATALOG);
  mocked.getEventSet.mockResolvedValue(STORED);
  mocked.listIntegrations.mockResolvedValue([]);
  mocked.createEventSet.mockImplementation(async request => ({ ...STORED, ...request, id: 'new' }));
  mocked.updateEventSet.mockImplementation(async (id, request) => ({ ...STORED, ...request, id }));
});

test('lists the whole catalog by family, and audit events by their audit group', async () => {
  renderEditor('/integrations/event-sets/new');

  expect(await screen.findByLabelText(/gateway created/i)).toBeInTheDocument();
  expect(screen.getByText('Gateway')).toBeInTheDocument();
  expect(screen.getByText('User')).toBeInTheDocument();
  expect(screen.getByText('Governance Audit: Policy')).toBeInTheDocument();
  expect(screen.getByText('Governance Audit: Requests')).toBeInTheDocument();
});

test('creates an event set from the picked events and opens the event sets tab', async () => {
  renderEditor('/integrations/event-sets/new');
  await screen.findByLabelText(/gateway created/i);

  type(/^name/i, 'Sign-ins');
  fireEvent.click(screen.getByLabelText(/user login/i));
  fireEvent.click(screen.getByLabelText(/policy decision/i));
  fireEvent.click(screen.getByRole('button', { name: /save/i }));

  await waitFor(() =>
    expect(mocked.createEventSet).toHaveBeenCalledWith({
      name: 'Sign-ins',
      description: '',
      events: ['user.login', 'audit.policy_decision'],
    })
  );
  await waitFor(() =>
    expect(screen.getByTestId('location')).toHaveTextContent('/integrations?tab=event-sets')
  );
  expect(showToast).toHaveBeenCalledWith('success', 'Event set Sign-ins saved');
});

test('needs a name and at least one event', async () => {
  renderEditor('/integrations/event-sets/new');
  await screen.findByLabelText(/gateway created/i);

  fireEvent.click(screen.getByRole('button', { name: /save/i }));

  expect(screen.getByRole('alert')).toHaveTextContent('Fill in: Name, at least one event');
  expect(mocked.createEventSet).not.toHaveBeenCalled();
});

test('notes that audit events go through the audit journal', async () => {
  renderEditor('/integrations/event-sets/new');
  await screen.findByLabelText(/gateway created/i);

  expect(screen.queryByText(/audit journal/i)).not.toBeInTheDocument();
  fireEvent.click(screen.getByLabelText(/policy decision/i));

  expect(screen.getByText(/audit journal/i)).toBeInTheDocument();
});

test('the audit preset starts with every audit event picked', async () => {
  renderEditor('/integrations/event-sets/new?preset=audit');

  expect(await screen.findByLabelText(/policy decision/i)).toBeChecked();
  expect(screen.getByLabelText(/authentication failed/i)).toBeChecked();
  expect(screen.getByLabelText(/gateway created/i)).not.toBeChecked();
  expect(screen.getByLabelText(/^name/i)).toHaveValue('Governance Audit');
});

test('edits a stored event set and names the integrations using it', async () => {
  mocked.listIntegrations.mockResolvedValue([
    {
      id: 'i1',
      name: 'Gateway alerts',
      description: '',
      endpoint_id: 'e1',
      event_set_id: 's1',
      content: {},
      status: 'active',
      created_at: '',
      updated_at: '',
    },
  ]);
  renderEditor('/integrations/event-sets/s1');

  expect(await screen.findByDisplayValue('Gateway changes')).toBeInTheDocument();
  expect(screen.getByLabelText(/gateway created/i)).toBeChecked();
  expect(screen.getByText(/used by gateway alerts/i)).toBeInTheDocument();

  fireEvent.click(screen.getByLabelText(/gateway deleted/i));
  fireEvent.click(screen.getByRole('button', { name: /save/i }));

  await waitFor(() =>
    expect(mocked.updateEventSet).toHaveBeenCalledWith('s1', {
      name: 'Gateway changes',
      description: 'Created and deleted gateways',
      events: ['gateway.created'],
    })
  );
});

test('a change the gateway refuses shows why', async () => {
  mocked.updateEventSet.mockRejectedValue(
    new Error(
      'Integration Gateway alerts uses variables no event of the set fills: GATEWAY_NAME (409)'
    )
  );
  renderEditor('/integrations/event-sets/s1');
  await screen.findByDisplayValue('Gateway changes');

  fireEvent.click(screen.getByLabelText(/gateway created/i));
  fireEvent.click(screen.getByLabelText(/gateway deleted/i));
  fireEvent.click(screen.getByLabelText(/user login/i));
  fireEvent.click(screen.getByRole('button', { name: /save/i }));

  expect(await screen.findByRole('alert')).toHaveTextContent(
    'Integration Gateway alerts uses variables no event of the set fills: GATEWAY_NAME (409)'
  );
});

test('events the catalog no longer lists are shown and can be removed', async () => {
  mocked.getEventSet.mockResolvedValue({
    ...STORED,
    events: ['gateway.created', 'identity.created'],
  });
  renderEditor('/integrations/event-sets/s1');
  await screen.findByDisplayValue('Gateway changes');

  expect(screen.getByText('identity.created')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: /remove identity.created/i }));
  fireEvent.click(screen.getByRole('button', { name: /save/i }));

  await waitFor(() =>
    expect(mocked.updateEventSet).toHaveBeenCalledWith(
      's1',
      expect.objectContaining({ events: ['gateway.created'] })
    )
  );
});

describe('without audit.view', () => {
  beforeEach(() => {
    mockPermissions = { 'integrations.edit': true };
  });

  test('audit events are shown but cannot be picked, and the editor says why', async () => {
    renderEditor('/integrations/event-sets/new');

    expect(await screen.findByLabelText(/policy decision/i)).toBeDisabled();
    expect(screen.getByLabelText(/authentication failed/i)).toBeDisabled();
    expect(screen.getByLabelText(/gateway created/i)).toBeEnabled();
    expect(screen.getByText(/audit events need the audit\.view permission/i)).toBeInTheDocument();
  });

  test('the audit preset picks nothing', async () => {
    renderEditor('/integrations/event-sets/new?preset=audit');

    expect(await screen.findByLabelText(/policy decision/i)).not.toBeChecked();
    expect(screen.getByLabelText(/^name/i)).toHaveValue('');
  });

  test('an event set holding audit events cannot be saved', async () => {
    mocked.getEventSet.mockResolvedValue({ ...STORED, events: ['audit.policy_decision'] });
    renderEditor('/integrations/event-sets/s1');
    await screen.findByDisplayValue('Gateway changes');

    expect(screen.getByRole('button', { name: /^save/i })).toBeDisabled();
    expect(screen.getByText(/audit events need the audit\.view permission/i)).toBeInTheDocument();
  });

  test('an event set without audit events is saved as usual', async () => {
    renderEditor('/integrations/event-sets/s1');
    await screen.findByDisplayValue('Gateway changes');

    fireEvent.click(screen.getByRole('button', { name: /^save/i }));

    await waitFor(() => expect(mocked.updateEventSet).toHaveBeenCalled());
  });
});

test('a catalog that cannot be loaded says why', async () => {
  mocked.getCatalog.mockRejectedValue(new Error('Forbidden (403)'));

  renderEditor('/integrations/event-sets/new');

  expect(await screen.findByRole('alert')).toHaveTextContent('Forbidden (403)');
});

test('exposes the test ids ui-tests use', async () => {
  mocked.getEventSet.mockResolvedValue({
    ...STORED,
    events: ['gateway.created', 'identity.created'],
  });
  renderEditor('/integrations/event-sets/s1');
  await screen.findByDisplayValue('Gateway changes');

  for (const id of [
    'page-event-set-editor',
    'event-set-save-button',
    'event-set-cancel-button',
    'event-set-name-input',
    'event-set-search-input',
    'event-set-group-gateway',
    'event-set-event-gateway.created',
    'event-set-remove-identity.created-button',
  ]) {
    expect(screen.getByTestId(id)).toBeInTheDocument();
  }
});
