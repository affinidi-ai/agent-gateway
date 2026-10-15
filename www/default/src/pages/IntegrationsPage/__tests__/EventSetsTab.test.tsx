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
  deleteEventSet: jest.fn(),
}));

const mocked = api as jest.Mocked<typeof api>;

function eventSet(overrides: Partial<api.EventSet> = {}): api.EventSet {
  return {
    id: 's1',
    name: 'Gateway changes',
    description: 'Created and deleted gateways',
    events: ['gateway.created', 'gateway.deleted'],
    created_at: '2026-10-15T00:00:00Z',
    updated_at: '2026-10-15T00:00:00Z',
    ...overrides,
  };
}

function integration(id: string, name: string, eventSetId: string): api.Integration {
  return {
    id,
    name,
    description: '',
    endpoint_id: 'e1',
    event_set_id: eventSetId,
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

function renderPage(path = '/integrations?tab=event-sets') {
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
  mocked.listEventSets.mockResolvedValue([
    eventSet(),
    eventSet({
      id: 's2',
      name: 'Governance',
      description: '',
      events: ['audit.policy_decision'],
    }),
  ]);
  mocked.listIntegrations.mockResolvedValue([integration('i1', 'Gateway alerts', 's1')]);
  mocked.listEndpoints.mockResolvedValue([]);
  mocked.deleteEventSet.mockResolvedValue();
});

test('lists event sets with their event count, audit marker and users', async () => {
  renderPage();

  const gateways = within(await row('Gateway changes'));
  expect(gateways.getByText('Created and deleted gateways')).toBeInTheDocument();
  expect(gateways.getByText('2 events')).toBeInTheDocument();
  expect(gateways.queryByText('audit')).not.toBeInTheDocument();
  expect(gateways.getByText('1 integration')).toBeInTheDocument();

  const governance = within(await row('Governance'));
  expect(governance.getByText('1 event')).toBeInTheDocument();
  expect(governance.getByText('audit')).toBeInTheDocument();
  expect(governance.getByText('Not used')).toBeInTheDocument();
});

test('the filter applies to event set names and their events', async () => {
  renderPage();
  await row('Gateway changes');

  fireEvent.change(screen.getByPlaceholderText(/filter/i), {
    target: { value: 'policy_decision' },
  });

  expect(screen.queryByText('Gateway changes')).not.toBeInTheDocument();
  expect(screen.getByText('Governance')).toBeInTheDocument();
});

test('a viewer sees no event set actions', async () => {
  renderPage();
  const gateways = within(await row('Gateway changes'));

  expect(screen.queryByRole('button', { name: /add event set/i })).not.toBeInTheDocument();
  expect(gateways.queryByRole('button', { name: /edit|delete/i })).not.toBeInTheDocument();
});

test('an editor adds and opens event sets', async () => {
  mockPermissions = { 'integrations.view': true, 'integrations.edit': true };
  renderPage();

  fireEvent.click(within(await row('Gateway changes')).getByRole('button', { name: /edit/i }));
  expect(screen.getByTestId('location')).toHaveTextContent('/integrations/event-sets/s1');
});

test('the add button opens a new event set', async () => {
  mockPermissions = { 'integrations.view': true, 'integrations.edit': true };
  renderPage();
  await row('Gateway changes');

  fireEvent.click(screen.getByRole('button', { name: /add event set/i }));

  expect(screen.getByTestId('location')).toHaveTextContent('/integrations/event-sets/new');
});

test('an event set in use cannot be deleted and names its integrations', async () => {
  mockPermissions = { 'integrations.view': true, 'integrations.delete': true };
  renderPage();

  const remove = within(await row('Gateway changes')).getByRole('button', { name: /delete/i });

  expect(remove).toBeDisabled();
  expect(remove).toHaveAttribute('title', 'Used by Gateway alerts');
});

test('an unused event set is deleted after confirmation', async () => {
  mockPermissions = { 'integrations.view': true, 'integrations.delete': true };
  renderPage();
  const remove = within(await row('Governance')).getByRole('button', { name: /delete/i });

  mocked.listEventSets.mockResolvedValue([eventSet()]);
  fireEvent.click(remove);
  fireEvent.click(remove);

  await waitFor(() => expect(mocked.deleteEventSet).toHaveBeenCalledWith('s2'));
  await waitFor(() => expect(screen.queryByText('Governance')).not.toBeInTheDocument());
});

test('a delete refused by the gateway shows why', async () => {
  mockPermissions = { 'integrations.view': true, 'integrations.delete': true };
  mocked.deleteEventSet.mockRejectedValue(
    new Error('The event set is used by these integrations: X (409)')
  );
  renderPage();
  const remove = within(await row('Governance')).getByRole('button', { name: /delete/i });

  fireEvent.click(remove);
  fireEvent.click(remove);

  await waitFor(() =>
    expect(showToast).toHaveBeenCalledWith(
      'error',
      'Delete failed: The event set is used by these integrations: X (409)',
      expect.anything()
    )
  );
});

test('no event sets yet invites the first one', async () => {
  mocked.listEventSets.mockResolvedValue([]);

  renderPage();

  expect(await screen.findByText(/add your first event set/i)).toBeInTheDocument();
});
