import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import AuditPage from '..';
import { apiClient } from '../../../api';
import { clearUserNames } from '../useUserNames';

let mockSessionToken: string | null = 'session-1';
jest.mock('../../../api', () => ({
  ApiError: jest.requireActual('../../../api').ApiError,
  apiClient: {
    get: jest.fn(),
    listIssuers: jest.fn(() => Promise.resolve([])),
  },
  sessionManager: { getSessionToken: () => mockSessionToken },
}));

jest.mock('../../../utils/toaster', () => ({
  showToast: jest.fn(),
}));

let mockPermissions: Record<string, boolean> = {};
jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    hasPermission: (feature: string) => mockPermissions[feature] === true,
    loading: false,
  }),
}));

let mockAuditEnabled: boolean | undefined = true;
jest.mock('../../../context/AppContext', () => ({
  useApp: () => ({ state: { settings: { audit_enabled: mockAuditEnabled } } }),
}));

const mockGet = apiClient.get as jest.Mock;

const AUDIT_RESPONSE = {
  events: [
    {
      id: 'entry-1',
      timestamp: '2026-02-01T10:00:00Z',
      event: {
        policy_decision: {
          scope: 'surface',
          flow: 'transit_point',
          policy_id: 'surface.policy',
          policy_name: 'My Surface Policy',
          policy_definition_id: 'def-uuid-1',
          decision: 'deny',
          deny_reason: 'blocked by policy',
          surface_id: 'surface-1',
          caller_did: 'did:web:example.com:agent',
          http_method: 'POST',
          http_path: '/v1/message',
        },
      },
      surface_id: 'surface-1',
      channel_name: 'Weather Surface',
      caller: { auth_method: 'jwt_bearer', did: 'did:web:example.com:agent' },
      trace_id: 'trace-1',
      via_fabric: false,
    },
    {
      id: 'entry-2',
      timestamp: '2026-02-01T10:05:00Z',
      event: 'token_injected',
      provider_id: 'prov-1',
      provider_name: 'GitHub',
      via_fabric: true,
    },
  ],
  total: 2,
  page: 1,
  limit: 50,
  category_counts: { policy_decision: 1, token_injected: 1 },
};

function renderPage() {
  return render(
    <MemoryRouter>
      <AuditPage />
    </MemoryRouter>
  );
}

/** Locate a filter facet container by its "Label:" heading text. */
function facet(label: string): HTMLElement {
  return screen.getByText(label).parentElement as HTMLElement;
}

describe('AuditPage', () => {
  beforeEach(() => {
    mockPermissions = {};
    mockGet.mockReset();
    mockGet.mockResolvedValue({ data: AUDIT_RESPONSE });
  });

  it('renders the page shell, filter tabs and refresh control with stable test ids', async () => {
    renderPage();

    expect(await screen.findByTestId('page-audit')).toBeInTheDocument();
    expect(screen.getByTestId('audit-search')).toBeInTheDocument();
    expect(screen.getByTestId('audit-refresh')).toBeInTheDocument();

    // Category facet: the "All" chip is always inline; a category with a
    // non-zero count (from category_counts) renders inline once data loads.
    const categoryFacet = facet('Category:');
    expect(within(categoryFacet).getByTestId('filter-chip-all')).toBeInTheDocument();
    expect(
      await within(categoryFacet).findByTestId('filter-chip-policy_decision')
    ).toBeInTheDocument();

    // Decision facet: All / Allow / Deny inline chips.
    const decisionFacet = facet('Decision:');
    expect(within(decisionFacet).getByTestId('filter-chip-all')).toBeInTheDocument();
    expect(within(decisionFacet).getByTestId('filter-chip-allow')).toBeInTheDocument();
    expect(within(decisionFacet).getByTestId('filter-chip-deny')).toBeInTheDocument();

    expect(await screen.findByTestId('audit-list')).toBeInTheDocument();
  });

  it('keeps the evidence panel open by default and swaps it on selection', async () => {
    renderPage();

    // Panel is open on load, showing the newest (first) event.
    const item0 = await screen.findByTestId('audit-item-0');
    expect(item0.tagName).toBe('BUTTON');
    expect(item0).toHaveAttribute('aria-current', 'true');
    expect(screen.getByTestId('audit-detail-panel')).toHaveAttribute('data-open', 'true');
    const evidence = await screen.findByTestId('audit-evidence');
    // The evidence pane leads with the request journey timeline.
    expect(within(evidence).getByTestId('audit-journey')).toBeInTheDocument();
    // The quick filters live in the non-scrolling panel header, not the evidence body.
    const panel = screen.getByTestId('audit-detail-panel');
    expect(within(panel).getByTestId('audit-quick-filters')).toBeInTheDocument();
    expect(within(evidence).queryByTestId('audit-quick-filters')).not.toBeInTheDocument();

    // Selecting another event swaps the panel content and moves the selection.
    fireEvent.click(screen.getByTestId('audit-item-1'));
    expect(screen.getByTestId('audit-item-1')).toHaveAttribute('aria-current', 'true');
    expect(screen.getByTestId('audit-item-0')).toHaveAttribute('aria-current', 'false');
    expect(screen.getByTestId('audit-detail-panel')).toHaveAttribute('data-open', 'true');
  });

  it('sends the selected categories as an OR set and the About banner is collapsed by default', async () => {
    renderPage();

    // About banner collapsed initially, expands on toggle.
    const about = await screen.findByTestId('audit-about-toggle');
    expect(about).toHaveAttribute('aria-expanded', 'false');
    fireEvent.click(about);
    expect(about).toHaveAttribute('aria-expanded', 'true');

    // Selecting two categories issues an OR-set (comma-separated) query.
    const categoryFacet = facet('Category:');

    // policy_decision is an inline chip once its count loads.
    fireEvent.click(await within(categoryFacet).findByTestId('filter-chip-policy_decision'));
    await waitFor(() =>
      expect(mockGet).toHaveBeenCalledWith(expect.stringContaining('category=policy_decision'))
    );

    // trust_check has no count, so it lives in the Category overflow menu.
    fireEvent.click(within(categoryFacet).getByTestId('filter-overflow-trigger-category'));
    fireEvent.click(screen.getByTestId('filter-overflow-checkbox-trust_check'));
    await waitFor(() =>
      expect(mockGet).toHaveBeenCalledWith(
        expect.stringContaining('category=policy_decision%2Ctrust_check')
      )
    );
  });

  it('filters rows server-side by the policy-decision flow marker', async () => {
    // The server applies the flow filter, so the mock echoes it: flow=access_point
    // returns no matching policy decisions, otherwise the transit_point row.
    mockGet.mockImplementation((url: string) => {
      if (url.includes('flow=access_point')) {
        return Promise.resolve({
          data: { events: [], total: 0, page: 1, limit: 50, category_counts: {} },
        });
      }
      return Promise.resolve({ data: AUDIT_RESPONSE });
    });

    renderPage();

    // The transit_point policy decision shows initially, its flow named in the summary.
    const initialRow = await screen.findByTestId('audit-item-0');
    expect(within(initialRow).getByText(/Transit Point/)).toBeInTheDocument();

    // Flow options live in the Flow overflow menu.
    const flowFacet = facet('Flow:');
    fireEvent.click(within(flowFacet).getByTestId('filter-overflow-trigger-flow'));
    expect(screen.getByTestId('filter-overflow-checkbox-transit_point')).toBeInTheDocument();

    // Filtering by flow=access_point issues a server query and clears the rows.
    fireEvent.click(screen.getByTestId('filter-overflow-checkbox-access_point'));
    await waitFor(() =>
      expect(mockGet).toHaveBeenCalledWith(expect.stringContaining('flow=access_point'))
    );
    await waitFor(() => expect(screen.queryByTestId('audit-item-0')).not.toBeInTheDocument());

    // Filtering by flow=transit_point brings the row back.
    fireEvent.click(screen.getByTestId('filter-overflow-checkbox-transit_point'));
    await waitFor(() =>
      expect(mockGet).toHaveBeenCalledWith(expect.stringContaining('flow=transit_point'))
    );
    const row = await screen.findByTestId('audit-item-0');
    expect(within(row).getByText(/Transit Point/)).toBeInTheDocument();

    // Type (scope) options live in the Type overflow menu.
    const typeFacet = facet('Type:');
    fireEvent.click(within(typeFacet).getByTestId('filter-overflow-trigger-type'));
    expect(screen.getByTestId('filter-overflow-checkbox-gateway')).toBeInTheDocument();
  });
});

function LocationProbe() {
  const location = useLocation();
  return <div data-testid="location">{`${location.pathname}${location.search}`}</div>;
}

function renderWithRoutes() {
  return render(
    <MemoryRouter initialEntries={['/audit']}>
      <Routes>
        <Route path="/audit" element={<AuditPage />} />
        <Route path="*" element={<LocationProbe />} />
      </Routes>
    </MemoryRouter>
  );
}

const AUDIT_SET = { id: 'audit-set', events: ['audit.policy_decision'] };
const GATEWAY_SET = { id: 'gateway-set', events: ['gateway.created'] };

/** An integration with the active endpoint `on`, receiving `eventSetId`'s events. */
const integration = (status: string, eventSetId = AUDIT_SET.id, endpointId = 'on') => ({
  status,
  endpoint_id: endpointId,
  event_set_id: eventSetId,
});

function withIntegrations(integrations: ReturnType<typeof integration>[]) {
  const definitions: Record<string, unknown> = {
    '/integrations': integrations,
    '/integrations/endpoints': [
      { id: 'on', status: 'active' },
      { id: 'off', status: 'disabled' },
    ],
    '/integrations/event-sets': [AUDIT_SET, GATEWAY_SET],
  };
  mockGet.mockImplementation((url: string) =>
    Promise.resolve({ data: url in definitions ? definitions[url] : AUDIT_RESPONSE })
  );
}

describe('AuditPage forwarding', () => {
  beforeEach(() => {
    mockGet.mockReset();
    mockAuditEnabled = true;
  });

  it('keeps forwarding while VP Auditing is off and says only the log keeps nothing', async () => {
    mockPermissions = { 'integrations.view': true };
    mockAuditEnabled = false;
    withIntegrations([integration('active')]);
    renderWithRoutes();

    const button = await screen.findByTestId('audit-forward-button');
    expect(button).toHaveTextContent(/^Forwarding to 1 integration$/);
    expect(button).toHaveAttribute(
      'title',
      'VP Auditing is off in Settings › Security, so the VP Audit Log keeps nothing; ' +
        'Governance Audit integrations still receive the audit events of their event sets.'
    );
  });

  it('warns about integrations with audit events that are disabled or whose endpoint is', async () => {
    mockPermissions = { 'integrations.view': true };
    withIntegrations([
      integration('active'),
      integration('disabled'),
      integration('active', AUDIT_SET.id, 'off'),
    ]);
    renderWithRoutes();

    const button = await screen.findByTestId('audit-forward-button');
    expect(button).toHaveTextContent(/^Forwarding to 1 integration$/);
    expect(within(button).getByTestId('audit-forward-paused-warning')).toBeInTheDocument();
    expect(button).toHaveAttribute(
      'title',
      '2 Governance Audit integrations are disabled, or their endpoint is, and receive nothing.'
    );
  });

  it('warns about a disabled integration while VP Auditing is off', async () => {
    mockPermissions = { 'integrations.view': true, 'integrations.edit': true };
    mockAuditEnabled = false;
    withIntegrations([integration('disabled')]);
    renderWithRoutes();

    const button = await screen.findByTestId('audit-forward-button');
    expect(button).toHaveTextContent(/^Forward records$/);
    expect(within(button).getByTestId('audit-forward-paused-warning')).toBeInTheDocument();
    expect(button).toHaveAttribute(
      'title',
      expect.stringContaining(
        '1 Governance Audit integration is disabled, or its endpoint is, and receives nothing.'
      )
    );
    expect(button).toHaveAttribute('title', expect.stringContaining('VP Audit Log keeps nothing'));
  });

  it('starts an event set of every audit event when no integration receives the records', async () => {
    mockPermissions = { 'integrations.view': true, 'integrations.edit': true };
    withIntegrations([integration('active', GATEWAY_SET.id)]);
    renderWithRoutes();

    const button = await screen.findByTestId('audit-forward-button');
    expect(button).toHaveTextContent('Forward records');
    fireEvent.click(button);
    expect(screen.getByTestId('location')).toHaveTextContent(
      '/integrations/event-sets/new?preset=audit'
    );
  });

  it('counts only active integrations with audit events and opens the list', async () => {
    mockPermissions = { 'integrations.view': true, 'integrations.edit': true };
    withIntegrations([
      integration('active'),
      integration('active'),
      integration('active', GATEWAY_SET.id),
    ]);
    renderWithRoutes();

    const button = await screen.findByTestId('audit-forward-button');
    expect(button).toHaveTextContent('Forwarding to 2 integrations');
    expect(within(button).queryByTestId('audit-forward-paused-warning')).not.toBeInTheDocument();
    expect(button).not.toHaveAttribute('title');
    fireEvent.click(button);
    expect(screen.getByTestId('location')).toHaveTextContent(/^\/integrations$/);
  });

  it('shows existing forwarding to a caller who cannot add integrations', async () => {
    mockPermissions = { 'integrations.view': true };
    withIntegrations([integration('active')]);
    renderWithRoutes();

    expect(await screen.findByTestId('audit-forward-button')).toHaveTextContent(
      /^Forwarding to 1 integration$/
    );
  });

  it('offers nothing to a caller who can view but not add integrations when none forward', async () => {
    mockPermissions = { 'integrations.view': true };
    withIntegrations([]);
    renderWithRoutes();

    await waitFor(() => expect(mockGet).toHaveBeenCalledWith('/integrations'));
    await screen.findByTestId('audit-list');
    expect(screen.queryByTestId('audit-forward-button')).not.toBeInTheDocument();
  });

  it('does not look up integrations without integrations.view', async () => {
    mockPermissions = {};
    withIntegrations([integration('active')]);
    renderWithRoutes();

    await screen.findByTestId('audit-list');
    expect(mockGet).not.toHaveBeenCalledWith('/integrations');
    expect(screen.queryByTestId('audit-forward-button')).not.toBeInTheDocument();
  });
});

describe('AuditPage policy changes', () => {
  const CHANGE_RESPONSE = {
    events: [
      {
        id: 'change-1',
        timestamp: '2026-10-27T10:00:00Z',
        event: {
          policy_attached: {
            policy_definition_id: 'deny-pii',
            policy_name: '<img src=x onerror=alert(1)>',
            policy_type: 'agent_surface',
            policy_version: 3,
            target: { kind: 'surface', id: 'surface-1', name: 'Orders' },
            scope: 'surface',
            slot: 'inbound',
            actor: { kind: 'user', id: 'u-1' },
            source: 'api',
          },
        },
        surface_id: 'surface-1',
        channel_name: 'Orders',
        request_id: '0123456789abcdef',
        via_fabric: false,
      },
    ],
    total: 1,
    page: 1,
    limit: 50,
    category_counts: { policy_attached: 1 },
  };

  beforeEach(() => {
    mockPermissions = { 'users.view': true };
    mockSessionToken = 'session-1';
    clearUserNames();
    mockGet.mockReset();
    mockGet.mockImplementation((url: string) =>
      Promise.resolve({
        data: url === '/users' ? [{ user_id: 'u-1', username: 'alice' }] : CHANGE_RESPONSE,
      })
    );
  });

  const usersRequests = () => mockGet.mock.calls.filter(([url]) => url === '/users');

  it('names actors by id without users.view and never asks for the users list', async () => {
    mockPermissions = {};
    renderPage();

    const item = await screen.findByTestId('audit-item-0');
    expect(within(item).getByText('user u-1')).toBeInTheDocument();
    expect(usersRequests()).toHaveLength(0);
  });

  it('asks for the users list again in a new session, not with the previous session’s names', async () => {
    const { unmount } = renderPage();
    const item = await screen.findByTestId('audit-item-0');
    await waitFor(() => expect(within(item).getByText('user alice')).toBeInTheDocument());
    unmount();

    mockSessionToken = 'session-2';
    mockGet.mockImplementation((url: string) =>
      Promise.resolve({
        data: url === '/users' ? [{ user_id: 'u-1', username: 'bob' }] : CHANGE_RESPONSE,
      })
    );
    renderPage();

    const again = await screen.findByTestId('audit-item-0');
    await waitFor(() => expect(within(again).getByText('user bob')).toBeInTheDocument());
    expect(usersRequests()).toHaveLength(2);
  });

  it('describes the change by its actor’s name and shows its details without a request journey', async () => {
    renderPage();

    const item = await screen.findByTestId('audit-item-0');
    expect(within(item).getByText('Policy attached')).toBeInTheDocument();
    expect(
      within(item).getByText(
        '“<img src=x onerror=alert(1)>” v3 was added to surface Orders as its inbound policy.'
      )
    ).toBeInTheDocument();
    await waitFor(() => expect(within(item).getByText('user alice')).toBeInTheDocument());

    const evidence = screen.getByTestId('audit-evidence');
    expect(within(evidence).queryByTestId('audit-journey')).not.toBeInTheDocument();
    expect(within(evidence).getByText('Where')).toBeInTheDocument();
    expect(within(evidence).getByText('inbound policy')).toBeInTheDocument();
  });

  it('asks for the users list once per page load', async () => {
    renderPage();

    const item = await screen.findByTestId('audit-item-0');
    await waitFor(() => expect(within(item).getByText('user alice')).toBeInTheDocument());
    expect(mockGet.mock.calls.filter(([url]) => url === '/users')).toHaveLength(1);
  });

  it.each([
    [403, 1],
    [500, 2],
  ])(
    'after the users list fails with %i, a later visit asks for it %i time(s) in all',
    async (status, calls) => {
      const { ApiError } = jest.requireActual('../../../api');
      mockGet.mockImplementation((url: string) =>
        url === '/users'
          ? Promise.reject(new ApiError('failed', status))
          : Promise.resolve({ data: CHANGE_RESPONSE })
      );

      const { unmount } = renderPage();
      const item = await screen.findByTestId('audit-item-0');
      await waitFor(() => expect(within(item).getByText('user u-1')).toBeInTheDocument());
      unmount();
      renderPage();
      await screen.findByTestId('audit-item-0');

      await waitFor(() =>
        expect(mockGet.mock.calls.filter(([url]) => url === '/users')).toHaveLength(calls)
      );
    }
  );

  it('does not ask for the users list when the page shows no policy change', async () => {
    mockGet.mockImplementation((url: string) =>
      Promise.resolve({ data: url === '/users' ? [] : AUDIT_RESPONSE })
    );
    renderPage();

    await screen.findByTestId('audit-item-0');
    expect(mockGet).not.toHaveBeenCalledWith('/users');
  });
});
